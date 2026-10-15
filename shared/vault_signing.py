# (c) Copyright 2026. Vault co-signer signing/verification helpers.
#
# shared/vault_signing.py
#
# Pure-python, host-and-device portable helpers for the vault co-signer:
#   - strict DER signature parsing (Bitcoin Core VerifyScript leniency for
#     structure, plus the low-S standardness rule)
#   - secp256k1 ECDSA verification (no ngu dependency: ngu exposes sign
#     but no verify, so this is self-contained big-int math; public data
#     only, so non-constant-time is acceptable)
#   - BIP-143 partial-signature verification for vault inputs (V-03 fix)
#   - (Phase 1) vault witness-script recognition, role-based signature
#     counting (V-01/V-02 fix) and witness-stack construction
#
# Runs on host (CPython, testing/) and target (MicroPython). No device
# imports; psbtObject is duck-typed where needed.
#
# Host-testable: python3 testing/test_vault_hardening.py

try:
    from uhashlib import sha256 as _sha256
except ImportError:
    from hashlib import sha256 as _sha256

from vault_policy import (VaultViolation, parse_vault_script,
                          parse_deepvault_script, p2wsh_spk, sequence_class)

SIGHASH_ALL = 0x01

# ---- secp256k1 domain parameters ------------------------------------------
_P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _inv(a, m=_N):
    # modular inverse (extended Euclid); a != 0 mod m
    lm, hm, low, high = 1, 0, a % m, m
    while low > 1:
        r = high // low
        lm, hm, low, high = hm - lm * r, lm, high - low * r, low
    if low != 1:
        raise VaultViolation('ecdsa: no inverse')
    return lm % m


def _padd(p, q):
    # affine point addition; None is the point at infinity
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None
        l = (3 * x1 * x1) * _inv((2 * y1) % _P, _P) % _P
    else:
        l = (y2 - y1) * _inv((x2 - x1) % _P, _P) % _P
    x3 = (l * l - x1 - x2) % _P
    return (x3, (l * (x1 - x3) - y1) % _P)


def _pmul(k, p):
    # double-and-add scalar multiplication
    r = None
    while k:
        if k & 1:
            r = _padd(r, p)
        p = _padd(p, p)
        k >>= 1
    return r


_G = (_GX, _GY)


def _decompress_pubkey(pub33):
    # 33-byte compressed -> affine point; raises if not on curve
    if len(pub33) != 33 or pub33[0] not in (0x02, 0x03):
        raise VaultViolation('ecdsa: bad pubkey')
    x = int.from_bytes(bytes(pub33[1:]), 'big')
    if x >= _P:
        raise VaultViolation('ecdsa: pubkey x out of range')
    y2 = (pow(x, 3, _P) + 7) % _P
    y = pow(y2, (_P + 1) // 4, _P)
    if y * y % _P != y2:
        raise VaultViolation('ecdsa: pubkey not on curve')
    if (y & 1) != (pub33[0] & 1):
        y = _P - y
    return (x, y)


def secp256k1_verify(pub33, r, s, digest):
    # Standard ECDSA verification over secp256k1. Returns bool; never
    # raises for mathematically-representable inputs (bad pubkeys raise
    # via _decompress_pubkey - caller decides policy).
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    if len(digest) != 32:
        return False
    q = _decompress_pubkey(bytes(pub33))
    z = int.from_bytes(bytes(digest), 'big')
    w = _inv(s)
    u1 = (z * w) % _N
    u2 = (r * w) % _N
    pt = _padd(_pmul(u1, _G), _pmul(u2, q))
    if pt is None:
        return False
    return pt[0] % _N == r


# ---- DER signature parsing -------------------------------------------------

def parse_der_sig(sig):
    # Strict DER parse of a Bitcoin transaction signature WITH its trailing
    # sighash-type byte:  0x30 len 0x02 lr R 0x02 ls S sh
    # Enforces Bitcoin Core's script-DER rules and the low-S standardness
    # rule (high-S sigs are consensus-valid but non-standard: they would
    # make a policy-approved tx unbroadcastable - class 3 - so refuse).
    # Returns (r, s, sighash_byte); raises VaultViolation.
    try:
        sig = bytes(sig)
        if len(sig) < 9 or len(sig) > 73:
            raise VaultViolation('sig: bad length %d' % len(sig))
        if sig[0] != 0x30:
            raise VaultViolation('sig: not DER sequence')
        if sig[1] != len(sig) - 3:
            raise VaultViolation('sig: bad sequence length')
        if sig[2] != 0x02:
            raise VaultViolation('sig: no r marker')
        lr = sig[3]
        if lr == 0 or 4 + lr >= len(sig):
            raise VaultViolation('sig: bad r length')
        if sig[4 + lr] != 0x02:
            raise VaultViolation('sig: no s marker')
        ls = sig[5 + lr]
        if ls == 0 or 6 + lr + ls != len(sig) - 1:
            raise VaultViolation('sig: bad s length')
        rb = sig[4:4 + lr]
        sb = sig[6 + lr:6 + lr + ls]
        for name, b in (('r', rb), ('s', sb)):
            if b[0] & 0x80:
                raise VaultViolation('sig: negative %s' % name)
            # non-minimal = unnecessary leading zero (Core's DER rule):
            # a leading 0x00 is required iff the next byte has its high
            # bit set (sign), otherwise it is non-minimal padding
            if len(b) > 1 and b[0] == 0x00 and b[1] < 0x80:
                raise VaultViolation('sig: non-minimal %s' % name)
        r = int.from_bytes(rb, 'big')
        s = int.from_bytes(sb, 'big')
        if s > _N // 2:
            raise VaultViolation('sig: high-S (non-standard)')
        return r, s, sig[-1]
    except VaultViolation:
        raise
    except Exception as e:
        raise VaultViolation('sig: malformed (%s)' % e)


def check_sighash_all(sig):
    # The sighash-type byte of a serialized signature must be exactly
    # SIGHASH_ALL (V-04 fix: vault signatures commit to the whole tx -
    # inputs AND outputs - so they can never be grafted).
    r, s, sh = parse_der_sig(sig)
    if sh != SIGHASH_ALL:
        raise VaultViolation('sighash: vault sigs must be SIGHASH_ALL, got 0x%02x' % sh)
    return r, s


# ---- BIP-143 partial-signature verification for vault inputs (V-03) -------

def _ser_string(script):
    # compactSize-length-prefixed script (the BIP-143 scriptCode form)
    n = len(script)
    if n < 253:
        return bytes([n]) + bytes(script)
    return b'\xfd' + bytes((n & 0xff, (n >> 8) & 0xff)) + bytes(script)


def verify_input_sigs(psbt, idx, inp, txi, wscript):
    # Verify EVERY partial signature on a vault-script input against the
    # BIP-143 sighash of the transaction being approved. The device's
    # finalize() will place these signatures in the final witness next to
    # its own, so a garbage/malleated signature here is a class-3 bug
    # (policy-valid but consensus-invalid tx), not a cosmetic issue.
    #
    # duck-typed against psbtObject: psbt.make_txn_segwit_sighash,
    # inp.get_utxo / inp.get / inp.part_sigs.
    # Raises VaultViolation on any malformed or invalid signature.
    # get_utxo indexes the FUNDING tx's outputs: the coin being spent is
    # at the prevout's vout, not at this input's position (a vault coin
    # at vout != input idx must not be verified against a sibling
    # output's amount - the digest would be wrong and valid sigs refused)
    utxo = inp.get_utxo(txi.prevout.n)
    script_code = _ser_string(wscript)
    digest = psbt.make_txn_segwit_sighash(idx, txi, utxo.nValue,
                                          script_code, SIGHASH_ALL)
    for pk, ref in (inp.part_sigs or {}).items():
        sig = inp.get(ref) if isinstance(ref, (tuple, list)) else ref
        r, s = check_sighash_all(sig)          # DER + low-S + SIGHASH_ALL
        if not secp256k1_verify(pk, r, s, digest):
            raise VaultViolation('invalid partial signature for %s'
                                 % _b2h(pk))


def _b2h(b):
    try:
        from ubinascii import hexlify
    except ImportError:
        from binascii import hexlify
    return str(hexlify(bytes(b)), 'ascii')


# ---- vault script recognition + role logic + witnesses (Phase 1) -----------

def recognize(wscript, cfg):
    # Identify a witness script as this device's enrolled S_v ('sv') or
    # S_e ('se'). Hash match AND structural parse must both succeed
    # (defense in depth); mismatch => None (not ours); hash-match with a
    # structural parse failure => raise (fail closed: the input claims to
    # be a vault coin but the script is not the enrolled shape).
    try:
        h = _sha256(wscript).digest()
    except Exception:
        return None
    for kind, field in (('sv', 'sv_hash'), ('se', 'spk_e')):
        want = _unhex_cfg(cfg, field)
        if want and want[2:] == h:
            try:
                if kind == 'sv':
                    parse_vault_script(wscript)
                else:
                    parse_deepvault_script(wscript)
            except VaultViolation as e:
                raise VaultViolation('vault script hash matches %s but '
                                     'structure invalid: %s' % (field, e))
            return kind
    return None


def _unhex_cfg(cfg, field):
    v = (cfg or {}).get(field)
    if not v:
        return None
    try:
        from ubinascii import unhexlify
    except ImportError:
        from binascii import unhexlify
    try:
        return unhexlify(v)
    except Exception:
        return None


def script_keys(kind, wscript):
    # ordered (k1, k2, k3) pubkeys of the vault script
    if kind == 'sv':
        return parse_vault_script(wscript)['keys']
    return (lambda d: (d['k1'], d['k2'], d['k3']))(
        parse_deepvault_script(wscript))


def vault_complete(kind, wscript, signed_pks):
    # Role-based completeness (V-01/V-02 fix): count signatures by the
    # role of the pubkey that produced them, never by raw sig count.
    #   S_v: any 2 of {K1, K2, K3}
    #   S_e: K1 AND one of {K2, K3}
    keys = script_keys(kind, wscript)
    have = [i for i, k in enumerate(keys) if k in signed_pks]
    if kind == 'sv':
        return len(have) >= 2
    return 0 in have and len(have) >= 2


def vault_missing_roles(kind, wscript, signed_pks):
    keys = script_keys(kind, wscript)
    return [i for i, k in enumerate(keys) if k not in signed_pks]


def build_witness(kind, wscript, sigs_by_pk, sequence, selector=None):
    # Construct the final witness stack for a vault input.
    #
    # Stack order requirements (verified empirically against a minimal
    # Bitcoin script interpreter with real signatures - see
    # testing/witness_order_check.py - and matching Bitcoin Core's
    # EvalScript pop order):
    #   S_v: [dummy, sig_a, sig_b, selector, script]
    #        - OP_IF pops the branch selector from the TOP of the stack, so
    #          the selector must be the LAST item before the witness script.
    #          empty = FALSE -> OP_ELSE (emergency, nSequence 0xFFFFFFFD);
    #          0x01 = TRUE -> OP_IF (CSV ladder, nSequence == N).
    #        - OP_CHECKMULTISIG matches the topmost signature against the
    #          topmost (last-in-script) pubkey first, so signatures must be
    #          laid bottom-to-top in script pubkey order.
    #   S_e: [dummy, sig_other, sig_K1, script]
    #        - OP_CHECKSIGVERIFY pops K1's pubkey, then the signature
    #          directly beneath it, so K1's signature must be the TOPMOST
    #          signature. The OP_1/OP_2 CHECKMULTISIG consumes one dummy
    #          before the remaining sig.
    # The selector comes from the policy approval record (plan section
    # 1.5: the device constructs the branch it approved); when absent
    # (host tests / direct finalize calls) it is derived from nSequence,
    # which is exactly the fact the policy gate verified.
    keys = script_keys(kind, wscript)
    stack = [b'']                           # CHECKMULTISIG dummy
    if kind == 'se':
        order = [i for i in (1, 2) if keys[i] in sigs_by_pk][:1] + [0]
    else:
        order = [i for i in range(3) if keys[i] in sigs_by_pk][:2]
    for i in order:
        sig = sigs_by_pk.get(keys[i])
        if sig is None:
            raise VaultViolation('witness: missing sig for key #%d' % i)
        stack.append(bytes(sig))
    if kind == 'sv':
        if selector is None:
            cls, _n = sequence_class(sequence)
            selector = 1 if cls in ('csv', 'csv_time') else 0
        stack.append(b'\x01' if selector else b'')
    stack.append(bytes(wscript))
    return stack

# EOF
