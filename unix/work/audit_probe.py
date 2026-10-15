# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# unix/work/audit_probe.py - ASSERTION-BASED regression suite for the
# vault-cosign-policy audit findings V-01..V-07.
#
# This started life as the informational probe used during the audit
# (print-only, cases 1-5, run without an enrolled policy so its output
# was unchanged pre/post-fix by design). Phase 4 of the remediation
# plan converts it into a regression suite: every finding is now driven
# through the REAL firmware signing chain inside the simulator -
#   psbtObject.read_psbt -> validate -> consider_keys/inputs/outputs
#   -> VaultMode.could_sign gate -> sign_it -> finalize
# - with hard assertions on the fixed behavior. It complements
# unix/vault_sign_sim.py (V-01/V-02 core flows, approval-record
# binding, CCC key path) by covering the adversarial edge cases the
# audit actually found:
#
#   V-01  S_v misparse (M=19 => 'Unknown multisig wallet' pre-gate)
#   V-02  S_e misparse (M=-47 => fully_signed illusion)
#   V-03  K1 signature accepted on presence alone
#   V-04  no SIGHASH_ALL enforcement on vault partial sigs
#   V-05  witness_utxo never cross-validated (no full UTXO required)
#   V-06  ccc.py ratchet skip fail-open via check_relevance polarity
#   V-07  e2e tests bypassed the real signing path
#
# Run from unix/work:
#   MICROPYPATH=:../../shared ../coldcard-mpy -X heapsize=9m \
#       ./audit_probe.py 3 4 5 6 < /dev/null
# Exits non-zero (prints FAIL) on any regression.

import sys

# mimic sim_boot.py's nvstore setup (without the socket / main boot)
import nvstore
from sim_settings import sim_defaults
nvstore.SettingsObject.default_values = lambda _: dict(sim_defaults)
nvstore.MK4_WORKDIR = './settings/'
nvstore.SettingsObject._deny_slot = lambda *a: None

import glob
s = nvstore.SettingsObject()
s.load()
glob.settings = s

# start clean: a previous crashed run may have left a stale 'vault' key
if s.get('vault', None):
    s.remove_key('vault')
    s.save()

import struct
import binascii
import uio

def b2h(b):
    return str(binascii.hexlify(bytes(b)), 'ascii')

R = []
def ok(name, cond):
    R.append((name, bool(cond)))
    if not cond:
        print('    FAIL: %s' % name)

# ---- device identity: inject a fixed seed, log in, derive the key ----------
from sim_secel import SECRETS
import bip39
WORDS = ('abandon abandon abandon abandon abandon abandon abandon '
         'abandon abandon abandon abandon about')
seed = bip39.a2b_words(WORDS.split())
raw = bytes([0x80]) + seed + bytes(72 - 1 - len(seed))
SECRETS['_pin1_secret'] = b2h(raw)

from pincodes import pa
pa.setup('12-12')
pa.login()

import stash
import ngu
with stash.SensitiveValues() as sv:
    _node = sv.derive_path('m/123')
    K2 = bytes(_node.pubkey())          # the device's vault co-signer key
    del _node

MY_XFP = s.get('xfp', 0)

class FakeDis:
    def fullscreen(self, *a): pass
    def progress_sofar(self, *a): pass
    def progress_bar_show(self, *a): pass
    def progress_bar_hide(self, *a): pass
glob.dis = FakeDis()

# ---- keys / scripts / policy (same shapes as vault_sign_sim) ---------------
import vault_signing as vsig
import vault_policy as vp
import vault

def pub_of(priv_int):
    x, y = vsig._pmul(priv_int, vsig._G)
    return bytes([2 | (y & 1)]) + x.to_bytes(32, 'big')

K1_PRIV = bytes([0x01] * 32)
K3_PRIV = bytes([0x03] * 32)
K1 = pub_of(int.from_bytes(K1_PRIV, 'big'))
K3 = pub_of(int.from_bytes(K3_PRIV, 'big'))

N, F0_MAX = 1008, 10000

def push(b):
    return bytes([len(b)]) + b

# S_v (D-1'): OP_IF <N> OP_CSV OP_DROP OP_ELSE OP_ENDIF OP_2 K1 K2 K3 OP_3 CMS
S_V = (bytes([vp.OP_IF]) + bytes([2, N & 0xff, (N >> 8) & 0xff]) +
       bytes([vp.OP_CSV, vp.OP_DROP, vp.OP_ELSE, vp.OP_ENDIF, 0x52]) +
       push(K1) + push(K2) + push(K3) + bytes([0x53, vp.OP_CMS]))
# S_e (E-2): <K1> OP_CHECKSIGVERIFY OP_1 <K2> <K3> OP_2 OP_CMS
S_E = (push(K1) + bytes([vp.OP_CHECKSIGVERIFY, 0x51]) +
       push(K2) + push(K3) + bytes([0x52, vp.OP_CMS]))
# standard bare 2-of-3 (audit contrast case)
S_STD = bytes([0x52]) + push(K1) + push(K2) + push(K3) + bytes([0x53, vp.OP_CMS])

SPK_V, SPK_E = vp.p2wsh_spk(S_V), vp.p2wsh_spk(S_E)
EXIT_SPK = vp.p2wsh_spk(bytes([0x51]) + K1 + K2 + K3 + bytes([vp.OP_CMS]))

CFG = {'n': N, 'sv_hash': b2h(SPK_V), 'spk_e': b2h(SPK_E),
       'k1_pubkey': b2h(K1), 'f0_max': F0_MAX, 'exit_spk': b2h(EXIT_SPK)}
res, msg = vault.validate_cfg(dict(CFG))
ok('setup: cfg validates', res)
vault.save_cfg(dict(CFG, enabled=1))
ok('setup: vault mode enabled', vault.is_enabled())

# ---- PSBT v0 builder -------------------------------------------------------
def vi(n):
    if n < 253:
        return bytes([n])
    return b'\xfd' + struct.pack('<H', n)

def ct_out(spk, value):
    return struct.pack('<q', value) + vi(len(spk)) + spk

def build_tx(prevouts, seqs, outs, lock_time=0, version=2):
    r = struct.pack('<i', version) + vi(len(prevouts))
    for i, (txid, n) in enumerate(prevouts):
        r += txid + struct.pack('<I', n) + vi(0) + struct.pack('<I', seqs[i])
    r += vi(len(outs))
    for spk, value in outs:
        r += ct_out(spk, value)
    return r + struct.pack('<I', lock_time)

def kv(key, val):
    return vi(len(key)) + key + vi(len(val)) + val

def build_psbt(tx_bytes, num_outputs, input_maps):
    r = b'psbt\xff' + kv(b'\x00', tx_bytes) + b'\x00'
    for m in input_maps:
        r += m
    for _ in range(num_outputs):
        r += b'\x00'
    return r

def vault_psbt(wscript, spk, utxo_val, seq, outs, part_sigs=None,
               full_utxo=True, witness_utxo=True, wscript_override=None):
    # 1-in/1-out spend of a freshly funded P2WSH coin. part_sigs: list
    # of (pubkey, sig). full_utxo / witness_utxo / wscript_override are
    # the V-05 / V-06 adversarial knobs: drop the non-witness UTXO, or
    # attach a witness script that does NOT hash to the claimed spk.
    fund = build_tx([(b'\x00' * 32, 0)], [0xffffffff], [(spk, utxo_val)],
                    version=1)
    fund_id = bytes(ngu.hash.sha256d(fund))
    tx = build_tx([(fund_id, 0)], [seq], outs)
    m = b''
    if full_utxo:
        m += kv(b'\x00', fund)                   # PSBT_IN_NON_WITNESS_UTXO
    if witness_utxo:
        m += kv(b'\x01', ct_out(spk, utxo_val))  # PSBT_IN_WITNESS_UTXO
    for pk, sig in (part_sigs or []):
        m += kv(b'\x02' + pk, sig)               # PSBT_IN_PARTIAL_SIG
    m += kv(b'\x05', wscript_override or wscript)  # PSBT_IN_WITNESS_SCRIPT
    m += kv(b'\x06' + K1, struct.pack('<I', 0x11111111))
    m += kv(b'\x06' + K2, struct.pack('<II', MY_XFP, 123))
    m += kv(b'\x06' + K3, struct.pack('<I', 0x33333333))
    m += b'\x00'
    return build_psbt(tx, len(outs), [m])

# ---- the real firmware chain ------------------------------------------------
from psbt import psbtObject

_keep_fds = []
def parse(blob):
    fd = uio.BytesIO(blob)
    _keep_fds.append(fd)         # proxies hold offsets into the fd
    return psbtObject.read_psbt(fd)

def prep(blob):
    # exact sync chain ApproveTransaction drives before sign_it
    p = parse(blob)
    for idx, txin in p.input_iter():
        p.inputs[idx].validate(idx, txin, p.my_xfp, p)
    p.consider_keys()
    p.consider_inputs(cosign_xfp=None)
    p.consider_outputs()
    p.consider_dangerous_sighash()
    return p

def digest_of(p):
    idx, txi = list(p.input_iter())[0]
    inp = p.inputs[idx]
    return p.make_txn_segwit_sighash(idx, txi, inp.amount, inp.scriptCode, 1)

def ext_sig(priv, p):
    # real ECDSA partial signature (external co-signer) over THIS tx's
    # BIP-143 digest, produced with the firmware signing primitive
    return psbtObject.ecdsa_grind_sign(priv, digest_of(p), 1)

def final_witness(p):
    fd = uio.BytesIO()
    txid = p.finalize(fd)
    from serializations import CTransaction
    t = CTransaction()
    t.deserialize(uio.BytesIO(bytes(fd.getvalue())))
    return txid, t.wit.vtxinwit[0].scriptWitness.stack

EMG_SEQ = vp.SEQ_EMERGENCY
EMG_OUT = [(SPK_E, 10000)]       # P1: emergency pays the sink spk_e
EXIT_OUT = [(EXIT_SPK, 9000)]    # P3: exit ceremony pays exit_spk

# garbage 71-byte DER-ish blob (the audit's FAKE_SIG shape)
FAKE_SIG = b'\x30' + b'\x45' + b'\x01' * 70

# =============================================================================
print('=== A1 (V-01): S_v emergency, NO policy enrolled => fail closed')
try:
    vault.wipe()
    ok('A1: policy wiped', not vault._cfg())
    blob = vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT)
    try:
        prep(blob)
        ok('A1: no-policy vault coin refused', False)
    except Exception as e:
        # never silently co-sign a vault-shaped coin with no policy: the
        # standard M/N path refuses it (M=19 => unknown wallet) and the
        # gate never runs. Pre-fix this was the ONLY behavior (the bug
        # was that it stayed the behavior WITH a policy enrolled too).
        ok('A1: no-policy vault coin refused',
           'Unknown multisig wallet' in str(e) or 'vault' in str(e).lower())
finally:
    vault.save_cfg(dict(CFG, enabled=1))
ok('A1: policy restored', vault.is_enabled())

print('=== A2 (V-01): S_v stuffed with 19 junk partial sigs (M=19 illusion)')
try:
    junk = [(bytes([0x02]) + bytes([i]) + bytes(range(31)), FAKE_SIG)
            for i in range(19)]
    blob = vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT, part_sigs=junk)
    p = prep(blob)
    inp = p.inputs[0]
    # pre-fix: M=19 + 19 junk sigs => fully_signed => device adds nothing
    ok('A2: junk sigs do not create completeness', not inp.fully_signed)
    ok('A2: still classified sv', inp.is_vault == 'sv')
    ok('A2: device key still required', inp.required_key == {K2})
    # the gate verifies EVERY partial signature (V-03) => junk DER refuses
    appr, msg = vault.VaultMode.could_sign(parse(blob))
    ok('A2: gate refuses junk-signed vault tx', not appr)
    p2 = prep(blob)
    try:
        p2.sign_it()
        ok('A2: sign_it refused without gate approval', False)
    except Exception as e:
        ok('A2: sign_it refused without gate approval',
           'approval record' in str(e))
except Exception as e:
    ok('A2: junk-sig case', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== A3 (V-02): S_e with REAL K1 partial - no fully_signed illusion')
try:
    p0 = prep(vault_psbt(S_E, SPK_E, 9600, EMG_SEQ, EXIT_OUT))
    sig_k1 = ext_sig(K1_PRIV, p0)
    blob = vault_psbt(S_E, SPK_E, 9600, EMG_SEQ, EXIT_OUT,
                      part_sigs=[(K1, sig_k1)])
    # pre-fix: M=-47 => len(part_sigs) >= -47 => 'completely signed already'
    p = prep(blob)
    inp = p.inputs[0]
    ok('A3: classified se', inp.is_vault == 'se')
    ok('A3: not fully signed with K1 alone', not inp.fully_signed)
    ok('A3: device key (K2) still required', inp.required_key == {K2})
    appr, msg = vault.VaultMode.could_sign(p)
    ok('A3: gate approves the exit ceremony', appr and 'exit' in msg)
    p.sign_it()
    ok('A3: complete after device co-signs', p.is_complete())
    txid, stack = final_witness(p)
    # consensus order (witness_order_check.py): [dummy, sigK2, sigK1, script]
    ok('A3: witness = [dummy, sigK2, sigK1, script]',
       stack == [b'', inp.added_sigs[K2], sig_k1, S_E])
except Exception as e:
    ok('A3: S_e K1 flow', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== A4 (V-03): garbage K1 partial sig is refused, never trusted')
try:
    blob = vault_psbt(S_E, SPK_E, 9600, EMG_SEQ, EXIT_OUT,
                      part_sigs=[(K1, FAKE_SIG)])
    # presence alone must not matter: classify flags it not-complete, the
    # gate (verify_input_sigs) refuses the malformed DER outright
    p = prep(blob)
    ok('A4: garbage sig does not complete', not p.inputs[0].fully_signed)
    appr, msg = vault.VaultMode.could_sign(parse(blob))
    ok('A4: gate refuses garbage partial sig', not appr)
except Exception as e:
    ok('A4: garbage-sig case', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== A5 (V-03): well-formed K1 sig over the WRONG DIGEST is refused')
try:
    # valid strict-DER low-S SIGHASH_ALL signature by K1 - but computed
    # over a DIFFERENT transaction's BIP-143 digest (outputs swapped).
    # Presence, shape and sighash all check out; only signature
    # verification against THIS tx catches it.
    p0 = prep(vault_psbt(S_E, SPK_E, 9600, EMG_SEQ, EXIT_OUT))
    other = prep(vault_psbt(S_E, SPK_E, 9600, EMG_SEQ, [(EXIT_SPK, 8900)]))
    wrong_sig = ext_sig(K1_PRIV, other)
    blob = vault_psbt(S_E, SPK_E, 9600, EMG_SEQ, EXIT_OUT,
                      part_sigs=[(K1, wrong_sig)])
    p = prep(blob)
    ok('A5: wrong-digest sig does not complete', not p.inputs[0].fully_signed)
    appr, msg = vault.VaultMode.could_sign(parse(blob))
    ok('A5: gate refuses non-verifying partial sig',
       not appr and ('signature' in msg or 'sighash' in msg.lower()))
except Exception as e:
    ok('A5: wrong-digest case', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== A6 (V-04): valid K1 sig with grafted sighash byte is refused')
try:
    p0 = prep(vault_psbt(S_E, SPK_E, 9600, EMG_SEQ, EXIT_OUT))
    good = ext_sig(K1_PRIV, p0)
    for flag, tag in ((0x81, 'ANYONECANPAY'), (0x02, 'NONE'),
                      (0x03, 'SINGLE')):
        grafted = good[:-1] + bytes([flag])
        blob = vault_psbt(S_E, SPK_E, 9600, EMG_SEQ, EXIT_OUT,
                          part_sigs=[(K1, grafted)])
        p = prep(blob)
        appr, msg = vault.VaultMode.could_sign(parse(blob))
        ok('A6: SIGHASH_%s graft refused by gate' % tag,
           not appr and 'SIGHASH' in msg.upper())
except Exception as e:
    ok('A6: sighash graft case', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== A7 (V-05): witness_utxo-only vault input refused by the gate')
try:
    blob = vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT, full_utxo=False)
    p = prep(blob)
    ok('A7: witness-utxo-only input classifies sv', p.inputs[0].is_vault == 'sv')
    appr, msg = vault.VaultMode.could_sign(parse(blob))
    # the fee window must not be judged against attacker-asserted amounts
    ok('A7: gate demands the full (non-witness) UTXO',
       not appr and 'UTXO' in msg.upper())
except Exception as e:
    ok('A7: witness-utxo-only case', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== A8 (V-05): witness script NOT hashing to the claimed spk refused')
try:
    # the witness script is the REAL enrolled S_v (so recognize() vouches
    # for it against the cfg), but the witness_utxo claims the coin being
    # spent is the EMERGENCY sink spk_e - a different hash. The signing-
    # side pin (cfg == script == spent coin) must refuse at
    # classification, before any signature is produced
    blob = vault_psbt(S_V, SPK_E, 9600, EMG_SEQ, EMG_OUT)
    try:
        prep(blob)
        ok('A8: spk/script hash mismatch refused', False)
    except Exception as e:
        ok('A8: spk/script hash mismatch refused', 'hash' in str(e).lower())
except Exception as e:
    ok('A8: hash-mismatch case', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== A9 (V-06): ccc velocity ratchet - strict vault predicate only')
try:
    import ccc
    pol = ccc.SpendingPolicy('ccc', {'vel': 100})   # vel=100 => always refuse

    # (a) a REAL vault emergency tx skips the ratchet (vault rule layer
    # owns timing) and meets_policy succeeds
    p_real = parse(vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT))
    try:
        pol.meets_policy(p_real)
        ok('A9a: real vault tx skips velocity ratchet', True)
    except Exception as e:
        ok('A9a: real vault tx skips velocity ratchet', False)
        print('      meets_policy raised: %s' % e)

    # (b) CRAFTED shape: spk claims SPK_V, witness script is the standard
    # 2-of-3. check_relevance (the OLD call) says True - 'odd shape =>
    # relevant' - which pre-fix made meets_policy SKIP the ratchet. The
    # new strict predicate must say False so the ratchet still applies.
    p_fake = parse(vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT,
                              wscript_override=S_STD))
    ok('A9b: old relevance sniff WOULD have vouched for it',
       vault.check_relevance(p_fake, vault._cfg()))
    ok('A9b: strict predicate refuses the crafted shape',
       not vault.is_vault_psbt(p_fake, vault._cfg()))
    try:
        pol.meets_policy(p_fake)
        ok('A9b: crafted shape hit by velocity ratchet', False)
    except ccc.SpendPolicyViolation:
        ok('A9b: crafted shape hit by velocity ratchet', True)
    except Exception as e:
        # any refusal is fail-closed; only silent success is a regression
        ok('A9b: crafted shape hit by velocity ratchet', True)
        print('      (refused via %s: %s)' % (type(e).__name__, e))

    # (c) input with NO utxo data at all: strict predicate => False =>
    # ratchet applies
    p_blind = parse(vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT,
                               full_utxo=False, witness_utxo=False))
    ok('A9c: blind input not vouched for by strict predicate',
       not vault.is_vault_psbt(p_blind, vault._cfg()))
    try:
        pol.meets_policy(p_blind)
        ok('A9c: blind input hit by velocity ratchet', False)
    except Exception as e:
        ok('A9c: blind input hit by velocity ratchet', True)
except Exception as e:
    ok('A9: ratchet cases', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== A10 (V-01 routing): enrolled 2-of-3 wallet cannot hijack vault coins')
try:
    from multisig import MultisigWallet
    old_ms = s.get('multisig', None)
    rec = ['auditreg', (2, 3),
           [(0x11111111, "m/48h/0h/0h/2", "xpubFAKE1"),
            (MY_XFP, "m/48h/0h/0h/2", "xpubFAKE2"),
            (0x33333333, "m/48h/0h/0h/2", "xpubFAKE3")],
           {'ft': 2}]   # AF_P2WSH == 2
    try:
        s.put('multisig', [rec])
        s.save()
        blob = vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT)
        p = prep(blob)
        inp = p.inputs[0]
        # pre-fix the M=19 misparse meant find_match never fired; the fix
        # routes vault inputs by PUBKEY match, so a wallet over the same
        # xfps must not pull the input into the wallet signing path
        ok('A10: classified as vault, not wallet multisig',
           inp.is_vault == 'sv')
        ok('A10: device key selected by pubkey match',
           inp.required_key == {K2})
        appr, msg = vault.VaultMode.could_sign(p)
        ok('A10: gate still approves through the vault path', appr)
    finally:
        if old_ms is None:
            s.remove_key('multisig')
        else:
            s.put('multisig', old_ms)
        s.save()
except Exception as e:
    ok('A10: wallet-hijack case', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== A11 (V-07): full real-path sign - gate, signer, finalize, witness')
try:
    p0 = prep(vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT))
    sig_k1 = ext_sig(K1_PRIV, p0)
    blob = vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT,
                      part_sigs=[(K1, sig_k1)])
    p = prep(blob)                       # gate and signer on the SAME object
    appr, msg = vault.VaultMode.could_sign(p)
    ok('A11: gate approves emergency', appr and 'emergency' in msg)
    p.sign_it()
    inp = p.inputs[0]
    ok('A11: device added exactly the K2 sig',
       list(inp.added_sigs.keys()) == [K2])
    # both signatures verify against THIS tx's BIP-143 digest
    dig = digest_of(p)
    both = True
    for pk, sig in ((K1, sig_k1), (K2, inp.added_sigs[K2])):
        try:
            r, sg, sh = vsig.parse_der_sig(sig)
            both = both and sh == 1 and vsig.secp256k1_verify(pk, r, sg, dig)
        except Exception:
            both = False
    ok('A11: both final sigs strict DER + verify vs digest', both)
    txid, stack = final_witness(p)
    # emergency (ELSE) branch: selector EMPTY, immediately before script
    ok('A11: witness = [dummy, sigK1, sigK2, empty-selector, script]',
       stack == [b'', sig_k1, inp.added_sigs[K2], b'', S_V])
    ok('A11: finalize returned a txid', isinstance(txid, str) and len(txid) == 64)
except Exception as e:
    ok('A11: full real-path flow', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== A12 (T7): valid K1 sig but HIGH-S is refused (non-standard)')
try:
    p0 = prep(vault_psbt(S_E, SPK_E, 9600, EMG_SEQ, EXIT_OUT))
    low = ext_sig(K1_PRIV, p0)
    # flip to the high-S form: s' = n - s (consensus-valid but
    # non-standard - would make an approved tx unbroadcastable)
    r, sg, sh = vsig.parse_der_sig(low)
    hi = vsig._N - sg if sg < vsig._N // 2 else sg
    # re-encode minimal DER manually
    def der_int(v):
        b = v.to_bytes(32, 'big').lstrip(b'\x00') or b'\x00'
        if b[0] & 0x80:
            b = b'\x00' + b
        return b
    rb, sb = der_int(r), der_int(hi)
    body = bytes([0x02, len(rb)]) + rb + bytes([0x02, len(sb)]) + sb
    high_sig = bytes([0x30, len(body)]) + body + bytes([sh])
    ok('A12: built a genuinely high-S sig', hi > vsig._N // 2)
    blob = vault_psbt(S_E, SPK_E, 9600, EMG_SEQ, EXIT_OUT,
                      part_sigs=[(K1, high_sig)])
    p = prep(blob)
    appr, msg = vault.VaultMode.could_sign(parse(blob))
    ok('A12: gate refuses high-S partial sig',
       not appr and 'S' in msg and 'high' in msg.lower().replace('-', ''))
except Exception as e:
    ok('A12: high-S case', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== A13 (T11): mixed PSBT - vault input + normal device input refused')
try:
    # second input: a plain P2WPKH coin of the device's own vault key, so
    # prep succeeds on BOTH inputs and only the policy gate judges the
    # mixed shape (the vault classes are single-input-spend shapes)
    kh = bytes(ngu.hash.hash160(K2))
    SPK_KH = bytes([0x00, 0x14]) + kh
    fund1 = build_tx([(b'\x00' * 32, 0)], [0xffffffff], [(SPK_V, 10500)],
                     version=1)
    fund2 = build_tx([(b'\x11' * 32, 0)], [0xffffffff], [(SPK_KH, 5000)],
                     version=1)
    id1 = bytes(ngu.hash.sha256d(fund1))
    id2 = bytes(ngu.hash.sha256d(fund2))
    tx = build_tx([(id1, 0), (id2, 0)], [EMG_SEQ, 0xfffffffe],
                  [(SPK_E, 15300)])
    m1 = (kv(b'\x00', fund1) + kv(b'\x01', ct_out(SPK_V, 10500)) +
          kv(b'\x05', S_V) +
          kv(b'\x06' + K1, struct.pack('<I', 0x11111111)) +
          kv(b'\x06' + K2, struct.pack('<II', MY_XFP, 123)) +
          kv(b'\x06' + K3, struct.pack('<I', 0x33333333)) + b'\x00')
    m2 = (kv(b'\x00', fund2) + kv(b'\x01', ct_out(SPK_KH, 5000)) +
          kv(b'\x06' + K2, struct.pack('<II', MY_XFP, 123)) + b'\x00')
    blob = build_psbt(tx, 1, [m1, m2])
    try:
        p = prep(blob)
        appr, msg = vault.VaultMode.could_sign(p)
        ok('A13: mixed vault+normal shape refused by gate', not appr)
    except Exception as e:
        # refusal at the signing chain is equally fail-closed
        ok('A13: mixed vault+normal shape refused by gate', True)
        print('      (refused at prep: %s)' % e)
except Exception as e:
    ok('A13: mixed-input case', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== A14 (4.4 fuzz): random mutations never sign without approval')
try:
    # deterministic LCG (no dependence on the sim's random module)
    _st = [0x5eed1234]
    def rnd(n):
        _st[0] = (_st[0] * 1103515245 + 12345) & 0x7fffffff
        return _st[0] % n

    p0 = prep(vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT))
    sig_k1 = ext_sig(K1_PRIV, p0)
    base = bytearray(vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT,
                                part_sigs=[(K1, sig_k1)]))
    refusals = approvals = 0
    invariant_ok = True
    # mute the parser's chatty 'no key:' diagnostics for mutated junk
    # (they are refusals, not errors - we count them, no need to see 100):
    # shadow the builtin print inside the psbt module for the loop
    import psbt as _psbt_mod
    _psbt_mod.print = lambda *a, **k: None
    try:
        for it in range(200):
            blob = bytearray(base)
            for _ in range(1 + rnd(3)):        # 1-3 byte mutations
                pos = rnd(len(blob))
                blob[pos] = rnd(256)
            signed = False
            try:
                p = prep(bytes(blob))
                appr, msg = vault.VaultMode.could_sign(p)
                if appr:
                    approvals += 1
                    p.sign_it()
                    signed = True
            except Exception:
                refusals += 1
            if signed:
                # the ONLY way to have signed is gate approval on this very
                # object (sign_it re-checks the approval record itself, so
                # reaching here means the record matched the mutated tx)
                rec = getattr(p, 'vault_approval', None)
                if not isinstance(rec, dict):
                    invariant_ok = False
                    print('      iter %d: signed with no approval record!' % it)
    finally:
        del _psbt_mod.print
    ok('A14: 200 mutations - all outcomes clean (refusals=%d approved=%d)'
       % (refusals, approvals), invariant_ok)
    ok('A14: mutation surface is live (not all-refused, not all-approved)',
       refusals > 50 and approvals < 200)
except Exception as e:
    ok('A14: fuzz case', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== A15 (vout != input idx): vault coin at a nonzero prevout vout ===')
try:
    # found by the Core-regtest oracle: get_utxo(n) indexes the FUNDING
    # tx's outputs, so every vault read must use txin.prevout.n - with
    # the input POSITION instead, a coin funded at vout=1 made the
    # relevance sniff miss it ('not vault-relevant' => gate skipped =>
    # sign_it refused with no approval record: unspendable-but-safe).
    # Fund at vout=1 and require the full approve+sign flow to work.
    sink = bytes([0x51]) + K1 + K2 + K3 + bytes([vp.OP_CMS])
    fund = build_tx([(b'\x00' * 32, 0)], [0xffffffff],
                    [(vp.p2wsh_spk(sink), 55555), (SPK_V, 10500)], version=1)
    fund_id = bytes(ngu.hash.sha256d(fund))
    tx = build_tx([(fund_id, 1)], [EMG_SEQ], EMG_OUT)      # spends vout 1
    m = (kv(b'\x00', fund) + kv(b'\x01', ct_out(SPK_V, 10500)) +
         kv(b'\x05', S_V) +
         kv(b'\x06' + K1, struct.pack('<I', 0x11111111)) +
         kv(b'\x06' + K2, struct.pack('<II', MY_XFP, 123)) +
         kv(b'\x06' + K3, struct.pack('<I', 0x33333333)) + b'\x00')
    blob = build_psbt(tx, 1, [m])
    p = prep(blob)
    ok('A15: vout=1 coin classified sv', p.inputs[0].is_vault == 'sv')
    appr, msg = vault.VaultMode.could_sign(p)
    ok('A15: relevance sees the vout=1 vault coin',
       appr and 'emergency' in msg)
    ok('A15: approval record left on the object',
       isinstance(getattr(p, 'vault_approval', None), dict))
    p.sign_it()
    ok('A15: device signs the vout=1 coin',
       list(p.inputs[0].added_sigs.keys()) == [K2])
except Exception as e:
    ok('A15: nonzero-vout case', False)
    print('      %s: %s' % (type(e).__name__, e))

# ---- tally -------------------------------------------------------------------
fails = [name for name, cond in R if not cond]
print('\n%s: %d/%d checks pass' % ('AUDIT REGRESSION (V-01..V-07)',
                                   len(R) - len(fails), len(R)))
if fails:
    print('FAILED:')
    for f in fails:
        print('  - %s' % f)
    sys.exit(1)
