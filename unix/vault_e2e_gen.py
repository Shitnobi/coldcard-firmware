#!/usr/bin/env python3
# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# unix/vault_e2e_gen.py - host-side generator for the simulator end-to-end run.
#
# Builds REAL binary PSBT files (BIP-174 v0) covering every vault policy
# class, plus expected.json (the lattice root, computed here via the same
# pure vault_policy module, and per-file expected gate outcomes). The
# device-side driver (unix/vault_sim_e2e.py) parses these files with the
# real firmware psbtObject and runs the full vault flow against them.
#
# Phase 2 fixture requirements (V-05 fail-closed view_from_psbt):
#   - every vault-relevant input carries BOTH the full non-witness UTXO
#     (P1/P3 fee windows refuse witness-utxo-only inputs) and the witness
#     script (a witness-utxo-only claim without script is "could be a
#     hidden vault coin" => relevant => refused)
#   - non-vault inputs carry a full UTXO + witness script too, so the
#     relevance sniff can verify their (foreign) spk and classify them
#     as truly not vault-relevant
#   - exit.psbt's K1 partial signature is a REAL deterministic ECDSA
#     signature over the BIP-143 digest of that exact leaf (V-03: the
#     device cryptographically verifies partial sigs, so a fake blob
#     would be refused)
#
# Run:  python3 unix/vault_e2e_gen.py [outdir]
#       (default outdir: unix/work/sim-e2e)

import os, sys, json, hashlib, struct

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'shared'))
import vault_policy as vp
import vault_signing as vsig

# ---- the enrolled policy (mirrors what the device enrolls) ----------------
# keys are REAL curve points (derived from explicit private keys on the
# host) so partial signatures can be produced and device-verified
K1_PRIV = bytes(range(1, 33))
K2_PRIV = bytes(range(33, 65))
K3_PRIV = bytes(range(65, 97))

def pub_of(priv):
    x, y = vsig._pmul(int.from_bytes(priv, 'big'), vsig._G)
    return bytes([2 | (y & 1)]) + x.to_bytes(32, 'big')

K1, K2, K3 = pub_of(K1_PRIV), pub_of(K2_PRIV), pub_of(K3_PRIV)
N = 1008
F0_MAX = 10000

def push(b):
    return bytes([len(b)]) + b


# S_e (E-2): <K1> OP_CHECKSIGVERIFY OP_1 <K2> <K3> OP_2 OP_CMS - 106 bytes
S_E = (push(K1) + bytes([vp.OP_CHECKSIGVERIFY, 0x51]) + push(K2) + push(K3) +
       bytes([0x52, vp.OP_CMS]))
assert len(S_E) == 106
vp.parse_deepvault_script(S_E)          # structural self-check

# S_v (D-1'): OP_IF <N> OP_CSV OP_DROP OP_ELSE OP_ENDIF OP_2 K1 K2 K3 OP_3 CMS
N_PUSH = bytes([2, N & 0xff, (N >> 8) & 0xff])
S_V = (bytes([vp.OP_IF]) + N_PUSH +
       bytes([vp.OP_CSV, vp.OP_DROP, vp.OP_ELSE, vp.OP_ENDIF, 0x52]) +
       push(K1) + push(K2) + push(K3) + bytes([0x53, vp.OP_CMS]))
assert 111 <= len(S_V) <= 140
vp.parse_vault_script(S_V)

SPK_V = vp.p2wsh_spk(S_V)
SPK_E = vp.p2wsh_spk(S_E)
EXIT_SPK = vp.p2wsh_spk(bytes([0x51]) + K1 + K2 + K3 + bytes([vp.OP_CMS]))
OTHER_SCRIPT = b'\x51' + b'\x00' * 40
OTHER_SPK = vp.p2wsh_spk(OTHER_SCRIPT)   # unrelated destination


def vi(n):
    # bitcoin compact size
    if n < 253:
        return bytes([n])
    if n < 0x10000:
        return b'\xfd' + struct.pack('<H', n)
    assert n < 0x100000000
    return b'\xfe' + struct.pack('<I', n)


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def build_tx(prevouts, seqs, outs, lock_time=0, version=2):
    # Legacy (no witness marker) unsigned-tx serialization.
    assert len(prevouts) == len(seqs)
    r = struct.pack('<i', version)
    r += vi(len(prevouts))
    for i, (txid, n) in enumerate(prevouts):
        r += txid + struct.pack('<I', n) + vi(0) + struct.pack('<I', seqs[i])
    r += vi(len(outs))
    for (spk, value) in outs:
        r += struct.pack('<q', value) + vi(len(spk)) + spk
    r += struct.pack('<I', lock_time)
    return r


def ct_out(spk, value):
    return struct.pack('<q', value) + vi(len(spk)) + spk


def kv(key, value):
    # one PSBT key-value pair
    return vi(len(key)) + key + vi(len(value)) + value


def der_int(i):
    b = i.to_bytes((i.bit_length() + 7) // 8 or 1, 'big')
    if b[0] & 0x80:
        b = b'\x00' + b
    return b


def der_sig(r, s):
    return (b'\x30' + bytes([4 + len(der_int(r)) + len(der_int(s))]) +
            b'\x02' + bytes([len(der_int(r))]) + der_int(r) +
            b'\x02' + bytes([len(der_int(s))]) + der_int(s))


def sign_digest(priv, digest):
    # deterministic (hash-based nonce) low-S ECDSA; SIGHASH_ALL appended.
    # Verified on-device by vault_signing.secp256k1_verify (V-03 path).
    d = int.from_bytes(priv, 'big')
    z = int.from_bytes(digest, 'big')
    k = int.from_bytes(hashlib.sha256(digest + priv).digest(), 'big') % vsig._N
    while True:
        R = vsig._pmul(k, vsig._G)
        r = R[0] % vsig._N
        s = (vsig._inv(k) * (z + r * d)) % vsig._N if r else 0
        if r and s:
            if s > vsig._N // 2:
                s = vsig._N - s       # low-S (BIP62 / check_sighash_all)
            return der_sig(r, s) + b'\x01'
        k = (k + 1) % vsig._N


def bip143_digest(prevout, seq, outs, amount, wscript, version=2, lock_time=0):
    # BIP-143 sighash for a 1-input SIGHASH_ALL spend; must byte-match the
    # device's psbtObject.make_txn_segwit_sighash over the same tx.
    txid, vout = prevout
    hp = dsha(txid + struct.pack('<I', vout))
    hs = dsha(struct.pack('<I', seq))
    ho = dsha(b''.join(ct_out(spk, val) for spk, val in outs))
    pre = (struct.pack('<i', version) + hp + hs +
           txid + struct.pack('<I', vout) +
           vi(len(wscript)) + wscript +
           struct.pack('<q', amount) +
           struct.pack('<I', seq) + ho +
           struct.pack('<I', lock_time) + struct.pack('<I', 1))
    return dsha(pre)


def build_psbt(tx_bytes, num_outputs, input_maps):
    # BIP-174 v0: globals(UNSIGNED_TX) + per-input maps + per-output maps.
    assert all(input_maps), 'every input map must be non-empty'
    r = b'psbt\xff'
    r += vi(1) + b'\x00' + vi(len(tx_bytes)) + tx_bytes
    r += b'\x00'                              # end of globals
    for im in input_maps:
        r += im + b'\x00'                     # this input map + terminator
    for o in range(num_outputs):
        r += b'\x00'                          # empty output map
    return r


def mk(prevout_seed, utxo_spk, utxo_val, seq, outs, lock_time=0,
       partial_sigs=None, wscript=None, k1_sign=False):
    # one-input PSBT with a FULL utxo: the prevout is the txid of a funding
    # tx that pays (utxo_spk, utxo_val), which is included in the input map
    # as PSBT_IN_NON_WITNESS_UTXO so the device can txid-cross-check it.
    fund = build_tx([(hashlib.sha256(b'e2e:fund:%d' % prevout_seed).digest(), 0)],
                    [0xffffffff], [(utxo_spk, utxo_val)], version=1)
    fund_id = dsha(fund)
    tx = build_tx([(fund_id, 0)], [seq], outs, lock_time=lock_time)

    im = kv(b'\x00', fund)                          # NON_WITNESS_UTXO
    im += kv(b'\x01', ct_out(utxo_spk, utxo_val))   # WITNESS_UTXO
    if wscript:
        im += kv(b'\x05', wscript)                  # WITNESS_SCRIPT
    if k1_sign:
        # real K1 signature over THIS leaf's BIP-143 digest
        dg = bip143_digest((fund_id, 0), seq, outs, utxo_val, wscript,
                           lock_time=lock_time)
        im += kv(b'\x02' + K1, sign_digest(K1_PRIV, dg))
    for pk, sig in (partial_sigs or {}):
        im += kv(b'\x02' + pk, sig)
    return build_psbt(tx, len(outs), [im])


EMG = vp.SEQ_EMERGENCY

def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    files = {}

    # lattice members: 5 compliant emergency exits (P1), distinct fees/prevouts
    for i in range(5):
        fee = 500 + 13 * i
        files['emg%d.psbt' % i] = mk(
            1000 + i, SPK_V, 10000 + fee, EMG, [(SPK_E, 10000)], wscript=S_V)

    # P3 exit ceremony: spends the sink, real K1 partial sig present
    files['exit.psbt'] = mk(
        2000, SPK_E, 9000 + 600, EMG, [(EXIT_SPK, 9000)],
        wscript=S_E, k1_sign=True)

    # INV-SEQ: correct-N ladder withdrawal (approved)
    files['ladder_ok.psbt'] = mk(
        3000, SPK_V, 50000, N, [(OTHER_SPK, 49000)], wscript=S_V)

    # INV-SEQ: wrong-N ladder (refused)
    files['ladder_bad.psbt'] = mk(
        3100, SPK_V, 50000, N - 10, [(OTHER_SPK, 49000)], wscript=S_V)

    # INV-SINK: ladder-shaped tx paying the sink (refused)
    files['sink_ladder.psbt'] = mk(
        3200, SPK_V, 50000, N, [(SPK_E, 49000)], wscript=S_V)

    # nLockTime != 0 on an otherwise-compliant emergency (refused)
    files['emg_lt.psbt'] = mk(
        3300, SPK_V, 10500, EMG, [(SPK_E, 10000)], lock_time=5, wscript=S_V)

    # non-vault spend (unrelated input, full utxo + script so the
    # relevance sniff can verify it): passes gate in non-strict mode
    files['novault.psbt'] = mk(
        4000, OTHER_SPK, 8000, 0xFFFFFFFE, [(OTHER_SPK, 7500)],
        wscript=OTHER_SCRIPT)

    for name, blob in files.items():
        with open(os.path.join(outdir, name), 'wb') as fd:
            fd.write(blob)

    # lattice root over the 5 emergency members - computed HERE, on the host,
    # from the exact raw unsigned-tx bytes inside the generated PSBTs
    leaves = []
    for i in range(5):
        blob = files['emg%d.psbt' % i]
        assert blob[:5] == b'psbt\xff'
        # locate UNSIGNED_TX (key 0x00) value in the globals map
        p = 5
        assert blob[p] == 1 and blob[p + 1] == 0      # keylen 1, key 0x00
        p += 2
        vlen = blob[p]
        tx = blob[p + 1:p + 1 + vlen]
        leaves.append(vp.leaf_hash(i, tx))
    root, count = vp.lattice_root(iter(leaves))

    # self-check: the K1 signature in exit.psbt verifies against the
    # enrolled pubkey over the exact digest the device will recompute
    blob = files['exit.psbt']
    fund = build_tx([(hashlib.sha256(b'e2e:fund:%d' % 2000).digest(), 0)],
                    [0xffffffff], [(SPK_E, 9600)], version=1)
    dg = bip143_digest((dsha(fund), 0), EMG, [(EXIT_SPK, 9000)], 9600, S_E)
    sig = sign_digest(K1_PRIV, dg)
    assert kv(b'\x02' + K1, sig) in blob
    r, s, sh = vsig.parse_der_sig(sig)
    assert sh == 1
    assert vsig.secp256k1_verify(K1, r, s, dg), 'generator self-check: K1 sig'
    print('self-check: exit.psbt K1 signature verifies (BIP-143 host==device math)')

    cfg = {
        'n': N,
        'sv_hash': vp.p2wsh_spk(S_V).hex(),
        'spk_e': SPK_E.hex(),
        'k1_pubkey': K1.hex(),
        'f0_max': F0_MAX,
        'exit_spk': EXIT_SPK.hex(),
    }
    expect = [
        # (file, expect_approve, msg_substring, note)
        ('emg0.psbt',     True,  'emergency',      'P1 compliant emergency exit'),
        ('exit.psbt',     True,  'exit ceremony',  'P3 exit ceremony w/ real K1 sig'),
        ('ladder_ok.psbt', True, 'ladder',         'INV-SEQ correct-N ladder'),
        ('ladder_bad.psbt', False, 'nSequence != N', 'wrong-N ladder refused'),
        ('sink_ladder.psbt', False, 'sink entry',  'INV-SINK refused'),
        ('emg_lt.psbt',   False, 'nLockTime == 0', 'locktime pin refused'),
        ('novault.psbt',  True,  'not vault-relevant', 'non-vault passes (non-strict)'),
    ]
    out = {
        'cfg': cfg,
        'lattice_root': root.hex(),
        'lattice_count': count,
        'expect': expect,
        'strict_expect': ['novault.psbt', False, 'strict'],
        'ccc_vel': [
            ['emg0.psbt', True,  'vault tx skips velocity ratchet'],
            ['novault.psbt', False, 'non-vault tx hit by velocity ratchet'],
        ],
    }
    with open(os.path.join(outdir, 'expected.json'), 'w') as fd:
        json.dump(out, fd, indent=1)

    print('wrote %d PSBTs + expected.json to %s' % (len(files), outdir))
    print('lattice root (host): %s count=%d' % (root.hex(), count))
    print('S_v len=%d S_e len=%d' % (len(S_V), len(S_E)))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else
         os.path.join(HERE, 'work', 'sim-e2e'))
