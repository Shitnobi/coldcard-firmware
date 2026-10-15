# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# unix/vault_core_sign.py - sim-side helper for the Bitcoin Core regtest
# oracle (unix/vault_core_oracle.py, remediation plan section 4.2).
#
# The oracle funds the device's enrolled vault scriptPubKey on a real
# regtest chain and then asks the SIMULATOR - through the full real
# firmware signing chain (read_psbt -> validate -> consider_* ->
# VaultMode.could_sign -> sign_it -> finalize) - to co-sign the
# emergency spend of that coin. The oracle submits the result with
# testmempoolaccept/sendrawtransaction: any policy-valid-but-consensus-
# invalid combination (the audit's class 3) fails the oracle.
#
# Two modes, selected by the presence of unix/work/core_oracle_request.json:
#   - dump:  derive the device vault key (fixed seed) and write
#            core_oracle_ctx.json (K2 pubkey, S_v/S_e scriptPubKeys)
#   - sign:  read the request (real funding txid/vout/amount + raw
#            funding tx), build the requested spend PSBT against that
#            REAL outpoint, run the real signing chain, write
#            core_oracle_response.json (signed raw tx hex).
#            Request field 'spend' selects the class (G-1 coverage):
#              'emergency' (default): P1 sink spend, nSequence
#                 0xFFFFFFFD, output pinned to spk_e
#              'ladder': P2 CSV spend, nSequence == N (height form),
#                 nVersion 2 (BIP-68/112), output to request 'dest_spk'
#
# Run from unix/work:
#   MICROPYPATH=:../../shared ../coldcard-mpy -X heapsize=9m \
#       ../vault_core_sign.py 3 4 5 6 < /dev/null
import sys

import nvstore
from sim_settings import sim_defaults
nvstore.SettingsObject.default_values = lambda _: dict(sim_defaults)
nvstore.MK4_WORKDIR = './settings/'
nvstore.SettingsObject._deny_slot = lambda *a: None

import glob
s = nvstore.SettingsObject()
s.load()
glob.settings = s

if s.get('vault', None):
    s.remove_key('vault')
    s.save()

import struct
import binascii
import uio
import json

def b2h(b):
    return str(binascii.hexlify(bytes(b)), 'ascii')

def h2b(h):
    return binascii.unhexlify(h)

# ---- device identity (fixed seed, same as every vault sim suite) ------------
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

S_V = (bytes([vp.OP_IF]) + bytes([2, N & 0xff, (N >> 8) & 0xff]) +
       bytes([vp.OP_CSV, vp.OP_DROP, vp.OP_ELSE, vp.OP_ENDIF, 0x52]) +
       push(K1) + push(K2) + push(K3) + bytes([0x53, vp.OP_CMS]))
S_E = (push(K1) + bytes([vp.OP_CHECKSIGVERIFY, 0x51]) +
       push(K2) + push(K3) + bytes([0x52, vp.OP_CMS]))
SPK_V, SPK_E = vp.p2wsh_spk(S_V), vp.p2wsh_spk(S_E)

CFG = {'n': N, 'sv_hash': b2h(SPK_V), 'spk_e': b2h(SPK_E),
       'k1_pubkey': b2h(K1), 'f0_max': F0_MAX,
       'exit_spk': b2h(vp.p2wsh_spk(bytes([0x51]) + K1 + K2 + K3 +
                                    bytes([vp.OP_CMS])))}

try:
    import os
    have_request = 'core_oracle_request.json' in os.listdir('.')
except Exception:
    have_request = False

if not have_request:
    # ---- dump mode: publish the device's vault commitments -----------------
    ctx = {'k2_pubkey': b2h(K2), 'k1_pubkey': b2h(K1), 'k3_pubkey': b2h(K3),
           'spk_v': b2h(SPK_V), 'spk_e': b2h(SPK_E),
           's_v': b2h(S_V), 's_e': b2h(S_E), 'n': N, 'f0_max': F0_MAX,
           'xfp': MY_XFP}
    with open('core_oracle_ctx.json', 'w') as f:
        f.write(json.dumps(ctx))
    print('CORE ORACLE CTX: k2=%s... spk_v=%s...' % (ctx['k2_pubkey'][:16],
                                                     ctx['spk_v'][:16]))
    sys.exit(0)

# ---- sign mode: co-sign the real outpoint ----------------------------------
with open('core_oracle_request.json') as f:
    req = json.loads(f.read())

# display-order txid (what bitcoind prints) -> internal byte order (what
# the tx serialization / deser_uint256 uses). mpy has no negative-step
# slices, so reverse byte-by-byte
_b = h2b(req['txid'])
prev_hash = bytes([_b[i] for i in range(len(_b) - 1, -1, -1)])
vout = int(req['vout'])
amount = int(req['amount_sat'])
funding_tx = h2b(req['funding_hex'])
FEE = 300                                  # well inside the f0_max window
# G-1: which policy class to co-sign. 'ladder' spends via the CSV branch
# (nSequence == N, nVersion 2) to the request-supplied destination; the
# default 'emergency' shape is unchanged.
SPEND = req.get('spend', 'emergency')
DEST = h2b(req['dest_spk']) if req.get('dest_spk') else None

vault.save_cfg(dict(CFG, enabled=1))

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

def make_psbt(part_sigs=None):
    # P1 emergency: nSequence 0xFFFFFFFD (CSV disabled) -> S_v ELSE branch,
    #              output pinned to the sink spk_e.
    # P2 ladder (G-1): nSequence == N (height-form CSV) -> S_v IF branch,
    #              nVersion 2 (BIP-68/112: OP_CSV cannot execute below it),
    #              output to the request-supplied dest_spk (INV-SINK forbids
    #              spk_e on non-emergency classes; a plain withdrawal dest
    #              is the canonical ladder shape).
    if SPEND == 'ladder':
        assert DEST is not None, "ladder request needs 'dest_spk'"
        seq, dest = N, DEST
    else:
        seq, dest = vp.SEQ_EMERGENCY, SPK_E
    tx = build_tx([(prev_hash, vout)], [seq],
                  [(dest, amount - FEE)])
    m = b''
    m += kv(b'\x00', funding_tx)               # full (non-witness) UTXO
    m += kv(b'\x01', ct_out(SPK_V, amount))    # witness utxo
    for pk, sig in (part_sigs or []):
        m += kv(b'\x02' + pk, sig)
    m += kv(b'\x05', S_V)
    m += kv(b'\x06' + K1, struct.pack('<I', 0x11111111))
    m += kv(b'\x06' + K2, struct.pack('<II', MY_XFP, 123))
    m += kv(b'\x06' + K3, struct.pack('<I', 0x33333333))
    m += b'\x00'
    r = b'psbt\xff' + kv(b'\x00', tx) + b'\x00' + m + b'\x00'
    return r

from psbt import psbtObject

def parse(blob):
    return psbtObject.read_psbt(uio.BytesIO(blob))

def prep(blob):
    p = parse(blob)
    for idx, txin in p.input_iter():
        p.inputs[idx].validate(idx, txin, p.my_xfp, p)
    p.consider_keys()
    p.consider_inputs(cosign_xfp=None)
    p.consider_outputs()
    p.consider_dangerous_sighash()
    return p

# pass 1: digest for the external K1 signature (same object shape, no sigs)
p0 = prep(make_psbt())
idx, txi = list(p0.input_iter())[0]
inp = p0.inputs[idx]
digest = p0.make_txn_segwit_sighash(idx, txi, inp.amount, inp.scriptCode, 1)
sig_k1 = psbtObject.ecdsa_grind_sign(K1_PRIV, digest, 1)

# pass 2: the real signing chain on the SAME object the gate judged
p = prep(make_psbt(part_sigs=[(K1, sig_k1)]))
appr, msg = vault.VaultMode.could_sign(p)
if not appr:
    print('CORE ORACLE FAIL: gate refused: %s' % msg)
    sys.exit(1)
p.sign_it()
if not p.is_complete():
    print('CORE ORACLE FAIL: not complete after device signature')
    sys.exit(1)

fd = uio.BytesIO()
txid = p.finalize(fd)
signed_hex = b2h(bytes(fd.getvalue()))

resp = {'signed_hex': signed_hex, 'txid': txid, 'class': msg,
        'fee': FEE, 'amount': amount}
with open('core_oracle_response.json', 'w') as f:
    f.write(json.dumps(resp))
print('CORE ORACLE SIGNED: %s (%s)' % (txid, msg))
