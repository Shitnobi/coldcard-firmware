# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# unix/work/audit2_probe.py - REGRESSION SUITE for the validity audit #2
# findings (W-01..W-06), driving each through the REAL firmware signing
# chain inside the simulator:
#   psbtObject.read_psbt -> validate -> consider_keys/inputs/outputs
#   -> VaultMode.could_sign gate -> sign_it -> finalize
#
#   W-01  ladder class must require tx nVersion >= 2 (BIP-68/112:
#         OP_CSV cannot execute on a v1 transaction)
#   W-02  ladder class must require full (txid-cross-checked) UTXOs -
#         the BIP-143 digest embeds nValue, so a witness-utxo-only
#         claim would bind the co-signature to a lie
#   W-03  ladder fee floor: zero-fee txs are non-standard. (Documented
#         decision: NO ceiling for ladders - post-cadence a 2-of-3
#         quorum can withdraw everything anyway; B3 pins the behavior)
#   W-04  dust outputs and below-min-relay fees refused in every class,
#         so "policy-approved" implies "broadcastable"
#   W-05  enrollment refuses sv_hash == spk_e (emergency self-lock)
#   W-06  (design, pinned) ladders allow foreign inputs / arbitrary
#         destinations - withdrawal-to-anywhere post-N is the S_v design
#
# Run from unix/work:
#   MICROPYPATH=:../../shared ../coldcard-mpy -X heapsize=9m \
#       ./audit2_probe.py 3 4 5 6 < /dev/null
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
    K2 = bytes(_node.pubkey())
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
# foreign (non-vault) 2-of-3 with no device key
FK1 = pub_of(0x05)
FK2 = pub_of(0x07)
S_STD = bytes([0x52]) + push(FK1) + push(FK2) + push(K3) + bytes([0x53, vp.OP_CMS])

SPK_V, SPK_E = vp.p2wsh_spk(S_V), vp.p2wsh_spk(S_E)
SPK_STD = vp.p2wsh_spk(S_STD)
EXIT_SPK = vp.p2wsh_spk(bytes([0x51]) + K1 + K2 + K3 + bytes([vp.OP_CMS]))
FOREIGN_OUT = vp.p2wsh_spk(bytes([0x51]) + FK1)   # arbitrary destination

CFG = {'n': N, 'sv_hash': b2h(SPK_V), 'spk_e': b2h(SPK_E),
       'k1_pubkey': b2h(K1), 'f0_max': F0_MAX, 'exit_spk': b2h(EXIT_SPK)}
res, msg = vault.validate_cfg(dict(CFG))
assert res, msg
vault.save_cfg(dict(CFG, enabled=1))
ok('setup: cfg validates', vault.validate_cfg(dict(CFG))[0])
ok('setup: impl version 4', vault.VAULT_IMPL_VERSION == 4)

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

def fund_tx(spk, val):
    fund = build_tx([(b'\x00' * 32, 0)], [0xffffffff], [(spk, val)],
                    version=1)
    return fund, bytes(ngu.hash.sha256d(fund))

def vault_psbt(wscript, spk, utxo_val, seq, outs, part_sigs=None,
               full_utxo=True, witness_utxo=True, wu_amount=None,
               version=2):
    # 1-in/1-out spend of a freshly funded P2WSH coin. wu_amount
    # overrides the witness-utxo's claimed value (W-02 case).
    fund, fund_id = fund_tx(spk, utxo_val)
    tx = build_tx([(fund_id, 0)], [seq], outs, version=version)
    m = b''
    if full_utxo:
        m += kv(b'\x00', fund)
    if witness_utxo:
        m += kv(b'\x01', ct_out(spk, wu_amount if wu_amount else utxo_val))
    for pk, sig in (part_sigs or []):
        m += kv(b'\x02' + pk, sig)
    m += kv(b'\x05', wscript)
    m += kv(b'\x06' + K1, struct.pack('<I', 0x11111111))
    m += kv(b'\x06' + K2, struct.pack('<II', MY_XFP, 123))
    m += kv(b'\x06' + K3, struct.pack('<I', 0x33333333))
    m += b'\x00'
    return build_psbt(tx, len(outs), [m])

def mixed_psbt(vault_val, foreign_val, outs):
    # 2-in spend: vault coin (seq N) + foreign coin (seq N)
    _, vid = fund_tx(SPK_V, vault_val)
    _, fid = fund_tx(SPK_STD, foreign_val)
    tx = build_tx([(vid, 0), (fid, 0)], [N, N], outs)
    mv = (kv(b'\x00', fund_tx(SPK_V, vault_val)[0]) +
          kv(b'\x01', ct_out(SPK_V, vault_val)) +
          kv(b'\x05', S_V) +
          kv(b'\x06' + K1, struct.pack('<I', 0x11111111)) +
          kv(b'\x06' + K2, struct.pack('<II', MY_XFP, 123)) +
          kv(b'\x06' + K3, struct.pack('<I', 0x33333333)) + b'\x00')
    mf = (kv(b'\x00', fund_tx(SPK_STD, foreign_val)[0]) +
          kv(b'\x01', ct_out(SPK_STD, foreign_val)) +
          kv(b'\x05', S_STD) +
          kv(b'\x06' + FK1, struct.pack('<I', 0x55555555)) +
          kv(b'\x06' + FK2, struct.pack('<I', 0x66666666)) + b'\x00')
    return build_psbt(tx, len(outs), [mv, mf])

from psbt import psbtObject

_keep_fds = []
def parse(blob):
    fd = uio.BytesIO(blob)
    _keep_fds.append(fd)
    return psbtObject.read_psbt(fd)

def prep(blob):
    p = parse(blob)
    for idx, txin in p.input_iter():
        p.inputs[idx].validate(idx, txin, p.my_xfp, p)
    p.consider_keys()
    p.consider_inputs(cosign_xfp=None)
    p.consider_outputs()
    p.consider_dangerous_sighash()
    return p

def digest_of(p, idx=0):
    _, txi = list(p.input_iter())[idx]
    inp = p.inputs[idx]
    return p.make_txn_segwit_sighash(idx, txi, inp.amount, inp.scriptCode, 1)

def ext_sig(priv, p):
    return psbtObject.ecdsa_grind_sign(priv, digest_of(p), 1)

def full_flow(blob, label):
    # prep -> gate -> sign -> finalize; returns (approved, msg, tx or None)
    p = prep(blob)
    appr, msg = vault.VaultMode.could_sign(p)
    if not appr:
        return False, msg, None
    p.sign_it()
    fd = uio.BytesIO()
    txid = p.finalize(fd)
    from serializations import CTransaction
    t = CTransaction()
    t.deserialize(uio.BytesIO(bytes(fd.getvalue())))
    return True, msg, t

EMG_SEQ = vp.SEQ_EMERGENCY
LADDER_OUT = [(SPK_V, 10000)]

# mute the simulator DEBUG 'no key:' prints (DEBUG is True under sim)
import psbt as _psbt_mod
_psbt_mod.print = lambda *a, **k: None

# =============================================================================
print('=== B7 (control): ladder nVersion == 2 - the valid path')
try:
    p0 = prep(vault_psbt(S_V, SPK_V, 10500, N, LADDER_OUT))
    sig_k1 = ext_sig(K1_PRIV, p0)
    blob = vault_psbt(S_V, SPK_V, 10500, N, LADDER_OUT,
                      part_sigs=[(K1, sig_k1)])
    appr, msg, t = full_flow(blob, 'B7')
    ok('B7: v2 ladder approved', appr and 'ladder' in msg)
    ok('B7: finalized nVersion == 2', t is not None and t.nVersion == 2)
    ok('B7: witness selector 0x01 (CSV branch)',
       t.wit.vtxinwit[0].scriptWitness.stack[3] == b'\x01')
except Exception as e:
    ok('B7: v2 ladder flow', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== B8 (control): emergency nVersion == 1 (ELSE branch: no CSV)')
try:
    p0 = prep(vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, [(SPK_E, 10000)],
                         version=1))
    sig_k3 = ext_sig(K3_PRIV, p0)       # S_v is 2-of-3 in both branches
    blob = vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, [(SPK_E, 10000)],
                      part_sigs=[(K3, sig_k3)], version=1)
    appr, msg, t = full_flow(blob, 'B8')
    # consensus-valid: the ELSE branch executes no OP_CSV, and seq
    # 0xFFFFFFFD carries the BIP-68 disable flag
    ok('B8: v1 emergency still approved (valid: no CSV executed)', appr)
except Exception as e:
    ok('B8: v1 emergency flow', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== B1 (W-01): ladder nVersion == 1 refused (OP_CSV needs v>=2)')
try:
    p0 = prep(vault_psbt(S_V, SPK_V, 10500, N, LADDER_OUT, version=1))
    sig_k1 = ext_sig(K1_PRIV, p0)
    blob = vault_psbt(S_V, SPK_V, 10500, N, LADDER_OUT,
                      part_sigs=[(K1, sig_k1)], version=1)
    appr, msg, t = full_flow(blob, 'B1')
    ok('B1: v1 ladder refused', not appr)
    ok('B1: reason mentions nVersion',
       'version' in msg.lower())
    ok('B1: nothing finalized', t is None)
except Exception as e:
    ok('B1: v1 ladder case', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== B2 (W-03): ladder zero fee refused (below min relay)')
try:
    p0 = prep(vault_psbt(S_V, SPK_V, 10500, N, [(SPK_V, 10500)]))
    sig_k1 = ext_sig(K1_PRIV, p0)
    blob = vault_psbt(S_V, SPK_V, 10500, N, [(SPK_V, 10500)],
                      part_sigs=[(K1, sig_k1)])
    appr, msg, t = full_flow(blob, 'B2')
    ok('B2: zero-fee ladder refused', not appr)
    ok('B2: reason mentions min-relay floor',
       'min-relay' in msg or 'fee' in msg.lower())
except Exception as e:
    ok('B2: zero-fee ladder case', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== B3 (W-03, pinned): ladder fee above f0_max stays approved')
try:
    # DOCUMENTED DECISION: ladders have no fee ceiling - after the
    # cadence a 2-of-3 quorum can already withdraw the full amount
    # anywhere, so a cap adds no security. This case pins that the
    # absence of a ceiling is intentional policy, not an oversight.
    outs = [(SPK_V, 189000)]
    p0 = prep(vault_psbt(S_V, SPK_V, 200000, N, outs))
    sig_k1 = ext_sig(K1_PRIV, p0)
    blob = vault_psbt(S_V, SPK_V, 200000, N, outs,
                      part_sigs=[(K1, sig_k1)])
    appr, msg, t = full_flow(blob, 'B3')
    ok('B3: over-f0_max ladder approved (documented: no ceiling)',
       appr and t is not None)
except Exception as e:
    ok('B3: over-f0_max ladder case', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== B4 (W-04): emergency dust output refused')
try:
    p0 = prep(vault_psbt(S_V, SPK_V, 549, EMG_SEQ, [(SPK_E, 500)]))
    sig_k3 = ext_sig(K3_PRIV, p0)
    blob = vault_psbt(S_V, SPK_V, 549, EMG_SEQ, [(SPK_E, 500)],
                      part_sigs=[(K3, sig_k3)])
    appr, msg, t = full_flow(blob, 'B4')
    ok('B4: dust emergency refused', not appr)
    ok('B4: reason mentions dust', 'dust' in msg.lower())
except Exception as e:
    ok('B4: dust emergency case', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== B5 (W-04): emergency fee below min relay refused')
try:
    p0 = prep(vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, [(SPK_E, 10499)]))
    sig_k3 = ext_sig(K3_PRIV, p0)
    blob = vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, [(SPK_E, 10499)],
                      part_sigs=[(K3, sig_k3)])
    appr, msg, t = full_flow(blob, 'B5')
    ok('B5: fee=1 emergency refused', not appr)
    ok('B5: reason mentions min-relay floor',
       'min-relay' in msg or 'fee' in msg.lower())
except Exception as e:
    ok('B5: fee=1 emergency case', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== B6 (W-02): ladder with witness-utxo-only FALSE amount refused')
try:
    # real coin: 100000 sats; witness_utxo claims 90000. Pre-fix the
    # device's BIP-143 digest embedded the claimed nValue, binding the
    # co-signature to a value the real coin does not have.
    p0 = prep(vault_psbt(S_V, SPK_V, 100000, N, [(SPK_V, 89500)],
                         full_utxo=False, wu_amount=90000))
    fake_digest = digest_of(p0)
    sig_k1 = ext_sig(K1_PRIV, p0)
    blob = vault_psbt(S_V, SPK_V, 100000, N, [(SPK_V, 89500)],
                      part_sigs=[(K1, sig_k1)],
                      full_utxo=False, wu_amount=90000)
    appr, msg, t = full_flow(blob, 'B6')
    ok('B6: witness-utxo-only ladder refused', not appr)
    ok('B6: reason demands full UTXO',
       'utxo' in msg.lower())
    # and the fake digest really would have mismatched the real coin
    _, txi = list(p0.input_iter())[0]
    real_digest = p0.make_txn_segwit_sighash(0, txi, 100000,
                                             p0.inputs[0].scriptCode, 1)
    ok('B6: fake-amount digest differs from real-coin digest',
       fake_digest != real_digest)
except Exception as e:
    ok('B6: witness-utxo ladder case', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== B9 (W-05): enrollment refuses sv_hash == spk_e')
try:
    bad = dict(CFG)
    bad['spk_e'] = CFG['sv_hash']
    res, msg = vault.validate_cfg(bad)
    ok('B9: sv_hash == spk_e refused at enrollment', not res)
    ok('B9: reason mentions the pair',
       'sv_hash' in msg and 'spk_e' in msg)
except Exception as e:
    ok('B9: sv_hash == spk_e case', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== B10 (W-06, pinned): mixed ladder - foreign inputs allowed')
try:
    # DESIGN (pinned): ladders impose no output/foreign-input
    # restrictions - withdrawal-to-anywhere after the cadence is the
    # S_v design, and the device's SIGHASH_ALL sig binds the whole tx.
    blob = mixed_psbt(10500, 50000, [(FOREIGN_OUT, 60000)])
    p = prep(blob)
    appr, msg = vault.VaultMode.could_sign(p)
    ok('B10: mixed ladder approved (design: withdrawal post-N)',
       appr and 'ladder' in msg)
except Exception as e:
    ok('B10: mixed ladder case', False)
    print('      %s: %s' % (type(e).__name__, e))

del _psbt_mod.print

# ---- verdict ----------------------------------------------------------------
fails = [name for name, cond in R if not cond]
print('')
if fails:
    print('AUDIT2 REGRESSION: %d/%d checks pass' % (len(R) - len(fails), len(R)))
    for f in fails:
        print('  FAILED: %s' % f)
    sys.exit(1)
print('AUDIT2 REGRESSION (W-01..W-06): %d/%d checks pass' % (len(R), len(R)))
