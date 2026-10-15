# Host-runnable tests for the Phase-2 vault hardening (V-03/V-04/V-05):
#   - vault_signing.parse_der_sig  (strict DER + low-S)
#   - vault_signing.secp256k1_verify (pure-python ECDSA, cross-checked
#     against the python-ecdsa reference implementation)
#   - vault_signing.check_sighash_all / verify_input_sigs (BIP-143 path
#     with real signatures over a fixed digest)
#   - VaultPolicy INV-SIGHASH and full-UTXO invariants
#   - vault.check_relevance / view_from_psbt fail-closed witness-utxo
#     behavior
#
# Run: python3 testing/test_vault_hardening.py   (needs: python3, pip ecdsa)
import sys, os, types, tempfile, atexit, shutil, struct

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'shared'))

# fake the glob/settings module before vault.py touches it
_store = {'vault': None}
class _FakeSettings:
    n_saves = 0
    fail_on = None
    master_nvram_key = None
    master_sv_data = {}
    def __init__(self, nvram_key=None): self.nvram_key = nvram_key
    def load(self): pass
    def get(self, k, d=None): return _store.get(k, d)
    def set(self, k, v): _store[k] = v
    def remove_key(self, k): _store.pop(k, None)
    def save(self): _FakeSettings.n_saves += 1
    def master_get(self, k, d=None):
        if not _FakeSettings.master_nvram_key: return self.get(k, d)
        return _FakeSettings.master_sv_data.get(k, d)
    def master_set(self, k, v):
        if not _FakeSettings.master_nvram_key: self.set(k, v); self.save()
        else:
            _store[k] = v; _FakeSettings.master_sv_data[k] = v

glob_mod = types.ModuleType('glob')
glob_mod.settings = _FakeSettings()
sys.modules['glob'] = glob_mod

import vault
import vault_policy as vp
import vault_signing as vs

import ecdsa
from hashlib import sha256

R = []
def ok(name, cond):
    R.append((name, bool(cond)))
    if not cond: print('    FAIL: %s' % name)

os.chdir(tempfile.mkdtemp(prefix='vhard-'))
atexit.register(shutil.rmtree, os.getcwd(), True)

def dsha(b): return sha256(sha256(b).digest()).digest()

# ---- fixtures ---------------------------------------------------------------
# REAL curve points: the vault keys are the pubkeys of fixed test privkeys
# (K1's signature must verify, so K1 must be an actual secp256k1 point)
import ecdsa as _ec
K1_PRIV = 0x0101010101010101010101010101010101010101010101010101010101010101
K2_PRIV = 0x0202020202020202020202020202020202020202020202020202020202020202
K3_PRIV = 0x0303030303030303030303030303030303030303030303030303030303030303
def _pub_of(priv):
    return _ec.SigningKey.from_secret_exponent(
        priv, curve=_ec.SECP256k1).get_verifying_key().to_string('compressed')
K1, K2, K3 = _pub_of(K1_PRIV), _pub_of(K2_PRIV), _pub_of(K3_PRIV)
N = 1008
def pd(k): return bytes([len(k)]) + k
WS_V = b'\x63\x02\xf0\x03\xb2\x75\x67\x68\x52' + pd(K1) + pd(K2) + pd(K3) + b'\x53\xae'
WS_E = pd(K1) + b'\xad\x51' + pd(K2) + pd(K3) + b'\x52\xae'
SPK_V = vp.p2wsh_spk(WS_V)
SPK_E = vp.p2wsh_spk(WS_E)
EXIT_SPK = vp.p2wsh_spk(b'\x52')
WARM_SPK = vp.p2wsh_spk(b'\x53')
CFG = dict(n=N, sv_hash=SPK_V.hex(), spk_e=SPK_E.hex(),
           k1_pubkey=K1.hex(), f0_max=10000, exit_spk=EXIT_SPK.hex())

_sk = _ec.SigningKey.from_secret_exponent(K1_PRIV, curve=_ec.SECP256k1)
assert _sk.get_verifying_key().to_string('compressed') == K1

def sign_digest(priv, digest):
    # low-S deterministic-ish ECDSA sign over a 32-byte digest
    sk = ecdsa.SigningKey.from_secret_exponent(priv, curve=ecdsa.SECP256k1)
    r, s = sk.sign_number(int.from_bytes(digest, 'big'))
    n = ecdsa.SECP256k1.order
    if s > n // 2:
        s = n - s
    return r, s

def der(r, s, sighash=0x01):
    def enc_int(v):
        b = v.to_bytes((v.bit_length() + 7) // 8 or 1, 'big')
        if b[0] & 0x80: b = b'\x00' + b
        return b'\x02' + bytes([len(b)]) + b
    body = enc_int(r) + enc_int(s)
    return b'\x30' + bytes([len(body)]) + body + bytes([sighash])

# ---- 1. strict DER parser ----------------------------------------------------
def _raises(fn):
    try:
        fn()
        return False
    except vp.VaultViolation:
        return True
    except Exception:
        return False

def _pub(priv):
    return _ec.SigningKey.from_secret_exponent(
        priv, curve=_ec.SECP256k1).get_verifying_key().to_string('compressed')

d = sha256(b'vault test digest').digest()
r, s = sign_digest(K1_PRIV, d)
sig = der(r, s)
rr, ss, sh = vs.parse_der_sig(sig)
ok('DER: roundtrip', (rr, ss, sh) == (r, s, 1))
ok('DER: empty refuses', _raises(lambda: vs.parse_der_sig(b'')))
ok('DER: garbage refuses', _raises(lambda: vs.parse_der_sig(b'\x30' + b'\x45' + b'\x01' * 70)))
ok('DER: bad seq len refuses', _raises(lambda: vs.parse_der_sig(
    b'\x30\x99' + sig[2:])))
ok('DER: trailing garbage refuses', _raises(lambda: vs.parse_der_sig(sig + b'\x00')))
# non-minimal integer: unnecessary leading zero byte
nm = b'\x30\x0b\x02\x03\x00\x12\x34\x02\x03\x00\x56\x78\x01'
ok('DER: non-minimal int refuses', _raises(lambda: vs.parse_der_sig(nm)))
neg = b'\x30\x09\x02\x02\x81\x00\x02\x03\x00\x56\x78\x01'
ok('DER: negative int refuses', _raises(lambda: vs.parse_der_sig(neg)))
# high-S
n_order = ecdsa.SECP256k1.order
hs = der(r, n_order - s)
ok('DER: high-S refuses', _raises(lambda: vs.parse_der_sig(hs)))

def _raises(fn):
    try:
        fn()
        return False
    except vp.VaultViolation:
        return True
    except Exception:
        return False

# ---- 2. pure-python ECDSA vs python-ecdsa reference ---------------------------
# ---- 2. pure-python ECDSA vs python-ecdsa reference ---------------------------
def _v(fn):
    # run fn, return the VaultViolation message (or '' if it did not raise)
    try:
        fn()
        return ''
    except vp.VaultViolation as e:
        return str(e)

ok('ECDSA: valid sig verifies', vs.secp256k1_verify(K1, r, s, d))
ok('ECDSA: wrong digest fails', not vs.secp256k1_verify(K1, r, s, sha256(b'other').digest()))
ok('ECDSA: wrong key fails', not vs.secp256k1_verify(K2, r, s, d))
ok('ECDSA: tampered r fails', not vs.secp256k1_verify(K1, (r % 1000) + 1, s, d))
ok('ECDSA: tampered s fails', not vs.secp256k1_verify(K1, r, (s % 1000) + 1, d))
ok('ECDSA: r=0 fails', not vs.secp256k1_verify(K1, 0, s, d))
ok('ECDSA: r=n fails', not vs.secp256k1_verify(K1, n_order, s, d))
ok('ECDSA: bad pubkey raises', _raises(lambda: vs.secp256k1_verify(b'\x02' + b'\x00' * 32, r, s, d)))
# cross-check 25 random-ish digests
import random
random.seed(42)
allv = True
for i in range(25):
    dd = sha256(bytes([i]) + os.urandom(0) + b'%d' % i).digest()
    rr, ss = sign_digest(K1_PRIV + i, dd)
    good = vs.secp256k1_verify(_pub(K1_PRIV + i), rr, ss, dd)
    bad = vs.secp256k1_verify(_pub(K1_PRIV + i), rr, ss, sha256(b'x%d' % i).digest())
    if not (good and not bad): allv = False
ok('ECDSA: 25-sample cross-check vs reference', allv)

# ---- 3. sighash enforcement (V-04) --------------------------------------------
ok('sighash: ALL accepted', vs.check_sighash_all(der(r, s, 0x01)) == (r, s))
ok('sighash: ANYONECANPAY refused', _raises(lambda: vs.check_sighash_all(der(r, s, 0x81))))
ok('sighash: NONE refused', _raises(lambda: vs.check_sighash_all(der(r, s, 0x02))))
ok('sighash: SINGLE refused', _raises(lambda: vs.check_sighash_all(der(r, s, 0x03))))

# policy-level INV-SIGHASH (fixture views, list-shape)
def pv(ins_sighashes=None, sht=None, utxo_full=None):
    inp = {'spk': SPK_V, 'value': 10500, 'sequence': 0xfffffffd, 'part_sigs': []}
    if ins_sighashes is not None: inp['sighashes'] = ins_sighashes
    if sht is not None: inp['sighash_type'] = sht
    if utxo_full is not None: inp['utxo_full'] = utxo_full
    return {'lock_time': 0, 'inputs': [inp],
            'outputs': [{'spk': SPK_E, 'value': 10000, 'is_change': False}]}

pol = vp.VaultPolicy(CFG)
ok('policy: sighashes [1] ok', 'emergency' in pol.check(pv(ins_sighashes=[1])))
ok('policy: sighashes [0x81] refused', 'SIGHASH' in _v(lambda: pol.check(pv(ins_sighashes=[0x81]))))
ok('policy: declared SINGLE type refused', 'SIGHASH' in _v(lambda: pol.check(pv(sht=3))))
ok('policy: declared ACP type refused', 'SIGHASH' in _v(lambda: pol.check(pv(sht=0x81))))

# ---- 4. full-UTXO requirement (V-05, policy side) ------------------------------
ok('policy: P1 utxo_full ok', 'emergency' in pol.check(pv(utxo_full=True)))
ok('policy: P1 witness-only refused', 'UTXO required' in _v(lambda: pol.check(pv(utxo_full=False))))
def p_exit(utxo_full=None):
    inp = {'spk': SPK_E, 'value': 9600, 'sequence': 0xfffffffd, 'part_sigs': [K1]}
    if utxo_full is not None: inp['utxo_full'] = utxo_full
    return {'lock_time': 0, 'inputs': [inp],
            'outputs': [{'spk': EXIT_SPK, 'value': 9000, 'is_change': False}]}
ok('policy: P3 utxo_full ok', 'exit' in pol.check(p_exit(utxo_full=True)))
ok('policy: P3 witness-only refused', 'UTXO required' in _v(lambda: pol.check(p_exit(utxo_full=False))))

# ---- 5. verify_input_sigs with a real BIP-143 digest --------------------------
# fixed 1-in/1-out tx; digest computed independently here (CPython) and
# fed to a minimal fake psbtObject exposing make_txn_segwit_sighash
TXID = b'\xab' * 32
AMT, SEQ, VAL_OUT, LOCKTIME = 10500, 0xfffffffd, 10000, 0
def ct_out(spk, value):
    return struct.pack('<q', value) + bytes([len(spk)]) + spk
OUT_E = ct_out(SPK_E, VAL_OUT)
hashPrevouts = dsha(TXID + struct.pack('<I', 0))
hashSequence = dsha(struct.pack('<I', SEQ))
hashOutputs = dsha(OUT_E)
script_code = bytes([len(WS_V)]) + WS_V      # compactSize-len witness script
pre = (struct.pack('<i', 2) + hashPrevouts + hashSequence + TXID +
       struct.pack('<I', 0) + script_code + struct.pack('<q', AMT) +
       struct.pack('<I', SEQ) + hashOutputs + struct.pack('<I', LOCKTIME) +
       struct.pack('<I', 1))
DIGEST = dsha(pre)

class FInp:
    def __init__(s, part): s.part_sigs = part
    def get_utxo(s, idx):
        class U: nValue = AMT
        return U()
    def get(s, ref): return ref
class FPsbt:
    def __init__(s, part): s.inputs = [FInp(part)]
    def make_txn_segwit_sighash(s, idx, txi, amt, sc, sht):
        assert (amt, sc, sht) == (AMT, script_code, 1), 'digest inputs mismatch'
        return DIGEST
class FTxi:
    # prevout vout 0: vault_signing reads the spent coin via
    # get_utxo(txi.prevout.n), not the input position
    prevout = type('po', (), {'n': 0})()

def _try_verify(part, wscript=WS_V):
    p = FPsbt(part)
    vs.verify_input_sigs(p, 0, p.inputs[0], FTxi(), wscript)

# a valid K1 signature over THIS digest passes
r1, s1 = sign_digest(K1_PRIV, DIGEST)
try:
    _try_verify({K1: der(r1, s1)})
    ok('verify: valid K1 sig passes', True)
except vp.VaultViolation as e:
    ok('verify: valid K1 sig passes (%s)' % e, False)

# garbage blob (the audit's V-03: 0x30 0x45 01*70) must be refused
try:
    _try_verify({K1: b'\x30\x45' + b'\x01' * 70})
    ok('verify: garbage K1 sig refused', False)
except vp.VaultViolation as e:
    ok('verify: garbage K1 sig refused', 'sig' in str(e))

# well-formed DER over a DIFFERENT transaction (graft attempt) must fail
r2, s2 = sign_digest(K1_PRIV, dsha(b'a different tx'))
try:
    _try_verify({K1: der(r2, s2)})
    ok('verify: grafted sig refused', False)
except vp.VaultViolation as e:
    ok('verify: grafted sig refused', 'invalid partial' in str(e))

# ANYONECANPAY byte on the partial sig must be refused
try:
    _try_verify({K1: der(r1, s1, 0x81)})
    ok('verify: ACP sig refused', False)
except vp.VaultViolation as e:
    ok('verify: ACP sig refused', 'SIGHASH' in str(e))

# signature by the WRONG key (K2's key, claiming K1's slot) must fail
r3, s3 = sign_digest(K2_PRIV, DIGEST)
try:
    _try_verify({K1: der(r3, s3)})
    ok('verify: wrong-key sig refused', False)
except vp.VaultViolation as e:
    ok('verify: wrong-key sig refused', 'invalid partial' in str(e))

# ---- 6. relevance / view fail-closed on unverifiable witness utxos -------------
class WIn:      # witness-utxo-only (full=False) or full-utxo (full=True) input
    def __init__(s, spk, ws, full=False, val=9600):
        s.utxo = (0, 1) if full else None
        s.witness_utxo = None if spk is None else (0, 1)
        s.witness_script = (0, 1) if ws else None
        s._spk, s._ws, s._val = spk, ws, val
    def get_utxo(s, idx):
        class U:
            scriptPubKey = s._spk
            nValue = s._val
        return U()
    def get(s, ref): return s._ws
class WPsbt:
    def __init__(s, ins): s.inputs = ins
    def input_iter(s):
        class TI:
            nSequence = 0xfffffffd
            # prevout vout 0 (vault reads use txin.prevout.n)
            prevout = type('po', (), {'n': 0})()
        for i, n in enumerate(s.inputs): yield i, TI()
    def output_iter(s): return iter([])

# spk claims a non-vault script, but the witness script IS the vault
# script: relevance must treat it as relevant (hidden vault coin)
hid = WPsbt([WIn(WARM_SPK, WS_V)])
ok('relevance: script/spk mismatch -> relevant',
   vault.check_relevance(hid, CFG))
# consistent non-vault pair -> irrelevant
ok('relevance: consistent non-vault -> irrelevant',
   not vault.check_relevance(WPsbt([WIn(WARM_SPK, b'\x53')]), CFG))
# witness-utxo-only with NO witness script -> relevant (fail closed)
class NoScript:
    utxo = None
    witness_utxo = (0, 1)
    witness_script = None
    def get_utxo(s, idx):
        class U: scriptPubKey = WARM_SPK
        return U()
ok('relevance: no witness script -> relevant',
   vault.check_relevance(WPsbt([NoScript()]), CFG))

# view_from_psbt must refuse unverifiable witness-utxo shapes
try:
    vault.view_from_psbt(hid)
    ok('view: spk/script mismatch refuses', False)
except vp.VaultViolation as e:
    ok('view: spk/script mismatch refuses', 'match' in str(e) or 'missing' in str(e))
ns = WPsbt([NoScript()])
try:
    vault.view_from_psbt(ns)
    ok('view: no witness script refuses', False)
except vp.VaultViolation as e:
    ok('view: no witness script refuses', 'witness script' in str(e))

# ---- 7. could_sign end-to-end with the fake (policy+verify wired) --------------
# real-psbtObject-shaped fake WITH make_txn_segwit_sighash: the K1 sig is
# garbage, so could_sign must refuse even though the P3 shape is perfect
class GPsbt(WPsbt):
    def __init__(s, ins, outs, part):
        WPsbt.__init__(s, ins)
        s._outs, s._part = outs, part
        s.outputs = outs            # view_from_psbt reads psbt.outputs[idx]
        s.lock_time = 0
    def output_iter(s):
        for i, o in enumerate(s._outs): yield i, o
    def make_txn_segwit_sighash(s, *a): return DIGEST
class GIn(WIn):
    def __init__(s, spk, ws, part, full=True):
        WIn.__init__(s, spk, ws, full=full)
        s.part_sigs = part
        s.sighash = None
    def has_utxo(s): return True    # _verify_vault_partials gate
class GOut:
    def __init__(s, spk, val): s.scriptPubKey, s.nValue = spk, val

_store['vault'] = dict(CFG, enabled=1)
g = GPsbt([GIn(SPK_E, WS_E, {K1: b'\x30\x45' + b'\x01' * 70})],
          [GOut(EXIT_SPK, 9000)], None)
appr, msg = vault.VaultMode.could_sign(g)
ok('could_sign: garbage K1 refused end-to-end', not appr)
ok('could_sign: reason mentions sig', 'sig' in msg.lower())

g2 = GPsbt([GIn(SPK_E, WS_E, {K1: der(r1, s1)})], [GOut(EXIT_SPK, 9000)], None)
appr, msg = vault.VaultMode.could_sign(g2)
ok('could_sign: valid K1 approved end-to-end', appr and 'exit' in msg)

# sighash violation through the same path: ACP partial sig
g3 = GPsbt([GIn(SPK_E, WS_E, {K1: der(r1, s1, 0x81)})], [GOut(EXIT_SPK, 9000)], None)
appr, msg = vault.VaultMode.could_sign(g3)
ok('could_sign: ACP partial refused end-to-end', not appr and 'sighash' in msg.lower())

# ---- summary -------------------------------------------------------------------
print('VAULT HARDENING (Phase 2): %d/%d checks pass' % (
    sum(1 for _, c in R if c), len(R)))
sys.exit(0 if all(c for _, c in R) else 1)
