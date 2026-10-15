# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# unix/work/audit3_probe.py - REGRESSION SUITE for the validity audit #3
# findings (X-01/X-02), driving each through the REAL firmware signing
# chain inside the simulator:
#   psbtObject.read_psbt -> validate -> consider_keys/inputs/outputs
#   -> VaultMode.could_sign gate -> sign_it -> finalize
#
# Expected behavior AFTER the audit-3 fixes land:
#   X-01  parse_vault_script / parse_deepvault_script refuse DUPLICATE
#         pubkeys (K1==K2 collapses the 2-of-3 to a single party: two
#         sigs from one key match the duplicate pubkeys in
#         CHECKMULTISIG, and the S_v ELSE branch has no CSV). Hash-
#         matching but degenerate scripts fail closed at recognition.
#   X-02  recognition cross-checks the parsed script's N against the
#         enrolled cfg cadence n (and the ladder nSequence check still
#         compares against N), so a mis-enrollment or a menu 'set_n'
#         edit while funded can no longer make the device co-sign a
#         transaction that fails OP_CSV on-chain.
#
# Case map (behavioral assertions: approved/signed booleans and
# raises/not-raises, never exact message strings):
#   C1   control: honest ladder (script N == cfg n) approved + signed
#   C2   X-02: script N=1009 enrolled, cfg n=1008, ladder seq=1008 ->
#        refused at classification, must NOT sign
#   C2b  guard: same cfg, ladder seq=1009 (would be on-chain valid) ->
#        still refused (cfg/script N mismatch caught at recognition)
#   C3   X-02 via menu set_n: honest script N=1008, cfg n edited to
#        1000, ladder seq=1000 -> refused, must NOT sign
#   C4   X-01: S_v with K1==K2 mixed with a device-signable foreign
#        coin -> the vault input is refused; the device must NOT
#        finalize a single-party vault witness
#   C5   X-01 (pure policy): vault_complete('sv', K1==K2, {K1}) raises
#   C6   X-01 (pure policy): vault_complete('se', K1==K2, {K1}) raises
#   C7   control: honest emergency approved + signed
#   C8   X-01: S_v duplicate permutations K1==K3 / K2==K3 / all-equal
#        -> parse and vault_complete each raise
#   C9   X-01: S_e duplicate permutations K1==K3 / K2==K3 / all-equal
#        -> parse and vault_complete each raise
#   C10  guard: honest cfg (script N == cfg n) but ladder seq == N+1
#        -> still refused by the ladder sequence check (the X-02 fix
#        must not over-permit sequences above the cadence)
#
# Run from unix/work:
#   MICROPYPATH=:../../shared ../coldcard-mpy -X heapsize=9m \
#       ./audit3_probe.py < /dev/null
# Exits non-zero (prints FAILED list) on any regression.

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

def sv_script(n, k1, k2, k3):
    return (bytes([vp.OP_IF]) +
            bytes([2, n & 0xff, (n >> 8) & 0xff]) +
            bytes([vp.OP_CSV, vp.OP_DROP, vp.OP_ELSE, vp.OP_ENDIF, 0x52]) +
            push(k1) + push(k2) + push(k3) + bytes([0x53, vp.OP_CMS]))

def se_script(k1, k2, k3):
    return (push(k1) + bytes([vp.OP_CHECKSIGVERIFY, 0x51]) +
            push(k2) + push(k3) + bytes([0x52, vp.OP_CMS]))

S_V = sv_script(N, K1, K2, K3)              # honest script, N == cfg n
S_V_1009 = sv_script(1009, K1, K2, K3)      # script N' != cfg n
S_V_DUP = sv_script(N, K1, K1, K3)          # K1 duplicated: quorum collapse
S_E = se_script(K1, K2, K3)
S_E_DUP = se_script(K1, K1, K3)             # K1 == K2 in S_e

SPK_V, SPK_E = vp.p2wsh_spk(S_V), vp.p2wsh_spk(S_E)
SPK_V_1009 = vp.p2wsh_spk(S_V_1009)
SPK_V_DUP = vp.p2wsh_spk(S_V_DUP)
EXIT_SPK = vp.p2wsh_spk(bytes([0x51]) + push(K1))

def make_cfg(n=1008, sv=SPK_V):
    return {'n': n, 'sv_hash': b2h(sv), 'spk_e': b2h(SPK_E),
            'k1_pubkey': b2h(K1), 'f0_max': F0_MAX,
            'exit_spk': b2h(EXIT_SPK)}

CFG = make_cfg()
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
               full_utxo=True, witness_utxo=True, version=2):
    # 1-in/1-out spend of a freshly funded P2WSH coin
    fund, fund_id = fund_tx(spk, utxo_val)
    tx = build_tx([(fund_id, 0)], [seq], outs, version=version)
    m = b''
    if full_utxo:
        m += kv(b'\x00', fund)
    if witness_utxo:
        m += kv(b'\x01', ct_out(spk, utxo_val))
    for pk, sig in (part_sigs or []):
        m += kv(b'\x02' + pk, sig)
    m += kv(b'\x05', wscript)
    m += kv(b'\x06' + K1, struct.pack('<I', 0x11111111))
    m += kv(b'\x06' + K2, struct.pack('<II', MY_XFP, 123))
    m += kv(b'\x06' + K3, struct.pack('<I', 0x33333333))
    m += b'\x00'
    return build_psbt(tx, len(outs), [m])

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
    # NOTE: input_iter() REUSES one mutable CTxIn object across yields
    # (non-v2 PSBT path) - values must be consumed at yield time; holding
    # the object (list(...)[idx]) reads the LAST input's data.
    for i, txi in p.input_iter():
        if i == idx:
            inp = p.inputs[idx]
            return p.make_txn_segwit_sighash(idx, txi, inp.amount,
                                             inp.scriptCode, 1)

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

def refused_case(build, label):
    # Behavioral refusal check for a vault-spend case. build(sig_or_None)
    # returns the PSBT blob (with the K1 partial when one could be made).
    # The case counts as REFUSED unless the real chain approves AND
    # finalizes a signed transaction: a could_sign refusal, a
    # FatalPSBTIssue raised anywhere in classification/signing/finalize,
    # or any other exception all count as fail-closed refusal.
    sig = None
    try:
        p0 = prep(build(None))
        sig = ext_sig(K1_PRIV, p0)
    except Exception as e:
        print('    %s: classification refused early (%s: %s)'
              % (label, type(e).__name__, e))
    try:
        appr, msg, t = full_flow(build(sig), label)
    except Exception as e:
        print('    %s: refused via %s: %s' % (label, type(e).__name__, e))
        return True
    if appr and t is not None:
        print('    %s: SIGNED (appr=%s msg="%s")' % (label, appr, msg))
        return False
    print('    %s: refused (appr=%s msg="%s")' % (label, appr, msg))
    return True

def raises_vv(name, fn, *a):
    # post-fix expectation: fn raises VaultViolation (fail closed)
    try:
        r = fn(*a)
    except vp.VaultViolation:
        ok(name, True)
        return
    except Exception as e:
        ok(name, False)
        print('      raised %s (not VaultViolation): %s'
              % (type(e).__name__, e))
        return
    ok(name, False)
    print('      no exception, returned %r (buggy)' % (r,))

# mute the simulator DEBUG 'no key:' prints (DEBUG is TRUE under sim)
import psbt as _psbt_mod
_psbt_mod.print = lambda *a, **k: None

# =============================================================================
print('=== C1 (control): honest ladder (script N == cfg n) - the valid path')
blob = vault_psbt(S_V, SPK_V, 162000, N, [(SPK_V, 150000)])
p = prep(blob)
sig_k1 = ext_sig(K1_PRIV, p)
appr, msg, t = full_flow(vault_psbt(S_V, SPK_V, 162000, N, [(SPK_V, 150000)],
                                    part_sigs=[(K1, sig_k1)]), 'C1')
print('    C1: appr=%s msg="%s" signed=%s' % (appr, msg, t is not None))
ok('C1 control: honest ladder (script N == cfg n) approved+signed',
   appr and t is not None)

# =============================================================================
print('=== C2 (X-02): script N=1009 enrolled with cfg n=1008; ladder seq=1008')
# BIP-112: on-chain OP_CSV demands nSequence >= 1009, but the enrolled
# cfg cadence says 1008. Post-fix the parsed script's N is cross-checked
# against cfg n at recognition, so the input is refused before any
# co-signature is added - instead of approved + signed (invalid on-chain).
vault.save_cfg(dict(make_cfg(n=1008, sv=SPK_V_1009), enabled=1))
ok('C2: script N != cfg n ladder refused (not signed)',
   refused_case(lambda sig: vault_psbt(S_V_1009, SPK_V_1009, 162000, 1008,
                                       [(SPK_V_1009, 150000)],
                                       part_sigs=[(K1, sig)] if sig else None),
                'C2'))

print('=== C2b (guard): same cfg, ladder seq=1009 (would be on-chain valid)')
# The sequence itself would satisfy the on-chain script, but the cfg/script
# N mismatch must still be caught at recognition - the fix must not make
# "sequence matches the script" sufficient while the enrollment disagrees.
ok('C2b: on-chain-valid seq still refused while cfg/script N mismatch',
   refused_case(lambda sig: vault_psbt(S_V_1009, SPK_V_1009, 162000, 1009,
                                       [(SPK_V_1009, 150000)],
                                       part_sigs=[(K1, sig)] if sig else None),
                'C2b'))

# =============================================================================
print('=== C3 (X-02 via menu set_n): honest script N=1008, cfg n edited to 1000')
# Simulates a 'Cadence N' menu edit while the vault is funded and ENABLED:
# the on-chain script still demands CSV >= 1008, so approving a seq=1000
# ladder co-signs a consensus-invalid transaction.
vault.save_cfg(dict(make_cfg(n=1000, sv=SPK_V), enabled=1))
ok('C3: post-set_n-edit ladder refused (not signed)',
   refused_case(lambda sig: vault_psbt(S_V, SPK_V, 162000, 1000,
                                       [(SPK_V, 150000)],
                                       part_sigs=[(K1, sig)] if sig else None),
                'C3'))

# =============================================================================
print('=== C4 (X-01): S_v with K1==K2 mixed with a device-signable foreign coin')
# The duplicated key collapses the 2-of-3: ONE K1 partial satisfies the
# (mis-counted) role slots, and on-chain two sigs from the same private
# key match the duplicate pubkeys - and the S_v ELSE branch has no CSV,
# so a single party could drain the vault at any time. Post-fix,
# parse_vault_script refuses duplicate pubkeys, so recognition of the
# vault input fails closed and the device must not finalize a complete
# (let alone single-party) witness for it.
vault.save_cfg(dict(make_cfg(n=N, sv=SPK_V_DUP), enabled=1))
with stash.SensitiveValues() as sv:
    _n2 = sv.derive_path('m/124')
    K_DEV2 = bytes(_n2.pubkey())
    del _n2
from serializations import hash160
SPK_DEV2 = b'\x00\x14' + hash160(K_DEV2)
FOREIGN_OUT = vp.p2wsh_spk(bytes([0x51]) + push(K3))

fund_v, vid = fund_tx(SPK_V_DUP, 162000)
fund_f, fid = fund_tx(SPK_DEV2, 50000)
tx = build_tx([(vid, 0), (fid, 0)], [N, N], [(FOREIGN_OUT, 200000)])

def c4_maps(sig_k1):
    mv = (kv(b'\x00', fund_v) + kv(b'\x01', ct_out(SPK_V_DUP, 162000)) +
          kv(b'\x02' + K1, sig_k1) + kv(b'\x05', S_V_DUP) +
          kv(b'\x06' + K1, struct.pack('<I', 0x11111111)) +
          kv(b'\x06' + K3, struct.pack('<I', 0x33333333)) + b'\x00')
    mf = (kv(b'\x00', fund_f) + kv(b'\x01', ct_out(SPK_DEV2, 50000)) +
          kv(b'\x06' + K_DEV2, struct.pack('<II', MY_XFP, 124)) + b'\x00')
    return [mv, mf]

shipped_witness = False
try:
    p0 = prep(build_psbt(tx, 1, c4_maps(b'')))
    sig_k1 = ext_sig(K1_PRIV, p0)      # digest for input 0 (S_V_DUP)
    p = prep(build_psbt(tx, 1, c4_maps(sig_k1)))
    appr, msg = vault.VaultMode.could_sign(p)
    if not appr:
        print('    C4: refused (msg="%s")' % msg)
    else:
        print('    C4: appr=%s msg="%s"' % (appr, msg))
        p.sign_it()
        fd = uio.BytesIO()
        p.finalize(fd)
        from serializations import CTransaction
        t = CTransaction()
        t.deserialize(uio.BytesIO(bytes(fd.getvalue())))
        wit = t.wit.vtxinwit[0].scriptWitness.stack
        sigs = [w for w in wit if len(w) > 2 and w[0] == 0x30]
        print('    C4: vault witness sig slots=%d distinct sigs=%d'
              % (len(sigs), len(set(sigs))))
        # a COMPLETE witness (2 sigs) for the degenerate script must
        # never ship - whether single-party (2 identical) or not
        shipped_witness = len(sigs) >= 2
except Exception as e:
    print('    C4: refused via %s: %s' % (type(e).__name__, e))
ok('C4: dup-key (K1==K2) vault input refused - no complete witness shipped',
   not shipped_witness)

# =============================================================================
print('=== C5 (X-01, pure policy): role completion with one key must raise')
# Pre-fix this returned True: the K1==K2 script counted K1 in slots 0
# and 1, declaring a single party sufficient for the 2-of-3.
raises_vv('C5: vault_complete(sv, K1==K2 script, {K1}) raises',
          vsig.vault_complete, 'sv', S_V_DUP, {K1})

print('=== C6 (X-01, pure policy): S_e exit with one key must raise')
raises_vv('C6: vault_complete(se, K1==K2 script, {K1}) raises',
          vsig.vault_complete, 'se', S_E_DUP, {K1})

# =============================================================================
print('=== C7 (control): honest emergency still approved (K1 + device K2)')
# restore the honest cfg first (C4 left the dup-script enrollment in)
vault.save_cfg(dict(CFG, enabled=1))
blob = vault_psbt(S_V, SPK_V, 162000, EMG_SEQ, [(SPK_E, 160000)])
p = prep(blob)
sig_k1 = ext_sig(K1_PRIV, p)
appr, msg, t = full_flow(vault_psbt(S_V, SPK_V, 162000, EMG_SEQ,
                                    [(SPK_E, 160000)],
                                    part_sigs=[(K1, sig_k1)]), 'C7')
print('    C7: appr=%s msg="%s" signed=%s' % (appr, msg, t is not None))
ok('C7 control: honest emergency approved+signed', appr and t is not None)

# =============================================================================
print('=== C8 (X-01): S_v duplicate-pubkey permutations must fail closed')
# Every duplicate permutation of the 2-of-3 is a quorum collapse (the
# signed set shown is the single party that would satisfy it pre-fix).
for tag, desc, keys, signed in [
    ('C8a', 'K1==K3', (K1, K2, K1), {K1}),
    ('C8b', 'K2==K3', (K1, K2, K2), {K2}),
    ('C8c', 'K1==K2==K3', (K1, K1, K1), {K1}),
]:
    ws = sv_script(N, *keys)
    raises_vv('%s: parse_vault_script refuses S_v %s' % (tag, desc),
              vp.parse_vault_script, ws)
    raises_vv('%s: vault_complete(sv, %s, signed) raises' % (tag, desc),
              vsig.vault_complete, 'sv', ws, signed)

print('=== C9 (X-01): S_e duplicate-pubkey permutations must fail closed')
for tag, desc, keys in [
    ('C9a', 'K1==K3', (K1, K2, K1)),
    ('C9b', 'K2==K3', (K1, K2, K2)),
    ('C9c', 'K1==K2==K3', (K1, K1, K1)),
]:
    ws = se_script(*keys)
    raises_vv('%s: parse_deepvault_script refuses S_e %s' % (tag, desc),
              vp.parse_deepvault_script, ws)
    raises_vv('%s: vault_complete(se, %s, {K1}) raises' % (tag, desc),
              vsig.vault_complete, 'se', ws, {K1})

# =============================================================================
print('=== C10 (guard): honest cfg, ladder seq == N+1 must stay refused')
# Guard against the X-02 fix over-permitting: with script N == cfg n,
# a sequence ABOVE the cadence is still not a valid ladder commitment
# (INV-SEQ: exactly N, height form).
ok('C10: ladder seq N+1 refused by sequence check (no over-permit)',
   refused_case(lambda sig: vault_psbt(S_V, SPK_V, 162000, N + 1,
                                       [(SPK_V, 150000)],
                                       part_sigs=[(K1, sig)] if sig else None),
                'C10'))

# restore honest cfg for any later runs
vault.save_cfg(dict(CFG, enabled=1))

# ---- verdict ----------------------------------------------------------------
del _psbt_mod.print

def _prefix(name, prefixes):
    # MicroPython's str.startswith does not accept a tuple argument
    for p in prefixes:
        if name.startswith(p):
            return True
    return False

FIND_PREFIX = ('C2:', 'C3:', 'C4:', 'C5:', 'C6:', 'C8', 'C9')
CTRL_PREFIX = ('setup', 'C1 ', 'C2b', 'C7 ', 'C10')
findings = [(n, c) for n, c in R if _prefix(n, FIND_PREFIX)]
controls = [(n, c) for n, c in R
            if _prefix(n, CTRL_PREFIX) or 'control' in n]
fails = [name for name, cond in R if not cond]
print('')
print('AUDIT3 REGRESSION: %d/%d checks pass, findings-verified: %d/%d, '
      'controls: %d/%d'
      % (len(R) - len(fails), len(R),
         sum(1 for _, c in findings if c), len(findings),
         sum(1 for _, c in controls if c), len(controls)))
if fails:
    for f in fails:
        print('  FAILED: %s' % f)
    print('RED: audit-3 source fixes not yet effective (or regressed)')
    sys.exit(1)
print('AUDIT3 REGRESSION (X-01/X-02): all green')
