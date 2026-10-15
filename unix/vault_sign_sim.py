# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# unix/vault_sign_sim.py - REAL signing path end-to-end for vault scripts,
# inside the simulator (Phase 1 / V-01, V-02 regression tests).
#
# Runs INSIDE the coldcard-mpy binary with the real nvstore, the REAL
# firmware PSBT parser (psbtObject.read_psbt) and the REAL signing
# machinery (determine_my_signing_key -> consider_inputs -> the auth.py
# sync chain -> VaultMode.could_sign gate -> sign_it -> finalize), with
# the device's vault key derived from an injected fixed seed.
#
# Pins the two class-1 (funds unspendable) audit findings:
#   V-01: S_v inputs hit disassemble_multisig_mn(OP_IF) => M=19 =>
#         FatalPSBTIssue('Unknown multisig wallet') BEFORE the policy
#         gate - the vault could never co-sign its own ladder/emergency
#         spends.
#   V-02: S_e inputs hit M=-47 => len(part_sigs) >= -47 is always True
#         => fully_signed illusion => 'Transaction looks completely
#         signed already?' - and a K1-only S_e could never collect the
#         device's required co-signature.
#
# Run from unix/work:
#   MICROPYPATH=:../../shared ../coldcard-mpy -X heapsize=9m \
#       ../vault_sign_sim.py 3 4 5 6 < /dev/null

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

MY_XFP = s.get('xfp', 0)                # xfp label the PSBT derivs must use

class FakeDis:
    def fullscreen(self, *a): pass
    def progress_sofar(self, *a): pass
    def progress_bar_show(self, *a): pass
    def progress_bar_hide(self, *a): pass
glob.dis = FakeDis()

# ---- the enrolled vault policy ---------------------------------------------
# K1 = holder primary (external), K2 = THIS DEVICE (restricted co-signer),
# K3 = holder backup (external). K1/K3 are real curve points so partial
# signatures can be produced with the real ngu signing primitive.
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
# standard bare 2-of-3 for the no-regression contrast
S_STD = bytes([0x52]) + push(K1) + push(K2) + push(K3) + bytes([0x53, vp.OP_CMS])

SPK_V, SPK_E = vp.p2wsh_spk(S_V), vp.p2wsh_spk(S_E)
EXIT_SPK = vp.p2wsh_spk(bytes([0x51]) + K1 + K2 + K3 + bytes([vp.OP_CMS]))

CFG = {'n': N, 'sv_hash': b2h(SPK_V), 'spk_e': b2h(SPK_E),
       'k1_pubkey': b2h(K1), 'f0_max': F0_MAX, 'exit_spk': b2h(EXIT_SPK)}
res, msg = vault.validate_cfg(dict(CFG))
ok('cfg validates', res)
vault.save_cfg(dict(CFG, enabled=1))
ok('vault mode enabled', vault.is_enabled())

# ---- minimal PSBT v0 builder (full UTXO form: V-05 requires it) ------------
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
               k2=None, k2_xfp=None):
    # 1-in/1-out spend of a freshly funded P2WSH coin; includes BOTH the
    # full (non-witness) UTXO and the witness utxo, the witness script,
    # and bip32 derivs: K1 external, K2 = device at m/123, K3 external.
    # k2/k2_xfp let T11 swap in the CCC temporary-seed key.
    if k2 is None:
        k2, k2_xfp = K2, MY_XFP
    fund = build_tx([(b'\x00' * 32, 0)], [0xffffffff], [(spk, utxo_val)], version=1)
    fund_id = bytes(ngu.hash.sha256d(fund))
    tx = build_tx([(fund_id, 0)], [seq], outs)
    m = b''
    m += kv(b'\x00', fund)                       # PSBT_IN_NON_WITNESS_UTXO
    m += kv(b'\x01', ct_out(spk, utxo_val))      # PSBT_IN_WITNESS_UTXO
    for pk, sig in (part_sigs or []):
        m += kv(b'\x02' + pk, sig)               # PSBT_IN_PARTIAL_SIG
    m += kv(b'\x05', wscript)                    # PSBT_IN_WITNESS_SCRIPT
    m += kv(b'\x06' + K1, struct.pack('<I', 0x11111111))
    m += kv(b'\x06' + k2, struct.pack('<II', k2_xfp, 123))
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
    # run finalize into a BytesIO and return (txid, witness stack)
    fd = uio.BytesIO()
    txid = p.finalize(fd)
    from serializations import CTransaction
    t = CTransaction()
    t.deserialize(uio.BytesIO(bytes(fd.getvalue())))
    return txid, t.wit.vtxinwit[0].scriptWitness.stack

EMG_SEQ = vp.SEQ_EMERGENCY
EMG_OUT = [(SPK_E, 10000)]       # P1: emergency pays the sink spk_e
EXIT_OUT = [(EXIT_SPK, 9000)]    # P3: exit ceremony pays exit_spk
LADDER_OUT = [(SPK_V, 10000)]    # ladder: state transition back to spk_v

# =============================================================================
print('=== T1: V-01 - S_v input reaches the gate (was: Unknown multisig wallet)')
blob = vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT)
try:
    p = prep(blob)
    inp = p.inputs[0]
    ok('T1: S_v emergency parses + considers', True)
    ok('T1: input classified as vault sv', inp.is_vault == 'sv')
    ok('T1: device key (K2) required', inp.required_key == {K2})
    ok('T1: not fully signed with zero sigs', not inp.fully_signed)
except Exception as e:
    ok('T1: S_v emergency parses + considers', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== T2: gate approves; device signs K2; ONE sig is not 2-of-3 complete')
try:
    appr, msg = vault.VaultMode.could_sign(p)
    ok('T2: gate approves emergency', appr and 'emergency' in msg)
    p.sign_it()
    inp = p.inputs[0]
    ok('T2: device added exactly the K2 signature',
       list(inp.added_sigs.keys()) == [K2])
    try:
        r, sg, sh = vsig.parse_der_sig(inp.added_sigs[K2])
        good = (sh == 1) and vsig.secp256k1_verify(K2, r, sg, digest_of(p))
    except vsig.VaultViolation:
        good = False
    ok('T2: added sig is strict DER + verifies vs BIP-143', good)
    ok('T2: single sig does NOT complete S_v (role-based)', not p.is_complete())
    try:
        p.finalize(uio.BytesIO())
        ok('T2: finalize refuses incomplete vault input', False)
    except Exception as e:
        ok('T2: finalize refuses incomplete vault input', 'Incomplete' in str(e))
except Exception as e:
    ok('T2: signing flow', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== T3: V-01 complete flow - K1 partial + device K2 => final witness')
try:
    p0 = prep(vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT))
    sig_k1 = ext_sig(K1_PRIV, p0)
    blob3 = vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT,
                       part_sigs=[(K1, sig_k1)])
    p = prep(blob3)
    appr, msg = vault.VaultMode.could_sign(p)
    ok('T3: gate approves (K1 partial verifies)', appr and 'emergency' in msg)
    p.sign_it()
    ok('T3: complete after device signs', p.is_complete())
    txid, stack = final_witness(p)
    # consensus order (see testing/witness_order_check.py):
    # [dummy, sigK1, sigK2, selector(empty), script] - OP_IF pops the
    # selector from the TOP of the stack, so it must sit just below the
    # witness script
    want = [b'', sig_k1, p.inputs[0].added_sigs[K2], b'', S_V]
    ok('T3: witness = [dummy, sigK1, sigK2, selector(empty), script]',
       stack == want)
    ok('T3: txid returned', txid is not None and len(txid) == 64)
except Exception as e:
    ok('T3: complete S_v flow', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== T4: ladder branch - nSequence == N selects the CSV (IF) path')
try:
    p0 = prep(vault_psbt(S_V, SPK_V, 10500, N, LADDER_OUT))
    sig_k1 = ext_sig(K1_PRIV, p0)
    blob4 = vault_psbt(S_V, SPK_V, 10500, N, LADDER_OUT,
                       part_sigs=[(K1, sig_k1)])
    p = prep(blob4)
    appr, msg = vault.VaultMode.could_sign(p)
    ok('T4: gate approves ladder', appr and 'ladder' in msg)
    p.sign_it()
    txid, stack = final_witness(p)
    # selector is the item directly below the witness script (OP_IF pops
    # it from the top); 0x01 = TRUE = IF/CSV ladder branch
    ok('T4: witness selector is 0x01 (IF/CSV branch)', stack[3] == b'\x01')
    ok('T4: witness shape', len(stack) == 5 and stack[4] == S_V)
except Exception as e:
    ok('T4: ladder flow', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== T5: V-02 - S_e with K1-only partial is NOT "completely signed"')
try:
    p0 = prep(vault_psbt(S_E, SPK_E, 9600, EMG_SEQ, EXIT_OUT))
    sig_k1 = ext_sig(K1_PRIV, p0)
    blob5 = vault_psbt(S_E, SPK_E, 9600, EMG_SEQ, EXIT_OUT,
                       part_sigs=[(K1, sig_k1)])
    p = prep(blob5)      # pre-fix this raised 'Transaction looks completely
                         # signed already?' (M=-47 => fully_signed illusion)
    inp = p.inputs[0]
    ok('T5: S_e K1-only parses without the fully_signed illusion', True)
    ok('T5: input classified as vault se', inp.is_vault == 'se')
    ok('T5: device key (K2) still required', inp.required_key == {K2})
    ok('T5: not fully signed', not inp.fully_signed)
    appr, msg = vault.VaultMode.could_sign(p)
    ok('T5: gate approves exit ceremony', appr and 'exit' in msg)
    p.sign_it()
    ok('T5: complete after device co-signs', p.is_complete())
    txid, stack = final_witness(p)
    # consensus order: [dummy, sig_other(K2), sig_K1, script] - OP_CHECK-
    # SIGVERIFY pops K1's pubkey then the sig directly beneath it, so
    # K1's signature must be the TOPMOST signature
    ok('T5: witness = [dummy, sigK2, sigK1, script]',
       stack == [b'', p.inputs[0].added_sigs[K2], sig_k1, S_E])
except Exception as e:
    ok('T5: S_e exit flow', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== T6: S_v presigned by K1+K3 (2-of-3 met) - device adds nothing')
try:
    p0 = prep(vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT))
    sig_k1 = ext_sig(K1_PRIV, p0)
    sig_k3 = ext_sig(K3_PRIV, p0)
    blob6 = vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT,
                       part_sigs=[(K1, sig_k1), (K3, sig_k3)])
    try:
        prep(blob6)
        ok('T6: presigned input refuses with "completely signed"', False)
    except Exception as e:
        # correct behavior: every input is already fully signed, there is
        # nothing for the device to do (V-02 pre-fix this same PSBT was
        # misparsed as M=-47 and raised here too, but as an *illusion* -
        # now it is a true role-based determination)
        ok('T6: presigned input refuses with "completely signed"',
           'completely signed' in str(e))
    # separately verify is_complete/finalize on the classified input
    # without running the whole consider_inputs chain (which raises the
    # fatal above once every input is presigned)
    p = parse(blob6)
    for idx, txin in p.input_iter():
        p.inputs[idx].validate(idx, txin, p.my_xfp, p)
    inp = p.inputs[0]
    inp.determine_my_signing_key(0, inp.get_utxo(0), p.my_xfp, p, None)
    ok('T6: classified presigned vault input, nothing required',
       inp.is_vault == 'sv' and inp.fully_signed and
       inp.required_key is None and inp.is_segwit)
    ok('T6: is_complete without any device signature', p.is_complete())
    txid, stack = final_witness(p)
    ok('T6: witness = [dummy, sigK1, sigK3, selector(empty), script]',
       stack == [b'', sig_k1, sig_k3, b'', S_V])
except Exception as e:
    ok('T6: finalize presigned S_v', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== T7: vault coin present but vault mode disabled => fail closed')
try:
    c = vault._cfg()
    del c['enabled']
    vault.save_cfg(c)
    blob7 = vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT)
    try:
        prep(blob7)
        ok('T7: disabled vault refuses vault coin', False)
    except Exception as e:
        ok('T7: disabled vault refuses vault coin', 'disabled' in str(e))
finally:
    vault.save_cfg(dict(CFG, enabled=1))
ok('T7: re-enabled', vault.is_enabled())

print('=== T8: no regression - standard 2-of-3 still needs a wallet')
try:
    blob8 = vault_psbt(S_STD, vp.p2wsh_spk(S_STD), 10500, EMG_SEQ, EMG_OUT)
    prep(blob8)
    ok('T8: unknown standard multisig still refused', False)
except Exception as e:
    ok('T8: unknown standard multisig still refused',
       'Unknown multisig wallet' in str(e))

print('=== T9: gate refuses policy-violating vault tx BEFORE any signing')
try:
    # fee = 0 violates the P1 window (0 < F <= f0_max)
    blob9 = vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, [(SPK_E, 10500)])
    p = prep(blob9)
    appr, msg = vault.VaultMode.could_sign(parse(blob9))
    ok('T9: zero-fee emergency refused by gate', not appr)

    # ACP graft attempt: SIGHASH_ALL|ANYONECANPAY partial on the vault input
    p0 = prep(vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT))
    dig = digest_of(p0)
    acp_sig = psbtObject.ecdsa_grind_sign(K1_PRIV, dig, 0x81)
    blob9b = vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT,
                        part_sigs=[(K1, acp_sig)])
    p = prep(blob9b)
    appr, msg = vault.VaultMode.could_sign(parse(blob9b))
    ok('T9: ANYONECANPAY partial refused by gate', not appr and 'SIGHASH' in msg)
except Exception as e:
    ok('T9: gate refusals', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== T10: approval-record binding (plan 1.5) - gate must precede signing')
try:
    # (a) skipped gate => sign_it refuses even a policy-valid PSBT
    p = prep(vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT))
    try:
        p.sign_it()
        ok('T10: sign_it without gate approval refused', False)
    except Exception as e:
        ok('T10: sign_it without gate approval refused',
           'no policy approval record' in str(e))

    # (b) tampered record => refusal (record/tx divergence)
    p = prep(vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT))
    appr, msg = vault.VaultMode.could_sign(p)
    ok('T10: gate approves + leaves record', appr and
       isinstance(getattr(p, 'vault_approval', None), dict))
    p.vault_approval['selector'] = 1      # claim ladder on an emergency tx
    try:
        p.sign_it()
        ok('T10: tampered branch selector refused', False)
    except Exception as e:
        ok('T10: tampered branch selector refused', 'branch selector' in str(e))

    # (c) gate + sign_it on the SAME object (the real auth.py flow)
    p = prep(vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT))
    appr, msg = vault.VaultMode.could_sign(p)
    p.sign_it()
    ok('T10: gate + sign_it on same object works',
       list(p.inputs[0].added_sigs.keys()) == [K2])

    # (d) foreign record: gate one PSBT, smuggle the record onto another
    pA = prep(vault_psbt(S_V, SPK_V, 10500, EMG_SEQ, EMG_OUT))
    vault.VaultMode.could_sign(pA)
    pB = prep(vault_psbt(S_V, SPK_V, 10600, EMG_SEQ, EMG_OUT))
    pB.vault_approval = pA.vault_approval
    try:
        pB.sign_it()
        ok('T10: foreign approval record refused', False)
    except Exception as e:
        ok('T10: foreign approval record refused',
           'differs from the approved' in str(e))
except Exception as e:
    ok('T10: approval-record binding', False)
    print('      %s: %s' % (type(e).__name__, e))

print('=== T11: CCC tmp-seed key path - alternate secret co-signs (plan 1.6)')
try:
    # a second seed plays the CCC temporary seed; its m/123 key is the
    # co-signer key in a second enrolled S_v script. In a real CCC
    # session the device is logged into the temporary seed, so
    # settings['xfp'] IS the tmp xfp (capture_xpub at login) and the
    # PSBT parser marks the tmp key as ours. The key is then found by
    # PUBKEY MATCH (not xfp/wallet lookup) and sign_it signs with
    # whichever secret owns the matched pubkey (alternate_secret).
    words2 = ('legal winner thank year wave sausage worth useful '
              'legal winner thank yellow')
    seed2 = bip39.a2b_words(words2.split())
    alt_raw = bytes([0x80]) + seed2 + bytes(72 - 1 - len(seed2))
    with stash.SensitiveValues(secret=alt_raw) as asv:
        K2_ALT = bytes(asv.derive_path('m/123').pubkey())
        ALT_XFP = asv.get_xfp()

    S_V_ALT = (bytes([vp.OP_IF]) +
               bytes([2, N & 0xff, (N >> 8) & 0xff]) +
               bytes([vp.OP_CSV, vp.OP_DROP, vp.OP_ELSE, vp.OP_ENDIF, 0x52]) +
               push(K1) + push(K2_ALT) + push(K3) +
               bytes([0x53, vp.OP_CMS]))
    SPK_V_ALT = vp.p2wsh_spk(S_V_ALT)
    try:
        # enroll the CCC-keyed script (k1/spk_e/exit unchanged) and
        # switch the device to the tmp-seed xfp, as a CCC session would
        vault.save_cfg(dict(CFG, sv_hash=b2h(SPK_V_ALT), enabled=1))
        s.put('xfp', ALT_XFP)
        blob11 = vault_psbt(S_V_ALT, SPK_V_ALT, 10500, EMG_SEQ, EMG_OUT,
                            k2=K2_ALT, k2_xfp=ALT_XFP)
        p = parse(blob11)
        for idx, txin in p.input_iter():
            p.inputs[idx].validate(idx, txin, p.my_xfp, p)
        p.consider_keys()
        p.consider_inputs(cosign_xfp=None)   # my_xfp already covers CCC key
        p.consider_outputs()
        p.consider_dangerous_sighash()
        inp = p.inputs[0]
        ok('T11: CCC-keyed vault input classified', inp.is_vault == 'sv')
        ok('T11: CCC tmp key required (pubkey match, foreign xfp)',
           inp.required_key == {K2_ALT})
        appr, msg = vault.VaultMode.could_sign(p)
        ok('T11: gate approves emergency under CCC script',
           appr and 'emergency' in msg)
        p.sign_it(alternate_secret=alt_raw)
        ok('T11: CCC key added its signature',
           list(inp.added_sigs.keys()) == [K2_ALT])
        try:
            r_, s_, sh_ = vsig.parse_der_sig(inp.added_sigs[K2_ALT])
            good = (sh_ == 1) and \
                vsig.secp256k1_verify(K2_ALT, r_, s_, digest_of(p))
        except vsig.VaultViolation:
            good = False
        ok('T11: CCC signature is strict DER + verifies', good)
    finally:
        vault.save_cfg(dict(CFG, enabled=1))     # restore main enrollment
        s.put('xfp', MY_XFP)                     # restore device identity
except Exception as e:
    ok('T11: CCC tmp-seed key path', False)
    print('      %s: %s' % (type(e).__name__, e))

# ---- cleanup ---------------------------------------------------------------
res, msg = vault.wipe()
ok('cleanup wipe ok', res)
s.save()

n = sum(1 for _, c in R if c)
print('VAULT SIGN SIM (Phase 1): %d/%d checks pass' % (n, len(R)))
if n != len(R):
    sys.exit(1)
