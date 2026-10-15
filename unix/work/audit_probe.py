# Empirical audit probe: does the real firmware signing path (the one
# ApproveTransaction drives: read_psbt -> validate -> consider_inputs)
# accept or refuse vault-script PSBTs?
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

import struct
import vault_policy as vp
from ubinascii import hexlify

def b2h(b):
    return str(hexlify(bytes(b)), 'ascii')

# ---- keys / scripts (same shapes as unix/vault_e2e_gen.py) ---------------
K1 = b'\x02' + bytes(range(1, 33))
K2 = b'\x03' + bytes(range(33, 65))
K3 = b'\x02' + bytes(range(65, 97))
N = 1008

def push(b):
    return bytes([len(b)]) + b

S_V = (bytes([vp.OP_IF]) + bytes([2, N & 0xff, (N >> 8) & 0xff]) +
       bytes([vp.OP_CSV, vp.OP_DROP, vp.OP_ELSE, vp.OP_ENDIF, 0x52]) +
       push(K1) + push(K2) + push(K3) + bytes([0x53, vp.OP_CMS]))
S_E = (push(K1) + bytes([vp.OP_CHECKSIGVERIFY, 0x51]) + push(K2) +
       push(K3) + bytes([0x52, vp.OP_CMS]))
# standard bare 2-of-3 for contrast
S_STD = bytes([0x52]) + push(K1) + push(K2) + push(K3) + bytes([0x53, vp.OP_CMS])

SPK_V = vp.p2wsh_spk(S_V)
SPK_E = vp.p2wsh_spk(S_E)

# ---- minimal PSBT v0 builder ---------------------------------------------
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
    for (spk, value) in outs:
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

def emg_psbt(wscript, utxo_spk, utxo_val, seq, outs, derivs, part_sigs=None,
             lock_time=0):
    # derivs: list of (pubkey, xfp_int) ; part_sigs: list of (pubkey, sig)
    txid = b'\xab' * 32
    tx = build_tx([(txid, 0)], [seq], outs, lock_time=lock_time)
    m = b''
    m += kv(b'\x01', ct_out(utxo_spk, utxo_val))          # witness_utxo
    for pk, sig in (part_sigs or []):
        m += kv(b'\x02' + pk, sig)                         # partial_sig
    m += kv(b'\x05', wscript)                              # witness_script
    for pk, xfp in derivs:
        m += kv(b'\x06' + pk, struct.pack('<I', xfp))      # bip32_deriv (path=[xfp])
    m += b'\x00'
    return build_psbt(tx, len(outs), [m])

XFP_K1, XFP_K2 = 0x11111111, 0x22222222
DERIVS = [(K1, XFP_K1), (K2, XFP_K2), (K3, 0)]   # xfp 0 => placeholder for main xfp
FAKE_SIG = b'\x30' + b'\x45' + b'\x01' * 70

from psbt import psbtObject

def parse(blob):
    import uio
    fd = uio.BytesIO(blob)
    return psbtObject.read_psbt(fd)

def run_pre_approval(p):
    # exact sync chain ApproveTransaction drives before its policy gates:
    #   validate()  -> per-input validate (parse_subpaths etc.)
    #   consider_inputs() -> get_utxo + determine_my_signing_key
    for idx, txin in p.input_iter():
        p.inputs[idx].validate(idx, txin, p.my_xfp, p)
    p.consider_inputs(cosign_xfp=None)
    return p

print('my_xfp = %08x' % p_my if False else '', end='')
import glob as _g
MY_XFP = _g.settings.get('xfp', 0)
print('device main xfp: %08x' % MY_XFP)

print('\n=== CASE 1: emergency leaf (S_v input, K3=main key) ===')
blob = emg_psbt(S_V, SPK_V, 10500, vp.SEQ_EMERGENCY, [(SPK_E, 10000)], DERIVS)
try:
    p = run_pre_approval(parse(blob))
    inp = p.inputs[0]
    print('  NO EXCEPTION; required_key=%r fully_signed=%r' % (
        inp.required_key, inp.fully_signed))
except Exception as e:
    print('  REFUSED BEFORE VAULT GATE: %s: %s' % (type(e).__name__, e))

print('\n=== CASE 2: exit ceremony (S_e input, K1 partial sig) ===')
blob = emg_psbt(S_E, SPK_E, 9600, vp.SEQ_EMERGENCY, [(SPK_V, 9000)], DERIVS,
                part_sigs=[(K1, FAKE_SIG)])
try:
    p = run_pre_approval(parse(blob))
    inp = p.inputs[0]
    print('  NO EXCEPTION; required_key=%r fully_signed=%r (M=-47 illusion)'
          % (inp.required_key, inp.fully_signed))
except Exception as e:
    print('  REFUSED BEFORE VAULT GATE: %s: %s' % (type(e).__name__, e))

print('\n=== CASE 3: S_v input stuffed with 19 junk partial sigs ===')
junk = [(bytes([0x02]) + bytes([i]) + bytes(range(31)), FAKE_SIG) for i in range(19)]
blob = emg_psbt(S_V, SPK_V, 10500, vp.SEQ_EMERGENCY, [(SPK_E, 10000)], DERIVS,
                part_sigs=junk)
try:
    p = run_pre_approval(parse(blob))
    inp = p.inputs[0]
    print('  NO EXCEPTION; required_key=%r fully_signed=%r -> device adds NO signature'
          % (inp.required_key, inp.fully_signed))
except Exception as e:
    print('  REFUSED: %s: %s' % (type(e).__name__, e))

print('\n=== CASE 4 (contrast): standard 2-of-3 script, no wallet enrolled ===')
blob = emg_psbt(S_STD, vp.p2wsh_spk(S_STD), 10500, vp.SEQ_EMERGENCY,
                [(SPK_E, 10000)], DERIVS)
try:
    p = run_pre_approval(parse(blob))
    print('  NO EXCEPTION')
except Exception as e:
    print('  %s: %s   <- correct M=2 parse; enrollable wallet would match' %
          (type(e).__name__, e))

print('\n=== CASE 5: find_match with an enrolled 2-of-3 wallet ===')
from multisig import MultisigWallet, disassemble_multisig_mn
m_v, n_v = disassemble_multisig_mn(S_V)
m_e, n_e = disassemble_multisig_mn(S_E)
m_s, n_s = disassemble_multisig_mn(S_STD)
print('  disassemble_multisig_mn: S_v => M=%d N=%d | S_e => M=%d N=%d | std => M=%d N=%d'
      % (m_v, n_v, m_e, n_e, m_s, n_s))

rec = ['vaulttest', (2, 3),
       [(XFP_K1, "m/48h/0h/0h/2", "xpubFAKE1"),
        (XFP_K2, "m/48h/0h/0h/2", "xpubFAKE2"),
        (MY_XFP, "m/48h/0h/0h/2", "xpubFAKE3")],
       {'ft': 2}]   # AF_P2WSH == 2
s.put('multisig', [rec])
s.save()

xfp_paths = sorted([[XFP_K1], [XFP_K2], [MY_XFP]])
w = MultisigWallet.find_match(2, 3, xfp_paths, [2])
print('  find_match(M=2,N=3) -> %s (wallet IS matchable)' % ('HIT' if w else 'None'))
w = MultisigWallet.find_match(m_v, n_v, xfp_paths, [2])
print('  find_match(M=%d,N=%d) [S_v parse] -> %s' % (m_v, n_v, 'HIT' if w else 'None'))
w = MultisigWallet.find_match(m_e, n_e, xfp_paths, [2])
print('  find_match(M=%d,N=%d) [S_e parse] -> %s' % (m_e, n_e, 'HIT' if w else 'None'))

print('\n=== CASE 6: vault gate itself (what the e2e actually tested) ===')
import vault
cfg = {'n': N, 'sv_hash': b2h(SPK_V), 'spk_e': b2h(SPK_E),
       'k1_pubkey': b2h(K1), 'f0_max': 10000,
       'exit_spk': b2h(vp.p2wsh_spk(bytes([0x51]) + K1 + K2 + K3 + bytes([vp.OP_CMS])))}
appr, msg = vault.VaultMode.could_sign(parse(
    emg_psbt(S_V, SPK_V, 10500, vp.SEQ_EMERGENCY, [(SPK_E, 10000)], DERIVS)))
print('  could_sign(S_v emergency) -> (%r, %r)  <- gate alone approves' % (appr, msg))
