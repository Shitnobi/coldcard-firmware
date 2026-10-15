# Host check: execute S_v / S_e with candidate witness orders in a minimal
# Bitcoin script interpreter, with REAL signatures - proves the consensus-
# correct witness layout before we fix vault_signing.build_witness.
import sys, os, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

import vault_signing as vs
import vault_policy as vp
import ecdsa
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from hashlib import sha256

def dsha(b): return sha256(sha256(b).digest()).digest()
def pub_of(priv_hex):
    sk = SigningKey.from_string(bytes.fromhex(priv_hex), curve=SECP256k1)
    return b'\x02' if sk.get_verifying_key().pubkey.point.y() & 1 == 0 else b'\x03', \
        sk.get_verifying_key().pubkey.point.x().to_bytes(32, 'big')

K1_PRIV = b'\x01' * 32
K2_PRIV = b'\x02' * 32
K3_PRIV = b'\x03' * 32
sks = {1: SigningKey.from_string(K1_PRIV, curve=SECP256k1),
       2: SigningKey.from_string(K2_PRIV, curve=SECP256k1),
       3: SigningKey.from_string(K3_PRIV, curve=SECP256k1)}
def pk(i):
    p = sks[i].get_verifying_key().pubkey.point
    return bytes([2 | (p.y() & 1)]) + p.x().to_bytes(32, 'big')
K1, K2, K3 = pk(1), pk(2), pk(3)

N = 1008
def push(b): return bytes([len(b)]) + b
S_V = (bytes([vp.OP_IF]) + bytes([2, N & 0xff, (N >> 8) & 0xff]) +
       bytes([vp.OP_CSV, vp.OP_DROP, vp.OP_ELSE, vp.OP_ENDIF, 0x52]) +
       push(K1) + push(K2) + push(K3) + bytes([0x53, vp.OP_CMS]))
S_E = push(K1) + bytes([vp.OP_CHECKSIGVERIFY, 0x51]) + push(K2) + push(K3) + \
      bytes([0x52, vp.OP_CMS])

DIGEST = dsha(b'test digest for witness order')

def der(i):
    return sks[i].sign_digest_deterministic(DIGEST, sigencode=ecdsa.util.sigencode_der) + b'\x01'

def checksig(sig_with_flag, pub):
    # strip sighash byte, DER-verify
    vk = VerifyingKey.from_string(pub, curve=SECP256k1)
    try:
        return vk.verify_digest(sig_with_flag[:-1], DIGEST,
                                sigdecode=ecdsa.util.sigdecode_der)
    except Exception:
        return False

def run_script(script, witness, nsequence):
    # minimal interpreter: enough for S_v / S_e
    stack = list(witness[:-1])         # data items, bottom->top
    assert witness[-1] == script
    i = 0
    pending_else = None
    while i < len(script):
        op = script[i]
        if op == 0x21:                      # push 33-byte pubkey
            stack.append(script[i+1:i+34]); i += 34; continue
        if 1 <= op <= 75:                   # data push
            stack.append(script[i+1:i+1+op]); i += 1 + op; continue
        if op == vp.OP_IF:
            sel = stack.pop()
            assert sel in (b'', b'\x01'), 'selector not bool: %r' % sel
            # find matching ELSE/ENDIF
            depth, j = 1, i + 1
            while depth:
                if script[j] == vp.OP_IF: depth += 1
                elif script[j] == vp.OP_ELSE and depth == 1: pending_else = j
                elif script[j] == vp.OP_ENDIF:
                    depth -= 1
                    if depth == 0: endif = j
                j += 1
            if sel == b'\x01':
                i += 1                      # execute IF branch
            else:
                i = (pending_else + 1) if pending_else is not None else (endif + 1)
            continue
        if op == vp.OP_ELSE or op == vp.OP_ENDIF:
            i += 1; continue                # (only reached executing IF branch)
        if op in (0x51, 0x52, 0x53):        # OP_1/2/3
            stack.append(bytes([op - 0x50])); i += 1; continue
        if op == 2 and False: pass
        if op == 0x02:                      # 2-byte push (the N in S_v)
            stack.append(script[i+1:i+3]); i += 3; continue
        if op == vp.OP_CSV:
            v = int.from_bytes(stack[-1], 'little')
            assert (nsequence & 0x80000000) == 0 and (nsequence & 0x400000) == 0
            assert (nsequence & 0xffff) == v, 'CSV mismatch'
            i += 1; continue                # value NOT popped
        if op == vp.OP_DROP:
            stack.pop(); i += 1; continue
        if op == vp.OP_CHECKSIGVERIFY or op == 0xAC:  # OP_CHECKSIG
            pubk = stack.pop(); sig = stack.pop()
            good = checksig(sig, pubk)
            if op == vp.OP_CHECKSIGVERIFY:
                assert good, 'CHECKSIGVERIFY failed'
            else:
                stack.append(b'\x01' if good else b'')
            i += 1; continue
        if op == vp.OP_CMS:
            n = stack.pop()[0]; pubs = [stack.pop() for _ in range(n)]
            m = stack.pop()[0]; sigs = [stack.pop() for _ in range(m)]
            stack.pop()                     # dummy
            # Core matching (interpreter.cpp EvalScript): both sigs and keys
            # are indexed from the TOP of the stack, so the first sig checked
            # is the topmost sig and the first key checked is the topmost
            # key (i.e. LAST key in script order). Greedy, forward-only.
            ip, iss = 0, 0
            while iss < len(sigs):
                while ip < len(pubs) and not checksig(sigs[iss], pubs[ip]):
                    ip += 1
                assert ip < len(pubs), 'CMS: sig %d unmatched' % iss
                ip += 1; iss += 1
            i += 1; continue
        raise AssertionError('unhandled op 0x%02x at %d' % (op, i))
    assert not stack, 'stack not empty: %d items' % len(stack)
    return True

print('--- S_v, emergency branch (selector empty), sigs K1+K2 ---')
w = [b'', der(1), der(2), b'', S_V]
run_script(S_V, w, 0xFFFFFFFD)
print('    [dummy, sigK1, sigK2, selector(empty), script] EXECUTES OK')

print('--- S_v, ladder branch (selector 0x01, nSequence=N), sigs K1+K2 ---')
w = [b'', der(1), der(2), b'\x01', S_V]
run_script(S_V, w, N)
print('    [dummy, sigK1, sigK2, selector(0x01), script] EXECUTES OK')

print('--- S_v, WRONG order (selector first) must FAIL ---')
try:
    w = [b'', b'', der(1), der(2), S_V]     # [selector, dummy, sig, sig, script]
    run_script(S_V, w, 0xFFFFFFFD)
    print('    ?? executed')
except AssertionError as e:
    print('    fails as expected: %s' % e)

print('--- S_e, order [dummy, sig_other, sig_K1, script] ---')
w = [b'', der(2), der(1), S_E]
run_script(S_E, w, 0xFFFFFFFD)
print('    [dummy, sigK2, sigK1, script] EXECUTES OK')

print('--- S_e, order [dummy, sig_K1, sig_other, script] must FAIL ---')
try:
    w = [b'', der(1), der(2), S_E]
    run_script(S_E, w, 0xFFFFFFFD)
    print('    ?? executed')
except AssertionError as e:
    print('    fails as expected: %s' % e)

print('--- S_v sig order: reversed sigs must FAIL (Core CMS ordering) ---')
try:
    w = [b'', der(2), der(1), b'', S_V]     # sigs reversed vs pubkey order
    run_script(S_V, w, 0xFFFFFFFD)
    print('    ?? executed (reversed ok?)')
except AssertionError as e:
    print('    fails as expected: %s' % e)
