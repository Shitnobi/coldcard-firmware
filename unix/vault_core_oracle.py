#!/usr/bin/env python3
# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# unix/vault_core_oracle.py - on-chain validity oracle (remediation plan
# section 4.2), host-side.
#
# The class-3 killer: any transaction the vault policy approves must also
# be CONSENSUS-valid. Two modes:
#
#  1. selfcheck (always runs, no bitcoind needed): funds the enrolled
#     S_v scriptPubKey with a synthetic funding transaction, asks the
#     simulator (unix/vault_core_sign.py, through the full real firmware
#     signing chain) to co-sign the emergency spend, then independently
#     verifies the result host-side: tx structure, prevout binding,
#     nSequence/nLockTime policy shape, witness stack order, script
#     hash, and BOTH signatures against a host-computed BIP-143 digest
#     (python-ecdsa). Found the vout-vs-input-index bug this way.
#
#  2. regtest (when bitcoind is on PATH): same flow but the funding is a
#     REAL coin on a private regtest chain, and the signed tx must be
#     accepted by `testmempoolaccept` and mined. This is Bitcoin Core
#     itself as the oracle - no reimplementation trust.
#
# Run from the repo root:  python3 unix/vault_core_oracle.py
# Exits non-zero on any failure.

import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import shutil

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(REPO, 'unix', 'work')
CTX = os.path.join(WORK, 'core_oracle_ctx.json')
REQ = os.path.join(WORK, 'core_oracle_request.json')
RESP = os.path.join(WORK, 'core_oracle_response.json')
AMOUNT = 100000                     # sats funded to the vault coin
FEE = 300                           # matches vault_core_sign.py


def run_sim():
    # the simulator wants fds 3..6 open (LED/button pipes per
    # unix/variant/ckcc.py) and /dev/null on stdin, like the documented
    # manual invocation
    env = dict(os.environ, MICROPYPATH=':../../shared')
    cmd = ('exec 3<>/dev/null 4<>/dev/null 5<>/dev/null 6<>/dev/null; '
           'MICROPYPATH=:../../shared ../coldcard-mpy -X heapsize=9m '
           '../vault_core_sign.py 3 4 5 6 < /dev/null')
    r = subprocess.run(cmd, shell=True, executable='/bin/bash',
                       cwd=WORK, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=180)
    out = r.stdout.decode(errors='replace')
    if r.returncode != 0:
        print(out)
        raise SystemExit('sim signer failed (exit %d)' % r.returncode)
    return out


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def vi(n):
    return bytes([n]) if n < 253 else b'\xfd' + struct.pack('<H', n)


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


def parse_signed(signed):
    # minimal segwit tx parse: 1 input, 1 output (the shapes we build)
    assert signed[4:6] == b'\x00\x01', 'not a segwit tx'
    i = 6
    n_in = signed[i]; i += 1
    assert n_in == 1
    prev_hash = signed[i:i + 32]
    prev_n = struct.unpack_from('<I', signed, i + 32)[0]; i += 36
    sl = signed[i]; i += 1 + sl
    seq = struct.unpack_from('<I', signed, i)[0]; i += 4
    n_out = signed[i]; i += 1
    assert n_out == 1
    out_val = struct.unpack_from('<q', signed, i)[0]; i += 8
    sl = signed[i]; out_spk = signed[i + 1:i + 1 + sl]; i += 1 + sl
    n_wit = signed[i]; i += 1
    stack = []
    for _ in range(n_wit):
        l = signed[i]; i += 1
        stack.append(signed[i:i + l]); i += l
    lock = struct.unpack_from('<I', signed, len(signed) - 4)[0]
    assert i == len(signed) - 4, 'trailing bytes after witness'
    return dict(prev_hash=prev_hash, prev_n=prev_n, seq=seq,
                out_val=out_val, out_spk=out_spk, stack=stack, lock=lock)


def verify_signed(signed, ctx, funding_txid_le, vout, amount, tag):
    # independent host-side consensus verification of the sim's output
    import ecdsa
    from ecdsa.util import sigdecode_der

    S_V = bytes.fromhex(ctx['s_v'])
    K1 = bytes.fromhex(ctx['k1_pubkey'])
    K2 = bytes.fromhex(ctx['k2_pubkey'])
    t = parse_signed(signed)

    ok = True

    def check(name, cond):
        nonlocal ok
        print('  [%s] %s: %s' % ('ok' if cond else 'FAIL', tag, name))
        ok = ok and cond

    check('prevout binds the funded coin',
          t['prev_hash'] == funding_txid_le and t['prev_n'] == vout)
    check('nSequence == 0xFFFFFFFD (emergency)', t['seq'] == 0xFFFFFFFD)
    check('nLockTime == 0', t['lock'] == 0)
    check('single output is the pinned spk_e',
          t['out_spk'] == bytes.fromhex(ctx['spk_e']))
    check('output value = amount - fee',
          t['out_val'] == amount - FEE)
    check('witness = [dummy, sig, sig, selector, script]',
          len(t['stack']) == 5 and t['stack'][0] == b'' and
          t['stack'][3] == b'')
    check('witness script is the enrolled S_v', t['stack'][4] == S_V)
    check('sha256(S_v) == spk_v[2:]',
          hashlib.sha256(S_V).digest() ==
          bytes.fromhex(ctx['spk_v'])[2:])

    script_code = bytes([len(S_V)]) + S_V
    preimage = (struct.pack('<i', 2)
                + dsha(t['prev_hash'] + struct.pack('<I', t['prev_n']))
                + dsha(struct.pack('<I', t['seq']))
                + t['prev_hash'] + struct.pack('<I', t['prev_n'])
                + script_code
                + struct.pack('<q', amount)
                + struct.pack('<I', t['seq'])
                + dsha(ct_out(t['out_spk'], t['out_val']))
                + struct.pack('<II', t['lock'], 1))
    digest = dsha(preimage)
    for pk, sig in ((K1, t['stack'][1]), (K2, t['stack'][2])):
        try:
            vk = ecdsa.VerifyingKey.from_string(pk, curve=ecdsa.SECP256k1)
            vk.verify_digest(sig[:-1], digest, sigdecode=sigdecode_der)
            check('signature by %s verifies (BIP-143)' % pk.hex()[:8], True)
        except Exception as e:
            check('signature by %s verifies: %s' % (pk.hex()[:8], e), False)
    return ok


def selfcheck():
    print('--- selfcheck: synthetic funding, full sim chain, host verify ---')
    run_sim()                                   # dump ctx
    ctx = json.load(open(CTX))
    spk_v = bytes.fromhex(ctx['spk_v'])

    # synthetic funding tx: vault coin at VOUT 1 (deliberately nonzero -
    # this is the shape that caught the input-index/vout confusion bug)
    fund = build_tx([(b'\x00' * 32, 0)], [0xffffffff],
                    [(bytes([0x00, 0x14]) + b'\xab' * 20, AMOUNT),
                     (spk_v, AMOUNT)], version=1)
    txid_le = dsha(fund)
    json.dump({'txid': txid_le[::-1].hex(), 'vout': 1,
               'amount_sat': AMOUNT, 'funding_hex': fund.hex()},
              open(REQ, 'w'))
    run_sim()                                   # sign
    resp = json.load(open(RESP))
    signed = bytes.fromhex(resp['signed_hex'])
    print('  sim signed: %s (%s)' % (resp['txid'], resp['class']))
    return verify_signed(signed, ctx, txid_le, 1, AMOUNT, 'selfcheck')


def which(prog):
    for d in os.environ.get('PATH', '').split(os.pathsep):
        if os.path.isfile(os.path.join(d, prog)):
            return True
    return False


def regtest():
    print('--- regtest: real coins, Bitcoin Core as the oracle ---')
    if not which('bitcoind') or not which('bitcoin-cli'):
        print('SKIP: bitcoind / bitcoin-cli not on PATH')
        return True

    datadir = tempfile.mkdtemp(prefix='vault-oracle-')
    port = 48332

    def cli(*args, wallet=None):
        cmd = ['bitcoin-cli', '-regtest', '-datadir=' + datadir,
               '-rpcport=%d' % port]
        if wallet:
            cmd += ['-rpcwallet=' + wallet]
        cmd += list(args)
        r = subprocess.run(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=120)
        out = r.stdout.decode().strip()
        if r.returncode != 0:
            raise SystemExit('bitcoin-cli %s failed: %s' %
                             (' '.join(args), out))
        return out

    try:
        node = subprocess.Popen(
            ['bitcoind', '-regtest', '-datadir=' + datadir,
             '-rpcport=%d' % port, '-fallbackfee=0.0002',
             '-noprinttoconsole'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # wait for readiness
        import time
        for _ in range(60):
            time.sleep(0.5)
            try:
                cli('getblockchaininfo')
                break
            except SystemExit:
                pass
        else:
            raise SystemExit('bitcoind did not come up')

        cli('createwallet', 'ora')
        addr = cli('getnewaddress', '', 'bech32', wallet='ora')
        cli('generatetoaddress', '101', addr, wallet='ora')

        # device commitments + the bcrt address of the vault spk
        run_sim()
        ctx = json.load(open(CTX))
        sys.path.insert(0, os.path.join(REPO, 'testing'))
        import bech32
        spk_v = bytes.fromhex(ctx['spk_v'])
        vaddr = bech32.encode('bcrt', 0, spk_v[2:])

        txid = cli('sendtoaddress', vaddr, '0.00100000', '', '', False,
                   False, None, None, False, wallet='ora')
        funding_hex = json.loads(
            cli('gettransaction', txid, wallet='ora'))['hex']
        dec = json.loads(cli('decoderawtransaction', funding_hex))
        vout = next(i for i, o in enumerate(dec['vout'])
                    if o['scriptPubKey']['hex'] == ctx['spk_v'])

        json.dump({'txid': txid, 'vout': vout, 'amount_sat': AMOUNT,
                   'funding_hex': funding_hex}, open(REQ, 'w'))
        run_sim()
        resp = json.load(open(RESP))
        signed = resp['signed_hex']
        print('  sim signed: %s (%s)' % (resp['txid'], resp['class']))

        # host-side verification too (the regtest check is additive)
        ok = verify_signed(bytes.fromhex(signed), ctx,
                           bytes.fromhex(txid)[::-1], vout, AMOUNT, 'regtest')

        res = json.loads(cli('testmempoolaccept', "['%s']" % signed))
        acc = res[0].get('allowed')
        print('  [regtest] testmempoolaccept allowed: %s' % acc)
        ok = ok and acc
        if acc:
            cli('sendrawtransaction', signed)
            cli('generatetoaddress', '1', addr, wallet='ora')
            mem = json.loads(cli('getmempoolinfo'))['size']
            print('  [regtest] mined (mempool size %d)' % mem)
            ok = ok and mem == 0
        return ok
    finally:
        try:
            cli('stop')
        except Exception:
            node.terminate()
        node.wait(timeout=30)
        shutil.rmtree(datadir, ignore_errors=True)


def main():
    os.chdir(WORK)
    for f in (CTX, REQ, RESP):
        if os.path.exists(f):
            os.remove(f)
    ok = selfcheck()
    ok = regtest() and ok
    print('\nCORE ORACLE: %s' % ('PASS' if ok else 'FAIL'))
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
