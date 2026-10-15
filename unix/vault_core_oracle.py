#!/usr/bin/env python3
# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# unix/vault_core_oracle.py - on-chain validity oracle (remediation plan
# section 4.2), host-side.
#
# The class-3 killer: any transaction the vault policy approves must also
# be CONSENSUS-valid. Two modes, each covering BOTH spend classes:
#
#  1. selfcheck (always runs, no bitcoind needed): funds the enrolled
#     S_v scriptPubKey with a synthetic funding transaction, asks the
#     simulator (unix/vault_core_sign.py, through the full real firmware
#     signing chain) to co-sign the P1 emergency spend AND the P2 CSV
#     ladder spend, then independently verifies the results host-side:
#     tx structure, prevout binding, nSequence/nLockTime policy shape,
#     witness stack order (incl. the S_v branch selector), script
#     hash, and BOTH signatures against a host-computed BIP-143 digest
#     (python-ecdsa). Found the vout-vs-input-index bug this way.
#
#  2. regtest (when bitcoind is on PATH): same flow but the funding is a
#     REAL coin on a private regtest chain, and the signed tx must be
#     accepted by `testmempoolaccept` and mined. This is Bitcoin Core
#     itself as the oracle - no reimplementation trust. The ladder
#     round additionally proves the cadence is enforced by CONSENSUS:
#     the CSV spend is refused pre-maturity and accepted only after
#     the deposit has N confirmations (BIP-68).
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


def verify_signed(signed, ctx, funding_txid_le, vout, amount, tag,
                  spend='emergency', dest_spk=None):
    # independent host-side consensus verification of the sim's output.
    # spend='emergency': P1 shape (nSequence 0xFFFFFFFD, out pinned to
    #   spk_e, empty OP_IF selector -> ELSE branch).
    # spend='ladder' (G-1): P2 shape (nSequence == ctx n, height-form
    #   CSV, out to dest_spk, 0x01 selector -> OP_IF/CSV branch).
    import ecdsa
    from ecdsa.util import sigdecode_der

    S_V = bytes.fromhex(ctx['s_v'])
    K1 = bytes.fromhex(ctx['k1_pubkey'])
    K2 = bytes.fromhex(ctx['k2_pubkey'])
    t = parse_signed(signed)

    if spend == 'ladder':
        assert dest_spk is not None, 'ladder verify needs dest_spk'
        seq_want = int(ctx['n'])
        sel_want = b'\x01'                  # TRUE -> OP_IF (CSV branch)
        out_want = bytes(dest_spk)
    else:
        seq_want = 0xFFFFFFFD
        sel_want = b''                      # empty -> OP_ELSE (no CSV)
        out_want = bytes.fromhex(ctx['spk_e'])

    ok = True

    def check(name, cond):
        nonlocal ok
        print('  [%s] %s: %s' % ('ok' if cond else 'FAIL', tag, name))
        ok = ok and cond

    check('prevout binds the funded coin',
          t['prev_hash'] == funding_txid_le and t['prev_n'] == vout)
    check('nSequence == %s (%s)' % (hex(seq_want), spend),
          t['seq'] == seq_want)
    check('nLockTime == 0', t['lock'] == 0)
    check('single output is the expected destination',
          t['out_spk'] == out_want)
    check('output value = amount - fee',
          t['out_val'] == amount - FEE)
    check('witness = [dummy, sig, sig, selector, script]',
          len(t['stack']) == 5 and t['stack'][0] == b'' and
          t['stack'][3] == sel_want)
    check('branch selector is the %s branch' % spend,
          t['stack'][3] == sel_want)
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
    ok = verify_signed(signed, ctx, txid_le, 1, AMOUNT, 'selfcheck')

    # G-1: ladder (P2 CSV) round on a second synthetic coin - same full
    # sim chain, host-verified against the ladder consensus shape
    # (nSequence == N height form, TRUE selector -> OP_IF/CSV branch,
    # withdrawal destination). The BIP-68 maturity itself needs a chain
    # and is exercised by the regtest mode below.
    fund2 = build_tx([(b'\x11' * 32, 0)], [0xffffffff],
                     [(bytes([0x00, 0x14]) + b'\xab' * 20, AMOUNT),
                      (spk_v, AMOUNT)], version=1)
    txid2_le = dsha(fund2)
    dest = bytes([0x00, 0x14]) + b'\xcd' * 20      # plain P2WPKH dest
    json.dump({'txid': txid2_le[::-1].hex(), 'vout': 1,
               'amount_sat': AMOUNT, 'funding_hex': fund2.hex(),
               'spend': 'ladder', 'dest_spk': dest.hex()},
              open(REQ, 'w'))
    run_sim()                                   # sign (ladder)
    resp = json.load(open(RESP))
    signed = bytes.fromhex(resp['signed_hex'])
    print('  sim signed ladder: %s (%s)' % (resp['txid'], resp['class']))
    ok = verify_signed(signed, ctx, txid2_le, 1, AMOUNT, 'selfcheck-ladder',
                       spend='ladder', dest_spk=dest) and ok
    return ok


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
        # H-1 fix (framework audit): subprocess wants strings, but callers
        # pass Python bools/None for the optional RPC params - a raw bool is
        # a TypeError and str(False) == 'False' is not JSON. Map to the
        # JSON literals bitcoin-cli parses ('true'/'false'/'null').
        conv = []
        for a in args:
            if isinstance(a, bool):
                conv.append('true' if a else 'false')
            elif a is None:
                conv.append('null')
            else:
                conv.append(str(a))
        cmd += conv
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

        # H-2 fix (framework audit): the 9-arg positional form with null
        # optionals is rejected by Core 28 ('Invalid estimate_mode'); every
        # omitted arg was a default anyway, so send the minimal form.
        txid = cli('sendtoaddress', vaddr, '0.00100000', wallet='ora')
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

        # H-3 fix (framework audit): modern bitcoin-cli only accepts
        # double-quoted JSON for array params; the legacy shell-style
        # "['hex']" form is a parse error.
        res = json.loads(cli('testmempoolaccept', '["%s"]' % signed))
        acc = res[0].get('allowed')
        print('  [regtest] testmempoolaccept allowed: %s' % acc)
        ok = ok and acc
        if acc:
            cli('sendrawtransaction', signed)
            cli('generatetoaddress', '1', addr, wallet='ora')
            mem = json.loads(cli('getmempoolinfo'))['size']
            print('  [regtest] mined (mempool size %d)' % mem)
            ok = ok and mem == 0

        # ---- G-1: CSV ladder spend of a second deposit -----------------
        # The emergency coin is spent; deposit a fresh coin to the same
        # enrolled S_v address, co-sign the P2 ladder withdrawal, and let
        # Bitcoin Core itself enforce the cadence: the spend must be
        # refused pre-maturity (BIP-68 relative locktime) and accepted
        # only once the deposit has N confirmations.
        txid2 = cli('sendtoaddress', vaddr, '0.00100000', wallet='ora')
        funding2_hex = json.loads(
            cli('gettransaction', txid2, wallet='ora'))['hex']
        dec2 = json.loads(cli('decoderawtransaction', funding2_hex))
        vout2 = next(i for i, o in enumerate(dec2['vout'])
                     if o['scriptPubKey']['hex'] == ctx['spk_v'])
        cli('generatetoaddress', '1', addr, wallet='ora')  # confirm deposit
        print('  ladder deposit txid=%s vout=%d' % (txid2, vout2))

        # withdrawal destination: a fresh bech32 wallet address (plain
        # P2WPKH - the canonical 'withdrawal' ladder shape)
        waddr = cli('getnewaddress', '', 'bech32', wallet='ora')
        _ver, prog = bech32.decode('bcrt', waddr)
        dest_spk = bytes([_ver, len(prog)]) + bytes(prog)

        json.dump({'txid': txid2, 'vout': vout2, 'amount_sat': AMOUNT,
                   'funding_hex': funding2_hex, 'spend': 'ladder',
                   'dest_spk': dest_spk.hex()}, open(REQ, 'w'))
        run_sim()
        resp = json.load(open(RESP))
        signed2 = resp['signed_hex']
        print('  sim signed ladder: %s (%s)' % (resp['txid'], resp['class']))
        ok = verify_signed(bytes.fromhex(signed2), ctx,
                           bytes.fromhex(txid2)[::-1], vout2, AMOUNT,
                           'regtest-ladder', spend='ladder',
                           dest_spk=dest_spk) and ok

        # pre-maturity: BIP-68 must refuse the spend outright
        res = json.loads(cli('testmempoolaccept', '["%s"]' % signed2))
        pre_ok = res[0].get('allowed') is False
        why = res[0].get('reject-reason') or res[0].get('reject_reason')
        print('  [regtest] ladder pre-maturity refused: %s (%s)' %
              (pre_ok, why))
        ok = ok and pre_ok

        # mature the coin (N confirmations), then the spend must pass
        cli('generatetoaddress', str(ctx['n']), addr, wallet='ora')
        res = json.loads(cli('testmempoolaccept', '["%s"]' % signed2))
        acc2 = res[0].get('allowed')
        print('  [regtest] ladder post-maturity allowed: %s' % acc2)
        ok = ok and acc2
        if acc2:
            cli('sendrawtransaction', signed2)
            cli('generatetoaddress', '1', addr, wallet='ora')
            mem = json.loads(cli('getmempoolinfo'))['size']
            print('  [regtest] ladder mined (mempool size %d)' % mem)
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
