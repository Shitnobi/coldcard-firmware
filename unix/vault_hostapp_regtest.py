#!/usr/bin/env python3
# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# unix/vault_hostapp_regtest.py - full-stack deposit e2e on regtest,
# driving BOTH host apps (the standalone coldcard-vault-hostapp repo
# AND its byte-synced firmware-repo mirror hostapp/vault_tree.py)
# through the REAL user flow against a private bitcoind chain and the
# REAL device simulator:
#
#   regtest coin -> funding PSBT (input-only shape) -> hostapp builds
#   the tree -> the regtest wallet SIGNS the hostapp's deposit.psbt
#   (walletprocesspsbt: the PSBT must be consumable by a real wallet)
#   -> broadcast + mined: on-chain txid == the manifest's PREDICTED
#   deposit_txid, gettxout shows the vault coin paying S_v with the
#   predicted value -> the device enrolls cfg + lattice from the
#   manifest and passes every gate check (vault_sim_e2e.py) -> the
#   device co-signs the HOSTAPP-BUILT emg0 leaf (unix/
#   vault_hostapp_cosign.py, K1 partial signature added host-side) ->
#   the co-signed emergency spend is host-verified (BIP-143) and
#   broadcast + mined; the vault coin is spent on-chain.
#
# Requires: python-ecdsa, Bitcoin Core binaries (/tmp/bitcoin-28.0/bin
# is prepended to PATH if present), the built coldcard-mpy.
# Run from the repo root:  python3 unix/vault_hostapp_regtest.py
# Exits non-zero on any failed check.

import base64
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STANDALONE = os.path.join(os.path.dirname(REPO), 'coldcard-vault-hostapp')
WORK = os.path.join(REPO, 'unix', 'work')
CTX = os.path.join(WORK, 'core_oracle_ctx.json')
REQ = os.path.join(WORK, 'core_oracle_request.json')
RESP = os.path.join(WORK, 'core_oracle_response.json')
OUTROOT = os.path.join(WORK, 'hostapp-regtest')

BTC = '/tmp/bitcoin-28.0/bin'
if os.path.isdir(BTC):
    os.environ['PATH'] = BTC + os.pathsep + os.environ.get('PATH', '')

PORT = 48333
AMOUNT = 100000                    # sats funded to each app's vault
DEPOSIT_FEE = 500
EMG_FEE = 500
LEAVES = 5
EMG_STEP = 13

APPS = [
    ('firmware hostapp mirror', os.path.join(REPO, 'hostapp',
                                             'vault_tree.py')),
    ('standalone hostapp repo', os.path.join(STANDALONE, 'vault_tree.py')),
]

R = []


def ok(name, cond, detail=''):
    R.append(bool(cond))
    print('  [%s] %s%s' % ('ok' if cond else 'FAIL', name,
                           ('  << %s' % detail) if (detail and not cond)
                           else ''))
    return bool(cond)


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def vi(n):
    return bytes([n]) if n < 253 else b'\xfd' + struct.pack('<H', n)


def ct_out(spk, value):
    return struct.pack('<q', value) + vi(len(spk)) + spk


def kv(key, val):
    return vi(len(key)) + key + vi(len(val)) + val


def ser_tx(version, ins, outs, locktime):
    r = struct.pack('<i', version) + vi(len(ins))
    for (txid, n, seq) in ins:
        r += txid + struct.pack('<I', n) + vi(0) + struct.pack('<I', seq)
    r += vi(len(outs))
    for (spk, val) in outs:
        r += ct_out(spk, val)
    return r + struct.pack('<I', locktime)


def sh(cmd, cwd, timeout=600):
    r = subprocess.run(cmd, shell=True, executable='/bin/bash', cwd=cwd,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=timeout)
    return r.returncode, r.stdout.decode(errors='replace')


def run_dump_sim():
    # dump mode: no request file must be present (a stale one would flip
    # vault_core_sign.py into sign mode)
    for f in (REQ, RESP):
        if os.path.exists(f):
            os.remove(f)
    cmd = ('exec 3<>/dev/null 4<>/dev/null 5<>/dev/null 6<>/dev/null; '
           'MICROPYPATH=:../../shared ../coldcard-mpy -X heapsize=9m '
           '../vault_core_sign.py 3 4 5 6 < /dev/null')
    return sh(cmd, WORK)


def run_e2e_sim(outdir):
    cmd = ('exec 5<>/dev/null 6<>/dev/null 7<>/dev/null; '
           'MICROPYPATH=:../../shared VAULT_E2E_DIR=%s '
           '../coldcard-mpy -X heapsize=9m ../vault_sim_e2e.py 5 -1 6 7 '
           '< /dev/null' % shlex.quote(outdir))
    return sh(cmd, WORK)


def run_cosign_sim(outdir, fname):
    cmd = ('exec 3<>/dev/null 4<>/dev/null 5<>/dev/null 6<>/dev/null; '
           'MICROPYPATH=:../../shared VAULT_COSIGN_DIR=%s '
           'VAULT_COSIGN_FILE=%s ../coldcard-mpy -X heapsize=9m '
           '../vault_hostapp_cosign.py 3 4 5 6 < /dev/null'
           % (shlex.quote(outdir), shlex.quote(fname)))
    return sh(cmd, WORK)


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


def verify_cosigned(signed, ctx, dep_txid_disp, vout, vault_value, fee,
                    tag):
    # independent host-side verification of the device-co-signed
    # hostapp leaf: P1 emergency shape, dest pinned to spk_e, BOTH
    # signatures against a host-computed BIP-143 digest
    import ecdsa
    from ecdsa.util import sigdecode_der

    S_V = bytes.fromhex(ctx['s_v'])
    K1 = bytes.fromhex(ctx['k1_pubkey'])
    K2 = bytes.fromhex(ctx['k2_pubkey'])
    t = parse_signed(signed)
    dep_txid_le = bytes.fromhex(dep_txid_disp)[::-1]

    good = True

    def check(name, cond):
        nonlocal good
        print('  [%s] %s: %s' % ('ok' if cond else 'FAIL', tag, name))
        good = good and bool(cond)

    check('prevout binds the confirmed deposit',
          t['prev_hash'] == dep_txid_le and t['prev_n'] == vout)
    check('nSequence == 0xFFFFFFFD (P1 emergency)',
          t['seq'] == 0xFFFFFFFD)
    check('nLockTime == 0', t['lock'] == 0)
    check('single output pinned to spk_e',
          t['out_spk'] == bytes.fromhex(ctx['spk_e']))
    check('output value = vault_value - leaf fee',
          t['out_val'] == vault_value - fee)
    check('witness = [dummy, sig, sig, selector, script]',
          len(t['stack']) == 5 and t['stack'][0] == b'' and
          t['stack'][3] == b'')
    check('witness script is the hostapp S_v', t['stack'][4] == S_V)
    check('sha256(S_v) == spk_v[2:]',
          hashlib.sha256(S_V).digest() ==
          bytes.fromhex(ctx['spk_v'])[2:])

    script_code = bytes([len(S_V)]) + S_V
    preimage = (struct.pack('<i', 2)
                + dsha(t['prev_hash'] + struct.pack('<I', t['prev_n']))
                + dsha(struct.pack('<I', t['seq']))
                + t['prev_hash'] + struct.pack('<I', t['prev_n'])
                + script_code
                + struct.pack('<q', vault_value)
                + struct.pack('<I', t['seq'])
                + dsha(ct_out(t['out_spk'], t['out_val']))
                + struct.pack('<II', t['lock'], 1))
    digest = dsha(preimage)
    for pk, sig in ((K1, t['stack'][1]), (K2, t['stack'][2])):
        try:
            vk = ecdsa.VerifyingKey.from_string(pk, curve=ecdsa.SECP256k1)
            vk.verify_digest(sig[:-1], digest, sigdecode=sigdecode_der)
            check('signature by %s verifies (BIP-143)' % pk.hex()[:8],
                  True)
        except Exception as e:
            check('signature by %s verifies: %s' % (pk.hex()[:8], e),
                  False)
    return good


def load_app(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def sign_k1(digest):
    # the user's own emergency key (K1 priv = 0x01*32, the fixed e2e
    # identity): deterministic, canonical (low-S) DER + sighash byte
    from ecdsa import SigningKey, SECP256k1
    from ecdsa.util import sigencode_der_canonize
    sk = SigningKey.from_string(bytes([0x01] * 32), curve=SECP256k1)
    return sk.sign_digest_deterministic(
        digest, hashfunc=hashlib.sha256,
        sigencode=sigencode_der_canonize) + b'\x01'


def gettxout(cli, txid, vout):
    out = cli('gettxout', txid, str(vout)).strip()
    if out in ('', 'null'):
        return None
    return json.loads(out)


def run_app(tag, app_path, cli, ctx, miner):
    print('--- %s: %s ---' % (tag, app_path))
    mod_name = 'vault_tree_' + tag.split()[0]
    outdir = os.path.join(OUTROOT, mod_name)
    if os.path.isdir(outdir):
        shutil.rmtree(outdir)
    os.makedirs(outdir)
    K1 = bytes.fromhex(ctx['k1_pubkey'])
    K2 = bytes.fromhex(ctx['k2_pubkey'])
    K3 = bytes.fromhex(ctx['k3_pubkey'])

    # ---- 1. a fresh real coin on the chain ------------------------------
    faddr = cli('getnewaddress', '', 'bech32', wallet='ora')
    ftxid = cli('sendtoaddress', faddr, '0.00100000', wallet='ora')
    cli('generatetoaddress', '1', miner, wallet='ora')
    fhex = json.loads(cli('gettransaction', ftxid, wallet='ora'))['hex']
    dec = json.loads(cli('decoderawtransaction', fhex))
    hit = next((i, o) for i, o in enumerate(dec['vout'])
               if o['scriptPubKey'].get('address') == faddr)
    vout, o = hit
    spk = o['scriptPubKey']['hex']
    ok('%s: funding coin is a confirmed 100000-sat output' % tag,
       o['value'] == 0.001 and gettxout(cli, ftxid, vout) is not None,
       o['value'])
    txid_le = bytes.fromhex(ftxid)[::-1]

    # ---- 2. funding PSBT (input-only shape, as a wallet export would) --
    ftx = ser_tx(2, [(txid_le, vout, 0xffffffff)], [], 0)
    im = kv(b'\x01', ct_out(bytes.fromhex(spk), AMOUNT)) + b'\x00'
    funding = b'psbt\xff' + kv(b'\x00', ftx) + b'\x00' + im
    fund_path = os.path.join(outdir, 'funding.psbt')
    open(fund_path, 'wb').write(funding)

    # ---- 3. policy: the device's own K1/K2/K3 commitments ---------------
    pol = {'k1': ctx['k1_pubkey'], 'k2': ctx['k2_pubkey'],
           'k3': ctx['k3_pubkey'], 'n': ctx['n'],
           'f0_max': ctx['f0_max'], 'leaves': LEAVES, 'emg_fee': EMG_FEE,
           'emg_step': EMG_STEP, 'deposit_fee': DEPOSIT_FEE}
    pol_path = os.path.join(outdir, 'policy.json')
    open(pol_path, 'w').write(json.dumps(pol, indent=1))

    # ---- 4. the host app builds the tree (real CLI subprocess) ---------
    r = subprocess.run([sys.executable, app_path, 'build', pol_path,
                        fund_path, outdir], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=120)
    out = r.stdout.decode(errors='replace')
    if r.returncode != 0:
        print(out)
    ok('%s: hostapp build exits 0' % tag, r.returncode == 0, out[-400:])
    ok("%s: report says 'wrote %d emg PSBTs'" % (tag, LEAVES),
       ('wrote %d emg PSBTs' % LEAVES) in out)
    man = json.load(open(os.path.join(outdir, 'manifest.json')))
    ok('%s: funding mode is input-only' % tag,
       man['funding_mode'] == 'input-only')
    ok('%s: vault value == %d (100000 - deposit fee 500)' %
       (tag, AMOUNT - DEPOSIT_FEE), man['vault_value'] ==
       AMOUNT - DEPOSIT_FEE)
    ok('%s: manifest predicts deposit txid + vout' % tag,
       len(man['deposit_txid']) == 64 and man['vault_vout'] == 0)
    ok('%s: host and device agree on sv_hash / spk_e / k1' % tag,
       man['cfg']['sv_hash'] == ctx['spk_v'] and
       man['cfg']['spk_e'] == ctx['spk_e'] and
       man['cfg']['k1_pubkey'] == ctx['k1_pubkey'])
    ok('%s: lattice of %d leaves declared' % (tag, LEAVES),
       man['lattice_count'] == LEAVES and
       len(man['files']) == LEAVES and man['files'][0] == 'emg0.psbt')

    # ---- 5. a REAL wallet signs the hostapp's deposit.psbt -------------
    b64 = base64.b64encode(
        open(os.path.join(outdir, 'deposit.psbt'), 'rb').read()).decode()
    try:
        res = json.loads(cli('walletprocesspsbt', b64, wallet='ora'))
        fin = json.loads(cli('finalizepsbt', res['psbt']))
        ok('%s: walletprocesspsbt signs the hostapp deposit PSBT' % tag,
           fin.get('complete') is True and fin.get('hex'),
           json.dumps(res)[:200])
        dep_hex = fin['hex']
    except SystemExit as e:
        ok('%s: walletprocesspsbt signs the hostapp deposit PSBT' % tag,
           False, str(e))
        return
    dep_txid = json.loads(cli('decoderawtransaction', dep_hex))['txid']
    ok('%s: signed deposit txid == manifest prediction' % tag,
       dep_txid == man['deposit_txid'],
       '%s vs %s' % (dep_txid, man['deposit_txid']))
    dec2 = json.loads(cli('decoderawtransaction', dep_hex))
    ok('%s: deposit output pays S_v with the predicted value' % tag,
       dec2['vout'][man['vault_vout']]['scriptPubKey']['hex'] ==
       ctx['spk_v'] and
       dec2['vout'][man['vault_vout']]['value'] ==
       man['vault_value'] / 1e8)

    # ---- 6. broadcast + mine: the deposit is REAL -----------------------
    acc = json.loads(cli('testmempoolaccept', '["%s"]' % dep_hex))[0]
    ok('%s: testmempoolaccept allows the deposit' % tag,
       acc.get('allowed') is True, acc.get('reject-reason'))
    sent = cli('sendrawtransaction', dep_hex)
    ok('%s: sendrawtransaction returns the predicted txid' % tag,
       sent == man['deposit_txid'])
    cli('generatetoaddress', '1', miner, wallet='ora')
    utxo = gettxout(cli, man['deposit_txid'], man['vault_vout'])
    ok('%s: vault coin CONFIRMED on-chain, pays S_v, %d sats' %
       (tag, man['vault_value']),
       utxo is not None and utxo['confirmations'] >= 1 and
       utxo['value'] == man['vault_value'] / 1e8 and
       utxo['scriptPubKey']['hex'] == ctx['spk_v'])

    # ---- 7. the device enrolls this exact tree (real firmware sim) -----
    rc, sim_out = run_e2e_sim(outdir)
    m = re.search(r'VAULT SIM E2E: (\d+)/(\d+) checks pass', sim_out)
    ok('%s: device sim e2e passes on the built tree' % tag,
       rc == 0 and m is not None and m.group(1) == m.group(2),
       sim_out[-600:])
    if m:
        print('      %s' % m.group(0))

    # ---- 8. the device co-signs the HOSTAPP-BUILT emergency leaf -------
    vt = load_app(app_path, mod_name)
    leaf = open(os.path.join(outdir, 'emg0.psbt'), 'rb').read()
    ps = vt.parse_psbt(leaf)
    version, ins, outs, locktime = vt.parse_tx(ps['tx'])
    (ltxid, lvout, lseq) = ins[0]
    (lspk, lval) = outs[0]
    ok('%s: leaf 0 spends the deposit outpoint, P1 shape' % tag,
       ltxid == bytes.fromhex(man['deposit_txid'])[::-1] and
       lvout == man['vault_vout'] and lseq == vt.SEQ_EMERGENCY and
       lspk == bytes.fromhex(ctx['spk_e']) and
       lval == man['vault_value'] - EMG_FEE and locktime == 0)

    # BIP-143 digest over the leaf, signed with the user's K1
    S_V = bytes.fromhex(ctx['s_v'])
    preimage = (struct.pack('<i', version)
                + dsha(ltxid + struct.pack('<I', lvout))
                + dsha(struct.pack('<I', lseq))
                + ltxid + struct.pack('<I', lvout)
                + bytes([len(S_V)]) + S_V
                + struct.pack('<q', man['vault_value'])
                + struct.pack('<I', lseq)
                + dsha(ct_out(lspk, lval))
                + struct.pack('<II', locktime, 1))
    digest = dsha(preimage)
    sig_k1 = sign_k1(digest)
    import ecdsa
    from ecdsa.util import sigdecode_der
    vk = ecdsa.VerifyingKey.from_string(K1, curve=ecdsa.SECP256k1)
    try:
        vk.verify_digest(sig_k1[:-1], digest, sigdecode=sigdecode_der)
        ok('%s: K1 partial signature verifies (BIP-143)' % tag, True)
    except Exception as e:
        ok('%s: K1 partial signature verifies (BIP-143)' % tag, False, e)

    # augment the leaf: K1 partial sig + BIP-32 key origins (the same
    # fields a real multi-sig wallet export would carry)
    extra = (kv(b'\x02' + K1, sig_k1) +
             kv(b'\x06' + K1, struct.pack('<I', 0x11111111)) +
             kv(b'\x06' + K2, struct.pack('<II', ctx['xfp'], 123)) +
             kv(b'\x06' + K3, struct.pack('<I', 0x33333333)))
    im0 = ps['in_maps'][0]
    ok('%s: leaf input map ends with a separator' % tag,
       im0[-1:] == b'\x00')
    k1_leaf = vt.build_psbt(ps['tx'], [im0[:-1] + extra + b'\x00'], 1)
    k1_path = os.path.join(outdir, 'emg0.k1.psbt')
    open(k1_path, 'wb').write(k1_leaf)

    rc, sim_out = run_cosign_sim(outdir, 'emg0.k1.psbt')
    ok('%s: device co-signs the hostapp leaf' % tag,
       rc == 0 and 'COSIGN OK' in sim_out, sim_out[-600:])
    resp = json.load(open(os.path.join(outdir, 'cosign_response.json')))
    ok("%s: gate classified it 'emergency'" % tag,
       'emergency' in resp['class'], resp['class'])

    # ---- 9. host verifies + broadcasts the co-signed emergency spend ---
    signed = bytes.fromhex(resp['signed_hex'])
    good = verify_cosigned(signed, ctx, man['deposit_txid'],
                           man['vault_vout'], man['vault_value'], EMG_FEE,
                           tag)
    ok('%s: host-side verification of the co-signed leaf' % tag, good)

    emg_hex = resp['signed_hex']
    acc = json.loads(cli('testmempoolaccept', '["%s"]' % emg_hex))[0]
    ok('%s: testmempoolaccept allows the emergency spend' % tag,
       acc.get('allowed') is True, acc.get('reject-reason'))
    emg_txid = cli('sendrawtransaction', emg_hex)
    ok('%s: sendrawtransaction accepts the emergency spend' % tag,
       len(emg_txid) == 64)
    cli('generatetoaddress', '1', miner, wallet='ora')
    ok('%s: vault coin SPENT on-chain' % tag,
       gettxout(cli, man['deposit_txid'], man['vault_vout']) is None)
    eutxo = gettxout(cli, emg_txid, 0)
    ok('%s: emergency output CONFIRMED, pays spk_e, %d sats' %
       (tag, man['vault_value'] - EMG_FEE),
       eutxo is not None and eutxo['confirmations'] >= 1 and
       eutxo['value'] == (man['vault_value'] - EMG_FEE) / 1e8 and
       eutxo['scriptPubKey']['hex'] == ctx['spk_e'])


def main():
    print('=== hostapp x firmware x regtest deposit e2e ===')
    for tag, path in APPS:
        if not os.path.isfile(path):
            raise SystemExit('host app not found: %s' % path)

    if os.path.isdir(OUTROOT):
        shutil.rmtree(OUTROOT)
    os.makedirs(OUTROOT)

    # ---- device identity dump (K2 etc. from the fixed sim seed) --------
    rc, out = run_dump_sim()
    if rc != 0:
        print(out)
        raise SystemExit('device dump failed')
    ctx = json.load(open(CTX))
    ok('device dump: K2 + scripts published',
       all(k in ctx for k in ('k2_pubkey', 'spk_v', 'spk_e', 's_v',
                              'xfp')))

    # ---- private regtest chain ------------------------------------------
    datadir = tempfile.mkdtemp(prefix='vault-ha-regtest-')

    def cli(*args, wallet=None):
        cmd = ['bitcoin-cli', '-regtest', '-datadir=' + datadir,
               '-rpcport=%d' % PORT]
        if wallet:
            cmd += ['-rpcwallet=' + wallet]
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
        o = r.stdout.decode().strip()
        if r.returncode != 0:
            raise SystemExit('bitcoin-cli %s failed: %s' %
                             (' '.join(args), o))
        return o

    node = None
    try:
        node = subprocess.Popen(
            ['bitcoind', '-regtest', '-datadir=' + datadir,
             '-rpcport=%d' % PORT, '-fallbackfee=0.0002',
             '-noprinttoconsole'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
        miner = cli('getnewaddress', '', 'bech32', wallet='ora')
        cli('generatetoaddress', '101', miner, wallet='ora')
        ok('regtest chain up, 101 blocks mined', True)

        for tag, path in APPS:
            run_app(tag, path, cli, ctx, miner)
    finally:
        if node is not None:
            node.terminate()
            try:
                node.wait(timeout=30)
            except subprocess.TimeoutExpired:
                node.kill()
        shutil.rmtree(datadir, ignore_errors=True)

    n = sum(R)
    print('HOSTAPP REGTEST E2E: %d/%d checks pass' % (n, len(R)))
    if n != len(R):
        sys.exit(1)


if __name__ == '__main__':
    main()
