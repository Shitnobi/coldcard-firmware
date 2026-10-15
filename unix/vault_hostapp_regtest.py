#!/usr/bin/env python3
# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# unix/vault_hostapp_regtest.py - full-stack deposit e2e on regtest,
# driving BOTH host apps (the standalone coldcard-vault-hostapp repo
# AND its byte-synced firmware-repo mirror hostapp/vault_tree.py)
# through the REAL user flow against a private bitcoind chain and the
# REAL device simulator. Four flows:
#
#  A. input-only (both apps): regtest coin -> funding PSBT (input-only
#     shape) -> hostapp builds the tree -> the regtest wallet SIGNS the
#     hostapp's deposit.psbt (walletprocesspsbt: the PSBT must be
#     consumable by a real wallet) -> broadcast + mined: on-chain txid
#     == the manifest's PREDICTED deposit_txid, gettxout shows the
#     vault coin paying S_v with the predicted value -> the device
#     enrolls cfg + lattice from the manifest and passes every gate
#     check (vault_sim_e2e.py) -> the device co-signs the HOSTAPP-BUILT
#     emg0 leaf (unix/vault_hostapp_cosign.py, K1 partial signature
#     added host-side) -> the co-signed emergency spend is host-verified
#     (BIP-143) and broadcast + mined; the vault coin is spent on-chain.
#
#  B. already-correct (both apps; device co-sign on the firmware copy):
#     the WALLET funds the vault directly (signed funding tx with a
#     0-value OP_RETURN output at vout 0 so the vault output sits at
#     vout 1 - nonzero vault_vout). The hostapp is given the funding
#     PSBT with a STRAY WITNESS MARKER injected into the global tx (the
#     non-compliant producer shape): it must classify it
#     'already-correct', commit the deposit txid over the CLEAN
#     serialization (HA-8 regression, on-chain: the manifest txid must
#     equal the real funding txid) and the leaves must spend vout 1.
#     The firmware copy's emergency co-sign uses K3 (not K1) as the
#     user key: 2-of-3 with the {K2, K3} signer set, proving the
#     finalize witness ordering with a non-K1 partial signature.
#
#  C. multi-input + CSV ladder recovery (firmware copy): a TWO-input
#     funding PSBT (two wallet coins) -> input-only build (total_in
#     summing, 2 input maps) -> wallet signs both inputs -> mined ->
#     device enrollment -> a HOST-CONSTRUCTED ladder (P2 CSV) spend of
#     that deposit is co-signed by the device (nSequence == N, nVersion
#     2): testmempoolaccept REFUSES it pre-maturity ('non-BIP68-final'),
#     then after mining N=1008 blocks it is accepted, broadcast and
#     mined - the BIP-68 cadence proven against a hostapp deposit.
#
#  D. GUI parity (standalone repo): the standalone GUI logic layer
#     (gui.policy_from_fields + gui.run_build - the exact calls the
#     Build button makes) is run on flow B's real funding PSBT bytes
#     and must produce byte-identical artifacts (deposit.psbt, every
#     emg leaf, manifest.json) to the CLI build.
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
AC_AMOUNT = 300000                 # flow B funding (OP_RETURN + vault)
DEPOSIT_FEE = 500
EMG_FEE = 500
LEAVES = 5
EMG_STEP = 13
LADDER_FEE = 500
OPRET = b'\x6a\x04e2e!'            # 0-value data output (standard)

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


def sh(cmd, cwd, timeout=900):
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
    return dict(version=struct.unpack_from('<i', signed, 0)[0],
                prev_hash=prev_hash, prev_n=prev_n, seq=seq,
                out_val=out_val, out_spk=out_spk, stack=stack, lock=lock)


def verify_cosigned(signed, ctx, dep_txid_disp, vout, vault_value, fee,
                    tag, spend='emergency', dest_spk=None, signers=None):
    # independent host-side verification of the device-co-signed spend:
    # spend='emergency': P1 shape (nSequence 0xFFFFFFFD, out pinned to
    #   spk_e, empty OP_IF selector -> ELSE branch).
    # spend='ladder': P2 shape (nSequence == ctx n, height-form CSV,
    #   nVersion 2, out to dest_spk, 0x01 selector -> OP_IF/CSV branch).
    # signers: the two pubkeys the witness signatures must belong to,
    #   in script order (default (K1, K2); flow B uses (K2, K3)).
    import ecdsa
    from ecdsa.util import sigdecode_der

    S_V = bytes.fromhex(ctx['s_v'])
    if signers is None:
        signers = (bytes.fromhex(ctx['k1_pubkey']),
                   bytes.fromhex(ctx['k2_pubkey']))
    t = parse_signed(signed)
    dep_txid_le = bytes.fromhex(dep_txid_disp)[::-1]

    if spend == 'ladder':
        seq_want, sel_want = int(ctx['n']), b'\x01'
        out_want = bytes(dest_spk)
    else:
        seq_want, sel_want = 0xFFFFFFFD, b''
        out_want = bytes.fromhex(ctx['spk_e'])

    good = True

    def check(name, cond):
        nonlocal good
        print('  [%s] %s: %s' % ('ok' if cond else 'FAIL', tag, name))
        good = good and bool(cond)

    check('prevout binds the confirmed deposit',
          t['prev_hash'] == dep_txid_le and t['prev_n'] == vout)
    check('nSequence == %s (%s)' % (hex(seq_want), spend),
          t['seq'] == seq_want)
    check('nLockTime == 0', t['lock'] == 0)
    if spend == 'ladder':
        check('nVersion == 2 (BIP-68/112)', t['version'] == 2)
    check('single output is the expected destination',
          t['out_spk'] == out_want)
    check('output value = vault_value - fee',
          t['out_val'] == vault_value - fee)
    check('witness = [dummy, sig, sig, selector, script]',
          len(t['stack']) == 5 and t['stack'][0] == b'' and
          t['stack'][3] == sel_want)
    check('branch selector is the %s branch' % spend,
          t['stack'][3] == sel_want)
    check('witness script is the hostapp S_v', t['stack'][4] == S_V)
    check('sha256(S_v) == spk_v[2:]',
          hashlib.sha256(S_V).digest() ==
          bytes.fromhex(ctx['spk_v'])[2:])

    script_code = bytes([len(S_V)]) + S_V
    preimage = (struct.pack('<i', t['version'])
                + dsha(t['prev_hash'] + struct.pack('<I', t['prev_n']))
                + dsha(struct.pack('<I', t['seq']))
                + t['prev_hash'] + struct.pack('<I', t['prev_n'])
                + script_code
                + struct.pack('<q', vault_value)
                + struct.pack('<I', t['seq'])
                + dsha(ct_out(t['out_spk'], t['out_val']))
                + struct.pack('<II', t['lock'], 1))
    digest = dsha(preimage)
    for pk, sig in zip(signers, (t['stack'][1], t['stack'][2])):
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


def sign_with(priv, digest):
    # a user-side emergency/ladder key: deterministic, canonical
    # (low-S) DER + sighash byte
    from ecdsa import SigningKey, SECP256k1
    from ecdsa.util import sigencode_der_canonize
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    return sk.sign_digest_deterministic(
        digest, hashfunc=hashlib.sha256,
        sigencode=sigencode_der_canonize) + b'\x01'


def bip143_digest(version, prev_hash, vout, seq, script, amount, out_spk,
                  out_val, locktime):
    # BIP-143 sighash (SIGHASH_ALL) for a 1-in-1-out segwit spend
    return dsha(struct.pack('<i', version)
                + dsha(prev_hash + struct.pack('<I', vout))
                + dsha(struct.pack('<I', seq))
                + prev_hash + struct.pack('<I', vout)
                + bytes([len(script)]) + script
                + struct.pack('<q', amount)
                + struct.pack('<I', seq)
                + dsha(ct_out(out_spk, out_val))
                + struct.pack('<II', locktime, 1))


def gettxout(cli, txid, vout):
    out = cli('gettxout', txid, str(vout)).strip()
    if out in ('', 'null'):
        return None
    return json.loads(out)


def get_coin(cli, miner, sats):
    # a fresh confirmed wallet coin of exactly `sats`, as
    # (display txid, vout, spk hex)
    addr = cli('getnewaddress', '', 'bech32', wallet='ora')
    txid = cli('sendtoaddress', addr, '%.8f' % (sats / 1e8), wallet='ora')
    cli('generatetoaddress', '1', miner, wallet='ora')
    hex_ = json.loads(cli('gettransaction', txid, wallet='ora'))['hex']
    dec = json.loads(cli('decoderawtransaction', hex_))
    for i, o in enumerate(dec['vout']):
        if o['scriptPubKey'].get('address') == addr:
            assert abs(o['value'] * 1e8 - sats) < 0.5, o['value']
            return txid, i, o['scriptPubKey']['hex']
    raise AssertionError('funding output not found')


def wallet_sign(cli, psbt_blob, tag):
    # the regtest wallet signs (and finalizes) a hostapp PSBT: the
    # PSBT a real wallet must be able to consume
    b64 = base64.b64encode(psbt_blob).decode()
    res = json.loads(cli('walletprocesspsbt', b64, wallet='ora'))
    fin = json.loads(cli('finalizepsbt', res['psbt']))
    ok('%s: walletprocesspsbt signs the hostapp PSBT' % tag,
       fin.get('complete') is True and fin.get('hex'),
       json.dumps(res)[:200])
    return fin['hex']


def write_policy(ctx, path):
    pol = {'k1': ctx['k1_pubkey'], 'k2': ctx['k2_pubkey'],
           'k3': ctx['k3_pubkey'], 'n': ctx['n'],
           'f0_max': ctx['f0_max'], 'leaves': LEAVES, 'emg_fee': EMG_FEE,
           'emg_step': EMG_STEP, 'deposit_fee': DEPOSIT_FEE}
    open(path, 'w').write(json.dumps(pol, indent=1))
    return pol


def build_tree(tag, app_path, outdir, pol_path, fund_path):
    r = subprocess.run([sys.executable, app_path, 'build', pol_path,
                        fund_path, outdir], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=120)
    out = r.stdout.decode(errors='replace')
    if r.returncode != 0:
        print(out)
    ok('%s: hostapp build exits 0' % tag, r.returncode == 0, out[-400:])
    ok("%s: report says 'wrote %d emg PSBTs'" % (tag, LEAVES),
       ('wrote %d emg PSBTs' % LEAVES) in out)
    return json.load(open(os.path.join(outdir, 'manifest.json')))


def device_enroll_e2e(tag, outdir):
    rc, sim_out = run_e2e_sim(outdir)
    m = re.search(r'VAULT SIM E2E: (\d+)/(\d+) checks pass', sim_out)
    ok('%s: device sim e2e passes on the built tree' % tag,
       rc == 0 and m is not None and m.group(1) == m.group(2),
       sim_out[-600:])
    if m:
        print('      %s' % m.group(0))


def cosign_and_verify(tag, app_path, outdir, ctx, leaf_name, dep_txid_disp,
                      vout, vault_value, user_priv, user_pk,
                      spend='emergency', dest_spk=None, fee=EMG_FEE,
                      prebuilt=False):
    # feed the hostapp leaf (augmented with the user's partial sig +
    # BIP-32 key origins) to the real firmware sim for co-signing, then
    # host-verify the result. prebuilt=True: leaf_name is already the
    # K1-augmented PSBT (the host-constructed ladder in flow C).
    vt = load_app(app_path, 'vt_' + tag.split()[0] + '_cosign')
    if prebuilt:
        k1_path = os.path.join(outdir, leaf_name)
    else:
        leaf = open(os.path.join(outdir, leaf_name), 'rb').read()
        ps = vt.parse_psbt(leaf)
        version, ins, outs, locktime = vt.parse_tx(ps['tx'])
        (ltxid, lvout, lseq) = ins[0]
        (lspk, lval) = outs[0]
        if spend == 'emergency':
            want = (ltxid == bytes.fromhex(dep_txid_disp)[::-1] and
                    lvout == vout and lseq == vt.SEQ_EMERGENCY and
                    lspk == bytes.fromhex(ctx['spk_e']) and
                    lval == vault_value - fee and locktime == 0)
            ok('%s: leaf spends the deposit outpoint, P1 shape' % tag,
               want)
        S_V = bytes.fromhex(ctx['s_v'])
        digest = bip143_digest(version, ltxid, lvout, lseq, S_V,
                               vault_value, lspk, lval, locktime)
        sig = sign_with(user_priv, digest)
        import ecdsa
        from ecdsa.util import sigdecode_der
        vk = ecdsa.VerifyingKey.from_string(user_pk,
                                            curve=ecdsa.SECP256k1)
        try:
            vk.verify_digest(sig[:-1], digest, sigdecode=sigdecode_der)
            ok('%s: %s partial signature verifies (BIP-143)' %
               (tag, user_pk.hex()[:8]), True)
        except Exception as e:
            ok('%s: %s partial signature verifies (BIP-143)' %
               (tag, user_pk.hex()[:8]), False, e)

        extra = (kv(b'\x02' + user_pk, sig) +
                 kv(b'\x06' + bytes.fromhex(ctx['k1_pubkey']),
                    struct.pack('<I', 0x11111111)) +
                 kv(b'\x06' + bytes.fromhex(ctx['k2_pubkey']),
                    struct.pack('<II', ctx['xfp'], 123)) +
                 kv(b'\x06' + bytes.fromhex(ctx['k3_pubkey']),
                    struct.pack('<I', 0x33333333)))
        im0 = ps['in_maps'][0]
        k1_leaf = vt.build_psbt(ps['tx'], [im0[:-1] + extra + b'\x00'], 1)
        k1_path = os.path.join(outdir,
                               leaf_name.replace('.psbt', '.k1.psbt'))
        open(k1_path, 'wb').write(k1_leaf)

    rc, sim_out = run_cosign_sim(outdir, os.path.basename(k1_path))
    ok('%s: device co-signs the hostapp %s' %
       (tag, 'leaf' if spend == 'emergency' else 'ladder spend'),
       rc == 0 and 'COSIGN OK' in sim_out, sim_out[-600:])
    resp = json.load(open(os.path.join(outdir, 'cosign_response.json')))
    ok("%s: gate classified it '%s'" % (tag, spend),
       spend in resp['class'], resp['class'])

    signed = bytes.fromhex(resp['signed_hex'])
    if spend == 'emergency':
        signers = (bytes.fromhex(ctx['k2_pubkey']), user_pk) \
            if user_pk != bytes.fromhex(ctx['k1_pubkey']) else \
            (user_pk, bytes.fromhex(ctx['k2_pubkey']))
    else:
        signers = (user_pk, bytes.fromhex(ctx['k2_pubkey']))
    good = verify_cosigned(signed, ctx, dep_txid_disp, vout, vault_value,
                           fee, tag, spend=spend, dest_spk=dest_spk,
                           signers=signers)
    ok('%s: host-side verification of the co-signed %s' %
       (tag, spend), good)
    return resp['signed_hex']


# ---- flow A: input-only funding, emergency recovery -----------------------

def flow_input_only(tag, app_path, cli, ctx, miner):
    print('--- A. %s: input-only funding -> deposit -> emergency ---' % tag)
    outdir = os.path.join(OUTROOT, 'vault_tree_' + tag.split()[0])
    if os.path.isdir(outdir):
        shutil.rmtree(outdir)
    os.makedirs(outdir)

    ftxid, vout, spk = get_coin(cli, miner, AMOUNT)
    ok('%s(A): funding coin is a confirmed %d-sat output' %
       (tag, AMOUNT), gettxout(cli, ftxid, vout) is not None)
    txid_le = bytes.fromhex(ftxid)[::-1]

    ftx = ser_tx(2, [(txid_le, vout, 0xffffffff)], [], 0)
    im = kv(b'\x01', ct_out(bytes.fromhex(spk), AMOUNT)) + b'\x00'
    funding = b'psbt\xff' + kv(b'\x00', ftx) + b'\x00' + im
    fund_path = os.path.join(outdir, 'funding.psbt')
    open(fund_path, 'wb').write(funding)
    write_policy(ctx, os.path.join(outdir, 'policy.json'))

    man = build_tree(tag, app_path, outdir,
                     os.path.join(outdir, 'policy.json'), fund_path)
    ok('%s(A): funding mode is input-only' % tag,
       man['funding_mode'] == 'input-only')
    ok('%s(A): vault value == %d' % (tag, AMOUNT - DEPOSIT_FEE),
       man['vault_value'] == AMOUNT - DEPOSIT_FEE)
    ok('%s(A): manifest predicts deposit txid + vout' % tag,
       len(man['deposit_txid']) == 64 and man['vault_vout'] == 0)
    ok('%s(A): host and device agree on sv_hash / spk_e / k1' % tag,
       man['cfg']['sv_hash'] == ctx['spk_v'] and
       man['cfg']['spk_e'] == ctx['spk_e'] and
       man['cfg']['k1_pubkey'] == ctx['k1_pubkey'])

    dep_hex = wallet_sign(cli, open(os.path.join(outdir, 'deposit.psbt'),
                                    'rb').read(), tag + '(A)')
    dep_txid = json.loads(cli('decoderawtransaction', dep_hex))['txid']
    ok('%s(A): signed deposit txid == manifest prediction' % tag,
       dep_txid == man['deposit_txid'],
       '%s vs %s' % (dep_txid, man['deposit_txid']))

    acc = json.loads(cli('testmempoolaccept', '["%s"]' % dep_hex))[0]
    ok('%s(A): testmempoolaccept allows the deposit' % tag,
       acc.get('allowed') is True, acc.get('reject-reason'))
    sent = cli('sendrawtransaction', dep_hex)
    ok('%s(A): sendrawtransaction returns the predicted txid' % tag,
       sent == man['deposit_txid'])
    cli('generatetoaddress', '1', miner, wallet='ora')
    utxo = gettxout(cli, man['deposit_txid'], man['vault_vout'])
    ok('%s(A): vault coin CONFIRMED on-chain, pays S_v, %d sats' %
       (tag, man['vault_value']),
       utxo is not None and utxo['confirmations'] >= 1 and
       utxo['value'] == man['vault_value'] / 1e8 and
       utxo['scriptPubKey']['hex'] == ctx['spk_v'])

    device_enroll_e2e(tag + '(A)', outdir)
    emg_hex = cosign_and_verify(
        tag + '(A)', app_path, outdir, ctx, 'emg0.psbt',
        man['deposit_txid'], man['vault_vout'], man['vault_value'],
        bytes([0x01] * 32), bytes.fromhex(ctx['k1_pubkey']))

    acc = json.loads(cli('testmempoolaccept', '["%s"]' % emg_hex))[0]
    ok('%s(A): testmempoolaccept allows the emergency spend' % tag,
       acc.get('allowed') is True, acc.get('reject-reason'))
    emg_txid = cli('sendrawtransaction', emg_hex)
    ok('%s(A): sendrawtransaction accepts the emergency spend' % tag,
       len(emg_txid) == 64)
    cli('generatetoaddress', '1', miner, wallet='ora')
    ok('%s(A): vault coin SPENT on-chain' % tag,
       gettxout(cli, man['deposit_txid'], man['vault_vout']) is None)
    eutxo = gettxout(cli, emg_txid, 0)
    ok('%s(A): emergency output CONFIRMED, pays spk_e, %d sats' %
       (tag, man['vault_value'] - EMG_FEE),
       eutxo is not None and eutxo['confirmations'] >= 1 and
       eutxo['value'] == (man['vault_value'] - EMG_FEE) / 1e8 and
       eutxo['scriptPubKey']['hex'] == ctx['spk_e'])
    return outdir


# ---- flow B: already-correct funding, HA-8, nonzero vout, K3 signer ------

def flow_already_correct(tag, app_path, cli, ctx, miner, do_cosign):
    print('--- B. %s: already-correct funding (HA-8 marker, vout 1%s)'
          ' ---' % (tag, ', K3 signer set' if do_cosign else ''))
    outdir = os.path.join(OUTROOT, 'vault_tree_' + tag.split()[0] + '_ac')
    if os.path.isdir(outdir):
        shutil.rmtree(outdir)
    os.makedirs(outdir)
    spk_v = bytes.fromhex(ctx['spk_v'])

    # the WALLET funds the vault directly: 0-value OP_RETURN at vout 0,
    # the vault output at vout 1 (nonzero vault_vout), fee 500
    ftxid, vout, spk = get_coin(cli, miner, AC_AMOUNT)
    vault_val = AC_AMOUNT - DEPOSIT_FEE
    ftx = ser_tx(2, [(bytes.fromhex(ftxid)[::-1], vout, 0xffffffff)],
                 [(OPRET, 0), (spk_v, vault_val)], 0)
    im = kv(b'\x01', ct_out(bytes.fromhex(spk), AC_AMOUNT)) + b'\x00'
    # 2 outputs in the global tx -> 2 empty output maps (BIP-174)
    wpsbt = (b'psbt\xff' + kv(b'\x00', ftx) + b'\x00' + im + b'\x00\x00')
    fhex = wallet_sign(cli, wpsbt, tag + '(B)')
    T = json.loads(cli('decoderawtransaction', fhex))['txid']
    cli('sendrawtransaction', fhex)
    cli('generatetoaddress', '1', miner, wallet='ora')
    ok('%s(B): wallet funding tx mined, vault output at vout 1' % tag,
       gettxout(cli, T, 1) is not None and
       gettxout(cli, T, 1)['scriptPubKey']['hex'] == ctx['spk_v'])

    # the hostapp gets the SAME funding with a STRAY WITNESS MARKER
    # injected into the global tx (non-compliant producer shape): HA-8
    # must commit the deposit txid over the CLEAN serialization
    poison = ftx[:4] + b'\x00\x01' + ftx[4:]
    hpsbt = (b'psbt\xff' + kv(b'\x00', poison) + b'\x00' + im +
             b'\x00\x00')
    fund_path = os.path.join(outdir, 'funding.psbt')
    open(fund_path, 'wb').write(hpsbt)
    write_policy(ctx, os.path.join(outdir, 'policy.json'))

    man = build_tree(tag + '(B)', app_path, outdir,
                     os.path.join(outdir, 'policy.json'), fund_path)
    ok('%s(B): funding mode is already-correct' % tag,
       man['funding_mode'] == 'already-correct', man['funding_mode'])
    ok('%s(B): vault vout == 1 (nonzero)' % tag, man['vault_vout'] == 1)
    ok('%s(B): vault value == %d' % (tag, vault_val),
       man['vault_value'] == vault_val)
    ok('%s(B): HA-8 on-chain: manifest txid == REAL funding txid '
       '(clean serialization committed)' % tag,
       man['deposit_txid'] == T,
       '%s vs %s' % (man['deposit_txid'], T))

    device_enroll_e2e(tag + '(B)', outdir)
    if do_cosign:
        # K3 (not K1) as the user key: the {K2, K3} 2-of-3 signer set
        emg_hex = cosign_and_verify(
            tag + '(B)', app_path, outdir, ctx, 'emg0.psbt',
            man['deposit_txid'], man['vault_vout'], man['vault_value'],
            bytes([0x03] * 32), bytes.fromhex(ctx['k3_pubkey']))
        acc = json.loads(cli('testmempoolaccept', '["%s"]' % emg_hex))[0]
        ok('%s(B): testmempoolaccept allows the K3+K2 emergency spend' %
           tag, acc.get('allowed') is True, acc.get('reject-reason'))
        emg_txid = cli('sendrawtransaction', emg_hex)
        cli('generatetoaddress', '1', miner, wallet='ora')
        ok('%s(B): vault coin (vout 1) SPENT on-chain by the K3 signer '
           'set' % tag, gettxout(cli, T, 1) is None)
        eutxo = gettxout(cli, emg_txid, 0)
        ok('%s(B): emergency output CONFIRMED, pays spk_e' % tag,
           eutxo is not None and eutxo['confirmations'] >= 1 and
           eutxo['scriptPubKey']['hex'] == ctx['spk_e'])
    return outdir


# ---- flow C: multi-input funding + CSV ladder recovery --------------------

def flow_multi_ladder(tag, app_path, cli, ctx, miner):
    print('--- C. %s: 2-input funding -> deposit -> CSV ladder ---' % tag)
    outdir = os.path.join(OUTROOT, 'vault_tree_' + tag.split()[0] + '_mi')
    if os.path.isdir(outdir):
        shutil.rmtree(outdir)
    os.makedirs(outdir)
    spk_v = bytes.fromhex(ctx['spk_v'])

    c1 = get_coin(cli, miner, AMOUNT)
    c2 = get_coin(cli, miner, AMOUNT)
    ftx = ser_tx(2, [(bytes.fromhex(t)[::-1], v, 0xffffffff)
                     for (t, v, _) in (c1, c2)], [], 0)
    ims = b''.join(kv(b'\x01', ct_out(bytes.fromhex(s), AMOUNT)) + b'\x00'
                   for (_, _, s) in (c1, c2))
    funding = b'psbt\xff' + kv(b'\x00', ftx) + b'\x00' + ims
    fund_path = os.path.join(outdir, 'funding.psbt')
    open(fund_path, 'wb').write(funding)
    write_policy(ctx, os.path.join(outdir, 'policy.json'))

    man = build_tree(tag + '(C)', app_path, outdir,
                     os.path.join(outdir, 'policy.json'), fund_path)
    ok('%s(C): funding mode is input-only (2 inputs)' % tag,
       man['funding_mode'] == 'input-only')
    ok('%s(C): total_in == 200000 summed across both input maps' % tag,
       man['funding_value'] == 2 * AMOUNT and
       man['vault_value'] == 2 * AMOUNT - DEPOSIT_FEE)

    dep_hex = wallet_sign(cli, open(os.path.join(outdir, 'deposit.psbt'),
                                    'rb').read(), tag + '(C)')
    dep_txid = json.loads(cli('decoderawtransaction', dep_hex))['txid']
    ok('%s(C): signed 2-input deposit txid == manifest prediction' % tag,
       dep_txid == man['deposit_txid'])
    cli('sendrawtransaction', dep_hex)
    cli('generatetoaddress', '1', miner, wallet='ora')
    utxo = gettxout(cli, man['deposit_txid'], man['vault_vout'])
    ok('%s(C): 2-input vault coin CONFIRMED, %d sats' %
       (tag, man['vault_value']),
       utxo is not None and utxo['confirmations'] >= 1 and
       utxo['value'] == man['vault_value'] / 1e8)

    device_enroll_e2e(tag + '(C)', outdir)

    # a HOST-CONSTRUCTED ladder (P2 CSV) spend of the hostapp deposit:
    # nSequence == N (height form), nVersion 2, plain P2WPKH dest
    dest_addr = cli('getnewaddress', '', 'bech32', wallet='ora')
    ai = json.loads(cli('getaddressinfo', dest_addr, wallet='ora'))
    dest_spk = bytes.fromhex(ai['scriptPubKey'])
    dep_txid_le = bytes.fromhex(man['deposit_txid'])[::-1]
    lad = ser_tx(2, [(dep_txid_le, man['vault_vout'], int(ctx['n']))],
                 [(dest_spk, man['vault_value'] - LADDER_FEE)], 0)
    S_V = bytes.fromhex(ctx['s_v'])
    digest = bip143_digest(2, dep_txid_le, man['vault_vout'],
                           int(ctx['n']), S_V, man['vault_value'],
                           dest_spk, man['vault_value'] - LADDER_FEE, 0)
    sig = sign_with(bytes([0x01] * 32), digest)
    im = (kv(b'\x00', bytes.fromhex(dep_hex)) +
          kv(b'\x01', ct_out(spk_v, man['vault_value'])) +
          kv(b'\x02' + bytes.fromhex(ctx['k1_pubkey']), sig) +
          kv(b'\x05', S_V) +
          kv(b'\x06' + bytes.fromhex(ctx['k1_pubkey']),
             struct.pack('<I', 0x11111111)) +
          kv(b'\x06' + bytes.fromhex(ctx['k2_pubkey']),
             struct.pack('<II', ctx['xfp'], 123)) +
          kv(b'\x06' + bytes.fromhex(ctx['k3_pubkey']),
             struct.pack('<I', 0x33333333)) + b'\x00')
    lad_psbt = b'psbt\xff' + kv(b'\x00', lad) + b'\x00' + im + b'\x00'
    open(os.path.join(outdir, 'ladder.k1.psbt'), 'wb').write(lad_psbt)

    lad_hex = cosign_and_verify(
        tag + '(C)', app_path, outdir, ctx, 'ladder.k1.psbt',
        man['deposit_txid'], man['vault_vout'], man['vault_value'],
        bytes([0x01] * 32), bytes.fromhex(ctx['k1_pubkey']),
        spend='ladder', dest_spk=dest_spk, fee=LADDER_FEE,
        prebuilt=True)

    # BIP-68 cadence enforced by CONSENSUS on the hostapp deposit:
    # refused pre-maturity, accepted after N confirmations
    pre = json.loads(cli('testmempoolaccept', '["%s"]' % lad_hex))[0]
    ok('%s(C): ladder REFUSED pre-maturity (BIP-68)' % tag,
       pre.get('allowed') is False and
       'non-BIP68-final' in (pre.get('reject-reason') or ''),
       json.dumps(pre))
    cli('generatetoaddress', str(ctx['n']), miner, wallet='ora')
    post = json.loads(cli('testmempoolaccept', '["%s"]' % lad_hex))[0]
    ok('%s(C): ladder allowed post-maturity (after N=%d blocks)' %
       (tag, ctx['n']), post.get('allowed') is True,
       post.get('reject-reason'))
    lad_txid = cli('sendrawtransaction', lad_hex)
    cli('generatetoaddress', '1', miner, wallet='ora')
    ok('%s(C): vault coin SPENT on-chain by the CSV ladder' % tag,
       gettxout(cli, man['deposit_txid'], man['vault_vout']) is None)
    lutxo = gettxout(cli, lad_txid, 0)
    ok('%s(C): ladder output CONFIRMED, pays the P2WPKH dest, %d sats' %
       (tag, man['vault_value'] - LADDER_FEE),
       lutxo is not None and lutxo['confirmations'] >= 1 and
       lutxo['value'] == (man['vault_value'] - LADDER_FEE) / 1e8 and
       lutxo['scriptPubKey']['hex'] == dest_spk.hex())


# ---- flow D: GUI logic parity on real funding -----------------------------

def flow_gui_parity(cli, ctx, ref_outdir, funding_path):
    tag = 'gui'
    print('--- D. standalone GUI logic parity (real funding bytes) ---')
    outdir = os.path.join(OUTROOT, 'vault_tree_standalone_gui')
    if os.path.isdir(outdir):
        shutil.rmtree(outdir)
    os.makedirs(outdir)
    sys.path.insert(0, STANDALONE)
    spec = importlib.util.spec_from_file_location(
        'vault_gui_e2e', os.path.join(STANDALONE, 'gui.py'))
    gui = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gui)

    fields = {'k1': ctx['k1_pubkey'], 'k2': ctx['k2_pubkey'],
              'k3': ctx['k3_pubkey'], 'n': str(ctx['n']),
              'f0_max': str(ctx['f0_max']), 'leaves': str(LEAVES),
              'emg_fee': str(EMG_FEE), 'emg_step': str(EMG_STEP),
              'deposit_fee': str(DEPOSIT_FEE), 'exit_spk': ''}
    pol = gui.policy_from_fields(fields)
    rep = gui.run_build(pol, open(funding_path, 'rb').read(), outdir)
    ok('gui: policy_from_fields + run_build build the tree', True)
    man_ref = json.load(open(os.path.join(ref_outdir, 'manifest.json')))
    ok('gui: same deposit txid as the CLI build',
       rep['deposit_txid'] == man_ref['deposit_txid'])
    same = all(open(os.path.join(ref_outdir, f), 'rb').read() ==
               open(os.path.join(outdir, f), 'rb').read()
               for f in (['deposit.psbt', 'manifest.json'] +
                         man_ref['files']))
    ok('gui: deposit.psbt + every emg leaf + manifest.json '
       'byte-identical to the CLI build', same)


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
                           stderr=subprocess.STDOUT, timeout=180)
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
            flow_input_only(tag, path, cli, ctx, miner)
        for tag, path in APPS:
            flow_already_correct(tag, path, cli, ctx, miner,
                                 do_cosign=(tag.startswith('firmware')))
        flow_multi_ladder(APPS[0][0], APPS[0][1], cli, ctx, miner)
        flow_gui_parity(cli, ctx,
                        os.path.join(OUTROOT, 'vault_tree_standalone_ac'),
                        os.path.join(OUTROOT, 'vault_tree_standalone_ac',
                                     'funding.psbt'))
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
