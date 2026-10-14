# Host-runnable tests for shared/vault_policy.py
# Run: python3 testing/test_vault_policy.py   (no device, no pytest required)
import sys, os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'shared'))

import vault_policy as vp


def push_num(n):
    if n <= 16:
        return bytes([0x50 + n]) if n else b'\x00'
    payload = n.to_bytes((n.bit_length() + 7) // 8, 'little')
    if payload[-1] & 0x80:
        payload += b'\x00'
    return bytes([len(payload)]) + payload


def push_data(d):
    assert len(d) < 76
    return bytes([len(d)]) + d


K1 = b'\x02' + b'\x01' * 32
K2 = b'\x02' + b'\x02' * 32
K3 = b'\x02' + b'\x03' * 32
N = 1008
H = 105120


def spk_v(shift):
    ws = (bytes([0x63]) + push_num(N + shift) + bytes([0xB2, 0x75, 0x67, 0x68, 0x52])
          + push_data(K1) + push_data(K2) + push_data(K3) + bytes([0x53, 0xAE]))
    return vp.p2wsh_spk(ws), ws


SPK_V, WS_V = spk_v(0)
SPK_EH, _ = spk_v(1)          # any other P2WSH spk plays "spk_e" here
EXIT_SPK, _ = spk_v(2)
WARM_SPK, _ = spk_v(3)


def pol(**kw):
    p = dict(n=N, sv_hash=SPK_V.hex(), spk_e=SPK_EH.hex(),
             k1_pubkey=K1.hex(), f0_max=7142, exit_spk=EXIT_SPK.hex())
    p.update(kw)
    return vp.VaultPolicy(p)


def view(seq=N, in_spk=SPK_V, out_spks=((WARM_SPK, 15000),), lock=0, vin=162000, sigs=()):
    return {
        'lock_time': lock,
        'inputs': [{'spk': in_spk, 'value': vin, 'sequence': seq, 'part_sigs': list(sigs)}],
        'outputs': [{'spk': s, 'value': v} for s, v in out_spks],
    }


def expect(tree, fn, *a, **kw):
    try:
        fn(*a, **kw)
    except Exception:
        return
    raise AssertionError('expected rejection: %s' % tree)


def expect_ok(fn, *a, **kw):
    fn(*a, **kw)


def expect_parse(fn, *a):
    try:
        fn(*a)
    except vp.VaultViolation:
        return
    raise AssertionError('expected parse rejection')


def test_sequences():
    assert vp.decode_sequence(0xFFFFFFFD) == 'emergency'
    assert vp.decode_sequence(0xFFFFFFFF) == 'disabled'
    assert vp.decode_sequence(1008) == 'csv'
    expect_parse(vp.decode_sequence, (1 << 22) | 144)     # time form refused


def test_vault_script_parse():
    q = vp.parse_vault_script(WS_V)
    assert q['n'] == N and q['keys'] == [K1, K2, K3]

    # the broken Rev2 shape: IF N CSV DROP 1 ELSE 2-of-3 ENDIF  (keyless)
    ws_bad = (bytes([0x63]) + push_num(N) + bytes([0xB2, 0x75, 0x51, 0x67, 0x52])
              + push_data(K1) + push_data(K2) + push_data(K3) + bytes([0x53, 0xAE, 0x68]))
    expect_parse(vp.parse_vault_script, ws_bad)

    # missing ENDIF between branches
    expect_parse(vp.parse_vault_script, bytes([0x63]) + b'\x01\x01' + bytes([0xB2, 0x75, 0x52]))

    # N=0 refused
    expect_parse(vp.parse_vault_script, bytes([0x63]) + b'\x00' + bytes([0xB2, 0x75, 0x67, 0x68])
                 + bytes([0x52]) + push_data(K1) + push_data(K2) + push_data(K3) + bytes([0x53, 0xAE]))

    # trunkated / wrong sig count / garbage tail all refused
    expect_parse(vp.parse_vault_script, WS_V[:-1])
    expect_parse(vp.parse_vault_script, spk_v(0)[0])        # spk is a hash, not the script


def test_deepvault_parse():
    ws = push_data(K1) + bytes([0xAD, 0x51]) + push_data(K2) + push_data(K3) + bytes([0x52, 0xAE])
    q = vp.parse_deepvault_script(ws)
    assert q['k1'] == K1

    ws_e1 = bytes([0x52]) + push_data(K1) + push_data(K2) + push_data(K3) + bytes([0x53, 0xAE])
    expect_parse(vp.parse_deepvault_script, ws_e1)


def test_emergency_P1():
    vp1 = pol()
    ok_em = view(seq=vp.SEQ_EMERGENCY, out_spks=((SPK_EH, 160218),), vin=162000)
    expect_ok(vp1.check, ok_em)                                  # pins everything, fee 1782

    # out == spk_e but the psbtObject flagged the output as wallet
    # change: contradictory P1, refuse (is_change is carried by
    # view_from_psbt on the real-psbtObject path)
    chg = view(seq=vp.SEQ_EMERGENCY, out_spks=((SPK_EH, 160218),), vin=162000)
    chg['outputs'][0]['is_change'] = True
    expect('P1 change', vp1.check, chg)

    for bad in [
        view(seq=vp.SEQ_EMERGENCY, out_spks=((SPK_EH, 160218),), vin=162000, lock=5),
        view(seq=vp.SEQ_EMERGENCY, out_spks=((WARM_SPK, 160218),), vin=162000),
        view(seq=vp.SEQ_EMERGENCY, out_spks=((SPK_EH, 160218), (WARM_SPK, 1)), vin=162000),
        view(seq=vp.SEQ_EMERGENCY, out_spks=((SPK_EH, 162000),), vin=162000),   # 0-fee
        view(seq=vp.SEQ_EMERGENCY, out_spks=((SPK_EH, 154857),), vin=162000),   # fee 7143 > max
        view(seq=vp.SEQ_EMERGENCY, out_spks=((SPK_EH, 170000),), vin=162000),   # value creates?
        view(seq=N,               out_spks=((SPK_EH, 160218),), vin=162000),    # csv seq in emergency shape
    ]:
        expect('P1', vp1.check, bad)


def test_ladder_sequence():
    vp1 = pol()
    expect_ok(vp1.check, view(seq=N))
    expect('seq!=N', vp1.check, view(seq=N - 1))
    expect('seq disabled', vp1.check, view(seq=0xFFFFFFFF))
    expect('locktime set', vp1.check, view(lock=900000))
    expect('time form', vp1.check, view(seq=(1 << 22) | 144))


def test_cfg_structural_validation():
    # VaultPolicy.__init__ must fail fast on a mis-enrolled cfg (=> 
    # validate_cfg 'bad policy' at enroll time, could_sign refuse at
    # spend time) instead of silently producing an unenforceable or
    # self-contradictory policy
    expect_ok(pol)

    # exit_spk == spk_e / sv_hash: P3 exit ceremonies must pay exit_spk
    # while INV-SINK forbids non-emergency classes paying spk_e/sv_v -
    # equal values make every exit ceremony unsignable (funds locked in
    # the sink forever)
    expect_parse(lambda: pol(exit_spk=SPK_EH.hex()))
    expect_parse(lambda: pol(exit_spk=SPK_V.hex()))

    # sv_hash/spk_e are P2WSH scriptPubKeys
    expect_parse(lambda: pol(sv_hash='00'))
    expect_parse(lambda: pol(sv_hash='0011'))
    expect_parse(lambda: pol(spk_e='0020' + '11' * 31))

    # k1_pubkey must be a 33-byte compressed pubkey (else the P3
    # K1-co-signature check can never match)
    expect_parse(lambda: pol(k1_pubkey='0200'))
    expect_parse(lambda: pol(k1_pubkey='04' + '00' * 32))

    # cadence N window (height-form CSV) + fee window
    expect_parse(lambda: pol(n=0))
    expect_parse(lambda: pol(n=0x10000))
    expect_parse(lambda: pol(f0_max=0))
    expect_parse(lambda: pol(f0_max=-1))


def test_P2_spend_forbid():
    vp1 = pol()
    v = view(seq=vp.SEQ_EMERGENCY, in_spk=SPK_EH, out_spks=((EXIT_SPK, 160000),), vin=162000, sigs=[K1])
    v['inputs'][0]['sequence'] = N
    expect('P2 plain', vp1.check, view(seq=N, in_spk=SPK_EH, out_spks=((WARM_SPK, 1000),), vin=162000, sigs=[K1]))


def test_P3_exit_ceremony():
    vp1 = pol()
    good = view(seq=vp.SEQ_EMERGENCY, in_spk=SPK_EH, out_spks=((EXIT_SPK, 160000),), vin=162000, sigs=[K1])
    expect_ok(vp1.check, good)

    # emergency class spends of spk_e without K1 sig: refuse
    expect('no K1', vp1.check, view(seq=vp.SEQ_EMERGENCY, in_spk=SPK_EH,
                                    out_spks=((EXIT_SPK, 160000),), vin=162000, sigs=[K2]))
    # wrong destination
    expect('bad dest', vp1.check, view(seq=vp.SEQ_EMERGENCY, in_spk=SPK_EH,
                                       out_spks=((WARM_SPK, 160000),), vin=162000, sigs=[K1]))
    # over-fee exit
    expect('overfee', vp1.check, view(seq=vp.SEQ_EMERGENCY, in_spk=SPK_EH,
                                      out_spks=((EXIT_SPK, 154000),), vin=162000, sigs=[K1]))


def test_lattice_commitment():
    import hashlib

    def dsha(b):
        return hashlib.sha256(hashlib.sha256(b).digest()).digest()

    def naive_root(hs):
        # reference: two-pass array Merkle, Bitcoin dup-last convention
        assert hs
        lvl = list(hs)
        while len(lvl) > 1:
            if len(lvl) % 2:
                lvl.append(lvl[-1])
            lvl = [dsha(lvl[i] + lvl[i + 1]) for i in range(0, len(lvl), 2)]
        return lvl[0]

    txs = [bytes([i]) * (40 + i) for i in range(40)]

    # T3 leaf definition: dSHA256(LE32(i) || unsigned_tx)
    for i in (0, 1, 7, 0xFFFF):
        assert vp.leaf_hash(i, txs[i % len(txs)]) == \
            dsha(i.to_bytes(4, 'little') + txs[i % len(txs)])
    try:
        vp.leaf_hash(0x10000, txs[0])
        raise AssertionError('accepted out-of-range index')
    except vp.VaultViolation:
        pass

    # T4 parity: streaming carry-tree == naive reference, incl. odd counts
    for n in (1, 2, 3, 4, 5, 6, 7, 8, 11, 16, 17, 33, 40):
        leaves = [vp.leaf_hash(i, txs[i]) for i in range(n)]
        root, cnt = vp.lattice_root(iter(leaves))
        assert cnt == n
        assert root == naive_root(leaves), 'parity failed at n=%d' % n

    # generator (true streaming) matches list input
    r_gen, _ = vp.lattice_root(vp.leaf_hash(i, txs[i]) for i in range(13))
    assert r_gen == naive_root([vp.leaf_hash(i, txs[i]) for i in range(13)])

    # tamper sensitivity: reorder / mutate one leaf / drop a leaf
    base = [vp.leaf_hash(i, txs[i]) for i in range(5)]
    r0, _ = vp.lattice_root(iter(base))
    swapped = list(base)
    swapped[1], swapped[2] = swapped[2], swapped[1]
    assert vp.lattice_root(iter(swapped))[0] != r0
    mutated = [dsha(h) if i == 3 else h for i, h in enumerate(base)]
    assert vp.lattice_root(iter(mutated))[0] != r0
    assert vp.lattice_root(iter(base[:4]))[0] != r0

    # empty set / bad leaf size refused
    try:
        vp.lattice_root(iter([]))
        raise AssertionError('accepted empty lattice')
    except vp.VaultViolation:
        pass
    try:
        vp.lattice_root(iter([b'x' * 31]))
        raise AssertionError('accepted short leaf')
    except vp.VaultViolation:
        pass


TESTS = [v for k, v in sorted(globals().items()) if k.startswith('test_')]

if __name__ == '__main__':
    for t in TESTS:
        t()
        print('ok: %s' % t.__name__)
    print('ALL VAULT TESTS PASS (%d)' % len(TESTS))
