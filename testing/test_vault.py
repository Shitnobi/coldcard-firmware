# Host-runnable tests for shared/vault.py
# Run: python3 testing/test_vault.py     (no device, no pytest required)
import sys, os, types, tempfile, atexit, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'shared'))

# fake the glob/settings module before vault.py touches it
# NOTE: a plain dict whose KEY is 'get' still exposes dict.get (keys are not
# attributes on builtins) — so the shim must be a real object with a method.
_store = {'vault': None}

class _FakeSettings:
    def get(self, k, d=None):
        return _store.get(k, d)
    def set(self, k, v):
        _store[k] = v
    def remove_key(self, k):
        _store.pop(k, None)

glob_mod = types.ModuleType('glob')
glob_mod.settings = _FakeSettings()
sys.modules['glob'] = glob_mod

import vault
import vault_policy as vp

R = []
def ok(name, cond): R.append((name, bool(cond)))

os.chdir(tempfile.mkdtemp(prefix='vlog-'))   # ledger goes to a scratch dir
atexit.register(shutil.rmtree, os.getcwd(), True)

# --- fixtures: S_v-shaped vault spk, arbitrary distinct sink/warm/exit spks ----
K1 = b'\x02' + b'\x01' * 32
K2 = b'\x02' + b'\x02' * 32
K3 = b'\x02' + b'\x03' * 32
N = 1008

def pd(k): return bytes([len(k)]) + k
WS_V = b'\x63\x02\xf0\x03\xb2\x75\x67\x68\x52' + pd(K1) + pd(K2) + pd(K3) + b'\x53\xae'
SPK_V = vp.p2wsh_spk(WS_V)
SPK_E = vp.p2wsh_spk(b'\x51')            # stands in for the deepvault sink spk
EXIT_SPK = vp.p2wsh_spk(b'\x52')
WARM_SPK = vp.p2wsh_spk(b'\x53')

CFG = dict(n=N, sv_hash=SPK_V.hex(), spk_e=SPK_E.hex(),
           k1_pubkey=K1.hex(), f0_max=10000, exit_spk=EXIT_SPK.hex())

class UTXO:
    def __init__(s, spk, val): s.scriptPubKey, s.nValue = spk, val
class Inp:
    def __init__(s, spk, val, seq, part=None):
        s.utxo = UTXO(spk, val); s.sequence = seq; s.part_sigs = part or []
class Out:
    def __init__(s, spk, val): s.scriptPubKey, s.nValue = spk, val
class P:
    def __init__(s, ins, outs, lt=0): s.inputs, s.outputs, s.lock_time = ins, outs, lt

def enable(cfg): _store['vault'] = cfg
def p_emg(fee=500, seq=0xfffffffd): return P([Inp(SPK_V, 10_000 + fee, seq)], [Out(SPK_E, 10_000)])
def p_other(): return P([Inp(WARM_SPK, 5000, 0xfffffffd)], [Out(WARM_SPK, 4500)])

# --- 1 feature flag -------------------------------------------------------------
enable(None);            ok('flag off', not vault.is_enabled())
enable(dict(CFG, enabled=1)); ok('flag on', vault.is_enabled())
enable(dict(CFG, enabled=0)); ok('flag off again', not vault.is_enabled())

# --- 2 relevance -----------------------------------------------------------------
enable(dict(CFG, enabled=1))
ok('relevant vault in', vault.check_relevance(p_emg(), CFG))
ok('irrelevant', not vault.check_relevance(p_other(), CFG))
ok('relevance None cfg (no crash)', not vault.check_relevance(p_other(), None))
ok('relevance empty cfg', not vault.check_relevance(p_other(), {}))
ok('relevance bad-hex cfg -> relevant (fail-closed)',
   vault.check_relevance(p_other(), {'sv_hash': 'zz', 'spk_e': 'zz'}))

# --- 3 auto-approve a canonical emergency -----------------------------------------
appr, msg = vault.VaultMode.could_sign(p_emg())
ok('approve emergency', appr)
ok('class named', 'emergency' in msg.lower())

# --- 4 refuse a ladder spend with wrong cadence N-10 ------------------------------
bad = P([Inp(SPK_V, 12000, N - 10)], [Out(WARM_SPK, 11000)])
appr, msg = vault.VaultMode.could_sign(bad)
ok('refuse wrong-N ladder', not appr)
ok('reason mentions seq', 'seq' in msg.lower())

# --- 4b refuse sink entry that is not the emergency class (INV-SINK) --------------
sinky = P([Inp(SPK_V, 12000, N)], [Out(SPK_E, 11000)])
appr, msg = vault.VaultMode.could_sign(sinky)
ok('refuse ladder sink entry', not appr)

# --- 5 strict mode -----------------------------------------------------------------
enable(dict(CFG, enabled=1, strict=1))
appr, msg = vault.VaultMode.could_sign(p_other())
ok('strict refuses non-vault', not appr)
ok('strict reason', 'strict' in msg.lower())
enable(dict(CFG, enabled=1))
appr, msg = vault.VaultMode.could_sign(p_other())
ok('non-strict passes non-vault', appr)

# --- 6 fail-closed view builder ------------------------------------------------------
class BareInp:
    part_sigs = []; sequence = 0xfffffffd          # no .utxo at all
class P2:
    inputs = [BareInp()]; outputs = [Out(WARM_SPK, 1)]; lock_time = 0
appr, msg = vault.could_sign(CFG, P2())
ok('missing utxo refuses', not appr)
ok('reason missing utxo', 'witness_utxo' in msg)

# --- 7 vault_log append ----------------------------------------------------------------
vault.vault_log('TEST1'); vault.vault_log('TEST2')
lines = open('vault.log').read().splitlines()
ok('log has entries', len(lines) >= 2)   # earlier could_sign calls also log
ok('log content', any('TEST1' in l for l in lines) and any('TEST2' in l for l in lines))

# --- 8 enroll/enable lifecycle (menu helpers) ---------------------------------------
_store['vault'] = None
r1, m1 = vault.set_enabled(True)
ok('enable refused when empty', (not r1) and 'no policy' in m1)
ok('validate rejects empty', not vault.validate_cfg({})[0])

vault.save_cfg(dict(CFG, sv_hash='zz'))       # unparseable hex
ok('validate rejects bad hex', not vault.validate_cfg(vault._cfg())[0])

vault.save_cfg(dict(CFG, exit_spk=SPK_E.hex()))
ok('validate rejects exit_spk == spk_e',
   not vault.validate_cfg(vault._cfg())[0])
vault.save_cfg(dict(CFG, exit_spk=SPK_V.hex()))
ok('validate rejects exit_spk == sv_hash',
   not vault.validate_cfg(vault._cfg())[0])
vault.save_cfg(dict(CFG, k1_pubkey='0200'))
ok('validate rejects bad k1', not vault.validate_cfg(vault._cfg())[0])
vault.save_cfg(dict(CFG, sv_hash='0011'))
ok('validate rejects non-p2wsh sv_hash',
   not vault.validate_cfg(vault._cfg())[0])
vault.save_cfg(dict(CFG, n=0))
ok('validate rejects n=0', not vault.validate_cfg(vault._cfg())[0])
vault.save_cfg(dict(CFG, f0_max=0))
ok('validate rejects f0_max=0', not vault.validate_cfg(vault._cfg())[0])

vault.save_cfg(dict(CFG))                     # enroll dark
ok('enrolled dark', not vault.is_enabled())
r2, m2 = vault.set_enabled(True)
ok('enable works', r2 and vault.is_enabled())
ok('cfg preserved', vault._cfg().get('sv_hash') == SPK_V.hex())

r3, m3 = vault.set_enabled(False)
ok('disable works', r3 and not vault.is_enabled())

vault.wipe()
ok('wiped', not vault._cfg())
ok('enable refused after wipe', not vault.set_enabled(True)[0])

# --- 9 lattice commitment enrollment -------------------------------------------------
def lat_psbt(i, fee=500):
    p = p_emg(fee=fee)
    p.txn = bytes([i]) * (60 + i)      # stands in for raw global unsigned-tx bytes
    return p

enable(dict(CFG, enabled=1))
members = [lat_psbt(i) for i in range(5)]
root_hex, cnt = vault.enroll_lattice(CFG, members)
ok('lattice root is 64 hex', isinstance(root_hex, str) and len(root_hex) == 64)
ok('lattice count', cnt == 5)

r_rev, _ = vault.enroll_lattice(CFG, list(reversed(members)))
ok('order sensitivity', r_rev != root_hex)

members[2].txn = b'\xff' * 62          # one member's tx bytes changed
r_tamper, _ = vault.enroll_lattice(CFG, members)
ok('tamper sensitivity', r_tamper != root_hex)

bad = lat_psbt(9)
bad.inputs[0].sequence = N - 10        # wrong-N ladder member
try:
    vault.enroll_lattice(CFG, [lat_psbt(0), bad])
    ok('invalid member refused', False)
except vault.VaultViolation as e:
    ok('invalid member refused', 'lattice[1]' in str(e))

try:
    vault.enroll_lattice(CFG, [])
    ok('empty lattice refused', False)
except vault.VaultViolation:
    ok('empty lattice refused', True)

vault.store_lattice(root_hex, cnt)
ok('root stored', vault._cfg().get('lattice_root') == root_hex)
ok('count stored', vault._cfg().get('lattice_count') == 5)

# --- 9b. real-psbtObject shape: (pos,len) proxies + iterators ------------------
# vault.view_from_psbt/_iter_input_utxos/enroll_lattice have a second
# path for the real firmware psbtObject (nSequence from input_iter,
# witness_utxos as (pos,len) proxies read via get_utxo(), part_sigs =
# {pubkey: sig} dicts, .txn = (pos,len) proxies). These fixtures mimic
# that shape so the real path gets host coverage too.
class RIn:
    def __init__(s, spk=None, val=None, seq=0xfffffffd, part=None):
        s.witness_utxo = None if spk is None else (0, 1)   # blank when None
        s.utxo = None
        s._o = UTXO(spk, val) if spk is not None else None
        s.part_sigs = part or {}
        s._seq = seq
    def get_utxo(s, idx):
        assert s._o is not None, 'no utxo'
        return s._o
class RTxIn:
    def __init__(s, seq): s.nSequence = seq
class ROut:
    def __init__(s, spk, val): s.scriptPubKey, s.nValue = spk, val
class RPsbt:
    def __init__(s, ins, outs, lt=0):
        s.inputs, s.outputs, s.lock_time = ins, outs, lt
        s._raw = b''
    def input_iter(s):
        for i, n in enumerate(s.inputs): yield i, RTxIn(n._seq)
    def output_iter(s):
        for i, o in enumerate(s.outputs): yield i, o
    def get(s, val): return s._raw[val[0]:val[0] + val[1]]

def r_emg(fee=500):
    return RPsbt([RIn(SPK_V, 10_000 + fee)], [ROut(SPK_E, 10_000)])

appr, msg = vault.VaultMode.could_sign(r_emg())
ok('real-path approve emergency', appr)
ok('real-path class named', 'emergency' in msg.lower())

bad = RPsbt([RIn(SPK_V, 12000, N - 10)], [ROut(WARM_SPK, 11000)])
appr, msg = vault.VaultMode.could_sign(bad)
ok('real-path refuse wrong-N ladder', not appr)
ok('real-path reason seq', 'seq' in msg.lower())

# P1 change contradiction: out == spk_e but psbtObject flagged the
# output as wallet change (is_change carried into the view)
chg = r_emg(); chg.outputs[0].is_change = True
appr, msg = vault.VaultMode.could_sign(chg)
ok('real-path refuse change-flagged emergency', not appr)

# P3 exit: K1 partial sig in the psbtObject-style part_sigs dict
K1SIG = b'\x30' + b'\x01' * 70
ex = RPsbt([RIn(SPK_E, 9600, part={K1: K1SIG})], [ROut(EXIT_SPK, 9000)])
appr, msg = vault.VaultMode.could_sign(ex)
ok('real-path approve exit w/ K1 partial', appr)
ex2 = RPsbt([RIn(SPK_E, 9600, part={K2: K1SIG})], [ROut(EXIT_SPK, 9000)])
appr, msg = vault.VaultMode.could_sign(ex2)
ok('real-path refuse exit w/o K1 partial', not appr)

# fail-closed on a missing witness_utxo (real path)
nu = RPsbt([RIn(SPK_V, 10500), RIn()], [ROut(SPK_E, 10_000)])
appr, msg = vault.VaultMode.could_sign(nu)
ok('real-path missing witness_utxo refuses', not appr)
ok('real-path reason missing utxo', 'witness_utxo' in msg)

# lattice over the real-path shape == lattice over host fakes (same raw
# global-unsigned-tx bytes, read through the .txn proxy)
rmem = [r_emg(fee=500 + i) for i in range(5)]
for i, p in enumerate(rmem):
    p.txn = (0, 60 + i); p._raw = bytes([i]) * (60 + i)
rroot_hex, rcnt = vault.enroll_lattice(CFG, rmem)
ok('real-path lattice root is 64 hex', len(rroot_hex) == 64)
ok('real-path lattice count', rcnt == 5)
fmem = [lat_psbt(i, fee=500 + i) for i in range(5)]
froot_hex, _ = vault.enroll_lattice(CFG, fmem)
ok('lattice real-path root == fake-path root', rroot_hex == froot_hex)

fails = [n for n, c in R if not c]
print('VAULT GLUE: %d/%d checks pass' % (len(R) - len(fails), len(R)))
for n in fails: print('    FAIL: %s' % n)
sys.exit(1 if fails else 0)
