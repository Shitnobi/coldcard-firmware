# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# unix/vault_sim_e2e.py - FULL end-to-end vault flow, inside the simulator.
#
# Runs INSIDE the coldcard-mpy binary with the real nvstore and the REAL
# firmware PSBT parser (psbtObject.read_psbt) against real binary PSBT
# files generated on the host by unix/vault_e2e_gen.py:
#
#   enroll policy -> validate -> enable -> lattice enrollment from parsed
#   PSBTs (root cross-checked vs the host-computed root) -> store -> the
#   auth.py signing choke point (VaultMode.could_sign) over every policy
#   class (P1 emergency / P3 exit / INV-SEQ ladder / INV-SINK / locktime
#   pin / non-vault pass / strict refuse) -> ccc.py velocity-ratchet
#   delegation -> wipe.
#
# Run from unix/work (like the launcher does):
#   ../coldcard-mpy -X heapsize=9m ../vault_sim_e2e.py <fd> -1 <fd> <fd>
# (fd args are the display/led/data fds the frozen ckcc mocks expect; the
#  harness passes /dev/null descriptors.)

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

import json
import binascii
import vault
import vault_policy as vp
from psbt import psbtObject

R = []
def ok(name, cond):
    R.append((name, bool(cond)))
    if not cond:
        print('    FAIL: %s' % name)

E2E = 'sim-e2e/'
try:
    import os
    _d = os.getenv('VAULT_E2E_DIR')
    if _d:
        E2E = _d if _d.endswith('/') else _d + '/'
except Exception:
    pass
# hostapp/vault_tree.py writes manifest.json; the generator writes expected.json
try:
    exp = json.loads(open(E2E + 'manifest.json').read())
except OSError:
    exp = json.loads(open(E2E + 'expected.json').read())

_open_fds = []
def parse(fname):
    # real firmware parse; the fd must stay open (proxies hold offsets)
    fd = open(E2E + fname, 'rb')
    _open_fds.append(fd)
    return psbtObject.read_psbt(fd)

# --- 1. enroll + enable (host-provided cfg) ------------------------------
cfg = dict(exp['cfg'])
res, msg = vault.validate_cfg(cfg)
ok('host cfg validates', res)
vault.save_cfg(dict(cfg))
res, msg = vault.set_enabled(True)
ok('vault mode enabled', res and vault.is_enabled())

# --- 1b. master-scoping: the gate stays ON during a tmp-seed session ----
# 'vault' is in nvstore MASTER_FIELDS; leaving_master_seed() captures it
# into SettingsObject.master_sv_data and _cfg() reads via master_get.
# Simulate the session switch with the real nvstore class state: without
# master-scoping, _cfg() would read the empty tmp scope and the vault
# gate would silently turn OFF for the whole session.
nvstore.SettingsObject.master_nvram_key = b'\x22' * 16
nvstore.SettingsObject.master_sv_data['vault'] = s.current.get('vault')
ok('gate on during tmp session', vault.is_enabled())
_leaf = (exp.get('files') or ['emg0.psbt'])[0]
appr, msg = vault.VaultMode.could_sign(parse(_leaf))
ok('policy path works during tmp session (canonical leaf approved)', appr)
nvstore.SettingsObject.master_nvram_key = None
nvstore.SettingsObject.master_sv_data.clear()
ok('gate intact after tmp session ends', vault.is_enabled())

# --- 2. lattice enrollment from REAL parsed PSBTs ------------------------
cnt_want = exp['lattice_count']
names = exp.get('files') or ['emg%d.psbt' % i for i in range(cnt_want)]
members = [parse(f) for f in names]
root_hex, cnt = vault.enroll_lattice(cfg, members)
ok('lattice root == host root', root_hex == exp['lattice_root'])
ok('lattice count', cnt == cnt_want)
vault.store_lattice(root_hex, cnt)
ok('lattice stored in settings', vault._cfg().get('lattice_root') ==
   exp['lattice_root'])

try:
    vault.enroll_lattice(cfg, [members[0], parse('ladder_bad.psbt')])
    ok('bad lattice member refused', False)
except OSError:
    pass          # this tree has no ladder_bad.psbt; check not applicable
except vp.VaultViolation as e:
    ok('bad lattice member refused', 'lattice[1]' in str(e))

# --- 2b. manifest cross-check (Decision B, choice b) --------------------
# hostapp trees ship manifest.json declaring the deposit outpoint every
# leaf must spend; generator trees don't, so exercise the same machinery
# with leaf 0's own (real-psbtObject) outpoint.
if exp.get('deposit_txid') is not None:
    man = {'deposit_txid': exp['deposit_txid'], 'vault_vout': exp['vault_vout'],
           'lattice_count': exp['lattice_count'], 'cfg': exp['cfg']}
    try:
        vault.check_lattice_binding(man, members, cfg=cfg)
        ok('manifest binding: full batch spends declared outpoint', True)
    except vp.VaultViolation as e:
        ok('manifest binding: full batch spends declared outpoint', False)
        print('      %s' % e)
    for name, bad in [
        ('wrong vault_vout refused', dict(man, vault_vout=man['vault_vout'] + 1)),
        ('wrong deposit_txid refused', dict(man, deposit_txid='ee' * 32)),
        ('leaf count mismatch refused', dict(man, lattice_count=cnt + 1)),
        ('cfg divergence refused', dict(man, cfg=dict(exp['cfg'], n=999))),
    ]:
        try:
            vault.check_lattice_binding(bad, members, cfg=cfg)
            ok('manifest binding: %s' % name, False)
        except vp.VaultViolation:
            ok('manifest binding: %s' % name, True)
else:
    # generator tree: leaves have distinct prevouts, so build the
    # manifest from leaf 0's own outpoint (real psbtObject -> CTxIn ->
    # COutPoint: exercises the int<->bytes / display-order conversion).
    _txin = list(members[0].input_iter())[0][1]
    _txid_disp = str(binascii.hexlify(
        bytes(reversed(_txin.prevout.hash.to_bytes(32, 'little')))), 'ascii')
    man = {'deposit_txid': _txid_disp, 'vault_vout': _txin.prevout.n,
           'lattice_count': 1}
    try:
        vault.check_lattice_binding(man, [members[0]])
        ok('manifest binding: leaf-0 outpoint passes (byte order ok)', True)
    except vp.VaultViolation as e:
        ok('manifest binding: leaf-0 outpoint passes (byte order ok)', False)
        print('      %s' % e)
    for name, bad, psbts in [
        ('wrong vault_vout refused', dict(man, vault_vout=_txin.prevout.n + 1),
         [members[0]]),
        ('wrong deposit_txid refused', dict(man, deposit_txid='ee' * 32),
         [members[0]]),
        ('leaf count mismatch refused', dict(man, lattice_count=2), [members[0]]),
        ('leaf with different prevout refused', man, members),
    ]:
        try:
            vault.check_lattice_binding(bad, psbts)
            ok('manifest binding: %s' % name, False)
        except vp.VaultViolation:
            ok('manifest binding: %s' % name, True)

# --- 3. the signing choke point (exact call auth.py makes) ---------------
for fname, want, sub, note in exp['expect']:
    appr, msg = vault.VaultMode.could_sign(parse(fname))
    good = (appr == want) and (sub in msg)
    ok('gate %s: %s' % (fname, note), good)
    if not good:
        print('      got appr=%r msg=%r (want %r)' % (appr, msg, want))

# --- 4. strict mode (optional in manifest) --------------------------------
if exp.get('strict_expect'):
    fname, want, sub = exp['strict_expect']
    c2 = vault._cfg()
    c2['strict'] = 1
    vault.save_cfg(c2)
    appr, msg = vault.VaultMode.could_sign(parse(fname))
    ok('strict refuses non-vault', (appr == want) and (sub in msg))
    c2['strict'] = 0
    vault.save_cfg(c2)

# --- 5. ccc.py velocity-ratchet delegation (optional in manifest) ---------
if exp.get('ccc_vel'):
    try:
        import ccc
        pol = ccc.SpendingPolicy('ccc', {'vel': 100})  # vel=100 blocks would
        try:
            pol.meets_policy(parse('emg0.psbt'))
            r1 = True
        except Exception as e:
            r1 = False
            print('      emg0 meets_policy raised: %s' % e)
        try:
            pol.meets_policy(parse('novault.psbt'))
            r2 = False
        except ccc.SpendPolicyViolation as e:
            r2 = 'nLockTime' in str(e)
        ok('ccc: vault tx skips velocity ratchet', r1)
        ok('ccc: non-vault hit by velocity ratchet', r2)
    except Exception as e:
        ok('ccc import', False)
        print('      ccc unavailable: %s' % e)

# --- cleanup ---------------------------------------------------------------
# PR C: wipe() now returns (ok, msg) and never raises - check it, a
# silently-surviving policy would poison the next e2e run
res, msg = vault.wipe()
ok('cleanup wipe ok', res)
s.save()

n = sum(1 for _, c in R if c)
print('VAULT SIM E2E: %d/%d checks pass' % (n, len(R)))
if n != len(R):
    sys.exit(1)
