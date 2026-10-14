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
