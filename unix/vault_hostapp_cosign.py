# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# unix/vault_hostapp_cosign.py - sim-side co-signer for the hostapp
# regtest e2e (unix/vault_hostapp_regtest.py).
#
# Companion to vault_core_sign.py: instead of building its own spend
# PSBT, it co-signs the HOSTAPP-BUILT emergency leaf (outdir/emg0.psbt,
# augmented host-side with the user's K1 partial signature and BIP-32
# key origins) through the full real firmware signing chain:
#
#   read_psbt -> validate -> consider_* -> VaultMode.could_sign ->
#   sign_it -> finalize
#
# after enrolling the policy + lattice exactly from the hostapp's own
# manifest.json (the same enrollment vault_sim_e2e.py performs), so
# what gets co-signed is a byte-for-byte hostapp artifact spending a
# REAL confirmed regtest deposit.
#
# Env (run from unix/work, like the launcher):
#   VAULT_COSIGN_DIR   the hostapp build outdir (absolute path)
#   VAULT_COSIGN_FILE  the K1-augmented leaf file name (emg0.k1.psbt)
# Writes <dir>/cosign_response.json: {signed_hex, txid, class}.
#
# Invocation (fds like vault_core_sign.py):
#   MICROPYPATH=:../../shared ../coldcard-mpy -X heapsize=9m \
#       ../vault_hostapp_cosign.py 3 4 5 6 < /dev/null
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

# start clean: a previous crashed run may have left a stale 'vault' key
if s.get('vault', None):
    s.remove_key('vault')
    s.save()

import os
import binascii
import uio
import json

def b2h(b):
    return str(binascii.hexlify(bytes(b)), 'ascii')

def h2b(h):
    return binascii.unhexlify(h)

E2E = os.getenv('VAULT_COSIGN_DIR') or './'
if not E2E.endswith('/'):
    E2E += '/'
FNAME = os.getenv('VAULT_COSIGN_FILE') or 'emg0.k1.psbt'

# ---- device identity (fixed seed, same as every vault sim suite) ----
from sim_secel import SECRETS
import bip39
WORDS = ('abandon abandon abandon abandon abandon abandon abandon '
         'abandon abandon abandon abandon about')
seed = bip39.a2b_words(WORDS.split())
raw = bytes([0x80]) + seed + bytes(72 - 1 - len(seed))
SECRETS['_pin1_secret'] = b2h(raw)

from pincodes import pa
pa.setup('12-12')
pa.login()

MY_XFP = s.get('xfp', 0)

class FakeDis:
    def fullscreen(self, *a): pass
    def progress_sofar(self, *a): pass
    def progress_bar_show(self, *a): pass
    def progress_bar_hide(self, *a): pass
glob.dis = FakeDis()

import vault
import vault_policy as vp
from psbt import psbtObject

# ---- 1. enroll policy + lattice from the hostapp's own manifest -------
man = json.loads(open(E2E + 'manifest.json').read())
cfg = dict(man['cfg'])
res, msg = vault.validate_cfg(cfg)
if not res:
    print('COSIGN FAIL: host cfg refused: %s' % msg)
    sys.exit(1)
vault.save_cfg(dict(cfg, enabled=1))
if not vault.is_enabled():
    print('COSIGN FAIL: vault mode not enabled')
    sys.exit(1)

names = man['files']
fds = []                      # must stay open: proxies hold offsets
members = []
for f in names:
    fd = open(E2E + f, 'rb')
    fds.append(fd)
    members.append(psbtObject.read_psbt(fd))
root_hex, cnt = vault.enroll_lattice(cfg, members)
if root_hex != man['lattice_root'] or cnt != man['lattice_count']:
    print('COSIGN FAIL: lattice root/count mismatch vs manifest')
    sys.exit(1)
vault.store_lattice(root_hex, cnt)

# ---- 2. the K1-augmented hostapp leaf through the real signing chain --
fd = open(E2E + FNAME, 'rb')
fds.append(fd)
p = psbtObject.read_psbt(fd)
for idx, txin in p.input_iter():
    p.inputs[idx].validate(idx, txin, p.my_xfp, p)
p.consider_keys()
p.consider_inputs(cosign_xfp=None)
p.consider_outputs()
p.consider_dangerous_sighash()

appr, msg = vault.VaultMode.could_sign(p)
if not appr:
    print('COSIGN FAIL: gate refused the hostapp leaf: %s' % msg)
    sys.exit(1)

p.sign_it()
if not p.is_complete():
    print('COSIGN FAIL: not complete after device signature')
    sys.exit(1)

out = uio.BytesIO()
txid = p.finalize(out)
resp = {'signed_hex': b2h(bytes(out.getvalue())), 'txid': txid,
        'class': msg}
with open(E2E + 'cosign_response.json', 'w') as f:
    f.write(json.dumps(resp))
print('COSIGN OK: %s (%s)' % (txid, msg))

# ---- cleanup -----------------------------------------------------------
vault.wipe()
s.save()
