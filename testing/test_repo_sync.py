#!/usr/bin/env python3
# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# testing/test_repo_sync.py - automated repo sync invariant.
#
# The vault work maintains TWO host app copies that must stay in lockstep:
#   - the standalone repo  ../coldcard-vault-hostapp/  (canonical)
#   - the firmware mirror  hostapp/ + shared/          (this repo)
# The sync rule so far was verified by hand at each re-sync; this test
# makes it a one-command check:
#
#   1. shared/vault_policy.py is BYTE-IDENTICAL to the standalone
#      repo's vault_policy.py (the host/device agreement core - any
#      drift means host and device no longer agree by construction).
#   2. hostapp/vault_tree.py equals the standalone vault_tree.py as
#      CODE: the only permitted differences are the documented wiring
#      (header/usage comments and the sys.path line that locates
#      vault_policy.py in each tree layout).
#   3. testing/test_vault_hostapp.py equals the standalone
#      tests/test_vault_hostapp.py the same way (plus the documented
#      APP path wiring).
#   4. structural expectation: the GUI lives ONLY in the standalone
#      repo, and each copy's sys.path wiring actually points at its
#      own vault_policy.py (so a 'passing' normalize can't hide a
#      copy whose wiring is broken).
#
# Run from the repo root:  python3 testing/test_repo_sync.py
# Exits non-zero on any failure.

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FW = os.path.dirname(HERE)                       # coldcard-vault/
SA = os.path.join(os.path.dirname(FW), 'coldcard-vault-hostapp')

R = []


def ok(name, cond, detail=''):
    R.append(bool(cond))
    print('[%s] %s%s' % ('ok' if cond else 'FAIL', name,
                         ('  << %s' % detail) if (detail and not cond)
                         else ''))
    return bool(cond)


def code_lines(path):
    # normalized 'code' view: full-line comments and blank lines dropped
    # (the documented wiring differences are comments + sys.path lines),
    # sys.path wiring dropped, and the documented APP path wiring in the
    # test file normalized to the standalone form
    out = []
    for line in open(path).read().splitlines():
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        if 'sys.path.' in line:
            continue
        line = line.replace("os.path.join(HERE, '..', 'hostapp', "
                            "'vault_tree.py')",
                            "os.path.join(HERE, '..', 'vault_tree.py')")
        out.append(line)
    return out


def main():
    print('=== repo sync invariant: firmware mirror vs standalone ===')
    for f in ('vault_tree.py', 'vault_policy.py', 'gui.py'):
        if not os.path.isfile(os.path.join(SA, f)):
            raise SystemExit('standalone repo not found at %s' % SA)

    # 1. the policy core must be byte-identical
    fw_pol = open(os.path.join(FW, 'shared', 'vault_policy.py'), 'rb').read()
    sa_pol = open(os.path.join(SA, 'vault_policy.py'), 'rb').read()
    ok('vault_policy.py byte-identical across repos', fw_pol == sa_pol)

    # 2. the host app equals as code (wiring comments/path excepted)
    fw_tree = code_lines(os.path.join(FW, 'hostapp', 'vault_tree.py'))
    sa_tree = code_lines(os.path.join(SA, 'vault_tree.py'))
    ok('vault_tree.py identical as code (%d lines each)' % len(sa_tree),
       fw_tree == sa_tree,
       'first divergence: %s' % next(
           (repr((i, a, b)) for i, (a, b) in enumerate(
               zip(fw_tree, sa_tree)) if a != b),
           'length %d vs %d' % (len(fw_tree), len(sa_tree))))

    # 3. the hostapp test battery equals as code
    fw_test = code_lines(os.path.join(FW, 'testing',
                                      'test_vault_hostapp.py'))
    sa_test = code_lines(os.path.join(SA, 'tests',
                                      'test_vault_hostapp.py'))
    ok('test_vault_hostapp.py identical as code', fw_test == sa_test,
       'first divergence: %s' % next(
           (repr((i, a, b)) for i, (a, b) in enumerate(
               zip(fw_test, sa_test)) if a != b),
           'length %d vs %d' % (len(fw_test), len(sa_test))))

    # 4. structural expectations + live wiring checks
    ok('GUI lives only in the standalone repo',
       os.path.isfile(os.path.join(SA, 'gui.py')) and
       not os.path.exists(os.path.join(FW, 'hostapp', 'gui.py')))
    fw_src = open(os.path.join(FW, 'hostapp', 'vault_tree.py')).read()
    sa_src = open(os.path.join(SA, 'vault_tree.py')).read()
    ok('firmware wiring points at ../shared/vault_policy.py',
       "sys.path.append(os.path.join(HERE, '..', 'shared'))" in fw_src)
    ok('standalone wiring points at its own vault_policy.py',
       'sys.path.append(HERE)' in sa_src)
    ok('both wirings resolve to the byte-identical policy core',
       fw_pol == sa_pol)

    n = sum(R)
    print('REPO SYNC: %d/%d checks pass' % (n, len(R)))
    if n != len(R):
        sys.exit(1)


if __name__ == '__main__':
    main()
