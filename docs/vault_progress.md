# Vault work — progress ledger (2026-10-14)

Branch `vault-cosign-policy` on coldcard-vault (Coldcard firmware fork).

## Done and committed

- `shared/vault_policy.py` — pure stdlib decision core (structural S_v/S_e
  parsers, sequence classification, P1/P2/P3 + INV-SEQ/INV-SINK checks,
  `decode_sequence`). Suite `testing/test_vault_policy.py` (host, CPython):
  **7/7 tests pass ("ALL VAULT TESTS PASS", 45 checks)** — verified by
  user run; local harness returned corrupt output mid-session so the pass
  was user-verified, then re-verified at commit time below.
- `docs/vault_signing_gameplan.md` — hook recon + ruleset + design.
- `docs/vault_device_mode_gameplan.md` — device-mode integration plan
  (Option 2: standalone `VaultFeature`; Option 1: CCC `meets_policy`
  delegation; view builder spec; NVS `vault`; minimal menu; 5-commit
  landing order).
- `docs/vault_lattice_commitment_plan.md` — TENTATIVE enrollment-time
  Merkle commitment over the vault PSBT lattice (leaf = dSHA256 of
  LE32(index)+unsigned-tx bytes; Bitcoin-style dup-last tree; device
  recomputes + displays root at enrollment; deposit gates on stored root;
  explicit no-spend-time-membership scoping decision + residual risk).

## Known history (kept honest)

- Commit `3975301` ("all 45 checks passing") was committed while tests
  were FAILING; the actual fixes (key alignment sv_hash/k1_pubkey/
  exit_spk, `.get("is_change")`, sink-entry guard, locktime rule) landed
  in the follow-up commit shipped with this ledger.
- Two docs drafts (device-mode plan, progress) were lost to failed shell
  heredocs during the session; both were rewritten via direct file writes.
- `ccc.py` once gained a stray `from menu import SystemMenu` (no such
  class); reverted in the fix commit.

## NOT done (next)

1. DONE 2026-10-14 (second attempt) — `shared/vault.py` `VaultMode` glue +
   auth.py hook + host test suite. See "Session 2026-10-14 (b)" below.
2. DONE 2026-10-14 — `ccc.py` `meets_policy` skips the height-based
   velocity ratchet for vault-relevant txs (they pin nLockTime==0, which
   the ratchet would always refuse); warnings / magnitude / whitelist
   still apply (belt-and-suspenders).
3. DONE 2026-10-14 — `shared/vault_menu.py` `VaultConfigMenu` + flow.py
   'Vault Co-Sign' item in the Spending Policy submenu. Menu: Vault Mode
   on/off (refused until enrolled + valid), Enroll Policy via JSON file
   (USB/SD, enrolls dark), Cadence N, Max Fee, Exit Destination,
   Commitment Root, Wipe. Settings key is `vault`; gameplan docs updated
   from `vaultcfg` to match the implementation.
4. DONE 2026-10-14 — lattice commitment implemented per plan:
   `vault_policy.py` gained `sha256d`/`leaf_hash` (T3: dSHA256 of
   LE32(index)+unsigned-tx bytes)/`lattice_root` (T4: Bitcoin-style
   dup-last Merkle over a streamed carry-stack, O(log n) RAM, 2^16 leaf
   cap, empty-set refused); `vault.py` gained `enroll_lattice`
   (full-batch shape validation w/ leaf-indexed errors + root, never
   writes settings) and `store_lattice` (persists lattice_root/
   lattice_count only after user confirms root == host root);
   `vault_menu.py` gained 'Enroll Lattice' (file-by-file .psbt selection,
   root short-form display, confirm-then-store) and the root+count
   display. Parity proven vs a naive two-pass reference tree across
   13 batch sizes incl. odd counts. USB framed transport (plan T7.4)
   simplified to the existing file picker.
5. DONE 2026-10-14 — simulator run (unix/ port). Built coldcard-mpy on a
   constrained host: submodules re-initialized, mpy-cross built first,
   `MICROPY_PY_FFI=0` (no libffi-dev, no sudo) +
   `CFLAGS_EXTRA="-Wno-error=dangling-pointer -Wno-error=enum-int-mismatch"`
   (old mpy vs new gcc). Two real bugs found and fixed by the simulator:
   (a) `vault.py`/`vault_policy.py` used `bytearray.fromhex`, which mpy
   v1.12 lacks -> replaced with `ubinascii`/`binascii` `unhexlify`
   (with ImportError fallback for host); (b) frozen `unix/variant/ckcc.py`
   `get_sim_root_dirs` assumed FFI libc getcwd -> no-FFI fallback to
   `cwd='.'` (launcher runs with cwd=unix/work). Validation, two tiers:
   (1) `unix/vault_sim_smoke.py` — device-context smoke run inside
   coldcard-mpy with real nvstore (SettingsObject + MK4_WORKDIR):
   14/14 checks incl. NVS round-trip, mpy-path emergency-approve and
   wrong-N ladder refuse, known-answer lattice root (computed
   independently on CPython host)
   `750024e529e68a0e2bb6abe0e6b58aab3e327573d1ca1ba193ff942924a993e9`
   (5 leaves, cross-runtime agreement), vault.log written,
   VaultConfigMenu constructs, wipe; (2) full headless firmware boot
   `python3 ./simulator.py --headless` — clean through sim_boot ->
   main -> 'Start: mainline' (flow.py vault_menu import chain) with no
   tracebacks. Host suites re-verified green after the portability
   fixes: policy 8/8, glue 34/34.

## Session 2026-10-14 (b) — vault mode glue landed (for real)

- `shared/vault.py` (153 lines): `VaultMode` class, CCCFeature-style.
  Settings key `vault` (dict): `enabled`, `strict`, plus policy fields
  `sv_hash`, `spk_e`, `k1_pubkey`, `n`, `f0_max`, `exit_spk`. Relevance
  sniff on input utxo spk; fail-closed view builder (missing
  witness_utxo -> refuse); `could_sign` returns `(ok, msg)`, never
  raises; append-only `vault.log` ledger (never raises).
- `shared/auth.py` hook: in `interact()` immediately after
  `CCCFeature.could_cosign` (L445): if `VaultMode.is_enabled()`, call
  `VaultMode.could_sign(self.psbt)`; refusal -> `self.failure(v_msg,
  title='VAULT')`. Unexpected vault errors also block (fail closed).
- `testing/test_vault.py`: 17-check host suite (feature flag, relevance,
  emergency approve, wrong-N ladder refuse, INV-SINK refuse, strict mode,
  missing-utxo fail-closed, vault_log). Runs in a mkdtemp so vault.log
  never dirties the repo.
- Test reality: **pytest is not installed on this box.** Suites run
  DIRECTLY: `python3 testing/test_vault_policy.py` -> "ALL VAULT TESTS
  PASS (7)" (45 checks); `python3 testing/test_vault.py` ->
  "VAULT GLUE: 17/17 checks pass". Any earlier pytest-count claims were
  garbled harness output.

## Session 2026-10-14 (b) — kept honest

- Every commit claimed after `de3867d` in the prior session silently
  no-op'd; HEAD was still `de3867d` at session start. The on-disk file
  edits survived; the commits and several ledger appends did not. This
  session re-verified and re-landed everything with in-call `git log`
  verification.
- Glue-suite bug found by user run: the fake settings object was a
  plain dict with a `get` KEY — builtin `dict.get` is not shadowed by
  keys, so `settings.get('vault')` returned None and every vault-relevant
  tx degraded to "not vault-relevant" (10/17 pass). Fixed with a real
  `_FakeSettings` class shim -> 17/17.
- Second test bug: `vault.log` assertion expected exactly 2 lines but
  earlier `could_sign` calls also append; relaxed to `>= 2`.

## Session 2026-10-14 (c) — full end-to-end flow in the simulator

User asked for the whole flow run in the simulator with fake PSBTs. Two
deliverables:

- **REAL-PSBT adapter in `shared/vault.py`** (integration gap found while
  preparing the run): the duck-typed view (`inp.utxo.scriptPubKey`,
  `inp.sequence`, `psbt.txn` as bytes) only worked on host-test fakes.
  Real firmware `psbtObject` stores utxo/witness_utxo as (pos,len) file
  proxies and keeps nSequence in the unsigned tx, so every real PSBT
  would have fail-closed with 'missing witness_utxo'. Added:
  `_iter_input_utxos` (relevance sniff via `input.get_utxo(idx)` /
  duck-typed fallback), a real-PSBT branch in `view_from_psbt`
  (sequences from `input_iter()`, outputs from `output_iter()`,
  part_sigs dict -> pubkey list), and proxy-aware `.txn` extraction in
  `enroll_lattice`. Host suites stayed green (fakes still work).
- **End-to-end tooling**: `unix/vault_e2e_gen.py` (host) builds REAL
  BIP-174 v0 PSBT binaries covering every policy class (P1 emergency,
  P3 exit w/ K1 partial sig, correct-N and wrong-N ladders, INV-SINK
  sink-paying ladder, locktime-pinned emergency, non-vault spend) plus
  `expected.json` with the host-computed lattice root;
  `unix/vault_sim_e2e.py` (device) parses them with the real
  `psbtObject.read_psbt` inside coldcard-mpy and runs: enroll -> enable
  -> lattice enrollment (root cross-checked vs host) -> store -> the
  exact auth.py choke-point call `VaultMode.could_sign` over all
  scenarios -> strict-mode refuse -> `ccc.SpendingPolicy({'vel':100})`
  velocity-ratchet delegation (vault tx skips, non-vault refused
  'no nLockTime') -> wipe.

Test reality: `VAULT SIM E2E: 16/16 checks pass` (rc=0, no stderr);
smoke re-run `14/14`; host suites `34/34` and `8/8`. All in the same
run after the adapter landed. Lattice root agreement host<->device over
real PSBT tx bytes: `8317744dbdd8cb62975ede46c71874681de147bcc95a6c6e3e`
`a244261c3ea6e1` (5 leaves). Generated PSBTs live in unix/work/sim-e2e
(not committed; regenerate with the generator).

## Session 2026-10-14 (d) — basic host app: funding PSBT -> vault PSBT tree

- **`hostapp/vault_tree.py`** (new, CPython host tool): accepts a funding
  PSBT in three shapes — "just the input" (inputs w/ witness utxos, no
  outputs), input(s) with an INCORRECT output (warned + replaced), or an
  already-correct output paying S_v (accepted as deposit) — and builds
  the vault PSBT tree: `deposit.psbt` (funding -> S_v, funding input
  maps carried verbatim), `emg<i>.psbt` pre-authorized emergency leaves
  (spend deposit txid:vout0, SEQ_EMERGENCY, nLockTime==0, fee ladder,
  S_e destination) and `manifest.json` (device-enrollment cfg + HOST
  lattice root for the enrollment confirmation). Rule layer imported
  from shared/vault_policy.py so host/device agree by construction.
  CLI: `init-policy` (sample/demo keys) + `build`; fee/leaf params
  overridable. Minimal host PSBT/tx codec included (parse + serialize).
- **`unix/vault_sim_e2e.py` generalized**: manifest dir via
  VAULT_E2E_DIR env var; reads `manifest.json` (app) or `expected.json`
  (generator); leaf list from manifest `files`; strict/ccc sections and
  the ladder_bad check are optional (skipped when absent).
- **`testing/test_vault_hostapp.py`**: 54 checks — all three funding
  shapes, deposit pays S_v at funding-fee, funding input maps carried,
  every leaf chained to the deposit txid w/ correct witness utxo, fee
  ladder, and the lattice root RE-DERIVED INDEPENDENTLY from the
  written files (not the manifest).
- Portability bug found + fixed: the app originally prepended shared/
  to sys.path, letting firmware shims (shared/random.py -> ngu) shadow
  CPython stdlib and break `import secrets`; now appended.
- Device validation: app-built tree (input-only funding case) run
  through unix/vault_sim_e2e.py in coldcard-mpy with real
  psbtObject parsing: enroll -> enable -> lattice root == manifest
  root -> all 5 leaves approved at the auth.py choke point ->
  `VAULT SIM E2E: 10/10 checks pass`.
- Test reality: hostapp 54/54; e2e 16/16 (regression, generator path);
  smoke 14/14; glue 34/34; policy 8/8. All in one run after the
  sys.path fix.

## Session 2026-10-14 (e) — external review: 12 issues, 3 fix PRs merged

- **External review (Rob1Ham)** filed 12 issues against
  `vault-cosign-policy` @ ef162dfa plus three fix PRs from their fork
  (PR #13 fix/vault-hostapp e4b64c62 -> issues #1-4; PR #14
  fix/vault-policy cb80710d -> #5-9; PR #15 fix/vault-menu 8759e21d ->
  #10-11; #12 = review notes/open design questions). All 11 bug claims
  verified against the code locally (line-level) before any merge.
  Under the recovery-key invariant (2-of-3 S_v, unencumbered third key
  on the second device: the multisig branch sits outside the CSV/IF
  branch, so principal is ALWAYS recoverable), no issue can strand
  coins; residual severity concentrates in policy-enforcement and
  trust-display gaps (#8 is_change, #11d lattice pre-load, #4 silent
  root divergence).
- **Fixes merged after audit**: every diff read line-by-line; each
  PR's suites run individually (hostapp 110/110, glue 55/55 + policy
  9/9 for B, glue 46/46 for C - all reviewer claims reproduced
  exactly); 3-way merge built with one trivial textual conflict (PRs B
  and C both append test sections at the same anchor in
  testing/test_vault.py - resolved by keeping both). Notable fix
  accuracy: PR B's is_change fix correctly identified that
  _check_emergency L217 already refused change outputs and only the
  view was dropping the flag (consider_outputs runs before the vault
  gate in auth.py:418 < 447 - verified).
- **New issues from the fixes: none found.** Audited specifically:
  VaultPolicy.__init__ now raises VaultViolation - all three
  construction sites handle it (could_sign catches VaultViolation AND
  Exception -> fail-closed; validate_cfg wraps; enroll_lattice is
  pre-validated by the menu). wipe() API now returns (ok, msg) -
  vault_sim_e2e.py updated to check it (this session). save_cfg now
  flushes via settings.save() (ccc/sssp precedent); store_lattice
  calls it bare but the menu wraps it.
- **Known deviation**: issue #6 text demanded a P2WSH shape check on
  exit_spk too; PR B checks only the sv_hash/spk_e collision. Defensible
  (exit_spk is user-overridable to any destination in the hostapp),
  but the any-spk vs P2WSH-only exit-destination policy is an OPEN
  design decision (#12). Others open: master-scoping the vault cfg
  (MASTER_FIELDS vs menu predicate - PR C took the predicate), device
  cross-check of manifest vault_vout (#12.4), lattice re-enrollment
  after post-enrollment n/fee edits.
- **e2e driver**: vault_sim_e2e.py cleanup now asserts wipe() ok (was
  ignoring the new return value); sim-e2e is 17 checks, app-tree 11.
- Test reality after merge (one run): hostapp 110/110; glue 67/67;
  policy 9/9; sim e2e 17/17; app-tree e2e 11/11; smoke 14/14.
