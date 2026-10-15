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

## Session 2026-10-14 (f) — submodule artifact resolved; exit_spk confined to P2WSH

- **`external/libngu` "dirty submodule" artifact diagnosed and cleanly
  ignored**: the dirt is libngu's OWN build applying `bech32.patch`
  (libngu/Makefile:6, `BECH32_PATCH`) to its nested `libs/bech32`
  submodule on every build - it un-`static`s `convert_bits()` so
  `ngu/codecs.c` can link it. Verified byte-for-byte: the working-tree
  diff in bech32 is exactly the patch. Upstream by-design behavior;
  reverting would be futile (re-applied at next build). Clean handling:
  local-only `git config submodule.external/libngu.ignore dirty`
  (nothing committed, no effect on other clones) -> `git status` fully
  clean.
- **DESIGN DECISION (issue #6 tail / #12): exit destinations are
  confined to P2WSH.** `VaultPolicy.__init__` now shape-checks
  `exit_spk` (34 bytes, `OP_0 PUSH32`) exactly like `sv_hash`/`spk_e`
  - a non-P2WSH exit_spk is refused at enrollment (fail-closed).
  Hostapp mirrors the check with a clearer message
  (`cfg_from_policy` refuses a non-P2WSH override before building the
  tree). This closes the PR-B-vs-issue-#6-text deviation: the stricter
  reading won. Single gate to relax later if arbitrary destinations
  are ever wanted.
- Tests added: policy suite - 4 parse-rejections (P2WPKH/short/33-byte/
  bare-op exit_spk); glue - validate rejects P2WPKH exit_spk; hostapp -
  non-P2WSH override refused w/ message + valid P2WSH override carried
  to the manifest cfg.
- Test reality (one run): policy 9/9; glue 68/68; hostapp 113/113;
  sim e2e 17/17; app-tree e2e 11/11; smoke 14/14.

## Session 2026-10-14 (g) — DECISION A implemented: vault cfg is master-scoped

- **`'vault'` added to `nvstore.MASTER_FIELDS`**: leaving_master_seed()
  now captures the vault cfg into SettingsObject.master_sv_data on tmp-
  seed entry, and `vault._cfg()` reads via `master_get` - the policy
  gate stays ON for the whole tmp session (before: the plain get read
  the empty tmp scope and the gate silently turned OFF; benign wrt
  funds since the tmp seed cannot produce K1 sigs, but a security
  policy should not have quiet windows).
- **`save_cfg` uses `master_set`** (ccc/sssp precedent): writes the
  MASTER seed's store, always flushes immediately, mirrors into
  master_sv_data during tmp sessions. The vault is now formally a
  device-level policy: one vault per device (the Coldcard is the
  dedicated co-signer), surviving seed switches and tmp sessions.
- **`wipe` is tmp-aware**: during a tmp session it removes the MASTER
  copy (load master SettingsObject, remove, save, pop the mirror) - a
  tmp-scope-only removal would leave the policy enforced while
  claiming it was gone. The menu's is_not_tmp predicate still prevents
  reaching wipe/enroll from tmp; this makes the API correct anyway.
- **Menu predicate unchanged** (enrollment stays a master-seed
  ceremony); the CHANGE is that the gate can no longer be silently
  absent.
- Host tests (test_vault.py): fake settings gained master_get/master_set
  + class-level session state; fake nvstore module registered so
  wipe()'s `from nvstore import SettingsObject` works on host and the
  fake SettingsObject IS the fake settings class (faithful to the real
  device where glob.settings is a SettingsObject instance). New section
  11: gate visible/enforced during simulated tmp session, tmp-session
  save goes to master scope, tmp-session wipe removes the master copy,
  clean return to master.
- Device tests (vault_sim_e2e.py): section 1b flips the REAL nvstore
  class state (master_nvram_key + master_sv_data) and checks the gate
  + full could_sign path during the session. Not vacuous: master_get
  asserts 'vault' in MASTER_FIELDS, so the check fails unless the
  nvstore change is live. CAUGHT during this session: an edit
  accidentally dropped the master_nvram_key setup line, making the
  first 20/20 run vacuous - restored and re-verified.
- Test reality (one run): policy 9/9; glue 76/76; hostapp 113/113;
  sim e2e 20/20; app-tree e2e 14/14; smoke 14/14.
- Decision B (device-side vault_vout cross-check) deliberately NOT
  implemented yet per maintainer instruction.

## Session 2026-10-14 (h) — DECISION B implemented: manifest cross-check (choice b)

- **`vault.check_lattice_binding(manifest, psbts, cfg=None)`** (new,
  shared/vault.py): the device parses the host's `manifest.json` and
  verifies, before accepting a lattice batch:
  1. every input of every picked leaf spends exactly the declared
     deposit outpoint (`deposit_txid` - display-order hex, converted to
     internal byte order - plus `vault_vout`); per-leaf and per-input
     indexed error messages;
  2. the leaf count equals the manifest's `lattice_count` (subset
     enrollment is refused: the ceremony expects the full lattice);
  3. (when the enrolled cfg is passed in) the manifest's `cfg` agrees
     with the device policy on every policy-defining field
     (n/sv_hash/spk_e/k1_pubkey/f0_max/exit_spk) - catches silent
     host-vs-device policy divergence (issue #4 family).
  Raises VaultViolation on any mismatch; never writes settings.
- **Menu wiring** (vault_menu.enroll_lattice): after the PSBT picking
  loop, `manifest.json` is read from the same card directory (derived
  from the last picked filename; card idiom `bytes(reversed(x))` for
  byte reversal - MicroPython has no step=-1 slices, caught by the sim).
  Manifest present + binding mismatch => loud refusal. Manifest absent
  => explicit "Deposit binding NOT cross-checked. Proceed anyway?"
  confirm (other tooling can still enroll; the user is told exactly
  what was not verified). Corrupt/unparseable manifest => refusal.
  The root-display story now states whether the binding was verified.
- **Byte-order details**: real psbtObject prevouts come from
  `input_iter()` -> CTxIn -> COutPoint (`.hash` is the deser_uint256
  int, `.n` the vout); `int.to_bytes(32,'little')` recovers internal
  order (in-tree precedent multisig.py). Host-test fakes duck-type
  `.prevout.hash` as internal-order bytes.
- **Trust boundary (documented in code)**: the manifest is host-
  authored, so this catches only INCONSISTENT lying - a host that
  builds bad leaves and a matching manifest passes. The real
  commitments remain the device-side policy check and the
  device-computed Merkle root compared by the human against the host
  UI. See the unchosen-paths note below for the stronger design.
- Tests: glue section 12 (13 checks: positive, wrong vout/txid, count
  mismatch, missing/short txid, foreign second input, missing prevout,
  cfg divergence x2, cfg-less manifest, cfg=None skip); sim e2e section
  2b - app-tree: full-batch binding + 4 refusals against the REAL
  manifest; generator tree: leaf-0 outpoint reconstruction (real
  psbtObject byte-order path) + 4 refusals. One test-construction bug
  caught during development: single-leaf rows initially inherited
  `lattice_count: 2` and failed on count (right verdict, wrong reason)
  - fixed so each row exercises its intended check.
- Test reality (one run): policy 9/9; glue 89/89; hostapp 113/113;
  sim e2e 25/25; app-tree e2e 19/19; smoke 14/14.

### Unchosen design paths (recorded per maintainer request)

**Decision A - where the vault cfg lives (chosen: master-scoped):**
- *(a, unchosen) per-seed cfg + menu predicate only*: zero nvstore
  work, but the policy gate would be silently ABSENT during tmp-seed
  sessions (plain `get` reads the empty tmp scope) - a security policy
  with quiet windows. Benign to funds (tmp seed cannot produce K1
  sigs) but wrong-looking.
- *(c, unchosen) hybrid master-scoped registry of per-seed policies*:
  a master-level list of `{master xfp, seed xfp, cfg}` entries allowing
  several vaults per device across seed switches. Deferred: one vault
  per dedicated co-signer device is the current model; revisit if a
  device ever hosts multiple vaults (adds registry lookup at every
  gate check + selection UX at enrollment).

**Decision B - verifying the leaves against the deposit (chosen: (b)
manifest cross-check):**
- *(a, unchosen) batch-consistency-only*: check the leaves agree with
  EACH OTHER (same declared outpoint across the batch) without a
  manifest. Catches accidental mixed batches; trusts nothing about the
  host's intent. Strictly weaker than (b) - subsumed by it.
- *(strongest, unchosen) PSBT-vs-PSBT chaining*: the host also ships
  `deposit.psbt`; the device parses it (real psbtObject, i.e.
  device-judged data, NOT host-authored JSON) and derives the deposit
  txid + vault vout + S_v script itself, optionally recomputing the
  Merkle root over the deposit's output script to bind the lattice to
  a PSBT-level commitment. No host-authored string ever becomes a
  trust root; the manifest demotes to a human-comparison convenience.
  Cost: one more file on the card, slightly longer ceremony, and the
  device must still trust the user picked the right deposit.psbt -
  which the on-screen root/txid comparison already handles. RECOMMENDED
  follow-up if the manifest check ever proves insufficient.
- *(c, unchosen) status quo*: enroll_lattice policy-validates leaves
  and displays the device-computed root; the human compares roots.
  Sufficient under the recovery-key invariant (mis-enrollment cannot
  strand funds: 2-of-3 with one unencumbered key), which is exactly
  why the weaker (b) was acceptable to ship now.

### Issue tracker closure (2026-10-14)

- Issue #12 (review notes / open questions) closed with a reply comment
  (Shitnobi/coldcard-firmware#issuecomment-6175897839) explaining the
  choices: Q1 master-scoping -> implemented (Decision A, 5e82925e);
  Q4 device-side manifest cross-check -> implemented (Decision B,
  a50cfc00); Q2 P2 hard mode -> declined (structural P2 routing +
  recovery-key invariant; dict field if ever wanted); Q3 strict menu ->
  intentional omission (dedicated-signer posture; re-enroll to change);
  Q5 vault.log growth -> accepted platform pattern. All 12 review
  issues are now closed; the living record for unchosen design paths is
  this ledger (sessions g/h).

## Session 2026-10-15 (i) — audit remediation: V-01..V-07 fixed, tested, released on-branch

Full-security audit of the vault-cosign-policy work (see
`docs/vault_audit_advisory.md`, findings V-01..V-07) and the complete
remediation program (`/home/shinobi/AI-Trident/vault-remediation-plan.md`)
landed on `vault-cosign-policy-fixes`. Commits, in order:

- `1c62a2f3` Phase 0 — the security advisory (do-not-fund notice).
- `d9500cff` Phase 2 — policy hardening FIRST (V-03 sig verification,
  V-04 INV-SIGHASH, V-05 full-UTXO requirement), so the tree is never
  in a state where vault signing works without the hardening.
- `ffd549e6` Phase 1 — the real signing path: `vault_signing.recognize`
  classifies S_v/S_e before any M/N heuristic, role-based completion,
  pubkey-match key selection, consensus-verified witness construction
  (`testing/witness_order_check.py`: minimal Bitcoin script interpreter
  with real ECDSA, 6/6 — S_v selector LAST, S_e K1 sig TOPMOST).
- `471d7a07` Phase 1 §1.5/§1.6 — the approval record (gate-to-signer
  binding: class, kinds, selector, outpoints, out_spks, fee, sighashes)
  checked fail-closed in `sign_it`; the CCC tmp-seed key path.
- `0a58683a` Phase 3 — V-06 strict `is_vault_psbt` predicate for the
  ccc velocity-ratchet skip; relevance surfacing/logging; five
  assert→`FatalPSBTIssue` conversions; `enrolled_ts` stamping and the
  'Show Policy' viewer.
- `f4feb763` — prevout-vout fix (found by the Core oracle): all vault
  UTXO reads use `txin.prevout.n`, never the input position.
- `d32b5869` Phase 4 — `unix/work/audit_probe.py` rewritten as the
  assertion-based V-01..V-07 regression suite (49/49) incl. a 200-case
  mutation fuzz (never signs without gate approval); the Core oracle
  (`unix/vault_core_oracle.py` + `unix/vault_core_sign.py`).

### New invariants (device-side; the on-chain script enforces only
### CSV/branch structure — the threat model assumes the HOST and the
### PSBT are adversarial)

- **INV-SIGHASH**: every signature in a vault witness (the device's and
  every partial it inherits) is strict-DER, low-S, SIGHASH_ALL, and
  verifies against the BIP-143 digest of the approved transaction.
  Vault signatures can never be grafted onto another transaction.
- **INV-UTXO**: fee-bearing policy classes (P1/P3) are judged only
  against txid-cross-checked full UTXOs; a witness script that does not
  hash to the claimed spk refuses at classification.
- **INV-BINDING**: `sign_it` refuses vault inputs unless the policy
  gate left an approval record on this exact object and every recorded
  fact (outpoints, outputs, fee, sighashes, selector) still matches.
- **INV-RATCHET**: the CCC velocity-ratchet skip requires the strict
  `is_vault_psbt` predicate (every input verifiable + structural vault
  match); any doubt => the ratchet applies.

### Ledger

`vault.log` entries now record the implementation version
(`vault_impl_version`, currently 2) that produced them, plus the
enrollment timestamp and policy hashes at save time. The cfg schema is
otherwise unchanged — no migration for enrolled policies.

## Session 2026-10-15 (j) — validity audit #2: W-01..W-05 fixed on master

Second audit round, focused on **validity** rather than security: bugs
that produce consensus-invalid or non-standard transactions after the
device co-signs, and coverage gaps in the policy gate. Report:
`/home/shinobi/AI-Trident/vault-validity-audit.md`; resolution section in
`docs/vault_audit_advisory.md`. Landed on `master` (previous round was
merged and pushed as `28ea046d`).

Findings fixed (`vault_impl_version` 2 → 3):

- **W-01** ladders (P2) require `tx_version >= 2` — BIP-68/112 `OP_CSV`
  cannot execute on v1 transactions, so a signed v1 ladder was
  consensus-invalid. Fail-closed on unknown version; `view_from_psbt`
  now carries `tx_version`.
- **W-02** ladders require **full UTXOs** (`_require_full_utxo`), same
  as P1/P3 — a spoofed witness-utxo amount was bound into the BIP-143
  digest and the device signature.
- **W-03** `_require_relayable_fee` floor (conservative 1 sat/vByte
  estimate) on all three fee-bearing classes; ladder fee ceiling
  deliberately omitted (post-cadence quorum owns everything) — pinned
  by regression case B3.
- **W-04** `DUST_LIMIT = 546` on every output of every policy class
  (OP_RETURN exempt) — previously 500-sat dust and fee=1 emergencies
  were approved.
- **W-05** enrollment refuses `sv_hash == spk_e` (self-inflicted
  emergency DoS: P1 would re-route to the exit checker and refuse
  forever).

Design pins (regression-pinned, not bugs): **W-06** ladder allows
foreign inputs/arbitrary destinations — after the CSV cadence the 2-of-3
quorum can spend unconditionally anyway (B10).

Regression suite: `unix/work/audit2_probe.py` rewritten as an
assertion-based suite (22/22) running through the REAL simulator signing
chain — same phase pattern as the V-round. Host suites updated
(`txn_version=2` on fakes, `txv`/`utxo_full` knobs on the policy view
fixture, `test_validity_audit2` added).

Full battery on this tree: policy 10/10, vault 89/89, hardening 43/43,
witness_order 6/6, sign_sim 45/45, sim_e2e 25/25, audit_probe (V-round)
49/49, audit2_probe (W-round) 22/22.

## Session 2026-10-15 (k) — consistency audit #3: X-01..X-03 fixed on master

Third audit round, on **script-vs-config consistency and degenerate-script
enrollment** — the boundary the first two rounds did not cover: the device
enrolls only the spk *hash*, so every assumption the policy makes about
script CONTENTS must be re-verified against the parsed script at spend
time. Report: `/home/shinobi/AI-Trident/vault-consistency-audit.md`;
resolution section in `docs/vault_audit_advisory.md`. Landed on `master`
(head was `e1d4218c`).

Findings fixed (`vault_impl_version` 3 → 4):

- **X-01** (class 3) `parse_vault_script` / `parse_deepvault_script`
  refuse **duplicate pubkeys** (all three pairwise distinct, both
  scripts). `OP_CHECKMULTISIG` has no distinctness rule: an S_v with
  K1==K2 is single-party-satisfiable and the ELSE branch carries no CSV
  — silent total quorum collapse the device previously waved through
  (the probe's C4 finalized a single-party vault witness). Spend-time
  recognition is the only device-side defense (only the spk hash is
  enrolled), so the parsers are where it fails closed.
- **X-02** (class 3) `vault_signing.recognize` cross-checks the parsed
  S_v script's **N against the enrolled cfg `n`** (default 1008,
  aligned with `VaultPolicy`). The ladder sequence check judges
  nSequence against cfg n while BIP-112 `OP_CSV` on-chain judges it
  against the script N — a divergence (mis-enrolled JSON or a post-
  funding `set_n` edit) previously made the device SIGN
  consensus-invalid ladders (cfg n < N; probe C2/C3) while refusing
  on-chain-valid ones (cfg n > N; C2b). Now a mismatch raises at
  recognition → `FatalPSBTIssue` on the real path, `is_vault_psbt`
  → False (ratchet applies). Covers every route to the divergence.
- **X-03** (class 4) `set_n` refuses cadence edits while vault mode is
  **enabled** (same enrolls-dark posture as policy enrollment). For the
  related enrollment-integrity gap (imported JSON silently enabling
  `strict`), the fix **deviates from the audit's literal text** and for
  good reason: stripping `strict` at enrollment would have made strict
  mode permanently unreachable, contradicting the recorded issue-#12/Q3
  design decision ("no strict menu — re-enroll to change"). The audit's
  real concern was a *silent* posture change; that is closed by
  **surfacing** the strict status in the enrollment confirmation story
  and in the 'Show Policy' viewer instead. (Defense in depth: even a
  bypassed menu edit cannot produce a bad signature — X-02's
  recognition check refuses the resulting ladder.)

Regression suite: `unix/work/audit3_probe.py` converted from findings
probe to assertion-based suite (23/23; findings-verified 17/17, controls
6/6) through the REAL simulator signing chain, same phase pattern as
the V/W rounds — C2/C2b/C3 (N mismatch both directions + menu-edit
route), C4 (single-party witness must not finalize), C5/C6 (pure-policy
role completion must raise), C8/C9 (all duplicate-pubkey permutations,
both scripts), C10 (guard: honest cfg, seq == N+1 still refused). Host
coverage: `test_consistency_audit3` added to `testing/test_vault_policy.py`
(parser permutations + recognize() cross-check controls).

Full battery on this tree: policy 11/11, vault 89/89, hardening 43/43,
hostapp 113/113, witness_order 6/6, sign_sim 45/45, sim_e2e 25/25,
audit_probe (V-round) 49/49, audit2_probe (W-round) 22/22, audit3_probe
(X-round) 23/23.

Observed and left as-is (audit observations O-01..O-05, documented in
the report): `set_fee` while enabled (no consensus meaning), O-02
re-enrollment fund-lock (fail-closed, break-glass recoverable),
`input_iter` CTxIn reuse (audited safe at every call site), lattice
leaf commitment-only enrollment, OP_RETURN dust exemption (matches
Core).

## (l) Core-oracle framework fixes + G-1: CSV ladder accepted by Bitcoin Core

Session 2026-10-15 (cont). A full e2e deposit simulation (session (k)
follow-up) exposed three bugs in the regtest half of the on-chain
validity oracle — all dead code until now, because regtest mode had
never actually run (no bitcoind in the dev environment, so it silently
skipped):

- **H-1** `vault_core_oracle.cli()` passed Python `bool`/`None` args
  straight to `subprocess` → `TypeError` the moment regtest mode runs.
- **H-2** even with stringified args, the 9-arg positional
  `sendtoaddress` form is rejected by Core 28 (`Invalid estimate_mode`
  on the null optionals); every omitted arg was a default anyway.
- **H-3** `testmempoolaccept` used legacy shell-style single-quoted
  JSON (`"['hex']"`), a parse error on modern bitcoin-cli.

Fixes: JSON-literal arg conversion in `cli()` (bool → `true`/`false`,
`None` → `null`), minimal `sendtoaddress` form, double-quoted JSON
array for `testmempoolaccept`. Red-first evidence: all three failures
were reproduced on the unpatched tree (tracebacks + `-8`/parse errors)
before patching; firmware untouched.

**G-1 closed** — the Core oracle now covers the P2 CSV ladder, not
just P1 emergency:

- `unix/vault_core_sign.py`: request field `spend` selects the class
  ('emergency' default; 'ladder' builds nSequence == N height-form,
  nVersion 2 per BIP-68/112, output to request `dest_spk`).
- `unix/vault_core_oracle.py`: `verify_signed()` parametrized by spend
  class (expected nSequence, S_v branch selector, destination);
  selfcheck gains a synthetic ladder round (host-verified consensus
  shape, no chain needed); regtest deposits a **second real coin** to
  the enrolled S_v address, has the device co-sign the ladder
  withdrawal through the full real firmware signing chain, and lets
  Bitcoin Core enforce the cadence.
- Verified against Bitcoin Core 28.0 (official binary): emergency
  spend accepted + mined; ladder spend **refused pre-maturity with
  `non-BIP68-final`**, **accepted after N=1008 confirmations**,
  broadcast, mined, mempool drained. The gate message was
  `ladder: withdrawal (100000 sats spent)` — policy class and
  consensus verdict agree.

Battery on this tree (spot after the framework patch — no `shared/`
or firmware files touched): sim_e2e 25/25, sign_sim 45/45, audit3
23/23, plus the oracle selfcheck (emergency + ladder rounds, 22
checks) all green.

## (m) Host app GUI + comprehensive test battery: leaf PSBT enroll bug found and fixed

Session 2026-10-15 (cont). The host app (now standalone at
Shitnobi/coldcard-vault-hostapp) got a tkinter GUI (funding PSBT
paste/decode, policy fields, preview, build, lattice-root copy) and a
three-tier test battery. Real tkinter 8.6.14 was installed locally
(no sudo) from extracted debs to test on a real X display.

The deepest tier — a GUI-built tree fed through the **real coldcard-mpy
simulator** (`VAULT_E2E_DIR=<tree> unix/vault_sim_e2e.py`) — caught a
real enroll-blocking bug in the host app's leaf PSBTs:

- **Bug**: leaf input maps carried only `0x01` witness utxo. Device
  `_verify_vault_partials` (vault.py, enroll_lattice) requires
  `0x05` witness script S_v and `0x00` full UTXO on vault inputs, so
  enrollment raised `lattice[0]: witness-utxo input missing witness
  script`. Host-app leaves could never have been enrolled on a real
  Coldcard before this fix.
- **Fix**: leaf input map now carries `0x01` witness utxo + `0x05`
  witness script S_v + `0x00` full UTXO (dep_tx). Applied to BOTH
  `hostapp/vault_tree.py` here and the standalone repo copy. The
  lattice root is unaffected (it commits to unsigned tx bytes only):
  `1c8b7fc230cdcdccd4bf3fc7e38cdf92f22973e1f5ff68a092aa5d581407db86`.

Battery after the fix (both repos' trees): hostapp 113/113, GUI
logic 29/29, GUI smoke 15/15, GUI real-tkinter 17/17 (real clicks,
clipboard, mainloop), sim e2e 19/19 on a hostapp-built tree, firmware
policy 11/11, firmware sim e2e 25/25; `vault_policy.py` verified
byte-identical across repos.

## (n) Host app audit round 2: HA-1..HA-13 fixed in both repos

Session 2026-10-15 (cont). A second audit of the host app (post-GUI,
post-leaf-fix), every finding red-first reproduced, every fix
regression-tested:

- **HA-1/HA-2 (GUI silent failures)**: duplicate-pubkey policies
  raised a bare `VaultViolation` and truncated PSBTs a bare
  `struct.error` - neither in the GUI error handlers, so Build died
  silently in the Tk callback. `run_build` now wraps every failure as
  `HostappError`.
- **HA-3 (BIP-174)**: duplicate keys within a PSBT map were accepted;
  a duplicated `0x01` witness-utxo key double-counted `total_in`
  (built vault value inflated 2x). `parse_psbt` refuses duplicates.
- **HA-4 (fund availability)**: dust leaf ladders (< 546 sats output,
  the device W-04 floor) enrolled fine but could never be co-signed.
  `build_tree` refuses dust vault values / dust ladders up front.
- **HA-5**: stale `emg*.psbt` files from a previous larger build
  survived a rebuild in the same outdir (valid spends, absent from
  manifest + lattice root). Rebuilds now clean prior artifacts + warn.
- **HA-6**: failed GUI rebuilds kept the old lattice root on screen;
  results cleared + Copy Lattice Root disabled on failure.
- **HA-7/HA-8**: deposit-fee min-relay warning; deposit txid committed
  over the CLEAN serialization (stray witness markers can no longer
  corrupt the outpoint the leaves spend).
- **HA-9/HA-10/HA-11/HA-13**: CLI policy validation without
  tracebacks; JSON-null fields; file-vs-paste funding conflicts;
  missing-witness-utxo preview hint; clipboard persistence;
  exception-based validation surviving `python -O`.

The standalone repo (Shitnobi/coldcard-vault-hostapp @ 1f687d5) is the
canonical copy; `hostapp/vault_tree.py` here was re-synced to it
(only header/sys.path wiring differs, for the firmware tree layout)
and `testing/test_vault_hostapp.py` re-synced the same way (135
checks, up from 113). Battery on this tree: hostapp 135/135, policy
11/11, glue 89/89, hardening 43/43, sim e2e 25/25; device sim e2e
19/19 against a tree built by the FIXED standalone host app (lattice
root unchanged: 1c8b7fc2...).

## (o) Full-stack deposit e2e on regtest: both host apps x the device

Session 2026-10-15 (cont). "Run both the firmware and the hostapp
through an end-to-end test against regtest to ensure that a deposit
functions correctly." New `unix/vault_hostapp_regtest.py` (host
driver) + `unix/vault_hostapp_cosign.py` (sim-side co-signer),
52/52 checks on the first full run, covering BOTH host apps (the
standalone repo copy AND the firmware-repo mirror) in one pass:

- real regtest coin -> funding PSBT (input-only shape) -> hostapp
  CLI builds the tree;
- the regtest wallet signs the hostapp's `deposit.psbt` via
  `walletprocesspsbt`/`finalizepsbt` (the PSBT a REAL wallet
  consumes - not host-side re-signing);
- broadcast + mined: on-chain txid == the manifest's PREDICTED
  `deposit_txid`; `gettxout` confirms the vault coin pays S_v with
  the predicted value;
- the device enrolls cfg + lattice from the manifest and passes all
  gate checks (`vault_sim_e2e.py`, 19/19 per tree);
- the device co-signs the HOSTAPP-BUILT `emg0` leaf (the leaf file
  itself, augmented host-side with the user's K1 partial signature
  and BIP-32 key origins, signed host-side with python-ecdsa,
  low-S), through the full real firmware chain (read_psbt ->
  validate -> consider_* -> VaultMode.could_sign -> sign_it ->
  finalize), after enrolling from the manifest;
- host-side BIP-143 verification of the co-signed spend, then
  testmempoolaccept + sendrawtransaction + mined: vault coin SPENT
  on-chain, emergency output confirmed paying spk_e.

Supporting change: `vault_core_sign.py` dump ctx now also publishes
the device xfp (additive; needed for the K2 key origin the
K1-augmented leaf carries). Oracle re-run after the change:
selfcheck + regtest (emergency + ladder, incl. BIP-68 pre-maturity
refusal) all PASS.

The two host app copies produced byte-equivalent trees for equal
policies (device derived the same K2, both enrollments hit the same
lattice-root machinery), confirming the sync invariant on-chain.
No bitcoind/sim processes left behind; temp datadir cleaned.

## (p) Coverage-gap round: 4 new on-chain flows + repo sync invariant

Session 2026-10-15 (cont). A coverage-gap review of the test framework
found six gaps; all closed:

1. **already-correct funding mode was never tested on-chain** (the
   only mode where the hostapp commits to a PRE-EXISTING txid - the
   HA-8 clean-serialization risk). New flow B: the wallet funds the
   vault directly (0-value OP_RETURN at vout 0 so the vault output
   sits at vout 1 - nonzero vault_vout, previously unreachable with
   standard outputs), the hostapp gets the funding PSBT with a STRAY
   WITNESS MARKER injected into the global tx (non-compliant producer
   shape) and must classify 'already-correct' with manifest txid ==
   the REAL on-chain funding txid. Both app copies; emergency
   co-sign + broadcast on the firmware copy.
2. **CSV ladder recovery never proven against a hostapp deposit** (the
   oracle's ladder coverage funds S_v directly, bypassing the host
   app). New flow C: a host-constructed P2 ladder spend of a hostapp
   deposit is device-co-signed, REFUSED by testmempoolaccept
   pre-maturity ('non-BIP68-final'), accepted after mining N=1008
   blocks, broadcast and mined.
3. **multi-input funding** never exercised (every prior test used a
   single input). Flow C funds from two wallet coins: input map
   multiplicity, total_in summing, wallet signing 2 inputs, on-chain
   txid == prediction.
4. **signer-set variation**: only the {K1, K2} 2-of-3 set had ever
   been co-signed. Flow B's emergency spend uses K3 as the user key
   ({K2, K3} set), proving the finalize witness ordering with a
   non-K1 partial signature.
5. **GUI logic layer never run against real funding**: new flow D
   runs gui.policy_from_fields + gui.run_build (the exact calls the
   Build button makes) on flow B's real funding bytes - deposit.psbt,
   every emg leaf and manifest.json byte-identical to the CLI build.
6. **repo sync invariant was manual**: new testing/test_repo_sync.py
   (7/7): vault_policy.py byte-identical across repos; vault_tree.py
   and test_vault_hostapp.py identical as code (wiring comments and
   sys.path lines excepted, with live wiring checks so a passing
   normalize cannot hide a broken copy); GUI standalone-only.

vault_hostapp_regtest.py restructured into four flows (A input-only /
B already-correct / C multi-input+ladder / D GUI parity), 90/90
checks. One driver bug found and fixed during the run (BIP-174
output-map count: a 2-output funding PSBT needs two empty output
maps; Core's walletprocesspsbt caught it - TX decode failed).

## (q) P3 exit ceremony: the last spend class proven on-chain

Coverage audit round 3 (follow-on to (p)): enumerate every gate
spend class and check each has an ON-CHAIN co-sign+broadcast+mine
proof against a real hostapp deposit. P1 emergency (flow A/B) and
P2 ladder (flow C) were proven; **P3 exit was not**: vault_e2e_gen's
exit.psbt covers the gate level only (could_sign approval with a
real K1 partial signature), and no exit ceremony had ever been
co-signed by the device and accepted by consensus.

New flow E in vault_hostapp_regtest.py (firmware copy):

1. The policy carries an EXPLICIT exit_spk (P2WSH 1-of-1 K1,
   distinct from the hostapp's default 3-key sink-shape) - verified
   to flow through policy.json -> manifest cfg -> device enrollment.
2. A normal deposit -> emergency-spend cycle leaves a REAL confirmed
   spk_e coin (99000 sats) on-chain.
3. A HOST-CONSTRUCTED exit ceremony spends that coin: 1-in/1-out
   paying exit_spk, nSequence 0xFFFFFFFD, full UTXO + witness utxo +
   S_e witness script + K1 partial signature over the S_e BIP-143
   digest in the input map (same construction pattern as flow C's
   ladder, but over S_e).
4. The device co-signs it through the FULL firmware chain
   (vault_hostapp_cosign.py: enroll -> validate -> consider_* ->
   VaultMode.could_sign -> sign_it -> finalize): the first live
   exercise of the 'se' input path (psbt.py _classify_vault_input
   kind 'se', vault_signing.build_witness -> [dummy, sig_K2,
   sig_K1, S_e]) and of _verify_vault_partials on a real S_e input
   outside the generator trees.
5. Host-side verification (BIP-143 both signatures, S_e witness
   order, sha256(S_e) == spk_e[2:]), testmempoolaccept, broadcast,
   mine: the spk_e coin is SPENT on-chain and the exit output pays
   the explicit exit_spk (98500 sats).
6. Two gate negatives through the real device chain: an exit paying
   a WRONG destination is refused ('P3: must re-enroll to fresh
   spk_v'') and an exit WITHOUT the K1 co-signature is refused
   ('P3: K1 co-signature required').

vault_hostapp_regtest.py is now five flows, 112/112 checks (was
90/90; +22 for flow E). Repo sync 7/7, hostapp battery 135/135,
policy battery PASS, sim e2e 19/19 per tree. No bitcoind left
running.

Remaining deliberately-uncovered item (unchanged from (p)): the
'incorrect-output' funding mode on-chain (classification is
unit-tested; on-chain behavior is identical to input-only's rebuild
path).

## (r) firmware builds for on-device testing; freeze-manifest bug found

Built the real STM32 firmware (MK-Makefile, DEBUG_BUILD=0, Mk4+Mk5)
locally with the host arm-none-eabi toolchain, signed with the
PUBLIC dev key 0 (the standard experimental-firmware route: the
bootrom shows a warning + delay, then boots): stm32/dev.dfu
(v5.6.3, hw_compat Mk4+Mk5, ~299 KB flash headroom).

**Bug found by the build**: the four vault modules (vault.py,
vault_policy.py, vault_signing.py, vault_menu.py) were copied into
shared/ but never added to shared/manifest.py's freeze_as_mpy list
- the board 'shared/' dirs are symlinks to the root shared/, so
both MK4 and Q1 manifests come from that one file. The firmware
compiled and linked fine, but 'import vault' in auth.py would have
raised ImportError ON-DEVICE ONLY (the sim loads from MICROPYPATH,
so every sim test passed while the frozen image was broken).
Fixed by adding all four to the opt=0 freeze list (asserts must
survive); verified present in frozen_content.c after rebuild.

Also: build-compat flags (-Wno-error=dangling-pointer,
enum-int-mismatch, stringop-overflow, return-type) added to both
boards' mpconfigboard.mk - this older micropython does not compile
clean under GCC >= 12 without them.

Toolchain notes for future builds: cli/ must be pip-installed (for
signit); 'make setup' needs autotools for libngu's secp256k1
autogen, but the precomputed_ecmult tables are committed in the
submodule, so the autogen step can be skipped entirely (just build
mpy-cross with -Wno-error=enum-int-mismatch and create the
l-port/l-mpy/board symlinks).
