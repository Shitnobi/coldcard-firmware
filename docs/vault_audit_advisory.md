# SECURITY ADVISORY — vault-cosign-policy branch (audit 2026-10-15)

**Status:** RESOLVED — all findings V-01..V-07 fixed and regression-tested on
branch `vault-cosign-policy-fixes` (head `d32b5869` at time of writing; see
"Resolution" below). **Not yet merged/released upstream.**

**Affected:** any firmware built from `vault-cosign-policy` @ `89f13b20`
(merge-base with upstream `Coldcard/firmware` master `f28e1b26`).

## Do NOT fund a vault with firmware from this branch

The device key cannot co-sign **any** vault spend:

- **V-01 (critical):** inputs spending the branched vault script `S_v` are
  misparsed by the stock multisig parser (`disassemble_multisig_mn`:
  `M = script[0]-0x50` → `M=19`), so `consider_inputs` raises
  `FatalPSBTIssue: Unknown multisig wallet` — *before* the vault policy gate
  in `auth.py` ever runs. Emergency (P1) and CSV-ladder spends are both
  affected.
- **V-02 (critical):** inputs spending the deepvault script `S_e` parse as
  `M = -47`, so `len(part_sigs) >= M` is always true and the input is marked
  "fully signed" regardless of how many valid signatures exist. The device
  never adds its signature; exit ceremonies (P3) fail with
  "Transaction looks completely signed already?".

The vault policy gate at `auth.py:447` is therefore **dead code on the real
signing path** — it is only reachable via the direct calls the simulator
e2e tests make.

## Recovery for already-funded vaults

The on-chain scripts are fine; the defect is entirely device-side. Two
options:

1. **Wait for the fix** (recommended if you can): the remediation is
   device-side only — `S_v`/`S_e` are unchanged, so a fixed firmware can
   co-sign existing vault coins under policy.
2. **Break-glass now:** spend `S_v` via its `OP_ELSE` branch (plain 2-of-3,
   no CSV) with K1+K2 directly in any standard wallet, or spend `S_e` with
   K1 plus the non-device key of {K2, K3}. This bypasses **all** device-side
   policy (including the CSV discipline) — it is an emergency path only.

## Full findings

See `/home/shinobi/AI-Trident/vault-cosign-policy-audit.md` (V-01 … V-07)
and `/home/shinobi/AI-Trident/vault-remediation-plan.md`. Summary:

| ID | Class | Severity | One-liner |
|----|-------|----------|-----------|
| V-01 | 1 | Critical | S_v misparse → device cannot co-sign emergency/ladder spends |
| V-02 | 1 | Critical | S_e misparse (M=-47) → device cannot co-sign exit ceremonies |
| V-03 | 3 | High | P3 checks only K1 sig *presence* — garbage sigs pass policy |
| V-04 | 2 | High (latent) | policy blind to sighash flags; ALL\|ANYONECANPAY never blocked for co-signer-key inputs |
| V-05 | 3 | Medium | witness_utxo never cross-validated — policy evaluates attacker-asserted data |
| V-06 | — | Low | CCC velocity-ratchet skip uses fail-open relevance predicate |
| V-07 | — | Low (process) | e2e tests bypass the real signing path |

Currently V-01/V-02 fail **closed** (refusals), so the realized harm is
class-1 unspendability via the device's key — not fund theft. Fixing the
parser alone would *activate* V-03/V-04, so the parser fix and the policy
hardening (sighash enforcement, K1 signature verification, UTXO provenance)
must ship together — which is how the `vault-cosign-policy-fixes` branch is
structured.

## Resolution (2026-10-15, branch `vault-cosign-policy-fixes`)

All seven findings are fixed; every fix is pinned by an assertion-based
regression suite driven through the REAL firmware signing chain inside the
simulator (`unix/work/audit_probe.py`, 49/49), plus host-side and
Core-regtest oracles.

| ID | Fixed by | What changed |
|----|----------|--------------|
| V-01 | `ffd549e6` | `S_v`/`S_e` recognized structurally (`shared/vault_signing.py`) before any M/N heuristic; device key selected by **pubkey match**; role-based completion (any 2-of-3 for S_v); witness built to the empirically verified consensus order (`testing/witness_order_check.py`) |
| V-02 | `ffd549e6` | same recognition path: S_e needs K1 **and** one of {K2, K3} — never a raw sig count |
| V-03 | `d9500cff` | every partial signature on a vault input is verified (strict DER, low-S) against the BIP-143 digest of the transaction being approved |
| V-04 | `d9500cff` | vault signatures must be SIGHASH_ALL (new invariant INV-SIGHASH); grafted sighash bytes refuse |
| V-05 | `d9500cff`, `ffd549e6` | fee-bearing classes require the full (non-witness) UTXO; the witness script must hash to the claimed spk at classification time |
| V-06 | `0a58683a` | CCC velocity-ratchet skip now uses the strict `is_vault_psbt` predicate (fail-closed), not the refusal-gate relevance sniff |
| V-07 | `d32b5869` (and `ffd549e6`) | the simulator suites sign through the real chain (`read_psbt → validate → consider_* → gate → sign_it → finalize`); the audit probe is now an assertion-based regression suite; a Bitcoin Core regtest oracle (plus a dependency-free host selfcheck) verifies consensus validity of everything the device signs |

Additional hardening landed during remediation (not in the original audit):

- **Approval-record binding** (`471d7a07`): the policy gate leaves an
  in-memory record of exactly what it approved (class, per-input kinds,
  selector, outpoints, output spks, fee, sighashes); `sign_it()` refuses
  vault inputs unless the record is present and still matches — closing
  the gate-to-signer semantic gap (TOCTOU on the decision, not just the
  bytes).
- **CCC tmp-seed path** (`471d7a07`): the device co-signs with whichever
  secret owns the matched pubkey, so real CCC sessions work.
- **Prevout-vout reads** (`f4feb763`): all vault-side UTXO reads use
  `txin.prevout.n`, never the input position — found by the Core oracle
  (a vault coin funded at vout ≠ input index was previously misread as a
  sibling output: relevance missed it, the gate was skipped, and sign_it
  refused with no approval record).
- **assert → raise conversions** (`0a58683a`): five `assert`s on the
  signing path are now `FatalPSBTIssue` raises, so they fail closed even
  in builds with asserts compiled out.
- **Enrollment auditing** (`0a58683a`): `save_cfg` stamps
  `enrolled_ts`, logs the policy hashes, and the on-device 'Show Policy'
  viewer displays sv_hash / spk_e / exit_spk with the enrollment time.
- **`vault_impl_version`** (this release): the cfg records which signing
  implementation produced each ledger entry (current: 2).

### Guidance for in-flight users

Anyone who funded a vault on `vault-cosign-policy` @ `89f13b20`: **wait for
the fixed firmware** rather than break-glass. The on-chain scripts
(`S_v`/`S_e`) are unchanged — the fix is entirely device-side — so the
fixed firmware can co-sign existing vault coins under policy, including
their CSV discipline. The break-glass paths in "Recovery" above remain
available but bypass all device-side policy.

### Test evidence (release build)

Full battery on the remediation branch:

```
testing/test_vault.py            89/89
testing/test_vault_hardening.py  43/43
testing/witness_order_check.py    6/6   (minimal interpreter, real ECDSA)
unix/vault_sign_sim.py           45/45  (real signing path in simulator)
unix/vault_sim_e2e.py            25/25  (enroll/lattice/gate e2e)
unix/work/audit_probe.py         49/49  (V-01..V-07 regression suite)
unix/vault_core_oracle.py        PASS   (host selfcheck; regtest when
                                          bitcoind available)
```

The audit probe doubles as the post-release evidence: re-run
`unix/work/audit_probe.py` against any release build and attach the
output to the release notes.

---

# VALIDITY AUDIT #2 — consensus-invalid / non-standard signatures (2026-10-15, `master` @ `28ea046d`)

**Status:** RESOLVED — findings W-01..W-05 fixed and regression-tested
(`vault_impl_version` 3). Full report:
`/home/shinobi/AI-Trident/vault-validity-audit.md`.

Scope of this round: bugs that let the device sign **consensus-invalid**
transactions (rejected by the network after co-signing) or
**non-standard** ones (never relayed), and coverage gaps in the policy
gate. The audit was a static review of the full signing chain
(`read_psbt → validate → consider_* → vault gate → sign_it → finalize`)
plus an empirical probe (`unix/work/audit2_probe.py`).

## Findings

| ID | Class | Finding | Fix |
|----|-------|---------|-----|
| W-01 | 3 | CSV ladder spends approved on nVersion=1 transactions — `OP_CSV` (BIP-68/112) fails unconditionally on v1, so the fully-signed tx is consensus-invalid | `_check_ladder` requires `tx_version >= 2`, fail-closed on unknown (`None`); `view_from_psbt` now carries `tx_version` from `psbt.txn_version` |
| W-02 | 3 | Ladder judged fee-bearing classes against **witness-utxo amounts** — the BIP-143 digest embeds `nValue`, so a spoofed WU amount binds the device signature to the attacker's claimed value | P2 ladders now require full (txid-cross-checked) UTXOs via `_require_full_utxo` (same as P1/P3) |
| W-03 | 3/design | Ladder fee unbounded in both directions: fee=0 signed (non-standard, never relays) and no ceiling | P2 fee **floor** via `_require_relayable_fee` (1 sat/vByte conservative vsize estimate); ceiling deliberately omitted (post-cadence the 2-of-3 quorum can withdraw everything anyway — pinned by regression B3) |
| W-04 | 3 | No dust threshold or min-relay floor in P1/P3: a 500-sat dust output and a fee=1 emergency were approved (consensus-valid but non-standard → stuck) | `DUST_LIMIT = 546` on every policy class for all outputs (OP_RETURN exempt); `_require_relayable_fee` in P1 (emergency), P3 (exit), P2 (ladder) |
| W-05 | 4 | Enrollment accepted `sv_hash == spk_e` — emergency mode then re-routes to the exit checker, which permanently refuses ("must re-enroll to fresh spk_v"), a self-inflicted DoS | `VaultPolicy.__init__` refuses `sv_hash == spk_e`; flows into `validate_cfg` for free |
| W-06 | design | Ladder allows foreign inputs / arbitrary destinations | **By design**: after the CSV cadence the 2-of-3 quorum can spend unconditionally anyway; pinned by regression B10 |

Minor observations (O-01..O-05, no code change): see the full report.

## Verified solid (negative results)

Duplicate outpoints (stock `consider_inputs` check), `prevout.n` indexing,
witness ordering (S_v selector topmost under script for the CSV branch),
INV-SIGHASH, approval-record binding, P1/P3 full-UTXO, ratchet predicate.

## Test evidence

```
unix/work/audit2_probe.py         22/22  (W-01..W-06 regression; B3/B10 pin
                                          the design decisions)
testing/test_vault_policy.py      10/10  (incl. test_validity_audit2)
testing/test_vault.py             89/89
testing/test_vault_hardening.py   43/43
testing/witness_order_check.py    6/6
unix/vault_sign_sim.py            45/45
unix/vault_sim_e2e.py             25/25
unix/work/audit_probe.py          49/49  (V-01..V-07 regression, re-run)
```

The on-chain scripts are unchanged; the fixes are entirely device-side,
so enrolled vaults need no migration. The cfg schema is unchanged except
`vault_impl_version` in ledger entries (2 → 3).
