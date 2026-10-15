# SECURITY ADVISORY — vault-cosign-policy branch (audit 2026-10-15)

**Status:** OPEN — fixed on branch `vault-cosign-policy-fixes` (see remediation
commits); **not yet merged/released.**

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
