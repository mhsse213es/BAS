# Carbanak BFSI Pack Expansion Implementation Plan

> **For agentic workers:** Do not start until this plan is approved. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the Carbanak BFSI pack: 16 remaining scenarios, validated ATT&CK mappings for them, and the registration and acceptance checks the spec requires.

**Architecture:** The simulated banking ledger (`orchestrator/cmd/carbanak-ledger-sim`, `orchestrator/internal/carbanakledger`) exists and its tests pass. The fraud-control model (`orchestrator/internal/scenario/fraud_control.go`) exists. The original chain's corrections and the Stage 8 sequence (8a–8g) are in `scenarios/carbanak-kill-chain.yaml`. Remaining work is scenarios, mappings, and registration.

**Tech Stack:** Go (orchestrator), YAML scenarios, signed with `orchestrator/scripts/signer.go`.

**Spec:** `docs/superpowers/specs/2026-11-17-carbanak-bfsi-expansion-design.md`. Its header ("Implementation NOT started") is out of date; Task 0 corrects it.

## Global Constraints

- Ledger binds to `127.0.0.1:8745` by default; non-loopback needs the explicit override and a `.test`, `.invalid` or `.lab` host label.
- No real banking, SWIFT, card or ATM endpoints. All identities are synthetic.
- Credential tier: LSASS uses `PROCESS_QUERY_LIMITED_INFORMATION` (0x1000) only; Credential Manager and browser stores are probed for existence only, never read.
- Lateral-movement scenarios (19–22) SKIP with a reason when `BAS_CARBANAK_TARGET_HOST` is unset.
- Every edit to a scenario file requires re-signing its `.sig`; `signer.go verify-all` must report zero failures.
- Proposed ATT&CK mappings are kept with `mapping: proposed` and excluded from coverage reporting.
- Items 23 and 28 use `attack_gap: no_clean_attack_technique` and an empty technique ID.

## Review Focus

1. Ledger request with malformed JSON → 400 with no state change, not a panic.
2. `BAS_CARBANAK_TARGET_HOST` set to a production-looking name → refused.
3. Port 8745 already in use → fraud steps ERROR with the reason, never PASS.
4. Audit log tampered between runs → 8f reports tampered.
5. Empty `run_id` on `GET /audit` → rejected, not an all-runs dump.

Each line gets its test in the owning task below.

## Current state (verified 2026-11-21)

| Item | State |
|---|---|
| Ledger service and tests | Present; `go test ./internal/carbanakledger/` passes |
| Attack-gap schema (`AttackGap`, `no_clean_attack_technique`) | Present in `engine.go:376` |
| Stage 3 → T1686.003 | Done |
| Stage 4 → 0x1000 | Done |
| Stage 8 → 8a–8g | Done (7 sub-steps) |
| Scenarios 9, 23, 24, 25, 26, 27, 28 | Present and signed |
| Scenarios 10–15, 17–22, 29–32 | **Not built (16)** |
| Kill-chain description | Still says Stage 8 "writes a decoy" (line ~51); stale |
| Scenario-count test | Now a floor of 180 (`product_line_test.go:18`); the spec's "bump by one" no longer applies |
| Mapping markers on 24–27 | Absent; spec says "validated with caveat", so the rule needs a ruling (Task 0) |

## Task 0: Reconcile the spec with the repository

**Files:** Modify `docs/superpowers/specs/2026-11-17-carbanak-bfsi-expansion-design.md`; Modify `scenarios/carbanak-kill-chain.yaml` description only.

- [ ] Step 1: Update the spec status line to list the Current state table above.
- [ ] Step 2: Replace the spec's count instruction with "floor check, not exact count".
- [ ] Step 3: Rule on 24–27: "validated with caveat" means the mapping is validated, so no `mapping: proposed` marker. Record as `Ruling:` in the spec.
- [ ] Step 4: Remove the decoy sentence from the kill-chain description. Verify `grep -c decoy scenarios/carbanak-kill-chain.yaml` returns 0.
- [ ] Step 5: Re-sign `carbanak-kill-chain.yaml`; `verify-all` reports zero failures.
- [ ] Step 6: Commit.

## Task 1: Discovery and credential-access scenarios (10–15, 17, 18)

**Files:** Create `scenarios/carbanak-bfsi-<name>.yaml` and `.sig` for each: 10 payment gateway config discovery (T1083), 11 database service discovery (T1046), 12 privileged account enumeration (T1069.002), 13 share discovery for financial data (T1135), 14 Credential Manager existence probe (T1555.004), 15 browser credential-store existence probe (T1555.003), 17 Kerberos service-account enumeration (T1558.003), 18 synthetic operator credential discovery (T1552, sub-technique to confirm).

- [ ] Step 1: Write the failing test: every built-in file with the `carbanak-bfsi-` prefix loads, has a technique ID or an attack gap, and has a valid signature. Run it; it fails for the missing files.
- [ ] Step 2: For each scenario, write the YAML following `carbanak-bfsi-app-discovery.yaml`. Each `command` is query-only. Scenario 14 and 15 check existence only; add a test that the command never opens the store.
- [ ] Step 3: Validate each technique on attack.mitre.org before setting it. Record the result in the spec's validation table.
- [ ] Step 4: Sign each file; run the test; it passes.
- [ ] Step 5: Commit.

## Task 2: Lateral-movement scenarios (19–22)

**Files:** Create four scenarios: 19 SMB admin share (T1021.002), 20 WinRM (T1021.006), 21 remote service (T1569.002), 22 remote scheduled task (T1053.005).

- [ ] Step 1: Write the failing test: with `BAS_CARBANAK_TARGET_HOST` unset, each returns SKIP with reason `target host unset`, never PASS. Run it; it fails.
- [ ] Step 2: Write the four YAMLs with the gate in each command. The test-host name must be a `.lab` or `.test` label.
- [ ] Step 3: Validate the four techniques on attack.mitre.org.
- [ ] Step 4: Sign; run the test; it passes.
- [ ] Step 5: Commit.

## Task 3: Collection and exfiltration scenarios (29–32)

**Files:** Create four scenarios: 29 financial document collection (T1005), 30 payment database staging (T1074.001), 31 archive financial records (T1560.001), 32 HTTPS exfiltration simulation (T1041, `.invalid` domain).

- [ ] Step 1: Write the failing test: scenario 32 targets only a `.invalid` host; a production-looking host is refused.
- [ ] Step 2: Write the four YAMLs. Collection uses synthetic files written to a temp directory and removed at the end; test that cleanup runs.
- [ ] Step 3: Validate the four techniques on attack.mitre.org.
- [ ] Step 4: Sign; run the test; it passes.
- [ ] Step 5: Commit.

## Task 4: Fraud-control acceptance checks

**Files:** Modify or create tests in `orchestrator/internal/scenario/fraud_control_test.go` and `orchestrator/internal/carbanakledger/server_test.go`.

- [ ] Step 1: Write failing tests for acceptance criteria 6, 7, 8 and 11a. Each names the case and the exact expected verdict.
- [ ] Step 2: Run them; confirm each fails for the expected reason.
- [ ] Step 3: Implement the missing behavior, if any, without changing the approved verdict table.
- [ ] Step 4: Run the tests; they pass.
- [ ] Step 5: Commit.

## Task 5: Registration and verification

- [ ] Step 1: Regenerate the step-contract ledger and baseline with `STEP_CONTRACT_WRITE=1`. Check the diff: new entries only for the 16 new scenarios and the corrected kill chain.
- [ ] Step 2: Run `go test ./internal/scenario/...`. Must be green.
- [ ] Step 3: Run `signer.go verify-all`. Zero failures.
- [ ] Step 4: Record the outcome in a QA log at `docs/carbanak-bfsi-qa-log.md`.
- [ ] Step 5: Commit.

## Task 6: Lab validation (needs the lab)

- [ ] Step 1: Run the ledger locally with `BAS_CARBANAK_FIXED_TIME` set; run the 7-step sequence twice; results match.
- [ ] Step 2: Run each new scenario on the lab. Record PASS, FAIL, ERROR or SKIP with reason.
- [ ] Step 3: Report results. Do not claim any bank's controls were validated (spec non-goal).

## Rulings and open items for approval

- **Ruling A (Task 0, step 3):** validated-with-caveat mappings carry no `mapping: proposed` marker. Cost if wrong: caveated mappings appear in coverage reporting. Reversible in one edit.
- **Open:** whether Task 6 lab runs happen before merge. The spec's merge gate needs them; I recommend yes.
- **Open:** lateral-movement lab validation (19–22) needs a second host. Without one they stay SKIP and are reported as unvalidated.
