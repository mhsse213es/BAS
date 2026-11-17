# Akira Expansion Part A (honesty corrections) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (user chose inline execution). Steps use checkbox syntax.

**Goal:** Correct the 9 existing Akira stages that overstate what they prove, without changing the scenario id.

**Architecture:** Hand edits to `scenarios/akira-kill-chain.yaml` (2.0.0 to 2.1.0), plus the three pinned touchpoints (`engine_test.go` stage-name pin, `rwtaxonomy` mapping, signature). Safe steps are executed locally on the Windows build host to verify behaviour; lab-gated paths are exercised only for their gate-off SKIP.

**Tech Stack:** Windows PowerShell 5.1 inside YAML, Go tests, `scripts/signer.go`.

**Spec:** `docs/superpowers/specs/2026-11-17-akira-expansion-part1-design.md` (Part A table).

## Global Constraints
- Scenario id `akira-kill-chain` unchanged; `version: "2.1.0"`.
- Keep verbatim: `BAS_CONFIRM_VSS_DELETE` gate text `SKIP: BAS_CONFIRM_VSS_DELETE not set to 'true'` and `SKIP: no C: VSS shadow copies exist` (pinned by `internal/rwevidence/realcorpus_test.go`); the single non-recon T1490 deletion step stays the Stage 8 step; recon step names in `reconnaissanceStepNames` unchanged.
- Verdict lines: first line `PASS:` / `FAIL:` / `SKIP:`; every SKIP says why (`gate not confirmed`, `prerequisite missing`).
- Any step that writes anything verifies its own cleanup and prints `cleanup_verified=True|False`.
- Lab gates are env vars, default off: `BAS_CONFIRM_CREDENTIAL_ARTIFACTS`, `BAS_CONFIRM_LSASS_HANDLE`, `BAS_CONFIRM_DEFENDER_TAMPER`.
- Gated or credential-touching steps: `production_safe: false`.
- Windows PowerShell 5.1; ASCII only inside commands (em-dash footgun); every edit re-signs the `.sig` with the main checkout key (absolute path), never `--allow-dev`.
- New techniques need `internal/rwtaxonomy/mapping.go` entries and the stale `T1567` entry removed (two-way corpus test).

## Review Focus
- Gate unset or set to `false`/`TRUE`/empty: must SKIP, never run (only exact `true` enables).
- Output dir already exists from a prior aborted run: step must not fail or leak old files.
- No Defender installed / cmdlet missing (server core, third-party AV): SKIP with prerequisite reason, not PASS.
- Not admin: SKIP with reason, not FAIL.
- Controlled Folder Access blocks the staging write: PASS (prevented), never a crash.

---
### Task 1: Baseline
- [ ] Run `go test -short -count=1 ./internal/scenario/ ./internal/rwevidence/ ./internal/rwtaxonomy/ ./internal/rwdetect/ ./internal/contentregistry/` from `orchestrator/`; expected: all `ok`. Record any pre-existing failure before editing.

### Task 2: Stage 3 (SAM/SYSTEM) and 3b (LSASS) gating
**Files:** Modify `scenarios/akira-kill-chain.yaml` (stages `akira-s3-sam-theft`, `akira-s3b-lsass-probe`).
- [ ] Stage 3: gate `BAS_CONFIRM_CREDENTIAL_ARTIFACTS` exactly `true`, else first line `SKIP: gate not confirmed (BAS_CONFIRM_CREDENTIAL_ARTIFACTS)`. When enabled: create a private directory under `%TEMP%` named `bas_akira_<runId>` (ACL: current user only), `reg save` into it, record sizes, overwrite each file with zeros then delete, remove the directory, print `cleanup_verified=` from `Test-Path`. `production_safe: false`. Verdict PASS if both saves denied, FAIL if either saved.
- [ ] Stage 3b: query-limited open reported as `process_query_access=`; VM_READ-capable open attempted only when `BAS_CONFIRM_LSASS_HANDLE` is `true`, opened and closed with no memory read, reported as `vm_read_handle=`; also print `ppl_protected=` when detectable. Output states "handle access, not credential extraction". Verdict FAIL only when `vm_read_handle=True`.
- [ ] Run stage 3 and 3b commands locally with the gates unset; expected: first line starts `SKIP`.

### Task 3: Stage 4 (Defender) state-based verdict
**Files:** Modify stage `akira-s4-defender-exclusion`; update the pinned name at `orchestrator/internal/scenario/engine_test.go:965`.
- [ ] New name `Akira Stage 4 — Defender Tamper Protection and Exclusion State (T1562.001)`; keep detection profile `windows_defender_tampering`.
- [ ] Default read-only: `Get-MpComputerStatus`/`Get-MpPreference`; print `tamper_protection=`, `realtime_monitoring=`, `exclusion_paths=<count>`. PASS if tamper protection on and real-time on; FAIL if tamper protection off; SKIP with reason if the Defender cmdlets are missing.
- [ ] With `BAS_CONFIRM_DEFENDER_TAMPER=true`: add exclusion for `%TEMP%\bas_akira_defender_<runId>` only, read back (`exclusion_added=`), remove, read back (`exclusion_removed=`), print `cleanup_verified=`. A failed read-back is an ERROR line, never PASS.
- [ ] Update the `engine_test.go` row to the new name; run `go test -short ./internal/scenario/ -run Detection` (the table test); expected pass.
- [ ] Run stage 4 locally; expected: a `PASS:`/`FAIL:` from real state or a reasoned `SKIP`.

### Task 4: Stage 5b split (staging T1074.001, exfil T1041) plus taxonomy
**Files:** Modify `scenarios/akira-kill-chain.yaml`; `orchestrator/internal/rwtaxonomy/mapping.go`.
- [ ] Insert `akira-s5a-local-staging` (name `Akira Stage 5a — Local Data Staging (T1074.001)`, technique `T1074.001`, profile `windows_dlp_exfiltration`): create `%TEMP%\bas_akira_stage_<runId>` with 5 synthetic files tagged `[BAS-SIM-AKIRA-S5A]`, verify the files exist and hash, delete, print `cleanup_verified=`. PASS = staging write was blocked; FAIL = staged.
- [ ] Change `akira-s5b-exfil-staging` to name `Akira Stage 5b — Pre-Encryption HTTPS Exfiltration to Own Sink (T1041)`, technique `T1041`; behaviour unchanged except text; `depends_on` the new 5a.
- [ ] `mapping.go`: add `"T1074.001": DomainDataDiscoveryAndStaging`, `"T1041": DomainExfiltration`; remove `"T1567"`.

### Task 5: Stage 6 (synthetic transform verified) and 6b (re-tag)
- [ ] Stage 6: directory `%TEMP%\bas_akira_enc_<runId>` with 6 synthetic files; transform each (XOR 0x41, `.akira`); verify hash of encoded differs from original, decoded hash equals original (`transform_verified=True`); print `files=6 transformed=N`; remove all, print `cleanup_verified=`. Wording: "transform simulation, not cryptographic encryption". PASS only if the write/transform was prevented.
- [ ] Stage 6b: technique `T1036.008`, name `Akira Stage 6b — Mass-Rename Fan-Out Simulation (T1036.008)`; text states rename alone is not encryption. `mapping.go`: add `"T1036.008": DomainDefenseEvasion`.

### Task 6: Stages 8, 9, 9b
- [ ] Stage 8: keep gate and SKIP text verbatim; add before/after counts and `targeted_copy_id=`; after `Delete()` re-query and print `deletion_verified=True|False`; a gate-off SKIP line adds `recovery_protection=not_evaluated`.
- [ ] Stage 9: after the clear attempt on the BAS custom log, query System log for EID 104 for that log and print `eid104_recorded=`; print retention for the Security log (`wevtutil gl Security`: size, retention); add `siem_ingestion=unverified (no sink visible from endpoint)`. Verdict logic unchanged.
- [ ] Stage 9b: add `auditpol /get /category:"Detailed Tracking"` read, `sysmon_service=` (`Get-Service Sysmon*`), `security_log_max_kb=`; text says posture, not proof of resistance.
- [ ] Run stages 9b and 9 locally if elevated; expected: SKIP-with-reason or real PASS/FAIL, never a crash.

### Task 7: Finish
- [ ] `version: "2.1.0"`, update description/stage list in the scenario header; sign: `go run scripts/signer.go sign /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator/private_key.pem ../scenarios/akira-kill-chain.yaml` from `orchestrator/`; `verify-all ../scenarios` expect `fail=0`.
- [ ] Re-run Task 1's test command; expected all `ok` (the rwtaxonomy two-way test now sees T1074.001, T1041, T1036.008 and no T1567).
- [ ] Write `docs/akira-expansion-qa-log.md` (what changed, what ran locally, what is NOT VERIFIED); commit and push branch `akira-expansion`.
