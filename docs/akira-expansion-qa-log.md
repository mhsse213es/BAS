# Akira Kill Chain expansion, Part A: QA log

Scenario `akira-kill-chain` v2.0.0 -> v2.1.0 (16 -> 17 steps). Branch `akira-expansion`.
Spec: `docs/superpowers/specs/2026-11-17-akira-expansion-part1-design.md`. Plan: `docs/superpowers/plans/2026-11-17-akira-expansion-part-a.md`.
Part B (`ransomware-backup-recovery-assurance`) is NOT built.

## What changed

| Stage | Change |
|---|---|
| 3 SAM/SYSTEM | Gate `BAS_CONFIRM_CREDENTIAL_ARTIFACTS` (exact `true`); elevation required else SKIP; private dir `bas_akira_cred_<run>` with owner-only ACL; hives overwritten then deleted; `cleanup_verified=`; `production_safe: false` |
| 3b LSASS | Reports `process_query_access=` and `vm_read_handle=` separately; VM_READ handle behind `BAS_CONFIRM_LSASS_HANDLE`; elevation required; states no memory read; `production_safe: false` |
| 4 Defender | Verdict from Defender state (`Get-MpComputerStatus`), not a command line; optional add/read-back/remove behind `BAS_CONFIRM_DEFENDER_TAMPER`; renamed (engine_test pin updated) |
| 5a (new) | Local staging, 5 synthetic files, hash check, cleanup verified (T1074.001) |
| 5b | Re-tagged T1567 -> T1041; now depends on 5a |
| 6 | 6 synthetic files, XOR transform verified by SHA-256 (original differs, decode equals original), `cleanup_verified` |
| 6b | Re-tagged T1486 -> T1036.008 (rename alone is not encryption) |
| 8 | Bug fix: shadow copies matched by volume DeviceID (old `-match 'C:'` could never match); `targeted_copy_id`, before/after, re-query `deletion_verified`; SKIP states `recovery_protection=not_evaluated`; pinned SKIP text kept |
| 9 | EID 104 check, retention, `siem_ingestion=unverified`, test log removal verified |
| 9b | Added Sysmon service and audit-policy checks; bug fix: SRUM path was `LogFiles\SRU`, real path is `System32\sru` |

Also: `rwtaxonomy/mapping.go` gains T1074.001, T1041, T1036.008; T1567 removed.

## Evidence (run on the Windows build host, elevated, Defender real-time OFF)

Executed for real: stage 5a (5/5 staged, hashes ok, cleanup verified), stage 6 (6/6 transformed and verified, cleanup verified), stage 9 (clear succeeded, EID 104 recorded, test log removed), stage 9b, stage 4 read-only path (reported FAIL because tamper protection and real-time monitoring are off on this host; correct for this host), stage 3b query-handle path.
Gate checks: stages 3, 3b, 4, 8 with values `TRUE`, `1`, `yes`, empty, `false`, ` true` all stayed gated; only exact `true` enables. Stage 3 and 8 gate-off output is SKIP. No `bas_akira*` residue left in `%TEMP%` after the runs.
Stage 8 resolution: dry run (Delete() replaced by a no-op) found 2 shadow copies on C: by DeviceID and reported deletion_verified=False. Shadow copy count stayed 2.
Automated: `signer verify-all` ok=156 fail=0; `go test -short` ok for scenario, rwevidence, rwtaxonomy, rwdetect, rwrecover, admatrix. Every step script parses cleanly (with the UTF-8 BOM the agent adds; old and new both fail to parse without it, so no regression).
Destructive-guard classification compared old vs new for every step: unchanged (only stage 8 is destructive).

## NOT verified (do not claim)

- Stage 3 with the gate on: would save real SAM/SYSTEM hives; not run on the build host.
- Stage 3b VM_READ handle, stage 4 exclusion add/remove: not run (gated; would touch lsass handle and Defender exclusions).
- Stage 8 real `Delete()`: never executed; only resolution and read-back logic were exercised.
- Control-blocked paths (PASS verdicts for 3, 5a, 6, 8, 9) were never observed: this host has no active protection, so only the FAIL/unblocked branches ran.
- Sysmon/SIEM: `siem_ingestion=unverified` by design; nothing confirms events reached a SIEM.
- `internal/contentregistry` corpus test and `internal/api` tests need Docker Postgres: not run.
- Nothing run through the real agent/orchestrator; no live run.

## Findings from the review

1. `id:` and `depends_on:` are not parsed by the scenario engine (the Step type has no such fields); order in the list is what counts. So the 5a/5b dependency edits are documentation only.
2. Pre-existing: stages 1, 2, 3 and 4 `depends_on: akira-s0-preflight`, which does not exist. Not changed (out of scope), flagged.
3. Re-tagging 6b away from T1486 means it no longer counts as encryption evidence in ransomware scoring (intended, but a visible scoring change). T1074.001, T1041, T1036.008 are not modeled by `rwevidence`, so 5a/5b/6b are reported but not graded as ransomware capabilities.
4. T1036.008 is the closest available tactic mapping for a mass rename; sub-technique choice is flagged for review.
