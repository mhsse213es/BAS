# APT29 expansion implementation plan

> Spec: `docs/superpowers/specs/2026-11-17-apt29-expansion-design.md`. Executed inline in this session (user preference). Branch `apt29-expansion`.

**Goal:** fix `apt29-kill-chain` in place and add five attributed scenarios, 29 steps total, with a shared evidence library.

## Global constraints
ASCII generated YAML; sign every changed scenario; `verify-all` clean; scenario count pin in `internal/scenario/product_line_test.go` (140 -> 145); step-contract ledger regenerated; destructive-guard classes non-destructive or declared; every step cleans up and reports `cleanup_verified`; gates are exact lowercase `true`.

## Review focus
- A block verdict from absence alone (must be inconclusive).
- Needle that cannot match a real event (name the artifact the event names).
- Cleanup that leaves registry/WMI/task/portproxy state when a step is killed.
- Localized Windows (match SIDs, not English names).
- PowerShell 5.1 quoting for native commands with paths that contain spaces.

## Tasks
1. Library `scenarios-src/apt29-common/lib.ps1` + decision-table test (all outcome classes, mechanisms, readable/unreadable logs).
2. Fix `apt29-kill-chain` (6 stages, new generated source `scenarios-src/apt29-kill-chain/`), keep id; update template descriptions and `docs/guides/scenarios.md`; fixtures for each stage.
3. `apt29-execution-evasion` (9). 4. `apt29-persistence` (4). 5. `apt29-credential-access` (3). 6. `apt29-command-control` (4). 7. `apt29-collection-staging` (3).
8. Register: pin, ledger, contracts doc `docs/apt29-test-contracts.md`, QA log `docs/apt29-expansion-qa-log.md`.
9. Run every step for real; code review; fix; merge to main.
