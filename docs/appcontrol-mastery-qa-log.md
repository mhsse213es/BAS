# Application Control Efficacy Mastery — QA Log

Date: 2026-10-18
Design: `docs/superpowers/specs/2026-10-18-application-control-efficacy-mastery-design.md`
Test contracts: `docs/appcontrol-test-contracts.md`

**Release distinction.** This work establishes implementation and test coverage. It does not establish verified real-world enforcement efficacy. Every passing fixture in this log is a stubbed test of the code. None of them shows that a live AppLocker, ASR, or endpoint control blocks anything. The run report states this on the page itself (Section 18a, Limitations).

## Status

Everything buildable without a live Windows lab or vendor tenant is complete. Two areas remain open by decision and are not claimed as done: live enforcement validation and vendor correlation. Section "What you need to do" lists the work that is yours.

| Phase | Scope | Status | Notes |
|---|---|---|---|
| 1 | Posture correction and LOLBin Posture tier | Done | em-01 uses effective coverage. full-scan no longer treats AppIDSvc as enforcement. ExecutionPolicy labelled as configuration posture. Five LOLBin Posture steps. |
| 2 | Behavioral harness and enforcement oracle | Done for the five families. Test contracts written. `inprocess_hosting` deferred (V3) by decision | indirect_execution, alternate_binary, script_host_proxy, alternate_ps_host, parent_child_asr. Each has a contract. |
| 3 | Security-product correlation | Local part done. Vendor correlation open | Sysmon telemetry is a separate fact mapped to the `avval` model (`appcontrol_avval.go`). Defender and SentinelOne correlation are open: they need tenant access. The `avval` mapping is intentionally not rendered yet; it is the seam for vendor correlation. |
| 4 | Coverage matrix and reporting | Done for run reports and campaign reports | Section 18a in the run report (HTML and PDF). Campaign reports carry one section per child run, labelled with its host. |

## What was done in this pass

- **AppLocker edition gating.** Where AppLocker cannot be read at all (an edition without it), the indirect, alternate-binary, script-host, and alternate-PS-host steps now report `not_applicable`, not `inconclusive`. A readable policy with no collections is still a valid "not enforced" reading. Fixtures cover both cases.
- **Test contracts.** `docs/appcontrol-test-contracts.md` has one contract per family. Each carries control under test, technique, prerequisites, expected-result source, expected outcome, evidence requirements, attribution rule, cleanup, unsupported conditions, and known blind spots. `TestAppControlContracts_EveryFamilyHasContract` reads the families from the scenario, so a family without a contract fails the build. This was checked by breaking one heading in a copy of the doc: the test failed, and the restored doc passed.
- **Campaign reports.** `BuildFromCampaign` builds one section per child run from that run's own results, before any filter, and labels it with the run's host. Runs are never merged. The campaign's top-level section stays empty. The database test confirms each run keeps its own rows.
- **Run report.** Unchanged from the previous pass: Section 18a, built from the run's own results before any filter.
- **Signatures.** `appcontrol-efficacy.yaml.sig` re-signed. `verify-all` reports ok=124 fail=0.

## Verification

| Check | Command | Result |
|---|---|---|
| Campaign per-run sections, HTML and database (container) | `go test -count=1 ./internal/reporting/ -run 'CampaignRenders\|BuildFromCampaign_AppControl' -v` | PASS |
| Run report end-to-end (container) | `go test -count=1 ./internal/reporting/ -run TestBuildFromRun_AppControl -v` | PASS |
| Report section unit and HTML tests | `go test -count=1 ./internal/reporting/ -run 'AppControl\|GenerateHTML' -v` | PASS |
| Family fixtures including edition-gated cases | `go test -count=1 ./internal/scenario/ -run 'TestAppControlFamilies\|TestAppControlBehavioral' -v` | 29 PASS, 0 FAIL |
| Test contracts, plus a mutation check | `go test -count=1 ./internal/scenario/ -run TestAppControlContracts -v` | PASS; mutation caught and restored |
| LOLBin Posture | `go test -count=1 ./internal/scenario/ -run TestLOLBinPosture -v` | PASS |
| Full scenario package | `go test -count=1 ./internal/scenario/` | ok, exit 0 |
| Full reporting package | `go test -count=1 ./internal/reporting/` | ok, exit 0 |
| Vet | `go vet ./internal/reporting/ ./internal/scenario/` | clean |
| Signatures | `go run scripts/signer.go verify-all ../scenarios` | ok=124 fail=0 |

**Not verified in this pass:**

- `internal/api` does not compile right now. Another session's uncommitted `phishingrun` files reference missing symbols. This work doesn't touch that package, but its tests should run once it builds.
- The destructiveguard scan was not repeated for this pass. The commands added here are benign state checks, and the earlier scan of every changed command found no vetoes.

## Test-first honesty

- The report unit tests, the parser tests, and the avval tests were written first and watched fail.
- The end-to-end, campaign, and contract tests were written after their implementations. They passed on their first run, so they verify behavior rather than driving it.
- The edition-gated fixtures were written after the YAML change, so they confirmed the change rather than driving it. The contract test was checked by a mutation.
- Earlier, two harness defects were found and fixed in the family fixtures. Both were test-harness gaps, not step defects.

## Limitations

- **Live enforcement is not verified.** Nothing ran against a host with an enforced AppLocker or ASR policy. The tests stub every control cmdlet and launch nothing real. Real event formats (AppLocker 8004 and 8006, Defender 1121, Sysmon 1) are unconfirmed on a live host.
- **Unreadable log is conservative.** An unreadable event log gives `inconclusive`, even if the attempt is seen to run. This under-claims in audit mode, but it keeps every enforcement claim tied to attribution.
- **parent_child_asr is name-based.** It uses a copy of `cmd.exe` named `winword.exe`, not a real Office parent. It shows whether the rule matches on image name, not whether it blocks a real Office child.
- **alternate_ps_host covers PowerShell 7 only.** It reports `not_applicable` where `pwsh.exe` is absent.
- **script_host_proxy covers `cscript` with `.vbs` only.**
- **Windows version is not gated separately.** Gating happens on the AppLocker policy being readable (edition) and on each control's presence. A build-number check was not added.
- **Visibility is not a verdict.** Sysmon visibility never asserts that nothing was detected.
- **Older runs get the section on regeneration.** The section is computed from stored results at report time. Steps that stored no structured output show as `unverified`.

## What you need to do

These need a lab, a tenant, or a decision that only you can make. Nothing here can be closed from this machine.

1. **Lab sign-off run (required before any efficacy claim).** Use a Windows host on which you can enforce AppLocker and an ASR rule, with Sysmon installed and logging. Then:
   - Confirm AppIDSvc is running.
   - Enforce AppLocker Exe and Script rules that cover `powershell.exe`, `cscript.exe`, and the test copies. Use a publisher or hash rule, not path-only.
   - Set the Office child-process ASR rule (`D4F940AB-401B-4EFC-AADC-AD5F3C50688A`) to Block.
   - Run `scenarios/appcontrol-efficacy.yaml`.
   - Expected: `blocked_as_expected` for indirect_execution, alternate_binary, script_host_proxy, and parent_child_asr.
   - Any `allowed_unexpectedly` or `not_enforced` is a real gap. Report it as one, not as a test failure.
2. **Negative controls on the same lab.** Repeat with the Exe rule in audit-only, or with the ASR rule in audit mode. Expected: `not_enforced` or `allowed_unexpectedly`. This shows the test can fail.
3. **Not-applicable control.** Run on an edition without AppLocker (or with the policy unavailable). Expected: `not_applicable` on the AppLocker steps, never a pass.
4. **Confirm event formats on the lab host.** Check that AppLocker 8004 and 8006, Defender 1121, and Sysmon EID 1 appear with the fields the attribution rule depends on. Record any difference in this log. A format change means the attribution rule needs updating before the results can be trusted.
5. **alternate_ps_host.** Install PowerShell 7 on the lab host. Without it this path is only `not_applicable`.
6. **Vendor correlation (deferred by you).** Defender and SentinelOne correlation needs tenant access and the integration. When you have both, the open work is to wire the `avval` mapping to those sources and confirm their field paths against a live tenant.
7. **V3 in-process hosting (deferred by you).** Nothing to do unless you decide to revisit it. The feasibility record recommends not building it: it tests a different control boundary (Constrained Language Mode, AMSI, ScriptBlock logging), not process gating.
8. **Campaign report review.** Check how the per-run sections read to a client when a campaign has many runs. The layout is one page per run.
9. **Limitations wording.** Review the four limitation statements in Section 18a before a client sees them. They are deliberately strong; soften only if the lab run supports it.
10. **Fix the `internal/api` build.** Another session's uncommitted `phishingrun` files stop the package compiling. Resolve that, then run its tests so the report handlers are covered.
11. **Regenerate existing reports on staging.** Existing runs get Section 18a only when their report is regenerated. Check a run with application-control steps on staging.

## V3 feasibility record (inspection, not a runnable spike)

- The host has the PowerShell automation assembly in the GAC (`System.Management.Automation`, Windows PowerShell 5.1, .NET Framework 4.8.9310). In-process hosting is possible on this host.
- The agent runs PowerShell as an external process (`agent/executor_windows.go`, `exec.CommandContext`). The Go binary does not host the CLR.
- A child .NET helper is still a separate process, so it does not test in-process behavior. Native CLR hosting from Go is fragile and needs cgo-level work.
- Recommendation: do not build it in this phase.
