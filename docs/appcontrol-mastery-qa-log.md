# Application Control Efficacy Mastery — QA Log

Date: 2026-10-18
Design: `docs/superpowers/specs/2026-10-18-application-control-efficacy-mastery-design.md`

**Release distinction.** This work establishes implementation and test coverage. It does not establish verified real-world enforcement efficacy. Every passing fixture in this log is a stubbed test of the code. None of them shows that a live AppLocker, ASR, or endpoint control blocks anything. The run report states this on the page itself (Section 18a, Limitations).

## Status by phase

| Phase | Scope | Status | Notes |
|---|---|---|---|
| 1 | Posture correction and missing LOLBin Posture tier | Done | em-01 uses effective coverage. full-scan no longer treats AppIDSvc as enforcement. ExecutionPolicy labelled as configuration posture. Five LOLBin Posture steps added. |
| 2 | Behavioral harness and enforcement oracle | Done for V2 families. `inprocess_hosting` deferred (V3) | Five families in `scenarios/appcontrol-efficacy.yaml`: indirect_execution, alternate_binary, script_host_proxy, alternate_ps_host, parent_child_asr. |
| 3 | Security-product correlation | Partial. Vendor correlation deferred | Local Sysmon telemetry visibility is a separate fact, mapped to the `avval` model in `appcontrol_avval.go`. That mapping is not rendered in the report. Defender and SentinelOne correlation are deferred until tenant access exists. |
| 4 | Coverage matrix and reporting | Done for run reports. Campaign reports not included | The section is built from each run's own results and rendered in the run report HTML and PDF (Section 18a). |

## Report integration (this pass)

- **Pipeline.** `FullReport.AppControl` (`internal/reporting/engine.go`) is built in `BuildFromRun` from the run's own results, before any report filter. A filter cannot hide a family that ran. `GenerateHTML` renders it as Section 18a in `html.go`, between Detection Validation and Coverage Analytics. The PDF export renders through the same HTML (`htmlpdf.go`), so it includes the section too.
- **Single renderer.** The earlier Markdown renderer (`RenderAppControlMatrix`) was removed, along with its tests. The HTML section is the only renderer, so there is no duplicate rendering logic.
- **Prevention and telemetry.** Each evaluated path has a prevention outcome and a telemetry visibility field, shown in separate columns. A blocked path can be unseen, and a visible path can be allowed. Neither is inferred from the other.
- **Inconclusive is preserved.** `inconclusive`, `not_applicable`, and `not_visible` are shown as they are. Missing telemetry is never rendered as proof that execution did not happen.
- **Coverage is explicit.** The section lists all five families in a fixed order. Each shows its observed outcome, `not_run`, or `unverified` (the step ran but produced no structured `APPCTL_OUTCOME`). Conflicting outcomes within one run show as `inconclusive`. A family that is not run is never presented as passing.
- **Limitations.** Four statements are rendered in every section that has data. They say that live AppLocker and ASR enforcement is verified only where a run executed on a configured host, that fixture tests are not evidence of enforcement, that telemetry visibility is not a verdict, and that vendor correlation is unverified.
- **Hidden when absent.** A run with no application-control steps has no section, so existing reports are unchanged.

## Changes in this pass

- `orchestrator/internal/reporting/appcontrol_report.go` (new): `AppControlSection`, `AppControlRow`, `AppControlFamilyStatus`, `buildAppControlSection`, and the limitations text.
- `orchestrator/internal/reporting/engine.go`: `FullReport.AppControl` field; one call in `BuildFromRun`.
- `orchestrator/internal/reporting/html.go`: Section 18a block, one hunk.
- `orchestrator/internal/reporting/appcontrol.go` and `appcontrol_test.go`: `RenderAppControlMatrix` and its two tests removed.
- Tests: `appcontrol_report_test.go` (unit and HTML), `appcontrol_report_db_test.go` (end-to-end through `BuildFromRun` against a Postgres container).
- Earlier in this initiative: `scenarios/appcontrol-efficacy.yaml` V2 families, `appcontrol_families_test.go`, `appcontrol_avval.go`, `appcontrol_avval_test.go`, and the parsers in `appcontrol.go`.

## Verification (this session)

| Check | Command | Result |
|---|---|---|
| Report section unit tests (RED first: undefined symbols, then GREEN) | `go test -count=1 ./internal/reporting/ -run 'AppControl\|GenerateHTML' -v` | All pass |
| End-to-end mapping through the real query (Postgres container) | `go test -count=1 ./internal/reporting/ -run TestBuildFromRun_AppControl -v` | PASS. Run A shows only its own indirect row. Run B shows only its own alternate-binary row, allowed with not_visible telemetry. Run C shows no section. |
| Full reporting package (includes TOC, HTML, PDF-path regressions) | `go test -count=1 ./internal/reporting/` | ok, exit 0 |
| Family fixtures, 12 cases | `go test -count=1 ./internal/scenario/ -run TestAppControlFamilies -v` | All pass |
| LOLBin Posture, 12 cases | `go test -count=1 ./internal/scenario/ -run TestLOLBinPosture -v` | All pass |
| V1 behavioral, 10 cases | `go test -count=1 ./internal/scenario/ -run TestAppControlBehavioral -v` | All pass |
| Scenario package | `go test -count=1 ./internal/scenario/` | ok |
| Vet | `go vet ./internal/reporting/ ./internal/scenario/` | clean |
| Signatures | `go run scripts/signer.go verify-all ../scenarios` | ok=124 fail=0 |
| destructiveguard over every changed scenario command | temporary scan, deleted afterwards | none classified as destructive; scan confirmed to parse real steps |

**Not verified in this pass:** `internal/api`. Its package does not currently compile because another session's uncommitted `phishingrun` files reference missing symbols. This change does not touch `internal/api`, and the report HTML that API handlers serve comes from the same `GenerateHTML` the reporting tests exercise. The api tests should be run once that package compiles.

## Test-first honesty

- The report unit tests were written first and watched fail on undefined symbols before the implementation existed.
- The end-to-end test was written after the implementation and passed on first run. It is a verification test, not a red-first test.
- Earlier V2 family fixtures were written after their steps, so they verified the steps rather than going red first. Two harness defects were found and fixed: ASR fixtures never set `logOK`, and the pwsh fixture did not name the binary in the block event. Both were test-harness gaps, not step defects.

## Limitations (explicit)

- **Live enforcement is not verified.** Nothing was run against a host with an enforced AppLocker or ASR policy. The tests stub every control cmdlet and launch nothing real. Real AppLocker and Defender event formats are unconfirmed on a live host. A run report from an unconfigured host will show `not_applicable` or `inconclusive`, not a pass.
- **Unreadable log is conservative.** If the event log is unreadable, the result is `inconclusive` even when the attempted process is observed to have run. This under-claims in the audit-mode case, but it keeps every enforcement claim tied to attribution, as the spec requires.
- **parent_child_asr is name-based.** It spawns a copy of `cmd.exe` named `winword.exe`, not a real Office parent. It tests whether the ASR rule matches on image name, not whether it blocks a real Office child.
- **alternate_ps_host covers PowerShell 7 only.** It reports `not_applicable` where `pwsh.exe` is absent, and this host does not have it.
- **Script host proxy covers cscript with `.vbs` only.** wscript and other script hosts are not covered.
- **Visibility is not a detection verdict.** `APPCTL_DETECTION` records whether Sysmon process-creation telemetry saw the attempt. It never asserts that nothing was detected.
- **The avval mapping is not in the report.** `AppControlToAVVal` is built and tested, but nothing in production calls it. Its only role today is as the seam for vendor correlation.
- **Campaign reports do not include this section.** A campaign spans several runs, so there is no single run to map the evidence to. The campaign path passes no run results to the builder, so it renders no section. Adding one would mean making per-run sections explicit in the campaign report, which is a separate design decision.
- **Older runs get the section on regeneration.** The section is computed from each run's stored results when its report is generated, not stored separately. A stored run that contains application-control steps shows the section when its report is regenerated. Its rows are only as complete as the APPCTL output it stored, and steps that stored no structured output show as `unverified`.

## Not done

- **Live AppLocker and ASR enforcement verification.** Deferred until a properly configured Windows lab is available. The expected lab results are below.
- **Phase 3 vendor correlation (Defender, SentinelOne).** Deferred until integration and tenant access are available. The AV Mastery bridge is still unwired per its own record.
- **`inprocess_hosting` (V3).** Deferred. It introduces a different execution model and tests different control boundaries (Constrained Language Mode, AMSI, ScriptBlock logging rather than process gating). See the feasibility record.
- **Full-mastery claim.** Not made.

## V3 feasibility record (inspection, not a runnable spike)

This was an inspection of the existing code and host. A runnable spike was not built.

- The host has the PowerShell automation assembly in the GAC (`System.Management.Automation`, Windows PowerShell 5.1, .NET Framework 4.8.9310). In-process hosting is possible on this host.
- The agent executes PowerShell as an external process: `agent/executor_windows.go` uses `exec.CommandContext` for `powershell`, `cmd`, `wscript`, and related interpreters. The Go binary does not host the CLR.
- Two options exist. A child .NET helper process is still a separate process, so it does not test in-process behavior. Native CLR hosting from Go through COM or hostfxr is fragile and needs cgo-level work. Neither is a small change.
- Recommendation: do not build `inprocess_hosting` in this phase. Revisit only if a claim about CLM or AMSI is needed, and then as its own design decision.

## Expected results for the lab sign-off run

Run these on a host with an enforced AppLocker Exe and Script policy and an enforced Office child-process ASR rule.

- `indirect_execution`, `alternate_binary`, `script_host_proxy`, `parent_child_asr`: expected `blocked_as_expected`. Any `allowed_unexpectedly` or `not_enforced` is a real gap and must be reported as one.
- `alternate_ps_host`: expected `blocked_as_expected` where `pwsh.exe` is installed and the Exe rule covers it, otherwise `not_applicable`.
- Telemetry visibility is recorded separately for each path. A `not_visible` result on a blocked path is a finding about telemetry coverage, not a prevention failure.
