# Application Control Efficacy Mastery — QA Log

Date: 2026-10-18
Design: `docs/superpowers/specs/2026-10-18-application-control-efficacy-mastery-design.md`

## Status by phase

| Phase | Scope | Status | Notes |
|---|---|---|---|
| 1 | Posture correction and missing LOLBin Posture tier | Done | em-01 uses effective coverage. full-scan no longer treats AppIDSvc as enforcement. ExecutionPolicy labelled as configuration posture. Five LOLBin Posture steps added. |
| 2 | Behavioral harness and enforcement oracle | Done for V2 families. `inprocess_hosting` not built (V3, see feasibility record) | Five families in `scenarios/appcontrol-efficacy.yaml`: indirect_execution, alternate_binary, script_host_proxy, alternate_ps_host, parent_child_asr. |
| 3 | Security-product correlation | Partial | Local Sysmon telemetry visibility is wired as a separate fact and mapped to the AV Mastery `avval` model. Vendor bridges (Defender, SentinelOne) are not wired. |
| 4 | Coverage matrix and reporting | Partial | Matrix renderer, comparator, and evidence model are built. The renderer is not yet wired into the report output. |

## Changes in this pass

- `scenarios/appcontrol-efficacy.yaml`: added script_host_proxy (cscript runs a benign `.vbs`, attributed via AppLocker MSI and Script event 8006), alternate_ps_host (pwsh.exe, not_applicable when absent), and parent_child_asr (renamed cmd.exe spoofing a Winword parent, attributed via Defender event 1121 and the Office child-process ASR rule). Every step emits `APPCTL_FAMILY`, `APPCTL_COVERAGE`, `APPCTL_EVIDENCE`, `APPCTL_DETECTION`, and `APPCTL_OUTCOME`.
- `orchestrator/internal/reporting/appcontrol.go`: `ParseAppControlFamily`, `ParseAppControlVisibility`, `AppControlPathResult`, `RenderAppControlMatrix`.
- `orchestrator/internal/reporting/appcontrol_avval.go`: `AppControlToAVVal` maps prevention, execution, and telemetry coverage onto `avval.CollectionResult`.
- Tests: `appcontrol_families_test.go` (family fixtures), `appcontrol_avval_test.go`, and extended `appcontrol_test.go`.
- Scenario signatures refreshed. `verify-all` reports ok=124 fail=0.

## Verification (this session)

| Check | Command | Result |
|---|---|---|
| Family fixtures, 12 cases | `go test -count=1 ./internal/scenario/ -run TestAppControlFamilies -v` | All pass |
| Parsers and matrix (RED first, then GREEN) | `go test -count=1 ./internal/reporting/ -run AppControl -v` | RED: undefined symbols. GREEN: all pass |
| Telemetry-to-avval mapping, 5 cases | `go test -count=1 ./internal/reporting/ -run AppControlToAVVal -v` | All pass |
| LOLBin Posture, 12 cases | `go test -count=1 ./internal/scenario/ -run TestLOLBinPosture -v` | All pass |
| V1 behavioral, 10 cases | `go test -count=1 ./internal/scenario/ -run TestAppControlBehavioral -v` | All pass |
| Full scenario package | `go test -count=1 ./internal/scenario/` | ok |
| Full reporting package | `go test -count=1 ./internal/reporting/` | ok |
| Vet | `go vet ./internal/reporting/ ./internal/scenario/` | clean |
| Signatures | `go run scripts/signer.go verify-all ../scenarios` | ok=124 fail=0 |
| destructiveguard backstop over all changed scenario commands | temporary scan, deleted afterwards | none classified as destructive; scan confirmed to parse real steps |

## Test-first honesty

- The parser, matrix, and avval tests were written first and watched fail on undefined symbols.
- The V2 scenario steps were written before their behavioral tests in this pass, so the family fixture run verified them rather than going red first. Two fixture defects were found and fixed: the ASR fixtures never set `logOK`, and the pwsh fixture did not name the binary in the block event. Both were harness gaps, not step defects.

## Limitations (explicit)

- **Live enforcement is not verified.** Nothing was run against a host with an enforced AppLocker or ASR policy. The tests stub every control cmdlet and launch nothing real. Real AppLocker and Defender event formats are unconfirmed on a live host. This needs an authorized lab.
- **Unreadable log is conservative.** If the event log is unreadable, the result is `inconclusive` even when the attempted process is observed to have run. This under-claims in the audit-mode case, but it keeps every enforcement claim tied to attribution, as the spec requires.
- **parent_child_asr is name-based.** It spawns a copy of `cmd.exe` named `winword.exe`, not a real Office parent. It tests whether the ASR rule matches on image name, not whether it blocks a real Office child.
- **alternate_ps_host covers PowerShell 7 only.** It reports `not_applicable` where `pwsh.exe` is absent. This host does not have it, so that path is untested here.
- **Script host proxy covers cscript with `.vbs` only.** wscript and other script hosts are not covered.
- **Visibility is not a detection verdict.** `APPCTL_DETECTION` records whether Sysmon process-creation telemetry saw the attempt. It is mapped to the independent-sensor source with `DetectionUnknown`, and it never asserts that nothing was detected.

## Not done

- **Phase 3 vendor correlation.** Defender and SentinelOne bridge wiring is not built. There is no live tenant to confirm field paths, and the AV Mastery bridge is still unwired per its own record.
- **Phase 4 report wiring.** The matrix renderer exists and is tested. It is not yet inserted into the board or HTML report output.
- **`inprocess_hosting` (V3).** Not built. See the feasibility record.
- **Full-mastery claim.** Not made. Phase 3 vendor correlation and live enforcement verification remain open.

## V3 feasibility record (inspection, not a runnable spike)

This was an inspection of the existing code and host. A runnable spike was not built.

- The host has the PowerShell automation assembly in the GAC (`System.Management.Automation`, Windows PowerShell 5.1, .NET Framework 4.8.9310). In-process hosting is possible on this host.
- The agent executes PowerShell as an external process: `agent/executor_windows.go` uses `exec.CommandContext` for `powershell`, `cmd`, `wscript`, and related interpreters. The Go binary does not host the CLR.
- Two options exist. A child .NET helper process is still a separate process, so it does not test in-process behavior. Native CLR hosting from Go through COM or hostfxr is fragile and needs cgo-level work. Neither is a small change.
- The value of in-process testing differs from process-gating tests. AppLocker Script rules do not gate in-process automation, so the claim it would test is different: Constrained Language Mode, AMSI, and ScriptBlock logging, not process execution control.
- Recommendation: do not build `inprocess_hosting` in this phase. Revisit only if a claim about CLM or AMSI is needed, and then as its own design decision.

## Known remaining gaps to report

- Sign-off requires a lab run on a host with an enforced AppLocker Exe and Script policy and an enforced Office child-process ASR rule. Expected: `blocked_as_expected` on the indirect, alternate-binary, script-host, and ASR paths. Expected `not_applicable` on the pwsh path if pwsh is absent.
- Vendor correlation (Phase 3) needs a live Defender or SentinelOne tenant.
