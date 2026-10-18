# Application Control Efficacy Mastery — QA Log

Date: 2026-10-18
Design: `docs/superpowers/specs/2026-10-18-application-control-efficacy-mastery-design.md`
Test contracts: `docs/appcontrol-test-contracts.md`

**Release distinction.** This work establishes implementation and test coverage. It does not establish verified real-world enforcement efficacy. Every passing fixture in this log is a stubbed test of the code. None of them shows that a live AppLocker, ASR, or endpoint control blocks anything. The run report states this on the page itself (Section 18a, Limitations).

## Status

Everything buildable without a live Windows lab or vendor tenant is complete, including V3 in-process hosting. Two areas remain open by decision and are not claimed as done: live enforcement validation and vendor correlation. Section "What you need to do" lists the work that is yours.

| Phase | Scope | Status | Notes |
|---|---|---|---|
| 1 | Posture correction and LOLBin Posture tier | Done | em-01 uses effective coverage. full-scan no longer treats AppIDSvc as enforcement. ExecutionPolicy labelled as configuration posture. Five LOLBin Posture steps. |
| 2 | Behavioral harness and enforcement oracle, including V3 in-process hosting | Done for six families. Test contracts written | indirect_execution, alternate_binary, script_host_proxy, alternate_ps_host, parent_child_asr, inprocess_hosting. Each has a contract. |
| 3 | Security-product correlation | Local part done. Vendor correlation open | Sysmon telemetry is a separate fact mapped to the `avval` model (`appcontrol_avval.go`). Defender and SentinelOne correlation are open: they need tenant access. The `avval` mapping is intentionally not rendered yet; it is the seam for vendor correlation. |
| 4 | Coverage matrix and reporting | Done for run reports and campaign reports | Section 18a in the run report (HTML and PDF). Campaign reports carry one section per child run, labelled with its host. |

## What was done in this pass

- **V3 in-process hosting (`inprocess_hosting`).** The custom PowerShell host is `tools/inprocess-host/bas-pshost.cs`. It hosts `System.Management.Automation` in its own process, not `powershell.exe`, and reports its language mode and whether `Add-Type` succeeds. `tools/inprocess-host/build.ps1` builds it with the .NET Framework compiler already on Windows, and downloads nothing. The scenario step runs the host only when `BAS_INPROC_HOST` points at a built binary, and reports `not_applicable` otherwise.
- **Positive control.** The host has a `--positive-control-constrained` flag that starts the runspace in Constrained Language Mode. The scenario never passes it. It exists only to show the probe can detect a restricted host. Results on this machine: default `FullLanguage`, `Add-Type` allowed; positive control `ConstrainedLanguage`, `Add-Type` blocked. The probe distinguishes the two.
- **The `__PSLockdownPolicy=4` environment variable does not restrict a custom host here.** Setting it for the process left the host at `FullLanguage`. It is not a usable lever for the test.
- **AppLocker edition gating.** Where AppLocker cannot be read at all, the AppLocker steps report `not_applicable`, not `inconclusive`. A readable policy with no collections is still a valid "not enforced" reading.
- **Test contracts.** `docs/appcontrol-test-contracts.md` has one contract per family, including `inprocess_hosting`. `TestAppControlContracts_EveryFamilyHasContract` reads the families from the scenario, so a family without a contract fails the build. It was checked by breaking one heading in a copy of the doc.
- **Campaign reports.** One section per child run, built from that run's own results before any filter, labelled with its host. Runs are never merged.
- **Signatures.** `appcontrol-efficacy.yaml.sig` re-signed.

## Real run on this machine

These results come from the real helper, not from stubs.

| Configuration | Language mode | Add-Type | Outcome |
|---|---|---|---|
| Default (what the scenario runs) | FullLanguage | allowed | `allowed_unexpectedly`, reported as FAIL |
| Positive control (`--positive-control-constrained`) | ConstrainedLanguage | blocked | would be `blocked_as_expected` |

The default result is a finding: a custom PowerShell host on this machine runs without a language restriction. Whether that is acceptable depends on the endpoint's policy, and that decision is yours.

## Verification

| Check | Command | Result |
|---|---|---|
| V3 fixtures, seven cases, stubbed host output | `go test -count=1 ./internal/scenario/ -run TestInProcessHosting_OutcomeFromHostOutput -v` | PASS |
| V3 real host binary | `BAS_INPROC_HOST=<path> go test -count=1 ./internal/scenario/ -run TestInProcessHosting_RealHostBinary -v` | PASS; real result shown above |
| Test contracts, including `inprocess_hosting` | `go test -count=1 ./internal/scenario/ -run TestAppControlContracts -v` | PASS |
| Report family list, six families in order | `go test -count=1 ./internal/reporting/ -run AppControl -v` | PASS |
| Full scenario package | `go test -count=1 ./internal/scenario/` | ok, exit 0 |
| Full reporting package | `go test -count=1 ./internal/reporting/` | ok, exit 0 |
| Vet | `go vet ./internal/reporting/ ./internal/scenario/` | clean |
| Signatures | `go run scripts/signer.go verify-all ../scenarios` | ok=126 fail=0 |
| destructiveguard over the six steps of the scenario | temporary scan, deleted afterwards | none classified as destructive; scan confirmed to parse 6 steps |
| Helper build | `tools/inprocess-host/build.ps1 -OutDir <dir>` | built |

**Not verified in this pass:**

- `internal/api` does not compile. Another session's uncommitted `phishingrun` files reference missing symbols. This work doesn't touch that package.
- The signature count moved from 124 to 126. Other sessions' signed scenario files account for the difference; this work signed only `appcontrol-efficacy.yaml`.

## Test-first honesty

- The report and parser tests were written first and watched fail.
- The V3 fixtures and the contract test were written after their steps, so they verified the steps rather than driving them. The contract test was checked by a mutation.
- The real host run was the first time the step ran against a real host. It exposed nothing that required a change; it confirmed the outcome.

## Limitations

- **Live enforcement is not verified.** Nothing ran against a host with an enforced AppLocker or ASR policy. The tests stub every control cmdlet and launch nothing real. Real event formats (AppLocker 8004 and 8006, Defender 1121, Sysmon 1) are unconfirmed on a live host.
- **Unreadable log is conservative.** An unreadable event log gives `inconclusive`, even if the attempt is seen to run. This under-claims in audit mode, but it keeps every enforcement claim tied to attribution.
- **parent_child_asr is name-based.** It uses a copy of `cmd.exe` named `winword.exe`, not a real Office parent.
- **alternate_ps_host covers PowerShell 7 only.** It reports `not_applicable` where `pwsh.exe` is absent.
- **script_host_proxy covers `cscript` with `.vbs` only.**
- **inprocess_hosting is a custom host, not `powershell.exe`.** It measures the language restriction on that host. It does not measure AMSI, ScriptBlock logging, or the policy that a product applies to `powershell.exe`. Its visibility is `unknown`, since no sensor is configured for it.
- **Windows version is not gated separately.** Gating happens on the AppLocker policy being readable and on each control's presence.
- **Visibility is not a verdict.** Sysmon visibility never asserts that nothing was detected.
- **Older runs get the section on regeneration.** The section is computed from stored results at report time.

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
4. **Confirm event formats on the lab host.** Check that AppLocker 8004 and 8006, Defender 1121, and Sysmon EID 1 appear with the fields the attribution rule depends on. Record any difference in this log.
5. **alternate_ps_host.** Install PowerShell 7 on the lab host. Without it this path is only `not_applicable`.
6. **inprocess_hosting: decide the policy.** Build the host with `tools/inprocess-host/build.ps1`, set `BAS_INPROC_HOST`, and run the step. On this machine the custom host runs FullLanguage and reports FAIL. Decide whether the endpoints you protect should run a custom PowerShell host under Constrained Language Mode. If they should, the FAIL is a real gap on those endpoints. If not, the contract's `restricted` expectation should be changed, and that change should be recorded here.
7. **Vendor correlation (deferred by you).** Defender and SentinelOne correlation needs tenant access and the integration. When you have both, the open work is to wire the `avval` mapping to those sources and confirm their field paths against a live tenant.
8. **Campaign report review.** Check how the per-run sections read to a client when a campaign has many runs.
9. **Limitations wording.** Review the four limitation statements in Section 18a before a client sees them. Soften only if the lab run supports it.
10. **Fix the `internal/api` build.** Another session's uncommitted `phishingrun` files stop the package compiling. Resolve that, then run its tests so the report handlers are covered.
11. **Regenerate existing reports on staging.** Existing runs get Section 18a only when their report is regenerated. Check a run with application-control steps on staging.
