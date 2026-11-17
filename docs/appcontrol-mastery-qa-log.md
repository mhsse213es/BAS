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

## Policy resolution and snapshot behaviour (2026-10-19)

**When the policy is resolved.** Every dispatch resolves the in-process policy once, at dispatch time, and nowhere else. The order is:

1. The policy given for that dispatch: the run-start request, or the campaign's execution policy.
2. The installation default, set through `PUT /api/execution-policy/default` (admin only).
3. Not stated, if neither is set. The in-process verdict then stays UNVERIFIED.

**What is recorded.** The resolved value is sent to the agent and stored on the run (`scenario_runs.inprocess_policy`). That stored value is the run's snapshot.

**What a change does.** Changing the installation default affects runs dispatched after the change. It never rewrites a finished run, whose verdict and snapshot stay as they were. Historical results are not recomputed from the current default.

**Scheduled assessments.** A schedule has no policy of its own. Each time it fires, it dispatches a run that resolves the installation default at that moment, and records the value on that run. A schedule therefore does not preserve the policy it was created under. If a schedule must keep a fixed policy, that needs a schedule-level override, which is deferred.

**Administration.** An admin can set the default from the Intel tab, in the "Execution policy (installation default)" card. The card uses `GET` and `PUT /api/execution-policy/default`. It is covered by four web unit tests, and by container-backed API tests for the default and for each dispatch's snapshot.

**Investigation: `TestGetAgents_Paginated_SearchMatchesHostnameAgentIDAndGroupName`.** This test failed once in a full API-suite run. Both searches returned nothing. It passed alone, both before and after the change below, and ten repeated runs of the `TestGetAgents_` group passed. The cause is not fully proven.

- *Confirmed in code.* The first page's snapshot was taken from the API host's clock (`time.Now()`). Rows are stamped by the database clock (`last_update DEFAULT NOW()`). The two clocks can disagree, so a freshly stamped agent can fall after the snapshot and vanish from the page.
- *Measured.* Skew on this host is about ±2 ms. Seeding and then searching 60 agents excluded none of them. That does not reproduce the failure.
- *Shared state checked.* No API tests run in parallel. Each test truncates every table when it finishes. Each test binary starts its own database container. No test overrides the clock.
- *Change.* The first page now takes its snapshot from the database clock (`SELECT NOW()`). Cursor pages keep the snapshot they were issued with. This removes the dependency on the two clocks agreeing, whatever their skew. It does not prove the failing run was caused by skew.

**Test stability.** Ten repeated runs of the agent-listing group passed after the change. The full `internal/api` suite has NOT passed. Four full runs (2026-10-19) each hung in test cleanup: the `TRUNCATE` in `testutil.truncateAll` never returned, at a different test each time, with no test failure before the hang. Investigation so far:

- The first hypothesis, a leaked transaction holding a lock, was not supported. The hung goroutine was running in the pgx client in one run and waiting on the socket in another, and the context timeout on the `TRUNCATE` did not end the call.
- A watchdog now stops waiting for a stuck `TRUNCATE` after 35 seconds and fails that test. In the fourth run the watchdog did not fire before the 50-minute limit, so the cause is not isolated.

A fifth full run on 2026-10-20 with `GOMAXPROCS=1` and a 30-second server-side `lock_timeout` on test connections passed: `ok internal/api 1683.8s`, no failures, no truncate errors. A run with the default setting (all CPUs) on the same code also passed: `ok internal/api 1681.9s`, no failures, no truncate errors. The cause of the earlier hang is still not isolated; the server-side `lock_timeout` is the change that let the suite finish, and it has passed both settings in one run each.

## Closure status

Each open item is one of three things: **Verified complete** (implementation and automated acceptance tests pass in this repo), **Blocked on environment or access** (the work is defined and the required real system is not available), or **Deferred by decision** (intentionally out of this release, with the impact stated).

**Verified complete**

- **Flaky cleanup tests** (`TestExecStepCleanupRunsAfterOperatorCancel`, `...ExecuteTimeout`). The root cause was in production code: the pre-cleanup snapshot ran inside the execute budget, so a slow snapshot could expire the budget before the command started. The snapshot is now taken first. The tests wait for a sentinel the command writes, not for elapsed time, and the timeout test fails if the command never started. Commit `70e20ff1`.
- **Policy propagation.** The in-process policy is resolved once per dispatch: explicit request or campaign value, then the installation default, then not stated. The result is sent to the agent and stored on the run as a snapshot. A later default change does not rewrite a finished run. Every dispatch path that carries an execution policy now carries the in-process policy too: run start, campaigns, sweeps and exercise, scheduled and remediation runs, and variant sweeps. Tests check the command the agent receives and the stored snapshot, and that an invalid value writes nothing.
- **Build floor (below 17763).** The shipped step text runs with the build expression replaced by `17000`, for all five gated families and the in-process host. Each must report `not_applicable`, with no verdict and the build recorded. This tests the real gate decision on this host. Older Windows builds were not run.

**Blocked on environment or access**

- **AppLocker/ASR lab sign-off.** Needs a Windows lab host with enforced policy. See "What you need to do".
- **ScriptBlock visibility with real event evidence.** Needs a host where you may enable ScriptBlock logging. The procedure is in `appcontrol-scriptblock-visibility-procedure.md`. Visibility stays `unknown` until it has been run and recorded.
- **Windows below 17763 on a real older image.** Needs an older VM. The gate itself is tested above.
- **Defender and SentinelOne correlation.** Needs tenant access. The adapters are not built. Building fixture-based adapters without a verified vendor event schema would mean guessing field names, so I have not done it. If you provide representative exported events from each product, the adapters and fixture tests can be built from them. Until a real tenant confirms the event, correlation is reported as unverified.

**Deferred by decision**

- **Management UI for the installation default.** The API exists: `GET` and `PUT /api/execution-policy/default`, restricted to `execution-policy:manage`, which only the admin role holds. The UI is not built.
- **Policy scope.** The default is installation-wide, because the product is on-prem with no tenants. Per-assessment overrides exist through the campaign's execution policy. Scheduled assessments inherit the installation default and have no separate override. Approve this scope, or ask for per-schedule overrides.

## What was done in this pass

- **V3 in-process hosting (`inprocess_hosting`).** The custom PowerShell host is `tools/inprocess-host/bas-pshost.cs`. It hosts `System.Management.Automation` in its own process, not `powershell.exe`, and reports its language mode and whether `Add-Type` succeeds. `tools/inprocess-host/build.ps1` builds it with the .NET Framework compiler already on Windows, and downloads nothing. The scenario step runs the host only when `BAS_INPROC_HOST` points at a built binary, and reports `not_applicable` otherwise.
- **Positive control.** The host has a `--positive-control-constrained` flag that starts the runspace in Constrained Language Mode. The scenario never passes it. It exists only to show the probe can detect a restricted host. Results on this machine: default `FullLanguage`, `Add-Type` allowed; positive control `ConstrainedLanguage`, `Add-Type` blocked. The probe distinguishes the two.
- **The `__PSLockdownPolicy=4` environment variable does not restrict a custom host here.** Setting it for the process left the host at `FullLanguage`. It is not a usable lever for the test.
- **AppLocker edition gating.** Where AppLocker cannot be read at all, the AppLocker steps report `not_applicable`, not `inconclusive`. A readable policy with no collections is still a valid "not enforced" reading.
- **Test contracts.** `docs/appcontrol-test-contracts.md` has one contract per family, including `inprocess_hosting`. `TestAppControlContracts_EveryFamilyHasContract` reads the families from the scenario, so a family without a contract fails the build. It was checked by breaking one heading in a copy of the doc.
- **Campaign reports.** One section per child run, built from that run's own results before any filter, labelled with its host. Runs are never merged.
- **Evidence shown in the report.** Section 18a now shows, for each evaluated path, the observed state (for the in-process host: its language mode and Add-Type result), the intended policy the verdict was judged against, the prevention outcome, and the telemetry visibility. The intended policy is shown as "not stated" when none was given, and as "not recorded" when the step never reached a verdict. It is never shown as a default.
- **AMSI limitation.** The report states that the in-process host test does not establish AMSI coverage.
- **ScriptBlock visibility for the in-process host.** The host's script text carries the run's marker. Visibility is `visible` when event 4104 contains the marker, `not_visible` only when ScriptBlock logging is enabled by policy and no such event exists, and `unknown` otherwise. The host validates its marker, so no argument can inject script.
- **Windows build gating and recording.** Every path records its build (`APPCTL_HOST`). The AppLocker, ASR, and in-process paths report `not_applicable` below build 17763. The build appears in the report's observed state.
- **Policy is set per run.** The run-start request accepts `executionPolicy.inProcessPolicy` (`restricted`, `unrestricted`, or omitted). The orchestrator rejects any other value. The agent exports the value as `BAS_INPROC_POLICY` for every step of that run, even when it is empty. A machine-wide `BAS_INPROC_POLICY` therefore cannot set a verdict for a run that did not state one.
- **Policy is not carried by campaign, sweep, or scheduled dispatch.** Those paths send no policy, so their in-process verdict stays UNVERIFIED. Carrying it through them is a follow-up.
- **No default policy.** Nothing defaults the policy. An unstated policy stays UNVERIFIED.
- **Signatures.** `appcontrol-efficacy.yaml.sig` re-signed.

## Real run on this machine

These results come from the real helper, not from stubs.

The host runs FullLanguage with `Add-Type` allowed. The verdict depends on the customer's intended policy, supplied as `BAS_INPROC_POLICY`:

| `BAS_INPROC_POLICY` | Host result | Outcome | Reported as |
|---|---|---|---|
| unset | FullLanguage, Add-Type allowed | `inconclusive` | UNVERIFIED |
| `restricted` | FullLanguage, Add-Type allowed | `allowed_unexpectedly` | FAIL |
| `unrestricted` | FullLanguage, Add-Type allowed | `allowed_by_policy` | PASS, exposure documented |

Positive control, run directly against the binary (not a scenario configuration): `--positive-control-constrained` gives ConstrainedLanguage with Add-Type blocked. The probe distinguishes restricted from unrestricted hosts. The control proves that the test can see a restriction. It does not show that the customer's controls enforce one.

A FullLanguage host is not automatically a failure. Whether that is a finding depends on the policy the customer has stated for custom hosts.

## Verification

| Check | Command | Result |
|---|---|---|
| V3 fixtures, 11 cases across policy values and host outputs, stubbed | `go test -count=1 ./internal/scenario/ -run TestInProcessHosting_OutcomeFromHostOutput -v` | PASS |
| V3 real host binary, each policy value | `BAS_INPROC_HOST=<path> [BAS_INPROC_POLICY=<value>] go test -count=1 ./internal/scenario/ -run TestInProcessHosting_RealHostBinary -v` | unset: inconclusive; restricted: allowed_unexpectedly; unrestricted: allowed_by_policy |
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
- **inprocess_hosting is a custom host, not `powershell.exe`.** It measures the language restriction on that host. It does not measure AMSI or the policy that a product applies to `powershell.exe`. Its visibility comes from ScriptBlock logging (event 4104) only where that logging is enabled by policy. Otherwise visibility is `unknown`. On this machine ScriptBlock logging is not enabled, so the live result is `unknown`.
- **Build gating is verified statically on the current build only.** Every path records its Windows build (`APPCTL_HOST`), and the report shows it. The AppLocker and ASR paths report `not_applicable` below build 17763. Below-floor behaviour has not been run on an older build, and no older build is available here. That check is a lab item.
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
6. **inprocess_hosting: state the policy.** The verdict needs your intended policy for custom PowerShell hosts. Send `"executionPolicy": {"inProcessPolicy": "restricted"}` in the run-start request if custom hosts must run ConstrainedLanguage and block `Add-Type`. Use `"unrestricted"` if FullLanguage is permitted, and the exposure is documented as a PASS. Leave it unset and the result stays UNVERIFIED. This is a decision about your endpoints, and the step does not make it for you.
   - Where a restriction is required, find a supported way to constrain the custom host, and verify the effective behaviour on the endpoint. Setting a language-mode flag alone is not a security boundary, and Constrained Language Mode is not a substitute for AppLocker or WDAC. The right control depends on the execution path.
   - Language-mode results say nothing about AMSI. Visibility uses ScriptBlock logging (event 4104) and is `unknown` wherever that logging is not enabled by policy. Turn it on in the lab to get a real visibility result for this path.
7. **Vendor correlation (deferred by you).** Defender and SentinelOne correlation needs tenant access and the integration. When you have both, the open work is to wire the `avval` mapping to those sources and confirm their field paths against a live tenant.
8. **Campaign report review.** Check how the per-run sections read to a client when a campaign has many runs.
9. **Limitations wording.** Review the four limitation statements in Section 18a before a client sees them. Soften only if the lab run supports it.
10. **Fix the `internal/api` build.** Another session's uncommitted `phishingrun` files stop the package compiling. Resolve that, then run its tests so the report handlers are covered.
11. **Regenerate existing reports on staging.** Existing runs get Section 18a only when their report is regenerated. Check a run with application-control steps on staging.

## Application Control Mastery expansion (2026-11-18)

Scope: 34 new steps in four scenarios (`appcontrol-proxy-execution` 9, `appcontrol-script-interpreter` 8, `appcontrol-file-enforcement` 10, `appcontrol-policy-integrity` 7) next to the unchanged six in `appcontrol-efficacy`, from the approved proposal. Contracts: `docs/appcontrol-mastery-contracts.md`. Sources: `scenarios-src/appcontrol-*`, shared oracle `scenarios-src/appcontrol-common/lib.ps1`, generator `orchestrator/scripts/appctlgen`.

### What changed and why
- One shared oracle (AppLocker and WDAC) replaces per-step copies. New outcome `audited_only`: audit mode records but does not prevent. Reporting parser, comparator and the AV validation adapter know it; mastery families show in a run's report only when that run produced them, so the six-family legacy view is unchanged.
- **Defect fixed in the shipped scenario.** `appcontrol-efficacy` script_host_proxy attributed blocks to AppLocker event 8006, which is the audit-mode event; the enforced Script/MSI block event is 8007 (Microsoft documentation). Under enforced Script rules the old step could not have reported `blocked_as_expected`. It now reads 8007 and the contract text says 8006 is not prevention evidence. Its own scenario was re-signed.
- Merged two overlapping list items (mshta and HTA are the same technique) and used the freed slot for Windows Script Files. The alternate-interpreter step never installs anything. The Control Panel step is tested against WDAC only because AppLocker does not evaluate .cpl.

### Verified on this host (Windows 10 Pro 19045, AppLocker service stopped, no WDAC user-mode policy)
- Every one of the 34 attempts was run for real through the shipped, generated YAML text and produced its benign marker (executed path), with cleanup verified and no leftover directories, certificates, products or processes. This host enforces nothing, so the execution steps reported `not_enforced`/FAIL (correct) or a not-applicable/inconclusive reason. Final tally of the 34 generated steps: 27 not_enforced, 4 not_applicable, 1 inconclusive (no drift baseline), 2 blocked_as_expected. The two passes are read-only permission checks on the policy-integrity scenario (AppIDSvc stop rights and the WDAC policy directory ACL), which are real findings about this host, not block events.
- Oracle decision table (21 cases), fixture runs of the shipped steps for every verdict class (including a realistic Get-WinEvent that throws when nothing matches), the ConstrainedLanguage path, integrity-step branches and the drift hash round trip all pass. `verify-all` ok=167, step-contract ledger regenerated with zero gaps for the new scenarios, destructive guard classifies every step non-destructive.

### NOT verified (read before relying on this)
- **No block was observed on a real host.** The block and audit paths are verified against stubs only. Event IDs come from Microsoft documentation (8004/8003, 8007/8006, 3077/3076, 8029/8028), not from a live enforced host; the AppLocker/WDAC message text that carries the file name is assumed to contain the unique file or binary name.
- WDAC user-mode state is read from `Win32_DeviceGuard`; its behaviour with multiple policies, signed policies and kernel-only policies is unverified.
- The gated paths (AppIDSvc stop/restore, identical-policy re-apply, WDAC canary file) have never run. The domain-independent integrity steps were only exercised in their read-only default.
- RLL modules, packaged apps (MSIX/APPX), COM activation, DLL search order/side-loading, scheduled-task/service launches and the operational-reliability tests (categories E to G) are not built.
- Some steps depend on the .NET Framework compiler (InstallUtil, unsigned executables, DLL) or on WMIC; they report not applicable where absent.
- Not run through a real agent and orchestrator; ten of the new steps compile code on the host and could be flagged by endpoint products themselves.
- Reported parent-spoofing mapping on the existing step 5 (T1204.002) is unchanged and still questionable (see the proposal); not touched.

### Code review findings fixed (2026-11-17, review of `main..appcontrol-mastery`)
Ten findings; all verified against the code. Fixed: (1) script steps b01 to b06 matched the host executable name, but AppLocker 8007 / WDAC 8029 name the script, so a working control could never score blocked; needles are now the unique script file names and the test stub emits events that name only that file. (2) the oracle swallowed non-result output from an attempt, hiding restore warnings; they are now printed. (3) gated admin actions no longer override the static verdict. (4) the report name fallback covers all 34 steps (new test). (5) c02 flipped a header byte; it now alters a resource or data section and accepts any non-Valid status (system binaries are catalog-signed, so the result reads NotSigned). (6) compile-dependent steps now say when ConstrainedLanguage is the cause. (7) b07 compared ASR GUIDs case-sensitively. (8) c03 left the CNG key container; it is now deleted and key file counts are printed (134 before, 134 after on this host). (9) c10 runs the installer in a child process with a 60 s kill; no product registration was observed. (10) the per-step cleanup sweep now covers APPDATA, Downloads, TEMP root files and the temporary certificate.
Documented, not fixable in the test itself: steps run from a user-writable temp directory cannot separate a signature rule from a location rule (see contracts); gated paths are still never run.

## Categories E to G (2026-11-17): packaging-trust (4), advanced-loading (4), operational-reliability (3)

Built from the same oracle and generator; 11 new steps, 45 across the pack, scenario pin 140, 170 signed scenarios verified.

### Verified
- Every step was executed for real on this host through its shipped, generated YAML text. Read-only steps return not_applicable (no enforcement) or a real finding (e3 AlwaysInstallElevated: unset, pass). f1 executed the DLL resolved by name and reported not_enforced.
- The gated COM scriptlet (f2) and scheduled-task (f3) paths were actually run with their flags set: each executed, removed what it created, and left no registry keys or tasks behind (checked afterwards).
- Fixture tests drive every verdict class of the direct-verdict steps (appx enforced, audit, missing; AlwaysInstallElevated both, one, unset; identity service running, stopped, disabled; allow rules over a drive, a user path, a protected path; log healthy, disabled, tiny, no policy) and prove each gate skips for unset, `True`, `1` and `yes`.

### NOT verified
- No enforced AppLocker or WDAC host was available: no block, audit or log-health verdict on a real policy has been observed, and the packaged-app, sideloading and writable-path branches are fixture-only.
- f4 (service launch) was never run, not even gated, because it creates a system service on the build host. Its create, start and delete sequence is untested; cleanup depends on `sc.exe delete`.
- Whether the Windows Installer, scheduled task or service manager paths are blocked by real rules is unobserved; the only evidence is that the launch worked on an unenforcing host.
- The writable-path list is fixed (six directories), not a complete ACL sweep; no package is installed, so packaged-app results are posture only.
- Policy update latency and audit-to-enforce transition timing are not tested.

### Code review of E to G (2026-11-17): 8 findings, all fixed
(1) e04 matched ACL identities by English name, so a localized host would pass a world-writable directory; it now matches SIDs, as do d02 and d04, and it only reports a bypass when a path allow rule covers the Windows directory. (2) f04 passed a quoted path through sc.exe, which Windows PowerShell 5.1 mangles for paths with spaces; it now uses New-Service and a short timeout on sc start (still not run on this host). (3) g03 counted paths under rule Exceptions as risky and ignored any-publisher rules; it reads only a rule's own conditions and flags wildcard publishers. (4) e02 let the local default overwrite the policy value and failed any enforced host for AllowAllTrustedApps, which is on by default; policy now wins and only developer mode fails. (5) the COM, task and service sweeps were in the cleanup of every step; they are now only on the three gated steps. (6) e03 read HKCU of whatever identity runs the step; under SYSTEM it is now inconclusive. (7) f02 broke on a quote or space in the profile path; both are escaped. (8) the ledger class for the task and service steps came from an empty action key; they now declare `schtask_create_delete` and `service_create_start_stop_delete`. The packaging-trust steps are classed destructive because the catalog fails closed for an unknown technique and action pair; they all declare a cleanup, so no gap results.
Added regression fixtures for each of the logic fixes.
