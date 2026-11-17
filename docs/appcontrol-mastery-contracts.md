# Application Control Mastery: test contracts

Companion to `docs/appcontrol-test-contracts.md`. It covers the four scenarios added on top of `appcontrol-efficacy`:
`appcontrol-proxy-execution` (9), `appcontrol-script-interpreter` (8), `appcontrol-file-enforcement` (10) and
`appcontrol-policy-integrity` (7). Sources live in `scenarios-src/appcontrol-*`; the shared oracle is
`scenarios-src/appcontrol-common/lib.ps1`; regenerate with `orchestrator/scripts/appctlgen` and re-sign.

## Shared rules (every step)

- **Mechanisms.** Each execution step is judged against AppLocker (collection mode from `Get-AppLockerPolicy -Effective`, service `AppIDSvc` running) and WDAC / App Control for Business (user-mode status from `Win32_DeviceGuard`). A mechanism that is unavailable is ignored; if none is available the result is `not_applicable`.
- **Block evidence.** AppLocker EXE/DLL 8004; AppLocker MSI/Script 8007; WDAC 3077 (and 8029 for script/MSI). Audit events (8003, 8006, 3076, 8028) never count as prevention.
- **Event needle.** Block events are matched by the name of the blocked object. Execution steps match the host binary (regsvr32.exe, mshta.exe ...); Script-collection steps match the unique per-run script file name (`bas_<id>.vbs/.bat/.wsf/.js/.ps1`) because AppLocker 8007 and WDAC 8029 name the script, not its host.
- **Outcomes.** `blocked_as_expected` needs the marker absent, exactly one matching block event per enforcing mechanism (none with more than one), and that mechanism Enabled. A run under an Enabled mechanism is `allowed_unexpectedly`; under audit mode `audited_only`; with nothing enforcing `not_enforced`. Unreadable logs, a missing or ambiguous event, or absence with nothing Enabled are `inconclusive`. Absence alone is never a pass.
- **ConstrainedLanguage.** `powershell_language_mode` also counts a script that ran only in ConstrainedLanguage under an Enabled mechanism as prevented.
- **Integrity steps** (`policy_*`, `supplemental_policy`, `managed_installer`) use direct verdicts: the step observes the denial or exposure itself and states the reason. They never count events.
- **Location confound.** Steps that run from the private temp directory (c01 to c03, c07) cannot tell a signature or publisher rule from a path rule that denies user-writable locations; use c04 to c06 for location, and read c01 to c03 together with them.
- **ConstrainedLanguage.** Where WDAC puts PowerShell into ConstrainedLanguage, steps that compile a test program or call native code report not_applicable with that reason; the result is unknown, not a pass.
- **Cleanup.** Every artifact lives in `%TEMP%\bas-appctl-<id>` (or a named extra path) and is deleted by the step; `cleanup_verified` is reported. The step's own `cleanup` also sweeps `bas-appctl-*`.
- **Lab gates (exact lowercase `true`).** `BAS_CONFIRM_APPCONTROL_SERVICE_STOP` (stops and restores AppIDSvc, administrator only), `BAS_CONFIRM_APPCONTROL_POLICY_TAMPER` (re-applies the identical local AppLocker policy; creates then removes one non-policy canary file in the WDAC active directory). An administrator succeeding at these is recorded as evidence in the step note and does not change the verdict, which stays based on who is permitted to write; only a non-administrative identity succeeding is a failure. Everything else is ungated and benign. Baseline input: `BAS_APPCTL_BASELINE_SHA256`.
- **Detection.** `APPCTL_DETECTION` records Sysmon process-create visibility separately and never sets a prevention verdict.

## appcontrol-proxy-execution

| Family | Technique | Control under test | Artifact (benign) | Known blind spots |
|---|---|---|---|---|
| regsvr32_proxy | T1218.010 | Exe rules / WDAC on regsvr32.exe | .sct scriptlet writing a marker | local file only; no remote scriptlet |
| rundll32_proxy | T1218.011 | Exe rules / WDAC on rundll32.exe | INF run through advpack.dll | advpack route only |
| mshta_proxy | T1218.005 | Exe rules / WDAC on mshta.exe | .hta writing a marker | covers HTA and inline script; the former separate HTA test was merged here |
| msiexec_proxy | T1218.007 | MSI rules / WDAC on a user-writable .msi | minimal MSI, no product registered | one custom-action type |
| installutil_proxy | T1218.004 | Exe rules on InstallUtil.exe | compiled unsigned assembly | needs the .NET Framework compiler |
| control_panel_cpl | T1218.002 | WDAC only: AppLocker does not evaluate .cpl | signed system applet copied and LoadLibrary'd | does not exercise control.exe itself |
| cmstp_proxy | T1218.003 | Exe rules / WDAC on cmstp.exe | INF with a pre-setup command | no UAC-bypass behaviour tested |
| xsl_script_processing | T1220 | Exe rules / WDAC on wmic.exe | XSL with inline JScript | not applicable where WMIC is absent |
| msbuild_proxy | T1127.001 | Exe rules / WDAC on MSBuild.exe | project with an inline C# task | .NET Framework MSBuild only |

## appcontrol-script-interpreter

| Family | Technique | Control under test | Notes |
|---|---|---|---|
| wscript_host | T1059.005 | Script rules / WDAC | .vbs from a user-writable path |
| cmd_batch_script | T1059.003 | Script rules | .bat from a user-writable path |
| wsf_script_host | T1059.005 | Script rules | .wsf through cscript |
| user_writable_script_host | T1059.007 | Script rules / WDAC | .js through wscript |
| powershell_script_signing | T1059.001 | Script rules | execution policy recorded as context only; it is not a security boundary |
| powershell_language_mode | T1059.001 | Script rules / WDAC | FullLanguage = allowed, ConstrainedLanguage under Enabled = prevented |
| wmi_process_create | T1047 | Exe rules | ASR PSExec/WMI rule state recorded as context; cmd.exe events can be noisy, which yields inconclusive |
| alternate_interpreters | T1059 | Exe rules / WDAC | uses an already-installed interpreter; never installs; not applicable if none |

## appcontrol-file-enforcement

| Family | Technique | What it distinguishes |
|---|---|---|
| unsigned_executable | T1204.002 | unsigned binary, neutral location |
| tampered_signature | T1553.002 | valid signature turned invalid; original untouched |
| publisher_trust | T1553.002 | self-signed publisher blocked; a Microsoft-signed copy recorded as context; certificate removed |
| exec_from_temp / exec_from_appdata / exec_from_downloads | T1204.002 | location rules; Downloads adds a Mark-of-the-Web stream and CreateProcess (no shell prompt) |
| renamed_extension | T1036.008 | file identity versus extension (.tmp PE) |
| dll_loading | T1129 | unsigned managed library loaded by a child process |
| ocx_module_loading | T1129 | .ocx extension; RLL is not tested |
| msi_installation | T1218.007 | installer enforcement through the Windows Installer API, not msiexec.exe |

## appcontrol-policy-integrity

| Family | Technique | Default (read-only) | Gated action |
|---|---|---|---|
| policy_service_interruption | T1562.001 | AppIDSvc security descriptor: unprivileged stop rights | stop and restore AppIDSvc |
| policy_modification | T1562.001 | permissions of the local AppLocker policy key | re-apply the identical effective policy |
| policy_downgrade | T1562.001 | audit mode, or collections with no rules | none |
| supplemental_policy | T1562.001 | permissions of the WDAC active policy directory | one non-policy canary file |
| managed_installer | T1553 | Managed Installer rules trusting user-writable paths | none |
| policy_after_reboot | T1562.001 | persistence and post-boot load evidence | none (no reboot) |
| policy_lifecycle | T1562.001 | effective policy hash against an operator baseline | none |
