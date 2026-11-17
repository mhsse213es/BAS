# APT29 Kill Chain Phase 7: lab validation runbook

Internal. Not part of what a client runs. The two shipped scenarios
(`scenarios/apt29-kill-chain-phase7.yaml`, id `apt29-kill-chain-phase7` -- kept
distinct from the separately-maintained `apt29-kill-chain` scenario; see the QA
log's naming note -- and `scenarios/apt29-cloud-identity.yaml`) are
production-safe and telemetry-safe by design — every stage is reversible and the
cloud branch refuses to run without a configured test tenant. This runbook is the
manual check that the telemetry each stage *claims* actually fires on a real
Windows endpoint. No results in this document yet — this is the checklist, not a
report. Results go in `docs/apt29-phase7-mastery-qa-log.md` once a real lab run has
happened.

**Why this exists.** The Phase 7 design doc's own requirement: "don't assume every
API call generates the expected EDR event." This repo's own history (ADCS stage 10
under-reporting, a stage-17 wording overclaim) shows that assumption breaks in
practice. The only way to know a claimed Sysmon/Security event ID actually fires is
to run the stage on a real endpoint and query the event log, independent of the
stage's own `Write-Output` text.

## Prerequisites

- A domain-joined Windows host to run the 30 Windows stages from.
- Local admin for stages that declare `requires_priv: admin` (14, 16, 17, 19, 24-26).
  A non-admin run of those stages must `ERROR` with an explicit reason, never
  PASS/FAIL — confirm that too, not just the admin-mode path.
- Sysmon installed with a configuration that logs EID 1, 3, 10, 11, 13, 14, 19, 20,
  21, 22, 23 (the event IDs this scenario's stages claim). If Sysmon is absent or a
  narrower config is in use, several stages' "telemetry" claims will not be
  confirmable — record that as a finding, not a silent gap.
- For stages 8, 24, 25, 26 (the 4 multi-host-dependent stages): a second reachable
  Windows host, and `$env:BAS_APT29_TARGET_HOST` set to it. Without it, confirm the
  SKIP behavior instead (see below).
- For the 5 cloud stages: a real Microsoft 365/Azure test tenant and a
  least-privilege test app registration (never a production tenant or app). Set
  `BAS_APT29_CLOUD_TENANT_ID`, `BAS_APT29_CLOUD_CLIENT_ID`,
  `BAS_APT29_CLOUD_CLIENT_SECRET`, and `BAS_APT29_CLOUD_TEST_MAILBOX` (a synthetic
  test mailbox's UPN). **Do this part only once a tenant actually exists** — until
  then, confirm the ERROR-without-tenant behavior instead.

## How to run a stage and confirm its telemetry

For each stage below: run it, then immediately query the event log the stage's
`telemetry:` field claims, scoped to the last minute and the relevant process/
object name. Example pattern:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=(Get-Date).AddMinutes(-1)} | Where-Object { $_.Message -match '<process or marker name>' }
```

A stage whose claimed event ID does not appear is a real finding — record it in the
QA log as "claimed but not observed," and consider whether the stage's `telemetry:`
field needs correcting (the same kind of fix the ESC10/stage-17 ADCS bugs were).

## Per-stage checklist (stages 6-30, Windows)

| Stage | Technique | Run as | Confirm this event fires |
|---|---|---|---|
| 6 | T1069.002 | user | Sysmon EID 1 for `net.exe group` |
| 7 | T1018 | user | Sysmon EID 1 for `nltest.exe` |
| 8 | T1018 (remote) | user | With `BAS_APT29_TARGET_HOST` unset: confirm `SKIP` + reason, not PASS/FAIL. With it set: Sysmon EID 1/22 against the target |
| 9 | T1518.001 | user | WMI query telemetry for `root/SecurityCenter2` |
| 10 | T1016 | user | Sysmon EID 1 for `ipconfig.exe`/`arp.exe` |
| 11 | T1047 | user | Sysmon EID 1, parent `WmiPrvSE.exe` |
| 12 | T1218.011 | user | Sysmon EID 1 for `rundll32.exe` |
| 13 | T1027 | user | PowerShell EID 4104 ScriptBlock (de-obfuscated text) |
| 14 | T1685.001 | **admin** | System/Security log config-change event; confirm restore; confirm `ERROR` (not PASS/FAIL) without admin |
| 15 | T1547.001 | user | Sysmon EID 11 (create) + EID 23 (delete) in Startup folder |
| 16 | T1546.003 | **admin** | Sysmon EID 19/20/21; confirm `ERROR` without admin |
| 17 | T1543.003 | **admin** | Security EID 4697 + System EID 7045; confirm `ERROR` without admin |
| 18 | T1546.015 | user | Sysmon EID 13 (set) + EID 14 (delete) |
| 19 | T1003.001 | **admin** | Sysmon EID 10 against `lsass.exe` **-- confirm whether this fires at all; the scenario's own text says this depends on Sysmon config granularity, don't assume** |
| 20 | T1555.004 | user | Sysmon EID 1 for `cmdkey.exe` |
| 21 | T1555.003 | user | Low-fidelity; confirm the stage completed and found/did-not-find the files, no DB was opened |
| 22 | T1558.003 | user | Sysmon EID 1 for `setspn.exe` |
| 23 | T1555 (DPAPI) | user | Confirm round-trip succeeded on synthetic data only |
| 24 | T1021.002 | **admin** | With no target: confirm `SKIP`. With target: Security EID 5140/5145 **on the target host** |
| 25 | T1021.006 | **admin** | With no target: confirm `SKIP`. With target: Security EID 4624 (Type 3) + WinRM EID 91 on the target |
| 26 | T1569.002 | **admin** | With no target: confirm `SKIP`. With target reachable but denied: confirm `ERROR`, not SKIP. With target and allowed: Security EID 4697 on the target |
| 27 | T1071.001 | user | Sysmon EID 22 for the `.invalid` domain |
| 28 | T1071.004 | user | Sysmon EID 22 x3 at the 2s interval (periodicity, distinct from stage 5) |
| 29 | T1005 | user | Sysmon EID 11 for the synthetic marker file under `$env:TEMP` |
| 30 | T1041 | user | Sysmon EID 22 for the `.invalid` exfil domain |

## Credential-access cluster (stages 19-23): extra scrutiny

Before recording any result for stages 19-23, re-confirm the safety tier directly
against the running command, not just the YAML text: watch the process in
Process Monitor or Sysmon while each stage runs, and confirm no handle with
`VM_READ` access, no `MiniDumpWriteDump`-style call, no `CredRead` against a
specific target, and no SQLite/`CryptUnprotectData` call against a real browser
profile ever appears. This is the same check Task 4 of the implementation plan ran
as a text grep; running it against live behavior on a real endpoint is the stronger
version of that check.

## Cloud branch (requires a real test tenant — do this part only once one exists)

| Stage | What to confirm |
|---|---|
| 1 | Without tenant env vars: `ERROR` with "cloud tenant not configured", never PASS. With tenant: Entra ID audit log shows "Update application – Certificates and secrets management" add then remove. |
| 2 | Without tenant env vars: `ERROR`. With tenant: Entra ID audit log shows an `oauth2PermissionGrants` add then delete, scope `User.Read` only. |
| 3 | Without tenant env vars: `ERROR`. With tenant: read-only Graph call succeeds; confirm nothing was written. |
| 4 | Without tenant env vars or without `BAS_APT29_CLOUD_TEST_MAILBOX`: `ERROR`. With both: confirm the Graph search targeted ONLY the synthetic mailbox named in that variable. |
| 5 | Local condition check only — confirm it never makes a network call (check with a network capture if in doubt). |

## Cleanup checklist

- No `ZZ-BAS-APT29-*` registry key, service, scheduled task, WMI subscription
  object, or Startup-folder file remains on the Windows host.
- No service principal credential, OAuth permission grant, or test data remains in
  the cloud tenant (stages 1, 2, 4).
- `$env:BAS_APT29_TARGET_HOST` left set or unset as the operator intends for the
  next run.

## Result status

Not yet run against a real lab endpoint or a real cloud tenant. This scenario's
structural correctness is verified (`go test ./internal/scenario/...` green, every
stage's `TechniqueID`/`DetectionProfiles` wiring confirmed, the credential-access
safety tier confirmed by static grep) — that is not the same as confirming real
telemetry on a real endpoint. See `docs/apt29-phase7-mastery-qa-log.md` for the
still-blank result table.
