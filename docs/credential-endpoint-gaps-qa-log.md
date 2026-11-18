# Credential Access: Endpoint Credential-Location Gaps, QA Log

Phase 4 of the credential-access review, first increment: the five endpoint
credential-location gaps that need no Active Directory. The AD items (NTDS,
Golden/Silver tickets, relay, spraying) are not started and need a lab.

## Scenarios (5)

| Scenario | Technique | What it does |
|---|---|---|
| credential-dpapi-store-discovery | T1555 | Counts files in DPAPI master-key and credential folders. Opens none. |
| credential-browser-store-access | T1555.003 | Opens each browser login store read-only, reads no byte, closes it. Locked stores report SKIP. |
| credential-files-discovery | T1552.001 | Matches credential-like file names (password, credential, secret, .kdbx, .rdp). Names only. |
| credential-registry-discovery | T1552.002 | Checks presence of PuTTY and WinSCP session keys and the Winlogon DefaultPassword value name. Never reads a value. |
| credential-keys-certs-discovery | T1552.004 | Counts key-material files and private-key certificates. Exports and accesses none. |

## Verified (offline)

- Each file loads through the scenario schema.
- Each PowerShell block parses. Blocks were not executed.
- All five are signed; `verify-all` reports ok=238, fail=0.
- Step-contract ledger regenerated with 5 added steps and no removals.
- Step-contract, verdict-token and product-line tests pass.

## Decisions and corrections

- **Registry value read avoided.** The first draft used Get-ItemProperty, which loads
  every value's data, including a stored password. Changed to (Get-Item).Property,
  which returns names only.
- **Browser store locked is SKIP, not FAIL.** A locked file shows neither that the
  access was allowed nor that it was noticed.
- **Nothing opens a credential.** The only open is the browser store check, which
  reads no bytes and closes at once.

## Not verified

- No scenario has run on a host. The first real run needs the rebuild and the lab VM.
- The detection side (Security EID 4663, EDR alerts) is not checked against real
  telemetry. Auditing must be enabled on the target for EID 4663 to appear.

## Open

- AD items (NTDS, Golden/Silver, Pass-the-Ticket, spraying, relay, forced auth): need
  an isolated AD lab, and some need explicit authorization before building.
- Identity and session items (MFA fatigue, web sessions, cloud tokens): not started.

## Detection telemetry (EID 4663)

- **This dev host has File System auditing off** (`auditpol /get` reports "No
  Auditing"), so EID 4663 cannot appear here. The check was not run, because it
  would change this host's security configuration.
- **Lab check script:** `docs/credential-audit-4663-check.ps1`. Run it elevated on the
  lab VM only. It audits one synthetic temp file, reads it, looks for the 4663 event,
  then restores the audit setting and deletes the file. Output is `EID4663_FOUND=True|False`.
- **Still needed:** run that script on the lab VM and record its output here. Then
  run a credential scenario with auditing on the browser store paths and confirm the
  4663 event for `Login Data` or `logins.json`.

### Result: lab VM, 2026-11-18

- Host: `WIN-2IP8FNO4MAD`. `Win32_ComputerSystem.DomainRole` = 3 (member server). Not a domain controller.
- Starting audit state: `File System: No Auditing`.
- Script output:
  ```
  EID4663_FOUND=True
  ObjectName=C:\Users\Administrator\AppData\Local\Temp\2\bas_audit_check_9fcd96b8.txt
  AuditRestoredToOff=True
  ```
- Result: **the telemetry path works.** A read of an audited file produced event 4663 in the Security log, with the object name.
- The script restored the audit setting to off. Manual check of the restore and leftover file: not yet recorded.

### Result: browser login-store access, lab VM, 2026-11-18 (OPEN GAP)

- Host: `WIN-2IP8FNO4MAD` (member server). Browser: Chrome, default profile, one synthetic login (`bas-sim-login.invalid`), Chrome closed.
- Scenario read: `check-browser-store.ps1` (copy of `credential-browser-store-access` Stage 1) output:
  ```
  EXEC T1555.003: login stores present=1, opened read-only=1, locked=0. No byte was read.
  FAIL: A non-browser process opened a browser login store with no alert.
  ```
- Audit rule on `Login Data`: `Everyone` / `ReadData` / `Success`, confirmed with `Get-Acl -Audit`.
- Control, same rule method on a plain temp file: EID 4663 **was** produced.
- Result: EID 4663 was **not** produced for the `Login Data` open, over a one-hour window, despite the rule and auditing both being on.
- Checks ruled out: auditing off (checked, `Success`), rule not saved (confirmed present), time window (1 hour searched), the rule method (control test logged).
- Not yet explained. Candidate causes, unverified: the browser store's ACL or SACL handling, or the open path differing from the control test.
- Cleanup done: audit rule removed from `Login Data`; File System auditing set back to `No Auditing`; test login deleted from Chrome. (Confirm the delete step was done by hand.)
- **Consequence:** the browser login-store probe is NOT verified as producing 4663 on this lab. Do not mark it detection-verified until this gap is closed.

## Active Directory, first increment (lab.local)

Scope agreed: Golden/Silver detection only (no forging); spraying limited to synthetic accounts; relay and forced authentication as detection checks only.

Lab (confirmed 2026-11-18):
- Domain `lab.local`; DC `WIN-TQ70FGLETIU.lab.local` (PDC, KDC, writable).
- DC audit: Directory Service Access Success and Failure; Kerberos Authentication Service and Service Ticket Operations Success.
- KRBTGT password last set 10/27/2026 (about 22 days).
- Synthetic accounts `bassim1..3` in OU `BAS-Sim`, enabled, random unrecorded passwords.
- Lockout threshold set to 3, window 30 min, duration 30 min (lab domain only).
- Target list `C:\bas-lab\allowed-targets.txt` = `WIN-TQ70FGLETIU.lab.local`.

Scenarios:

| Scenario | Technique | What it does | Verdict rule |
|---|---|---|---|
| ad-forged-ticket-telemetry | T1558.001, T1558.002 | Reads KRBTGT age and encryption types (observation); counts 4768/4769 and RC4 events in the last hour | Posture never PASS. Telemetry PASS only if ticket events are visible, which proves logging, not alerting. |
| ad-ntds-access-attempt | T1003.003 | One read-only open of ntds.dit; closed at once; no bytes read | Open succeeds = FAIL. Blocked by lock = SKIP, because blocking is access control, not detection. |

Verified offline: schema, PowerShell parse, signatures (verify-all ok=241, fail=0), step-contract ledger (no removals), tests pass.

Not verified: neither scenario has run on the DC. Both need a platform run on the lab agent. The 4662 path for ntds.dit needs a SACL on the file, which is not set.

### ad-password-spray-lab (T1110.003)

- Three steps: preflight, spray, telemetry visibility.
- Guardrails enforced in the script: accounts hard-coded to `bassim1..3`; DC must be in `allowed-targets.txt`; lockout threshold must be 1 to 5 (refuses `Never`); one wrong-password attempt per account per run; refuses if any synthetic account failed in the last 30 minutes.
- Guess is the fixed fake string `BAS-SIM-Spray-Wrong-1!`. No real credential is tested.
- Verdicts: telemetry PASS only proves 4625/4771 logging, not alerting. Preflight refusals are SKIP.
- `live_policy`: `max_spray_attempts: 3`, `spray_account_allowlist: [bassim1, bassim2, bassim3]`.
- Verified offline: schema and spray-limit validation, PowerShell parse, signature (verify-all ok=242 fail=0), step-contract ledger (no removals), tests pass.
- Not verified: not run on the DC. Lockout threshold on the lab is currently 3, set in Step 6.

### Result: ad-password-spray-lab run on the DC, 2026-11-18

- DC: `WIN-TQ70FGLETIU.lab.local`. Lockout threshold 3.
- First attempt refused by the preflight: `found 0 of 3`. Cause: the AD filter used the unsupported `-in` operator, and the error was hidden by `SilentlyContinue`. Fixed in `40e95bba`. Nothing was sprayed in the refused run.
- Second run output:
  ```
  EXEC T1110.003: preflight passed. DC=WIN-TQ70FGLETIU.lab.local, lockout threshold=3, accounts=3.
  EXEC T1110.003: one attempt per synthetic account: bassim1=rejected, bassim2=rejected, bassim3=rejected.
  EXEC T1110.003: failure events for synthetic accounts in last 10 minutes = 3 (expected at least 3).
  PASS: the DC logged the spray attempts. Logging only; alerting needs a separate SIEM check.
  ```
- Lockout after the run: `LockedOut False` for `bassim1`, `bassim2`, `bassim3`; all `Enabled True`.
- Status: telemetry visibility confirmed on the DC for these attempts. Alerting NOT checked (no SIEM in this lab), so the spray scenario is not detection-verified.
- Next allowed run: not before 30 minutes after this run.

### NTLM relay posture and forced authentication (T1557.001, T1187), 2026-11-18

- **ad-ntlm-relay-posture** (2 steps): reads SMB RequireSecuritySignature, NTDS LDAPServerIntegrity and LdapEnforceChannelBinding (DC only; values read, nothing changed). Counts 4776 NTLM validation events in the last hour. Posture is never PASS. Visibility PASS proves logging only.
- **ad-forced-auth-attempt** (1 step): one Test-Path to an unresolvable `.invalid` UNC. No SMB session, no credential sent, no listener or relay. Detection verdict is not set by the probe; it needs the Sysmon or EDR record checked for the run ID.
- Verified offline: schema, PowerShell parse, signatures (verify-all ok=245 fail=0), step-contract ledger (no removals), tests pass.
- Not verified: neither scenario has run on a host. The forced-auth detection needs a Sysmon or EDR check on the run ID.

### ad-forced-auth-attempt on the lab VM, 2026-11-18 (partial)

- Host: `WIN-2IP8FNO4MAD` (member server). Sysmon: not installed (`Get-Service Sysmon64,Sysmon` empty).
- Probe run `ff31418d`: `EXEC T1187: outbound UNC check to \bas-sim-fa-ff31418d.invalid\share. reached=False (expected False).`
- DNS client log (enabled on this VM for the check) recorded the lookup for `bas-sim-fa-ff31418d.invalid` at 12:12:21 AM, server response status 9003 (name not found).
- **Verified:** the name lookup reached the DNS client and server.
- **Not observed:** no outbound SMB attempt. The name never resolved, so Windows did not open an SMB connection. The step's Sysmon EID 3 telemetry does not apply to this run.
- **Not checked:** alerting. Nothing on the lab reads DNS or SMB events for alerts.
- Status: lookup-level only. Not detection-verified.
- Open: decide whether to turn the DNS client log back off (`wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:false`).

### ad-ntlm-relay-posture run on the DC, 2026-11-18

- DC: `WIN-TQ70FGLETIU`, DomainRole 4 or 5 (ran).
- Output:
  ```
  EXEC T1557.001: SMB RequireSecuritySignature=True; LDAPServerIntegrity=1 (2 = required); LdapEnforceChannelBinding= (2 = always).
  SKIP: configuration observation only ...
  EXEC T1557.001: NTLM validation events (4776) in last hour = 0.
  SKIP: no 4776 events in the last hour. Inconclusive.
  ```
- Posture findings (observed, not a detection result):
  - SMB signing is required. Relay to SMB is blocked by configuration.
  - LDAP signing is negotiated but not required (`LDAPServerIntegrity=1`). LDAP relay is not blocked by configuration. This is a gap.
  - LDAP channel binding is not set on the DC.
- 4776 count of 0: consistent with no NTLM validations in the window. The earlier spray used Kerberos-based validation. Credential Validation auditing was `Success` at the last check. Not a logging fault.
- Status: posture recorded. No detection verdict. Relay detection is not verified.

### LDAP signing change tested and reverted, 2026-11-18

- Set `LDAPServerIntegrity` to `2` on `WIN-TQ70FGLETIU`, verified it read `2`, then set it back to `1`.
- Current state: `LDAPServerIntegrity=1` (signing negotiated, not required). **Open gap:** LDAP relay is not blocked by configuration.
- Decision: leave as is. Channel binding remains unset.
- The posture re-run after a change was not done, since the value was reverted.

### ad-forced-auth-attempt: Sysmon telemetry on the lab VM, 2026-11-18

- Sysmon64 installed on `WIN-2IP8FNO4MAD` with a minimal config (DnsQuery and NetworkConnect, both `onmatch="exclude"`, meaning log all). Service Running.
- Probe run `741f6602`: `reached=False`.
- Sysmon EID 22 recorded `QueryName: bas-sim-fa-741f6602.invalid` at 12:43:57 AM. **Image: `C:\Windows\System32\svchost.exe`.**
- **Finding:** the lookup is attributed to the DNS Client service (svchost), not to the PowerShell process that started it. A rule that matches on the image name alone would miss this. Linking the query to PowerShell needs the parent process or the time window.
- No SMB attempt, as expected for an unresolvable name. Sysmon EID 3 is not expected.
- Status: DNS lookup verified with process attribution, to svchost. **Alerting still not checked**; no SIEM or EDR rule was read. Detection not verified.

### ad-pass-the-hash-telemetry (T1550.002), 2026-11-18

- Scope: detection-visibility only. No NT hash is read, created, or used, and no authentication is attempted. Building a real pass-the-hash emulation needs a hash-using tool, which is an attack primitive and was not built.
- Step 1 (posture, any host): reads LmCompatibilityLevel, RestrictSendingNTLMTraffic, RestrictReceivingNTLMTraffic. Never PASS.
- Step 2 (DC): counts 4624 network logons (type 3, NTLM package) and 4776 validations in the last 30 minutes. PASS proves logging only.
- Verified offline: schema, PowerShell parse, signature (verify-all ok=248 fail=0), ledger (no removals), tests pass.
- Not verified: not run on the DC. Pass-the-hash alerting is not checked.

### ad-pass-the-hash-telemetry run on the DC, 2026-11-18

- Posture (step 1): `LmCompatibilityLevel`, `RestrictSendingNTLMTraffic` and `RestrictReceivingNTLMTraffic` are all **not defined** on `WIN-TQ70FGLETIU`. NTLM is not restricted by configuration, so pass-the-hash is not blocked by policy. Observation only, no verdict.
- Telemetry (step 2): 0 NTLM network logons (4624, type 3) and 0 NTLM validations (4776) in the last 30 minutes. SKIP, inconclusive: no NTLM activity occurred in that window, so logging could not be shown.
- Status: not detection-verified. Telemetry visibility not yet demonstrated, because the probe needs NTLM activity in the window.
- Open: generate NTLM logon events to show visibility. That needs a logon for a synthetic account, which needs a known synthetic password. Not done; awaiting decision.
