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
