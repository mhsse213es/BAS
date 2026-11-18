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
