# Endpoint Mastery 04 — Credential Theft Simulation: QA log

Scenario: `scenarios/endpoint-mastery/em-04-credential-theft.yaml` (signed, `.sig` alongside)
Steps: 44, nine categories. Read-only checks and access-control probes. No credential is read, dumped, extracted or displayed.

## Scope and design

The three original steps were replaced rather than kept verbatim, because their logic was wrong:

| Original | Problem | Now |
|---|---|---|
| LSASS handle with `PROCESS_VM_READ` (0x1010), PASS on denial credited to RunAsPPL/Credential Guard | Denial was treated as proof of a protection control. 0x1010 also requests more rights than needed. | Step 1 requests `PROCESS_VM_READ` (0x0010) only, closes the handle, and reports denial as an access-control result without attributing a cause. Protection is assessed by separate RunAsPPL, Credential Guard and ASR checks. |
| `Get-Item HKLM:\SAM\SAM` readability | Overclaimed that hashes were extractable. Read existence only. | Steps 18–21: ACL checks on the SAM account database and SECURITY, plus read-only open probes that read no values. |
| DPAPI `$env:APPDATA\Microsoft\Protect` enumeration, `-Recurced` typo | Typo; enumeration result was not evaluated. | Steps 23–27: ACL and owner checks, file count only (contents never read). |

Verdict rules: PASS = control effective or access denied. FAIL = control missing or access granted. SKIP = not applicable or not assessable here, with a reason, not scored. ERROR = the check could not complete.

Environmental and policy limits are reported as SKIP with `NOT_ASSESSED` and are not scored. These include domain-side properties (Protected Users, DPAPI domain backup key, privileged-account storage), settings not configured by policy (DisableDomainCreds), and checks that need a domain-joined or Sysmon-equipped host.

## Test run — this client (not the server)

- Host: DESKTOP-5TVEBSI (WORKGROUP, not domain-joined), Windows 10 Pro 19045, PowerShell 5.1, elevated.
- Runner: `scripts/em01/em01_readonly_run.ps1` from the EM-01 branch, with `em-04-steps.json` exported from the signed YAML (source sha256 `cde79b9a…b848`).
- Run 3 (final): **20 PASS, 13 FAIL, 11 SKIP, 0 ERROR, 0 NO_VERDICT, 0 TIMEOUT.**

Two earlier runs were used to fix checks, not as evidence:
- Run 1: 17 PASS, 16 FAIL, 11 SKIP. Steps 18 and 24 flagged `BUILTIN\Users` on the SAM root and the system DPAPI folder. Inspection showed both are Windows defaults (`ReadKey` on the SAM root, inherited read on Protect). Step 18 was moved to the SAM account database and step 24 now flags only write or modify grants to broad principals.
- Run 2: step 15 flagged the stored `""` value. The Security Packages value is a single empty entry, the Windows default. The check now strips quotes before comparison.

## Verdicts that need owner attention

- **Step 1 (LSASS PROCESS_VM_READ probe): FAIL.** A read handle to lsass.exe was granted to this elevated context. This is an access-control result on this host. The step does not read memory.
- **RunAsPPL absent, Credential Guard not running and not configured, VBS running, Secure Boot disabled.** These are real configuration gaps on this client and are FAIL, not SKIP. Secure Boot disabled is consistent with the earlier BIOS note in the EM-01 log.
- **Credential Manager: 15 stored credentials.** FAIL. Only the count is reported. Targets and account names are not displayed; the owner should review them.
- **NTLM (LmCompatibilityLevel unset) and RestrictAnonymous=0.** FAIL. Both are Windows defaults that permit legacy behaviour.
- **Process creation auditing and PowerShell script block logging off.** FAIL. Detection gaps, not protection failures.

## SKIPs and why (not scored)

- Domain-only: cached domain logons (host not domain-joined), Protected Users, DPAPI domain backup key, privileged-account storage.
- Not configured: Kerberos SupportedEncryptionTypes (default applies), DisableDomainCreds, Sysmon not deployed (steps 07, 40).
- No data: RC4 ticket check (no 4769 events in 24 hours or Security log not readable), no DPAPI master-key files for this user.
- Credential Guard configuration vs runtime: neither configured nor running on this host, so not assessed here. This is not evidence that Credential Guard is absent.

## Limits and what was not verified

- Not run on the server (Windows Server 2019). Server Credential Guard, RunAsPPL and Sysmon results need a server run.
- Not lab-verified against an attack. These checks are configuration and access-control evidence only; no credential-access technique was executed.
- The LSASS handle probe result depends on the caller's privilege. A non-elevated run SKIPs.
- Step 1 and any PASS/FAIL that depends on Sysmon, the Security log or Defender are only as reliable as those sources on the target.

## Changes in this branch

- `scenarios/endpoint-mastery/em-04-credential-theft.yaml` — rewritten (44 steps).
- `scenarios/endpoint-mastery/em-04-credential-theft.yaml.sig` — re-signed.
- `orchestrator/internal/scenario/testdata/step_contract_ledger.json` — em-04 rows only (old SAM technique row replaced). `TestStepContract` passes; full package passes.
- `docs/endpoint-mastery-04-qa-log.md` — this log.

## Server run — WIN-2IP8FNO4MAD (Windows Server 2019 Standard Evaluation, lab.local, domain-joined)

- Run at 2026-11-20 21:08 -08:00, elevated, PowerShell 5.1.17763. Source sha256 `cde79b9a…b848` (matches commit).
- Output: `out\results.csv`, `out\results.json`, `out\summary.txt`.
- Counts: **PASS 25, FAIL 11, SKIP 7, NO_VERDICT 1, ERROR 0, TIMEOUT 0.**

FAIL (scored): 02 RunAsPPL not configured (0); 03 Credential Guard not running; 04 LsaCfgFlags absent; 06 LSASS ASR rule in Audit (action 2), not Block; 07 Sysmon running but no EID 10 in 7 days; 09 Credential Guard not in SecurityServicesConfigured; 17 unexpected notification package `rassfm`; 28 one stored Credential Manager credential; 31 cached domain logons 10 (threshold 2, recommended default); 38 LmCompatibilityLevel not set; 39 RestrictAnonymous 0.

**Open items on this run:**
- **Step 05 — NO_VERDICT** ("An error occurred while creating the pipeline", exit 1). Not a check result. The same command ran cleanly on the client (SKIP, neither configured nor running). Not reproduced locally. Treat as a transient runner error and re-run the full set; a repeat would need investigation.
- **Step 00 — PASS on denial is not attributable.** The `PROCESS_VM_READ` request was denied (Win32 error 5) with RunAsPPL=0 and Credential Guard not running. The denial is therefore not evidence of LSASS protection. On the client the same probe was GRANTED. The cause on the server is unknown (candidates: token privilege state, a third-party process-protection driver). Per the design, this step reports the denial without crediting a control; the PASS should not be read as "protected".
- **Step 17 — `rassfm` in notification packages.** Flagged as unexpected. It is a Remote Access notification package that can be present by default on Server installs. Owner should confirm whether RAS is installed before treating this as a finding.
- Steps 05 and 17 need owner or re-run confirmation before the server counts are final.

## Server re-run (out2) and follow-up checks — WIN-2IP8FNO4MAD, 2026-11-20 21:24 -08:00

- Counts: **PASS 25, FAIL 11, SKIP 8, NO_VERDICT 0, ERROR 0.**
- Step 05: now SKIP (CG neither configured nor running). The earlier NO_VERDICT was a transient runner error; it did not reproduce.
- Step 00 (LSASS probe): PASS (denied, Win32 error 5) again. `whoami /priv` in the same elevated shell shows SeDebugPrivilege **Enabled**, so the denial is not caused by missing debug privilege. Process-handle restriction is present on the server; its source is NOT yet attributed. Visible minifilters: SysmonDrv, WdFilter, mfehidk (Trellix), hdlpflt and others. Running Trellix services: masvc, mfemms, mfevtp, mfewc, TrellixDLPAgentService. A process-handle callback is not visible through `fltmc`, so attribution needs Trellix configuration or a vendor check. Step 00 still reports the denial without crediting any control.
- Step 17 (`rassfm`): Remote Access role is **Available, not Installed**; RasMan (Remote Access Connection Manager) is Running (Automatic); RemoteAccess service Stopped/Disabled. `rassfm` is a Windows Remote Access component that the RasMan service uses, not a RRAS role. Notification packages on the server: `rassfm`, `scecli`. Pending: confirm the DLL is Microsoft-signed (`Get-AuthenticodeSignature C:\Windows\System32\rassfm.dll`) before deciding whether it's an accepted default.

## Owner-approved change: step 17 (notification packages) and step 00 (SeDebugPrivilege)

- Step 00: the probe enables SeDebugPrivilege before requesting the handle; SKIP if it cannot. Commit 879fe015. Server run out3 used the pre-change file (header hash cde79b9a…), so it does not count as the step 00 result. Re-run needed with the new file.
- Step 17: `rassfm` is accepted only when `System32\rassfm.dll` has a valid signature from Microsoft Corporation (the server check showed exactly that). scecli remains the only other expected package. Any other unexpected package still FAILs. Commit 21913b19. Not exercised on the client, which has no rassfm.dll.
- Expected header for the next server run: Source sha256 b02ad3f3c83704497e04991374b841f5206867e41594390992bd3990a614c7ce.

## Final server run (out6) — WIN-2IP8FNO4MAD, 2026-11-20 22:00 -08:00

- Source sha256 b02ad3f3c83704497e04991374b841f5206867e41594390992bd3990a614c7ce (matches HEAD at the time of the run).
- Counts: **PASS 26, FAIL 10, SKIP 8, NO_VERDICT 0, ERROR 0.**
- Step 00: PASS, handle DENIED with SeDebugPrivilege enabled (Win32 error 5). Access-control result only. The cause is still not attributed; visible candidates are the Trellix stack (mfehidk minifilter and services masvc, mfemms, mfevtp, mfewc, TrellixDLPAgentService). Attribution needs Trellix configuration.
- Step 17: PASS. Observed rassfm, scecli; rassfm accepted as a Microsoft-signed OS component (Microsoft Corporation, valid signature). This is an owner-approved exception.
- FAIL (scored): 02 RunAsPPL not configured; 03 Credential Guard not running; 04 LsaCfgFlags absent; 06 LSASS ASR rule in Audit; 07 Sysmon no EID 10 in 7 days; 09 CG not in SecurityServicesConfigured; 28 one stored Credential Manager credential; 31 cached domain logons 10 (threshold 2); 38 LmCompatibilityLevel unset; 39 RestrictAnonymous 0.
- SKIP: 05 (CG neither configured nor running), 25, 27, 29, 30, 33, 34, 35 (domain-only, no data, or not configured).
- Runner errors seen across server runs: "An error occurred while creating the pipeline" (exit 1) for step 05 (out) and step 17 (out5). Both cleared on the next full run, and the standalone run of step 17 passed. Treated as transient runner errors; not reproduced locally.

## Final client run (client-final) — DESKTOP-5TVEBSI, 2026-11-21 11:40 +05:30

- Source sha256 cde… is the pre-change file; the final file's hash is b02ad3f3c83704497e04991374b841f5206867e41594390992bd3990a614c7ce.
- Counts: **PASS 20, FAIL 13, SKIP 11, NO_VERDICT 0, ERROR 0.**
- Step 00: FAIL. The handle was GRANTED with SeDebugPrivilege enabled. On this client RunAsPPL is absent and Credential Guard is not running, so the grant is consistent with no LSASS protection.
- Step 17: PASS (only scecli observed; no rassfm on this client, so the accept branch was not exercised).
- Client and server results differ as expected: server denies the handle (step 00 PASS), client grants it (step 00 FAIL). Neither is attributed yet.
