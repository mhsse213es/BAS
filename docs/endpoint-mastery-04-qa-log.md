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
