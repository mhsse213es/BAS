# AD CS mastery scenario: QA log

Scenario: `scenarios/adcs-esc-template-exposure-audit.yaml` (generated; never edit by hand).
Source: `orchestrator/internal/adcsaudit/` (`lib.ps1`, `gen.go`) and `orchestrator/cmd/gen-adcs-scenario`.
Regenerate: `cd orchestrator && go run ./cmd/gen-adcs-scenario ../scenarios/adcs-esc-template-exposure-audit.yaml`, then re-sign with `scripts/signer.go`.

## What it is

18 read-only stages: 0 context, 1-15 one per ESC, 16 publication and trust, 17 correlation. Findings carry a state:
confirmed, path (exploitable issuance path), potential (needs live verification), insufficient (could not be read).
A stage PASSes only when every source it needs was read and nothing was found. Potential or insufficient evidence is
SKIP, never PASS. Every finding line is `low-privileged principal -> right -> object -> conditions -> impact`.
Nothing requests a certificate or changes a template, CA object, CA setting or registry value.

## Verified (offline)

- Analyzer logic: 60-plus fixture cases (`internal/adcsaudit/adcsaudit_test.go`), run through real PowerShell: each ESC
  vulnerable / mitigated / unreadable, deny ACEs, tier-0-only enrollment, manager approval, RA signature, unread sources.
- Correlation: published vs unpublished template, CA-level flag with and without a reachable template, clean, unread source.
- Off-domain host: every stage returns SKIP (never PASS) in about a second.
- Generation deterministic and matches the committed file; static check that no write or certificate-request command appears.
- Step-contract ledger regenerated; baseline gained only a zero-gap entry for the ESC8 probe file.

## NOT verified

- The collectors (LDAP template and PKI ACL reads, `certutil -getreg`, remote registry for CA security and DC mapping,
  altSecurityIdentities search, NTAuth certificate parsing, the ESC8 HTTP probe) have never run against a real AD CS
  environment. This build host is not domain joined. Needs a lab run before any maturity claim.
- Per-ESC limits stated by the scenario: CA enrollment-agent restrictions (ESC3), the CA patch level (ESC15), the DC
  2025 binding-update level (ESC10), HSM assurance (ESC12), HTTPS Extended Protection (ESC8) are not readable here.
- ESC8 is POTENTIAL unless `BAS_ADCS_LIVE_PROBE=true`, so stage 17 cannot PASS without the probe.
- Detection and telemetry text in each step is expectation, not confirmed against a SIEM.

## Leaner steps and ESC15 wording (follow-up)

- Each step now carries only the collectors it uses. The live web probe is in stages 0, 8 and 17 only; `certutil` only in
  stages 0, 6, 11, 12 and 17. Each stage asks for exactly the CA fields it reads, and an unrequested field is null, which
  an analyzer reports as unreadable, not clean. Total command size fell from 372 KB to 264 KB. `TestStagesCarryOnlyTheCollectorsTheyUse` enforces it.
- ESC15 is always at most potential, and says so: exploitability depends on the CA patch level (CVE-2024-49019), which the
  step does not read. `TestEsc15WordingNamesThePatchDependency` pins the wording.
- Correction to an earlier note: the old ESC15 step did have a FAIL path; ESC10, ESC11 and ESC13 were the SKIP-heavy ones.

## Patch-level checks for ESC10 and ESC15

Both stages now read the host's Windows build (CurrentBuildNumber and UBR, remote registry) and compare it with Microsoft's
published numbers. A build that cannot be read, or is not in the table, is unknown and stays "potential", never clean.
Tables live in `lib.ps1` (`$script:AdcsFixBuilds`) and are pinned by `TestFixedBuildTable`.

ESC15, CVE-2024-49019 fixed builds (Microsoft CSAF data as mirrored by CIRCL, https://cvepremium.circl.lu/vuln/msrc_cve-2024-49019;
KBs agree with Rapid7): Server 2016 14393.7515 (KB5046612), 2019 17763.6532 (KB5046615), 2022 20348.2849 (KB5046616),
2022 23H2 Core 25398.1251 (KB5046618), 2025 26100.2314 (KB5046617). Hotpatch baselines 20348.2819 and 26100.2240 are already
fixed, so a revision between the baseline and the fixed build is reported unknown, not vulnerable. Server 2012, 2012 R2,
2008 and 2008 R2 are in the advisory but their revision is not readable as UBR, so they stay potential.

ESC10, KB5014754 (https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16):
Full Enforcement from February 11, 2025; the StrongCertificateBindingEnforcement opt-out is no longer honored from the
September 9, 2025 update. September 9, 2025 builds (Microsoft KB titles): Server 2016 14393.8422 (KB5065427), 2019 17763.7792
(KB5065428), 2022 20348.4171 (KB5065432). Only these three are matched because the KB5014754 page lists them (and 2012 R2,
2012, 2008, whose builds are not matched). Server 2022 23H2 (25398.1849, KB5065425) and 2025 (26100.6584, KB5065426) were
found but are not on that page's "Applies to" list, so they are not used. On a matched build at or above the update, a weak
registry value is ignored; the Schannel CertificateMappingMethods UPN bit (0x4) is a separate setting and still counts.
Below it, StrongCertificateBindingEnforcement=0 is confirmed and 1 (compatibility) is potential.

Not verified: the numbers were taken from search results and Microsoft pages, not from running updates on hosts; the
Microsoft Security Response Center page for CVE-2024-49019 was not read directly; the remote-registry build read has not run
against a real CA or DC.

## Open

- `adcs-esc8-web-enrollment-probe.yaml` was removed; stage 8 replaces it. Behaviour change: the old scenario sent its one unauthenticated HTTP GET by default, stage 8 only with `BAS_ADCS_LIVE_PROBE=true`.
- Not deployed; the console has not been checked against the new step list.
