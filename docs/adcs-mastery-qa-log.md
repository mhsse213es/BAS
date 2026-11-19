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

## Code review (high effort, run after implementation) and what changed

A review of commits `7c1bab28~1..6df1b427` found these; each was checked against the code before fixing.

Fixed:
- **certutil config lost its backslash** (`host` + `CAName` instead of `host\CAName`). ESC6, ESC11 and ESC12 could never read a CA,
  so they always SKIPped. The offline fixtures bypass the collectors, so nothing caught it. Now covered by
  `TestCollectorUsesHostBackslashCaNameForCertutil` (mocked certutil; verified to fail when the bug is put back).
- **ESC1/ESC15 missed the enrollee-supplied-SAN flag** (0x10000). `SuppliesSubject` now counts 0x1 or 0x10000. This is my
  judgement from the reviewer's point (a requester-supplied SAN is what ESC1 abuses); lab-confirm against Certipy/Locksmith.
- **ESC12 was a confirmed FAIL for every software key provider**, inflating failures. Now "potential" (posture, not scored),
  and excluded from the correlation verdict.
- **Stage 17 could never PASS by default** because ESC8 is "potential" without the live probe. ESC8 is now left out of the
  correlation verdict unless the probe ran, and the stage prints that ESC8 was not assessed.
- **ESC8 treated "nothing listens on HTTP" as unreadable.** A refused connection is now clean for the HTTP endpoint; a
  timeout stays insufficient. HTTPS-only web enrollment is still not assessed.
- **ESC6 correlation attributed a path to the wrong CA** (first reachable template on any CA). Now only templates published on
  the CA that has the flag count.
- **NTAuth read failed on ECDSA CA certificates** (PublicKey.Key throws on PowerShell 5.1). Per-certificate, RSA/ECDSA-aware.
- **Template and PKI object owners were ignored.** The owner holds an implicit WriteDacl, so a non-tier-0 owner is now a writer.
- **Slow or unreachable hosts:** a short TCP check precedes each SMB registry read; one registry connection per DC (it was
  two); keys are closed; the domain-join check and enrollment services are cached within a run.
- **Dead `Stage.Tag`:** `TestStageTagsAreEmitted` now ties it to the code.

Not changed (decided, with reason):
- ACEs granting WriteProperty on a *specific* property GUID still count as writers. Without a schema lookup we cannot tell a
  harmless attribute from a dangerous one (for example the template name-flag), so we stay conservative.

## First lab run (lab.local, 2026-11-16) and what it changed

Run by hand with the extracted stage scripts as `labdministrator` against one CA/DC host (Windows Server 2022 Standard
Evaluation, 20348.587, `WIN-TQ70FGLETIU`, CA `LAB-CA`).

Verified against a real environment: LDAP template and CA reads (33 templates, 11 published, no unreadable ACLs); CA edit
flags, interface flags and key provider through `certutil` (the backslash fix held); CA security descriptor; remote-registry
build read; every stage finished in 0.5-2.3 s. Stage 9 crashed once in the runner ("An error occurred while creating the
pipeline", 0.5 s); run on its own it returned PASS, so it is recorded as an unreproduced one-off, not a code defect.

Finding: stage 10 (and so stage 17) returned SKIP because the DC's StrongCertificateBindingEnforcement was unset and the
build was not matched to a threshold. The DC was 20348.587, below the May 10, 2022 update (KB5013944, 20348.707), so it has no
strong certificate mapping at all. Added a `may2022` threshold (Server 2022 only) and a confirmed finding below it, with
four fixtures. Basis and limits: Microsoft's KB5013944 page gives the build; the KB5014754 page ties the changes to "the May
10, 2022 update" but names no KB for Server 2022, so matching them is an inference by date. Server 2016 and 2019 builds are not
stated on the page and are not matched. The pre-update KDC behaviour is not described on the page; "maps by UPN or SAN alone"
is general knowledge, not taken from it.

Second finding: stage 17 said "exploitable certificate-issuance path" while its own count line said 0 paths (only the DC
finding was confirmed). The FAIL sentence now says a confirmed misconfiguration is present but no complete issuance path was
established unless a finding is in the `path` state. Two fixtures cover both wordings.

Still NOT shown by this run: every PASS (stages 1-7, 9, 11, 13-16) is consistent with a clean lab and with a collector that
cannot see a defect. A deliberately vulnerable template (ESC1) or a cross-check with an independent read-only tool is
needed before claiming detection. Stage 8 was not probed (live probe off).

## Lab controls (same lab, run by the user; outputs reviewed)

Repeatable steps: `docs/adcs-lab-validation-runbook.md`.

Each control changed the lab CA or a test template by hand, was detected by the stage, and was reverted; the stage was then
re-run. Evidence is the pasted stage output, not a SIEM or a certificate request (nothing was requested).

| ESC | Weakness introduced | With weakness | After revert |
|---|---|---|---|
| ESC1 | test template, enrollee-supplied subject, client-auth EKU, Domain Users enroll | stage 1 FAIL, path names Domain Users and template | stage 1 PASS |
| ESC4 | test template, Domain Users Write | stage 4 FAIL; stage 17 latent (potential) while unpublished, path once published | stage 4 PASS |
| ESC6 | `EDITF_ATTRIBUTESUBJECTALTNAME2` set (`11014e` to `15014e`) | stage 6 FAIL; stage 17 path via published template Machine | stage 6 PASS, value back to `11014e` |
| ESC7 | Domain Users granted Manage this CA | stage 7 FAIL, `Domain Users -> ManageCA -> CA LAB-CA`; stage 17 path | stage 7 PASS |
| ESC2 | test template, Any Purpose EKU, Domain Users enroll | stage 2 FAIL (confirmed, unpublished) | stage PASS |
| ESC3 | agent template plus a template requiring an agent signature | stage 3 FAIL confirmed; with only the agent template, SKIP (potential) | stage PASS |
| ESC9 | test template with the no-security-extension flag (0x80000) | stage 9 FAIL (confirmed, unpublished) | stage PASS |
| ESC11 | `IF_ENFORCEENCRYPTICERTREQUEST` cleared | stage 11 FAIL; stage 17 FAIL with the no-path wording (live) | stage 11 PASS |
| ESC10 | none added (real DC at 20348.587) | stage 10 FAIL, then stage 17 | not applicable |
| ESC5 | Domain Users given Write on the `AIA` container under Public Key Services | stage 5 FAIL, confirmed, Domain Users -> Write -> PKI object AIA | `dsacls /R` removed it; stage PASS |
| ESC13 | unpublished template `ZZ-BAS-ESC13-Test` (Domain Users Enroll) carrying issuance policy `ZZ-BAS-ESC13-Policy`, linked by `msDS-OIDToGroupLink` to a stand-in group with `adminCount=1` | stage 13 FAIL, confirmed, "(not published on any CA)", 0 paths | link cleared; stage PASS |

| ESC14 | test user with `altSecurityIdentities` = `X509:<RFC822>...` | stage 14 FAIL, confirmed, weak mapping on the account | strong mapping (`<I>...<SR>...`) then user deleted; stage PASS (one PASS pasted, not labelled which step) |
| ESC15 | unpublished test template, schema version forced to 1 by LDAP write, subject supplied, Domain Users Enroll | stage 15 SKIP, `potential`, "latent" (unpublished) | **partial**: published case (expect confirmed on build 20348.587) and cleanup runs not reported |

Notes: ESC15 was stopped by the user after the unpublished run. The `confirmed` branch (a CA below the CVE-2024-49019 build publishes the template) was not shown live, and the cleanup of `ZZ-BAS-ESC15-Test` was not confirmed. The same run found that the stage 15 headline said "CA build checked" for an unpublished template; fixed in `c480761e`. ESC8 live probe, stage 16 and the Locksmith comparison were not run.

Notes: the ESC13 group was a stand-in with `adminCount=1`, not a real tier-0 group. The post-cleanup stage 13 run (template, policy, group deleted) was not yet reported when this was written.

Notes: the ESC6 control was set in the registry and not restarted before the first read; the scenario reads the value, not
the running service state, and does not say so in its wording. The ESC4 path text lists all write rights rather than the
one the ACE holds.

Still not shown to find anything in a real environment: ESC15 (confirmed branch), stage 16 (publication and trust) and
the ESC8 live probe. Their only live result is "reads real data, finds nothing on a clean lab". The Locksmith cross-check was
not run.

## Open

- `adcs-esc8-web-enrollment-probe.yaml` was removed; stage 8 replaces it. Behaviour change: the old scenario sent its one unauthenticated HTTP GET by default, stage 8 only with `BAS_ADCS_LIVE_PROBE=true`.
- Not deployed; the console has not been checked against the new step list.
