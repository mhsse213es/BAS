# AD CS scenario: lab validation runbook

Internal. Not part of what a client runs. The shipped scenario (`scenarios/adcs-esc-template-exposure-audit.yaml`) is read-only.
This runbook weakens a **lab** CA on purpose, checks that the stage reports it, reverts it, and checks that the stage goes
clean. Never run it on a production or client CA. Results from the first run are in `docs/adcs-mastery-qa-log.md`.

The offline fixtures (`internal/adcsaudit`, run in CI) stay the automatic gate. This runbook is the manual pre-release check
that the collectors and the analysis agree with a real CA.

## Lab and accounts

- A domain-joined **member host** to run the stages from, and the **CA host** (the CA and DC were the same machine in the first run).
- Run the stages as a domain admin (or admin on the CA and DCs). A local account cannot do LDAP, and every stage then SKIPs.
  A plain domain user reads templates and ACLs but not the CA registry (stages 6, 7, 11, 12, 17 report unreadable, never clean).
- Make the template and CA changes on the CA host as a domain admin.

## Get the stage scripts onto the member host

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\adcs-extract-stages.ps1 -OutDir C:\temp\adcs-stages
```

Copy the folder to the member host if you extracted elsewhere. Run a stage with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\temp\adcs-stages\stage06.ps1
```

`run-all.ps1` runs stages 0-17 and saves `results-<time>.txt`. Paste commands **one per line**: a multi-line paste can arrive
in reverse order in some consoles.

## Baseline (before any change)

Run `run-all.ps1`. On a clean lab expect PASS or the documented SKIPs: stage 0 SKIP (context only), stage 8 SKIP unless
`$env:BAS_ADCS_LIVE_PROBE='true'`, stage 12 SKIP (software key provider is posture, not scored). Stage 10 FAILs on a DC below
the May 10, 2022 update (Server 2022 build 20348.707); that is a real finding, not a control.

## Rules for every control

1. Record the original value or state first.
2. Make one change at a time. Run the stage, then the correlation stage 17 where noted.
3. Revert, confirm the original value, re-run the stage, and expect PASS.
4. Keep new templates **unpublished** unless the control says otherwise. Stages 1-4 and 9 flag a template whether or not it is
   published; publishing only changes stage 17 (published: `path`, unpublished: `potential`).

## ESC1: enrollee-supplied subject

Change (CA host, `certtmpl.msc`): duplicate **User** (Windows Server 2016 compatibility), name `ZZ-BAS-ESC1-Test`, untick
Publish certificate in Active Directory. Subject Name tab: **Supply in the request**. Keep Client Authentication. Issuance
Requirements: nothing ticked. Security: Domain Users **Enroll**. To also see a path in stage 17, publish it in `certsrv.msc`
(Certificate Templates, New, Certificate Template to Issue).
Stage 1: FAIL, finding for `ZZ-BAS-ESC1-Test`, path `Domain Users -> Enroll -> template ... -> request a certificate naming any identity`.
Stage 17 (published): `state=path`.
Revert: unpublish (`certsrv.msc`, Delete) then Delete Template in `certtmpl.msc`. Stage 1: PASS.

## ESC2: Any Purpose or no EKU

Change: duplicate **User**, name `ZZ-BAS-ESC2-Test`, unpublished. Extensions, Application Policies: remove every policy, add
**Any Purpose**. Security: Domain Users **Enroll**. Subject Name and Issuance Requirements at defaults.
Stage 2: FAIL, `state=confirmed`, `(not published on any CA)`.
Revert: Delete Template. Stage 2: PASS.

## ESC3: enrollment agent

Change: two unpublished templates.
- `ZZ-BAS-ESC3-Agent`: duplicate **Enrollment Agent**, add Domain Users **Enroll**.
- `ZZ-BAS-ESC3-Target`: duplicate **User**; Issuance Requirements: authorized signatures `1`, policy type **Application policy**,
  application policy **Certificate Request Agent**; Domain Users **Enroll**.
Stage 3: FAIL, `state=confirmed`, "another enrollable template accepts agent-signed requests".
Control for potential: delete only `ZZ-BAS-ESC3-Target`. Stage 3: **SKIP**, `state=potential`, "no template that accepts
agent-signed requests was found". The CA's enrollment-agent restrictions are not readable from AD, so ESC3 never reaches PASS
while an enrollable agent template exists.
Revert: delete the Agent template too. Stage 3: PASS.

## ESC4: template ACL

Change: duplicate **User**, name `ZZ-BAS-ESC4-Test`, unpublished. Security: Domain Users, tick **Write** (leave Enroll as is).
Stage 4: FAIL, `state=confirmed`, path `Domain Users -> Write ... -> template -> turn the template into an ESC1 template`.
Stage 17 unpublished: `state=potential` (latent). Published in `certsrv.msc`: `state=path`.
Revert: untick Write (or delete the template). Stage 4: PASS.

## ESC5: write access on PKI objects

Change (CA host, one line): give Domain Users Write on the AIA container, e.g.
`dsacls "CN=AIA,CN=Public Key Services,CN=Services,$cfg" /G "LAB\Domain Users:GW"` (`$cfg` = configuration naming context).
Stage 5: FAIL, `state=confirmed`, `Domain Users -> Write -> PKI object AIA`. Stage 17 does not build a path for ESC5.
Revert: `dsacls ... /R "LAB\Domain Users"`. Check: `dsacls ... | Select-String 'Domain Users'` prints nothing. Stage 5: PASS.

## ESC13: issuance policy linked to a group

Change: create universal group `ZZ-BAS-ESC13-Priv` with `adminCount=1` (stand-in for a privileged group). Duplicate **User** as
unpublished `ZZ-BAS-ESC13-Test` (Domain Users Enroll) with a new issuance policy `ZZ-BAS-ESC13-Policy`. Link the policy object
(`CN=OID,...`) to the group with `Set-ADObject $o -Replace @{'msDS-OIDToGroupLink'=<group DN>}`.
Stage 13: FAIL, `state=confirmed`, `(not published on any CA)`, 0 paths.
Revert: `Set-ADObject $o -Clear 'msDS-OIDToGroupLink'`. Stage 13: PASS. Then delete the template, the policy and the group
and run stage 13 again.

## ESC14: weak explicit certificate mapping

Change: enabled test user `ZZ-BAS-ESC14-User` (throwaway password typed at a prompt, never in chat or files);
`Set-ADUser ... -Replace @{altSecurityIdentities='X509:<RFC822>zz-bas-esc14@lab.local'}`.
Stage 14: FAIL, `state=confirmed`, "weak explicit certificate mapping". Disabled accounts are skipped, so the user must be enabled.
Control: replace with a strong mapping `X509:<I>DC=local,DC=lab,CN=LAB-CA<SR>0123456789ab`. Stage 14: PASS.
Revert: `Remove-ADUser ZZ-BAS-ESC14-User`. Stage 14: PASS.

## ESC15: schema-version-1 template with a supplied subject (partly run)

Change: duplicate **User** as unpublished `ZZ-BAS-ESC15-Test`, Subject Name **Supply in the request**, Domain Users Enroll.
`certtmpl.msc` cannot make a version 1 template, so set `msPKI-Template-Schema-Version` to 1 with an LDAP write (lab only; it
printed `1`). Unpublished, stage 15: SKIP, `state=potential`, "latent". Run live.
Not run live: publish in `certsrv.msc`, stage 15 should be FAIL, `confirmed`, "below the fixed build" on a CA under
20348.2849; stage 1 also flags it (ESC1). Revert: unpublish, delete the template, stages 15 and 1 PASS.

## ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 (CA host, elevated)

```powershell
certutil -getreg policy\EditFlags
certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
Restart-Service certsvc
```
First run: `11014e` became `15014e`. Stage 6: FAIL, confirmed on the CA. Stage 17: `state=path` through a published template
enrollable by a low-privileged principal (the first run used the published `Machine` template, Domain Computers); if none is
published it is `potential`.
Revert: `certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2`, `Restart-Service certsvc`, confirm the recorded value.
Stage 6: PASS.

## ESC7: low-privilege CA rights

Change (`certsrv.msc`): CA Properties, Security, add Domain Users with **Manage this CA**.
Stage 7: FAIL, `Domain Users -> ManageCA -> CA <name>`. Stage 17: `state=path`.
Variant: **Issue and manage certificates** (ManageCertificates), same result.
Revert: remove Domain Users from the Security tab. Stage 7: PASS. If a change does not show until `Restart-Service certsvc`,
record it; it says which security descriptor the collector reads.

## ESC9: no security extension

Change: duplicate **User**, name `ZZ-BAS-ESC9-Test`, unpublished, Domain Users **Enroll**. Set the flag (CA host, one line):

```powershell
$cfg=([adsi]'LDAP://RootDSE').configurationNamingContext; $t=[adsi]"LDAP://CN=ZZ-BAS-ESC9-Test,CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg"; $v=[int]$t.Properties['msPKI-Enrollment-Flag'].Value; $t.Properties['msPKI-Enrollment-Flag'].Value=($v -bor 0x80000); $t.CommitChanges(); $t.RefreshCache(); [Convert]::ToString([int]$t.Properties['msPKI-Enrollment-Flag'].Value,16)
```

The printed hex has the `80000` bit set. Stage 9: FAIL, `state=confirmed`.
Revert: Delete Template. Stage 9: PASS.

## ESC11: RPC encryption not enforced (CA host, elevated)

```powershell
certutil -getreg CA\InterfaceFlags
certutil -setreg CA\InterfaceFlags -IF_ENFORCEENCRYPTICERTREQUEST
Restart-Service certsvc
```
Stage 11: FAIL, confirmed on the CA. Stage 17: FAIL with **no path**; the sentence must read "a confirmed misconfiguration is
present, but no complete low-privilege issuance path ... was established" when only ESC10/ESC11 are confirmed.
Revert: `certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`, `Restart-Service certsvc`,
`certutil -getreg CA\InterfaceFlags` equals the recorded value. Stage 11: PASS.

## ESC10 and ESC12

No control is added. ESC10 is a real finding on a DC below its May 10, 2022 update (Server 2022 build below 20348.707); a
patched DC is not changed by this runbook. ESC12 reports a software key provider as `potential` (a posture note, never FAIL).

## Not covered by any control yet

ESC8 (needs `BAS_ADCS_LIVE_PROBE=true` and web enrollment installed), the ESC15 published/confirmed case, and stage 16 (publication and
trust). Their only live result so far is "reads real data, finds nothing on a clean lab". A Locksmith cross-check has not been run.

## Cleanup checklist (leave the lab as found)

- No `ZZ-BAS-*` template remains published or unpublished (`certtmpl.msc`, `certsrv.msc`).
- `certutil -getreg policy\EditFlags` and `CA\InterfaceFlags` equal the recorded values.
- LAB-CA Security tab holds no Domain Users entry for Manage CA or Issue and manage certificates.
- `run-all.ps1` is back to its baseline.

## Result status (first run, 2026-11-16 to 17, `lab.local`, Server 2022 20348.587)

| ESC | Weakness shown by the stage | Back to PASS after revert |
|---|---|---|
| 1 | yes | yes |
| 2 | yes | yes |
| 3 | yes (confirmed, and potential with one template) | yes |
| 4 | yes (latent, then path) | yes |
| 6 | yes | yes |
| 7 | yes | yes |
| 9 | yes | yes |
| 11 | yes | yes (the before and after InterfaceFlags values were not sent, so they are not recorded here) |
| 5 | yes (AIA, Domain Users Write) | yes |
| 13 | yes (stand-in `adminCount=1` group) | yes after clearing the link; post-cleanup run not yet reported |

| 14 | yes (RFC822 mapping) | yes (strong mapping, then user deleted) |
| 15 | partly: unpublished `potential` only | not run |

Eleven controls were run to a PASS after revert (ESC15 was stopped part way). The ESC11 before and after `InterfaceFlags` values were not recorded; stage 11 returned PASS after the revert.
