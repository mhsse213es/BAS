# Enterprise scenario plan: what each scenario needs to compete at enterprise level

Scope: every scenario file in `scenarios/` (113), `scenarios/detection-profiles/` (29) and `scenarios/endpoint-mastery/` (14), 156 files in all. Every file was scored on the same criteria (below). Nothing here changes a scenario, a score or a signature. This is a plan.

## What "enterprise level" has to mean here

An enterprise buyer tests a BAS product against a few concrete questions. This plan is built on these:

1. **Coverage:** does each scenario map to ATT&CK or a named control framework, and do its steps really exercise that technique?
2. **Depth:** how many variants are covered, and do they reproduce what a real intrusion looks like?
3. **Detection verification:** for each step, what should the EDR, SIEM or DLP product see, and did it see it?
4. **Evidence:** is each verdict (PASS, FAIL, ERROR, SKIPPED) backed by recorded telemetry, not by the script's own claim?
5. **Safety and reversibility:** can the buyer run it in production, and does every step clean up after itself?
6. **Reviewability:** can the buyer see exactly what will run before it runs, and is it signed?

**Parity claims:** this plan does not claim Audspect matches or beats Cymulate or any other product. Parity is a measured result from live runs against real products, and none of that has been done for these scenarios yet. Each item below says whether it can be built and checked in this repo or needs a lab.

## Criteria used for every scenario

- **Steps:** number of steps defined in the file.
- **Cleanup %:** share of steps that declare a cleanup action.
- **Detection %:** share of steps that declare what the detection should see.
- **Telemetry %:** share of steps that declare the telemetry expected.
- **MITRE mapping:** the scenario declares techniques or tactics.
- **Expansion:** steps are generated at runtime from an external library rather than written in the file.

## Inventory

- **156 files:** 113 scenarios, 29 detection profiles, 14 endpoint-mastery scenarios.
- **Executable:** 108 files. **Non-executable posture audits:** 10. Some files have no `executable` field and are counted in neither group.
- **Steps:** 636 across the 110 files that define steps.
- **Signed:** every file has a `.sig`.
- **Platforms:** 89 Windows-only, 17 Linux-only, 4 macOS-only, 2 cross-platform, and some files with no OS listed.

## Cross-cutting gaps (apply to most scenarios)

These repeat across many files, so each is fixed once, in the shared step schema or the runner.

1. **Cleanup coverage (largest gap, now measured class-aware).** Of the 517 steps in executable scenarios, 446 are non-destructive and need no cleanup. Of the 71 destructive or potentially destructive steps, 43 are gaps: 25 ART steps whose cleanup is external and unpinned, and 18 with no undo. The rest have an undo, a self-cleaning declaration, or both. Two of the 18 are ungated VSS or wbadmin deletions that need urgent review. Details are in `reports/step-contract-remediation.md` and `docs/scenario-step-contract-qa-log.md`. An earlier figure of 85 mixed non-destructive steps into the count; that figure is superseded. *Fix:* a schema rule that every mutating step declares a cleanup action, enforced by the signature gate, plus a runner check that cleanup ran. *Buildable here:* yes, the schema and validator. *Live check:* needed to prove cleanup reverses the change on a real host.
2. **Detection expectations per step.** 60% of steps declare what detection should fire. *Fix:* require it for every step a product is expected to see, linked to a detection profile. *Buildable here:* yes.
3. **Telemetry expectations.** 61% of steps. *Fix:* same approach as detection. *Buildable here:* yes.
4. **Scenario-level expected detections.** None of the 110 step-bearing files declares them at scenario level; they live only in the 29 detection profiles. *Fix:* each scenario lists the profiles it depends on, so the buyer sees the whole expected picture in one file. *Buildable here:* yes.
5. **MITRE mapping.** 18 files have no technique or tactic mapping. Most are posture audits, which should map to a control framework (CIS, RBI, CSCRF or the relevant standard) instead. *Fix:* control mappings for posture audits and ATT&CK mappings for attack scenarios. *Buildable here:* yes, but control IDs must come from the framework's own text, verified against the source document, not from memory.
6. **Runtime expansion of 16 scenarios.** The ART and Caldera wrappers, and several Linux and macOS scenarios, define no steps in the file. The steps come from the external atomics library at run time, so the buyer can't review the exact commands and they aren't covered by the signature. *Fix:* generate a frozen, reviewed step manifest for each, check it in and sign it. *Buildable here:* yes. *Live check:* the library version must be pinned.
7. **Thin scenarios.** 11 DB-simulation scenarios and several others have one or two steps. A single step is one test, not a scenario a buyer can use to see what is covered. *Fix:* expand each to the variants its technique family needs, with a benign twin where it applies, following the WAF depth work. *Buildable here:* yes, under the same safety rules.

## Plan by family

### Ransomware kill chains (13 files)
- Each stage should declare its own detection and cleanup. Today a buyer can't see which stage the product should have caught.
- Add per-stage verdicts so one scenario reports where the chain was stopped, not just pass or fail.
- Akira and Hunters International are the deepest; Clop and RansomHub are the thinnest. Start with the thinnest.
- *Lab:* encryption stages must touch only a canary directory on a lab host, never production.

### APT and BFSI kill chains (14 files)
- The same stage-level verdict and cleanup work as ransomware.
- The BFSI-specific chains (Carbanak, Cobalt, Silence, Lazarus, UPI) should each map to the relevant regulatory control, not only to ATT&CK.
- Volt Typhoon and Scattered Spider need their cross-platform and identity steps checked against the EDR coverage they claim.

### Endpoint and EDR technique scenarios (about 38 files)
- The largest group, and where variant depth matters most. Many have one to ten steps covering a single technique.
- For each technique, add the variants a real product must handle, following the WAF depth work, with a benign twin where it applies.
- Linux, macOS and Windows scenarios that expand at run time need the frozen-manifest fix (cross-cutting item 6) first, so the buyer can review them.

### Detection profiles (29 files)
- These hold the expected detection for a technique, so each must stay linked to the scenario that runs it. Check every profile is referenced by at least one executable scenario; an unreferenced profile tests nothing.
- Provider-specific rule IDs (for example Defender or Sentinel rule names) must come from the vendor's documentation, not from memory.

### Compliance and posture audits (about 20 files)
- These are read-only configuration checks. They attack nothing, so they should be scored on control evidence, not on pass or fail of an attack.
- Each should map to a named control with the framework's own ID.
- The compliance drills (CSCRF, RBI) already run as control checks. Confirm each control ID against the source framework document before a buyer sees it.

### Active Directory and identity (10 files)
- The exposure audits (ACL, ADCS, GPO, Kerberos delegation, RBCD, trust and SID history) are read-only. They should report exposure with the affected objects listed, not just a score.
- The live-verification DCSync scenario is the model: it has positive and negative controls. Apply the same pattern to the other audits.
- Any step that changes directory state needs a cleanup, which most don't have yet.

### DLP and exfiltration (17 files)
- The sink-verified channels (HTTPS, cloud storage, code repositories) already prove traffic reached the sink. Extend that verification to every channel, so a verdict never depends on the script's own claim.
- Channel coverage gaps are listed in `reports/cymulate-gap-list.md`; that list is the source and is not restated here.
- *Lab:* a live DLP product is needed to show detection, not just egress.

### Database simulation (11 files)
- Eight of the eleven have one step each. Each should cover the variants its control family needs (grants, audit, classification, revocation, bulk read), not a single probe.
- Database steps must run against a lab database only.

### Cloud, identity, email and network (5 files)
- Cloud and identity scenarios (metadata theft, Entra hybrid attack, Outlook rules) need the cleanup fix most urgently, because they change tenant or mailbox state.
- The network posture audits need control mapping.

### ART and Caldera wrappers (7 files)
- These can't be reviewed as written, so they are a supply-chain question as much as a coverage one. Freeze them into manifests as cross-cutting item 6 describes, and pin the library version.

## What cannot be verified in this repo

- Whether any step is detected by a real product. That needs a lab with EDR, SIEM and DLP, and a live run.
- Whether cleanup actually reverses the change on a real host.
- Whether the runtime expansion of the ART library matches a frozen manifest on a real host.
- Whether a control ID is correct for the customer's framework version. The text must be checked against the source document.

## Suggested order

1. **Schema and validator, no behaviour change (status: contract done on `step-contract-ratchet`).** The class-aware contract is implemented and tested; the additive `irreversible` field is in place. Still to do: review the 43-row remediation table, and decide finding 1 (ungated VSS and wbadmin steps) first. Scenario YAML is not edited, and nothing is re-signed, until those are approved.
2. **Freeze the runtime-expanded scenarios** (16 files) into reviewed, signed manifests.
3. **Add scenario-level detection links and control or ATT&CK mappings**, starting with the 18 unmapped files.
4. **Thin scenarios:** expand the DB simulations and the single-step endpoint scenarios.
5. **Kill-chain stage verdicts** for ransomware and APT chains.
6. **Lab runs** (you run these on staging), then update customer material only with measured results.

Any change that alters a customer-facing score is done separately, with a baseline recorded before and after, as agreed.

## Per-scenario table

Each row is one file. "Flags" lists what applies to it.

| Scenario | Family | Steps | Cleanup % | Detection % | Telemetry % | Flags |
|---|---|---:|---:|---:|---:|---|
| apt29-kill-chain | APT / BFSI kill chains | 5 | 60 | 100 | 100 | cleanup gap |
| apt36-kill-chain | APT / BFSI kill chains | 10 | 50 | 100 | 100 | cleanup gap |
| carbanak-kill-chain | APT / BFSI kill chains | 8 | 50 | 100 | 100 | cleanup gap |
| cobalt-group-kill-chain | APT / BFSI kill chains | 8 | 50 | 100 | 100 | cleanup gap |
| em-12-adversary-emulation | APT / BFSI kill chains | 1 | 0 | 100 | 100 | cleanup gap; thin (1-2 steps) |
| fin7-kill-chain | APT / BFSI kill chains | 5 | 20 | 100 | 100 | cleanup gap |
| fin8-kill-chain | APT / BFSI kill chains | 9 | 33 | 100 | 100 | cleanup gap |
| insider-threat-kill-chain | APT / BFSI kill chains | 3 | 33 | 100 | 100 | cleanup gap |
| lazarus-swift-heist | APT / BFSI kill chains | 9 | 22 | 22 | 22 | cleanup gap; detection gap |
| scattered-spider-kill-chain | APT / BFSI kill chains | 5 | 20 | 100 | 100 | cleanup gap |
| silence-kill-chain | APT / BFSI kill chains | 8 | 38 | 100 | 100 | cleanup gap |
| ta505-kill-chain | APT / BFSI kill chains | 9 | 56 | 100 | 100 | cleanup gap |
| upi-fraud-killchain | APT / BFSI kill chains | 9 | 22 | 100 | 100 | cleanup gap |
| volt-typhoon-lotl | APT / BFSI kill chains | 10 | 50 | 100 | 100 | cleanup gap |
| art-full-darwin | ART / Caldera expansion wrappers | 0 | - | - | - | steps expanded at runtime |
| art-full-linux | ART / Caldera expansion wrappers | 0 | - | - | - | steps expanded at runtime |
| art-full-windows | ART / Caldera expansion wrappers | 0 | - | - | - | steps expanded at runtime |
| art-selective-darwin | ART / Caldera expansion wrappers | 0 | - | - | - | steps expanded at runtime |
| art-selective-linux | ART / Caldera expansion wrappers | 0 | - | - | - | steps expanded at runtime |
| art-selective-windows | ART / Caldera expansion wrappers | 0 | - | - | - | steps expanded at runtime |
| caldera-full-windows | ART / Caldera expansion wrappers | 0 | - | - | - | steps expanded at runtime |
| acl-privilege-exposure-audit | Active Directory / identity | 6 | 0 | 83 | 83 | cleanup gap; detection gap |
| adcs-esc-template-exposure-audit | Active Directory / identity | 1 | 0 | 100 | 100 | cleanup gap; thin (1-2 steps) |
| dcsync-replication-rights-audit | Active Directory / identity | 1 | 0 | 100 | 100 | cleanup gap; thin (1-2 steps) |
| dcsync-replication-rights-live-verification | Active Directory / identity | 2 | 0 | 100 | 100 | cleanup gap; thin (1-2 steps) |
| gpo-writable-linked-exposure-audit | Active Directory / identity | 1 | 0 | 100 | 100 | cleanup gap; thin (1-2 steps) |
| kerberoasting-ad-drill | Active Directory / identity | 8 | 0 | 100 | 100 | cleanup gap |
| kerberos-delegation-exposure-audit | Active Directory / identity | 1 | 0 | 100 | 100 | cleanup gap; thin (1-2 steps) |
| purplesharp-ad-drill | Active Directory / identity | 6 | 33 | 100 | 100 | cleanup gap |
| rbcd-configure-exposure-audit | Active Directory / identity | 1 | 0 | 100 | 100 | cleanup gap; thin (1-2 steps) |
| trust-sid-history-exposure-audit | Active Directory / identity | 1 | 0 | 100 | 100 | cleanup gap; thin (1-2 steps) |
| cloud-vm-attack | Cloud / identity / email / network | 5 | 20 | 100 | 100 | cleanup gap |
| entra-hybrid-identity-attack | Cloud / identity / email / network | 6 | 0 | 67 | 67 | cleanup gap; detection gap |
| linux-network-kernel-exposure-posture | Cloud / identity / email / network | 4 | 0 | 0 | 0 | no MITRE mapping; non-executable audit; cleanup gap; detection gap |
| outlook-rules-bec | Cloud / identity / email / network | 5 | 0 | 0 | 0 | cleanup gap; detection gap |
| windows-east-west-host-firewall-posture | Cloud / identity / email / network | 1 | 0 | 0 | 0 | no MITRE mapping; non-executable audit; cleanup gap; detection gap; thin (1-2 steps) |
| cis-ubuntu-l1 | Compliance, hardening and posture audits | 38 | 0 | 0 | 0 | no MITRE mapping; cleanup gap; detection gap |
| cscrf-mii-drill | Compliance, hardening and posture audits | 9 | 22 | 100 | 100 | cleanup gap |
| full-scan | Compliance, hardening and posture audits | 25 | 0 | 0 | 0 | cleanup gap; detection gap |
| linux-account-privilege-posture | Compliance, hardening and posture audits | 3 | 0 | 0 | 0 | no MITRE mapping; non-executable audit; cleanup gap; detection gap |
| linux-audit-logging-posture | Compliance, hardening and posture audits | 2 | 0 | 0 | 0 | no MITRE mapping; non-executable audit; cleanup gap; detection gap; thin (1-2 steps) |
| linux-installed-software | Compliance, hardening and posture audits | 1 | 0 | 0 | 0 | no MITRE mapping; cleanup gap; detection gap; thin (1-2 steps) |
| linux-patch-posture | Compliance, hardening and posture audits | 2 | 0 | 0 | 0 | no MITRE mapping; cleanup gap; detection gap; thin (1-2 steps) |
| linux-ssh-hardening-posture | Compliance, hardening and posture audits | 4 | 0 | 0 | 0 | no MITRE mapping; non-executable audit; cleanup gap; detection gap |
| rbi-cscf-drill | Compliance, hardening and posture audits | 9 | 0 | 0 | 0 | no MITRE mapping; cleanup gap; detection gap |
| safe-simulation | Compliance, hardening and posture audits | 0 | - | - | - | - |
| ubuntu-hardening-validation | Compliance, hardening and posture audits | 28 | 21 | 29 | 29 | cleanup gap; detection gap |
| windows-backup-posture | Compliance, hardening and posture audits | 3 | 0 | 0 | 0 | no MITRE mapping; non-executable audit; cleanup gap; detection gap |
| windows-credential-protection-posture | Compliance, hardening and posture audits | 4 | 0 | 0 | 0 | no MITRE mapping; non-executable audit; cleanup gap; detection gap |
| windows-detection-prerequisites-posture | Compliance, hardening and posture audits | 4 | 0 | 0 | 0 | no MITRE mapping; non-executable audit; cleanup gap; detection gap |
| windows-execution-control-posture | Compliance, hardening and posture audits | 3 | 0 | 0 | 0 | no MITRE mapping; non-executable audit; cleanup gap; detection gap |
| windows-installed-software | Compliance, hardening and posture audits | 1 | 0 | 0 | 0 | no MITRE mapping; cleanup gap; detection gap; thin (1-2 steps) |
| windows-patch-posture | Compliance, hardening and posture audits | 1 | 0 | 0 | 0 | no MITRE mapping; cleanup gap; detection gap; thin (1-2 steps) |
| windows-persistence-posture | Compliance, hardening and posture audits | 4 | 0 | 0 | 0 | no MITRE mapping; non-executable audit; cleanup gap; detection gap |
| windows-security-config | Compliance, hardening and posture audits | 10 | 0 | 0 | 0 | no MITRE mapping; cleanup gap; detection gap |
| windows_rdp_nla_posture | Detection profile | 0 | - | - | - | detection profile (no steps) |
| collection-staging-exfil | DLP / exfiltration | 10 | 60 | 100 | 100 | cleanup gap |
| dlp-exfiltration-ai-prompt | DLP / exfiltration | 4 | 0 | 100 | 100 | cleanup gap |
| dlp-exfiltration-browser-upload | DLP / exfiltration | 1 | 0 | 100 | 100 | cleanup gap; thin (1-2 steps) |
| dlp-exfiltration-cloud-storage | DLP / exfiltration | 11 | 0 | 100 | 100 | cleanup gap |
| dlp-exfiltration-coderepo | DLP / exfiltration | 6 | 0 | 100 | 100 | cleanup gap |
| dlp-exfiltration-data-types | DLP / exfiltration | 7 | 0 | 100 | 100 | cleanup gap |
| dlp-exfiltration-db-export | DLP / exfiltration | 4 | 0 | 100 | 100 | cleanup gap |
| dlp-exfiltration-dns-tunnel | DLP / exfiltration | 4 | 0 | 100 | 100 | cleanup gap |
| dlp-exfiltration-file-carriers | DLP / exfiltration | 7 | 0 | 100 | 100 | cleanup gap |
| dlp-exfiltration-multichannel | DLP / exfiltration | 9 | 0 | 100 | 100 | cleanup gap |
| dlp-exfiltration-sftp | DLP / exfiltration | 6 | 0 | 100 | 100 | cleanup gap |
| dlp-exfiltration-sink-https | DLP / exfiltration | 6 | 0 | 100 | 100 | cleanup gap |
| dlp-exfiltration-smtp | DLP / exfiltration | 6 | 0 | 100 | 100 | cleanup gap |
| dlp-exfiltration-telnet | DLP / exfiltration | 4 | 0 | 100 | 100 | cleanup gap |
| dlp-exfiltration-validation | DLP / exfiltration | 5 | 0 | 100 | 100 | cleanup gap |
| dlp-exfiltration-webhook | DLP / exfiltration | 5 | 0 | 100 | 100 | cleanup gap |
| em-10-endpoint-exfiltration | DLP / exfiltration | 1 | 0 | 100 | 100 | cleanup gap; thin (1-2 steps) |
| dbsim-db01-auth-policy | Database simulation (DB-01..11) | 2 | 0 | 0 | 0 | cleanup gap; detection gap; thin (1-2 steps) |
| dbsim-db02-excessive-grants | Database simulation (DB-01..11) | 2 | 0 | 0 | 0 | cleanup gap; detection gap; thin (1-2 steps) |
| dbsim-db03-unauthorized-access | Database simulation (DB-01..11) | 1 | 0 | 0 | 0 | cleanup gap; detection gap; thin (1-2 steps) |
| dbsim-db04-audit-coverage | Database simulation (DB-01..11) | 2 | 0 | 0 | 0 | cleanup gap; detection gap; thin (1-2 steps) |
| dbsim-db05-suspicious-read | Database simulation (DB-01..11) | 1 | 0 | 0 | 0 | cleanup gap; detection gap; thin (1-2 steps) |
| dbsim-db06-account-revocation | Database simulation (DB-01..11) | 1 | 0 | 0 | 0 | cleanup gap; detection gap; thin (1-2 steps) |
| dbsim-db07-sensitive-classification | Database simulation (DB-01..11) | 1 | 0 | 0 | 0 | cleanup gap; detection gap; thin (1-2 steps) |
| dbsim-db08-audit-tamper-resistance | Database simulation (DB-01..11) | 1 | 0 | 0 | 0 | cleanup gap; detection gap; thin (1-2 steps) |
| dbsim-db09-bounded-bulk-read | Database simulation (DB-01..11) | 1 | 0 | 0 | 0 | cleanup gap; detection gap; thin (1-2 steps) |
| dbsim-db10-write-delete-prevention | Database simulation (DB-01..11) | 1 | 0 | 0 | 0 | cleanup gap; detection gap; thin (1-2 steps) |
| dbsim-db11-backup-export-permissions | Database simulation (DB-01..11) | 1 | 0 | 0 | 0 | cleanup gap; detection gap; thin (1-2 steps) |
| appcontrol-efficacy | Endpoint / EDR technique scenarios | 6 | 100 | 100 | 100 | - |
| av-ngav-assessment | Endpoint / EDR technique scenarios | 16 | 94 | 0 | 0 | cleanup gap; detection gap |
| caldera-lateral-movement | Endpoint / EDR technique scenarios | 5 | 0 | 0 | 0 | cleanup gap; detection gap |
| credential-access | Endpoint / EDR technique scenarios | 5 | 20 | 100 | 100 | cleanup gap |
| dll-hijack-execution | Endpoint / EDR technique scenarios | 6 | 17 | 17 | 17 | cleanup gap; detection gap |
| em-01-control-validation | Endpoint / EDR technique scenarios | 7 | 0 | 100 | 100 | cleanup gap |
| em-02-attack-behavioral-depth | Endpoint / EDR technique scenarios | 6 | 0 | 100 | 100 | cleanup gap |
| em-03-memory-attacks | Endpoint / EDR technique scenarios | 4 | 50 | 75 | 75 | cleanup gap; detection gap |
| em-04-credential-theft | Endpoint / EDR technique scenarios | 3 | 0 | 67 | 100 | cleanup gap; detection gap |
| em-05-persistence-validation | Endpoint / EDR technique scenarios | 2 | 100 | 50 | 100 | detection gap; thin (1-2 steps) |
| em-06-defense-evasion | Endpoint / EDR technique scenarios | 2 | 50 | 50 | 50 | cleanup gap; detection gap; thin (1-2 steps) |
| em-08-exploit-mitigation | Endpoint / EDR technique scenarios | 2 | 0 | 0 | 0 | cleanup gap; detection gap; thin (1-2 steps) |
| em-09-browser-attack | Endpoint / EDR technique scenarios | 2 | 0 | 0 | 50 | cleanup gap; detection gap; thin (1-2 steps) |
| em-11-hardening-validation | Endpoint / EDR technique scenarios | 2 | 0 | 0 | 0 | cleanup gap; detection gap; thin (1-2 steps) |
| em-13-product-validation | Endpoint / EDR technique scenarios | 1 | 0 | 0 | 0 | cleanup gap; detection gap; thin (1-2 steps) |
| em-14-continuous-validation | Endpoint / EDR technique scenarios | 1 | 0 | 0 | 0 | cleanup gap; detection gap; thin (1-2 steps) |
| evasion-testing | Endpoint / EDR technique scenarios | 5 | 20 | 100 | 100 | cleanup gap |
| exposure-validation | Endpoint / EDR technique scenarios | 5 | 0 | 100 | 100 | cleanup gap |
| lolbin-execution-coverage | Endpoint / EDR technique scenarios | 21 | 62 | 100 | 100 | cleanup gap |
| lolbin-execution | Endpoint / EDR technique scenarios | 5 | 60 | 100 | 100 | cleanup gap |
| lolbin-extended | Endpoint / EDR technique scenarios | 5 | 60 | 100 | 100 | cleanup gap |
| linux-credential-access | Endpoint technique scenarios (Windows/Linux/macOS) | 0 | - | - | - | steps expanded at runtime |
| linux-defense-evasion | Endpoint technique scenarios (Windows/Linux/macOS) | 0 | - | - | - | steps expanded at runtime |
| linux-discovery | Endpoint technique scenarios (Windows/Linux/macOS) | 0 | - | - | - | steps expanded at runtime |
| linux-lateral-movement | Endpoint technique scenarios (Windows/Linux/macOS) | 0 | - | - | - | steps expanded at runtime |
| linux-persistence | Endpoint technique scenarios (Windows/Linux/macOS) | 0 | - | - | - | steps expanded at runtime |
| linux-privilege-escalation | Endpoint technique scenarios (Windows/Linux/macOS) | 0 | - | - | - | steps expanded at runtime |
| macos-credential-access | Endpoint technique scenarios (Windows/Linux/macOS) | 0 | - | - | - | steps expanded at runtime |
| macos-persistence | Endpoint technique scenarios (Windows/Linux/macOS) | 0 | - | - | - | steps expanded at runtime |
| windows-discovery-validation | Endpoint technique scenarios (Windows/Linux/macOS) | 3 | 0 | 100 | 100 | cleanup gap |
| windows-discovery | Endpoint technique scenarios (Windows/Linux/macOS) | 0 | - | - | - | steps expanded at runtime |
| windows_ad_discovery | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_archive_staging | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_asrep_roast | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_backup_service_stop | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_cloud_egress | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_credential_access | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_data_destruction | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_defender_tampering | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_dlp_exfiltration | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_dns_c2 | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_encoded_powershell | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_file_discovery | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_kerberoast | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_log_manipulation | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_lolbin_download_cradle | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_malicious_service | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_netsh_portproxy | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_network_share_discovery | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_ransomware_encryption | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_runkey_persistence | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_sam_theft | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_schtask_persistence | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_security_process_termination | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_security_software_discovery | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_smb_lateral_probe | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_vss_inhibition | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_vulnerable_driver_load | Detection profile | 0 | - | - | - | detection profile (no steps) |
| windows_webmail_egress | Detection profile | 0 | - | - | - | detection profile (no steps) |
| akira-kill-chain | Ransomware kill chains | 16 | 31 | 100 | 100 | cleanup gap |
| black-basta-kill-chain | Ransomware kill chains | 10 | 40 | 100 | 100 | cleanup gap |
| blackcat-kill-chain | Ransomware kill chains | 8 | 62 | 100 | 100 | cleanup gap |
| clop-kill-chain | Ransomware kill chains | 5 | 60 | 100 | 100 | cleanup gap |
| em-07-ransomware-readiness | Ransomware kill chains | 10 | 40 | 100 | 100 | cleanup gap |
| hunters-international-kill-chain | Ransomware kill chains | 9 | 0 | 0 | 0 | no MITRE mapping; cleanup gap; detection gap |
| linux-ransomware-drill | Ransomware kill chains | 4 | 50 | 100 | 100 | cleanup gap |
| lockbit-kill-chain | Ransomware kill chains | 5 | 60 | 100 | 100 | cleanup gap |
| medusa-kill-chain | Ransomware kill chains | 10 | 0 | 0 | 0 | cleanup gap; detection gap |
| play-kill-chain | Ransomware kill chains | 8 | 62 | 100 | 100 | cleanup gap |
| ransomhub-kill-chain | Ransomware kill chains | 8 | 50 | 100 | 100 | cleanup gap |
| ransomware-drill | Ransomware kill chains | 9 | 44 | 100 | 100 | cleanup gap |
| rhysida-kill-chain | Ransomware kill chains | 11 | 0 | 0 | 0 | cleanup gap; detection gap |
