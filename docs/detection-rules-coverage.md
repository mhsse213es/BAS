# Detection rule coverage: measured, not assumed

Measured 2026-11-03. Source: SigmaHQ release `r2026-04-01`, commit `0e3b749e0d85cd943706ed610a1447f0d54e8388`
(pinned in `tools/rulelib/SIGMA_COMMIT`). Rules are under the Detection Rule License 1.1; deprecated and
unsupported rules are excluded. Tools: `tools/rulelib/coverage.py` and `tools/rulelib/translation_stats.py`.

## 1. Which upstream release

Audspect bundles ATT&CK **v16.1**. SigmaHQ's newest commit (and release `r2026-07-01`) tags rules with the
renumbered ATT&CK ids (for example Impair Defenses T1562 became T1685/T1686, and the tactic is now
`defense-impairment`), so those rules stop matching Audspect's scenarios. Measured per release, over the 152
techniques Audspect's scenarios run:

| SigmaHQ release | Rules | Exact match | No rule |
|---|---:|---:|---:|
| r2026-01-01 | 3,101 | 137 (90%) | 2 |
| **r2026-04-01 (pinned)** | 3,132 | **138 (91%)** | **2** |
| r2026-07-01 | 3,142 | 130 (86%) | 9 |
| main @ adf5a62 | 3,161 | 130 (86%) | 9 |

Moving to a newer SigmaHQ release needs the ATT&CK data and the scenarios' technique ids updated to the same
ATT&CK version first.

## 2. Technique coverage (r2026-04-01, main `rules/` tree)

- Techniques Audspect's scenarios run: **152** (38 also carry a detection profile)
- Exact rule match: **138** (91%). Only exact matches are directly applicable.
- Rule exists for the parent technique only: **12** (shown as such, never presented as exact)
- **No Sigma rule: 2**. These stay "no rule available"; nothing is invented.

## 3. Translation to the six SIEMs

Applicable rules (exact or parent match): **2,104**. With the field-mapping pipelines of section 4, **1,927 (92%)**
translate to the five original backends, and **1,643 (78%)** to all six including QRadar. (Before field mapping, a generic conversion succeeded for 99%, because a bare
backend accepts any field name; the drop is rules whose fields a SIEM's real schema cannot express, now reported
honestly instead of producing a query that matches nothing.)

| Backend | Translated | Not available |
|---|---:|---:|
| Microsoft Sentinel (KQL) | 2,075 | 29 |
| Microsoft Defender (KQL) | 2,075 | 29 |
| Splunk (SPL) | 2,104 | 0 |
| Elastic (Lucene) | 2,104 | 0 |
| CrowdStrike (LogScale) | 1,945 | 159 |
| IBM QRadar (AQL), generic only | 1,753 | 351 |

## 4. Field mapping per SIEM (Windows process creation, network connection, PowerShell script block, registry set, file event, image load, Security log, System log, PowerShell module, Linux and macOS process creation, AWS CloudTrail, Azure logs)

A bare pySigma backend emits Sigma's own field names with no table, index or event type, so its query matches
nothing in a real SIEM. For Windows `process_creation`, `network_connection`, `ps_script`, `registry_set`, `file_event`, `image_load`, Security-log, System-log, PowerShell-module, Linux and macOS process-creation, AWS CloudTrail and Azure-log rules the generator now applies a
per-SIEM processing pipeline, and every such translation records the pipeline and the data source the customer must collect for the
query to match anything. Pipelines were chosen by measuring each over all 1,177 SigmaHQ Windows process-creation
rules:

| Backend | Pipeline | Data source the customer must collect | Converts (of 1,177) |
|---|---|---|---:|
| Microsoft Sentinel | `microsoft_xdr_pipeline` | Defender for Endpoint device events connected to Sentinel (`DeviceProcessEvents`) | 97% |
| Microsoft Defender | `microsoft_365_defender_pipeline` | Defender for Endpoint advanced hunting (`DeviceProcessEvents`) | 97% |
| Splunk | `audspect_splunk_sysmon_process_creation` (ours) | Sysmon event 1 via the Splunk Add-on for Sysmon | 100% |
| Elastic | `ecs_windows` | Windows process events in ECS field names (Elastic Defend, or Winlogbeat/Sysmon with the ECS pipeline) | 100% |
| CrowdStrike | `crowdstrike_fdr_pipeline` | Falcon Data Replicator `ProcessRollup2` events | 82% |

Rejected for Sentinel: ASIM (51% convert) and Security event 4688 (41%), which cannot express most rules' fields.
Splunk's bundled pipeline adds no process-creation condition, so one small pipeline of ours adds the standard
Sysmon condition. The original Sigma rule is never changed.

**Network connection** (Windows, 37 rules) uses the same pipelines on different data:

| Backend | Pipeline | Data source the customer must collect | Field-mapped (of 37) |
|---|---|---|---:|
| Microsoft Sentinel | `microsoft_xdr_pipeline` | Defender for Endpoint device events: `DeviceNetworkEvents` | 36 |
| Microsoft Defender | `microsoft_365_defender_pipeline` | Defender for Endpoint advanced hunting: `DeviceNetworkEvents` | 36 |
| Splunk | `audspect_splunk_sysmon_network_connection` (ours) | Sysmon event 3 via the Splunk Add-on for Sysmon | 37 |
| Elastic | `ecs_windows` + `audspect_ecs_initiated_to_direction` (ours) | Network events in ECS field names (Elastic Defend, or Winlogbeat's Sysmon module, event 3) | 37 |
| CrowdStrike | `crowdstrike_fdr_pipeline` | Falcon Data Replicator `NetworkConnectIP4` events (IPv4 only) | 18 |

Not expressible: one rule on Sentinel and Defender (the `SourceIsIpv6` field has no column), and 19 on CrowdStrike (it
supports only the file name of the image, and not OR-ed CIDR ranges).

**One correction of ours, unverified.** pySigma's `ecs_windows` writes Sysmon's `Initiated` as `network.direction:true`,
a value no ECS data contains. Our extra step rewrites it to `egress` / `ingress`, which is what ECS and Winlogbeat's
Sysmon module use. This is from the ECS field definition, not tested against live Elastic data.

**PowerShell script block** (Windows `ps_script`, 108 rules) maps for three SIEMs:

| Backend | Pipeline | Data source the customer must collect | Field-mapped (of 108) |
|---|---|---|---:|
| Splunk | `audspect_splunk_powershell_script_block` (ours) | Event 4104 in `Microsoft-Windows-PowerShell/Operational` | 108 |
| Elastic | `ecs_windows` | `powershell.file.script_block_text` (Winlogbeat PowerShell module or Elastic Defend) | 108 |
| CrowdStrike | `crowdstrike_fdr_pipeline` | `CommandHistory` / `ScriptControlScanTelemetry` events | 108 |

Microsoft Sentinel and Defender stay **generic** for this family: their pipelines have no table for script-block
text, so nothing is guessed. Script block logging must be enabled on the endpoints for any of these to match.

**Registry set** (Windows `registry_set`, 102 rules) maps for four SIEMs:

| Backend | Pipeline | Data source the customer must collect | Field-mapped (of 102) |
|---|---|---|---:|
| Microsoft Sentinel | `microsoft_xdr_pipeline` | Defender for Endpoint device events: `DeviceRegistryEvents` | 102 |
| Microsoft Defender | `microsoft_365_defender_pipeline` | Defender for Endpoint advanced hunting: `DeviceRegistryEvents` | 102 |
| Splunk | `audspect_splunk_sysmon_registry_set` (ours) | Sysmon event 13 via the Splunk Add-on for Sysmon | 102 |
| Elastic | `ecs_windows` | Winlogbeat's Sysmon module (event 13); the registry value is `winlog.event_data.Details`, so Elastic Defend alone may not carry it | 102 |

CrowdStrike stays **generic** for this family: its pipeline emits Sysmon field names with no event type, so calling
it mapped would be false.

**File event** (Windows `file_event`, 99 rules) maps for four SIEMs:

| Backend | Pipeline | Data source the customer must collect | Field-mapped (of 99) |
|---|---|---|---:|
| Microsoft Sentinel | `microsoft_xdr_pipeline` | Defender for Endpoint device events: `DeviceFileEvents` | 98 |
| Microsoft Defender | `microsoft_365_defender_pipeline` | Defender for Endpoint advanced hunting: `DeviceFileEvents` | 98 |
| Splunk | `audspect_splunk_sysmon_file_event` (ours) | Sysmon event 11 via the Splunk Add-on for Sysmon | 99 |
| Elastic | `ecs_windows` | File creation events in ECS (Elastic Defend, or Winlogbeat's Sysmon module, event 11) | 99 |

One rule uses `InitiatingProcessParentFileName`-style fields the Defender tables lack and is recorded as unavailable
on Sentinel and Defender. CrowdStrike stays **generic** (its pipeline emits Sysmon field names with no event type).

**Image load** (Windows `image_load`, 94 rules) maps for all five SIEMs:

| Backend | Pipeline | Data source the customer must collect | Field-mapped (of 94) |
|---|---|---|---:|
| Microsoft Sentinel | `microsoft_xdr_pipeline` | Defender for Endpoint device events: `DeviceImageLoadEvents` | 77 |
| Microsoft Defender | `microsoft_365_defender_pipeline` | Defender for Endpoint advanced hunting: `DeviceImageLoadEvents` | 77 |
| Splunk | `audspect_splunk_sysmon_image_load` (ours) | Sysmon event 7 via the Splunk Add-on for Sysmon | 94 |
| Elastic | `ecs_windows` | Winlogbeat's Sysmon module (event 7) or Elastic Defend library events | 94 |
| CrowdStrike | `crowdstrike_fdr_pipeline` | Falcon Data Replicator `ClassifiedModuleLoad` events | 74 |

Not expressible: 17 rules on Sentinel and Defender (mostly the `Signed` field, and unsupported hash formats) and 20 on
CrowdStrike (`Signed`, `OriginalFileName`); each is recorded with its reason. Sysmon does not log image loads by default,
so event 7 must be enabled. The Elastic query carries no event-type condition; it relies on the field names.

**Windows Security log** (`service: security`, 106 rules, keyed by event ID) maps for three SIEMs:

| Backend | Pipeline | Data source the customer must collect | Field-mapped (of 106) |
|---|---|---|---:|
| Microsoft Sentinel | `azure_monitor_pipeline` with the table forced to `SecurityEvent` (ours) | The `SecurityEvent` table (Windows Security Events via AMA connector) | 83 |
| Splunk | `splunk_windows_pipeline` | `WinEventLog:Security` with the event id as `EventCode` (Splunk Add-on for Microsoft Windows) | 106 |
| Elastic | `ecs_windows` | Security channel in ECS field names (Winlogbeat or the Elastic Agent Windows integration) | 106 |

The Azure Monitor pipeline picks a table only for a short list of event ids and fails the rest, so we name
`SecurityEvent` ourselves. 23 rules use fields that table lacks (for example `AttributeLDAPDisplayName`) and are
recorded as unavailable on Sentinel. Defender XDR and CrowdStrike have no Security-event source and stay **generic**.
The audit policy for each event must be enabled on the endpoints for any of these to match.

**Windows System log** (`service: system`, 49 rules) maps for two SIEMs:

| Backend | Pipeline | Data source the customer must collect | Field-mapped (of 49) |
|---|---|---|---:|
| Splunk | `splunk_windows_pipeline` | `WinEventLog:System` with the event id as `EventCode` (Splunk Add-on for Microsoft Windows) | 49 |
| Elastic | `ecs_windows` | System channel in ECS field names (Winlogbeat or the Elastic Agent Windows integration) | 49 |

Sentinel stays **generic** on purpose: its Azure Monitor pipeline can only put these rules in `SecurityEvent`, which is
the wrong table (the System log is in the `Event` table with different fields, such as `Source` for the provider), so
labelling that mapped would be false. Defender XDR and CrowdStrike have no System-event source.

**PowerShell module logging** (Windows `ps_module`, event 4103, 30 rules) maps for Splunk only
(`audspect_splunk_powershell_module`, source `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational`, matched on
`Payload`; module logging must be enabled). Elastic stays **generic** on purpose: the stock `ecs_windows` pipeline
renames `Payload` to the script-block field, which belongs to event 4104, so a mapped label would be false. Sentinel
and Defender have no table for it and CrowdStrike no event type.

**Linux process creation** (`product: linux`, 74 rules) maps for four SIEMs:

| Backend | Pipeline | Data source the customer must collect | Field-mapped (of 74) |
|---|---|---|---:|
| Microsoft Sentinel | `microsoft_xdr_pipeline` | Defender for Endpoint on Linux device events: `DeviceProcessEvents` | 72 |
| Microsoft Defender | `microsoft_365_defender_pipeline` | Defender for Endpoint on Linux advanced hunting: `DeviceProcessEvents` | 72 |
| CrowdStrike | `crowdstrike_fdr_pipeline` | Falcon Data Replicator process events from the Linux sensor (`event_platform` Lin) | 74 |
| Elastic | `audspect_ecs_linux_process_creation` (ours) | Linux process start events in ECS (Elastic Defend for Linux, or Auditbeat) | 72 |

pySigma's `ecs_windows` only renames Windows fields, so Linux rules kept Sigma's own names (`Image`, `CommandLine`) in the
query. Our pipeline maps the seven fields these rules use to ECS (`process.executable`, `process.command_line`,
`process.parent.*`, `user.name`, `process.working_directory`) and adds `event.category:process AND event.type:start`.
That mapping is from the ECS definition and is **unverified against live Elastic data**. A field with no ECS equivalent
(`LogonId`, 2 rules) is a recorded failure, never a raw name. Sentinel and Defender cannot express `CurrentDirectory`
(2 rules). **Splunk stays generic**: Sigma's Linux field names are Sysmon for Linux's, and the Splunk source and
sourcetype for it are not something this generator can state truthfully.

**macOS process creation** (`product: macos`, 39 rules) maps for four SIEMs, all 39 on each: Sentinel and Defender
through `DeviceProcessEvents` (Defender for Endpoint on macOS), CrowdStrike through the stock pipeline (`event_platform`
Mac), and Elastic through the same ECS pipeline of ours as Linux (Elastic Defend for macOS; unverified on live data;
pySigma's `ecs_macos_esf` also leaves `Image` and `CommandLine` unrenamed). Splunk stays generic.

**AWS CloudTrail** (29 rules; 22 use only top-level fields such as `eventName` and `eventSource`) maps for three SIEMs:

| Backend | Pipeline | Data source the customer must collect | Field-mapped (of 29) |
|---|---|---|---:|
| Microsoft Sentinel | `audspect_sentinel_aws_cloudtrail` (ours) + `azure_monitor_pipeline` on `AWSCloudTrail` | The `AWSCloudTrail` table (Amazon Web Services connector) | 24 |
| Splunk | `audspect_splunk_aws_cloudtrail` (ours) | Sourcetype `aws:cloudtrail` (Splunk Add-on for AWS); CloudTrail's JSON keys are the field names | 29 |
| Elastic | `audspect_ecs_aws_cloudtrail` (ours) | Filebeat AWS module / Elastic AWS integration (`event.dataset` aws.cloudtrail) | 23 |

Top-level keys are renamed to each SIEM's columns or fields. A nested field (`requestParameters.x`,
`responseElements.x`, `userIdentity.sessionContext...`) is not a column or ECS field we can name, so the rule is a
recorded failure on that SIEM with the field in the reason (5 on Sentinel, 6 on Elastic). The Sentinel column names
and the Elastic AWS field names are from the products' documented schemas and are unverified against live data.
Defender XDR and CrowdStrike have no CloudTrail source and stay generic.

**Azure logs** map for Sentinel only, using the Azure Monitor pipeline on an explicit table:

| Log | Table | Our rename | Field-mapped |
|---|---|---|---:|
| Activity logs (21 rules) | `AzureActivity` | `operationName` to `OperationNameValue` | 17 |
| Entra audit logs (21) | `AuditLogs` | `properties.message` to `OperationName` | 16 |
| Entra sign-in logs (17) | `SigninLogs` | none (stock pipeline) | 8 |

The two renames lift the stock pipeline from 1 to 17 and 5 to 16 rules; they come from what the fields hold (Sigma's
`operationName` carries the raw resource-provider operation, `properties.message` the audit operation name) and are
unverified against live data. A sign-in rename that would have helped was a guess and is not applied. A field the table
lacks (`userAgent`, `Count`, `TargetResources.modifiedProperties` and others) is a recorded failure. Splunk, Elastic,
Defender XDR and CrowdStrike stay generic: there is no Azure source or sourcetype this generator can state truthfully.
The Entra risk-detection (15), PIM (7), GCP audit (5) and Microsoft 365 (5) rules remain generic: none converts
usefully through the Azure Monitor pipeline.

**Long tail of Windows log sources** (186 rules in 30 groups). Chosen by measuring every unmapped Windows group
against the stock pipelines and reading the output, not by whether the output changed:

- **Event-log services** (Defender, Application, Firewall, BITS, DNS client, Exchange management, Task Scheduler and
  others) map for Splunk and Elastic through the stock pipelines, **only when the output actually carries the source
  (`source="`) or channel (`winlog.channel`)**. A service the pipeline does not recognise (`iis-configuration`, `ldap`,
  `smbserver-connectivity`) stays generic, and a service recognised by only one SIEM maps for only that one.
- **Sysmon categories for Splunk** use our own pipelines pinning the event codes: process access 10, DNS query 22, named
  pipe 17/18, driver load 6, remote thread 8, registry event 12/13/14, registry delete 12, file delete 23/26. Classic
  PowerShell start (event 400, `Windows PowerShell` log) maps for Splunk and Elastic.
- **Stock pipelines where they are correct**: Sentinel and Defender for registry events, registry delete and file delete
  (`DeviceRegistryEvents`, `DeviceFileEvents`); CrowdStrike for DNS query and driver load; Elastic for DNS query and the
  two registry categories.
- **Deliberately left generic**: Elastic for process access (pySigma emits a corrupt query for regex rules), remote
  thread, named pipe, driver load and file delete (their ECS fields are not specific to the event); Sentinel and Defender
  for file access (file events are creation and modification, not reads).

**Query integrity gate.** The generator now rejects any query containing a leaked pySigma object (the defect above) and
records it as a failure; none exists in the shipped bundle.

**Small log sources** (169 rules, added last). Each maps only for the SIEMs whose schema is documented:

| Source (rules) | Splunk | Elastic | Sentinel |
|---|---|---|---|
| Web proxy (27), web server (12), Apache (1) | CIM Web (`tag=web`, `url`, `http_method`, `http_user_agent`) | ECS `url.*`, `http.*`, `user_agent.*` | none |
| DNS (6) | CIM DNS (`tag=dns`, `query`) | ECS `dns.*` | none |
| Antivirus (4) | CIM Malware (`signature`) | none | none |
| Linux auditd (28) | sourcetype `linux_audit` (Unix and Linux add-on) | none | none |
| Cisco IOS (12) | sourcetype `cisco:ios` | `event.dataset cisco.ios` | none |
| Okta (3) | sourcetype `OktaIM2:log`, native keys | none | none |
| OpenCanary (21), Bitbucket audit (10) | native JSON keys, no source condition | none | none |
| Zeek (14) | none | stock `ecs_zeek_beats` | none |
| Kubernetes audit (3) | none | stock `ecs_kubernetes` | none |
| GCP audit (5) | none | Filebeat `gcp.audit.*` + dataset | none |
| Entra risk detection (15) | none | none | `AADUserRiskEvents` |

Sources checked against vendor documentation: the `linux_audit`, `OktaIM2:log` and `cisco:ios` sourcetypes and the CIM
Web fields. Not verified: the CIM DNS and Malware field names, `auditd` `SYSCALL` as `syscall`, the Filebeat Cisco and
GCP dataset names. A field with no equivalent (for example `cs-cookie`, `dst_ip` on Splunk, raw `protoPayload` on GCP) is a
recorded failure naming the field.

The stock Zeek pipeline emits an invalid wildcard field name (`zeek.\*.path`) for SMB file rules; those two fields are
mapped to Filebeat's `zeek.smb_files.*` names first. The integrity gate also rejects any query with a wildcard field-name
segment, which caught one remaining Zeek Kerberos rule (a recorded failure on Elastic).

The last Sysmon and PowerShell categories map for Splunk: WMI events 19/20/21, Sysmon state 4/16, Sysmon error 255,
executable detected 29, process tampering 25, and the classic PowerShell provider start (event 600; Elastic too).

**Verification.** Every translation carries a `verification` value, shown beside the query in the console, the API and the
PDF: `none` (generic, Sigma's own field names), `documented` (names from the product's documentation or an upstream
pipeline, never run on events; 7,109 translations), `assumed` (our own assumption, flagged unverified in the data-source
note: 217, all Splunk or Elastic) and `validated` (matched a positive and not a negative sample event). The generator
never sets `validated`; it is reserved for mappings tested against supplied events, and none is yet. A test fails if a
mapped translation says `assumed` without the note, or `documented` while the note says unverified.

Rules with at least one field-mapped translation: **2,004 of 2,104**. Coverage per SIEM differs:

| Backend | Field-mapped | Not expressible |
|---|---:|---:|
| Microsoft Sentinel | 1,436 | 98 |
| Microsoft Defender | 1,273 | 52 |
| Splunk | 1,808 | 5 |
| Elastic | 1,775 | 11 |
| CrowdStrike | 1,034 | 197 |

A rule a backend cannot express (for example a hash format, `CurrentDirectory`, or CrowdStrike's missing
`Description`/`ParentCommandLine` fields) is recorded as **"backend translation unavailable"** with the reason. It
is never silently replaced by a generic query. The 100 rules with no field-mapped translation are left generic on purpose, in three groups:

- **Free text with no schema** (27): application-framework logs (JVM, Spring, Django, Rails, Node, Python, SQL, Velocity),
  Linux syslog/sshd/vsftpd and unscoped Linux keyword rules, and Juniper/Huawei BGP. These are keyword searches of raw log
  text; there is no field to map, so the generic query is already what the rule says. They need scoping to the right log.
- **No schema verified** (44): GitHub audit (8), Fortigate (4), M365 audit and threat management (7), RPC Firewall
  (6), Linux file-event and network-connection from Sysmon for Linux (6), Windows IIS, LDAP, SMB-server and file-access
  (13). A guessed field name would produce a query that looks right and never matches.
- **Fields the table lacks or other defects** (29): the Azure activity, audit, sign-in and PIM rules that use fields no Sentinel table
  has (PIM alert incidents are not in `AuditLogs` or `AADUserRiskEvents`), and the GCP/Zeek rules a pipeline cannot express.

Their translations are labelled `generic`, need adapting to the customer's schema, and are not presented
as ready to paste.
as ready to paste. Each further log-source family is one more entry in `scripts/rulelib-gen/translate.py`.

## 5. Limits that decide what the product may claim

- **A mapped query still depends on the data source.** It only matches if the customer collects the data source
  named beside it. Copying a query never means the SIEM will detect the attack.
- **A rule existing is not a detection working.** No rule has been tested against telemetry.
- **Tag-based matching.** A technique counts as covered when a rule carries its ATT&CK tag; relevance of the rule
  to Audspect's specific test is not judged.
- **pyparsing must stay pinned to 3.2.5** (`scripts/rulelib-gen/requirements.txt`); with 3.3.x, 492 of the 2,104
  rules fail on every backend with a misleading error.
- **pySigma edits rules in place**, so the generator converts a fresh copy of the rule for every backend.

### QRadar

QRadar is the sixth backend. Its pySigma backend needs pySigma below 0.10, so it is generated in a separate
environment (`scripts/rulelib-gen/qradar/README.md`). Every QRadar query is **generic**: AQL with Sigma's own field
names as custom event properties, never labelled field-mapped, because the package's bundled Windows pipelines
convert only 77 of 845 Windows process-creation rules and two crash. 1,753 of 2,104 rules (83%) have a QRadar query;
the other 351 are recorded as "backend translation unavailable" because the backend supports only a fixed set of
fields per log source. The queries have not been run on a QRadar; treat them as a starting point.

## 6. What ships in the product

The orchestrator embeds the full library generated from the pinned commit: **2,104 SigmaHQ rules** covering
**282 ATT&CK technique ids** (the 152 techniques Audspect's scenarios run, plus parents), every rule with its
translations, mapping labels and provenance (SigmaHQ, exact commit, path inside the checkout, licence DRL 1.1).

- Size: `rules.json` is 16.1 MB (up to 6 queries and the raw rule per rule), embedded in the binary. This is larger
  than the 6 MB first estimated.
- Rule ids are stable across regenerations: `scripts/rulelib-gen/id_registry.json` maps each SigmaHQ id to its
  AUDRULE id and only grows. Commit it with every regeneration.
- Two rules carry ATT&CK ids newer than the bundled ATT&CK v16.1 data (T1059.012, T1204.004); they are kept and
  listed in `metadata.json` as `unrecognizedTechniqueIds`.
- Regenerate: `tools/rulelib/fetch_sigma.sh`, then
  `python scripts/rulelib-gen/build.py --sigma-dir tools/rulelib/sigma/rules --sigma-root tools/rulelib/sigma --qradar-python <python of the QRadar environment>`.
- Every export (Sigma, KQL, SPL, Lucene, LogScale, AQL) returns the upstream rule id, source, commit and licence as
  response headers.

## 7. Where the recommendations appear, and closing the loop

- **Console**: Detection Verification > Detection gaps, per run, with copy buttons and a zip export.
- **Run report (HTML and PDF)**: Section 18b, Detection Engineering Recommendations. Present only when the run has at
  least one reviewed detection gap. It shows the highest-severity rule per gap with its query for every SIEM, the
  mapped or generic note, "Not validated", "No rule available" where there is none, and the SigmaHQ attribution.
  Queries are capped at 1,200 characters (the export has the rest). The PDF comes from the HTML through the Chromium
  sidecar; the plain-Go fallback renderer does not include this section.
- **Deploy and re-test**: the customer records that they deployed a rule ("Mark deployed"), then re-tests. The
  re-test is a new run of the same scenario on the same agent, started from the console with the original run's mode
  (telemetry and lab keep their confirmations), and linked to the deployment. The outcome comes only from the re-test
  run's own reviewed verifications:

| Status | Meaning |
|---|---|
| Deployed | Recorded; nothing is known about detection |
| Re-test running | The linked run has not finished |
| Re-test awaiting verification | The re-test executed the technique but nobody has reviewed whether an alert fired |
| Closed on re-test | The re-test executed the technique and a reviewed verification found an alert. Audspect does **not** confirm the deployed rule produced it |
| Still a gap | The re-test executed the technique and a reviewed verification found no alert |
| Technique not re-tested | The re-test errored, skipped the technique, or did not include it |

A re-test must be another run of the same scenario on the same agent that started after the deployment was recorded.
None of this has been run against a real deployment yet.

## 8. Attribution

Rules are from SigmaHQ (https://github.com/SigmaHQ/sigma), licensed under the Detection Rule License (DRL) 1.1.
Every export carries the rule's original author, Sigma id, source commit and this attribution.
