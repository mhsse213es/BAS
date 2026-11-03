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

## 4. Field mapping per SIEM (Windows process creation, network connection, PowerShell script block, registry set, file event)

A bare pySigma backend emits Sigma's own field names with no table, index or event type, so its query matches
nothing in a real SIEM. For Windows `process_creation`, `network_connection`, `ps_script`, `registry_set` and `file_event` rules the generator now applies a
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

Of the 2,104 applicable rules, **1,191** are in the five mapped families (845 process creation, 37 network connection, 108 PowerShell script block, 102 registry set, 99 file event):

| Backend | Field-mapped | Not expressible |
|---|---:|---:|
| Microsoft Sentinel | 1,052 | 31 |
| Microsoft Defender | 1,052 | 31 |
| Splunk | 1,191 | 0 |
| Elastic | 1,191 | 0 |
| CrowdStrike | 829 | 161 |

A rule a backend cannot express (for example a hash format, `CurrentDirectory`, or CrowdStrike's missing
`Description`/`ParentCommandLine` fields) is recorded as **"backend translation unavailable"** with the reason. It
is never silently replaced by a generic query. The other 913 applicable rules (other log sources) are still
generic: their translations are labelled `generic`, need adapting to the customer's schema, and are not presented
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
