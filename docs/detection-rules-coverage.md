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

## 3. Translation to the five SIEMs

Applicable rules (exact or parent match): **2,104**. With the field-mapping pipelines of section 4, **1,927 (91%)**
translate to all five backends. (Before field mapping, a generic conversion succeeded for 99%, because a bare
backend accepts any field name; the drop is rules whose fields a SIEM's real schema cannot express, now reported
honestly instead of producing a query that matches nothing.)

| Backend | Translated | Not available |
|---|---:|---:|
| Microsoft Sentinel (KQL) | 2,075 | 29 |
| Microsoft Defender (KQL) | 2,075 | 29 |
| Splunk (SPL) | 2,104 | 0 |
| Elastic (Lucene) | 2,104 | 0 |
| CrowdStrike (LogScale) | 1,945 | 159 |

## 4. Field mapping per SIEM (Windows process creation)

A bare pySigma backend emits Sigma's own field names with no table, index or event type, so its query matches
nothing in a real SIEM. For Windows `process_creation` rules the generator now applies a per-SIEM processing
pipeline, and every such translation records the pipeline and the data source the customer must collect for the
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

Of the 2,104 applicable rules, **845** are Windows process-creation:

| Backend | Field-mapped | Not expressible |
|---|---:|---:|
| Microsoft Sentinel | 816 | 29 |
| Microsoft Defender | 816 | 29 |
| Splunk | 845 | 0 |
| Elastic | 845 | 0 |
| CrowdStrike | 703 | 142 |

A rule a backend cannot express (for example a hash format, `CurrentDirectory`, or CrowdStrike's missing
`Description`/`ParentCommandLine` fields) is recorded as **"backend translation unavailable"** with the reason. It
is never silently replaced by a generic query. The other 1,259 applicable rules (other log sources) are still
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

## 6. Attribution

Rules are from SigmaHQ (https://github.com/SigmaHQ/sigma), licensed under the Detection Rule License (DRL) 1.1.
Every export carries the rule's original author, Sigma id, source commit and this attribution.
