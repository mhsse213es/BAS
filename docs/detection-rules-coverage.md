# Detection rule coverage: measured, not assumed

Measured 2026-11-03. Source: SigmaHQ release `r2026-04-01`, commit `0e3b749e0d85cd943706ed610a1447f0d54e8388`
(pinned in `tools/rulelib/SIGMA_COMMIT`). Rules are under the Detection Rule License 1.1; deprecated and
unsupported rules are excluded. Tools: `tools/rulelib/coverage.py` and `tools/rulelib/translation_stats.py`.

## 1. Which upstream release

Audspect bundles ATT&CK **v16.1**. SigmaHQ's newest commit (and release `r2026-07-01`) tags rules with the
renumbered ATT&CK ids (for example Impair Defenses T1562 became T1685/T1686, and the tactic is now
`defense-impairment`), so those rules stop matching Audspect's scenarios. Measured per release, over the 150
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

- Techniques Audspect's scenarios run: **150** (38 also carry a detection profile)
- Exact rule match: **138** (91%). Only exact matches are directly applicable.
- Rule exists for the parent technique only: **10** (shown as such, never presented as exact)
- **No Sigma rule: 2**. These stay "no rule available"; nothing is invented.

## 3. Translation to the five SIEMs

Applicable rules (exact or parent match): **2,104**. Converted to all five backends: **2,087 (99%)**.

| Backend | Converted | Failed |
|---|---:|---:|
| Microsoft Sentinel (KQL) | 2,104 | 0 |
| Microsoft Defender (KQL) | 2,104 | 0 |
| Splunk (SPL) | 2,104 | 0 |
| Elastic (Lucene) | 2,104 | 0 |
| CrowdStrike (LogScale) | 2,087 | 17 (OR-ed CIDR matching is not supported by that backend) |

## 4. Limits that decide what the product may claim

- **The queries are generic.** The current generator converts with bare backends, so a query uses Sigma's own
  field names (`Image`, `CommandLine`) with no table, index or event type and no mapping to the SIEM's real
  schema. A Sentinel or Defender query has no `DeviceProcessEvents` table or `FileName`/`ProcessCommandLine`
  fields; Splunk has no index or sourcetype; Elastic is not in ECS field names. **They are not ready to paste into a
  SIEM** until per-backend processing pipelines are applied, and those depend on which log source the customer
  collects (for example Sysmon versus Windows Security 4688).
- **A rule existing is not a detection working.** No rule has been tested against telemetry.
- **Tag-based matching.** A technique counts as covered when a rule carries its ATT&CK tag; relevance of the
  rule to Audspect's specific test is not judged.
- **pyparsing must stay pinned to 3.2.5** (`scripts/rulelib-gen/requirements.txt`); with 3.3.x 492 of the 2,104 rules
  fail on every backend with a misleading error.

## 5. Attribution

Rules are from SigmaHQ (https://github.com/SigmaHQ/sigma), licensed under the Detection Rule License (DRL) 1.1.
Every export carries the rule's original author, Sigma id, source commit and this attribution.
