# Audspect BAS — Scoring Methodology

**Platform Version:** v1.7.3

---

## Overview

Every completed simulation run produces a multi-dimensional score. The scoring system answers four questions simultaneously:

1. **Prevention Score** — How well do your controls block known attack techniques? (higher = better)
2. **Exposure Score** — How exposed is this endpoint to adversary progression? (higher = worse)
3. **Coverage Score** — How broadly do your controls defend across kill-chain phases? (higher = better)
4. **Risk Classification** — What risk band best describes this endpoint's overall posture?

Scores are per-run and per-agent. Campaign scores aggregate across multiple agents and scenarios.

---

## Verdict Taxonomy

Scoring begins with step-level verdicts:

| Verdict | Scoring Inclusion | Meaning |
|---|---|---|
| **PASS** | Yes | The control blocked or detected the technique |
| **FAIL** | Yes | The technique succeeded (attacker advantage) |
| **ERROR** | **No** | Execution failed on the BAS side; not a control result |
| **SKIPPED** | **No** | Step not applicable to this OS/config |
| **VETOED** | **No** | Agent refused to execute the step under its destructive-action policy |

ERROR, SKIPPED and VETOED are excluded entirely from scoring. BLOCKED results (the control stopped the technique) are scored as PASS. The denominator in all score calculations uses only PASS + FAIL steps.

---

## Prevention Score

**Range:** 0–100 (higher = better controls)

### Formula

```
Prevention Score = Σ(step_weight × is_pass) / Σ(step_weight) × 100
```

Where `step_weight` is derived from the step's severity:

| Severity | Weight |
|---|---|
| Critical | 4 |
| High | 3 |
| Medium | 2 |
| Low | 1 |
| Informational (and any other value) | 1 |

### Example

| Step | Severity | Weight | Verdict | Contribution |
|---|---|---|---|---|
| T1003.001 LSASS dump | Critical | 4 | FAIL | 0 |
| T1059.001 PowerShell exec | High | 3 | PASS | 3 |
| T1047 WMI execution | High | 3 | PASS | 3 |
| T1053.005 Scheduled task | Medium | 2 | FAIL | 0 |
| T1082 System info discovery | Low | 1 | PASS | 1 |

```
Prevention Score = (0 + 3 + 3 + 0 + 1) / (4 + 3 + 3 + 2 + 1) × 100
                = 7 / 13 × 100
                = 53.8 → 54
```

---

## Exposure Score

**Range:** 0–100 (higher = worse — more exposed)

The Exposure Score measures how far an attacker can progress through the kill chain. Failures in earlier kill-chain phases are amplified by failures in subsequent phases (momentum effect).

### Kill Chain Phase Order

Kill Chain Amplifier evaluation follows this ordered sequence of ATT&CK tactics:

```
1. Initial Access
2. Execution
3. Persistence
4. Privilege Escalation
5. Defense Evasion
6. Credential Access
7. Lateral Movement
8. Collection
9. Exfiltration
```

### Kill Chain Amplifier

The Kill Chain Amplifier multiplies the Risk Score when an attacker achieves consecutive failures (techniques succeeding) across advancing kill-chain phases:

| Consecutive phase failures | Amplifier |
|---|---|
| 0–1 phases | 1.0× |
| 2 consecutive phases | 1.3× |
| 3–4 consecutive phases | 1.8× |
| 5+ consecutive phases | 2.5× |

### Base Exposure Formula

```
Base Exposure = Σ(tactic_weight of each FAIL step) / Σ(tactic_weight of each scored step) × 100
```

Each scored (PASS or FAIL) step contributes its tactic weight to the denominator, and each FAIL step adds its weight to the numerator.

| Tactic weight | Tactics |
|---|---|
| 4 | Credential Access, Lateral Movement, Privilege Escalation |
| 3 | Persistence, Defense Evasion, Execution, Command and Control, Impact, Exfiltration, Collection |
| 2 | Initial Access |
| 1 | All other tactics (for example Reconnaissance, Resource Development, Discovery) |

```
Exposure Score (stored value) = Base Exposure
Risk Score = min(round(Base Exposure × Kill Chain Amplifier), 100)
```

The Risk Score drives the Risk Classification. The Kill Chain Amplifier is applied to the Risk Score, not to the stored Exposure Score.

---

## Coverage Score

**Range:** 0–100 (higher = broader defense)

Coverage Score measures what percentage of tested MITRE ATT&CK tactics had no FAIL verdicts.

```
Coverage Score = (tactics_fully_passed / tactics_tested) × 100
```

A tactic is counted as "fully passed" when no step mapped to that tactic in the run produced a FAIL verdict (ERROR, SKIPPED and VETOED steps are not counted).

### Distinction from Prevention Score

- **Prevention Score:** Weighted average across all steps — partially failed tactics still contribute positive score
- **Coverage Score:** Binary per tactic — one failed step in a tactic marks that tactic as exposed, regardless of how many steps passed

A Prevention Score of 85 with a Coverage Score of 40 means controls are generally strong but there are specific kill-chain phases with active gaps.

---

## Risk Classification

The Risk Classification bands a run into one of five risk levels based on its Risk Score (the Base Exposure with the Kill Chain Amplifier applied, see Exposure Score above):

| Band | Risk Score Range | Meaning |
|---|---|---|
| **Protected** | 0–20 | Controls are comprehensive; minor gaps only |
| **Low Risk** | 21–40 | Controls are generally effective; targeted gaps |
| **Medium Risk** | 41–60 | Significant gaps; attacker has partial advantage |
| **High Risk** | 61–80 | Controls are failing on critical techniques |
| **Critical** | 81–100 | Severe control failure; immediate remediation required |

The band is displayed as a colored badge on every run and in all reports.

---

## Trend

Trend compares the current run's Prevention Score to the most recent previous run on the same agent with the same scenario:

| Trend | Condition |
|---|---|
| **Baseline** | No prior run exists for this agent + scenario combination |
| **Improving** | Prevention Score increased by 5 points or more |
| **Stable** | Score changed by less than 5 points in either direction |
| **Degrading** | Prevention Score decreased by 5 points or more |

The 5-point threshold avoids marking noise (a single borderline step verdict) as a trend change.

---

## Confidence

Each run carries a Confidence value from 0 to 100. It is the average of two percentages: the share of steps that actually executed (ERROR, SKIPPED and VETOED steps are not counted), and the share of the nine main kill-chain tactics (initial access through exfiltration) that the run exercised. A run that skips many steps or covers few tactics therefore shows lower confidence.

---

## Baseline Comparison

The first run of a new scenario on an agent establishes the **Baseline**. All subsequent runs are compared against the baseline score, not just the immediately prior run. The agent summary shows:

- Current Prevention Score
- Baseline Prevention Score (first run)
- Score delta since baseline
- Trend direction

---

## Aggregated Scores

### Agent-Level Score

The agent report scores the agent from its most recent completed or partial scenario run: the Prevention, Exposure and Risk values shown are those of that run. The report's run history lists the score of each of the 20 most recent runs.

### Campaign Score

Campaign scores are computed over the pooled step results of every agent and scenario in the campaign, so each scorable step counts once, with its severity weight.

---

## Asset Score

Attack Path assets can be tagged with criticality (crown-jewel, high, medium, low). Attack Path scoring produces an **Asset Exposure Score** (0–100, higher = worse) that measures how many active attack paths terminate at or pass through each asset tier.

```
Asset Exposure Score = Σ(criticality_weight × paths_through_asset) / max_possible × 100
```

Asset Exposure Score is independent of the BAS Prevention Score and appears exclusively in the Attack Path section and Attack Path compliance reports.

---

## Scoring Data Access

All scoring data is available via API:

```
GET /api/scenarios/runs                — Run list, including each run's score
GET /api/report/full/json?agentId={id} — Agent-level report with scores (JSON)
GET /api/campaigns/{id}/summary        — Campaign aggregate score
GET /api/compliance/scores             — Framework coverage scores
```

---

*© Audspect — Confidential — Customer Distribution*
