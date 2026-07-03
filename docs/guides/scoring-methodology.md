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

ERROR and SKIPPED are excluded entirely from scoring. The denominator in all score calculations uses only PASS + FAIL steps.

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
| Informational | 0.5 |

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

```
1. Reconnaissance
2. Resource Development
3. Initial Access
4. Execution
5. Persistence
6. Privilege Escalation
7. Defense Evasion
8. Credential Access
9. Discovery
10. Lateral Movement
11. Collection
12. Command and Control
13. Exfiltration
14. Impact
```

### Kill Chain Amplifier

The Kill Chain Amplifier multiplies the base Exposure Score when an attacker achieves consecutive failures (techniques succeeding) across advancing kill-chain phases:

| Consecutive phase failures | Amplifier |
|---|---|
| 0–1 phases | 1.0× |
| 2 consecutive phases | 1.2× |
| 3 consecutive phases | 1.5× |
| 4 consecutive phases | 1.8× |
| 5+ consecutive phases | 2.5× |

### Base Exposure Formula

```
Base Exposure = Σ(tactic_weight × fail_rate_in_tactic) / Σ(tactic_weight) × 100
```

Tactic weights increase toward later kill-chain phases (Impact > Exfiltration > Lateral Movement > ... > Reconnaissance).

```
Exposure Score = min(Base Exposure × Kill Chain Amplifier, 100)
```

---

## Coverage Score

**Range:** 0–100 (higher = broader defense)

Coverage Score measures what percentage of tested MITRE ATT&CK tactics achieved a perfect pass rate (all steps in that tactic passed).

```
Coverage Score = (tactics_fully_passed / tactics_tested) × 100
```

A tactic is "fully passed" when every step mapped to that tactic in the run produced a PASS verdict.

### Distinction from Prevention Score

- **Prevention Score:** Weighted average across all steps — partially failed tactics still contribute positive score
- **Coverage Score:** Binary per tactic — one failed step in a tactic marks that tactic as exposed, regardless of how many steps passed

A Prevention Score of 85 with a Coverage Score of 40 means controls are generally strong but there are specific kill-chain phases with active gaps.

---

## Risk Classification

The Risk Classification bands a run into one of five risk levels based on Prevention Score:

| Band | Prevention Score Range | Meaning |
|---|---|---|
| **Protected** | 90–100 | Controls are comprehensive; minor gaps only |
| **Low Risk** | 75–89 | Controls are generally effective; targeted gaps |
| **Medium Risk** | 50–74 | Significant gaps; attacker has partial advantage |
| **High Risk** | 25–49 | Controls are failing on critical techniques |
| **Critical Risk** | 0–24 | Severe control failure; immediate remediation required |

The band is displayed as a colored badge on every run and in all reports.

---

## Trend

Trend compares the current run's Prevention Score to the most recent previous run on the same agent with the same scenario:

| Trend | Condition |
|---|---|
| **Baseline** | No prior run exists for this agent + scenario combination |
| **Improving** | Prevention Score increased by more than 3 points |
| **Stable** | Score changed by 3 points or fewer in either direction |
| **Degrading** | Prevention Score decreased by more than 3 points |

The 3-point threshold avoids marking noise (a single borderline step verdict) as a trend change.

---

## Confidence

Score confidence is affected by sample size. A run with 3 tested steps (2 scorable) produces a less reliable score than a run with 40 steps. The platform displays a **Low Confidence** badge when fewer than 5 steps contributed to a score.

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

When viewing the full agent report (across all scenarios and runs), the platform aggregates by taking the weighted average of the most-recent completed run per scenario for that agent. Scenarios with more steps are weighted proportionally higher.

### Campaign Score

Campaign scores aggregate across all agents and scenarios in the campaign. Each agent's contribution is weighted by the number of scorable steps across all scenarios run against that agent.

### Business Unit Score

If agents are tagged with a business unit label, the platform computes a Business Unit Score as the unweighted average of the most-recent Prevention Score per agent in that unit.

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
GET /api/scenarios/runs/{id}           — Single run: full score breakdown
GET /api/agents/{id}/score             — Current agent-level aggregated score
GET /api/campaigns/{id}/summary        — Campaign aggregate score
GET /api/compliance/scores             — Framework coverage scores
```

---

*© Audspect — Confidential — Customer Distribution*
