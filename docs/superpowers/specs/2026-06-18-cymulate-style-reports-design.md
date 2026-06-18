# Cymulate-Style Report Redesign — Design Spec

**Goal:** Restructure the per-agent posture report (and shared components, reused later for per-assessment reports) into a high-end BAS report matching the structure validated in `reports.txt`, backed only by data we honestly compute.

**Reference:** `reports/` (Cymulate Email Gateway / WAF / Data Exfiltration). **Review/decisions:** `reports.txt` (product-owner sign-off with modifications).

---

## Decisions (from reports.txt — authoritative over earlier choices)

- **Detection Score is elevated** alongside Prevention Score in the Assessment Summary.
- **Tactic Summary adds Coverage** (techniques tested) next to Prevented %, Detected %, MTTD.
- **No Benchmark section** — removed entirely (no placeholder, no fabricated peers).
- **Glossary → Technical Appendix at the very end**, never a prominent "Appendix A".
- **New required sections:** Executive Conclusion, Top Risk Drivers, Simulation Reliability.
- **Score-impact wording is attribution, not prediction:** "Credential Access failures **account for** N score points" — never "fixing adds N".

## Honesty constraints (standing rules)

- **Score-impact is mathematically exact.** `PreventionScore = weightedPassed/weightedTotal×100` (severity-weighted, ERROR/SKIPPED excluded — `models.ComputeScore`). Points currently lost to a group G = `(Σ severityWeight(G's FAILs) / weightedTotal) × 100`. This is the share of the 100-pt scale lost to G's failures — exactly the attribution reports.txt allows.
- **Detection Score = N/A, not 0, when no telemetry was observed** (`DetectionSummary.TelemetryObserved == false`). An old/offline agent ≠ "evaded the SOC".
- **CVE shown only where the technique genuinely carries one** (no auto-mapping/fabrication).
- **No section is rendered from absent data** — empty builders → the section states "not available", never invents.

---

## Report structure (posture report)

1. **Executive Summary** — cover (existing).
2. **Executive Conclusion** — generated narrative (least-protected tactics, key unprevented objectives, telemetry gaps, top fixes). First thing a CISO reads.
3. **Assessment Summary** — Prevention Score · **Detection Score** · Exposure Level (plain word) · **Penetration Ratio** (`failed/tested`, %) · Trend (Δ vs previous + sparkline history). Secondary: tactic coverage, defense rate, kill-chain amplifier.
4. **Top Risk Drivers** — ranked techniques driving score loss (technique, tactic, severity, score-points attributable).
5. **Risk Summary** — failure counts by severity + business-objective risk bands (`ObjectiveRisks`).
6. **Asset Context** — agent metadata (host, OS, IP, env, security tools, last update).
7. **Attack Path Analysis** — `AttackPath` (observed unprevented traversal across kill-chain phases).
8. **Tactic Summary** — per tactic: Coverage (tested), Prevented %, Detected %, MTTD, risk weight.
9. **Assessment Insights** — Most / Least protected tactic + telemetry-coverage note.
10. **Action Plan** — remediations ranked by score-points attributable (honest phrasing).
11. **Regulatory Compliance Status** — existing table (testable/manual aware).
12. **Scenario Run History** — existing.
13. **Technical Findings** — detailed Critical/High failures (existing `TopFindings`).
14. **Technical Appendix** — ATT&CK technique glossary for techniques seen (authoritative `attackdata` enrichment; CVE only where real).
15. **Forensic CSV Export** — separate technical CSV artifact (one row per result: timestamp, tactic, technique, status, detection, risk, mitigation, payload, hashes, CVE-where-real, ATT&CK URL).

## New computations (engine.go), all json-tagged on `FullReport`/`ExecutiveSummary`

- `ExposureLevel` — `≥80 Low · 60–79 Medium · 40–59 High · <40 Critical` from prevention score.
- `DetectionScore` + `DetectionMeasured` — `Detected/(ExecutedUnprevented)`; N/A when no telemetry.
- `PenetrationFailed/Tested/Pct`.
- `ExecutiveConclusion` (narrative).
- `TopRiskDrivers []RiskDriver{TechniqueID,Name,Tactic,Severity,ScorePoints}`.
- `Insights{Most,Least TacticInsight{Tactic,Pct,Tested}}`.
- `ActionPlan []ActionItem{Group,ScorePoints,Failures,Recommendation}` (ranked desc).
- `Reliability{Attempted,Valid,Errored,Skipped,Confidence}`.
- `TacticEntry` enriched with `Detected`, `DetectedPct`, `MTTDMs`.
- `Glossary []GlossaryEntry{TechniqueID,Name,Tactic,Description,Detection,DataSources,Mitigations}`.
- Export `models.SeverityWeight(severity) int` for exact attribution.

## Reusable components (for later per-assessment reports)

Exposure mapping · detection-score · penetration ratio · insight (most/least) · score-impact ranker · reliability · glossary builder · forensic-CSV writer — all live in `reporting` and are report-source agnostic.

## Out of scope (now)

Per-assessment (per-scenario) reports — phase 2, built on these shared components once landed.
