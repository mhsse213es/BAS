# Audspect / BAS — Assessment

Independent codebase, maturity, security, and competitive assessment.
**Prepared:** 2026-09-26, from a full static review of the repository plus a live local deployment.

> Secret values are intentionally omitted from every document here.

## Contents

| File | What it is |
|---|---|
| [AUDSPECT_ASSESSMENT_REPORT.md](AUDSPECT_ASSESSMENT_REPORT.md) | Full report: local setup, architecture, maturity scorecard, vision-vs-reality, and the **findings register with root-cause fixes** (groups A–J). |
| [AUDSPECT_Findings_Tracker.xlsx](AUDSPECT_Findings_Tracker.xlsx) | Live Excel tracker — Dashboard (auto-updating KPIs + charts), Findings Tracker (dropdowns, auto risk score, conditional formatting), Legend. Manual issue tracking. |
| [COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) | Honest comparison vs Cymulate / Picus / AttackIQ / SafeBreach; corrects the "only on-prem BAS" claim. |
| [FOCUS_AREAS_STRATEGY.md](FOCUS_AREAS_STRATEGY.md) | Where to focus to win: turning gaps into moats (air-gapped + compliance-native + Indian BFSI). |
| [SECRET_ROTATION_RUNBOOK.md](SECRET_ROTATION_RUNBOOK.md) | Step-by-step: rotate the exposed credentials and purge them from git history (finding A1). |

## Headline

- **Maturity:** Beta / release-candidate for a single-tenant on-prem appliance. High engineering quality (~1:1 test ratio, parameterized SQL, strong crypto/RBAC, honest docs); held back by a few fixable architectural gaps, not by code quality.
- **Findings:** 21 tracked — **5 Critical, 3 High, 8 Medium, 5 Low.** Fix order: secrets → agent trust model → web/API hardening → multi-tenancy/signing/guardrail → maturity → hygiene.
- **Top risk:** live secrets committed to the repo, and an endpoint-agent trust model that allows fleet-wide SYSTEM RCE. Both fixable at the root without changing intended behavior.
- **Positioning:** not a peer to the giants on breadth; a credible, defensible niche leader for air-gapped, compliance-native Indian BFSI.

## ⚠️ Immediate action (before anything else)

Rotate/revoke and purge from git history the credentials committed in the repo root (`keys.txt`, `tenantID.txt`, `setting.json`, `Model Configurator.txt`). See finding **A1** in the report.
