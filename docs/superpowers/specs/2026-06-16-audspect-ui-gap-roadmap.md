# Audspect UI Gap Roadmap — `audspect.html` (vision) → `wwwroot/index.html` (product)

**Date:** 2026-06-16
**Purpose:** Map every capability in the `audspect.html` design mockup to the *real* state of `orchestrator/wwwroot/index.html` and its Go backend, with honest effort + backend cost, so we can execute the gap in deliberate waves rather than blindly skinning a dummy-data prototype.

> `audspect.html` is a **dummy-data UI mockup with zero backend** (design north-star). `index.html` is the **shipping dashboard** wired to the Go orchestrator. "Advanced" in the mockup is mostly *unbacked UI*; closing the gap is therefore part frontend-port, part net-new feature engineering, and (in one case) a strategic call against our air-gapped, dumb-executor architecture.

---

## What index.html ALREADY has (verified against code)

Tabs: **Dashboard, Scenarios, Runs, Compliance, Agents, Users, Settings**. Plus: run-results drawer (verdict score panel, detection coverage, **dual-rail kill-chain** ✅ shipped, key findings, recommendations), full HTML/PDF report + audit-pack, per-run JSON/CSV export, posture-check picker, step picker, scenario builder/upload/clone, agent detail + operational/security logs + telemetry, user CRUD + reset-password, threat-intel connector (MISP/OpenCTI sync), Caldera + ART content management, posture catalog.

Backend routes already exist for: scenarios CRUD + run + cancel, runs list + report(.json/.html/.pdf) + export + events + **detections**, agents + logs + telemetry + download, compliance frameworks + report, users CRUD, connector status/sync, caldera, ART content status/reseed, posture catalog.

So the real gaps below are narrower than the mockup's 11-page nav suggests.

---

## Legend

- **Effort:** S = hours · M = 1–3 days · L = multi-day/week+ (real feature, design needed)
- **Backend:** None (pure frontend) · Minor (small handler/column) · Major (new tables/subsystem/agent change)
- **Status:** ✅ done · 🟡 partial today · ⬜ absent

---

## Gap table

| # | Capability (audspect) | index.html today | Effort | Backend | Notes / dependency |
|---|---|---|---|---|---|
| 1 | **Dual-rail kill-chain** | ✅ shipped | — | — | Done (`buildKillChain` + run drawer). |
| 2 | **Visual system** — verdict-color consistency, sparkline/donut/gauge/bars SVG, distinctive type (Space Grotesk/JetBrains) | 🟡 navy theme, fewer charts | M | None | Pure CSS/SVG. Biggest *perceived* upgrade for the least risk. Apply dual-rail/verdict palette everywhere. |
| 3 | **Command palette (⌘K)** | ⬜ | S | None | Self-contained; routes to existing tabs/actions. High polish, cheap. |
| 4 | **Dashboard upgrade** — clickable stat tiles, posture gauge + trend, control-effectiveness donut, live-runs list, top-gaps, kill-chain preview | 🟡 basic dashboard | M | Minor | Most data exists (scores, runs, detection). Trend needs run history (already in report engine). |
| 5 | **ATT&CK Coverage matrix** (enterprise grid colored by verdict, filter, technique modal) | 🟡 tactic heatmap in report | M | Minor | Need a per-technique "last validated verdict" rollup endpoint across runs. ATT&CK STIX already bundled. |
| 6 | **Multi-step Run Wizard** (scenario→targets→options→review, monitor/prevent, guardrails) | 🟡 single run modal + pickers | M | Minor | Backend run dispatch + lab/live gating exist. Mostly a UX re-skin of current modal; "monitor vs prevent" mode may need a run flag. |
| 7 | **Reports builder** (type/scope/section toggles/format) + history table | 🟡 full report + PDF + audit-pack exist | S–M | Minor | Wrap existing report endpoints in a builder modal; add a generated-reports history table (needs a small `reports` table or list from runs). |
| 8 | **Agents page upgrade** + deploy-agent modal (install commands per OS) | 🟡 agents table + detail | S | None | Deploy modal is static install snippets; agent download route exists. |
| 9 | **Scheduling UI** (once/recurring) | ⬜ (connector has a poller) | M | Major | Needs a scheduled-runs table + a scheduler tick to dispatch + UI. Connector scheduler is a precedent. |
| 10 | **Campaigns as a first-class entity** (group N runs across N agents; aggregate progress/result mix; campaign detail) | 🟡 per-run "Runs" tab | L | Major | **Backbone feature.** New `campaigns` model (1 campaign → many runs), fan-out dispatch, progress aggregation, detail view. Findings/Reports/Dashboard "live campaigns" all hang off this. |
| 11 | **Findings as tracked objects** (triage/accept/age/status, cross-linked) | 🟡 findings derived per-report, not persisted | L | Major | New `findings` table + lifecycle (open/triaged/remediated/accepted), de-dupe across runs, links to run+agent+technique. Enables Remediation + dashboard "open findings". |
| 12 | **Remediation workspace** (prioritized fixes, impl steps, resolves-findings, re-validate, Jira) | 🟡 recommendations inside report | L | Major | Depends on #11. Persisted remediations, re-validate = launch linked scenario, optional Jira via a connector. |
| 13 | **Integrations / SIEM-EDR alert correlation** (Splunk/CrowdStrike/Sentinel connect + "94% detections matched") | ⬜ (agent-local detection only) | L | Major | **⚠️ Strategic decision required.** This contradicts our air-gapped, agent-is-dumb-executor model (we deliberately do agent-local detection, no SIEM creds). Either (a) keep out of scope, (b) add *optional* read-only connectors for environments that allow it. Needs your call before any build. |
| 14 | **Settings expansion** — Team & roles (RBAC), Notifications rules, Safety & guardrails, API tokens | 🟡 users + basic settings | M | Major | RBAC roles + token issuance are real backend work; notification rules need a delivery channel (Slack/email/webhook). |
| 15 | **Notifications center** (bell + activity feed) | ⬜ | M | Major | Needs an events/notifications store + WS push (WS hub exists). |
| 16 | **Env switcher** (Prod/Staging/Lab) | ⬜ | varies | — | Cosmetic unless we actually support multi-environment tenancy — likely out of scope for on-prem single-tenant. |

---

## Architectural decisions to settle BEFORE building (not UI choices)

1. **Campaigns model (#10).** Is a "campaign" = one scenario fanned out to many agents, or many scenarios too? This shapes the schema and is the dependency for #4, #11, #12. → needs a brainstorm.
2. **Findings persistence (#11).** Today findings are *recomputed* from each run's results (stateless, honest). Tracking them as mutable objects (triage/accept) introduces lifecycle + de-dupe + drift-vs-truth questions. → design call.
3. **Integrations (#13).** Direct conflict with the air-gapped / dumb-executor / agent-local-detection architecture. **Do not build without an explicit decision.** Recommend: defer, or scope to optional read-only correlation for connected sites only.
4. **RBAC + tokens (#14).** Real auth surface; security-sensitive. Spec separately.

---

## Recommended waves

- **Wave 1 — Close the *look* gap (frontend-only, low risk):** #2 visual system, #3 command palette, #8 deploy modal, #6 run-wizard reskin, #4 dashboard upgrade. *Outcome: index.html visually matches audspect; zero backend risk; no dead buttons.*
- **Wave 2 — Coverage + reporting depth (minor backend):** #5 ATT&CK matrix rollup, #7 reports builder + history. *Outcome: the analyst-facing surfaces.*
- **Wave 3 — Campaigns backbone (large, design-first):** brainstorm → spec → plan → build #10. Unlocks dashboard "live campaigns" and is prerequisite for findings.
- **Wave 4 — Findings + Remediation lifecycle:** #11 then #12, each design-first.
- **Wave 5 — Platform (decision-gated):** #9 scheduling, #14 RBAC/tokens, #15 notifications, and the #13 integrations decision.

Each Wave-3+ item goes through the normal brainstorm → spec → plan → subagent-driven build. Wave-1 items are direct ports and can be batched.

---

## How to use this doc

Pick the wave/order you want. Wave 1 I can start immediately as direct frontend ports (no design gate). Anything in Waves 3–5 I will brainstorm and spec with you first — they are features, not skins, and two of them (Integrations, Findings persistence) need an explicit architectural decision from you before a line of code.
