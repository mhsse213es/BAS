# Findings — Design Spec

**Date:** 2026-06-17
**Status:** Approved-with-changes (incorporates the `findings.txt` review)

## Purpose

Turn ephemeral per-run results into a **persistent, de-duplicated, analyst-managed exposure-management layer**. Today a "finding" is derived on report-read (`reporting.buildTopFindings`) and vanishes; it has no identity, no triage state, and no history. This feature introduces a durable `findings` store that the platform auto-populates from run results, auto-heals on re-validation, and an analyst triages over time — surfaced on the dashboard, a dedicated Findings page, and campaign detail.

This is **mutable analyst state**, deliberately the opposite of the campaign rollup (derived, compute-on-read). The two must stay separate.

## Identity & de-duplication

A finding is uniquely keyed by:

```
(agent_id, technique_id, control_class)
```

`control_class` is the *expected* control derived deterministically from the technique's ATT&CK data sources (see Control mapping). The triple is stable, so the same gap observed across many runs collapses into **one** finding that accumulates occurrences rather than duplicating.

To keep historical findings interpretable after a control migration (e.g. Defender → CrowdStrike), the finding stores a **`security_product_snapshot`** — the agent's relevant installed product(s) at creation time — without putting it in the key (which would fragment findings on inventory churn). `productFingerprint`-in-key is a documented future option, not v1.

## Generation (persist-on-ingest)

Findings are created/updated inside `SubmitScenarioResult` (`handlers.go:1167`) — the single point where a run's results are persisted (REPLACE semantics, idempotent). For each result the server classifies the per-technique outcome the same way the kill-chain / donut do:

| Result | exposure_state | Finding? |
|---|---|---|
| pass / blocked (Prevented) | — | No — triggers **auto-heal** |
| fail + detected (Detected-only) | `detected_only` | Yes |
| fail + undetected (Missed) | `missed` | Yes |
| error / skipped | — | Ignored |

**Severity is the technique's own severity, never downgraded.** Detected-only vs missed is captured by `exposure_state`, so a Critical technique that was detected-but-not-blocked still reports **Critical · Detected Only** (accurate risk, per the review). When a key is observed as both `missed` and `detected_only` across runs, the finding keeps the **worst** (`missed` > `detected_only`).

**Idempotency:** the finding stores `last_run_id`. Re-ingesting the same run (REPLACE) does **not** increment `occurrence_count`; a new run id does.

**Out-of-order protection:** the finding stores `last_observed_at` (the driving run's execution time). State transitions only apply when the incoming run is **newer** than `last_observed_at`. A late-imported older run never overwrites newer state and never heals a finding.

**`source_type`** is derived per result from the step's framework (`scenario_runs.step_meta`): ART → `atomic`, Caldera → `caldera`, otherwise → `custom`. `manual` is reserved for future manually-recorded validations.

## Control mapping

Each technique's authoritative ATT&CK data sources map to one `control_class` via a fixed priority (first match wins, default Endpoint):

1. **Identity · SIEM/IdP** — Logon Session, Active Directory, User Account, Authentication logs
2. **Network · NDR/Firewall** — Network Traffic, Network Connection Creation, Network Flow
3. **DNS** — Domain Name, DNS
4. **Cloud/Email · CASB** — Cloud Service, Cloud Storage, SaaS, Application Log (email/office)
5. **Endpoint · EDR** — Process, Command, Script, Module, File, OS API (and the default)

The finding stores **both** the raw `attack_data_source` (the data sources observed) **and** the derived `control_class`, so a future remapping changes new findings without rewriting history. The detail view additionally shows the agent's matching installed product (from `agents.security_products`) as live context.

## Lifecycle

States: **Open → Triaged → Remediated → Risk-accepted.**

- **Create:** a qualifying result with no existing finding → `open`.
- **Recur:** existing `open`/`triaged` → bump `last_seen`, `occurrence_count` (per new run), refresh `last_run_id`/`last_campaign_id`, keep worst `exposure_state`.
- **Auto-heal:** same key later **Prevented** in a *newer* run → `remediated`, stamp `resolved_at`, `resolved_by = "system"`, `resolved_reason = "re-validated prevented"` — **unless** status is `risk_accepted` (sticky; analyst's decision stands).
- **Reopen (regression):** a `remediated` finding that **misses again** in a newer run → `open`, clear `resolved_at`, increment `reopened_count`. `risk_accepted` stays put.
- **Manual:** an analyst sets `triaged` / `risk_accepted` / `remediated` via the API, recording `resolved_by` (the user) and an optional `resolved_reason`.

`risk_accepted` is sticky against both auto-heal and regression — only an analyst moves it.

## Schema — `findings` table

```
id                        text PRIMARY KEY            -- gen_random_uuid()::text
agent_id                  text NOT NULL
technique_id              text NOT NULL
control_class             text NOT NULL               -- Endpoint | Network | Identity | DNS | Cloud
technique_name            text NOT NULL DEFAULT ''
tactic                    text NOT NULL DEFAULT ''
severity                  text NOT NULL DEFAULT 'Medium'   -- Critical|High|Medium|Low (technique severity, unmodified)
exposure_state            text NOT NULL DEFAULT 'missed'   -- missed | detected_only (worst observed)
status                    text NOT NULL DEFAULT 'open'     -- open | triaged | remediated | risk_accepted
source_type               text NOT NULL DEFAULT ''         -- atomic | caldera | custom | manual
attack_data_source        jsonb NOT NULL DEFAULT '[]'      -- raw ATT&CK data sources at creation
security_product_snapshot jsonb NOT NULL DEFAULT '[]'      -- agent's relevant products at creation
occurrence_count          int  NOT NULL DEFAULT 1
reopened_count            int  NOT NULL DEFAULT 0
last_run_id               text
last_campaign_id          text
first_seen                timestamptz NOT NULL DEFAULT NOW()
last_seen                 timestamptz NOT NULL DEFAULT NOW()
last_observed_at          timestamptz NOT NULL DEFAULT NOW()   -- driving run's execution time (out-of-order guard)
resolved_at               timestamptz
resolved_by               text                                 -- "system" | <user id>
resolved_reason           text
created_at                timestamptz NOT NULL DEFAULT NOW()
UNIQUE (agent_id, technique_id, control_class)
```

Indexes: `UNIQUE(agent_id, technique_id, control_class)`, `idx_findings_status_sev (status, severity)`, `idx_findings_campaign (last_campaign_id)`.

## API

Read = viewer+; mutate = analyst+. Generation is internal (no public create).

- `GET /api/findings` — list with optional `status`, `severity`, `agentId` filters; ordered by severity then `last_seen` desc.
- `GET /api/findings/{id}` — one finding + technique enrichment (`attackdata.Lookup`) + the agent's live matching product.
- `POST /api/findings/{id}/status` — body `{status, reason?}`; validates the transition (e.g. can't set `remediated` on a non-existent finding), records `resolved_by` = the requesting user. Analyst+.

## Surfacing

- **Dashboard:** replace the greyed stubs — the **Open findings** KPI tile (count `open`, real) and **Top exposure gaps** (top Open by severity, links into the finding). The dashboard KPI row stays at four tiles; "Reopened" lives on the Findings page (below) to avoid overloading it.
- **Findings page** (new tab `findings`): hero + 4 stat tiles (**Open / Critical / Reopened / Remediated-30d** — Reopened = currently-open findings with `reopened_count > 0`, the "gap came back" metric management tracks; the Triaged count is still visible on its filter segment), status-filter segments (All/Open/Triaged/Remediated/Risk-accepted with counts), table (Finding · Technique · Severity+exposure · Control · Agent · Status · Age), and a detail drawer (technique enrichment, agent product, occurrences/first-seen/last-seen, regression count, status actions).
- **Campaign detail → Recommended next steps:** show **Top Open findings** and **Top Regressions** for that campaign's runs (not all findings — avoids noise on large campaigns).

## Testing

- Pure unit tests (new `internal/findings` package) for the classifier: result → (finding? exposure_state? severity unchanged?), the data-source→control_class priority map, and the transition engine (create / recur / auto-heal / reopen / risk-accepted-sticky / out-of-order-ignored / idempotent re-ingest).
- `internal/api` test for the status-transition handler (valid/invalid transitions, role gate).
- No tests against a real/prod Postgres; the schema migration is exercised by the existing `internal/db` test harness.

## Non-goals (v1)

Assignee, threaded comments, full status-change audit trail (beyond `resolved_by`/`resolved_reason`), SLAs, notifications, ATT&CK Navigator export of findings, and `productFingerprint` in the dedup key. All are natural follow-ups once the core store proves out.

## Architecture note

Generation is **persist-on-ingest**, not compute-on-read. Campaign rollups are derived state (safe to recompute); findings are mutable analyst state (triage decisions) that cannot be re-derived. Keeping these domains separate is intentional.
