# Initiative Layer UI — Design

**Status:** approved by user in chat, pending written-spec review
**Origin:** follow-on to the backend-only Initiative layer sub-project (spec `2026-08-22-initiative-layer-design.md`, commits `07c02b2`..`a13a748` on `main`), which explicitly deferred all UI work as a separate sub-project.

## Problem

The Initiative layer's 6 REST endpoints are live in production but have zero frontend presence — there is no way for a user to create, browse, or manage an Initiative except via raw API calls. This spec builds that surface in `wwwroot/index.html`.

## Grounding: no Job Engine UI exists at all

Before scoping this, `wwwroot/index.html` was searched for any reference to `/api/jobs`, `/api/job-targets`, `/api/notifications`, `/api/drift` — none exist. The entire Fleet Job Engine (batch-remediation jobs, scheduling, notifications, drift, ownership) has never had a UI. This matters because `GET /api/initiatives/{id}` returns a job list, but there is nowhere to drill into a job ID, and no UI exists to create a batch-remediation job with an `initiativeId` in the first place. This shaped the scope decision below.

## Scope

**In scope:**
- New `data-tab="initiatives"` nav item, Operations section (near "Campaigns" and "Scheduled Assessments" — a deliberate choice: Initiatives is a planning/coordination concept like those, not a passive report).
- Initiatives list view: table (Name / State badge / Created by / Created at), state filter (Active / Closed / Archived / All via `?state=`), "+ New Initiative" create flow.
- Initiative detail side-drawer: header (name, state badge, contextual Close/Archive buttons), description, Progress section (percentage + raw counts), read-only Jobs table.
- Manual browser QA of the full create → filter → open → close → archive → 409-on-reopen-attempt flow before considering this done.

**Explicitly out of scope (confirmed via clarifying questions, not silently omitted):**
- **Any Job management UI** — no job creation, cancellation, retry, detail drawer, fleet-wide job list, notifications, drift, or ownership UI. The Jobs table inside an Initiative's detail drawer is read-only and exists only because the detail endpoint already returns it — it is explicitly a "related resource panel," not the start of a Jobs product surface. If a future Jobs UI ships, it can link back to its parent Initiative; this sub-project does not build that link.
- **Job creation UI changes** — no `initiativeId` picker added anywhere, since no batch-remediation creation UI exists to add it to. Assign/detach stays API-only until a Jobs UI exists.
- **"Scope/Targets" section** — the backend deliberately does not track this at the Initiative level (an initiative aggregates only `Job.State`; see the backend spec's explicit design decision). There is no data source for this, so it is not built, not faked.
- **Owner field distinct from Created By** — the API has no separate ownership concept.
- **Progress numbers in the list view** — `GET /api/initiatives` returns initiatives only, no progress. Adding it would mean either N+1 per-row calls or a backend change to batch-compute progress (like `GetAgentRiskSummary` does for jobs) — deliberately deferred. The list shows only the lifecycle state badge; progress appears once you open the detail drawer.
- **Audit/history panel** — `audit_logs` rows exist for every initiative event, but `GET /api/audit-logs` has no `resource=` filter today, so there's no query path to fetch one initiative's history without a backend change. Deferred as a small, well-scoped follow-up if actually needed later (reuses the existing table, no new one).
- **Pagination** — matches the API, which has none; reasonable for an internal tool's initiative count.

## Architecture

Pure frontend addition to `wwwroot/index.html`'s existing single-page-app pattern. No new backend work — consumes the 6 existing Initiative endpoints exactly as-is. Vanilla JS (`fetch` + string-templated HTML injection), matching every other tab in this file — no new frontend framework or build step. The detail drawer reuses the existing `.drawer-overlay`/`.drawer` CSS/JS mechanics already used for the Results/Live Run/Adversary drawers, not a new drawer implementation.

## Components

**List view** (`#initiatives` tab): table — Name / State badge / Created by / Created at. Segmented control (Active / Closed / Archived / All) maps directly to the `?state=` query param. "+ New Initiative" button. Row click opens the detail drawer — no separate per-row Actions menu; lifecycle actions live inside the drawer, matching how every other drawer in this app owns both detail and actions. Empty state: "No initiatives yet" when the filtered list is empty. State badges use the existing `.badge` class (rounded-pill, `border-radius: 999px`) with inline color overrides per state — Active uses `--success`, Closed/Archived use `--muted` — matching the exact pattern already used throughout this file (e.g. Enabled/Disabled connector badges) rather than inventing a new badge style.

**Create flow**: "+ New Initiative" opens a small drawer-form (Name + Description fields, Create button) — not a modal, consistent with this app's established drawer-only convention (no `<dialog>`/modal overlay pattern exists anywhere else in this file for creation flows of this size). On success, closes the form and refreshes the list.

**Detail drawer**: header shows Name + State badge. **Close** button shown only when `state=active`; **Archive** button shown only when `state=closed`. Both call their endpoint, then re-fetch the detail endpoint to refresh the drawer in place and refresh the underlying list row. Body: Description; Progress section rendering `percentComplete` as a bar plus the raw counts in the form `"<total> total · <completed> completed · <running> running · <failed> failed"` (any zero-value bucket omitted, matching the user's own sketch during design); read-only Jobs table (ID truncated / Type / State badge / Created / Completed) built directly from the `jobs` array `GET /api/initiatives/{id}` already returns — no separate fetch, no click-through.

## Data flow

- List tab load → `GET /api/initiatives?state=<filter>`.
- Row click → `GET /api/initiatives/{id}` (one call returns initiative + progress + jobs, already shaped for the drawer).
- Close/Archive → `POST /api/initiatives/{id}/close` or `.../archive` → re-fetch the detail endpoint → refresh drawer + list row.
- Create submit → `POST /api/initiatives` → close form → re-fetch list.

## Error handling

- Close/Archive 409 (wrong state) → inline error banner in the drawer (`"Initiative is not active"` / `"Initiative is not closed"`). Not normally reachable since the buttons are hidden by state, but handled defensively since the API — not button visibility — is the source of truth.
- Create with empty name → client-side validation blocks submit before hitting the network (mirrors the API's own `name is required` 400).
- Any fetch failure → the same inline-error pattern already used elsewhere in this file; no new error-display mechanism introduced.

## Testing

No JS test framework exists for `wwwroot` in this codebase — every prior UI sub-project this session was verified via manual browser QA (several explicitly flagged "not yet browser-QA'd" in memory rather than falsely claimed as tested). Same standard applies here: implement, then manually walk through create → list-filter → open detail → close → archive → attempt-to-reopen-a-closed-initiative-and-confirm-409 in an actual running instance, and record the real QA status in memory afterward — never claim untested UI as verified.

## Spec self-review

- **Placeholder scan:** none — every field, endpoint, and interaction above is concrete and maps to a real API shape already verified working in production.
- **Internal consistency:** the "read-only Jobs table, no drill-down" decision is stated once in Scope and referenced consistently in Components; the "no progress in list" decision is stated once and not contradicted by the detail drawer's progress section (which is explicitly allowed).
- **Scope check:** single sub-project, frontend-only, no backend changes — confirmed focused enough for one implementation plan. Job management UI, audit panel, and list-level progress are named explicitly as deferred/future work rather than left ambiguous.
- **Ambiguity check:** "does Close/Archive live in the list row or the drawer" — resolved explicitly (drawer only). "What happens to a zero-value progress bucket in the counts string" — resolved explicitly (omitted). "Is there a job click-through" — resolved explicitly (no, nothing to link to yet).
