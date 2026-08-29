# Posture Finding SLA Reporting — Design

**Status:** Sub-project D1 of the Posture/Compliance SLA initiative (Phase 9
of the original Fleet Job Engine 10-phase proposal,
[[project_endpoint_health_remediation]], Sub-project 6, 2026-08-03). Builds
directly on Sub-project A (`2026-08-26-posture-finding-sla-foundation-design.md`,
DONE, commits `92d92a3`..`08215c2`), Sub-project B
(`2026-08-29-posture-finding-sla-policy-design.md`, DONE, commits
`a31b52b`..`a8bfa88`), and Sub-project C
(`2026-08-29-posture-finding-remediation-telemetry-design.md`, DONE, commits
`87011c7`..`0e6e94f`). This sub-project was split, during brainstorming, into
D1 (this spec — API/backend only) and a future D2 (UI), mirroring how the
Initiative layer split into Sub-project 13 (backend) and 13b (UI) earlier
this session.

## Goal

Give the fleet a compliance-rate view: what fraction of posture findings get
resolved within their SLA deadline, broken down by severity, trending
month-to-month, plus a recent history of resolved episodes with their
outcome. Today a resolved `finding_slas` episode's outcome is invisible the
moment it heals — every existing endpoint (`GET /api/sla/breaches`, the SLA
fields on `ListAgentPostureFindings`/`GetPostureFinding`) only surfaces
currently-open or currently-breached episodes. This closes that gap.

## Scope

**In scope:** one new fleet-wide report endpoint, computed on read from
already-persisted `finding_slas` data. No new schema.

**Explicitly out of scope:**
- **UI** — this is D1 (API/backend) only. A `wwwroot` view is D2, a separate
  future sub-project, brainstormed once this API's real shape exists to
  build against.
- **Category or agent breakdown** — the report breaks down by `severity`
  only, matching `sla_policy`'s own dimension exactly (severity is the only
  thing that ever determined an episode's deadline; category structurally
  never participated in SLA timing, per Sub-project B's explicit decision).
- **Real pagination** for the recently-resolved list — a bounded
  `LIMIT 50`, matching `ListAgentRemediations`' existing precedent, not new
  cursor/offset machinery.
- **Any change to `TickSLABreaches`, `sla_policy`, or any existing
  endpoint** — this sub-project is purely additive.

## Historical truth vs. current state — the report's key design decision

A resolved episode's on-time/late classification uses **`resolved_at`
compared against `deadline_at`** — never the `status` column — via the
already-existing, already-tested `slapolicy.EvaluateSLABreach(deadlineAt,
resolvedAt)` (treating `resolvedAt` as the "now" argument that function
already accepts). This matters because `TickSLABreaches` only runs every 5
minutes: a finding resolved 2 minutes after its deadline but before the next
tick still has `status='active'` at the moment it resolves. Trusting `status`
for *historical* classification would misclassify that episode as on-time.
Timestamps are ground truth and never lag; `status` can lag by up to 5
minutes.

The one place `status` *is* the right source: `currentlyOpen`/`currently
breached` counts, which are genuinely asking about live operational state
right now, not history. Historical classification uses timestamps;
current-state counts use `status`. Both are correct for what they're
answering.

## Computation: new pure package `internal/slareport`

Mirrors `internal/slapolicy`'s and `internal/driftanalytics`'s shape — no
DB/network dependency, fully unit-testable, deterministic from its input:

```go
package slareport

// Episode is one finding_slas row's data relevant to reporting.
type Episode struct {
	Severity   string
	DeadlineAt time.Time
	Status     string     // "active" | "breached" | "resolved"
	ResolvedAt *time.Time // non-nil only when Status == "resolved"
}

// Stats is one bucket's aggregate numbers -- used for both the fleet-wide
// overall summary (Severity == "") and each per-severity row.
type Stats struct {
	Severity       string
	TotalEpisodes  int
	OnTime         int
	Late           int
	CurrentlyOpen  int
	ComplianceRate float64 // OnTime / (OnTime+Late) * 100; 0 if none resolved yet
}

// MonthStats is one calendar month's resolution outcomes, bucketed by
// ResolvedAt.
type MonthStats struct {
	Month          string // "YYYY-MM"
	Resolved       int
	OnTime         int
	ComplianceRate float64
}

type Report struct {
	Overall      Stats
	BySeverity   []Stats       // one row per severity with >= 1 episode
	MonthlyTrend []MonthStats  // one row per month with >= 1 resolution
}

func ComputeReport(episodes []Episode) Report
```

`ComplianceRate` is computed **only over resolved episodes**
(`OnTime / (OnTime + Late)`) — a still-open episode (active or currently
breached) counts toward `TotalEpisodes` and `CurrentlyOpen`, but is excluded
from the rate itself, since its outcome hasn't concluded. `ComputeReport`
takes no `now` parameter: every classification it makes depends only on each
episode's own already-fixed `ResolvedAt`/`DeadlineAt`/`Status`, never on the
current wall-clock time.

## API

One new endpoint, reusing the existing SLA read permission:

- `GET /api/sla/report` — `CanExecuteRemediation`.

Handler logic: fetch every `finding_slas` row
(`SELECT severity_at_start, deadline_at, status, resolved_at FROM
finding_slas`, mapped to `slareport.Episode`), call `slareport.ComputeReport`
once, then run a second, simple query for the bounded recent history
(`SELECT pf.agent_id, pf.check_id, fs.severity_at_start, fs.started_at,
fs.resolved_at, fs.deadline_at FROM finding_slas fs JOIN posture_findings pf
ON pf.id = fs.posture_finding_id WHERE fs.status = 'resolved' ORDER BY
fs.resolved_at DESC LIMIT 50`), computing each row's `onTime` boolean the
same way (`!slapolicy.EvaluateSLABreach(deadlineAt, resolvedAt)`). Response
(map-based JSON, matching this initiative's established convention — no
typed struct on the wire):

```json
{
  "overall": {"totalEpisodes": 412, "onTime": 301, "late": 58, "currentlyOpen": 53, "complianceRate": 83.8},
  "bySeverity": [
    {"severity": "Critical", "totalEpisodes": 12, "onTime": 7, "late": 5, "currentlyOpen": 0, "complianceRate": 58.3},
    {"severity": "High", "...": "..."},
    {"severity": "Medium", "...": "..."},
    {"severity": "Low", "...": "..."}
  ],
  "monthlyTrend": [
    {"month": "2026-07", "resolved": 34, "onTime": 30, "complianceRate": 88.2},
    {"month": "2026-08", "...": "..."}
  ],
  "recentlyResolved": [
    {"agentId": "...", "checkId": "...", "severity": "High", "startedAt": "...", "resolvedAt": "...", "deadlineAt": "...", "onTime": true}
  ]
}
```

## Testing

TDD, matching this initiative's established pattern:

- `internal/slareport` (no container, pure): empty input → zero-valued
  report, no divide-by-zero; all-on-time → 100% rate; all-late → 0%; mixed →
  correct rate; currently-open episodes counted in `TotalEpisodes`/
  `CurrentlyOpen` but excluded from `ComplianceRate`'s denominator;
  per-severity buckets appear only for severities with ≥1 episode; monthly
  trend correctly buckets multiple resolutions into the same/different
  months by `ResolvedAt`.
- `internal/api` (testcontainers): `GET /api/sla/report` seeded with a
  realistic mix (on-time resolved, late resolved, active, breached, across
  ≥2 severities and ≥2 resolution months) returns correct `overall`/
  `bySeverity`/`monthlyTrend` values; `recentlyResolved` returns only
  resolved episodes, newest first, respects the 50-row bound.

## Migration

None — no schema change, purely computed from existing `finding_slas` and
`posture_findings` data.
