# TCF Phase 10 — Live Threat Coverage Design

**Goal:** Give customers an honest answer to "given the threats currently known to us, which ones can we meaningfully simulate with available content, and where are the gaps?" — using the live threat-intelligence pipeline, not the static embedded ATT&CK dataset the existing Coverage page shows today.

## 1. Current-state evidence (gap analysis, verified against code)

### 1.1 Existing customer-facing surfaces
No dedicated threat-exposure page exists. The closest thing is the Coverage page (`orchestrator/web/src/features/coverage.js`), backed by `GET /api/coverage/analytics` (`handlers.go:4531`), `GET /api/attack/matrix` (`routes.go:337`), and `GET /api/techniques/unified` (`handlers.go:4391`, `routes.go:264`) — all `tierAny` (every authenticated user, not admin-only; confirmed via `rbac_matrix_test.go` rows 89/92/126). Its technique drilldown (`coverage.js:353-362`) shows "known actors" sourced from `attackdata.Groups` (`attackdata.go:106,310`) — the **static embedded MITRE ATT&CK dataset**. This has zero connection to the live `threatidentity`/`evidence` pipeline Phase 9 just instrumented. This is the central problem Phase 10 fixes.

### 1.2 Threat relevance
Exists, but global per-deployment, not per-customer: `Generator` (`generator.go:56-62,402-412`) tags generated content "sector-relevant"/"region-relevant" against the deployment's own configured sectors/regions. Consistent with the standing on-prem, single-tenant architecture (§1.8) — no change needed here.

### 1.3 Technique → content → run-evidence chain
**More already exists than either prior investigation found.** Three real, already-wired pieces:
- `content_version_threats(content_version_id, threat_id, relationship_kind)` (`threat_identity_schema.go:211-220`, `relationship_kind IN ('generated_for','emulates')`) — a direct, FK-constrained threat↔content-version join, with real production writers (`contentregistry/content_threats.go`, `contentregistry/store.go` — this is Phase 2C's `emulatesLinks` work, not dead code).
- `threat_techniques(threat_id, technique_id, last_seen_at, status)` (`evidence_schema.go:102-113`) — the active-technique projection, already used by `evidence.ActiveTechniques` (`generation.go:14`).
- `scenario_runs.content_version_id text REFERENCES content_versions(id)` (`content_registry_schema.go:158`, indexed at line 164) — **a real, already-populated FK**, not a coincidental string match. Correction to an earlier gap-analysis finding in this same design thread: `TriggerScan` (`handlers.go:1481-1484`) already sets it from `ev.VersionID` (`scenario.ExecutableVersion.VersionID`, `registry.go:27`), resolved via `Engine.ResolveExecutable` (`engine.go:79`).

**Real, narrower gap found:** two other dispatch paths that also `INSERT INTO scenario_runs` — `remediation_dispatch.go` and `variant_handlers.go` — do not set `content_version_id` at all. Runs dispatched through those paths (remediation-verification re-runs, variant-depth expansions) will not join to a specific content version. This is a secondary signal relative to "was this threat's primary content ever run," and is named here as a known, accepted limitation (§4), not fixed in this phase.

So the full chain `threat → content_version_threats → content_versions → scenario_runs.content_version_id` is queryable today for the primary dispatch path. Phase 10's job here is assembly and honest presentation, not new relational plumbing.

### 1.4 Evidence freshness
**Confirmed gap.** `threats.last_seen_at`/`threats.first_seen_at` (`threat_identity_schema.go:133-134`) and `threat_techniques.last_seen_at` (`evidence_schema.go:106`) exist in the DB. Grepping every API handler and frontend `.js` file for `last_seen_at` finds zero customer-facing uses. Phase 10 surfaces this for the first time.

### 1.5 Content availability (executable vs. draft)
**Already works, already customer-facing — not a gap.** `GET /api/scenarios` (`tierAny`) returns `contentregistry.Summary` (`validations.go:178-193`) with `ExecutableVersion`/`ExecutableLifecycle`/`ExecutableTrust` distinct from `LatestVersion`/`LatestLifecycle`/`LatestTrust`. Phase 10 reuses this distinction rather than rebuilding it.

### 1.6 Validation status
**Confirmed near-total gap, inherited from the (deferred) Phase 7 findings.** Only a STRUCTURAL check runs at content creation (`createVersion`, `store.go:287-304`); the `VALIDATING`/`VALIDATED` lifecycle states have zero production callers. Honest Phase 10 behavior: report validation as `"structural-only"` for everything, never imply dynamic/behavioral validation happened, since Phase 6 (the actual validation lab) is unbuilt. The roadmap itself anticipated this ("provided the UI labels evidence limitations honestly").

### 1.7 Terminology collision risk
`evidence/observations.go`'s `RecordObservation`/`observed_at` (`observations.go:10-36`) already means "an intel source reported seeing this" (a MISP/OpenCTI sighting). Phase 10 must not reuse "observed" for a second, different meaning ("we ran a scenario and saw a detection outcome"). This spec avoids the observed/inferred/unknown framing entirely (see §5) and uses concrete field names instead (`lastSeenAt` for intel-sighting freshness, `lastRunAt` for execution freshness, `hasExecutableContent`, etc. — §2.1) — a reasonable customer-facing design does not need a new abstract three-state epistemology layered on top of the existing data; it needs each fact shown plainly, with an honest `null`/absent value where a fact doesn't exist.

### 1.8 Multi-tenancy
Confirmed single-tenant-per-deployment. `tenant_id` columns exist but are vestigial (always `'default'`, no query varies on it). No multi-tenant design needed.

## 2. Design

### 2.1 New read-only endpoint: `GET /api/threats/exposure`

`tierAny`, matching the existing Coverage/techniques-unified RBAC tier (§1.1) — this is a read-only view of data every authenticated user can already see pieces of elsewhere.

Query params: `status` (default `active`, matching `threats.status`), `limit`/`offset` for pagination (bounded, same convention as `GetCoverageAnalytics`'s `?limit=` — default 20, max 100).

Response: one entry per active threat —

```json
{
  "threatId": "thr-...",
  "title": "APT29",
  "firstSeenAt": "2026-09-01T00:00:00Z",
  "lastSeenAt": "2026-10-13T08:00:00Z",
  "techniques": [
    {
      "techniqueId": "T1059",
      "lastSeenAt": "2026-10-13T08:00:00Z",
      "hasExecutableContent": true
    }
  ],
  "content": [
    {
      "contentVersionId": "cv-...",
      "contentId": "intel-...",
      "relationshipKind": "generated_for",
      "lifecycle": "PUBLISHED_LOCAL",
      "trust": "LOCAL_TRUSTED",
      "isExecutable": true,
      "validation": "structural-only",
      "lastRunAt": "2026-10-10T12:00:00Z",
      "runCount": 3
    }
  ]
}
```

- `techniques[].hasExecutableContent`: true only if at least one row in `content` for this threat is both `isExecutable` and covers that technique (technique coverage per content version comes from the scenario's own existing technique tags — no new table needed, this is read-only aggregation over what already exists).
- `content[].isExecutable`: reuses the registry's existing `Executable()` gate logic (`lifecycle.go:75-85`) — not re-derived ad hoc.
- `content[].validation`: always `"structural-only"` today (§1.6) — a literal, honest constant, not a computed field pretending to be more granular than the system actually is.
- `content[].lastRunAt`/`runCount`: from `scenario_runs WHERE content_version_id = $1`, `MAX(started_at)`/`COUNT(*)`. Absent (`null`/`0`) when no run exists for that content version — including, honestly, for variant/remediation-dispatched runs that never recorded `content_version_id` (§1.3's named limitation) — this endpoint reports what it can actually join to, not an inferred superset.
- A threat with zero rows in `content` renders with an empty `content` array — the frontend shows this as "no content available for this threat" rather than hiding the threat or guessing.

### 2.2 Query implementation

One function, `evidence` or a new small package (`internal/exposure` — a single new file, not a new subsystem) that:
1. Lists active threats (`SELECT * FROM threats WHERE status = $1 ORDER BY last_seen_at DESC LIMIT $2 OFFSET $3`).
2. For each, `SELECT * FROM threat_techniques WHERE threat_id = $1 AND status = 'active'`.
3. For each, `SELECT cvt.*, cv.* FROM content_version_threats cvt JOIN content_versions cv ON cv.id = cvt.content_version_id WHERE cvt.threat_id = $1`.
4. For each content version found, `SELECT MAX(started_at), COUNT(*) FROM scenario_runs WHERE content_version_id = $1`.
5. Technique-level `hasExecutableContent` is computed in Go by cross-referencing each content version's own `content_versions.technique_ids text[]` column (`content_registry_schema.go:69`, populated and validated against the catalog at creation time, `store.go:256,356`) against the threat's active technique list — a plain array read, no YAML parsing needed.

This is N+1-shaped (one query per threat for techniques, content, run-aggregate) rather than one giant join, matching this codebase's existing style in `analytics/factory.go`'s per-metric query functions rather than forcing one mega-query. Acceptable at the data volumes this system operates at (an "active threats" list is not expected to be in the thousands); revisit only if it proves slow in practice.

### 2.3 Frontend: a new, clearly separate section

`coverage.js` gets a new section — not a replacement of the existing static-ATT&CK technique drilldown, which stays as-is, relabeled in the UI as a "technique library" or similar (theoretical/reference view). The new section is sourced from `/api/threats/exposure` and visually/structurally distinct, so a user never mistakes the live threat list for the full ATT&CK matrix or vice versa.

## 3. Acceptance criteria

1. `GET /api/threats/exposure` returns only threats with `status = 'active'` by default, each with real `firstSeenAt`/`lastSeenAt` from the `threats` table — no synthetic/placeholder dates.
2. A threat with no `content_version_threats` row renders with `content: []`, never omitted from the list and never silently defaulted to "covered."
3. `content[].isExecutable` matches exactly what `GET /api/scenarios`' `ExecutableVersion` would say for the same content version — no second, divergent definition of "executable."
4. `content[].validation` is always the literal string `"structural-only"` — never a value implying dynamic validation occurred, since none can today.
5. `content[].lastRunAt`/`runCount` only count runs with a real, non-NULL `scenario_runs.content_version_id` — never derived from a `scenario_id` string match.
6. The existing static-ATT&CK technique drilldown in `coverage.js` is unchanged in behavior, only relabeled/repositioned so it's visually distinct from the new live section.
7. The endpoint is `tierAny` and has a `rbac_matrix_test.go` row — no RBAC drift introduced.
8. `?limit=`/`?offset=` are bounded the same way `GetCoverageAnalytics` bounds `?limit=` (default 20, max 100).

## 4. Out of scope (this phase)

- Fixing `remediation_dispatch.go`/`variant_handlers.go` to also set `content_version_id` on insert — named as a known limitation (§1.3), not fixed here. Those runs simply won't appear in `lastRunAt`/`runCount` for now.
- Any new "observed vs. inferred vs. unknown" abstraction layer (§1.7) — this spec uses concrete, honestly-absent fields instead.
- Phase 6's actual dynamic validation lab — `validation` stays a literal constant until that phase exists.
- Any detection-efficacy claim (prevented/detected/missed) — that's the existing Coverage page's run-result matrix, a different, already-built concern this phase doesn't touch or duplicate.
- Multi-tenant filtering — confirmed not needed (§1.8).
- Rebuilding or removing the static ATT&CK technique-library view — it stays, just relabeled.

## 5. Review Focus

- A threat with active techniques but zero `content_version_threats` rows — confirm the response is an honest empty `content: []`, not an error, not an omitted threat, not a false "covered" inference.
- A content version whose `lifecycle` is `DRAFT` (not yet executable) — confirm `isExecutable: false` and that it still appears (drafts are real, relevant information: "we're working on content for this threat"), rather than being filtered out.
- A technique present in `threat_techniques` that no content version's `technique_ids` array contains — confirm `hasExecutableContent: false`, not an incorrect `true` from a loose/partial match.
- A content version reached only through `remediation_dispatch.go`/`variant_handlers.go` runs (no `content_version_id` set on those rows) — confirm `lastRunAt`/`runCount` correctly show no-run rather than silently including an unrelated run via a fallback string match.
- Pagination (`?limit=`/`?offset=`) behavior at the boundary (0 active threats, exactly `limit` threats, more than `limit`) — confirm no off-by-one and no unbounded query if `limit` is omitted or garbage.
