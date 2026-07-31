# IOC Relationships & Analytics — Design Spec

**Phase B of the IOC Handling initiative** (source vision: `iochandling.txt`, repo root, §10-13/18/20/24).
Phase 0+A (canonical `IOC` model, `iocs`/`ioc_sightings` tables, extraction from
`DetectionAlert.CommandLine`/`ProcessName`, `GET /api/iocs` flat search) is **done** —
`c309b00`, `38c5c6c`, `5ad41e4`. This phase reads and extends that data; it does not
replace it.

## Goal

Make the IOC registry built in Phase 0+A queryable by relationship (§12/§20), searchable
by more than `type`/`value`/`scenarioId`/`agentId` (§18), and summarized on a dashboard
(§24) — reusing three systems that already do exactly this job for other entities in this
codebase, rather than building parallel infrastructure.

## Investigation: three existing systems, not a greenfield build

- **`internal/threatgraph`** (`types.go`, `assemble.go`) is a generic, already-shipped
  graph: `Node{ID, Type, Label}`, `Edge{From, To, Relationship}`,
  `Neighborhood{Nodes, Edges}`. It already has `actor`/`campaign`/`malware`/`tool`/
  `technique` node types and a single dispatch function, `Lookup(ctx, pool, nodeType, id)`,
  exposed at the *existing* `GET /api/knowledge-graph/{type}/{id}`
  (`internal/api/threatgraph_handlers.go`, `routes.go:218`, `tierAny`). Adding an `ioc`
  node type here is strictly additive — no new route, no new engine, no new Node/Edge
  vocabulary. This directly satisfies §12 (Correlation) and §20 (Relationships): both are
  "build chains between related entities," which is exactly what `Neighborhood` already
  models.
- **`internal/analytics`** is not one engine — it's 7 small, single-purpose files
  (`risk.go`, `compliance.go`, `campaigns.go`, `exposure.go`, `detection.go`,
  `threatintel.go`, `endpoint.go`), each exposing one function that a thin
  `internal/api/*_handlers.go` handler calls and returns via `respond(w, result)`
  (e.g. `endpoint_posture_handlers.go:12-19`). An 8th file, `ioc.go`, plus a matching
  `GET /api/analytics/iocs` handler, is the established shape for §24's dashboard —
  not a new subsystem.
- **`internal/search`** (`search_documents`, full-text via `to_tsvector`, one row per
  titled entity — scenarios, actors, campaigns, techniques) does not fit IOC search.
  IOC values (`whoami /all`, `powershell.exe`) aren't title-like free text a user
  free-text-searches the way they search scenario names, and Phase 0+A's `iocs` table is
  already deduped cross-run — one IOC row can belong to many scenarios via
  `ioc_sightings`, which doesn't map onto `search_documents`' one-row-per-entity model.
  §18's actual filter axes (hash/domain/MITRE/scenario/source/date) are structured filters,
  which is what `GET /api/iocs` already is. **Decision: extend `GET /api/iocs`'s filters,
  don't integrate IOCs into `internal/search`.**
- **Data already computed but not yet captured**: `SubmitRunDetections`
  (`internal/api/detection_handlers.go:66-93`) already has, per result, both
  `results[i].Technique.ID` and `results[i].DetectionVerdict` (`prevented` | `detected` |
  `undetected`) sitting right next to the `DetectionAlert` that Phase 0+A's extraction
  loop (line 138-142) already iterates. Neither value is passed into
  `ExtractFromDetectionAlert` today. This phase wires both through instead of
  recomputing or duplicating them.

## Decisions

1. **`ioc_sightings` gains two columns**: `technique_id text NOT NULL DEFAULT ''` and
   `detection_verdict text NOT NULL DEFAULT ''`. Populated at the same extraction call
   site, from data the caller already has — no new query, no new correlation logic.
   This is the join key Phase B's graph and analytics both need (§12's
   hash→process→...→alert chain, for this phase's 2 populated types, becomes
   IOC→technique/scenario/run/agent; §24's "most detected" needs a verdict per sighting).
2. **`ExtractFromDetectionAlert`'s signature grows two parameters**:
   `techniqueID, detectionVerdict string` inserted after `agentID`. `recordSighting`
   grows the same two columns. This is a breaking change to Task 2's call site
   (`detection_handlers.go:139`), updated in the same phase.
3. **`GET /api/iocs` gains five filters**: `techniqueId` (joins `ioc_sightings`, same
   join-on-demand pattern Phase 0+A's `scenarioId`/`agentId` already use), `source`,
   `origin`, `status` (all direct `iocs` column equality), `since`/`until` (range on
   `last_seen`). No new endpoint.
4. **`threatgraph` gains `NodeTypeIOC` and `IOCNeighborhood(ctx, pool, iocID string)`**:
   looks up the `iocs` row by `id` (the registry's own PK, not `(type,value)` — consistent
   with how `CampaignNeighborhood`/`MalwareNeighborhood`/`ToolNeighborhood` all key on
   their table's own PK, not a composite business key), then adds one edge per distinct
   `scenario_id`/`run_id`/`agent_id`/`technique_id` found across that IOC's
   `ioc_sightings` rows. New node types: `scenario`, `run`, `agent` don't exist yet in
   `threatgraph` — added alongside `ioc` in this phase, since nothing needed them before.
   Relationship label: `"observed_in"` for all four (an IOC doesn't "use" a run the way an
   actor "uses" a technique; it was *observed* there).
5. **`internal/analytics/ioc.go`, one function**: `IOCAnalytics(ctx, pool, limit int)
   (IOCAnalyticsResult, error)`, returning four ranked lists — `MostDetected` (highest
   `sighting_count` among sightings with `detection_verdict IN ('detected','prevented')`),
   `HighestBypassRate` (highest `sighting_count` among sightings with
   `detection_verdict = 'undetected'` — §24's "highest bypass rate" for data that has no
   confidence score to compute an actual rate from, so this is a count-based proxy,
   stated plainly as such, not a fabricated percentage), `FrequentlyReused` (top
   `iocs.sighting_count` overall, no verdict filter), `LongestSurviving` (largest
   `NOW() - first_seen` among `status NOT IN ('archived','expired')`). Exposed at
   `GET /api/analytics/iocs?limit=`, `tierAny`, matching every other analytics endpoint.

## Architecture

### 1. Schema: `ioc_sightings` extension

```sql
ALTER TABLE ioc_sightings ADD COLUMN IF NOT EXISTS technique_id text NOT NULL DEFAULT '';
ALTER TABLE ioc_sightings ADD COLUMN IF NOT EXISTS detection_verdict text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_ioc_sightings_technique ON ioc_sightings (technique_id);
```

### 2. Extraction: signature change

```go
func ExtractFromDetectionAlert(ctx context.Context, pool *pgxpool.Pool,
	scenarioID, runID, agentID, techniqueID, detectionVerdict string,
	res models.SimulationResult) error
```

`recordSighting`'s `INSERT` grows two columns/params in lockstep. Caller
(`detection_handlers.go:139`) passes `results[i].Technique.ID` and
`results[i].DetectionVerdict` — both already in scope in that loop, zero new
computation.

### 3. `GET /api/iocs`: new filters

Same builder pattern already in `ioc_handlers.go`'s `GetIOCs` (append to `args`, grow
`where` by one `$N` clause per present filter):

```go
if techniqueID := q.Get("techniqueId"); techniqueID != "" {
	if joins == "" { joins = " JOIN ioc_sightings s ON s.ioc_id = i.id" }
	args = append(args, techniqueID)
	where += " AND s.technique_id = $" + strconv.Itoa(len(args))
}
if source := q.Get("source"); source != "" {
	args = append(args, source)
	where += " AND i.source = $" + strconv.Itoa(len(args))
}
if origin := q.Get("origin"); origin != "" {
	args = append(args, origin)
	where += " AND i.origin = $" + strconv.Itoa(len(args))
}
if status := q.Get("status"); status != "" {
	args = append(args, status)
	where += " AND i.status = $" + strconv.Itoa(len(args))
}
if since := q.Get("since"); since != "" {
	args = append(args, since)
	where += " AND i.last_seen >= $" + strconv.Itoa(len(args))
}
if until := q.Get("until"); until != "" {
	args = append(args, until)
	where += " AND i.last_seen <= $" + strconv.Itoa(len(args))
}
```

`since`/`until` accept any Postgres-parseable timestamp string (RFC3339); an
unparseable value is passed through to Postgres and surfaces as a normal query error
(500), matching how every other filter in this handler already has no client-side
validation.

### 4. `threatgraph`: `NodeTypeIOC` + `IOCNeighborhood`

New constants: `NodeTypeIOC = "ioc"`, `NodeTypeScenario = "scenario"`,
`NodeTypeRun = "run"`, `NodeTypeAgent = "agent"`.

```go
func IOCNeighborhood(ctx context.Context, pool *pgxpool.Pool, iocID string) (Neighborhood, error) {
	n := Neighborhood{Nodes: []Node{}, Edges: []Edge{}}

	var iocType, value string
	err := pool.QueryRow(ctx, `SELECT type, value FROM iocs WHERE id = $1`, iocID).Scan(&iocType, &value)
	if err == pgx.ErrNoRows {
		return n, nil
	}
	if err != nil {
		return n, err
	}

	iocNodeID := "ioc:" + iocID
	n.Nodes = append(n.Nodes, Node{ID: iocNodeID, Type: NodeTypeIOC, Label: iocType + ": " + value})

	rows, err := pool.Query(ctx,
		`SELECT DISTINCT scenario_id, run_id, agent_id, technique_id FROM ioc_sightings WHERE ioc_id = $1`, iocID)
	if err != nil {
		return n, err
	}
	defer rows.Close()

	seen := map[string]bool{}
	add := func(nodeType, key, label string) {
		if key == "" || seen[nodeType+":"+key] {
			return
		}
		seen[nodeType+":"+key] = true
		nodeID := nodeType + ":" + key
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: nodeType, Label: label})
		n.Edges = append(n.Edges, Edge{From: iocNodeID, To: nodeID, Relationship: "observed_in"})
	}
	for rows.Next() {
		var scenarioID, runID, agentID, techniqueID string
		if err := rows.Scan(&scenarioID, &runID, &agentID, &techniqueID); err != nil {
			return n, err
		}
		add(NodeTypeScenario, scenarioID, scenarioID)
		add(NodeTypeRun, runID, runID)
		add(NodeTypeAgent, agentID, agentID)
		if techniqueID != "" {
			label, lerr := techniqueLabel(ctx, pool, techniqueID)
			if lerr != nil {
				return n, lerr
			}
			add(NodeTypeTechnique, techniqueID, label)
		}
	}
	return n, rows.Err()
}
```

`Lookup`'s switch gains one case: `case NodeTypeIOC: return IOCNeighborhood(ctx, pool, id)`.

Scenario/run/agent nodes use their raw ID as both node key and label (no display-name
lookup table exists for any of the three, unlike technique/campaign/malware/tool, which
all have a `name` column their existing neighborhoods already select) — consistent with
how this package already treats sector/region labels (raw string, no lookup) in
`ActorNeighborhood`.

### 5. `internal/analytics/ioc.go`

```go
type IOCAnalyticsEntry struct {
	IOCID         string `json:"iocId"`
	Type          string `json:"type"`
	Value         string `json:"value"`
	SightingCount int    `json:"sightingCount"`
}

type IOCAnalyticsResult struct {
	MostDetected       []IOCAnalyticsEntry `json:"mostDetected"`
	HighestBypassRate  []IOCAnalyticsEntry `json:"highestBypassRate"`
	FrequentlyReused   []IOCAnalyticsEntry `json:"frequentlyReused"`
	LongestSurviving   []IOCAnalyticsEntry `json:"longestSurviving"`
}

func IOCAnalytics(ctx context.Context, pool *pgxpool.Pool, limit int) (IOCAnalyticsResult, error)
```

Each of the four lists is one query against `iocs` (optionally joined to
`ioc_sightings` for the verdict-filtered two), `ORDER BY` the relevant column
`DESC LIMIT $1`. `MostDetected`/`HighestBypassRate` use
`SELECT DISTINCT i.id, i.type, i.value, i.sighting_count FROM iocs i JOIN ioc_sightings s
ON s.ioc_id = i.id WHERE s.detection_verdict = $2 ORDER BY i.sighting_count DESC LIMIT $1`;
`FrequentlyReused` is a plain `iocs` scan ordered by `sighting_count`; `LongestSurviving`
orders by `first_seen ASC` (oldest = longest-surviving) filtered to
`status NOT IN ('archived','expired')`.

`GetIOCAnalytics` handler mirrors `GetEndpointPosture` exactly (5 lines: call, error
check, respond). Route: `r.Get("/api/analytics/iocs", h.GetIOCAnalytics)`, `tierAny`.

## Non-goals

- **No IOC Timeline (§11)**: a literal `generated → deployed → DNS resolved → alerted →
  quarantined → cleaned` event log needs per-IOC lifecycle event rows that don't exist.
  `iocs.status` is set once at insert (`observed`) and never transitions today — nothing
  in Phase 0+A or this phase moves it through `detected`/`missed`/`expired`/`archived`.
  Building a "timeline" from just `first_seen`/`last_seen` would show two points and call
  it a timeline, which is misleading. Deferred until something actually drives `Status`
  transitions (candidate: Phase D).
- **No IOC Variants/families (§13)**: grouping `evil.com`/`a.evil.com`/`cdn.evil.com` as
  one logical family needs fuzzy/hierarchical matching this phase has no data to justify —
  Phase 0+A only populates `command_line`/`process`, neither of which has a natural
  "family" relationship the way domains/hashes do. Revisit once Phase C (Generation)
  populates domain/hash/etc.
- **No full-text IOC search / `internal/search` integration** — see Investigation above.
- **No frontend** — backend-only, matching every foundation phase this session.
- **No severity/confidence/creator filters on `GET /api/iocs`** — `iocs.metadata` can hold
  a `threatName` today but nothing populates `confidence`/`severity`/`creator` as
  queryable fields; adding filters for columns nothing writes would be dead API surface.
- **`internal/threatgraph`'s new scenario/run/agent node types stay IOC-only for now** —
  not retrofitted onto actor/campaign/malware/tool neighborhoods, which have no existing
  relationship to a specific run/agent to expose.

## Testing

- `internal/iocregistry/extract_test.go`: existing 4 tests updated for the 2 new
  `ExtractFromDetectionAlert` parameters; one new test asserts `technique_id`/
  `detection_verdict` land correctly on the `ioc_sightings` row.
- `internal/api/detection_handlers_test.go`: existing test updated to assert the
  extracted sighting carries `results[0].Technique.ID`/`DetectionVerdict`.
- `internal/api/ioc_handlers_test.go`: new tests for each of the 5 new filters
  (`techniqueId`, `source`, `origin`, `status`, `since`/`until`), following the existing
  `seedIOC` helper pattern (extended to accept techniqueId/verdict).
- `internal/threatgraph/assemble_test.go`: new tests for `IOCNeighborhood` — an IOC with
  2 sightings across different scenarios/runs/agents/techniques produces the right
  deduped node/edge set; an unknown `iocID` returns an empty (not nil) `Neighborhood`,
  matching every other neighborhood function's convention.
- `internal/analytics/ioc_test.go` (new): seed `iocs`/`ioc_sightings` rows with known
  `sighting_count`/`detection_verdict`/`first_seen` values, assert each of the 4 ranked
  lists orders and filters correctly.
- `internal/api/ioc_analytics_handler_test.go` (new): `GET /api/analytics/iocs` returns
  200 with the expected shape; RBAC matrix gains one entry.
