# Attack Path Validation — Results Backend Enrichment (Sub-project A) — Design Spec

**Source**: `attackpatvalidtionImprove.txt` (repo root), a 16-point UX critique of the Attack
Path Validation results page. Decomposed into 4 sub-projects during brainstorming — this
spec covers **Sub-project A: backend enrichment** only. Sub-project B (results-page redesign
+ documentation rewrite, folded together per user decision) consumes this phase's output.
Sub-project C (change-tracking/diffing across collections) is deferred, out of scope here.

## Goal

Add the data the results page needs but the backend doesn't yet compute or expose: score
drivers, per-edge-kind relationship counts, collection confidence, graph coverage, an
unambiguous Domain Compromise status, and remediation text per detection gap. All of it is
either already computed and discarded, or derivable from data the server already has —
nothing here is speculative or invented.

## Investigation summary

- `Summary` (`internal/attackpath/score.go`) is a pure function of `*Graph` — `Analyze()`
  never sees the raw `[]Collection` (source/timestamp per agent). `BuildAndAnalyze(cols,
  tags)` / `BuildGraphAndAnalyze(cols, tags)` (`assets.go:85-97`) are the two call sites that
  DO have `cols` in scope — one used by the summary handler, one by `pathcorrelation`.
- `internal/attackpath` has **no database access anywhere** — it's pure in-memory
  transformation (`Collection`/`Graph`/`Summary` are plain structs). This is a real
  architectural boundary worth preserving, not incidental: it's why the package is easy to
  unit test today. `Coverage` (below) needs a DB query the package doesn't do, so it stays
  out of this package entirely — computed in the handler, same pattern `agentMeta` in
  `GetAttackPathSummary` already uses (a sibling top-level JSON field, not nested in
  `summary`).
- `Analyze()`'s deficit math (`score.go:86-115`) already computes 4 weighted contributions
  (`wDomainCompromise=30`, `wLateralMax=35`, `wCrownJewel=20`, `wSegmentation=15`) as local
  variables, summed into one `deficit float64` and discarded — only the final
  `AttackPathScore` survives.
- `DomainCompromise bool` (`score.go:14`) is only ever set `if len(hv) > 0` (high-value
  targets exist in the graph) — when no AD data was ever collected, it silently stays
  `false`, indistinguishable from "checked, confirmed no path."
- `Collection.Source` (`build.go:18`, values `"agent"|"sharphound"|"monkey"`) is explicitly
  commented as existing "so the server can reason about confidence and provenance" — never
  used for that. It's available in `cols`, just not read.
- `DispatchAttackPathCollect` (`attackpath_handlers.go:437`) receives `Targets []string` per
  dispatch but nothing persists that list anywhere queryable later.
- The agent's probe loop (`agent/attackpath.go:143-164`) only appends a target to
  `col.Nodes` when found reachable on at least one of SMB/WinRM/RDP — an unreachable target
  leaves zero trace in the submitted payload. **Confirmed during brainstorming**: this means
  "how many of the requested targets are represented in the resulting graph" is fully
  computable server-side, by diffing the persisted request against which targets became host
  nodes — no agent protocol change needed.
- `pathcorrelation.PrioritizedGap` (`pathcorrelation/types.go:116-122`) already has
  `Edge.Kind`, ranked `Priority`, and a generated `Reason` string. `mapper.go`'s
  `DefaultEdgeTechniqueMapper.Techniques(kind)` is the exact pattern to mirror for
  remediation text — a curated `switch kind` table, one entry per `EdgeKind`.
- `EdgeKind` (`graph.go:50-58`, plus `EdgeCredential` used in `mapper.go:55`) has 7 values:
  `smb`, `winrm`, `rdp`, `admin-to`, `has-session`, `member-of`, `credential`.

## Decisions

1. **`ScoreDrivers` and `RelationshipCounts` compute inside `Analyze()`** — both are fully
   derivable from `*Graph` alone (`Analyze()`'s existing deficit math; a loop over graph
   edges by kind). No signature change to `Analyze()`, just more fields on its `Summary`
   return value.
2. **`Confidence` and `DomainCompromiseStatus` compute inside `BuildAndAnalyze`/
   `BuildGraphAndAnalyze`** — both need `cols[].Source`, which `Analyze()` doesn't see but
   `BuildAndAnalyze` already receives. Computed as a post-processing step after `g.Analyze()`
   returns.
3. **`Coverage` lives entirely in the handler, not in `internal/attackpath`** — it's the one
   piece needing a DB query (the new request-log table), which would violate the package's
   existing DB-free boundary. Exposed as a new top-level `coverage` key in
   `GetAttackPathSummary`'s JSON response, sibling to `summary` and `agentMeta` (not nested
   inside `summary`).
4. **Coverage wording never claims to know *why* a target is missing** (user's explicit
   correction during brainstorming) — the server only knows a target was requested and
   whether it appears in the resulting graph, not whether it was offline, filtered by a
   firewall, or never attempted. `Coverage.TargetsRepresented` is the field name (not
   `TargetsCollected`); Sub-project B's UI copy must say *"N of M requested targets
   represented in the graph"*, never "Collected."
5. **`ScoreDrivers` shows real subtractions, not invented bonus points.** The scoring model
   is pure-deficit (`100 - sum(deficits)`); a driver contributing 0 deficit is shown as "no
   deficit," not as a fabricated "+20 bonus" the actual math doesn't compute.
6. **Remediation text is a static, curated `EdgeKind → string` table** (`pathcorrelation`),
   mirroring `DefaultEdgeTechniqueMapper`'s exact shape — one switch statement, no dynamic
   generation, no LLM calls, matching this codebase's consistent "curated lookup table" style
   for this kind of mapping (see also Phase C's `internal/artifactgen` curated table this
   session).
7. **`DomainCompromiseStatus` values**: `reachable` (a path was found), `not-observed` (AD/
   high-value target data was present, no path found), `undetermined` (no AD/SharpHound data
   was ever collected — the existing bool can't distinguish this from `not-observed`). The
   existing `DomainCompromise bool` field is kept unchanged for backward compatibility;
   `DomainCompromiseStatus` is additive.

## Architecture

### 1. Schema — `internal/db/postgres.go`

```sql
CREATE TABLE IF NOT EXISTS attackpath_collection_requests (
	id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
	agent_id       text        NOT NULL,
	targets        jsonb       NOT NULL DEFAULT '[]',
	run_sharphound boolean     NOT NULL DEFAULT false,
	requested_at   timestamptz NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_attackpath_collection_requests_agent
	ON attackpath_collection_requests (agent_id, requested_at DESC);
```

One row per dispatch (not upserted — a history of what was ever requested, needed since
`Coverage` reconciles against the *most recent* dispatch per agent, and keeping history costs
nothing here).

### 2. `DispatchAttackPathCollect` writes a request row

`internal/api/attackpath_handlers.go`, right after the existing `buildCollectCmd` call
(`attackpath_handlers.go:447`), insert:

```go
_, _ = h.db.Exec(r.Context(),
	`INSERT INTO attackpath_collection_requests (agent_id, targets, run_sharphound)
	 VALUES ($1, $2, $3)`,
	agentID, mustJSON(body.Targets), body.RunSharpHound)
```

Best-effort (`_, _ =`) — a failed insert degrades `Coverage` to "unknown" for this dispatch,
never blocks the actual collection dispatch. `mustJSON` is a small helper (`json.Marshal`,
swallow error, matches this file's existing loose error-handling style for non-critical
writes).

### 3. `internal/attackpath`: `ScoreDrivers` + `RelationshipCounts`

`score.go`'s `Summary` gains two fields:

```go
type Summary struct {
	// ... existing fields unchanged ...
	ScoreDrivers      []ScoreDriver  `json:"scoreDrivers"`
	RelationshipCounts map[string]int `json:"relationshipCounts"` // keyed by EdgeKind string value
}

type ScoreDriver struct {
	Label   string  `json:"label"`
	Deficit float64 `json:"deficit"` // points subtracted from 100; 0 = no deficit in this category
}
```

Inside `Analyze()`, replace the bare `deficit float64` accumulator with per-category capture
(the arithmetic is unchanged — same 4 `if`/computations already there, just also recorded
individually):

```go
	deficit := 0.0
	var drivers []ScoreDriver

	dcDeficit := 0.0
	if s.DomainCompromise {
		dcDeficit = wDomainCompromise
	}
	deficit += dcDeficit
	drivers = append(drivers, ScoreDriver{Label: "Domain Admin path reachable", Deficit: dcDeficit})

	lateralDeficit := 0.0
	if denom := float64(maxInt(len(hosts)-1, 1)); len(hosts) > 0 {
		frac := s.AvgBlastRadius / denom
		if frac > 1 {
			frac = 1
		}
		lateralDeficit = frac * wLateralMax
	}
	deficit += lateralDeficit
	drivers = append(drivers, ScoreDriver{Label: "Lateral movement exposure", Deficit: round2(lateralDeficit)})

	crownJewelDeficit := 0.0
	if len(s.CrownJewels) > 0 {
		reach := 0
		for _, cj := range s.CrownJewels {
			if cj.Reachable {
				reach++
			}
		}
		crownJewelDeficit = (float64(reach) / float64(len(s.CrownJewels))) * wCrownJewel
	}
	deficit += crownJewelDeficit
	drivers = append(drivers, ScoreDriver{Label: "Crown jewel exposure", Deficit: round2(crownJewelDeficit)})

	segDeficit := 0.0
	if v := len(s.SegmentationViols); v > 0 {
		frac := float64(v) / float64(v+3)
		segDeficit = frac * wSegmentation
	}
	deficit += segDeficit
	drivers = append(drivers, ScoreDriver{Label: "Segmentation violations", Deficit: round2(segDeficit)})

	s.ScoreDrivers = drivers
```

(This replaces `score.go:86-115`'s existing deficit block exactly — same 4 computations,
same weights, same order; each just also appends a `ScoreDriver` before being summed.)

`RelationshipCounts` — new loop, added anywhere in `Analyze()` after `hosts := g.hostIDs()`:

```go
	s.RelationshipCounts = map[string]int{}
	for _, e := range g.Edges() {
		s.RelationshipCounts[string(e.Kind)]++
	}
```

(`g.Edges() []Edge` already exists, `graph.go:131` — no addition needed.)

### 4. `internal/attackpath`: `Confidence` + `DomainCompromiseStatus`

`score.go`'s `Summary` gains:

```go
	Confidence              Confidence `json:"confidence"`
	DomainCompromiseStatus  string     `json:"domainCompromiseStatus"` // reachable | not-observed | undetermined
```

```go
type Confidence struct {
	Level   string   `json:"level"`   // High | Medium | Low
	Based   []string `json:"based"`
	Missing []string `json:"missing"`
}

const (
	DCStatusReachable   = "reachable"
	DCStatusNotObserved = "not-observed"
	DCStatusUndetermined = "undetermined"
)
```

New function, `assets.go` (alongside `BuildAndAnalyze`):

```go
func computeConfidence(cols []Collection) Confidence {
	hasAgent, hasSharpHound := false, false
	for _, c := range cols {
		switch c.Source {
		case "agent":
			hasAgent = true
		case "sharphound":
			hasSharpHound = true
		}
	}
	c := Confidence{Based: []string{}, Missing: []string{}}
	if hasAgent {
		c.Based = append(c.Based, "Reachability", "Local Admins", "Sessions")
	}
	if hasSharpHound {
		c.Based = append(c.Based, "Active Directory relationships")
	} else {
		c.Missing = append(c.Missing, "Active Directory relationships")
	}
	switch {
	case hasAgent && hasSharpHound:
		c.Level = "High"
	case hasAgent || hasSharpHound:
		c.Level = "Medium"
	default:
		c.Level = "Low"
	}
	return c
}

func domainCompromiseStatus(s Summary, cols []Collection) string {
	hasSharpHound := false
	for _, c := range cols {
		if c.Source == "sharphound" {
			hasSharpHound = true
			break
		}
	}
	if s.DomainCompromise {
		return DCStatusReachable
	}
	if hasSharpHound {
		return DCStatusNotObserved
	}
	return DCStatusUndetermined
}
```

`BuildAndAnalyze`/`BuildGraphAndAnalyze` (`assets.go:85-97`) call both after `g.Analyze()`:

```go
func BuildGraphAndAnalyze(cols []Collection, tags []AssetTag) (*Graph, Summary) {
	g := BuildGraph(cols...)
	g.applyAssetTags(tags)
	s := g.Analyze()
	s.Confidence = computeConfidence(cols)
	s.DomainCompromiseStatus = domainCompromiseStatus(s, cols)
	return g, s
}
```

### 5. Handler: `Coverage`

`internal/api/attackpath_handlers.go`'s `GetAttackPathSummary` (`:181-236`) gains, after
loading `cols`:

```go
type coverage struct {
	TargetsRequested    int    `json:"targetsRequested"`
	TargetsRepresented  int    `json:"targetsRepresented"`
	SharpHoundRequested bool   `json:"sharpHoundRequested"`
	SharpHoundAvailable bool   `json:"sharpHoundAvailable"`
	Completeness        string `json:"completeness"` // Full | Limited | Minimal | Unknown
}

func (h *Handler) buildAttackPathCoverage(r *http.Request, g *attackpath.Graph, cols []attackpath.Collection) coverage {
	var cov coverage
	row := h.db.QueryRow(r.Context(), `
		SELECT targets, run_sharphound FROM attackpath_collection_requests
		ORDER BY requested_at DESC LIMIT 1`)
	var targetsRaw []byte
	if err := row.Scan(&targetsRaw, &cov.SharpHoundRequested); err != nil {
		cov.Completeness = "Unknown"
		return cov
	}
	var targets []string
	_ = json.Unmarshal(targetsRaw, &targets)
	cov.TargetsRequested = len(targets)

	represented := map[string]bool{}
	for _, n := range g.Nodes() {
		if n.Kind == attackpath.KindHost {
			represented[attackpath.NormalizeHostKey(n.ID)] = true
		}
	}
	for _, t := range targets {
		if represented[attackpath.NormalizeHostKey(t)] {
			cov.TargetsRepresented++
		}
	}

	for _, c := range cols {
		if c.Source == "sharphound" {
			cov.SharpHoundAvailable = true
			break
		}
	}

	switch {
	case cov.TargetsRequested == 0:
		cov.Completeness = "Unknown"
	case cov.TargetsRepresented == cov.TargetsRequested && (cov.SharpHoundAvailable || !cov.SharpHoundRequested):
		cov.Completeness = "Full"
	case cov.TargetsRepresented > 0:
		cov.Completeness = "Limited"
	default:
		cov.Completeness = "Minimal"
	}
	return cov
}
```

`GetAttackPathSummary`'s response gains one field:

```go
	respond(w, map[string]any{
		"collected":         true,
		"agents":            len(cols),
		"summary":           s,
		"coverage":          h.buildAttackPathCoverage(r, g, cols),
		"latestCollectedAt": latest,
		"agentMeta":         agentMetas,
	})
```

(`g *attackpath.Graph` — `GetAttackPathSummary` currently calls
`attackpath.BuildAndAnalyze(cols, ...)`, discarding the graph; switches to
`attackpath.BuildGraphAndAnalyze(cols, ...)` to keep the graph for the coverage node lookup.
`attackpath.NormalizeHostKey` (`assets.go:31`, already exported and already used by the
asset-tagging code path) is reused directly for both sides of the target/node-ID comparison
— no new normalization helper needed.)

### 6. `pathcorrelation`: remediation text

New file `internal/pathcorrelation/remediation.go`:

```go
package pathcorrelation

import "github.com/audspect/bas/internal/attackpath"

// RemediationFor returns a curated, static remediation sentence for an edge kind. Mirrors
// DefaultEdgeTechniqueMapper's exact shape (mapper.go) -- one switch, no dynamic generation.
func RemediationFor(kind attackpath.EdgeKind) string {
	switch kind {
	case attackpath.EdgeSMB:
		return "Restrict SMB connectivity between these hosts (firewall rule or host-based policy)."
	case attackpath.EdgeWinRM:
		return "Restrict WinRM access to only the hosts and accounts that require it."
	case attackpath.EdgeRDP:
		return "Restrict RDP access between these hosts; consider a jump-host-only policy."
	case attackpath.EdgeAdminTo:
		return "Remove unnecessary Local Administrator membership for this account on this host."
	case attackpath.EdgeHasSession:
		return "Reduce interactive session exposure on this host (e.g. avoid privileged logons on shared workstations)."
	case attackpath.EdgeMemberOf:
		return "Review this group membership for least-privilege — it grants inherited access along this path."
	case attackpath.EdgeCredential:
		return "Rotate or remove the exposed credential material enabling this edge."
	default:
		return ""
	}
}
```

`PrioritizedGap` (`types.go:116-122`) gains one field, `Remediation string`, populated in
`buildGaps` (`correlate.go:326-367`) alongside the existing `Reason` computation:

```go
	gaps = append(gaps, PrioritizedGap{
		Edge:        e,
		Techniques:  st.Techniques,
		Priority:    priorityFor(score),
		Reason:      gapReason(crossCount[k], totalPaths, dist, st),
		Remediation: RemediationFor(e.Kind),
		score:       score,
	})
```

## Non-goals

- **No Sub-project B (UI redesign / documentation rewrite)** — this spec is backend-only;
  the results page continues rendering exactly as it does today until Sub-project B consumes
  these new fields.
- **No Sub-project C (change-tracking/diffing across collections)** — deferred, separate
  initiative.
- **No per-target failure-reason reporting** (Timeout/DNS/Firewall/Access-Denied) — explicitly
  deferred per the brainstorming discussion; `Coverage` only proves presence/absence, never
  claims to know why a target is missing. The design leaves room for this as a future,
  independent addition (an agent protocol change) without invalidating anything here.
- **No dynamic/LLM-generated remediation text** — static curated table only, matching
  `DefaultEdgeTechniqueMapper`'s existing style.
- **No frontend changes** — matching this session's backend-only foundation-phase convention.

## Testing

- `internal/attackpath`: `Analyze()` test asserting `ScoreDrivers` sums to the same deficit
  the existing `AttackPathScore` calculation already produces (regression-safe refactor
  check) and that a category with zero deficit shows `Deficit: 0`, not an omitted/negative
  value. `RelationshipCounts` test asserting exact per-kind counts on a small fixture graph
  (matches existing test fixtures' style, e.g. `attackpath_test.go`'s 6-edge graph).
- `computeConfidence`/`domainCompromiseStatus` unit tests: agent-only cols → Medium/Missing
  AD; agent+sharphound → High/no Missing; no cols → Low. `DomainCompromiseStatus`:
  `DomainCompromise=true` → `reachable` regardless of Source; `false` + sharphound present →
  `not-observed`; `false` + no sharphound → `undetermined`.
- `internal/api`: `buildAttackPathCoverage` test seeding a request row + a partial-match
  graph (2 requested, 1 represented) asserting `TargetsRequested=2`,
  `TargetsRepresented=1`, `Completeness="Limited"`; a full-match case asserting `"Full"`; a
  no-request-row case asserting `Completeness="Unknown"`.
- `internal/pathcorrelation`: `RemediationFor` test mirroring `mapper_test.go`'s
  `TestDefaultEdgeTechniqueMapper` exactly — a table-driven case per `EdgeKind` (all 7 values)
  asserting a non-empty string, plus an `EdgeKind("unknown")` case asserting an empty string
  (same two assertion shapes that test already uses for `Techniques`). `Correlate()`
  regression test confirming `PrioritizedGap.Remediation` is populated for a known gap.
