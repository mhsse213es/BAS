# Attack Path Validation Results Backend Enrichment (Sub-project A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add score-driver breakdown, relationship-type counts, collection confidence, graph coverage, an unambiguous Domain Compromise status, and remediation text to the Attack Path Validation backend — everything the results page needs but doesn't yet get.

**Architecture:** `internal/attackpath`'s `Analyze()` gains fields computable from `*Graph` alone; `BuildAndAnalyze`/`BuildGraphAndAnalyze` (which already receive the raw `[]Collection`) gain fields needing `Source`/provenance data. `Coverage` — the one piece needing a DB query — is computed entirely in the `internal/api` handler, preserving `internal/attackpath`'s existing zero-DB-access boundary. `internal/pathcorrelation` gains a static remediation-text lookup mirroring its existing `DefaultEdgeTechniqueMapper` pattern.

**Tech Stack:** Go (`internal/attackpath`, `internal/pathcorrelation`, `internal/api`, `internal/db`), `*pgxpool.Pool`.

## Global Constraints

- `internal/attackpath` has zero database access today and must keep it that way — `Coverage` is computed in the handler, never inside this package.
- Coverage wording never claims to know *why* a target is missing — the field is named `TargetsRepresented`, not `TargetsCollected`; UI copy (a later sub-project) must say "N of M requested targets represented in the graph," never "Collected."
- `ScoreDrivers` shows real subtractions from the actual deficit math (`100 - sum(deficits)`) — never an invented "bonus points" framing the scoring model doesn't compute.
- Remediation text is a static curated `switch` table (mirroring `pathcorrelation/mapper.go`'s `DefaultEdgeTechniqueMapper`) — no dynamic generation, no LLM calls.
- No frontend changes — backend-only, matching this session's foundation-phase convention.
- Every task ends with a commit + `git push`.

---

### Task 1: Request log — schema + `DispatchAttackPathCollect` writes a row

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (new `attackpath_collection_requests` table)
- Modify: `orchestrator/internal/api/attackpath_handlers.go` (`DispatchAttackPathCollect`)
- Test: `orchestrator/internal/api/attackpath_dispatch_test.go`

**Interfaces:**
- Produces: `attackpath_collection_requests` table (`agent_id text`, `targets jsonb`, `run_sharphound boolean`, `requested_at timestamptz`). Task 4 reads this table.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/attackpath_dispatch_test.go` (append to the end of the file):

```go
// TestDispatchAttackPathCollect_WritesRequestLog pins that a successful
// dispatch persists the requested targets/runSharpHound flag for later
// coverage reconciliation (Task 4).
func TestDispatchAttackPathCollect_WritesRequestLog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		agent := startFakeAgent(t, h.hub, "reqlog-agent")
		defer agent.Disconnect(t)

		rec := httptest.NewRecorder()
		req := withURLParam(dispatchCollectReq(map[string]any{
			"targets": []string{"10.0.0.1", "10.0.0.2"}, "runSharpHound": true,
		}), "agentId", "reqlog-agent")
		h.DispatchAttackPathCollect(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var targetsRaw []byte
		var runSharpHound bool
		if err := pool.QueryRow(context.Background(),
			`SELECT targets, run_sharphound FROM attackpath_collection_requests WHERE agent_id=$1`,
			"reqlog-agent").Scan(&targetsRaw, &runSharpHound); err != nil {
			t.Fatalf("read request log: %v", err)
		}
		var targets []string
		json.Unmarshal(targetsRaw, &targets)
		if len(targets) != 2 || !runSharpHound {
			t.Fatalf("targets=%v runSharpHound=%v, want 2 targets and runSharpHound=true", targets, runSharpHound)
		}
	})
}
```

Add `"context"` to this file's import block if not already present (check first — `attackpath_dispatch_test.go`'s existing imports are `bytes`, `encoding/base64`, `encoding/json`, `net/http`, `net/http/httptest`, `os`, `path/filepath`, `testing`, `time`, `github.com/audspect/bas/internal/models`, `github.com/jackc/pgx/v5/pgxpool` — `context` is not yet imported).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestDispatchAttackPathCollect_WritesRequestLog -v`
Expected: FAIL — `attackpath_collection_requests` table doesn't exist yet (query error).

- [ ] **Step 3: Add the schema**

In `orchestrator/internal/db/postgres.go`, find:

```go
		`ALTER TABLE attackpath_asset_tags ADD COLUMN IF NOT EXISTS compliance_scope text[]  NOT NULL DEFAULT '{}'`,

		// attackpath_jobs: lifecycle record for every operator-initiated or scheduled
```

Replace with:

```go
		`ALTER TABLE attackpath_asset_tags ADD COLUMN IF NOT EXISTS compliance_scope text[]  NOT NULL DEFAULT '{}'`,

		// attackpath_collection_requests: one row per dispatch, recording what was
		// asked for -- lets the summary handler reconcile "requested" against
		// "represented in the resulting graph" without any agent protocol change
		// (an unreachable target already leaves no trace in the agent's own
		// submission, so absence already means "not represented"). See
		// docs/superpowers/specs/2026-07-31-attack-path-results-backend-design.md.
		`CREATE TABLE IF NOT EXISTS attackpath_collection_requests (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			agent_id       text        NOT NULL,
			targets        jsonb       NOT NULL DEFAULT '[]',
			run_sharphound boolean     NOT NULL DEFAULT false,
			requested_at   timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_attackpath_collection_requests_agent
			ON attackpath_collection_requests (agent_id, requested_at DESC)`,

		// attackpath_jobs: lifecycle record for every operator-initiated or scheduled
```

- [ ] **Step 4: Write the request row in `DispatchAttackPathCollect`**

In `orchestrator/internal/api/attackpath_handlers.go`, find:

```go
	cmd, sharpHoundLoaded := buildCollectCmd(body.Targets, body.Segment, body.RunSharpHound, body.SharpHoundArgs)
```

Replace with:

```go
	cmd, sharpHoundLoaded := buildCollectCmd(body.Targets, body.Segment, body.RunSharpHound, body.SharpHoundArgs)
	if targetsJSON, err := json.Marshal(body.Targets); err == nil {
		_, _ = h.db.Exec(r.Context(),
			`INSERT INTO attackpath_collection_requests (agent_id, targets, run_sharphound)
			 VALUES ($1, $2, $3)`,
			agentID, targetsJSON, body.RunSharpHound)
	}
```

Best-effort (`_, _ =`) — a failed insert degrades Task 4's coverage computation to "Unknown," never blocks the actual collection dispatch. `agentID` is already in scope (`chi.URLParam(r, "agentId")` at the top of the function, `attackpath_handlers.go:438`).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/api/... -run TestDispatchAttackPathCollect -v`
Expected: build/vet clean; all `TestDispatchAttackPathCollect*` tests PASS, including the new one and the pre-existing `TestDispatchAttackPathCollect_AgentNotConnected`/`_Success`.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/api/attackpath_handlers.go orchestrator/internal/api/attackpath_dispatch_test.go
git commit -m "feat(attackpath): persist collection-request targets for coverage reconciliation

New attackpath_collection_requests table + DispatchAttackPathCollect
writes a row per dispatch. No agent protocol change needed -- an
unreachable target already leaves no trace in the agent's own
submission, so the server can reconcile requested-vs-represented
purely by diffing against the resulting graph (Task 4).

Attack Path results backend enrichment (Sub-project A), piece 1/5."
git push
```

---

### Task 2: `ScoreDrivers` + `RelationshipCounts`

**Files:**
- Modify: `orchestrator/internal/attackpath/score.go`
- Test: `orchestrator/internal/attackpath/attackpath_test.go`

**Interfaces:**
- Produces: `type ScoreDriver struct{Label string; Deficit float64}`, `Summary.ScoreDrivers []ScoreDriver`, `Summary.RelationshipCounts map[string]int`. Sub-project B (later, not this plan) renders these.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/attackpath/attackpath_test.go` (append to the end of the file):

```go
func TestAnalyzeScoreDrivers_SumsToActualDeficit(t *testing.T) {
	g := sample()
	s := g.Analyze()
	if len(s.ScoreDrivers) != 4 {
		t.Fatalf("ScoreDrivers = %+v, want 4 entries", s.ScoreDrivers)
	}
	var total float64
	for _, d := range s.ScoreDrivers {
		if d.Label == "" {
			t.Errorf("driver has empty label: %+v", d)
		}
		total += d.Deficit
	}
	wantDeficit := float64(100 - s.AttackPathScore)
	if total < wantDeficit-1 || total > wantDeficit+1 {
		t.Fatalf("ScoreDrivers sum to %.2f, want ~%.2f (100 - AttackPathScore, allowing rounding)", total, wantDeficit)
	}
}

func TestAnalyzeScoreDrivers_CleanGraphAllZero(t *testing.T) {
	g := New()
	g.AddNode(Node{ID: "A", Kind: KindHost, Role: RoleEndpoint, Segment: "vlan1"})
	g.AddNode(Node{ID: "B", Kind: KindHost, Role: RoleEndpoint, Segment: "vlan1"})
	s := g.Analyze()
	for _, d := range s.ScoreDrivers {
		if d.Deficit != 0 {
			t.Errorf("driver %q deficit = %v, want 0 for a clean graph", d.Label, d.Deficit)
		}
	}
}

func TestAnalyzeRelationshipCounts(t *testing.T) {
	g := sample()
	s := g.Analyze()
	want := map[string]int{"smb": 2, "winrm": 1, "has-session": 1, "member-of": 1, "admin-to": 1}
	if len(s.RelationshipCounts) != len(want) {
		t.Fatalf("RelationshipCounts = %+v, want %+v", s.RelationshipCounts, want)
	}
	for k, v := range want {
		if s.RelationshipCounts[k] != v {
			t.Errorf("RelationshipCounts[%q] = %d, want %d", k, s.RelationshipCounts[k], v)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/attackpath/... -run "TestAnalyzeScoreDrivers|TestAnalyzeRelationshipCounts" -v`
Expected: FAIL — build error, `s.ScoreDrivers`/`s.RelationshipCounts` undefined.

- [ ] **Step 3: Add the new types and fields**

In `orchestrator/internal/attackpath/score.go`, find:

```go
type Summary struct {
	AttackPathScore      int                     `json:"attackPathScore"` // 0..100, HIGHER = better (less exposed)
	Band                 string                  `json:"band"`            // Critical|High|Medium|Low (risk band, inverse of score)
	Hosts                int                     `json:"hosts"`
	Users                int                     `json:"users"`
	Groups               int                     `json:"groups"`
	Edges                int                     `json:"edges"`
	DomainCompromise     bool                    `json:"domainCompromise"`     // some host can reach a Domain Admin / Tier-0 target
	LateralMovementBand  string                  `json:"lateralMovementBand"`  // Critical|High|Medium|Low
	AvgBlastRadius       float64                 `json:"avgBlastRadius"`       // avg other-hosts compromisable per entry
	MaxBlastRadius       int                     `json:"maxBlastRadius"`       // worst single entry host
	MaxBlastEntry        string                  `json:"maxBlastEntry"`        // that host id
	SegmentationViols    []SegmentationViolation `json:"segmentationViolations"`
	CrownJewels          []CrownJewelExposure    `json:"crownJewels"`
	ChokePoints          []ChokePoint            `json:"chokePoints"`
	ShortestDAPath       []Edge                  `json:"shortestDomainAdminPath"` // representative worst-case path to DA (nil if none)
	ShortestDADifficulty Difficulty              `json:"shortestDomainAdminDifficulty"`
}
```

Replace with:

```go
type Summary struct {
	AttackPathScore      int                     `json:"attackPathScore"` // 0..100, HIGHER = better (less exposed)
	Band                 string                  `json:"band"`            // Critical|High|Medium|Low (risk band, inverse of score)
	Hosts                int                     `json:"hosts"`
	Users                int                     `json:"users"`
	Groups               int                     `json:"groups"`
	Edges                int                     `json:"edges"`
	DomainCompromise     bool                    `json:"domainCompromise"`     // some host can reach a Domain Admin / Tier-0 target
	LateralMovementBand  string                  `json:"lateralMovementBand"`  // Critical|High|Medium|Low
	AvgBlastRadius       float64                 `json:"avgBlastRadius"`       // avg other-hosts compromisable per entry
	MaxBlastRadius       int                     `json:"maxBlastRadius"`       // worst single entry host
	MaxBlastEntry        string                  `json:"maxBlastEntry"`        // that host id
	SegmentationViols    []SegmentationViolation `json:"segmentationViolations"`
	CrownJewels          []CrownJewelExposure    `json:"crownJewels"`
	ChokePoints          []ChokePoint            `json:"chokePoints"`
	ShortestDAPath       []Edge                  `json:"shortestDomainAdminPath"` // representative worst-case path to DA (nil if none)
	ShortestDADifficulty Difficulty              `json:"shortestDomainAdminDifficulty"`
	ScoreDrivers         []ScoreDriver           `json:"scoreDrivers"`
	RelationshipCounts   map[string]int          `json:"relationshipCounts"` // keyed by EdgeKind string value
}

// ScoreDriver is one weighted category's contribution to the AttackPathScore
// deficit. Deficit is the real number subtracted from 100 for this category --
// never an invented "bonus"; the scoring model is pure-deficit (100 - sum(deficits)).
type ScoreDriver struct {
	Label   string  `json:"label"`
	Deficit float64 `json:"deficit"` // points subtracted from 100; 0 = no deficit in this category
}
```

- [ ] **Step 4: Capture each deficit as a `ScoreDriver`**

In `orchestrator/internal/attackpath/score.go`, find:

```go
	// ---- deficits ----
	deficit := 0.0
	if s.DomainCompromise {
		deficit += wDomainCompromise
	}

	// lateral movement: fraction of the fleet an average entry can reach
	if denom := float64(maxInt(len(hosts)-1, 1)); len(hosts) > 0 {
		frac := s.AvgBlastRadius / denom
		if frac > 1 {
			frac = 1
		}
		deficit += frac * wLateralMax
	}

	// crown jewels: fraction of tagged jewels reachable from any host
	if len(s.CrownJewels) > 0 {
		reach := 0
		for _, cj := range s.CrownJewels {
			if cj.Reachable {
				reach++
			}
		}
		deficit += (float64(reach) / float64(len(s.CrownJewels))) * wCrownJewel
	}

	// segmentation: saturating penalty on cross-segment lateral edges
	if v := len(s.SegmentationViols); v > 0 {
		frac := float64(v) / float64(v+3) // 1 viol→0.25, 3→0.5, 9→0.75
		deficit += frac * wSegmentation
	}

	score := 100 - int(deficit+0.5)
```

Replace with:

```go
	// ---- deficits ----
	deficit := 0.0
	var drivers []ScoreDriver

	dcDeficit := 0.0
	if s.DomainCompromise {
		dcDeficit = wDomainCompromise
	}
	deficit += dcDeficit
	drivers = append(drivers, ScoreDriver{Label: "Domain Admin path reachable", Deficit: dcDeficit})

	// lateral movement: fraction of the fleet an average entry can reach
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

	// crown jewels: fraction of tagged jewels reachable from any host
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

	// segmentation: saturating penalty on cross-segment lateral edges
	segDeficit := 0.0
	if v := len(s.SegmentationViols); v > 0 {
		frac := float64(v) / float64(v+3) // 1 viol→0.25, 3→0.5, 9→0.75
		segDeficit = frac * wSegmentation
	}
	deficit += segDeficit
	drivers = append(drivers, ScoreDriver{Label: "Segmentation violations", Deficit: round2(segDeficit)})

	s.ScoreDrivers = drivers

	score := 100 - int(deficit+0.5)
```

- [ ] **Step 5: Add `RelationshipCounts`**

In `orchestrator/internal/attackpath/score.go`, find:

```go
	hosts := g.hostIDs()
	s.LateralMovementBand = g.LateralMovementBand()
```

Replace with:

```go
	hosts := g.hostIDs()
	s.RelationshipCounts = map[string]int{}
	for _, e := range g.Edges() {
		s.RelationshipCounts[string(e.Kind)]++
	}
	s.LateralMovementBand = g.LateralMovementBand()
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/attackpath/... -v`
Expected: build/vet clean; every test in the package PASSES, including the 3 new ones and every pre-existing test (`TestAnalyzeScore`, `TestCleanGraphScoresHigh`, `TestBuildGraphAndAnalyzeReturnsSameSummaryAsBuildAndAnalyze`, etc. — this is the regression check for editing shared deficit-computation code).

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/attackpath/score.go orchestrator/internal/attackpath/attackpath_test.go
git commit -m "feat(attackpath): expose ScoreDrivers and RelationshipCounts on Summary

Both fully derivable from *Graph alone -- ScoreDrivers captures the
same 4 weighted deficit computations Analyze() already ran (arithmetic
unchanged, each just also recorded individually before being summed);
RelationshipCounts is a new per-EdgeKind tally over g.Edges().

Attack Path results backend enrichment (Sub-project A), piece 2/5."
git push
```

---

### Task 3: `Confidence` + `DomainCompromiseStatus`

**Files:**
- Modify: `orchestrator/internal/attackpath/score.go` (new types)
- Modify: `orchestrator/internal/attackpath/assets.go` (`BuildGraphAndAnalyze`, new helper functions)
- Test: `orchestrator/internal/attackpath/assets_test.go`

**Interfaces:**
- Consumes: `Collection.Source` (`build.go:18`, already exists).
- Produces: `type Confidence struct{Level string; Based, Missing []string}`, `Summary.Confidence`, `Summary.DomainCompromiseStatus string`, constants `DCStatusReachable`/`DCStatusNotObserved`/`DCStatusUndetermined`.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/attackpath/assets_test.go` (append to the end of the file):

```go
func TestBuildGraphAndAnalyze_ConfidenceLevels(t *testing.T) {
	agentOnly := []Collection{{AgentID: "a", Source: "agent", Nodes: []Node{{ID: "H1", Kind: KindHost}}}}
	_, s := BuildGraphAndAnalyze(agentOnly, nil)
	if s.Confidence.Level != "Medium" {
		t.Errorf("agent-only Confidence.Level = %q, want Medium", s.Confidence.Level)
	}
	found := false
	for _, m := range s.Confidence.Missing {
		if m == "Active Directory relationships" {
			found = true
		}
	}
	if !found {
		t.Errorf("agent-only Confidence.Missing = %+v, want it to include Active Directory relationships", s.Confidence.Missing)
	}

	both := []Collection{
		{AgentID: "a", Source: "agent", Nodes: []Node{{ID: "H1", Kind: KindHost}}},
		{AgentID: "a", Source: "sharphound", Nodes: []Node{{ID: "H1", Kind: KindHost}}},
	}
	_, s2 := BuildGraphAndAnalyze(both, nil)
	if s2.Confidence.Level != "High" {
		t.Errorf("agent+sharphound Confidence.Level = %q, want High", s2.Confidence.Level)
	}
	if len(s2.Confidence.Missing) != 0 {
		t.Errorf("agent+sharphound Confidence.Missing = %+v, want empty", s2.Confidence.Missing)
	}

	_, s3 := BuildGraphAndAnalyze(nil, nil)
	if s3.Confidence.Level != "Low" {
		t.Errorf("no collections Confidence.Level = %q, want Low", s3.Confidence.Level)
	}
}

func TestBuildGraphAndAnalyze_DomainCompromiseStatus(t *testing.T) {
	// Reachable: DomainCompromise true regardless of Source.
	reachableCols := []Collection{{AgentID: "a", Source: "agent",
		Nodes: []Node{
			{ID: "WS01", Kind: KindHost}, {ID: "alice", Kind: KindUser}, {ID: "DA", Kind: KindGroup, HighValue: true}, {ID: "DC01", Kind: KindHost},
		},
		Edges: []Edge{
			{From: "WS01", To: "alice", Kind: EdgeHasSession},
			{From: "alice", To: "DA", Kind: EdgeMemberOf},
			{From: "DA", To: "DC01", Kind: EdgeAdminTo},
		}}}
	_, s := BuildGraphAndAnalyze(reachableCols, nil)
	if s.DomainCompromiseStatus != DCStatusReachable {
		t.Errorf("DomainCompromiseStatus = %q, want %q", s.DomainCompromiseStatus, DCStatusReachable)
	}

	// Not-observed: sharphound ran, high-value target exists, but no path found.
	notObservedCols := []Collection{{AgentID: "a", Source: "sharphound",
		Nodes: []Node{{ID: "WS01", Kind: KindHost}, {ID: "DA", Kind: KindGroup, HighValue: true}}}}
	_, s2 := BuildGraphAndAnalyze(notObservedCols, nil)
	if s2.DomainCompromiseStatus != DCStatusNotObserved {
		t.Errorf("DomainCompromiseStatus = %q, want %q", s2.DomainCompromiseStatus, DCStatusNotObserved)
	}

	// Undetermined: no sharphound data at all, no path found.
	undeterminedCols := []Collection{{AgentID: "a", Source: "agent", Nodes: []Node{{ID: "WS01", Kind: KindHost}}}}
	_, s3 := BuildGraphAndAnalyze(undeterminedCols, nil)
	if s3.DomainCompromiseStatus != DCStatusUndetermined {
		t.Errorf("DomainCompromiseStatus = %q, want %q", s3.DomainCompromiseStatus, DCStatusUndetermined)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/attackpath/... -run "TestBuildGraphAndAnalyze_Confidence|TestBuildGraphAndAnalyze_DomainCompromiseStatus" -v`
Expected: FAIL — build error, `s.Confidence`/`s.DomainCompromiseStatus`/`DCStatusReachable` etc. undefined.

- [ ] **Step 3: Add the new types**

In `orchestrator/internal/attackpath/score.go`, find:

```go
// ScoreDriver is one weighted category's contribution to the AttackPathScore
```

Insert directly above it:

```go
// Confidence summarizes which data sources contributed to this graph, so the
// operator knows how much to trust it. Level is derived from which Source
// values (see Collection.Source) are present across the collections merged
// into this graph.
type Confidence struct {
	Level   string   `json:"level"`   // High | Medium | Low
	Based   []string `json:"based"`
	Missing []string `json:"missing"`
}

// DomainCompromiseStatus values. The plain DomainCompromise bool can't
// distinguish "we checked and found no path" from "we never collected the
// data needed to check" -- these three values can.
const (
	DCStatusReachable    = "reachable"
	DCStatusNotObserved  = "not-observed"
	DCStatusUndetermined = "undetermined"
)

// ScoreDriver is one weighted category's contribution to the AttackPathScore
```

And add the two new `Summary` fields. Find:

```go
	ScoreDrivers         []ScoreDriver           `json:"scoreDrivers"`
	RelationshipCounts   map[string]int          `json:"relationshipCounts"` // keyed by EdgeKind string value
}
```

Replace with:

```go
	ScoreDrivers           []ScoreDriver  `json:"scoreDrivers"`
	RelationshipCounts     map[string]int `json:"relationshipCounts"` // keyed by EdgeKind string value
	Confidence             Confidence     `json:"confidence"`
	DomainCompromiseStatus string         `json:"domainCompromiseStatus"` // reachable | not-observed | undetermined
}
```

- [ ] **Step 4: Implement the two helper functions and wire them into `BuildGraphAndAnalyze`**

In `orchestrator/internal/attackpath/assets.go`, find:

```go
// BuildGraphAndAnalyze is BuildAndAnalyze but also returns the built graph,
// for callers (internal/pathcorrelation) that need to run further graph
// queries beyond the Summary.
func BuildGraphAndAnalyze(cols []Collection, tags []AssetTag) (*Graph, Summary) {
	g := BuildGraph(cols...)
	g.applyAssetTags(tags)
	return g, g.Analyze()
}
```

Replace with:

```go
// BuildGraphAndAnalyze is BuildAndAnalyze but also returns the built graph,
// for callers (internal/pathcorrelation) that need to run further graph
// queries beyond the Summary.
func BuildGraphAndAnalyze(cols []Collection, tags []AssetTag) (*Graph, Summary) {
	g := BuildGraph(cols...)
	g.applyAssetTags(tags)
	s := g.Analyze()
	s.Confidence = computeConfidence(cols)
	s.DomainCompromiseStatus = domainCompromiseStatus(s, cols)
	return g, s
}

// computeConfidence derives a High/Medium/Low confidence level from which
// Collection.Source values contributed to this graph.
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

// domainCompromiseStatus disambiguates s.DomainCompromise's bare bool: a
// reachable path is always "reachable" regardless of source; otherwise the
// status depends on whether SharpHound (the source of AD/high-value-target
// data) actually ran.
func domainCompromiseStatus(s Summary, cols []Collection) string {
	if s.DomainCompromise {
		return DCStatusReachable
	}
	for _, c := range cols {
		if c.Source == "sharphound" {
			return DCStatusNotObserved
		}
	}
	return DCStatusUndetermined
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/attackpath/... -v`
Expected: build/vet clean; every test in the package PASSES, including the 2 new tests and every pre-existing test.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/attackpath/score.go orchestrator/internal/attackpath/assets.go orchestrator/internal/attackpath/assets_test.go
git commit -m "feat(attackpath): add Confidence and DomainCompromiseStatus

Both computed in BuildGraphAndAnalyze (which already receives the raw
[]Collection; Analyze() itself stays a pure function of *Graph).
DomainCompromiseStatus fixes a real ambiguity: the existing bool
silently stays false whether a path was checked-and-not-found or
never checked at all (no AD data ever collected) -- now distinguished
as not-observed vs undetermined.

Attack Path results backend enrichment (Sub-project A), piece 3/5."
git push
```

---

### Task 4: `Coverage` (handler-level)

**Files:**
- Modify: `orchestrator/internal/api/attackpath_handlers.go`
- Test: `orchestrator/internal/api/attackpath_collection_test.go`

**Interfaces:**
- Consumes: `attackpath_collection_requests` table (Task 1), `attackpath.NormalizeHostKey` (`assets.go:31`, already exists), `attackpath.BuildGraphAndAnalyze` (Task 3).
- Produces: `coverage` top-level key in `GetAttackPathSummary`'s JSON response. Terminal for the handler layer — nothing later depends on this Go-level.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/attackpath_collection_test.go` (append to the end of the file):

```go
// TestGetAttackPathSummary_CoverageReconciliation pins that Coverage compares
// the most recent request-log row against which targets ended up represented
// in the resulting graph -- never claiming to know *why* a target is missing.
func TestGetAttackPathSummary_CoverageReconciliation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)

		targetsJSON, _ := json.Marshal([]string{"REPRESENTED-HOST", "MISSING-HOST"})
		pool.Exec(context.Background(),
			`INSERT INTO attackpath_collection_requests (agent_id, targets, run_sharphound) VALUES ($1, $2, $3)`,
			"cov-agent", targetsJSON, false)

		c := minimalCollection("cov-agent", "REPRESENTED-HOST", "agent")
		h.SubmitAttackPathCollection(httptest.NewRecorder(), collectionReq(c))

		rec := httptest.NewRecorder()
		h.GetAttackPathSummary(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Coverage struct {
				TargetsRequested   int    `json:"targetsRequested"`
				TargetsRepresented int    `json:"targetsRepresented"`
				Completeness       string `json:"completeness"`
			} `json:"coverage"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Coverage.TargetsRequested != 2 {
			t.Errorf("TargetsRequested = %d, want 2", out.Coverage.TargetsRequested)
		}
		if out.Coverage.TargetsRepresented != 1 {
			t.Errorf("TargetsRepresented = %d, want 1 (only REPRESENTED-HOST appears in the graph)", out.Coverage.TargetsRepresented)
		}
		if out.Coverage.Completeness != "Limited" {
			t.Errorf("Completeness = %q, want Limited", out.Coverage.Completeness)
		}
	})
}

func TestGetAttackPathSummary_CoverageNoRequestLog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		c := minimalCollection("no-reqlog-agent", "H1", "agent")
		h.SubmitAttackPathCollection(httptest.NewRecorder(), collectionReq(c))

		rec := httptest.NewRecorder()
		h.GetAttackPathSummary(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var out struct {
			Coverage struct {
				Completeness string `json:"completeness"`
			} `json:"coverage"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Coverage.Completeness != "Unknown" {
			t.Errorf("Completeness = %q, want Unknown when no request log exists", out.Coverage.Completeness)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestGetAttackPathSummary_Coverage" -v`
Expected: FAIL — the response has no `coverage` key yet, so `out.Coverage` stays zero-valued and the assertions fail (`TargetsRequested`/`TargetsRepresented` both 0, `Completeness` empty string instead of "Limited"/"Unknown").

- [ ] **Step 3: Implement `buildAttackPathCoverage` and wire it into `GetAttackPathSummary`**

In `orchestrator/internal/api/attackpath_handlers.go`, find:

```go
func (h *Handler) GetAttackPathSummary(w http.ResponseWriter, r *http.Request) {
	cols := h.loadAttackPathCollections(r)
	if len(cols) == 0 {
		respond(w, map[string]any{"collected": false})
		return
	}
	s := attackpath.BuildAndAnalyze(cols, h.loadAssetTags(r))
```

Replace with:

```go
func (h *Handler) GetAttackPathSummary(w http.ResponseWriter, r *http.Request) {
	cols := h.loadAttackPathCollections(r)
	if len(cols) == 0 {
		respond(w, map[string]any{"collected": false})
		return
	}
	g, s := attackpath.BuildGraphAndAnalyze(cols, h.loadAssetTags(r))
```

Then find:

```go
	respond(w, map[string]any{
		"collected":        true,
		"agents":           len(cols),
		"summary":          s,
		"latestCollectedAt": latest,
		"agentMeta":        agentMetas,
	})
}
```

Replace with:

```go
	respond(w, map[string]any{
		"collected":         true,
		"agents":            len(cols),
		"summary":           s,
		"coverage":          h.buildAttackPathCoverage(r, g, cols),
		"latestCollectedAt": latest,
		"agentMeta":         agentMetas,
	})
}

// attackPathCoverage compares what was most recently requested against what
// actually ended up represented in the resulting graph. It never claims to
// know *why* a target is missing (offline, firewalled, DNS failure, and
// "never attempted" are all observationally identical from here) -- the
// field is TargetsRepresented, not TargetsCollected, and callers must not
// relabel it as "Collected" in the UI.
type attackPathCoverage struct {
	TargetsRequested    int    `json:"targetsRequested"`
	TargetsRepresented  int    `json:"targetsRepresented"`
	SharpHoundRequested bool   `json:"sharpHoundRequested"`
	SharpHoundAvailable bool   `json:"sharpHoundAvailable"`
	Completeness        string `json:"completeness"` // Full | Limited | Minimal | Unknown
}

func (h *Handler) buildAttackPathCoverage(r *http.Request, g *attackpath.Graph, cols []attackpath.Collection) attackPathCoverage {
	var cov attackPathCoverage
	var targetsRaw []byte
	err := h.db.QueryRow(r.Context(), `
		SELECT targets, run_sharphound FROM attackpath_collection_requests
		ORDER BY requested_at DESC LIMIT 1`).Scan(&targetsRaw, &cov.SharpHoundRequested)
	if err != nil {
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

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/api/... -run "TestGetAttackPathSummary" -v`
Expected: build/vet clean; all `TestGetAttackPathSummary*` tests PASS, including the 2 new ones and the pre-existing `_NotCollected`/`_Success`.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/attackpath_handlers.go orchestrator/internal/api/attackpath_collection_test.go
git commit -m "feat(attackpath): add Coverage to GET /api/attackpath/summary

Computed entirely in the handler (internal/attackpath stays DB-free)
by diffing the most recent request-log row against which targets
ended up as host nodes in the resulting graph. Field is
TargetsRepresented, not TargetsCollected -- the server only knows a
target was requested and whether it appears in the graph, never why
it's missing when it isn't.

Attack Path results backend enrichment (Sub-project A), piece 4/5."
git push
```

---

### Task 5: Remediation text (`pathcorrelation`)

**Files:**
- Create: `orchestrator/internal/pathcorrelation/remediation.go`
- Test: `orchestrator/internal/pathcorrelation/remediation_test.go`
- Modify: `orchestrator/internal/pathcorrelation/types.go` (`PrioritizedGap`)
- Modify: `orchestrator/internal/pathcorrelation/correlate.go` (`buildGaps`)

**Interfaces:**
- Produces: `func RemediationFor(kind attackpath.EdgeKind) string`, `PrioritizedGap.Remediation string`. Terminal task — nothing later depends on this.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/pathcorrelation/remediation_test.go`:

```go
package pathcorrelation

import (
	"testing"

	"github.com/audspect/bas/internal/attackpath"
)

func TestRemediationFor(t *testing.T) {
	cases := []attackpath.EdgeKind{
		attackpath.EdgeSMB, attackpath.EdgeWinRM, attackpath.EdgeRDP,
		attackpath.EdgeAdminTo, attackpath.EdgeHasSession, attackpath.EdgeMemberOf,
		attackpath.EdgeCredential,
	}
	for _, kind := range cases {
		if got := RemediationFor(kind); got == "" {
			t.Errorf("RemediationFor(%s) = \"\", want a non-empty remediation sentence", kind)
		}
	}
	if got := RemediationFor(attackpath.EdgeKind("unknown")); got != "" {
		t.Errorf("RemediationFor(unknown) = %q, want empty string", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/pathcorrelation/... -run TestRemediationFor -v`
Expected: FAIL — build error, `RemediationFor` undefined.

- [ ] **Step 3: Implement `RemediationFor`**

Create `orchestrator/internal/pathcorrelation/remediation.go`:

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
		return "Review this group membership for least-privilege -- it grants inherited access along this path."
	case attackpath.EdgeCredential:
		return "Rotate or remove the exposed credential material enabling this edge."
	default:
		return ""
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go build ./... && go test ./internal/pathcorrelation/... -run TestRemediationFor -v`
Expected: build succeeds; test PASSES.

- [ ] **Step 5: Add `PrioritizedGap.Remediation` and populate it**

In `orchestrator/internal/pathcorrelation/types.go`, find:

```go
type PrioritizedGap struct {
	Edge       attackpath.Edge    `json:"edge"`
	Techniques []TechniqueMapping `json:"techniques"`
	Priority   GapPriority        `json:"priority"`
	Reason     string             `json:"reason"`
	score      float64
}
```

Replace with:

```go
type PrioritizedGap struct {
	Edge        attackpath.Edge    `json:"edge"`
	Techniques  []TechniqueMapping `json:"techniques"`
	Priority    GapPriority        `json:"priority"`
	Reason      string             `json:"reason"`
	Remediation string             `json:"remediation"`
	score       float64
}
```

In `orchestrator/internal/pathcorrelation/correlate.go`, find:

```go
		gaps = append(gaps, PrioritizedGap{
			Edge:       e,
			Techniques: st.Techniques,
			Priority:   priorityFor(score),
			Reason:     gapReason(crossCount[k], totalPaths, dist, st),
			score:      score,
		})
```

Replace with:

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

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/pathcorrelation/... -v`
Expected: build/vet clean; every test in the package PASSES. `correlate_test.go` has no exact `PrioritizedGap{}` struct-literal assertions (confirmed by inspection — its tests check individual fields, not whole-struct equality), so adding `Remediation` doesn't require updating any existing test expectation.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/pathcorrelation/remediation.go orchestrator/internal/pathcorrelation/remediation_test.go orchestrator/internal/pathcorrelation/types.go orchestrator/internal/pathcorrelation/correlate.go
git commit -m "feat(pathcorrelation): add remediation text to PrioritizedGap

RemediationFor mirrors DefaultEdgeTechniqueMapper's exact shape -- a
static curated switch, no dynamic generation. Every already-ranked,
already-scored PrioritizedGap now carries a concrete next action.

Attack Path results backend enrichment (Sub-project A), piece 5/5 --
complete pending Task 6's full regression."
git push
```

---

### Task 6: Full regression

**Files:** none (verification only)

- [ ] **Step 1: Confirm Docker is running**

Run: `docker info 2>&1 | grep -iE "server|error"`
If down, start Docker Desktop and poll: `timeout 180 bash -c 'until docker info >/dev/null 2>&1; do sleep 5; done' && echo "DOCKER_READY"`

- [ ] **Step 2: Run the full Go test suite**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./... -count=1`
Expected: `go build`/`go vet` clean, every package `ok`. If any package fails only under full-suite load (Docker resource contention across concurrent testcontainers was seen repeatedly across the IOC Handling initiative's phases this session), re-run that package standalone: `go test ./internal/<pkg>/... -count=1 -timeout 20m`. A standalone pass confirms it was contention, not a regression.

- [ ] **Step 3: Report completion**

Executes directly on `main`, no branch/worktree/PR decision needed. Confirm with the user that Sub-project A (backend enrichment) is complete, and that Sub-project B (results-page redesign + documentation rewrite, folded together per user decision) is the next part of the Attack Path Validation improvement work — not started, needs its own brainstorm/spec/plan cycle once the user is ready. Sub-project C (change-tracking/diffing across collections) remains deferred beyond that.
