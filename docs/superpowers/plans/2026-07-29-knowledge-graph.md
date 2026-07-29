# Knowledge Graph (Threat Intelligence Relationship API) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A read-only `internal/threatgraph` package that assembles a graph-shaped (`Node`/`Edge`) view of existing threat-intelligence relationships on request, plus one API route `GET /api/knowledge-graph/{type}/{id}` exposing it — no new storage, no UI.

**Architecture:** Five assembly functions (`ActorNeighborhood`, `CampaignNeighborhood`, `MalwareNeighborhood`, `ToolNeighborhood`, `TechniqueNeighborhood`), one per queryable node type, each issuing a small fixed set of already-indexed queries against `threat_actor_profiles`, `intelligence_campaigns`/`malware`/`tools` (their existing `actor_ids`/`technique_ids`/`campaign_ids` array columns), `techniques`, and the bundled `attackdata.GroupTechniqueIndex()`. A single dispatcher (`Neighborhood`) picks the right function by type string; the API handler just calls it and returns JSON.

**Tech Stack:** Go, `internal/threatgraph` (new package, `pgx/v5` direct SQL, no ORM — matches every other package in this codebase), `internal/api` (chi routes).

## Global Constraints

- No new tables, no new storage — every node/edge is assembled at request time. (Spec §Non-Goals)
- No whole-graph/bulk endpoint — only per-entity `GET /api/knowledge-graph/{type}/{id}`. (Spec §Non-Goals)
- No free-text search endpoint — `{id}` is always an explicit key, never a search string. (Spec §Non-Goals)
- Kept fully separate from `internal/attackpath` (different domain — network lateral-movement paths vs. threat-intel relationships), even though both happen to use `Node`/`Edge` vocabulary. No shared code, no shared package.
- No `intrusion_set` node type — this codebase already merges OpenCTI's `intrusionSets` into the same `ThreatActor` representation as `threatActors` (Intelligence Expansion Phase 2). Only `actor`.
- `{id}` semantics are each entity type's own natural key: actor → `threat_actor_profiles.name` (raw name, e.g. `APT29`, not normalized — `NormalizeKey` is lossy and can't be reversed back to the real name); campaign/malware/tool → their own already-`NormalizeKey`'d `.ID`; technique → `technique_id` (e.g. `T1059.001`).
- Relationship vocabulary: `"uses"` (actor/campaign/malware/tool → technique; actor → malware/tool), `"attributed_to"` (actor → campaign), `"targets"` (actor → sector/region), `"used_in"` (malware/tool → campaign, the reverse direction of Malware/Tool's own `CampaignIDs`, needed for `CampaignNeighborhood` to show its malware/tools since `Campaign` itself stores no `MalwareIDs`/`ToolIDs`). Edge direction is always canonical (e.g. always `From: actor, To: technique` for a "uses" edge, regardless of which node the query started from) — never flipped based on which node is the query's center.

---

## File Structure

- Create `orchestrator/internal/threatgraph/types.go` — `Node`, `Edge`, `Neighborhood` types, `NodeType*` constants.
- Create `orchestrator/internal/threatgraph/assemble.go` — the 5 `*Neighborhood` functions, the `Neighborhood` dispatcher, and shared helpers (`techniqueLabel`, `addTechniques`, `addActors`, `addCampaigns`).
- Create `orchestrator/internal/threatgraph/assemble_test.go` — `TestMain` (mirrors `internal/intelligence/store_test.go`'s `sharedDB`/`testutil.TestDB` convention exactly), one test per assembly function, dispatcher error-path tests.
- Modify `orchestrator/internal/api/handlers.go` — no change expected (handler needs only `h.db`, already present); confirmed in Task 3.
- Create `orchestrator/internal/api/threatgraph_handlers.go` — `KnowledgeGraphNeighborhood` handler.
- Modify `orchestrator/internal/api/routes.go` — register `GET /api/knowledge-graph/{type}/{id}`.
- Modify `orchestrator/internal/api/rbac_matrix_test.go` — RBAC matrix entry.

---

### Task 1: `types.go` + shared assembly helpers + `TechniqueNeighborhood`

**Files:**
- Create: `orchestrator/internal/threatgraph/types.go`
- Create: `orchestrator/internal/threatgraph/assemble.go` (helpers + `TechniqueNeighborhood` only this task; the other 4 functions come in Tasks 2-3)
- Create: `orchestrator/internal/threatgraph/assemble_test.go`

**Interfaces:**
- Produces: `type Node struct{ID, Type, Label string}`, `type Edge struct{From, To, Relationship string}`, `type Neighborhood struct{Nodes []Node; Edges []Edge}`, `const NodeTypeActor/Campaign/Malware/Tool/Technique/Sector/Region = "..."`, `func techniqueLabel(ctx, pool, id string) (string, error)`, `func addTechniques(ctx, pool, n *Neighborhood, from string, techIDs []string) error`, `func addActors(n *Neighborhood, from string, names []string, relationship string)`, `func addCampaigns(ctx, pool, n *Neighborhood, from string, ids []string, relationship string) error`, `func TechniqueNeighborhood(ctx, pool, techniqueID string) (Neighborhood, error)` — the helpers here are consumed again by Tasks 2-3.

First, check whether a shared Postgres test-DB helper already exists that this new package can reuse (matching `internal/intelligence`'s exact convention):

```bash
cd orchestrator && grep -n "MustSharedTestDB\|RunWithPool" internal/testutil/testdb.go | head -5
```

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/threatgraph/assemble_test.go`:

```go
package threatgraph

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func TestTechniqueNeighborhood_IncludesActorsFromGroupTechniqueIndex(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	// "Wizard Spider" is a real bundled ATT&CK group -- internal/connector's
	// otx_test.go already relies on this exact fixture assumption.
	wantTechs := attackdata.GroupTechniqueIndex()["Wizard Spider"]
	if len(wantTechs) == 0 {
		t.Fatal("test fixture assumption broken: \"Wizard Spider\" not found in GroupTechniqueIndex()")
	}
	techID := wantTechs[0]

	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		n, err := TechniqueNeighborhood(context.Background(), pool, techID)
		if err != nil {
			t.Fatalf("TechniqueNeighborhood: %v", err)
		}
		if len(n.Nodes) < 2 {
			t.Fatalf("Nodes = %+v, want at least 2 (the technique itself + Wizard Spider)", n.Nodes)
		}
		if n.Nodes[0].Type != NodeTypeTechnique || n.Nodes[0].ID != "technique:"+techID {
			t.Fatalf("Nodes[0] = %+v, want the technique itself first", n.Nodes[0])
		}
		foundActor := false
		for _, node := range n.Nodes {
			if node.Type == NodeTypeActor && node.Label == "Wizard Spider" {
				foundActor = true
			}
		}
		if !foundActor {
			t.Errorf("Nodes = %+v, want to include actor Wizard Spider", n.Nodes)
		}
		foundEdge := false
		for _, e := range n.Edges {
			if e.To == "technique:"+techID && e.Relationship == "uses" {
				foundEdge = true
			}
		}
		if !foundEdge {
			t.Errorf("Edges = %+v, want at least one uses-edge into the technique", n.Edges)
		}
	})
}

func TestTechniqueNeighborhood_UnknownIDReturnsEmptyNeighborhood(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		n, err := TechniqueNeighborhood(context.Background(), pool, "T9999.999")
		if err != nil {
			t.Fatalf("TechniqueNeighborhood: %v", err)
		}
		if len(n.Nodes) != 0 || len(n.Edges) != 0 {
			t.Fatalf("Neighborhood = %+v, want empty for an unknown technique ID", n)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/threatgraph/... -v 2>&1 | head -20`
Expected: FAIL — `no Go files in ...` or `undefined: TechniqueNeighborhood` (the package doesn't exist yet)

- [ ] **Step 3: Create `types.go`**

```go
// Package threatgraph assembles a read-only, graph-shaped view of
// threat-intelligence relationships that already exist across
// threat_actor_profiles, internal/intelligence's Campaign/Malware/Tool
// tables, and the bundled attackdata.GroupTechniqueIndex() -- no new
// storage, nothing to keep in sync. Kept fully separate from
// internal/attackpath, which models a different domain (network
// lateral-movement paths, not threat-intel relationships) despite both
// using Node/Edge vocabulary. See
// docs/superpowers/specs/2026-07-29-knowledge-graph-design.md.
package threatgraph

// Node is one entity in the graph -- an actor, campaign, malware family,
// tool, technique, sector, or region.
type Node struct {
	ID    string `json:"id"`    // "<type>:<key>" -- e.g. "actor:apt29", "technique:T1059.001"
	Type  string `json:"type"`
	Label string `json:"label"`
}

// Edge is one directed, labelled relationship between two Nodes. Direction
// is always canonical (e.g. always From: actor, To: technique for a "uses"
// edge) regardless of which node a query started from.
type Edge struct {
	From         string `json:"from"`
	To           string `json:"to"`
	Relationship string `json:"relationship"` // "uses" | "attributed_to" | "targets" | "used_in"
}

// Neighborhood is one center node plus everything directly (1-hop)
// connected to it. Center is always Nodes[0] when the center itself
// exists; Nodes/Edges are both empty (never nil) when the requested ID
// doesn't exist -- callers/JSON encoders shouldn't need a nil guard, same
// convention internal/intelligence.ListCampaigns already uses.
type Neighborhood struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

const (
	NodeTypeActor     = "actor"
	NodeTypeCampaign  = "campaign"
	NodeTypeMalware   = "malware"
	NodeTypeTool      = "tool"
	NodeTypeTechnique = "technique"
	NodeTypeSector    = "sector"
	NodeTypeRegion    = "region"
)
```

- [ ] **Step 4: Create `assemble.go` with the shared helpers and `TechniqueNeighborhood`**

```go
package threatgraph

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/intelligence"
	"github.com/audspect/bas/internal/reporting/attackdata"
)

// techniqueLabel looks up a technique's display name, falling back to the
// ID itself if not found (a technique referenced by intelligence data
// should always exist in the techniques table, but this is a display
// concern, not a hard failure).
func techniqueLabel(ctx context.Context, pool *pgxpool.Pool, id string) (string, error) {
	var name string
	err := pool.QueryRow(ctx, `SELECT name FROM techniques WHERE technique_id = $1`, id).Scan(&name)
	if err == pgx.ErrNoRows {
		return id, nil
	}
	if err != nil {
		return "", err
	}
	if name == "" {
		return id, nil
	}
	return name, nil
}

// addTechniques appends one technique node and one "uses" edge (from ->
// technique) per ID in techIDs. Shared by every neighborhood function that
// has a TechniqueIDs list (actor via GroupTechniqueIndex, campaign,
// malware, tool).
func addTechniques(ctx context.Context, pool *pgxpool.Pool, n *Neighborhood, from string, techIDs []string) error {
	for _, id := range techIDs {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id == "" {
			continue
		}
		label, err := techniqueLabel(ctx, pool, id)
		if err != nil {
			return err
		}
		nodeID := "technique:" + id
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeTechnique, Label: label})
		n.Edges = append(n.Edges, Edge{From: from, To: nodeID, Relationship: "uses"})
	}
	return nil
}

// addActors appends one actor node and one edge (from -> actor, or actor
// -> from depending on relationship's natural direction -- see call
// sites) per name. No DB lookup needed: an actor's label is its own name,
// already known to the caller (unlike campaign/malware/tool, which need a
// lookup to get a display name from an ID).
func addActors(n *Neighborhood, from string, names []string, relationship string) {
	for _, name := range names {
		if name == "" {
			continue
		}
		nodeID := "actor:" + intelligence.NormalizeKey(name)
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeActor, Label: name})
		n.Edges = append(n.Edges, Edge{From: nodeID, To: from, Relationship: relationship})
	}
}

// addCampaigns appends one campaign node and one edge (campaign -> from)
// per ID in ids, in a single batched query. Shared by Malware/Tool
// neighborhoods (their own CampaignIDs) via "used_in".
func addCampaigns(ctx context.Context, pool *pgxpool.Pool, n *Neighborhood, from string, ids []string, relationship string) error {
	if len(ids) == 0 {
		return nil
	}
	rows, err := pool.Query(ctx, `SELECT id, name FROM intelligence_campaigns WHERE id = ANY($1)`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return err
		}
		nodeID := "campaign:" + id
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeCampaign, Label: name})
		n.Edges = append(n.Edges, Edge{From: nodeID, To: from, Relationship: relationship})
	}
	return rows.Err()
}

// TechniqueNeighborhood assembles the 1-hop neighborhood around a
// technique: every actor whose GroupTechniqueIndex() entry contains it
// (linear scan -- the index is small and cached, see the design doc's
// Non-Goals on why a reverse index isn't built), plus every
// campaign/malware/tool whose TechniqueIDs contains it.
func TechniqueNeighborhood(ctx context.Context, pool *pgxpool.Pool, techniqueID string) (Neighborhood, error) {
	techniqueID = strings.ToUpper(strings.TrimSpace(techniqueID))
	n := Neighborhood{Nodes: []Node{}, Edges: []Edge{}}

	label, err := techniqueLabel(ctx, pool, techniqueID)
	if err != nil {
		return n, err
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM techniques WHERE technique_id = $1)`, techniqueID).Scan(&exists); err != nil {
		return n, err
	}
	if !exists {
		return n, nil
	}

	techNodeID := "technique:" + techniqueID
	n.Nodes = append(n.Nodes, Node{ID: techNodeID, Type: NodeTypeTechnique, Label: label})

	for actorName, techIDs := range attackdata.GroupTechniqueIndex() {
		for _, t := range techIDs {
			if strings.ToUpper(t) == techniqueID {
				actorNodeID := "actor:" + intelligence.NormalizeKey(actorName)
				n.Nodes = append(n.Nodes, Node{ID: actorNodeID, Type: NodeTypeActor, Label: actorName})
				n.Edges = append(n.Edges, Edge{From: actorNodeID, To: techNodeID, Relationship: "uses"})
				break
			}
		}
	}

	for _, table := range []struct {
		name     string
		nodeType string
	}{
		{"intelligence_campaigns", NodeTypeCampaign},
		{"intelligence_malware", NodeTypeMalware},
		{"intelligence_tools", NodeTypeTool},
	} {
		var rows pgx.Rows
		var err error
		switch table.name {
		case "intelligence_campaigns":
			rows, err = pool.Query(ctx, `SELECT id, name FROM intelligence_campaigns WHERE $1 = ANY(technique_ids)`, techniqueID)
		case "intelligence_malware":
			rows, err = pool.Query(ctx, `SELECT id, name FROM intelligence_malware WHERE $1 = ANY(technique_ids)`, techniqueID)
		case "intelligence_tools":
			rows, err = pool.Query(ctx, `SELECT id, name FROM intelligence_tools WHERE $1 = ANY(technique_ids)`, techniqueID)
		}
		if err != nil {
			return n, err
		}
		for rows.Next() {
			var id, name string
			if err := rows.Scan(&id, &name); err != nil {
				rows.Close()
				return n, err
			}
			nodeID := table.nodeType + ":" + id
			n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: table.nodeType, Label: name})
			n.Edges = append(n.Edges, Edge{From: nodeID, To: techNodeID, Relationship: "uses"})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return n, err
		}
	}

	return n, nil
}
```

(The `switch table.name` inside the loop looks slightly awkward but deliberately avoids building SQL from a dynamic table-name string — every query is a literal, fully static SQL string. This codebase has no precedent for dynamic SQL construction anywhere; not introducing one here.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/threatgraph/... -v`
Expected: PASS (2 tests). Docker Desktop must be running — check `docker info` first, start Docker Desktop if needed.

- [ ] **Step 6: Commit**

```bash
git add internal/threatgraph/
git commit -m "feat(threatgraph): Node/Edge types + TechniqueNeighborhood (Knowledge Graph)"
```

---

### Task 2: `ActorNeighborhood`

**Files:**
- Modify: `orchestrator/internal/threatgraph/assemble.go`
- Modify: `orchestrator/internal/threatgraph/assemble_test.go`

**Interfaces:**
- Consumes: `addTechniques`, `addActors` is NOT used here (actors don't add other actors) — `NodeTypeActor` etc. from Task 1.
- Produces: `func ActorNeighborhood(ctx context.Context, pool *pgxpool.Pool, name string) (Neighborhood, error)` — consumed by Task 4's dispatcher.

- [ ] **Step 1: Write the failing test**

Add `"github.com/audspect/bas/internal/intelligence"` to `orchestrator/internal/threatgraph/assemble_test.go`'s import block (needed for `intelligence.NormalizeKey` in the assertions below).

Add to `orchestrator/internal/threatgraph/assemble_test.go`:

```go
func TestActorNeighborhood_AssemblesTechniquesCampaignsMalwareToolsSectorsRegions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	// Uses the real "Wizard Spider" bundled ATT&CK group (same fixture
	// TechniqueNeighborhood's test and internal/connector/otx_test.go rely
	// on) specifically so this test exercises ActorNeighborhood's
	// GroupTechniqueIndex()-backed technique lookup for real, not just the
	// DB-backed campaign/malware/tool/sector/region lookups. A fake actor
	// name would have zero GroupTechniqueIndex() entries and silently skip
	// that code path entirely.
	wantTechs := attackdata.GroupTechniqueIndex()["Wizard Spider"]
	if len(wantTechs) == 0 {
		t.Fatal("test fixture assumption broken: \"Wizard Spider\" not found in GroupTechniqueIndex()")
	}

	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, err := pool.Exec(ctx,
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source)
			 VALUES ($1, '{}', $2, $3, 'test')`,
			"Wizard Spider", []string{"banking"}, []string{"APAC"})
		if err != nil {
			t.Fatalf("seed threat_actor_profiles: %v", err)
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO intelligence_campaigns (id, name, description, actor_ids, technique_ids, source_provider)
			 VALUES ('kgtestcampaign', 'KG Test Campaign', '', $1, '{}', 'test')`,
			[]string{"Wizard Spider"})
		if err != nil {
			t.Fatalf("seed intelligence_campaigns: %v", err)
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO intelligence_malware (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider)
			 VALUES ('kgtestmalware', 'KG Test Malware', '{}', '{}', $1, '{}', 'test')`,
			[]string{"Wizard Spider"})
		if err != nil {
			t.Fatalf("seed intelligence_malware: %v", err)
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO intelligence_tools (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider)
			 VALUES ('kgtesttool', 'KG Test Tool', '{}', '{}', $1, '{}', 'test')`,
			[]string{"Wizard Spider"})
		if err != nil {
			t.Fatalf("seed intelligence_tools: %v", err)
		}

		n, err := ActorNeighborhood(ctx, pool, "Wizard Spider")
		if err != nil {
			t.Fatalf("ActorNeighborhood: %v", err)
		}
		if n.Nodes[0].ID != "actor:"+intelligence.NormalizeKey("Wizard Spider") || n.Nodes[0].Type != NodeTypeActor {
			t.Fatalf("Nodes[0] = %+v, want the actor itself first", n.Nodes[0])
		}
		wantTypes := map[string]bool{NodeTypeTechnique: false, NodeTypeCampaign: false, NodeTypeMalware: false, NodeTypeTool: false, NodeTypeSector: false, NodeTypeRegion: false}
		for _, node := range n.Nodes[1:] {
			if _, ok := wantTypes[node.Type]; ok {
				wantTypes[node.Type] = true
			}
		}
		for nodeType, found := range wantTypes {
			if !found {
				t.Errorf("Nodes = %+v, missing a node of type %q", n.Nodes, nodeType)
			}
		}
		techniqueEdges := 0
		for _, e := range n.Edges {
			if e.Relationship == "uses" && e.From == "actor:"+intelligence.NormalizeKey("Wizard Spider") {
				techniqueEdges++
			}
		}
		if techniqueEdges != len(wantTechs) {
			t.Errorf("actor->technique 'uses' edges = %d, want %d (len(GroupTechniqueIndex()[\"Wizard Spider\"]))", techniqueEdges, len(wantTechs))
		}
	})
}

func TestActorNeighborhood_UnknownNameReturnsEmptyNeighborhood(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		n, err := ActorNeighborhood(context.Background(), pool, "NoSuchActor")
		if err != nil {
			t.Fatalf("ActorNeighborhood: %v", err)
		}
		if len(n.Nodes) != 0 || len(n.Edges) != 0 {
			t.Fatalf("Neighborhood = %+v, want empty for an unknown actor", n)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/threatgraph/... -run TestActorNeighborhood -v`
Expected: FAIL — `undefined: ActorNeighborhood`

- [ ] **Step 3: Add `ActorNeighborhood`**

In `orchestrator/internal/threatgraph/assemble.go`, add after `TechniqueNeighborhood`:

```go
// ActorNeighborhood assembles the 1-hop neighborhood around a threat
// actor: its techniques (attackdata.GroupTechniqueIndex(), keyed by
// canonical actor name), campaigns/malware/tools that list it in their
// ThreatActorIDs, and its sectors/regions (threat_actor_profiles).
func ActorNeighborhood(ctx context.Context, pool *pgxpool.Pool, name string) (Neighborhood, error) {
	n := Neighborhood{Nodes: []Node{}, Edges: []Edge{}}

	var sectors, regions []string
	err := pool.QueryRow(ctx, `SELECT sectors, regions FROM threat_actor_profiles WHERE name = $1`, name).Scan(&sectors, &regions)
	if err == pgx.ErrNoRows {
		return n, nil
	}
	if err != nil {
		return n, err
	}

	actorID := "actor:" + intelligence.NormalizeKey(name)
	n.Nodes = append(n.Nodes, Node{ID: actorID, Type: NodeTypeActor, Label: name})

	if err := addTechniques(ctx, pool, &n, actorID, attackdata.GroupTechniqueIndex()[name]); err != nil {
		return n, err
	}

	campaignRows, err := pool.Query(ctx, `SELECT id, name FROM intelligence_campaigns WHERE $1 = ANY(actor_ids)`, name)
	if err != nil {
		return n, err
	}
	for campaignRows.Next() {
		var id, cname string
		if err := campaignRows.Scan(&id, &cname); err != nil {
			campaignRows.Close()
			return n, err
		}
		nodeID := "campaign:" + id
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeCampaign, Label: cname})
		n.Edges = append(n.Edges, Edge{From: actorID, To: nodeID, Relationship: "attributed_to"})
	}
	campaignRows.Close()
	if err := campaignRows.Err(); err != nil {
		return n, err
	}

	malwareRows, err := pool.Query(ctx, `SELECT id, name FROM intelligence_malware WHERE $1 = ANY(actor_ids)`, name)
	if err != nil {
		return n, err
	}
	for malwareRows.Next() {
		var id, mname string
		if err := malwareRows.Scan(&id, &mname); err != nil {
			malwareRows.Close()
			return n, err
		}
		nodeID := "malware:" + id
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeMalware, Label: mname})
		n.Edges = append(n.Edges, Edge{From: actorID, To: nodeID, Relationship: "uses"})
	}
	malwareRows.Close()
	if err := malwareRows.Err(); err != nil {
		return n, err
	}

	toolRows, err := pool.Query(ctx, `SELECT id, name FROM intelligence_tools WHERE $1 = ANY(actor_ids)`, name)
	if err != nil {
		return n, err
	}
	for toolRows.Next() {
		var id, tname string
		if err := toolRows.Scan(&id, &tname); err != nil {
			toolRows.Close()
			return n, err
		}
		nodeID := "tool:" + id
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeTool, Label: tname})
		n.Edges = append(n.Edges, Edge{From: actorID, To: nodeID, Relationship: "uses"})
	}
	toolRows.Close()
	if err := toolRows.Err(); err != nil {
		return n, err
	}

	for _, s := range sectors {
		nodeID := "sector:" + intelligence.NormalizeKey(s)
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeSector, Label: s})
		n.Edges = append(n.Edges, Edge{From: actorID, To: nodeID, Relationship: "targets"})
	}
	for _, r := range regions {
		nodeID := "region:" + intelligence.NormalizeKey(r)
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeRegion, Label: r})
		n.Edges = append(n.Edges, Edge{From: actorID, To: nodeID, Relationship: "targets"})
	}

	return n, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/threatgraph/... -run TestActorNeighborhood -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Run the full package**

Run: `cd orchestrator && go test ./internal/threatgraph/... -v`
Expected: PASS (all tests from Tasks 1-2)

- [ ] **Step 6: Commit**

```bash
git add internal/threatgraph/
git commit -m "feat(threatgraph): ActorNeighborhood (Knowledge Graph)"
```

---

### Task 3: `CampaignNeighborhood`, `MalwareNeighborhood`, `ToolNeighborhood` + dispatcher

**Files:**
- Modify: `orchestrator/internal/threatgraph/assemble.go`
- Modify: `orchestrator/internal/threatgraph/assemble_test.go`

**Interfaces:**
- Consumes: `addTechniques`, `addActors`, `addCampaigns` (Task 1); `TechniqueNeighborhood`, `ActorNeighborhood` (Tasks 1-2, referenced by the dispatcher).
- Produces: `func CampaignNeighborhood(ctx, pool, id string) (Neighborhood, error)`, `func MalwareNeighborhood(ctx, pool, id string) (Neighborhood, error)`, `func ToolNeighborhood(ctx, pool, id string) (Neighborhood, error)`, `func Neighborhood(ctx, pool, nodeType, id string) (Neighborhood, error)` — the dispatcher is consumed by Task 5's API handler.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/threatgraph/assemble_test.go`:

```go
func TestCampaignNeighborhood_IncludesActorsTechniquesMalwareTools(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, err := pool.Exec(ctx,
			`INSERT INTO intelligence_campaigns (id, name, description, actor_ids, technique_ids, source_provider)
			 VALUES ('kgcampaign2', 'KG Campaign Two', '', $1, $2, 'test')`,
			[]string{"KGActor2"}, []string{"T1059"})
		if err != nil {
			t.Fatalf("seed intelligence_campaigns: %v", err)
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO intelligence_malware (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider)
			 VALUES ('kgmalware2', 'KG Malware Two', '{}', '{}', '{}', $1, 'test')`,
			[]string{"kgcampaign2"})
		if err != nil {
			t.Fatalf("seed intelligence_malware: %v", err)
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO intelligence_tools (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider)
			 VALUES ('kgtool2', 'KG Tool Two', '{}', '{}', '{}', $1, 'test')`,
			[]string{"kgcampaign2"})
		if err != nil {
			t.Fatalf("seed intelligence_tools: %v", err)
		}

		n, err := CampaignNeighborhood(ctx, pool, "kgcampaign2")
		if err != nil {
			t.Fatalf("CampaignNeighborhood: %v", err)
		}
		if n.Nodes[0].ID != "campaign:kgcampaign2" {
			t.Fatalf("Nodes[0] = %+v, want the campaign itself first", n.Nodes[0])
		}
		wantTypes := map[string]bool{NodeTypeActor: false, NodeTypeTechnique: false, NodeTypeMalware: false, NodeTypeTool: false}
		for _, node := range n.Nodes[1:] {
			if _, ok := wantTypes[node.Type]; ok {
				wantTypes[node.Type] = true
			}
		}
		for nodeType, found := range wantTypes {
			if !found {
				t.Errorf("Nodes = %+v, missing a node of type %q", n.Nodes, nodeType)
			}
		}
	})
}

func TestMalwareNeighborhood_IncludesActorsTechniquesCampaigns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, err := pool.Exec(ctx,
			`INSERT INTO intelligence_campaigns (id, name, description, actor_ids, technique_ids, source_provider)
			 VALUES ('kgcampaign3', 'KG Campaign Three', '', '{}', '{}', 'test')`)
		if err != nil {
			t.Fatalf("seed intelligence_campaigns: %v", err)
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO intelligence_malware (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider)
			 VALUES ('kgmalware3', 'KG Malware Three', '{}', $1, $2, $3, 'test')`,
			[]string{"T1105"}, []string{"KGActor3"}, []string{"kgcampaign3"})
		if err != nil {
			t.Fatalf("seed intelligence_malware: %v", err)
		}

		n, err := MalwareNeighborhood(ctx, pool, "kgmalware3")
		if err != nil {
			t.Fatalf("MalwareNeighborhood: %v", err)
		}
		if n.Nodes[0].ID != "malware:kgmalware3" {
			t.Fatalf("Nodes[0] = %+v, want the malware itself first", n.Nodes[0])
		}
		wantTypes := map[string]bool{NodeTypeActor: false, NodeTypeTechnique: false, NodeTypeCampaign: false}
		for _, node := range n.Nodes[1:] {
			if _, ok := wantTypes[node.Type]; ok {
				wantTypes[node.Type] = true
			}
		}
		for nodeType, found := range wantTypes {
			if !found {
				t.Errorf("Nodes = %+v, missing a node of type %q", n.Nodes, nodeType)
			}
		}
	})
}

func TestToolNeighborhood_IncludesActorsTechniquesCampaigns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, err := pool.Exec(ctx,
			`INSERT INTO intelligence_campaigns (id, name, description, actor_ids, technique_ids, source_provider)
			 VALUES ('kgcampaign4', 'KG Campaign Four', '', '{}', '{}', 'test')`)
		if err != nil {
			t.Fatalf("seed intelligence_campaigns: %v", err)
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO intelligence_tools (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider)
			 VALUES ('kgtool4', 'KG Tool Four', '{}', $1, $2, $3, 'test')`,
			[]string{"T1018"}, []string{"KGActor4"}, []string{"kgcampaign4"})
		if err != nil {
			t.Fatalf("seed intelligence_tools: %v", err)
		}

		n, err := ToolNeighborhood(ctx, pool, "kgtool4")
		if err != nil {
			t.Fatalf("ToolNeighborhood: %v", err)
		}
		if n.Nodes[0].ID != "tool:kgtool4" {
			t.Fatalf("Nodes[0] = %+v, want the tool itself first", n.Nodes[0])
		}
		wantTypes := map[string]bool{NodeTypeActor: false, NodeTypeTechnique: false, NodeTypeCampaign: false}
		for _, node := range n.Nodes[1:] {
			if _, ok := wantTypes[node.Type]; ok {
				wantTypes[node.Type] = true
			}
		}
		for nodeType, found := range wantTypes {
			if !found {
				t.Errorf("Nodes = %+v, missing a node of type %q", n.Nodes, nodeType)
			}
		}
	})
}

func TestNeighborhood_DispatchesByType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if _, err := Neighborhood(context.Background(), pool, NodeTypeActor, "NoSuchActor"); err != nil {
			t.Errorf("Neighborhood(actor): %v", err)
		}
		if _, err := Neighborhood(context.Background(), pool, "bogus-type", "x"); err == nil {
			t.Error("Neighborhood(bogus-type) = nil error, want an error for an unknown type")
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/threatgraph/... -run 'TestCampaignNeighborhood|TestMalwareNeighborhood|TestToolNeighborhood|TestNeighborhood_Dispatches' -v`
Expected: FAIL — `undefined: CampaignNeighborhood` (and siblings)

- [ ] **Step 3: Add `CampaignNeighborhood`, `MalwareNeighborhood`, `ToolNeighborhood`, and the dispatcher**

In `orchestrator/internal/threatgraph/assemble.go`, add after `ActorNeighborhood`:

```go
// CampaignNeighborhood assembles the 1-hop neighborhood around a
// campaign: its own ThreatActorIDs and TechniqueIDs, plus every
// malware/tool that references it in their CampaignIDs (the reverse
// direction -- Campaign itself stores no MalwareIDs/ToolIDs).
func CampaignNeighborhood(ctx context.Context, pool *pgxpool.Pool, id string) (Neighborhood, error) {
	n := Neighborhood{Nodes: []Node{}, Edges: []Edge{}}

	var name string
	var actorIDs, techIDs []string
	err := pool.QueryRow(ctx, `SELECT name, actor_ids, technique_ids FROM intelligence_campaigns WHERE id = $1`, id).
		Scan(&name, &actorIDs, &techIDs)
	if err == pgx.ErrNoRows {
		return n, nil
	}
	if err != nil {
		return n, err
	}

	campaignID := "campaign:" + id
	n.Nodes = append(n.Nodes, Node{ID: campaignID, Type: NodeTypeCampaign, Label: name})

	addActors(&n, campaignID, actorIDs, "attributed_to")
	if err := addTechniques(ctx, pool, &n, campaignID, techIDs); err != nil {
		return n, err
	}

	malwareRows, err := pool.Query(ctx, `SELECT id, name FROM intelligence_malware WHERE $1 = ANY(campaign_ids)`, id)
	if err != nil {
		return n, err
	}
	for malwareRows.Next() {
		var mid, mname string
		if err := malwareRows.Scan(&mid, &mname); err != nil {
			malwareRows.Close()
			return n, err
		}
		nodeID := "malware:" + mid
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeMalware, Label: mname})
		n.Edges = append(n.Edges, Edge{From: nodeID, To: campaignID, Relationship: "used_in"})
	}
	malwareRows.Close()
	if err := malwareRows.Err(); err != nil {
		return n, err
	}

	toolRows, err := pool.Query(ctx, `SELECT id, name FROM intelligence_tools WHERE $1 = ANY(campaign_ids)`, id)
	if err != nil {
		return n, err
	}
	for toolRows.Next() {
		var tid, tname string
		if err := toolRows.Scan(&tid, &tname); err != nil {
			toolRows.Close()
			return n, err
		}
		nodeID := "tool:" + tid
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeTool, Label: tname})
		n.Edges = append(n.Edges, Edge{From: nodeID, To: campaignID, Relationship: "used_in"})
	}
	toolRows.Close()
	if err := toolRows.Err(); err != nil {
		return n, err
	}

	return n, nil
}

// MalwareNeighborhood assembles the 1-hop neighborhood around a malware
// family: its own ThreatActorIDs, TechniqueIDs, and CampaignIDs.
func MalwareNeighborhood(ctx context.Context, pool *pgxpool.Pool, id string) (Neighborhood, error) {
	n := Neighborhood{Nodes: []Node{}, Edges: []Edge{}}

	var name string
	var actorIDs, techIDs, campaignIDs []string
	err := pool.QueryRow(ctx, `SELECT name, actor_ids, technique_ids, campaign_ids FROM intelligence_malware WHERE id = $1`, id).
		Scan(&name, &actorIDs, &techIDs, &campaignIDs)
	if err == pgx.ErrNoRows {
		return n, nil
	}
	if err != nil {
		return n, err
	}

	malwareID := "malware:" + id
	n.Nodes = append(n.Nodes, Node{ID: malwareID, Type: NodeTypeMalware, Label: name})

	addActors(&n, malwareID, actorIDs, "uses")
	if err := addTechniques(ctx, pool, &n, malwareID, techIDs); err != nil {
		return n, err
	}
	if err := addCampaigns(ctx, pool, &n, malwareID, campaignIDs, "used_in"); err != nil {
		return n, err
	}
	return n, nil
}

// ToolNeighborhood mirrors MalwareNeighborhood exactly (same field shape).
func ToolNeighborhood(ctx context.Context, pool *pgxpool.Pool, id string) (Neighborhood, error) {
	n := Neighborhood{Nodes: []Node{}, Edges: []Edge{}}

	var name string
	var actorIDs, techIDs, campaignIDs []string
	err := pool.QueryRow(ctx, `SELECT name, actor_ids, technique_ids, campaign_ids FROM intelligence_tools WHERE id = $1`, id).
		Scan(&name, &actorIDs, &techIDs, &campaignIDs)
	if err == pgx.ErrNoRows {
		return n, nil
	}
	if err != nil {
		return n, err
	}

	toolID := "tool:" + id
	n.Nodes = append(n.Nodes, Node{ID: toolID, Type: NodeTypeTool, Label: name})

	addActors(&n, toolID, actorIDs, "uses")
	if err := addTechniques(ctx, pool, &n, toolID, techIDs); err != nil {
		return n, err
	}
	if err := addCampaigns(ctx, pool, &n, toolID, campaignIDs, "used_in"); err != nil {
		return n, err
	}
	return n, nil
}

// Neighborhood dispatches to the right assembly function by node type --
// the single entry point internal/api's handler calls.
func Neighborhood(ctx context.Context, pool *pgxpool.Pool, nodeType, id string) (Neighborhood, error) {
	switch nodeType {
	case NodeTypeActor:
		return ActorNeighborhood(ctx, pool, id)
	case NodeTypeCampaign:
		return CampaignNeighborhood(ctx, pool, id)
	case NodeTypeMalware:
		return MalwareNeighborhood(ctx, pool, id)
	case NodeTypeTool:
		return ToolNeighborhood(ctx, pool, id)
	case NodeTypeTechnique:
		return TechniqueNeighborhood(ctx, pool, id)
	default:
		return Neighborhood{}, fmt.Errorf("unknown node type %q", nodeType)
	}
}
```

Add `"fmt"` to the import block (used by the dispatcher's error).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/threatgraph/... -v`
Expected: PASS — every test in the package, Tasks 1-3 combined.

- [ ] **Step 5: Commit**

```bash
git add internal/threatgraph/
git commit -m "feat(threatgraph): Campaign/Malware/Tool neighborhoods + dispatcher (Knowledge Graph)"
```

---

### Task 4: `GET /api/knowledge-graph/{type}/{id}` + RBAC

**Files:**
- Create: `orchestrator/internal/api/threatgraph_handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `threatgraph.Neighborhood` (Task 3).
- Produces: `func (h *Handler) KnowledgeGraphNeighborhood(w http.ResponseWriter, r *http.Request)`, route `GET /api/knowledge-graph/{type}/{id}`.

- [ ] **Step 1: Write the failing RBAC matrix test entry**

In `orchestrator/internal/api/rbac_matrix_test.go`, find the three existing lines:

```go
	{http.MethodGet, "/api/intelligence/campaigns", tierAny, ""},
	{http.MethodGet, "/api/intelligence/malware", tierAny, ""},
	{http.MethodGet, "/api/intelligence/tools", tierAny, ""},
```

Add directly after:

```go
	{http.MethodGet, "/api/knowledge-graph/{type}/{id}", tierAny, ""},
```

- [ ] **Step 2: Run the RBAC matrix test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix -v`
Expected: FAIL — route `/api/knowledge-graph/{type}/{id}` not registered

- [ ] **Step 3: Add the handler**

Create `orchestrator/internal/api/threatgraph_handlers.go`:

```go
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/threatgraph"
)

// GET /api/knowledge-graph/{type}/{id}
func (h *Handler) KnowledgeGraphNeighborhood(w http.ResponseWriter, r *http.Request) {
	nodeType := chi.URLParam(r, "type")
	id := chi.URLParam(r, "id")
	n, err := threatgraph.Neighborhood(r.Context(), h.db, nodeType, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	respond(w, n)
}
```

(`threatgraph.Neighborhood` only returns an error for an unrecognized `nodeType` string — Task 3's assembly functions all return an empty `Neighborhood` with a `nil` error for a well-formed type with an unknown ID, per the design's "empty slice, not error" convention. So every error this handler sees is a bad `{type}`, correctly mapped to `400 Bad Request`.)

Check the exact chi import path/alias this codebase already uses before adding it, to match style exactly:

```bash
cd orchestrator && grep -n "go-chi/chi" internal/api/threatpriority_handlers.go
```

- [ ] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, find:

```go
		r.Get("/api/intelligence/campaigns", h.IntelligenceCampaigns)
		r.Get("/api/intelligence/malware", h.IntelligenceMalware)
		r.Get("/api/intelligence/tools", h.IntelligenceTools)
```

Add directly after:

```go
		r.Get("/api/knowledge-graph/{type}/{id}", h.KnowledgeGraphNeighborhood)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix -v`
Expected: PASS

- [ ] **Step 6: Run the full `internal/api` test suite to confirm no other regressions**

Run: `cd orchestrator && go test ./internal/api/... -v`
Expected: PASS across the whole package. (This package is large — if it times out interactively, run it with `run_in_background` and check the result once it completes.)

- [ ] **Step 7: Commit**

```bash
git add internal/api/threatgraph_handlers.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(api): GET /api/knowledge-graph/{type}/{id} (Knowledge Graph)"
```

---

### Task 5: Full regression

**Files:** none (verification only)

- [ ] **Step 1: Full build**

Run: `cd orchestrator && go build ./...`
Expected: no errors

- [ ] **Step 2: Full vet**

Run: `cd orchestrator && go vet ./...`
Expected: no errors

- [ ] **Step 3: Full test suite**

Run: `cd orchestrator && go test ./... -count=1` (run in background if it exceeds the interactive timeout — this project's full suite takes several minutes)
Expected: PASS across all packages (Docker Desktop must be running). If a single unrelated package fails with a `testcontainers`/Docker provider connection error, re-run that package alone before treating it as a real regression — this project has hit transient Docker-provider flakes under full-suite load multiple times before (Phase 4, Phase 5).

- [ ] **Step 4: Confirm `internal/threatgraph` has no import-cycle or naming collision with `internal/attackpath`**

```bash
cd orchestrator && go build ./internal/threatgraph/... ./internal/attackpath/... 2>&1
```

Expected: no errors (Step 1 already proves this, but this is a targeted confirmation of the specific Non-Goal — both packages define their own unexported/exported `Node`/`Edge` types with no shared import between them).
