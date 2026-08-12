# Per-Relationship Technique Evidence Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface OpenCTI's real per-relationship "uses → technique" evidence (confidence, dates, and whether it came from the actor directly or via a linked campaign/malware/tool) on the actor detail view, for OpenCTI-sourced actors only.

**Architecture:** `OpenCTIClient` gains a new `TechniqueEvidenceSource` capability (mirroring the existing `IntelligenceSource` pattern) that extracts `confidence`/`start_time`/`stop_time` from the same 4 relationship-edge query blocks that already fetch technique IDs. `Scheduler.sync()` collects this alongside the existing curated-source loop, resolves it against the merged roster (reusing `resolveActivitySignalActor`, unmodified), and persists to a new `technique_evidence` table. Scoring is untouched — this is a read-only display layer, like the Sources card.

**Tech Stack:** Go (`internal/connector`, `internal/api`), Postgres via pgx, vanilla JS in `orchestrator/wwwroot/index.html`.

## Global Constraints

- No change to `internal/threatpriority`'s scoring — `Context.TechniqueIDs` stays a flat `[]string`, no `ScoreFactor` signature changes.
- MISP and the bundle source are structurally incapable of supplying this data (see spec) — only `OpenCTIClient` implements `TechniqueEvidenceSource`.
- Evidence for an actor with no existing curated profile is dropped, not stubbed (unlike OTX's activity signals) — this enriches an actor that must already exist.
- A technique reached via multiple paths (direct + via a campaign, say) gets multiple rows — never deduplicated/merged into one.
- **Pre-merge verification required**: the `confidence`/`start_time`/`stop_time` GraphQL field names are inferred from STIX 2.1 conventions, not confirmed against a live OpenCTI instance (same category of unverified assumption as this file's existing sector/region comment). Flag this explicitly when reporting completion — it needs checking against a real OpenCTI instance before the query can be trusted in production.

---

### Task 1: `TechniqueEvidence` extraction from OpenCTI

**Files:**
- Modify: `orchestrator/internal/connector/source.go` (add `TechniqueEvidenceSource` interface, `TechniqueEvidence` type)
- Modify: `orchestrator/internal/connector/opencti.go` (query fragment, `octiRelationshipNode` named type, extraction, `Fetch()` wiring)
- Modify: `orchestrator/internal/connector/opencti_intelligence_test.go` (11 existing `Node: struct {...}{...}` literals must be rewritten to the new named type — this is a required, mechanical part of this task, not optional cleanup: the anonymous struct type changes shape once fields are added, so old literals stop compiling)
- Test: same file, append new tests after the literal-syntax migration

**Interfaces:**
- Produces: `type TechniqueEvidenceSource interface { FetchTechniqueEvidence() []TechniqueEvidence }` and `type TechniqueEvidence struct { ActorName, TechniqueID, Via, ViaName string; Confidence int; StartTime, StopTime *time.Time }` (`internal/connector`) — consumed by Task 2's `Scheduler`.

- [ ] **Step 1: Migrate existing test literals to a named type first (required before anything else compiles)**

In `orchestrator/internal/connector/opencti.go`, replace:

```go
type octiRelationshipEdge struct {
	Node struct {
		To   octiRelatedEntity `json:"to"`
		From octiRelatedEntity `json:"from"`
	} `json:"node"`
}
```

with:

```go
// octiRelationshipNode is the "node" of one stixCoreRelationships edge --
// named (not the previous inline anonymous struct) so it can carry the
// relationship's own STIX properties (Confidence/StartTime/StopTime)
// without every construction site needing to repeat the full field list.
type octiRelationshipNode struct {
	To         octiRelatedEntity `json:"to"`
	From       octiRelatedEntity `json:"from"`
	Confidence int               `json:"confidence"`
	StartTime  string            `json:"start_time"`
	StopTime   string            `json:"stop_time"`
}

type octiRelationshipEdge struct {
	Node octiRelationshipNode `json:"node"`
}
```

In `orchestrator/internal/connector/opencti_intelligence_test.go`, every occurrence of the pattern:

```go
{Node: struct {
	To   octiRelatedEntity `json:"to"`
	From octiRelatedEntity `json:"from"`
}{To: octiRelatedEntity{...}}}
```

(or the `From: octiRelatedEntity{...}` variant) becomes:

```go
{Node: octiRelationshipNode{To: octiRelatedEntity{...}}}
```

(or `{Node: octiRelationshipNode{From: octiRelatedEntity{...}}}`). There are 11 such sites in this file (lines 15, 19, 37, 58, 73, 117, 121, 193, 237, 243, 249 as of this session — re-grep `Node: struct {` at execution time to get the current exact set, since line numbers drift). Each replacement is purely mechanical: same `To`/`From` value, shorter literal, identical runtime behavior.

Run: `cd orchestrator && go build ./... 2>&1 | head -30`
Expected: FAIL with 11 "cannot use ... (value of type struct{...}) as octiRelationshipNode value" (or similar) errors until every site is migrated. Keep migrating until `go build ./...` succeeds with zero errors.

- [ ] **Step 2: Confirm the whole package still passes with zero behavior change**

Run: `cd orchestrator && go test ./internal/connector/... -run 'TestTechniqueRefsFrom|TestCampaignEntitiesFrom|TestMalwareEntitiesFrom|TestToolEntitiesFrom|TestOpenCTIClient' -v`
Expected: every pre-existing test in this file still PASSes, unchanged in behavior (only the literal syntax changed, not what it constructs).

- [ ] **Step 3: Write the failing tests for the new extraction**

Append to `orchestrator/internal/connector/opencti_intelligence_test.go`:

```go

func TestTechniqueEvidenceFrom_ExtractsConfidenceAndDates(t *testing.T) {
	start := "2026-01-10T00:00:00Z"
	stop := "2026-02-01T00:00:00Z"
	conn := octiRelationshipConnection{
		Edges: []octiRelationshipEdge{
			{Node: octiRelationshipNode{
				To:         octiRelatedEntity{XMitreID: "T1059.001", Name: "PowerShell"},
				Confidence: 75, StartTime: start, StopTime: stop,
			}},
		},
	}
	ev := techniqueEvidenceFrom(conn, "APT-EVID", "", "")
	if len(ev) != 1 {
		t.Fatalf("techniqueEvidenceFrom() = %+v, want 1 entry", ev)
	}
	e := ev[0]
	if e.ActorName != "APT-EVID" || e.TechniqueID != "T1059.001" || e.Via != "" || e.ViaName != "" {
		t.Fatalf("evidence = %+v, want ActorName=APT-EVID TechniqueID=T1059.001 Via=\"\" ViaName=\"\"", e)
	}
	if e.Confidence != 75 {
		t.Fatalf("Confidence = %d, want 75", e.Confidence)
	}
	wantStart, _ := time.Parse(time.RFC3339, start)
	wantStop, _ := time.Parse(time.RFC3339, stop)
	if e.StartTime == nil || !e.StartTime.Equal(wantStart) {
		t.Errorf("StartTime = %v, want %v", e.StartTime, wantStart)
	}
	if e.StopTime == nil || !e.StopTime.Equal(wantStop) {
		t.Errorf("StopTime = %v, want %v", e.StopTime, wantStop)
	}
}

func TestTechniqueEvidenceFrom_TagsViaAndViaName(t *testing.T) {
	conn := octiRelationshipConnection{
		Edges: []octiRelationshipEdge{
			{Node: octiRelationshipNode{To: octiRelatedEntity{XMitreID: "T1566.001", Name: "Spearphishing"}}},
		},
	}
	ev := techniqueEvidenceFrom(conn, "APT-EVID", "campaign", "Operation Ghost")
	if len(ev) != 1 || ev[0].Via != "campaign" || ev[0].ViaName != "Operation Ghost" {
		t.Fatalf("evidence = %+v, want Via=campaign ViaName=\"Operation Ghost\"", ev)
	}
}

func TestTechniqueEvidenceFrom_SkipsInvalidATTACKIDs(t *testing.T) {
	conn := octiRelationshipConnection{
		Edges: []octiRelationshipEdge{
			{Node: octiRelationshipNode{To: octiRelatedEntity{XMitreID: "not-an-id"}}},
		},
	}
	if ev := techniqueEvidenceFrom(conn, "APT-EVID", "", ""); len(ev) != 0 {
		t.Fatalf("techniqueEvidenceFrom() = %+v, want none (invalid ATT&CK ID)", ev)
	}
}

func TestTechniqueEvidenceFrom_MissingDatesLeavesNilPointers(t *testing.T) {
	conn := octiRelationshipConnection{
		Edges: []octiRelationshipEdge{
			{Node: octiRelationshipNode{To: octiRelatedEntity{XMitreID: "T1059"}}},
		},
	}
	ev := techniqueEvidenceFrom(conn, "APT-EVID", "", "")
	if len(ev) != 1 || ev[0].StartTime != nil || ev[0].StopTime != nil {
		t.Fatalf("evidence = %+v, want nil StartTime/StopTime when the source sent no dates", ev)
	}
}

// TestOpenCTIClient_Fetch_PopulatesTechniqueEvidenceAcrossAllFourSites proves
// evidence accumulates from the actor's own attackPatterns AND from each
// linked campaign/malware/tool's nested attackPatterns, each tagged with
// its own Via/ViaName -- the core contract this whole feature rests on.
func TestOpenCTIClient_Fetch_PopulatesTechniqueEvidenceAcrossAllFourSites(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := octiThreatActorsResp{}
		resp.Data.ThreatActors.Edges = []octiActorEdge{
			{Node: octiThreatActorNode{
				ID: "ta-1", Name: "EvidenceActor",
				AttackPatterns: octiRelationshipConnection{Edges: []octiRelationshipEdge{
					{Node: octiRelationshipNode{To: octiRelatedEntity{XMitreID: "T1059"}, Confidence: 80}},
					{Node: octiRelationshipNode{To: octiRelatedEntity{XMitreID: "T1105"}, Confidence: 60}},
				}},
				Campaigns: octiRelationshipConnection{Edges: []octiRelationshipEdge{
					{Node: octiRelationshipNode{From: octiRelatedEntity{
						ID: "campaign--1", Name: "Operation Ghost",
						AttackPatterns: octiRelationshipConnection{Edges: []octiRelationshipEdge{
							{Node: octiRelationshipNode{To: octiRelatedEntity{XMitreID: "T1566.001"}, Confidence: 50}},
						}},
					}}},
				}},
			}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := NewOpenCTIClient(server.URL, "test-key", nil)
	if _, err := c.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	ev := c.FetchTechniqueEvidence()

	direct := 0
	viaCampaign := 0
	for _, e := range ev {
		if e.ActorName != "EvidenceActor" {
			t.Fatalf("unexpected ActorName in evidence: %+v", e)
		}
		switch {
		case e.Via == "" && (e.TechniqueID == "T1059" || e.TechniqueID == "T1105"):
			direct++
		case e.Via == "campaign" && e.ViaName == "Operation Ghost" && e.TechniqueID == "T1566.001":
			viaCampaign++
		default:
			t.Fatalf("unexpected evidence entry: %+v", e)
		}
	}
	if direct != 2 {
		t.Fatalf("direct evidence count = %d, want 2", direct)
	}
	if viaCampaign != 1 {
		t.Fatalf("via-campaign evidence count = %d, want 1", viaCampaign)
	}
}
```

Add `"time"` to this file's import block if not already present (it currently imports `encoding/json`, `net/http`, `net/http/httptest`, `testing`, `github.com/audspect/bas/internal/intelligence`).

- [ ] **Step 4: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/connector/... -run 'TestTechniqueEvidenceFrom|TestOpenCTIClient_Fetch_PopulatesTechniqueEvidence' -v`
Expected: FAIL to compile — `undefined: techniqueEvidenceFrom`, `c.FetchTechniqueEvidence undefined`.

- [ ] **Step 5: Add `TechniqueEvidenceSource`/`TechniqueEvidence` to `source.go`**

In `orchestrator/internal/connector/source.go`, append below `ActivitySignal`:

```go

// TechniqueEvidenceSource is implemented by connectors that can supply
// real per-relationship confidence/date evidence for a technique
// assertion -- today, only OpenCTI's STIX relationship-object graph
// carries this data. See
// docs/superpowers/specs/2026-08-12-technique-evidence-layer-design.md.
type TechniqueEvidenceSource interface {
	FetchTechniqueEvidence() []TechniqueEvidence
}

// TechniqueEvidence is one "uses" relationship's own STIX evidence --
// Via/ViaName distinguish a technique asserted directly by the actor from
// one reached through a linked campaign/malware/tool. Confidence/dates
// are the source's own, never fabricated or inherited from the actor's
// overall Confidence/LastSeen. A technique reached through multiple paths
// produces multiple TechniqueEvidence entries, never merged into one.
type TechniqueEvidence struct {
	ActorName   string
	TechniqueID string
	Via         string // "" (direct) | "campaign" | "malware" | "tool"
	ViaName     string // the linked entity's name, "" when Via == ""
	Confidence  int
	StartTime   *time.Time
	StopTime    *time.Time
}
```

- [ ] **Step 6: Extend the GraphQL query fragment**

In `orchestrator/internal/connector/opencti.go`'s `actorFieldsFragment`, add `confidence`, `start_time`, `stop_time` as siblings of `to { ... }` inside `node { ... }`, at all 4 occurrences of the `attackPatterns: stixCoreRelationships(...)` block (the actor's own, and the ones nested inside `campaigns`/`malwares`/`tools`). Each occurrence changes from:

```graphql
        attackPatterns: stixCoreRelationships(
          relationship_type: "uses"
          toTypes: ["Attack-Pattern"]
          first: 100
        ) {
          edges {
            node {
              to {
                ... on AttackPattern {
                  x_mitre_id
                  name
                  killChainPhases { phase_name }
                }
              }
            }
          }
        }
```

to:

```graphql
        attackPatterns: stixCoreRelationships(
          relationship_type: "uses"
          toTypes: ["Attack-Pattern"]
          first: 100
        ) {
          edges {
            node {
              confidence
              start_time
              stop_time
              to {
                ... on AttackPattern {
                  x_mitre_id
                  name
                  killChainPhases { phase_name }
                }
              }
            }
          }
        }
```

**Verification note (flag when reporting completion, don't silently skip):** `confidence`/`start_time`/`stop_time` are inferred STIX 2.1 relationship-property field names, not confirmed against a live OpenCTI GraphQL schema (same category of assumption as this file's existing sector/region comment at `opencti.go:20-29`). If these field names are wrong, OpenCTI's GraphQL server will reject the entire query with a schema error, not silently return empty values — so this must be checked against a real instance before this is trusted in production, but a wrong query fails loudly (a full sync error), never silently.

- [ ] **Step 7: Add `techniqueEvidenceFrom` and wire it into all 4 extraction sites**

In `orchestrator/internal/connector/opencti.go`, add immediately after `techniqueRefsFrom`:

```go

// techniqueEvidenceFrom extracts TechniqueEvidence entries from a
// "uses"->Attack-Pattern connection -- the same edges techniqueRefsFrom
// reads, but preserving each edge's own confidence/dates instead of
// discarding them. via/viaName tag whether this connection came from the
// actor directly ("", "") or through a linked campaign/malware/tool.
func techniqueEvidenceFrom(conn octiRelationshipConnection, actorName, via, viaName string) []TechniqueEvidence {
	var out []TechniqueEvidence
	for _, e := range conn.Edges {
		id := strings.ToUpper(strings.TrimSpace(e.Node.To.XMitreID))
		if !isATTACKID(id) {
			continue
		}
		ev := TechniqueEvidence{
			ActorName: actorName, TechniqueID: id, Via: via, ViaName: viaName,
			Confidence: e.Node.Confidence,
		}
		if t, err := time.Parse(time.RFC3339, e.Node.StartTime); err == nil {
			ev.StartTime = &t
		}
		if t, err := time.Parse(time.RFC3339, e.Node.StopTime); err == nil {
			ev.StopTime = &t
		}
		out = append(out, ev)
	}
	return out
}
```

Add a `lastTechniqueEvidence []TechniqueEvidence` field to `OpenCTIClient` (alongside `lastCampaigns`/`lastMalware`/`lastTools`):

```go
	lastCampaigns []intelligence.Campaign
	lastMalware   []intelligence.Malware
	lastTools     []intelligence.Tool
	lastTechniqueEvidence []TechniqueEvidence
	retryDelay    time.Duration
```

In `Fetch()`, replace:

```go
	var actors []ThreatActor
	var campaigns []intelligence.Campaign
	var malware []intelligence.Malware
	var tools []intelligence.Tool
	for _, raw := range actorsRaw {
		actor := c.convertActor(raw)
		if actor == nil || len(actor.Techniques) < 2 {
			continue
		}
		actors = append(actors, *actor)

		for _, entity := range campaignEntitiesFrom(raw.Campaigns) {
			campaigns = append(campaigns, c.convertCampaign(entity, actor))
		}
		for _, entity := range malwareEntitiesFrom(raw.Malwares) {
			malware = append(malware, c.convertMalware(entity, actor))
		}
		for _, entity := range toolEntitiesFrom(raw.Tools) {
			tools = append(tools, c.convertTool(entity, actor))
		}
	}
	c.lastStat = SourceStat{Name: "opencti", RawCount: len(actorsRaw), ActorCount: len(actors), FetchedAt: time.Now()}
	c.lastCampaigns = campaigns
	c.lastMalware = malware
	c.lastTools = tools
	return actors, nil
```

with:

```go
	var actors []ThreatActor
	var campaigns []intelligence.Campaign
	var malware []intelligence.Malware
	var tools []intelligence.Tool
	var evidence []TechniqueEvidence
	for _, raw := range actorsRaw {
		actor := c.convertActor(raw)
		if actor == nil || len(actor.Techniques) < 2 {
			continue
		}
		actors = append(actors, *actor)
		evidence = append(evidence, techniqueEvidenceFrom(raw.AttackPatterns, actor.Name, "", "")...)

		for _, entity := range campaignEntitiesFrom(raw.Campaigns) {
			campaigns = append(campaigns, c.convertCampaign(entity, actor))
			evidence = append(evidence, techniqueEvidenceFrom(entity.AttackPatterns, actor.Name, "campaign", entity.Name)...)
		}
		for _, entity := range malwareEntitiesFrom(raw.Malwares) {
			malware = append(malware, c.convertMalware(entity, actor))
			evidence = append(evidence, techniqueEvidenceFrom(entity.AttackPatterns, actor.Name, "malware", entity.Name)...)
		}
		for _, entity := range toolEntitiesFrom(raw.Tools) {
			tools = append(tools, c.convertTool(entity, actor))
			evidence = append(evidence, techniqueEvidenceFrom(entity.AttackPatterns, actor.Name, "tool", entity.Name)...)
		}
	}
	c.lastStat = SourceStat{Name: "opencti", RawCount: len(actorsRaw), ActorCount: len(actors), FetchedAt: time.Now()}
	c.lastCampaigns = campaigns
	c.lastMalware = malware
	c.lastTools = tools
	c.lastTechniqueEvidence = evidence
	return actors, nil
```

Add the accessor method near `FetchIntelligence`:

```go

// FetchTechniqueEvidence implements TechniqueEvidenceSource -- returns the
// per-relationship evidence gathered during the most recent Fetch() call.
func (c *OpenCTIClient) FetchTechniqueEvidence() []TechniqueEvidence {
	return c.lastTechniqueEvidence
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./internal/connector/... && go test ./internal/connector/... -run 'TestTechniqueEvidenceFrom|TestOpenCTIClient|TestTechniqueRefsFrom|TestCampaignEntitiesFrom|TestMalwareEntitiesFrom|TestToolEntitiesFrom' -v`
Expected: `go build` succeeds. All new tests PASS, and every pre-existing test in this file still PASSes (behavior-identical after the Step 1 literal migration).

Then the whole package: `cd orchestrator && go test ./internal/connector/...`
Expected: `ok github.com/audspect/bas/internal/connector`.

- [ ] **Step 9: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/connector/source.go orchestrator/internal/connector/opencti.go orchestrator/internal/connector/opencti_intelligence_test.go
git commit -m "feat(connector): extract per-relationship technique evidence from OpenCTI"
git push
```

---

### Task 2: `technique_evidence` table + `Scheduler` wiring

**Files:**
- Modify: `orchestrator/internal/db/content_schema.go` (append to `stmts`)
- Modify: `orchestrator/internal/connector/scheduler.go` (collect evidence in the curated-source loop, `upsertTechniqueEvidence`, sync wiring)
- Test: `orchestrator/internal/connector/scheduler_test.go` (append only)

**Interfaces:**
- Consumes: `TechniqueEvidenceSource`/`TechniqueEvidence` (Task 1), `resolveActivitySignalActor(signalName string, merged []ThreatActor) (string, bool)` (already generic, reused verbatim -- not renamed, not modified).
- Produces: the `technique_evidence` table (read by Task 3) and `func (s *Scheduler) upsertTechniqueEvidence(evidence []TechniqueEvidence, merged []ThreatActor)`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/connector/scheduler_test.go`:

```go

// TestUpsertTechniqueEvidence_ResolvesAgainstMergedRoster proves evidence
// for an actor that DOES have a curated profile persists under that
// actor's canonical (merged) name.
func TestUpsertTechniqueEvidence_ResolvesAgainstMergedRoster(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		s.upsertActorProfiles([]ThreatActor{{
			Name: "EVID-Wizard Spider", Aliases: []string{}, Sectors: []string{}, Regions: []string{},
		}})
		merged := []ThreatActor{{Name: "EVID-Wizard Spider"}}

		s.upsertTechniqueEvidence([]TechniqueEvidence{
			{ActorName: "EVID-Wizard Spider", TechniqueID: "T1059.001", Confidence: 80},
		}, merged)

		var techID string
		var confidence int
		if err := pool.QueryRow(t.Context(),
			`SELECT technique_id, confidence FROM technique_evidence WHERE actor_name = $1 AND source = 'opencti'`,
			"EVID-Wizard Spider",
		).Scan(&techID, &confidence); err != nil {
			t.Fatalf("query: %v", err)
		}
		if techID != "T1059.001" || confidence != 80 {
			t.Fatalf("got techID=%q confidence=%d, want T1059.001/80", techID, confidence)
		}
	})
}

// TestUpsertTechniqueEvidence_UnresolvedActorIsDropped is the key
// difference from OTX's activity signals: no orphan stub gets created.
func TestUpsertTechniqueEvidence_UnresolvedActorIsDropped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		s.upsertTechniqueEvidence([]TechniqueEvidence{
			{ActorName: "EVID-Nobody-Curated-Ever-Reported", TechniqueID: "T1059.001", Confidence: 50},
		}, nil)

		var count int
		if err := pool.QueryRow(t.Context(),
			`SELECT COUNT(*) FROM threat_actor_profiles WHERE name = $1`, "EVID-Nobody-Curated-Ever-Reported",
		).Scan(&count); err != nil {
			t.Fatalf("query: %v", err)
		}
		if count != 0 {
			t.Fatal("expected no profile stub created for unresolved evidence -- unlike OTX activity signals, evidence must not create actors")
		}
	})
}

// TestUpsertTechniqueEvidence_MultiplePathsToSameTechniquePersistSeparately
// proves the composite PK (actor_name, technique_id, via, via_name,
// source) lets a technique reached both directly and via a campaign keep
// both rows -- two real, distinct pieces of evidence, never collapsed.
func TestUpsertTechniqueEvidence_MultiplePathsToSameTechniquePersistSeparately(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		s.upsertActorProfiles([]ThreatActor{{
			Name: "EVID-Multi-Path", Aliases: []string{}, Sectors: []string{}, Regions: []string{},
		}})
		merged := []ThreatActor{{Name: "EVID-Multi-Path"}}

		s.upsertTechniqueEvidence([]TechniqueEvidence{
			{ActorName: "EVID-Multi-Path", TechniqueID: "T1566.001", Via: "", ViaName: "", Confidence: 70},
			{ActorName: "EVID-Multi-Path", TechniqueID: "T1566.001", Via: "campaign", ViaName: "Operation Ghost", Confidence: 40},
		}, merged)

		var count int
		if err := pool.QueryRow(t.Context(),
			`SELECT COUNT(*) FROM technique_evidence WHERE actor_name = $1 AND technique_id = 'T1566.001'`,
			"EVID-Multi-Path",
		).Scan(&count); err != nil {
			t.Fatalf("query: %v", err)
		}
		if count != 2 {
			t.Fatalf("row count = %d, want 2 (direct + via campaign, both preserved)", count)
		}
	})
}

// TestScheduler_Sync_PersistsTechniqueEvidenceFromOpenCTI exercises the
// real sync() path end to end.
func TestScheduler_Sync_PersistsTechniqueEvidenceFromOpenCTI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := octiThreatActorsResp{}
			resp.Data.ThreatActors.Edges = []octiActorEdge{
				{Node: octiThreatActorNode{
					ID: "ta-sync-1", Name: "SYNC-EVID-ACTOR",
					AttackPatterns: octiRelationshipConnection{Edges: []octiRelationshipEdge{
						{Node: octiRelationshipNode{To: octiRelatedEntity{XMitreID: "T1059"}, Confidence: 90}},
						{Node: octiRelationshipNode{To: octiRelatedEntity{XMitreID: "T1105"}, Confidence: 90}},
					}},
				}},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		octiClient := NewOpenCTIClient(server.URL, "test-key", nil)
		s := NewScheduler([]Source{octiClient}, NewGenerator(t.TempDir(), nil, nil, nil), scenario.NewEngine(t.TempDir()), 24, pool, nil)

		s.sync()

		var count int
		if err := pool.QueryRow(t.Context(),
			`SELECT COUNT(*) FROM technique_evidence WHERE actor_name = $1 AND source = 'opencti'`, "SYNC-EVID-ACTOR",
		).Scan(&count); err != nil {
			t.Fatalf("query: %v", err)
		}
		if count != 2 {
			t.Fatalf("evidence row count = %d, want 2", count)
		}
	})
}
```

Add `"encoding/json"` and `"net/http"`/`"net/http/httptest"` to this file's import block if not already present.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/connector/... -run 'TestUpsertTechniqueEvidence|TestScheduler_Sync_PersistsTechniqueEvidence' -v`
Expected: FAIL to compile — `s.upsertTechniqueEvidence undefined`.

- [ ] **Step 3: Add the table**

In `orchestrator/internal/db/content_schema.go`, append to the `stmts` slice immediately after the `threat_actor_profiles.techniques` ALTER (the last entry before the closing `}`):

```go

		// technique_evidence: OpenCTI's own per-relationship "uses" evidence
		// (confidence/dates), distinct from the flat, provenance-free
		// technique lists every other source contributes. via/via_name
		// distinguish a technique asserted directly by the actor from one
		// reached through a linked campaign/malware/tool -- a technique
		// reached multiple ways gets multiple rows, by design. MISP/bundle
		// structurally cannot supply this data (see the design spec), so
		// source is always 'opencti' today, kept as a real column for the
		// same reason threat_actor_sources/threat_actor_activity do. See
		// docs/superpowers/specs/2026-08-12-technique-evidence-layer-design.md.
		`CREATE TABLE IF NOT EXISTS technique_evidence (
			actor_name   text NOT NULL REFERENCES threat_actor_profiles(name) ON DELETE CASCADE,
			technique_id text NOT NULL,
			via          text NOT NULL DEFAULT '',
			via_name     text NOT NULL DEFAULT '',
			source       text NOT NULL,
			confidence   int  NOT NULL DEFAULT 0,
			start_time   timestamptz,
			stop_time    timestamptz,
			updated_at   timestamptz NOT NULL DEFAULT NOW(),
			PRIMARY KEY (actor_name, technique_id, via, via_name, source)
		)`,
```

- [ ] **Step 4: Collect evidence in `sync()`'s curated-source loop**

In `orchestrator/internal/connector/scheduler.go`'s `sync()`, replace:

```go
	for _, src := range sources {
		got, err := src.Fetch()
		if ss, ok := src.(StatsSource); ok {
			bySource[src.Name()] = ss.Stats()
		}
		if err != nil {
			log.Printf("[connector/%s] fetch error: %v", src.Name(), err)
			s.setError(src.Name()+": "+err.Error(), bySource)
			continue
		}
		log.Printf("[connector/%s] %d actors fetched", src.Name(), len(got))
		actors = append(actors, got...)
		if bs, ok := src.(*BundleSource); ok {
			bundleVersion = bs.Version()
		}
		if is, ok := src.(IntelligenceSource); ok {
			campaigns, malware, tools, ierr := is.FetchIntelligence()
			if ierr != nil {
				log.Printf("[connector/%s] intelligence fetch error: %v", src.Name(), ierr)
			} else {
				allCampaigns = append(allCampaigns, campaigns...)
				allMalware = append(allMalware, malware...)
				allTools = append(allTools, tools...)
			}
		}
	}
```

with:

```go
	var techEvidence []TechniqueEvidence
	for _, src := range sources {
		got, err := src.Fetch()
		if ss, ok := src.(StatsSource); ok {
			bySource[src.Name()] = ss.Stats()
		}
		if err != nil {
			log.Printf("[connector/%s] fetch error: %v", src.Name(), err)
			s.setError(src.Name()+": "+err.Error(), bySource)
			continue
		}
		log.Printf("[connector/%s] %d actors fetched", src.Name(), len(got))
		actors = append(actors, got...)
		if bs, ok := src.(*BundleSource); ok {
			bundleVersion = bs.Version()
		}
		if is, ok := src.(IntelligenceSource); ok {
			campaigns, malware, tools, ierr := is.FetchIntelligence()
			if ierr != nil {
				log.Printf("[connector/%s] intelligence fetch error: %v", src.Name(), ierr)
			} else {
				allCampaigns = append(allCampaigns, campaigns...)
				allMalware = append(allMalware, malware...)
				allTools = append(allTools, tools...)
			}
		}
		if tes, ok := src.(TechniqueEvidenceSource); ok {
			techEvidence = append(techEvidence, tes.FetchTechniqueEvidence()...)
		}
	}
```

- [ ] **Step 5: Persist after the merge, and add `upsertTechniqueEvidence`**

In `sync()`, replace:

```go
	// Activity evidence -- resolved against the now-merged curated roster,
	// or given a minimal stub if nothing curated matches. MUST also run
	// after upsertActorProfiles for the same FK reason.
	for _, r := range activityResults {
		s.upsertActivitySignals(r.source, r.signals, actors)
	}
```

with:

```go
	// Activity evidence -- resolved against the now-merged curated roster,
	// or given a minimal stub if nothing curated matches. MUST also run
	// after upsertActorProfiles for the same FK reason.
	for _, r := range activityResults {
		s.upsertActivitySignals(r.source, r.signals, actors)
	}
	// Per-relationship technique evidence (OpenCTI only) -- resolved
	// against the merged roster; unlike activity signals, an unresolved
	// actor's evidence is dropped, not stubbed (this enriches an actor
	// that must already exist via a curated source).
	s.upsertTechniqueEvidence(techEvidence, actors)
```

Add `upsertTechniqueEvidence` immediately after `upsertActivitySignals`'s closing brace:

```go

// upsertTechniqueEvidence resolves each evidence record against the
// merged curated roster (reusing resolveActivitySignalActor, unmodified)
// and persists to technique_evidence. Unlike upsertActivitySignals, a
// record that doesn't resolve to an existing actor is dropped and
// logged -- this enriches an actor a curated source must already have
// established, it never creates one. A single record failing is logged
// and skipped, never aborting the rest -- same discipline every other
// upsert* function in this file applies. No-op when pool is nil.
func (s *Scheduler) upsertTechniqueEvidence(evidence []TechniqueEvidence, merged []ThreatActor) {
	if s.pool == nil {
		return
	}
	ctx := context.Background()
	for _, ev := range evidence {
		actorName, found := resolveActivitySignalActor(ev.ActorName, merged)
		if !found {
			log.Printf("[connector] technique evidence for unresolved actor %q dropped (technique %s)", ev.ActorName, ev.TechniqueID)
			continue
		}
		_, err := s.pool.Exec(ctx,
			`INSERT INTO technique_evidence (actor_name, technique_id, via, via_name, source, confidence, start_time, stop_time, updated_at)
			 VALUES ($1,$2,$3,$4,'opencti',$5,$6,$7,NOW())
			 ON CONFLICT (actor_name, technique_id, via, via_name, source) DO UPDATE SET
			   confidence = EXCLUDED.confidence, start_time = EXCLUDED.start_time,
			   stop_time = EXCLUDED.stop_time, updated_at = NOW()`,
			actorName, ev.TechniqueID, ev.Via, ev.ViaName, ev.Confidence, ev.StartTime, ev.StopTime)
		if err != nil {
			log.Printf("[connector] upsert technique evidence %q/%s: %v", actorName, ev.TechniqueID, err)
		}
	}
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./internal/connector/... && go test ./internal/connector/... -run 'TestUpsertTechniqueEvidence|TestScheduler_Sync' -v`
Expected: all 4 new tests PASS, plus every pre-existing `TestScheduler_Sync*`/`TestUpsertActor*`/`TestUpsertActivitySignals*` test still PASSes unmodified.

Then the whole package: `cd orchestrator && go test ./internal/connector/...`
Expected: `ok github.com/audspect/bas/internal/connector`.

- [ ] **Step 7: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/db/content_schema.go orchestrator/internal/connector/scheduler.go orchestrator/internal/connector/scheduler_test.go
git commit -m "feat(connector): persist and resolve per-relationship technique evidence"
git push
```

---

### Task 3: Serve technique evidence on the actor detail endpoint

**Files:**
- Modify: `orchestrator/internal/api/threatpriority_handlers.go`
- Test: `orchestrator/internal/api/threatpriority_handlers_test.go`

**Interfaces:**
- Consumes: the `technique_evidence` table (Task 2). `h.db *pgxpool.Pool`.
- Produces: `type TechniqueEvidenceRow struct` with JSON keys `techniqueId`, `via`, `viaName`, `confidence`, `startTime`, `stopTime` — read by Task 4's frontend as `d.techniqueEvidence`.

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/api/threatpriority_handlers_test.go`:

```go

func TestThreatPriorityActorDetail_ReturnsTechniqueEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source, confidence)
			 VALUES ('API-EVID-ACTOR','{}','{}','{}','opencti','high')
			 ON CONFLICT (name) DO NOTHING`); err != nil {
			t.Fatalf("seed profile: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO technique_evidence (actor_name, technique_id, via, via_name, source, confidence)
			 VALUES ('API-EVID-ACTOR','T1059.001','','','opencti',80),
			        ('API-EVID-ACTOR','T1566.001','campaign','Operation Ghost','opencti',40)
			 ON CONFLICT (actor_name, technique_id, via, via_name, source) DO NOTHING`); err != nil {
			t.Fatalf("seed evidence: %v", err)
		}

		engine := scenario.NewEngine(t.TempDir())
		if err := engine.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}
		pe := threatpriority.NewEngine(pool, engine, nil, nil)
		h := New(pool, ws.NewHub(), engine, "").WithThreatPriority(pe)

		req := httptest.NewRequest("GET", "/api/threat-priority/actors/API-EVID-ACTOR", nil)
		req = withURLParams(req, map[string]string{"name": "API-EVID-ACTOR"})
		w := httptest.NewRecorder()
		h.ThreatPriorityActorDetail(w, req)

		if w.Code != 200 {
			t.Fatalf("status = %d, body: %s", w.Code, w.Body.String())
		}
		var got struct {
			TechniqueEvidence []TechniqueEvidenceRow `json:"techniqueEvidence"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got.TechniqueEvidence) != 2 {
			t.Fatalf("techniqueEvidence = %+v, want 2 entries", got.TechniqueEvidence)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestThreatPriorityActorDetail_ReturnsTechniqueEvidence -v`
Expected: FAIL to compile — `undefined: TechniqueEvidenceRow`.

- [ ] **Step 3: Implement**

In `orchestrator/internal/api/threatpriority_handlers.go`, add above `threatPriorityActorDetail`:

```go

// TechniqueEvidenceRow is OpenCTI's own per-relationship evidence for one
// actor-technique assertion. Via/ViaName distinguish a technique asserted
// directly by the actor from one reached through a linked
// campaign/malware/tool. Only ever populated for OpenCTI-sourced actors --
// MISP/bundle cannot supply this (see
// docs/superpowers/specs/2026-08-12-technique-evidence-layer-design.md).
type TechniqueEvidenceRow struct {
	TechniqueID string     `json:"techniqueId"`
	Via         string     `json:"via,omitempty"`
	ViaName     string     `json:"viaName,omitempty"`
	Confidence  int        `json:"confidence"`
	StartTime   *time.Time `json:"startTime,omitempty"`
	StopTime    *time.Time `json:"stopTime,omitempty"`
}

// loadTechniqueEvidence returns every per-relationship evidence row for
// one actor, technique-then-via-ordered for stable rendering.
func loadTechniqueEvidence(ctx context.Context, db *pgxpool.Pool, actorName string) ([]TechniqueEvidenceRow, error) {
	if db == nil {
		return []TechniqueEvidenceRow{}, nil
	}
	rows, err := db.Query(ctx,
		`SELECT technique_id, via, via_name, confidence, start_time, stop_time
		   FROM technique_evidence WHERE actor_name = $1 ORDER BY technique_id, via`, actorName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TechniqueEvidenceRow{}
	for rows.Next() {
		var e TechniqueEvidenceRow
		if err := rows.Scan(&e.TechniqueID, &e.Via, &e.ViaName, &e.Confidence, &e.StartTime, &e.StopTime); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
```

Add the field to `threatPriorityActorDetail`:

```go
type threatPriorityActorDetail struct {
	threatpriority.ActorPriority
	History             []threatpriority.ActorPriorityHistory `json:"history"`
	UncoveredTechniques []string                              `json:"uncoveredTechniques"`
	TechniqueCoverage   []TechniqueCoverage                   `json:"techniqueCoverage"`
	Sources             []ActorSource                         `json:"sources"`
	TechniqueEvidence   []TechniqueEvidenceRow                `json:"techniqueEvidence"`
}
```

Update the nil-engine early return:

```go
		respond(w, threatPriorityActorDetail{UncoveredTechniques: []string{}, TechniqueCoverage: []TechniqueCoverage{}, Sources: []ActorSource{}, TechniqueEvidence: []TechniqueEvidenceRow{}})
```

And in the handler body, immediately after the `sources, err := loadActorSources(...)` block:

```go
	techEvidence, err := loadTechniqueEvidence(r.Context(), h.db, name)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
```

Add `TechniqueEvidence: techEvidence,` to the final `respond` composite literal.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./internal/api/... && go test ./internal/api/... -run 'TestThreatPriorityActor' -v`
Expected: the new test PASSes, and all pre-existing `TestThreatPriorityActor*` tests still PASS unmodified.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/api/threatpriority_handlers.go orchestrator/internal/api/threatpriority_handlers_test.go
git commit -m "feat(api): serve per-relationship technique evidence on actor detail"
git push
```

---

### Task 4: Technique Evidence card on the actor detail view

**Files:**
- Modify: `orchestrator/wwwroot/index.html` — static drawer markup near the Sources card, `renderThreatPriorityDetail`.

**Interfaces:**
- Consumes: `d.techniqueEvidence` (Task 3's `[]TechniqueEvidenceRow`). Pre-existing helpers reused as-is: `x()`, `fmtDate()`.
- Produces: no new interface — terminal, UI-facing step.

- [ ] **Step 1: Add the static card**

In `orchestrator/wwwroot/index.html`, insert a new card between the Sources card and the History card. Current:

```html
          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">Sources</div>
            <div id="tp-detail-sources" class="tiny"></div>
          </div>

          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">History</div>
            <div id="tp-detail-history" class="tiny"></div>
          </div>
```

Replace with:

```html
          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">Sources</div>
            <div id="tp-detail-sources" class="tiny"></div>
          </div>

          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem" id="tp-detail-evidence-card">
            <div class="card-title">Technique Evidence</div>
            <div id="tp-detail-evidence" class="tiny"></div>
          </div>

          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">History</div>
            <div id="tp-detail-history" class="tiny"></div>
          </div>
```

- [ ] **Step 2: Render the evidence table, hiding the card when empty**

In `renderThreatPriorityDetail`, insert immediately after the `tp-detail-sources` block ends (after its closing `: '<span class="muted">No per-source records yet — populated by the next threat-intel sync.</span>';` line) and before `var hist = (d.history || []);`:

```js

  var techEvidence = (d.techniqueEvidence || []);
  var evidenceCard = document.getElementById('tp-detail-evidence-card');
  if (techEvidence.length) {
    evidenceCard.style.display = '';
    document.getElementById('tp-detail-evidence').innerHTML =
      '<table style="width:100%"><thead><tr><th>Technique</th><th>Via</th><th>Confidence</th><th>Since</th></tr></thead><tbody>' +
      techEvidence.map(function(e) {
        var via = e.via ? (e.via + (e.viaName ? ' (' + x(e.viaName) + ')' : '')) : '<span class="muted">direct</span>';
        var since = e.startTime ? x(fmtDate(e.startTime)) : '<span class="muted">&mdash;</span>';
        return '<tr><td>' + x(e.techniqueId) + '</td><td>' + via + '</td><td>' + x(e.confidence) + '%</td><td>' + since + '</td></tr>';
      }).join('') +
      '</tbody></table>';
  } else {
    evidenceCard.style.display = 'none';
  }
```

- [ ] **Step 3: Verify manually**

This file has no automated frontend test suite (consistent with the rest of the codebase). Verify by hand if a dev instance is reachable: open an OpenCTI-sourced actor with real evidence, confirm the Technique Evidence card shows rows with correct Via/Confidence/Since; confirm the card is entirely absent (not an empty state) for a MISP/bundle-only actor. If no dev instance is reachable in this environment, say so explicitly and add it to the standing Pending Manual QA Backlog.

- [ ] **Step 4: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): show per-relationship technique evidence on actor detail"
git push
```

---

## Self-Review Notes

- **Spec coverage:** query fragment extension (4 sites) + `TechniqueEvidenceSource`/`TechniqueEvidence` + extraction wired into all 4 call sites — Task 1. Persistence table + merge-roster resolution (reusing, not duplicating, `resolveActivitySignalActor`) + "dropped not stubbed" behavior + multi-path-same-technique preserved — Task 2. API field — Task 3. UI card, hidden (not empty-stated) for non-OpenCTI actors — Task 4. The spec's stated uncertainty (GraphQL field names) is carried into Task 1 Step 6 verbatim, not silently dropped.
- **A real, unavoidable extra change found during planning, not in the original spec:** `octiRelationshipEdge.Node`'s current anonymous struct type must become a named type (`octiRelationshipNode`) to add the new fields without breaking every existing test — 11 existing literal-construction sites in `opencti_intelligence_test.go` require mechanical migration as part of Task 1 Step 1, before any new code is even written. This isn't optional cleanup; the anonymous struct's literal syntax genuinely stops compiling once its shape changes.
- **Placeholder scan:** no TBD/TODO; every step has literal, runnable code and exact commands. Task 4 Step 3's manual-verification framing is an honest limitation statement, matching every other UI task this session.
- **Type consistency:** `TechniqueEvidenceSource`/`TechniqueEvidence` (Task 1) match exactly across `opencti.go`, `scheduler.go` (Task 2), and their respective tests. `upsertTechniqueEvidence(evidence []TechniqueEvidence, merged []ThreatActor)` signature identical in definition and all 4 tests. `TechniqueEvidenceRow`'s JSON keys (`techniqueId`/`via`/`viaName`/`confidence`/`startTime`/`stopTime`) match exactly what Task 4's JS reads (`e.techniqueId`, `e.via`, `e.viaName`, `e.confidence`, `e.startTime`). Column names identical across Task 2's `CREATE TABLE`, `INSERT`, test queries, and Task 3's `SELECT`.
