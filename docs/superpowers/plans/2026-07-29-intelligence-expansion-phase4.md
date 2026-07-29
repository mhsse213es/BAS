# Intelligence Expansion Phase 4 (Tools) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `Tool` entity (ATT&CK Software objects typed `tool`, e.g. PsExec, Mimikatz, AdFind) to `internal/intelligence`, sourced from both OpenCTI (verified live) and MISP (unverified galaxy-type name, explicitly flagged), mirroring the existing Campaign/Malware pattern end-to-end: model, per-provider extraction, union-merge persistence, API route.

**Architecture:** `Tool` is a new sibling type to `Campaign`/`Malware` in `internal/intelligence/models.go` — same `SourceRef` provenance, same denormalized `[]string` ID-list fields, no new package. OpenCTI extraction reuses the existing relationship-extraction helper pattern (`toolEntitiesFrom`, mirroring `malwareEntitiesFrom`) and the actor's own nested `tools` GraphQL connection, confirmed live to use `relationship_type: "uses", toTypes: ["Tool"]` (actor is the FROM side, same as Malware — no direction surprise this time). MISP extraction adds a third `GalaxyCluster` loop filtering `gc.Type == "mitre-tool"`, parallel to the existing `mitre-malware` loop, but this galaxy-type name is *assumed* from established ATT&CK-galaxy convention, not verified against live MISP data — Task 4 below carries this as an explicit, testable assumption rather than a silent guess. `IntelligenceSource.FetchIntelligence()` widens from a 2-slice to a 3-slice return (`[]Campaign, []Malware, []Tool, error`) — both implementers (`MISPClient`, `OpenCTIClient`) and the one `Scheduler.sync()` call site update together in the task that touches each.

**Tech Stack:** Go, `internal/connector` (GraphQL client, raw `net/http`+`encoding/json`; MISP client, same style), `internal/intelligence` (Postgres upsert via `pgx/v5`), `internal/api` (chi routes, existing `respond`/`jsonError` helpers).

## Global Constraints

- No new package, no schema redesign — reuse `internal/intelligence`, `IntelligenceSource`, and the Phase 2 extraction-helper structure. (Spec §Non-Goals)
- Do NOT add a `Tool.ToolTypes` field — verified live, `tool_types` was 0/98 populated on real OpenCTI sample data. (Spec §Non-Goals)
- Do NOT add a `killChainPhases`/tactic field on `Tool` itself — tactic data already flows through `TechniqueIDs`/`TechniqueRef.Tactic`. (Spec §Non-Goals)
- OpenCTI relationship direction: `toTypes: ["Tool"]` from the actor's own node (actor is FROM/subject side) — confirmed live, do not second-guess this against the Campaign direction surprise from Phase 2. (Spec §Problem, verified live)
- MISP's `mitre-tool` galaxy cluster type is an assumption, not verified — the plan must not present it as confirmed, and the test written for it must say so in its own comment. (Spec §Non-Goals)
- `IntelligenceSource.FetchIntelligence()` widens to 3 slices (chosen: option a, not a second optional interface). (Spec §Architecture 4)
- One HTTP round trip per `Fetch()` call for OpenCTI, same as today — no per-entity follow-up queries.

---

## File Structure

- Modify `orchestrator/internal/intelligence/models.go` — add `Tool` struct.
- Modify `orchestrator/internal/intelligence/store.go` — add `UpsertTool`/`ListTools`, mirroring `UpsertMalware`/`ListMalware`.
- Modify `orchestrator/internal/intelligence/store_test.go` — add `TestUpsertTool_MergesArraysOnConflict`, `TestListTools_Empty_ReturnsEmptyNotNil`.
- Modify `orchestrator/internal/db/content_schema.go` — add the `intelligence_tools` `CREATE TABLE IF NOT EXISTS` statement to the `stmts` slice inside `EnsureContentSchema` (this codebase applies schema via an in-Go statement list, not separate `.sql` migration files — confirmed by reading the existing `intelligence_campaigns`/`intelligence_malware` entries at lines 282-306).
- Modify `orchestrator/internal/connector/opencti.go` — `octiThreatActorNode.Tools` field, `actorFieldsFragment` query text, `toolEntitiesFrom`, `convertTool`, `Fetch()` wiring, `lastTools` field, widened `FetchIntelligence()`.
- Modify `orchestrator/internal/connector/opencti_intelligence_test.go` — new tests for `toolEntitiesFrom`/`convertTool`, extend the existing `FetchIntelligence_PopulatedAfterFetch` test for the third return value.
- Modify `orchestrator/internal/connector/misp.go` — third `GalaxyCluster` loop in `extractIntelligence`, `lastTools` field, widened `FetchIntelligence()`.
- Modify `orchestrator/internal/connector/misp_intelligence_test.go` — new test for tool extraction, explicitly flagged as validating an assumed-not-verified galaxy type.
- Modify `orchestrator/internal/connector/source.go` — widen `IntelligenceSource.FetchIntelligence()` signature.
- Modify `orchestrator/internal/connector/scheduler.go` — `allTools` accumulator, updated call site, `UpsertTool` persistence loop.
- Modify `orchestrator/internal/connector/scheduler_test.go` — existing `TestScheduler_Sync_PersistsCampaignsAndMalwareFromIntelligenceSource` test's assertions aren't required to change (it doesn't currently assert on tools), but the file must still compile against the widened interface — no test code changes anticipated beyond what compiles already, confirmed in Task 6.
- Modify `orchestrator/internal/api/intelligence_handlers.go` — add `IntelligenceTools` handler.
- Modify `orchestrator/internal/api/routes.go` — register `GET /api/intelligence/tools`.
- Modify `orchestrator/internal/api/rbac_matrix_test.go` — add RBAC matrix entry for the new route.

---

### Task 1: `Tool` model + `intelligence_tools` table + store functions

**Files:**
- Modify: `orchestrator/internal/intelligence/models.go`
- Modify: `orchestrator/internal/intelligence/store.go`
- Modify: `orchestrator/internal/intelligence/store_test.go`
- Modify: `orchestrator/internal/db/content_schema.go:294-306` (add `intelligence_tools` statement to the `stmts` slice, right after the existing `intelligence_malware` entry)

**Interfaces:**
- Produces: `type Tool struct{...}` (fields: `ID`, `Name`, `Aliases []string`, `TechniqueIDs []string`, `ThreatActorIDs []string`, `CampaignIDs []string`, `Source SourceRef`), `func UpsertTool(ctx context.Context, pool *pgxpool.Pool, t Tool) error`, `func ListTools(ctx context.Context, pool *pgxpool.Pool) ([]Tool, error)` — consumed by Task 2 (OpenCTI), Task 4 (MISP), Task 5 (scheduler), Task 6 (API).

- [ ] **Step 1: Write the failing test for `UpsertTool`/`ListTools`**

Add to `orchestrator/internal/intelligence/store_test.go`, after `TestListCampaigns_Empty_ReturnsEmptyNotNil`:

```go
func TestUpsertTool_MergesArraysOnConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		first := Tool{
			ID: "psexec", Name: "PsExec", // Aliases deliberately left nil -- exercises UpsertTool's nonNil coalescing
			TechniqueIDs: []string{"T1569.002"}, ThreatActorIDs: []string{"BlackTech"}, CampaignIDs: []string{"evt-1"},
			Source: SourceRef{Provider: "opencti", ExternalID: "tool--1", LastUpdated: time.Now(), Confidence: "high"},
		}
		if err := UpsertTool(ctx, pool, first); err != nil {
			t.Fatalf("first UpsertTool: %v", err)
		}

		second := Tool{
			ID: "psexec", Name: "PsExec",
			TechniqueIDs: []string{"T1569.002", "T1136.002"}, ThreatActorIDs: []string{"FIN8"}, CampaignIDs: []string{"evt-2"},
			Source: SourceRef{Provider: "opencti", ExternalID: "tool--1", LastUpdated: time.Now(), Confidence: "high"},
		}
		if err := UpsertTool(ctx, pool, second); err != nil {
			t.Fatalf("second UpsertTool: %v", err)
		}

		got, err := ListTools(ctx, pool)
		if err != nil {
			t.Fatalf("ListTools: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d tool rows, want 1 (merged, not duplicated)", len(got))
		}
		tl := got[0]
		sort.Strings(tl.TechniqueIDs)
		if len(tl.TechniqueIDs) != 2 || tl.TechniqueIDs[0] != "T1136.002" || tl.TechniqueIDs[1] != "T1569.002" {
			t.Errorf("TechniqueIDs = %v, want deduplicated union [T1136.002 T1569.002]", tl.TechniqueIDs)
		}
		sort.Strings(tl.ThreatActorIDs)
		if len(tl.ThreatActorIDs) != 2 || tl.ThreatActorIDs[0] != "BlackTech" || tl.ThreatActorIDs[1] != "FIN8" {
			t.Errorf("ThreatActorIDs = %v, want union [BlackTech FIN8]", tl.ThreatActorIDs)
		}
		sort.Strings(tl.CampaignIDs)
		if len(tl.CampaignIDs) != 2 || tl.CampaignIDs[0] != "evt-1" || tl.CampaignIDs[1] != "evt-2" {
			t.Errorf("CampaignIDs = %v, want union [evt-1 evt-2]", tl.CampaignIDs)
		}
	})
}

func TestListTools_Empty_ReturnsEmptyNotNil(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := ListTools(context.Background(), pool)
		if err != nil {
			t.Fatalf("ListTools: %v", err)
		}
		if got == nil {
			t.Fatal("expected an empty slice, not nil -- callers/JSON encoders shouldn't need a nil guard")
		}
	})
}
```

(`sort`, `context`, `time`, `pgxpool` are already imported in this file — no new imports needed.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/intelligence/... -run 'TestUpsertTool|TestListTools' -v`
Expected: FAIL — `undefined: Tool`, `undefined: UpsertTool`, `undefined: ListTools`

- [ ] **Step 3: Add the `Tool` struct**

In `orchestrator/internal/intelligence/models.go`, add after the `Malware` struct:

```go
// Tool is one ATT&CK Software object typed "tool" (as opposed to
// "malware") -- e.g. PsExec, Mimikatz, AdFind. Same shape as Malware minus
// the OpenCTI-only MalwareTypes field, which has no Tool analog (ToolTypes
// exists in OpenCTI's schema but was never populated on live data -- see
// docs/superpowers/specs/2026-07-29-intelligence-expansion-phase4-design.md's
// Non-Goals).
type Tool struct {
	ID             string    `json:"id"` // = MalwareKey(Name) -- same cross-provider dedup key Malware already uses
	Name           string    `json:"name"`
	Aliases        []string  `json:"aliases"`
	TechniqueIDs   []string  `json:"techniqueIds"`
	ThreatActorIDs []string  `json:"threatActorIds"`
	CampaignIDs    []string  `json:"campaignIds"`
	Source         SourceRef `json:"source"`
}
```

- [ ] **Step 4: Add the `intelligence_tools` schema statement**

In `orchestrator/internal/db/content_schema.go`, the `stmts` slice inside `EnsureContentSchema` already ends with the `intelligence_malware` entry (lines 294-306):

```go
		`CREATE TABLE IF NOT EXISTS intelligence_malware (
			id                  text        PRIMARY KEY,
			name                text        NOT NULL,
			aliases             text[]      NOT NULL DEFAULT '{}',
			technique_ids       text[]      NOT NULL DEFAULT '{}',
			actor_ids           text[]      NOT NULL DEFAULT '{}',
			campaign_ids        text[]      NOT NULL DEFAULT '{}',
			source_provider     text        NOT NULL,
			source_external_id  text        NOT NULL DEFAULT '',
			source_confidence   text        NOT NULL DEFAULT '',
			last_updated        timestamptz NOT NULL DEFAULT NOW(),
			tenant_id           text        NOT NULL DEFAULT 'default'
		)`,
	}
```

Insert a new statement directly after the `intelligence_malware` entry (before the closing `}` of `stmts`), matching its exact column shape and the `tenant_id text NOT NULL DEFAULT 'default'` convention every table in this list carries (per-tenant scoping backstop, not currently enforced — see [[ADR-013 Full Multi-Tenancy Rollout Deferred Until Audspect Cloud]] in project memory; every table gets the column regardless):

```go
		// Intelligence Expansion Phase 4 — Tools entity
		// (see docs/superpowers/specs/2026-07-29-intelligence-expansion-phase4-design.md).
		`CREATE TABLE IF NOT EXISTS intelligence_tools (
			id                  text        PRIMARY KEY,
			name                text        NOT NULL,
			aliases             text[]      NOT NULL DEFAULT '{}',
			technique_ids       text[]      NOT NULL DEFAULT '{}',
			actor_ids           text[]      NOT NULL DEFAULT '{}',
			campaign_ids        text[]      NOT NULL DEFAULT '{}',
			source_provider     text        NOT NULL,
			source_external_id  text        NOT NULL DEFAULT '',
			source_confidence   text        NOT NULL DEFAULT '',
			last_updated        timestamptz NOT NULL DEFAULT NOW(),
			tenant_id           text        NOT NULL DEFAULT 'default'
		)`,
```

`UpsertTool` (next step) omits `tenant_id` from its explicit column list, same as `UpsertCampaign`/`UpsertMalware` already do — the column's `DEFAULT 'default'` fills it in on insert, and `ON CONFLICT DO UPDATE` never touches it, matching the existing pattern exactly.

- [ ] **Step 5: Add `UpsertTool`/`ListTools` to the store**

In `orchestrator/internal/intelligence/store.go`, add after `UpsertMalware`:

```go
// UpsertTool merges on conflict -- the same tool is legitimately referenced
// by many different actors/events, so technique/actor/campaign ID lists
// accumulate (deduplicated union) rather than overwrite. Same reasoning as
// UpsertMalware.
func UpsertTool(ctx context.Context, pool *pgxpool.Pool, t Tool) error {
	t.Aliases, t.TechniqueIDs = nonNil(t.Aliases), nonNil(t.TechniqueIDs)
	t.ThreatActorIDs, t.CampaignIDs = nonNil(t.ThreatActorIDs), nonNil(t.CampaignIDs)
	_, err := pool.Exec(ctx,
		`INSERT INTO intelligence_tools
		   (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider, source_external_id, source_confidence, last_updated)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 ON CONFLICT (id) DO UPDATE SET
		   aliases       = ARRAY(SELECT DISTINCT UNNEST(intelligence_tools.aliases || EXCLUDED.aliases)),
		   technique_ids = ARRAY(SELECT DISTINCT UNNEST(intelligence_tools.technique_ids || EXCLUDED.technique_ids)),
		   actor_ids     = ARRAY(SELECT DISTINCT UNNEST(intelligence_tools.actor_ids || EXCLUDED.actor_ids)),
		   campaign_ids  = ARRAY(SELECT DISTINCT UNNEST(intelligence_tools.campaign_ids || EXCLUDED.campaign_ids)),
		   source_confidence = EXCLUDED.source_confidence,
		   last_updated  = GREATEST(intelligence_tools.last_updated, EXCLUDED.last_updated)`,
		t.ID, t.Name, t.Aliases, t.TechniqueIDs, t.ThreatActorIDs, t.CampaignIDs,
		t.Source.Provider, t.Source.ExternalID, t.Source.Confidence, t.Source.LastUpdated)
	return err
}

// ListTools returns every tool record, newest-updated first. Always
// non-nil, same convention as ListCampaigns/ListMalware.
func ListTools(ctx context.Context, pool *pgxpool.Pool) ([]Tool, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider, source_external_id, source_confidence, last_updated
		 FROM intelligence_tools ORDER BY last_updated DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Tool{}
	for rows.Next() {
		var t Tool
		if err := rows.Scan(&t.ID, &t.Name, &t.Aliases, &t.TechniqueIDs, &t.ThreatActorIDs, &t.CampaignIDs,
			&t.Source.Provider, &t.Source.ExternalID, &t.Source.Confidence, &t.Source.LastUpdated); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/intelligence/... -v`
Expected: PASS — the two new tests plus every existing `intelligence` package test. (Docker Desktop must be running for these container-backed tests — check `docker info` first, start Docker Desktop if needed.)

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/intelligence/models.go orchestrator/internal/intelligence/store.go orchestrator/internal/intelligence/store_test.go orchestrator/internal/db/content_schema.go
git commit -m "feat(intelligence): Tool entity + intelligence_tools table (Intelligence Expansion Phase 4)"
```

---

### Task 2: OpenCTI Tool extraction — relationship helper + converter

**Files:**
- Modify: `orchestrator/internal/connector/opencti.go`
- Modify: `orchestrator/internal/connector/opencti_intelligence_test.go`

**Interfaces:**
- Consumes: `intelligence.Tool`, `intelligence.MalwareKey` (Task 1); existing `octiRelatedEntity`, `octiRelationshipConnection`, `techniqueRefsFrom`, `techniqueIDs` (already in `opencti.go` from Phase 2).
- Produces: `func toolEntitiesFrom(conn octiRelationshipConnection) []octiRelatedEntity`, `func (c *OpenCTIClient) convertTool(entity octiRelatedEntity, actor *ThreatActor) intelligence.Tool` — consumed by Task 3.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/connector/opencti_intelligence_test.go`:

```go
func TestToolEntitiesFrom_ReadsToSide(t *testing.T) {
	conn := octiRelationshipConnection{
		Edges: []octiRelationshipEdge{
			{Node: struct {
				To   octiRelatedEntity `json:"to"`
				From octiRelatedEntity `json:"from"`
			}{To: octiRelatedEntity{ID: "tool--1", Name: "PsExec", Aliases: []string{"psexec.exe"}}}},
		},
	}
	entities := toolEntitiesFrom(conn)
	if len(entities) != 1 || entities[0].Name != "PsExec" || len(entities[0].Aliases) != 1 || entities[0].Aliases[0] != "psexec.exe" {
		t.Fatalf("toolEntitiesFrom() = %+v, want one entity Name=PsExec Aliases=[psexec.exe]", entities)
	}
}

func TestOpenCTIClient_ConvertTool_UsesOwnTechniques(t *testing.T) {
	c := NewOpenCTIClient("http://example.invalid", "test-key", nil)
	actor := &ThreatActor{Name: "BlackTech"}
	entity := octiRelatedEntity{
		ID: "tool--1", Name: "PsExec", Aliases: []string{"psexec.exe"},
		AttackPatterns: twoTechniqueConn(),
	}
	tool := c.convertTool(entity, actor)
	if tool.Name != "PsExec" || len(tool.Aliases) != 1 || tool.Aliases[0] != "psexec.exe" {
		t.Fatalf("convertTool() = %+v, want Name=PsExec Aliases=[psexec.exe]", tool)
	}
	if len(tool.TechniqueIDs) != 2 {
		t.Fatalf("convertTool().TechniqueIDs = %v, want 2 (tool's own techniques)", tool.TechniqueIDs)
	}
	if tool.ID != intelligence.MalwareKey("PsExec") {
		t.Fatalf("convertTool().ID = %q, want %q", tool.ID, intelligence.MalwareKey("PsExec"))
	}
	if len(tool.ThreatActorIDs) != 1 || tool.ThreatActorIDs[0] != "BlackTech" {
		t.Fatalf("convertTool().ThreatActorIDs = %v, want [BlackTech]", tool.ThreatActorIDs)
	}
	if tool.Source.Provider != "opencti" || tool.Source.ExternalID != "tool--1" {
		t.Fatalf("convertTool().Source = %+v, want Provider=opencti ExternalID=tool--1", tool.Source)
	}
}
```

(`twoTechniqueConn` and the `intelligence` import already exist in this test file from Phase 2 — no new imports needed.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/connector/... -run 'TestToolEntitiesFrom|TestOpenCTIClient_ConvertTool' -v`
Expected: FAIL — `undefined: toolEntitiesFrom`, `c.convertTool undefined`

- [ ] **Step 3: Add `toolEntitiesFrom` and `convertTool`**

In `orchestrator/internal/connector/opencti.go`, add after `malwareEntitiesFrom`:

```go
// toolEntitiesFrom extracts tool identity from a "uses"->Tool connection --
// the actor is the "from" side, tool is "to", same convention as
// malwareEntitiesFrom.
func toolEntitiesFrom(conn octiRelationshipConnection) []octiRelatedEntity {
	out := make([]octiRelatedEntity, 0, len(conn.Edges))
	for _, e := range conn.Edges {
		out = append(out, e.Node.To)
	}
	return out
}
```

Add after `convertMalware`:

```go
// convertTool builds an intelligence.Tool from a tool entity discovered
// under a specific actor's "uses" relationship. Uses the tool's OWN nested
// technique relationships, same reasoning as convertCampaign/convertMalware.
func (c *OpenCTIClient) convertTool(entity octiRelatedEntity, actor *ThreatActor) intelligence.Tool {
	return intelligence.Tool{
		ID:             intelligence.MalwareKey(entity.Name),
		Name:           entity.Name,
		Aliases:        entity.Aliases,
		TechniqueIDs:   techniqueIDs(techniqueRefsFrom(entity.AttackPatterns)),
		ThreatActorIDs: []string{actor.Name},
		Source: intelligence.SourceRef{
			Provider: "opencti", ExternalID: entity.ID,
			LastUpdated: actor.LastSeen, Confidence: actor.Confidence,
		},
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/connector/... -run 'TestToolEntitiesFrom|TestOpenCTIClient_ConvertTool' -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/connector/opencti.go orchestrator/internal/connector/opencti_intelligence_test.go
git commit -m "feat(connector): OpenCTI Tool relationship helper + converter (Intelligence Expansion Phase 4)"
```

---

### Task 3: OpenCTI query + `Fetch()` wiring for Tools

**Files:**
- Modify: `orchestrator/internal/connector/opencti.go`
- Modify: `orchestrator/internal/connector/opencti_intelligence_test.go`

**Interfaces:**
- Consumes: `toolEntitiesFrom`, `convertTool` (Task 2).
- Produces: `octiThreatActorNode.Tools octiRelationshipConnection` field; `OpenCTIClient.lastTools []intelligence.Tool` field, populated by `Fetch()` — consumed by Task 5 (`FetchIntelligence` signature widening touches this field directly).

- [ ] **Step 1: Write the failing test extending `FetchIntelligence_PopulatedAfterFetch`**

In `orchestrator/internal/connector/opencti_intelligence_test.go`, find `TestOpenCTIClient_FetchIntelligence_PopulatedAfterFetch`. Add a `Tools` connection to the mock `octiThreatActorNode` node it builds, and extend the assertions. Replace the whole test function with:

```go
func TestOpenCTIClient_FetchIntelligence_PopulatedAfterFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := octiThreatActorsResp{}
		resp.Data.ThreatActors.Edges = []octiActorEdge{
			{Node: octiThreatActorNode{
				ID: "ta-1", Name: "APT29", AttackPatterns: twoTechniqueConn(),
				Campaigns: octiRelationshipConnection{Edges: []octiRelationshipEdge{
					{Node: struct {
						To   octiRelatedEntity `json:"to"`
						From octiRelatedEntity `json:"from"`
					}{From: octiRelatedEntity{ID: "campaign--1", Name: "SolarWinds Compromise", AttackPatterns: twoTechniqueConn()}}},
				}},
				Malwares: octiRelationshipConnection{Edges: []octiRelationshipEdge{
					{Node: struct {
						To   octiRelatedEntity `json:"to"`
						From octiRelatedEntity `json:"from"`
					}{To: octiRelatedEntity{ID: "malware--1", Name: "TSCookie", AttackPatterns: twoTechniqueConn()}}},
				}},
				Tools: octiRelationshipConnection{Edges: []octiRelationshipEdge{
					{Node: struct {
						To   octiRelatedEntity `json:"to"`
						From octiRelatedEntity `json:"from"`
					}{To: octiRelatedEntity{ID: "tool--1", Name: "PsExec", AttackPatterns: twoTechniqueConn()}}},
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

	campaigns, malware, tools, err := c.FetchIntelligence()
	if err != nil {
		t.Fatalf("FetchIntelligence: %v", err)
	}
	if len(campaigns) != 1 || campaigns[0].Name != "SolarWinds Compromise" {
		t.Fatalf("FetchIntelligence() campaigns = %+v, want one named SolarWinds Compromise", campaigns)
	}
	if len(malware) != 1 || malware[0].Name != "TSCookie" {
		t.Fatalf("FetchIntelligence() malware = %+v, want one named TSCookie", malware)
	}
	if len(tools) != 1 || tools[0].Name != "PsExec" {
		t.Fatalf("FetchIntelligence() tools = %+v, want one named PsExec", tools)
	}
}
```

(This anticipates Task 5's widened `FetchIntelligence()` signature — that's expected; this step's Run/Verify below will still fail for the `Tools` field reason first, then Step 2 of Task 5 will make the 3-return-value part compile. Do not skip ahead to Task 5's changes here.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/connector/... -run TestOpenCTIClient_FetchIntelligence_PopulatedAfterFetch -v`
Expected: FAIL — `unknown field Tools in struct literal of type octiThreatActorNode` (compile error)

- [ ] **Step 3: Add the `Tools` field, query text, and `Fetch()` wiring**

In `orchestrator/internal/connector/opencti.go`, add a `Tools` field to `octiThreatActorNode`:

```go
type octiThreatActorNode struct {
	ID             string                     `json:"id"`
	Name           string                     `json:"name"`
	Aliases        []string                   `json:"aliases"`
	Description    string                     `json:"description"`
	Confidence     int                        `json:"confidence"` // 0-100
	Modified       string                     `json:"modified"`
	AttackPatterns octiRelationshipConnection `json:"attackPatterns"`
	Campaigns      octiRelationshipConnection `json:"campaigns"`
	Malwares       octiRelationshipConnection `json:"malwares"`
	Tools          octiRelationshipConnection `json:"tools"`
}
```

In `actorFieldsFragment`, add a `tools` block immediately after the closing `` ` `` of the existing `malwares` block (i.e. right before the fragment's closing backtick):

```graphql
        tools: stixCoreRelationships(
          relationship_type: "uses"
          toTypes: ["Tool"]
          first: 100
        ) {
          edges {
            node {
              to {
                ... on Tool {
                  id
                  name
                  aliases
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
                }
              }
            }
          }
        }
```

In `Fetch()`, add a `tools` accumulator and loop, and store it on `c.lastTools`:

```go
func (c *OpenCTIClient) Fetch() ([]ThreatActor, error) {
	actorsRaw, err := c.queryThreatActors()
	if err != nil {
		c.lastStat = SourceStat{Name: "opencti", Error: err.Error(), FetchedAt: time.Now()}
		return nil, fmt.Errorf("opencti query actors: %w", err)
	}
	log.Printf("[connector/opencti] fetched %d threat actors", len(actorsRaw))

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
}
```

Add `lastTools` to the `OpenCTIClient` struct:

```go
type OpenCTIClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	sectors       []string
	lastStat      SourceStat
	lastCampaigns []intelligence.Campaign
	lastMalware   []intelligence.Malware
	lastTools     []intelligence.Tool
}
```

- [ ] **Step 4: Run test to verify it still fails, but on the expected line**

Run: `cd orchestrator && go test ./internal/connector/... -run TestOpenCTIClient_FetchIntelligence_PopulatedAfterFetch -v`
Expected: FAIL — now a different error, `assignment mismatch: 4 variables but c.FetchIntelligence returns 3 values` (this confirms the `Tools` field wiring compiles; the remaining failure is the signature width, fixed in Task 5). This is expected — do not attempt to fix `FetchIntelligence`'s signature in this task.

- [ ] **Step 5: Run the rest of the connector suite to confirm nothing else broke**

Run: `cd orchestrator && go test ./internal/connector/... -run 'TestToolEntitiesFrom|TestOpenCTIClient_ConvertTool|TestOpenCTIClient_Fetch_MergesThreatActorsAndIntrusionSets|TestOpenCTIClient_Stats' -v`
Expected: PASS — everything except `TestOpenCTIClient_FetchIntelligence_PopulatedAfterFetch`, which is expected to remain red until Task 5.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/connector/opencti.go orchestrator/internal/connector/opencti_intelligence_test.go
git commit -m "feat(connector): OpenCTI Tools query + Fetch() wiring (Intelligence Expansion Phase 4)"
```

---

### Task 4: MISP Tool extraction (unverified galaxy type, explicitly flagged)

**Files:**
- Modify: `orchestrator/internal/connector/misp.go`
- Modify: `orchestrator/internal/connector/misp_intelligence_test.go`

**Interfaces:**
- Consumes: `intelligence.Tool`, `intelligence.MalwareKey` (Task 1); existing `techniqueIDs` (already in `misp.go`).
- Produces: `extractIntelligence` returns a third value `[]intelligence.Tool`; `MISPClient.lastTools []intelligence.Tool` field, populated by `Fetch()`.

**Before starting:** this task encodes an *assumption* — that MISP's ATT&CK galaxy taxonomy uses `mitre-tool` as the cluster type for Software objects typed "tool" (parallel to the already-confirmed `mitre-malware` for Software typed "malware"). This has not been verified against a live MISP instance (spec §Non-Goals). If a live MISP instance becomes reachable before or during this task, verify the real galaxy type name first (e.g. via a MISP `GalaxyCluster` API/UI check for `type` values on ATT&CK Software galaxy entries) and adjust the filter string in Step 3 accordingly before proceeding — don't ship a guessed-wrong string.

- [ ] **Step 1: Write the failing test, explicitly marked as validating an assumption**

Add to `orchestrator/internal/connector/misp_intelligence_test.go`, after `TestMISPClient_FetchIntelligence_MultipleMalwareClusters`:

```go
// TestMISPClient_FetchIntelligence_ExtractsTools validates extraction against
// the "mitre-tool" galaxy cluster type -- an ASSUMED name, inferred from the
// already-confirmed "mitre-malware"/"mitre-attack-pattern" convention this
// codebase already relies on, but NOT independently verified against a live
// MISP instance (see docs/superpowers/specs/2026-07-29-intelligence-expansion-phase4-design.md's
// Non-Goals). If a future live-MISP check finds the real type name differs,
// this test is the first thing that should be updated.
func TestMISPClient_FetchIntelligence_ExtractsTools(t *testing.T) {
	index := []mispEventIndex{
		{ID: "3", Info: "Living-off-the-Land Toolkit Event", Timestamp: "1700000000", Tag: []mispTag{{Name: "mitre-attack-pattern"}}},
	}
	details := map[string]mispEventDetail{
		"3": {Event: struct {
			ID            string          `json:"id"`
			Info          string          `json:"info"`
			Timestamp     string          `json:"timestamp"`
			Tag           []mispTag       `json:"Tag"`
			GalaxyCluster []mispGalaxy    `json:"GalaxyCluster"`
			Attribute     []mispAttribute `json:"Attribute"`
		}{
			ID: "3", Info: "Living-off-the-Land Toolkit Event",
			GalaxyCluster: []mispGalaxy{
				{Type: "mitre-attack-pattern", Value: "PowerShell", Meta: struct {
					ExternalID []string `json:"external_id"`
					KillChain  []string `json:"kill_chain"`
				}{ExternalID: []string{"T1059.001"}}},
				{Type: "mitre-attack-pattern", Value: "Remote System Discovery", Meta: struct {
					ExternalID []string `json:"external_id"`
					KillChain  []string `json:"kill_chain"`
				}{ExternalID: []string{"T1018"}}},
				{Type: "mitre-tool", Value: "PsExec"},
				{Type: "mitre-tool", Value: "AdFind"},
				{Type: "mitre-malware", Value: "NotATool"}, // wrong type -- must not become a Tool entry
			},
		}},
	}
	server := mispServer(t, index, details)
	defer server.Close()

	c := NewMISPClient(server.URL, "test-key", nil, nil)
	if _, err := c.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	_, _, tools, err := c.FetchIntelligence()
	if err != nil {
		t.Fatalf("FetchIntelligence: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("tools = %+v, want 2 entries (PsExec, AdFind)", tools)
	}
	names := map[string]bool{tools[0].Name: true, tools[1].Name: true}
	if !names["PsExec"] || !names["AdFind"] {
		t.Errorf("tool names = %v, want PsExec and AdFind", names)
	}
	for _, tl := range tools {
		if tl.ID != MalwareKeyForTest(tl.Name) {
			t.Errorf("tool ID = %q, want normalized key of %q", tl.ID, tl.Name)
		}
		if len(tl.TechniqueIDs) != 2 {
			t.Errorf("tool %q TechniqueIDs = %v, want the event's 2 techniques", tl.Name, tl.TechniqueIDs)
		}
		if len(tl.CampaignIDs) != 1 || tl.CampaignIDs[0] != "3" {
			t.Errorf("tool %q CampaignIDs = %v, want [3]", tl.Name, tl.CampaignIDs)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/connector/... -run TestMISPClient_FetchIntelligence_ExtractsTools -v`
Expected: FAIL — `assignment mismatch: 4 variables but c.FetchIntelligence returns 3 values` (or similar compile error against the not-yet-widened signature)

- [ ] **Step 3: Add the `mitre-tool` extraction loop**

In `orchestrator/internal/connector/misp.go`, modify `extractIntelligence`'s signature and add the third loop:

```go
// extractIntelligence builds Intelligence Expansion data (Campaign +
// Malware + Tool) from an already-qualified, already-fetched MISP event --
// reuses the same event detail and actor name/techniques extractActor
// already derived, no second fetch. One Campaign per qualifying event (the
// event itself is the campaign container). Zero or more Malware/Tool
// records, one per mitre-malware/mitre-tool GalaxyCluster entry
// respectively. Both inherit the SAME technique/actor association as the
// event's actor -- MISP's flat galaxy list doesn't support finer
// per-entry technique attribution without deeper relationship parsing,
// which this client deliberately doesn't attempt.
func (c *MISPClient) extractIntelligence(ev mispEventIndex, detail *mispEventDetail, actor *ThreatActor) (*intelligence.Campaign, []intelligence.Malware, []intelligence.Tool) {
	src := intelligence.SourceRef{
		Provider: "misp", ExternalID: ev.ID,
		LastUpdated: actor.LastSeen, Confidence: actor.Confidence,
	}
	if src.LastUpdated.IsZero() {
		src.LastUpdated = time.Now()
	}

	campaign := &intelligence.Campaign{
		ID: ev.ID, Name: detail.Event.Info, Description: detail.Event.Info,
		ThreatActorIDs: []string{actor.Name}, TechniqueIDs: techniqueIDs(actor.Techniques),
		Source: src,
	}

	var malware []intelligence.Malware
	var tools []intelligence.Tool
	for _, gc := range detail.Event.GalaxyCluster {
		name := strings.TrimSpace(gc.Value)
		if name == "" {
			continue
		}
		switch gc.Type {
		case "mitre-malware":
			malware = append(malware, intelligence.Malware{
				ID: intelligence.MalwareKey(name), Name: name,
				TechniqueIDs: techniqueIDs(actor.Techniques),
				ThreatActorIDs: []string{actor.Name}, CampaignIDs: []string{ev.ID},
				Source: src,
			})
		case "mitre-tool":
			tools = append(tools, intelligence.Tool{
				ID: intelligence.MalwareKey(name), Name: name,
				TechniqueIDs: techniqueIDs(actor.Techniques),
				ThreatActorIDs: []string{actor.Name}, CampaignIDs: []string{ev.ID},
				Source: src,
			})
		}
	}
	return campaign, malware, tools
}
```

(This restructures the existing single-purpose `if gc.Type != "mitre-malware" { continue }` loop into a `switch` covering both types — behavior-preserving for the malware branch.)

Update `Fetch()`'s call site and accumulator:

```go
	actorMap := make(map[string]*ThreatActor)
	var campaigns []intelligence.Campaign
	var malware []intelligence.Malware
	var tools []intelligence.Tool

	for _, ev := range events {
		// ... unchanged hasMitre/detail/actor logic ...

		campaign, eventMalware, eventTools := c.extractIntelligence(ev, detail, actor)
		if campaign != nil {
			campaigns = append(campaigns, *campaign)
		}
		malware = append(malware, eventMalware...)
		tools = append(tools, eventTools...)
	}

	// ... unchanged out/actorMap loop ...
	c.lastStat = SourceStat{Name: "misp", RawCount: len(events), ActorCount: len(out), FetchedAt: time.Now()}
	c.lastCampaigns = campaigns
	c.lastMalware = malware
	c.lastTools = tools
	return out, nil
```

Add `lastTools` to the `MISPClient` struct:

```go
type MISPClient struct {
	baseURL       string
	apiKey        string
	httpClient    *http.Client
	sectors       []string
	regions       []string
	lastStat      SourceStat
	lastCampaigns []intelligence.Campaign
	lastMalware   []intelligence.Malware
	lastTools     []intelligence.Tool
}
```

- [ ] **Step 4: Run test to verify it still fails on the expected line**

Run: `cd orchestrator && go test ./internal/connector/... -run TestMISPClient_FetchIntelligence_ExtractsTools -v`
Expected: FAIL — `c.FetchIntelligence` still returns 3 values (unwidened) vs. this test's 4-variable assignment. This is expected — `FetchIntelligence`'s signature is widened in Task 5, not here.

- [ ] **Step 5: Run the rest of the MISP intelligence tests to confirm the malware branch still behaves correctly**

Run: `cd orchestrator && go test ./internal/connector/... -run 'TestMISPClient_FetchIntelligence_OneCampaignNoMalware|TestMISPClient_FetchIntelligence_MultipleMalwareClusters' -v`

These call sites also use the old 2-value `campaign, malware, err := c.FetchIntelligence()` shape and will fail to compile until Task 5. Expected: FAIL with the same "returns 3 values" compile error — confirms this task's `switch` restructuring itself introduced no new problem beyond the expected, not-yet-fixed signature width.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/connector/misp.go orchestrator/internal/connector/misp_intelligence_test.go
git commit -m "feat(connector): MISP mitre-tool extraction, unverified galaxy type (Intelligence Expansion Phase 4)"
```

---

### Task 5: Widen `IntelligenceSource.FetchIntelligence()` to 3 slices + scheduler wiring

**Files:**
- Modify: `orchestrator/internal/connector/source.go`
- Modify: `orchestrator/internal/connector/opencti.go`
- Modify: `orchestrator/internal/connector/misp.go`
- Modify: `orchestrator/internal/connector/scheduler.go`

**Interfaces:**
- Consumes: `OpenCTIClient.lastTools` (Task 3), `MISPClient.lastTools` (Task 4), `intelligence.UpsertTool` (Task 1).
- Produces: `IntelligenceSource.FetchIntelligence() ([]intelligence.Campaign, []intelligence.Malware, []intelligence.Tool, error)` — this is the change that makes every test written in Tasks 3-4 (which already assume this 3-slice-plus-error shape) finally compile and pass.

This task has no new test of its own — it's the wiring fix that makes Tasks 3's and 4's already-written tests pass. This is intentional: those tests were written against the target interface shape before the interface itself changed, so their failures in Tasks 3/4 double as the "verify it fails" step for this task.

- [ ] **Step 1: Widen the interface**

In `orchestrator/internal/connector/source.go`:

```go
// IntelligenceSource is an optional Source capability: providers that can
// also extract Campaign/Malware/Tool intelligence beyond actor-technique
// profiles implement this. Both MISPClient and OpenCTIClient implement it
// as of Intelligence Expansion Phase 4 -- see
// docs/superpowers/specs/2026-07-29-intelligence-expansion-phase4-design.md.
type IntelligenceSource interface {
	FetchIntelligence() ([]intelligence.Campaign, []intelligence.Malware, []intelligence.Tool, error)
}
```

- [ ] **Step 2: Widen `OpenCTIClient.FetchIntelligence()`**

In `orchestrator/internal/connector/opencti.go`:

```go
// FetchIntelligence implements connector.IntelligenceSource -- returns the
// Campaign/Malware/Tool data gathered during the most recent Fetch() call,
// same after-the-fact-accessor pattern Stats() already uses.
func (c *OpenCTIClient) FetchIntelligence() ([]intelligence.Campaign, []intelligence.Malware, []intelligence.Tool, error) {
	return c.lastCampaigns, c.lastMalware, c.lastTools, nil
}
```

- [ ] **Step 3: Widen `MISPClient.FetchIntelligence()`**

In `orchestrator/internal/connector/misp.go`:

```go
// FetchIntelligence implements IntelligenceSource -- returns the
// Campaign/Malware/Tool data gathered during the most recent Fetch() call.
func (c *MISPClient) FetchIntelligence() ([]intelligence.Campaign, []intelligence.Malware, []intelligence.Tool, error) {
	return c.lastCampaigns, c.lastMalware, c.lastTools, nil
}
```

- [ ] **Step 4: Update `misp_intelligence_test.go`'s two existing 2-slice call sites**

In `orchestrator/internal/connector/misp_intelligence_test.go`:

In `TestMISPClient_FetchIntelligence_OneCampaignNoMalware`, change:
```go
	campaigns, malware, err := c.FetchIntelligence()
```
to:
```go
	campaigns, malware, _, err := c.FetchIntelligence()
```

In `TestMISPClient_FetchIntelligence_MultipleMalwareClusters`, change:
```go
	_, malware, err := c.FetchIntelligence()
```
to:
```go
	_, malware, _, err := c.FetchIntelligence()
```

- [ ] **Step 5: Update `scheduler.go`'s call site and add `UpsertTool` persistence**

In `orchestrator/internal/connector/scheduler.go`, find the `sync()` method. Add an `allTools` accumulator next to the existing `allCampaigns`/`allMalware`:

```go
	var allCampaigns []intelligence.Campaign
	var allMalware []intelligence.Malware
	var allTools []intelligence.Tool
```

Update the `IntelligenceSource` type-assertion block:

```go
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
```

Add a persistence loop next to the existing `UpsertCampaign`/`UpsertMalware` loops:

```go
		for _, tl := range allTools {
			if err := intelligence.UpsertTool(context.Background(), s.pool, tl); err != nil {
				log.Printf("[connector] upsert tool %q: %v", tl.ID, err)
			}
		}
```

- [ ] **Step 6: Run the full connector package test suite**

Run: `cd orchestrator && go test ./internal/connector/... -v`
Expected: PASS — every test in the package, including all tests from Tasks 2-4 that were previously failing to compile against the old 3-return-value signature.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/connector/source.go orchestrator/internal/connector/opencti.go orchestrator/internal/connector/misp.go orchestrator/internal/connector/scheduler.go orchestrator/internal/connector/misp_intelligence_test.go
git commit -m "feat(connector): widen IntelligenceSource for Tool extraction, wire into Scheduler (Intelligence Expansion Phase 4)"
```

---

### Task 6: `GET /api/intelligence/tools` + RBAC

**Files:**
- Modify: `orchestrator/internal/api/intelligence_handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `intelligence.ListTools` (Task 1).
- Produces: `func (h *Handler) IntelligenceTools(w http.ResponseWriter, r *http.Request)`, route `GET /api/intelligence/tools`.

- [ ] **Step 1: Write the failing RBAC matrix test entry**

In `orchestrator/internal/api/rbac_matrix_test.go`, find the two existing lines:

```go
	{http.MethodGet, "/api/intelligence/campaigns", tierAny, ""},
	{http.MethodGet, "/api/intelligence/malware", tierAny, ""},
```

Add directly after:

```go
	{http.MethodGet, "/api/intelligence/tools", tierAny, ""},
```

- [ ] **Step 2: Run the RBAC matrix test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix -v`
Expected: FAIL — route `/api/intelligence/tools` not registered (exact failure message depends on how `rbac_matrix_test.go` iterates the table — it will fail either on a 404 from the unregistered route or an explicit "route not found" assertion; either confirms the route doesn't exist yet).

- [ ] **Step 3: Add the handler**

In `orchestrator/internal/api/intelligence_handlers.go`, add after `IntelligenceMalware`:

```go
// GET /api/intelligence/tools
func (h *Handler) IntelligenceTools(w http.ResponseWriter, r *http.Request) {
	tools, err := intelligence.ListTools(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, tools)
}
```

- [ ] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, find:

```go
		// Intelligence Expansion Phase 1 -- MISP-sourced Campaigns/Malware
		// (distinct from /api/threat-priority's actor-level scoring).
		r.Get("/api/intelligence/campaigns", h.IntelligenceCampaigns)
		r.Get("/api/intelligence/malware", h.IntelligenceMalware)
```

Replace with:

```go
		// Intelligence Expansion -- MISP/OpenCTI-sourced Campaigns/Malware/Tools
		// (distinct from /api/threat-priority's actor-level scoring).
		r.Get("/api/intelligence/campaigns", h.IntelligenceCampaigns)
		r.Get("/api/intelligence/malware", h.IntelligenceMalware)
		r.Get("/api/intelligence/tools", h.IntelligenceTools)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix -v`
Expected: PASS

- [ ] **Step 6: Run the full `internal/api` test suite to confirm no other regressions**

Run: `cd orchestrator && go test ./internal/api/... -v`
Expected: PASS across the whole package.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/intelligence_handlers.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(api): GET /api/intelligence/tools (Intelligence Expansion Phase 4)"
```

---

### Task 7: Full regression

**Files:** none (verification only)

- [ ] **Step 1: Full build**

Run: `cd orchestrator && go build ./...`
Expected: no errors

- [ ] **Step 2: Full vet**

Run: `cd orchestrator && go vet ./...`
Expected: no errors

- [ ] **Step 3: Full test suite**

Run: `cd orchestrator && go test ./... -count=1`
Expected: PASS across all packages (Docker Desktop must be running for `internal/api` and `internal/intelligence`'s DB-backed tests — check `docker info` first, start Docker Desktop if needed).

- [ ] **Step 4: Confirm no leftover 2-slice/3-slice `FetchIntelligence` call-site mismatches anywhere else in the codebase**

```bash
cd orchestrator && grep -rn "FetchIntelligence()" --include="*.go" .
```

Manually confirm every result destructures exactly 4 return values (`campaigns, malware, tools, err`, using `_` for any unused ones) — this is a final sweep in case any call site outside `internal/connector` (e.g. a future dashboard handler) was missed by the earlier tasks. If any 3-value call site is found, fix it and re-run Step 3.

Expected: every match already uses the 4-value shape; no changes needed (Tasks 4-5 already covered all real call sites in `misp_intelligence_test.go`, `opencti_intelligence_test.go`, and `scheduler.go`).
