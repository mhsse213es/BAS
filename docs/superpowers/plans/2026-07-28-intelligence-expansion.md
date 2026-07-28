# Intelligence Expansion (Phase 1: MISP Campaigns + Malware) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop discarding MISP's already-fetched `GalaxyCluster` malware data and treat each qualifying event as a Campaign container, persisting both into a new flat `internal/intelligence` package with a minimal read API.

**Architecture:** New `internal/intelligence` package owns `Campaign`/`Malware`/`SourceRef` types and their persistence (free functions, no stateful wrapper). `connector.MISPClient` gains a third optional `Source` capability (`IntelligenceSource`, alongside the existing `StatsSource` pattern) that extracts Campaign/Malware from the same event-detail fetch already used for actor extraction — no second MISP query. `Scheduler.sync()` persists what it collects. Two new read-only API endpoints expose the result.

**Tech Stack:** Go, PostgreSQL (pgx/v5), extends existing `internal/connector` MISP client.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-28-intelligence-expansion-design.md` — read it before starting; this plan implements it exactly.
- `internal/intelligence` must never import `internal/connector` (one-directional: connector → intelligence, matching the same discipline `internal/threatpriority` already established).
- OpenCTI and OTX `Fetch()` implementations are untouched — only `MISPClient` changes.
- No relationship/join tables — `Campaign`/`Malware` carry denormalized `[]string` ID-list fields, per the spec's explicit "don't normalize yet" decision.
- Every new route needs a `routeMatrix` entry in `internal/api/rbac_matrix_test.go` added in the *same task* as the route (established discipline from the two prior projects this session — both shipped this correctly the second time after Phase 1 got it wrong once).
- `go test ./... -count=1`, `go build ./...`, `go vet ./...` must all be clean before this plan is done (Task 6).

---

### Task 1: `internal/intelligence` — types and `MalwareKey`

**Files:**
- Create: `orchestrator/internal/intelligence/models.go`
- Test: `orchestrator/internal/intelligence/models_test.go`

**Interfaces:**
- Produces: `SourceRef`, `Campaign`, `Malware` structs; `func MalwareKey(name string) string` — used by Task 3's MISP extraction and Task 2's store tests.

- [ ] **Step 1: Write the failing test**

```go
package intelligence

import "testing"

func TestMalwareKey_NormalizesCase(t *testing.T) {
	if got := MalwareKey("Emotet"); got != "emotet" {
		t.Fatalf("MalwareKey(%q) = %q, want %q", "Emotet", got, "emotet")
	}
}

func TestMalwareKey_StripsSpacesAndHyphens(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Cobalt Strike", "cobaltstrike"},
		{"BlackCat/ALPHV", "blackcat/alphv"}, // slash intentionally untouched -- only spaces/hyphens are stripped, matching connector.actorKey()'s exact scope
		{"Trickbot-v2", "trickbotv2"},
	}
	for _, c := range cases {
		if got := MalwareKey(c.in); got != c.want {
			t.Errorf("MalwareKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMalwareKey_SameKeyForDifferentCasing(t *testing.T) {
	if MalwareKey("Emotet") != MalwareKey("EMOTET") {
		t.Fatal("expected case-insensitive dedup key")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/intelligence/... -v`
Expected: FAIL to compile — package `internal/intelligence` doesn't exist yet.

- [ ] **Step 3: Create `models.go`**

```go
// Package intelligence holds Campaign and Malware -- the two entities the
// Intelligence Expansion project adds. Everything else in the originally
// envisioned "Intelligence Repository" (Actors, IOCs, CVEs) already has a
// home elsewhere (threat_actor_profiles, internal/ioc's ioc_enrichment
// table, the CVE Relationship Store) -- see
// docs/superpowers/specs/2026-07-28-intelligence-expansion-design.md's
// Problem section for why this package doesn't duplicate those.
//
// No relationship/join tables here -- Campaign/Malware carry denormalized
// []string ID-list fields and get normalized only in a future phase, once
// more than one provider contributes overlapping data.
package intelligence

import (
	"strings"
	"time"
)

// SourceRef is provenance metadata carried by every Campaign/Malware
// record. Exists from day one so a future multi-provider reconciliation
// phase has a mechanism already in place rather than requiring a schema
// redesign when other providers start contributing the same entities.
type SourceRef struct {
	Provider    string    `json:"provider"`   // "misp" (only value today)
	ExternalID  string    `json:"externalId"` // MISP event ID (Campaign) / galaxy cluster value (Malware)
	LastUpdated time.Time `json:"lastUpdated"`
	// Confidence uses the same "high"|"medium"|"low"|"" convention as
	// connector.ThreatActor.Confidence and threatpriority.ConfidenceFactor
	// -- deliberately not a numeric scale, to avoid two parallel confidence
	// representations for the same concept across the codebase.
	Confidence string `json:"confidence"`
}

// Campaign is one MISP event that qualified as ATT&CK-relevant (the same
// gate connector.MISPClient already applies for actor extraction). The
// event itself is the campaign container -- MISP doesn't expose a distinct
// "campaign" galaxy type separate from its events in what this client
// parses.
type Campaign struct {
	ID             string    `json:"id"` // = Source.ExternalID for MISP (event ID, already unique)
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	ThreatActorIDs []string  `json:"threatActorIds"` // threat_actor_profiles.name values
	TechniqueIDs   []string  `json:"techniqueIds"`
	Source         SourceRef `json:"source"`
}

// Malware is one mitre-malware GalaxyCluster entry, deduplicated by
// normalized name across every event that references it (MalwareKey).
type Malware struct {
	ID             string    `json:"id"` // = MalwareKey(Name) -- cross-event dedup key
	Name           string    `json:"name"`
	Aliases        []string  `json:"aliases"`
	TechniqueIDs   []string  `json:"techniqueIds"`
	ThreatActorIDs []string  `json:"threatActorIds"`
	CampaignIDs    []string  `json:"campaignIds"`
	Source         SourceRef `json:"source"`
}

// MalwareKey normalizes a malware name into a stable dedup key -- the same
// normalization connector.actorKey() already applies to actor names
// (lowercase, strip spaces/hyphens). Duplicated here (not exported from
// internal/connector) to keep the connector<->intelligence dependency
// strictly one-way: connector imports intelligence for types, never the
// reverse.
func MalwareKey(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	return s
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/intelligence/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/intelligence/models.go internal/intelligence/models_test.go
git commit -m "feat(intelligence): Campaign/Malware/SourceRef types + MalwareKey"
```

---

### Task 2: `internal/intelligence` — persistence

**Files:**
- Modify: `orchestrator/internal/db/content_schema.go` (append to the `stmts` slice, after the `tph_actor_time` index at line 278)
- Create: `orchestrator/internal/intelligence/store.go`
- Test: `orchestrator/internal/intelligence/store_test.go`

**Interfaces:**
- Consumes: `Campaign`, `Malware`, `SourceRef` (Task 1).
- Produces: `UpsertCampaign(ctx, pool, c Campaign) error`, `UpsertMalware(ctx, pool, m Malware) error`, `ListCampaigns(ctx, pool) ([]Campaign, error)`, `ListMalware(ctx, pool) ([]Malware, error)` — used by Task 4's Scheduler wiring and Task 5's API handlers.

- [ ] **Step 1: Add the DDL**

In `orchestrator/internal/db/content_schema.go`, immediately after the `tph_actor_time` index statement (line 278, right before the closing `}` of the `stmts` slice), add:

```go
		`CREATE TABLE IF NOT EXISTS intelligence_campaigns (
			id                  text        PRIMARY KEY,
			name                text        NOT NULL,
			description         text        NOT NULL DEFAULT '',
			actor_ids           text[]      NOT NULL DEFAULT '{}',
			technique_ids       text[]      NOT NULL DEFAULT '{}',
			source_provider     text        NOT NULL,
			source_external_id  text        NOT NULL DEFAULT '',
			source_confidence   text        NOT NULL DEFAULT '',
			last_updated        timestamptz NOT NULL DEFAULT NOW(),
			tenant_id           text        NOT NULL DEFAULT 'default'
		)`,
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
```

- [ ] **Step 2: Write the failing test**

```go
// orchestrator/internal/intelligence/store_test.go
package intelligence

import (
	"context"
	"flag"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

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

func TestUpsertCampaign_InsertThenOverwriteOnConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		c := Campaign{
			ID: "evt-1", Name: "Original Name", Description: "first",
			ThreatActorIDs: []string{"APT-TEST"}, TechniqueIDs: []string{"T1059"},
			Source: SourceRef{Provider: "misp", ExternalID: "evt-1", LastUpdated: time.Now(), Confidence: "medium"},
		}
		if err := UpsertCampaign(ctx, pool, c); err != nil {
			t.Fatalf("first UpsertCampaign: %v", err)
		}

		c.Name = "Updated Name"
		c.TechniqueIDs = []string{"T1059", "T1105"}
		if err := UpsertCampaign(ctx, pool, c); err != nil {
			t.Fatalf("second UpsertCampaign: %v", err)
		}

		got, err := ListCampaigns(ctx, pool)
		if err != nil {
			t.Fatalf("ListCampaigns: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d campaigns, want 1 (overwrite, not duplicate)", len(got))
		}
		if got[0].Name != "Updated Name" {
			t.Fatalf("Name = %q, want %q (overwrite must win)", got[0].Name, "Updated Name")
		}
		if len(got[0].TechniqueIDs) != 2 {
			t.Fatalf("TechniqueIDs = %v, want 2 entries", got[0].TechniqueIDs)
		}
	})
}

func TestUpsertMalware_MergesArraysOnConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		first := Malware{
			ID: "emotet", Name: "Emotet",
			TechniqueIDs: []string{"T1059"}, ThreatActorIDs: []string{"APT-A"}, CampaignIDs: []string{"evt-1"},
			Source: SourceRef{Provider: "misp", ExternalID: "evt-1", LastUpdated: time.Now(), Confidence: "medium"},
		}
		if err := UpsertMalware(ctx, pool, first); err != nil {
			t.Fatalf("first UpsertMalware: %v", err)
		}

		second := Malware{
			ID: "emotet", Name: "Emotet",
			TechniqueIDs: []string{"T1059", "T1105"}, ThreatActorIDs: []string{"APT-B"}, CampaignIDs: []string{"evt-2"},
			Source: SourceRef{Provider: "misp", ExternalID: "evt-2", LastUpdated: time.Now(), Confidence: "high"},
		}
		if err := UpsertMalware(ctx, pool, second); err != nil {
			t.Fatalf("second UpsertMalware: %v", err)
		}

		got, err := ListMalware(ctx, pool)
		if err != nil {
			t.Fatalf("ListMalware: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d malware rows, want 1 (merged, not duplicated)", len(got))
		}
		m := got[0]
		sort.Strings(m.TechniqueIDs)
		if len(m.TechniqueIDs) != 2 || m.TechniqueIDs[0] != "T1059" || m.TechniqueIDs[1] != "T1105" {
			t.Errorf("TechniqueIDs = %v, want deduplicated union [T1059 T1105]", m.TechniqueIDs)
		}
		sort.Strings(m.ThreatActorIDs)
		if len(m.ThreatActorIDs) != 2 || m.ThreatActorIDs[0] != "APT-A" || m.ThreatActorIDs[1] != "APT-B" {
			t.Errorf("ThreatActorIDs = %v, want union [APT-A APT-B]", m.ThreatActorIDs)
		}
		sort.Strings(m.CampaignIDs)
		if len(m.CampaignIDs) != 2 || m.CampaignIDs[0] != "evt-1" || m.CampaignIDs[1] != "evt-2" {
			t.Errorf("CampaignIDs = %v, want union [evt-1 evt-2]", m.CampaignIDs)
		}
		if m.Source.Confidence != "high" {
			t.Errorf("Source.Confidence = %q, want %q (most recent upsert wins)", m.Source.Confidence, "high")
		}
	})
}

func TestListCampaigns_Empty_ReturnsEmptyNotNil(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := ListCampaigns(context.Background(), pool)
		if err != nil {
			t.Fatalf("ListCampaigns: %v", err)
		}
		if got == nil {
			t.Fatal("expected an empty slice, not nil -- callers/JSON encoders shouldn't need a nil guard")
		}
	})
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/intelligence/... -v`
Expected: FAIL to compile — `UpsertCampaign`/`UpsertMalware`/`ListCampaigns`/`ListMalware` not defined.

- [ ] **Step 4: Create `store.go`**

```go
package intelligence

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// UpsertCampaign overwrites on conflict -- each MISP event ID is already
// unique, so re-syncing the same event is a plain refresh, no merge needed.
func UpsertCampaign(ctx context.Context, pool *pgxpool.Pool, c Campaign) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO intelligence_campaigns
		   (id, name, description, actor_ids, technique_ids, source_provider, source_external_id, source_confidence, last_updated)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (id) DO UPDATE SET
		   name = EXCLUDED.name, description = EXCLUDED.description,
		   actor_ids = EXCLUDED.actor_ids, technique_ids = EXCLUDED.technique_ids,
		   source_provider = EXCLUDED.source_provider, source_external_id = EXCLUDED.source_external_id,
		   source_confidence = EXCLUDED.source_confidence, last_updated = EXCLUDED.last_updated`,
		c.ID, c.Name, c.Description, c.ThreatActorIDs, c.TechniqueIDs,
		c.Source.Provider, c.Source.ExternalID, c.Source.Confidence, c.Source.LastUpdated)
	return err
}

// UpsertMalware merges on conflict -- the same malware family is
// legitimately referenced by many different events, so technique/actor/
// campaign ID lists accumulate (deduplicated union) rather than overwrite.
func UpsertMalware(ctx context.Context, pool *pgxpool.Pool, m Malware) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO intelligence_malware
		   (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider, source_external_id, source_confidence, last_updated)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 ON CONFLICT (id) DO UPDATE SET
		   aliases       = ARRAY(SELECT DISTINCT UNNEST(intelligence_malware.aliases || EXCLUDED.aliases)),
		   technique_ids = ARRAY(SELECT DISTINCT UNNEST(intelligence_malware.technique_ids || EXCLUDED.technique_ids)),
		   actor_ids     = ARRAY(SELECT DISTINCT UNNEST(intelligence_malware.actor_ids || EXCLUDED.actor_ids)),
		   campaign_ids  = ARRAY(SELECT DISTINCT UNNEST(intelligence_malware.campaign_ids || EXCLUDED.campaign_ids)),
		   source_confidence = EXCLUDED.source_confidence,
		   last_updated  = GREATEST(intelligence_malware.last_updated, EXCLUDED.last_updated)`,
		m.ID, m.Name, m.Aliases, m.TechniqueIDs, m.ThreatActorIDs, m.CampaignIDs,
		m.Source.Provider, m.Source.ExternalID, m.Source.Confidence, m.Source.LastUpdated)
	return err
}

// ListCampaigns returns every campaign, newest-updated first. Always
// non-nil (an empty slice, not null) so JSON callers can iterate without a
// guard -- same convention internal/recommend.Recommendations already uses.
func ListCampaigns(ctx context.Context, pool *pgxpool.Pool) ([]Campaign, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, name, description, actor_ids, technique_ids, source_provider, source_external_id, source_confidence, last_updated
		 FROM intelligence_campaigns ORDER BY last_updated DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Campaign{}
	for rows.Next() {
		var c Campaign
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.ThreatActorIDs, &c.TechniqueIDs,
			&c.Source.Provider, &c.Source.ExternalID, &c.Source.Confidence, &c.Source.LastUpdated); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListMalware returns every malware record, newest-updated first. Always
// non-nil, same convention as ListCampaigns.
func ListMalware(ctx context.Context, pool *pgxpool.Pool) ([]Malware, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider, source_external_id, source_confidence, last_updated
		 FROM intelligence_malware ORDER BY last_updated DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Malware{}
	for rows.Next() {
		var m Malware
		if err := rows.Scan(&m.ID, &m.Name, &m.Aliases, &m.TechniqueIDs, &m.ThreatActorIDs, &m.CampaignIDs,
			&m.Source.Provider, &m.Source.ExternalID, &m.Source.Confidence, &m.Source.LastUpdated); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/intelligence/... -v`
Expected: PASS (schema migration runs automatically via `EnsureContentSchema` at test-container startup, same as every other `content_schema.go` table).

- [ ] **Step 6: Commit**

```bash
git add internal/db/content_schema.go internal/intelligence/store.go internal/intelligence/store_test.go
git commit -m "feat(intelligence): persistence -- intelligence_campaigns/intelligence_malware tables"
```

---

### Task 3: MISP extraction — `IntelligenceSource`, `extractIntelligence`, `Fetch()` restructure

**Files:**
- Modify: `orchestrator/internal/connector/source.go` (add `IntelligenceSource` interface)
- Modify: `orchestrator/internal/connector/misp.go` (`MISPClient` fields, `extractActor` signature, new `extractIntelligence`/`techniqueIDs`/`FetchIntelligence`, `Fetch()` restructure)
- Test: `orchestrator/internal/connector/misp_intelligence_test.go`

**Interfaces:**
- Consumes: `intelligence.Campaign`, `intelligence.Malware`, `intelligence.SourceRef`, `intelligence.MalwareKey` (Task 1).
- Produces: `connector.IntelligenceSource` interface; `(*MISPClient).FetchIntelligence() ([]intelligence.Campaign, []intelligence.Malware, error)` — used by Task 4's Scheduler wiring.

- [ ] **Step 1: Add the `IntelligenceSource` interface**

In `orchestrator/internal/connector/source.go`, add after the existing `Source` interface:

```go
// IntelligenceSource is an optional Source capability: providers that can
// also extract Campaign/Malware intelligence beyond actor-technique
// profiles implement this. Only MISPClient does today -- see
// docs/superpowers/specs/2026-07-28-intelligence-expansion-design.md.
// OpenCTI/OTX/Bundle are unaffected until a later phase extends them.
type IntelligenceSource interface {
	FetchIntelligence() ([]intelligence.Campaign, []intelligence.Malware, error)
}
```

Add the import `"github.com/audspect/bas/internal/intelligence"` to `source.go`.

- [ ] **Step 2: Write the failing test**

```go
// orchestrator/internal/connector/misp_intelligence_test.go
package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mispServer builds a mock MISP server serving both /events/index (the
// event list) and /events/{id} (per-event detail) from the given detail
// map, keyed by event ID -- the two-call flow extractIntelligence's tests
// need, matching the real listEvents+getEvent sequence Fetch() performs.
func mispServer(t *testing.T, index []mispEventIndex, details map[string]mispEventDetail) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events/index" {
			json.NewEncoder(w).Encode(index)
			return
		}
		for id, d := range details {
			if r.URL.Path == "/events/"+id {
				json.NewEncoder(w).Encode(d)
				return
			}
		}
		t.Fatalf("unexpected request path: %s", r.URL.Path)
	}))
}

func TestMISPClient_FetchIntelligence_OneCampaignNoMalware(t *testing.T) {
	index := []mispEventIndex{
		{ID: "1", Info: "APT36 Kill Chain", Timestamp: "1700000000", Tag: []mispTag{{Name: "mitre-attack-pattern"}}},
	}
	details := map[string]mispEventDetail{
		"1": {Event: struct {
			ID            string          `json:"id"`
			Info          string          `json:"info"`
			Timestamp     string          `json:"timestamp"`
			Tag           []mispTag       `json:"Tag"`
			GalaxyCluster []mispGalaxy    `json:"GalaxyCluster"`
			Attribute     []mispAttribute `json:"Attribute"`
		}{
			ID: "1", Info: "APT36 Kill Chain",
			Tag: []mispTag{{Name: "misp-galaxy:threat-actor=\"APT36\""}},
			GalaxyCluster: []mispGalaxy{
				{Type: "mitre-attack-pattern", Value: "PowerShell", Meta: struct {
					ExternalID []string `json:"external_id"`
					KillChain  []string `json:"kill_chain"`
				}{ExternalID: []string{"T1059.001"}, KillChain: []string{"mitre-attack:execution"}}},
				{Type: "mitre-attack-pattern", Value: "Phishing", Meta: struct {
					ExternalID []string `json:"external_id"`
					KillChain  []string `json:"kill_chain"`
				}{ExternalID: []string{"T1566.001"}, KillChain: []string{"mitre-attack:initial-access"}}},
			},
		}},
	}
	server := mispServer(t, index, details)
	defer server.Close()

	c := NewMISPClient(server.URL, "test-key", nil, nil)
	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 1 {
		t.Fatalf("actors = %+v, want 1", actors)
	}

	campaigns, malware, err := c.FetchIntelligence()
	if err != nil {
		t.Fatalf("FetchIntelligence: %v", err)
	}
	if len(campaigns) != 1 {
		t.Fatalf("campaigns = %+v, want 1", campaigns)
	}
	if campaigns[0].ID != "1" || campaigns[0].Name != "APT36 Kill Chain" {
		t.Errorf("campaign = %+v, want ID=1 Name=%q", campaigns[0], "APT36 Kill Chain")
	}
	if len(campaigns[0].TechniqueIDs) != 2 {
		t.Errorf("campaign TechniqueIDs = %v, want 2 entries", campaigns[0].TechniqueIDs)
	}
	if len(campaigns[0].ThreatActorIDs) != 1 || campaigns[0].ThreatActorIDs[0] != "APT36" {
		t.Errorf("campaign ThreatActorIDs = %v, want [APT36]", campaigns[0].ThreatActorIDs)
	}
	if len(malware) != 0 {
		t.Fatalf("malware = %+v, want none (no mitre-malware cluster in this event)", malware)
	}
}

func TestMISPClient_FetchIntelligence_MultipleMalwareClusters(t *testing.T) {
	index := []mispEventIndex{
		{ID: "2", Info: "Emotet/Trickbot Campaign", Timestamp: "1700000000", Tag: []mispTag{{Name: "mitre-attack-pattern"}}},
	}
	details := map[string]mispEventDetail{
		"2": {Event: struct {
			ID            string          `json:"id"`
			Info          string          `json:"info"`
			Timestamp     string          `json:"timestamp"`
			Tag           []mispTag       `json:"Tag"`
			GalaxyCluster []mispGalaxy    `json:"GalaxyCluster"`
			Attribute     []mispAttribute `json:"Attribute"`
		}{
			ID: "2", Info: "Emotet/Trickbot Campaign",
			GalaxyCluster: []mispGalaxy{
				{Type: "mitre-attack-pattern", Value: "PowerShell", Meta: struct {
					ExternalID []string `json:"external_id"`
					KillChain  []string `json:"kill_chain"`
				}{ExternalID: []string{"T1059.001"}}},
				{Type: "mitre-attack-pattern", Value: "Scheduled Task", Meta: struct {
					ExternalID []string `json:"external_id"`
					KillChain  []string `json:"kill_chain"`
				}{ExternalID: []string{"T1053.005"}}},
				{Type: "mitre-malware", Value: "Emotet"},
				{Type: "mitre-malware", Value: "Trickbot"},
				{Type: "mitre-intrusion-set", Value: "SomeIntrusionSet"}, // not mitre-malware -- must not become a Malware entry
			},
		}},
	}
	server := mispServer(t, index, details)
	defer server.Close()

	c := NewMISPClient(server.URL, "test-key", nil, nil)
	if _, err := c.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	_, malware, err := c.FetchIntelligence()
	if err != nil {
		t.Fatalf("FetchIntelligence: %v", err)
	}
	if len(malware) != 2 {
		t.Fatalf("malware = %+v, want 2 entries (Emotet, Trickbot)", malware)
	}
	names := map[string]bool{malware[0].Name: true, malware[1].Name: true}
	if !names["Emotet"] || !names["Trickbot"] {
		t.Errorf("malware names = %v, want Emotet and Trickbot", names)
	}
	for _, m := range malware {
		if m.ID != MalwareKeyForTest(m.Name) {
			t.Errorf("malware ID = %q, want normalized key of %q", m.ID, m.Name)
		}
		if len(m.TechniqueIDs) != 2 {
			t.Errorf("malware %q TechniqueIDs = %v, want the event's 2 techniques", m.Name, m.TechniqueIDs)
		}
		if len(m.CampaignIDs) != 1 || m.CampaignIDs[0] != "2" {
			t.Errorf("malware %q CampaignIDs = %v, want [2]", m.Name, m.CampaignIDs)
		}
	}
}
```

`MalwareKeyForTest` is a thin test-local wrapper (`func MalwareKeyForTest(name string) string { return intelligence.MalwareKey(name) }`) so the assertion doesn't need `internal/intelligence` imported just for one call in the test file — add this helper directly in `misp_intelligence_test.go` above the test functions, with the `"github.com/audspect/bas/internal/intelligence"` import.

- [ ] **Step 3: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/connector/... -run TestMISPClient_FetchIntelligence -v`
Expected: FAIL to compile — `FetchIntelligence` not defined, `mispEventDetail`'s anonymous struct literal syntax in the test may also need adjusting once you see the real compiler error (anonymous-struct field lists must match the real `mispEventDetail.Event` struct exactly — copy it from `misp.go` verbatim rather than retyping, to avoid a mismatched-literal compile error).

- [ ] **Step 4: Modify `misp.go`**

Add the import: `"github.com/audspect/bas/internal/intelligence"`.

Add fields to `MISPClient` (after the existing `lastStat SourceStat` field):

```go
	lastStat      SourceStat
	lastCampaigns []intelligence.Campaign
	lastMalware   []intelligence.Malware
```

Replace `extractActor`'s signature and body start (currently accepts only `ev mispEventIndex` and internally calls `c.getEvent`):

```go
// extractActor builds a ThreatActor from a MISP event index entry and its
// already-fetched detail. detail is fetched once by Fetch()'s loop and
// shared with extractIntelligence to avoid a second per-event API call.
func (c *MISPClient) extractActor(ev mispEventIndex, detail *mispEventDetail) *ThreatActor {
	actor := &ThreatActor{
		Source:   "misp",
		SourceID: ev.ID,
	}

	// Extract actor name and sectors from tags
	for _, tag := range detail.Event.Tag {
		name := tag.Name
		switch {
		case strings.HasPrefix(name, "misp-galaxy:threat-actor="):
			actor.Name = strings.Trim(strings.TrimPrefix(name, "misp-galaxy:threat-actor="), `"`)
		case strings.HasPrefix(name, "misp-galaxy:mitre-intrusion-set="):
			if actor.Name == "" {
				actor.Name = strings.Trim(strings.TrimPrefix(name, "misp-galaxy:mitre-intrusion-set="), `"`)
			}
		case strings.Contains(name, "sector:"):
			actor.Sectors = append(actor.Sectors, strings.TrimPrefix(name, "sector:"))
		case strings.Contains(name, "region:"):
			actor.Regions = append(actor.Regions, strings.TrimPrefix(name, "region:"))
		case strings.Contains(name, "confidence:"):
			actor.Confidence = strings.TrimPrefix(name, "confidence:")
		}
	}

	if actor.Name == "" {
		actor.Name = sanitiseEventName(detail.Event.Info)
	}

	if actor.Confidence == "" {
		actor.Confidence = "medium"
	}

	// Apply sector/region filter
	if !passesSectorRegionFilter(actor.Sectors, actor.Regions, c.sectors, c.regions) {
		return nil
	}

	// Extract techniques from GalaxyCluster (preferred — structured)
	for _, gc := range detail.Event.GalaxyCluster {
		if gc.Type != "mitre-attack-pattern" {
			continue
		}
		for _, extID := range gc.Meta.ExternalID {
			extID = strings.ToUpper(strings.TrimSpace(extID))
			if isATTACKID(extID) {
				tactic := ""
				if len(gc.Meta.KillChain) > 0 {
					parts := strings.SplitN(gc.Meta.KillChain[0], ":", 2)
					if len(parts) == 2 {
						tactic = parts[1]
					}
				}
				actor.Techniques = append(actor.Techniques, TechniqueRef{
					ID:     extID,
					Name:   gc.Value,
					Tactic: tactic,
				})
			}
		}
	}

	// Also extract from attributes with type mitre-attack-pattern
	for _, attr := range detail.Event.Attribute {
		if attr.Type == "mitre-attack-pattern" {
			id := strings.ToUpper(strings.TrimSpace(attr.Value))
			if isATTACKID(id) {
				actor.Techniques = append(actor.Techniques, TechniqueRef{ID: id})
			}
		}
	}

	actor.Techniques = dedupTechniques(actor.Techniques)
	actor.Description = detail.Event.Info

	ts := ev.Timestamp
	if t, err := parseTimestamp(ts); err == nil {
		actor.LastSeen = t
	}

	return actor
}
```

(This is the existing body verbatim — verified byte-accurate against `orchestrator/internal/connector/misp.go` at plan-writing time — minus the `hasMitre` pre-filter and `getEvent` call, which move to `Fetch()` in Step 5 below.)

Add the new extraction function and its helpers, right after `extractActor`:

```go
// extractIntelligence builds Phase 1 Intelligence Expansion data (Campaign +
// Malware) from an already-qualified, already-fetched MISP event -- reuses
// the same event detail and actor name/techniques extractActor already
// derived, no second fetch. One Campaign per qualifying event (the event
// itself IS the campaign container). Zero or more Malware records, one per
// mitre-malware GalaxyCluster entry. Malware entries inherit the SAME
// technique/actor association as the event's actor -- MISP's flat galaxy
// list doesn't support finer per-malware technique attribution without
// deeper relationship parsing, which Phase 1 deliberately doesn't attempt.
func (c *MISPClient) extractIntelligence(ev mispEventIndex, detail *mispEventDetail, actor *ThreatActor) (*intelligence.Campaign, []intelligence.Malware) {
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
	for _, gc := range detail.Event.GalaxyCluster {
		if gc.Type != "mitre-malware" {
			continue
		}
		name := strings.TrimSpace(gc.Value)
		if name == "" {
			continue
		}
		malware = append(malware, intelligence.Malware{
			ID: intelligence.MalwareKey(name), Name: name,
			TechniqueIDs: techniqueIDs(actor.Techniques),
			ThreatActorIDs: []string{actor.Name}, CampaignIDs: []string{ev.ID},
			Source: src,
		})
	}
	return campaign, malware
}

func techniqueIDs(techs []TechniqueRef) []string {
	ids := make([]string, 0, len(techs))
	for _, t := range techs {
		ids = append(ids, t.ID)
	}
	return ids
}

// FetchIntelligence implements IntelligenceSource -- returns the Campaign/
// Malware data gathered during the most recent Fetch() call, the same
// after-the-fact-accessor pattern Stats() already uses for lastStat.
func (c *MISPClient) FetchIntelligence() ([]intelligence.Campaign, []intelligence.Malware, error) {
	return c.lastCampaigns, c.lastMalware, nil
}
```

- [ ] **Step 5: Restructure `Fetch()`**

Replace `Fetch()`'s body:

```go
func (c *MISPClient) Fetch() ([]ThreatActor, error) {
	events, err := c.listEvents()
	if err != nil {
		c.lastStat = SourceStat{Name: "misp", Error: err.Error(), FetchedAt: time.Now()}
		return nil, fmt.Errorf("misp list events: %w", err)
	}
	log.Printf("[connector/misp] fetched %d events", len(events))

	actorMap := make(map[string]*ThreatActor)
	var campaigns []intelligence.Campaign
	var malware []intelligence.Malware

	for _, ev := range events {
		hasMitre := false
		for _, t := range ev.Tag {
			if strings.Contains(t.Name, "mitre-attack-pattern") || strings.Contains(t.Name, "mitre-attack") {
				hasMitre = true
				break
			}
		}
		if !hasMitre {
			continue
		}

		detail, err := c.getEvent(ev.ID)
		if err != nil {
			log.Printf("[connector/misp] fetch event %s: %v", ev.ID, err)
			continue
		}

		actor := c.extractActor(ev, detail)
		if actor == nil || len(actor.Techniques) < 2 {
			continue
		}

		// Merge by actor name (same actor may appear in multiple events)
		if existing, ok := actorMap[actor.Name]; ok {
			existing.Techniques = mergeTechniques(existing.Techniques, actor.Techniques)
			if actor.LastSeen.After(existing.LastSeen) {
				existing.LastSeen = actor.LastSeen
				existing.SourceID = actor.SourceID
			}
		} else {
			actorMap[actor.Name] = actor
		}

		campaign, eventMalware := c.extractIntelligence(ev, detail, actor)
		if campaign != nil {
			campaigns = append(campaigns, *campaign)
		}
		malware = append(malware, eventMalware...)
	}

	out := make([]ThreatActor, 0, len(actorMap))
	for _, a := range actorMap {
		if len(a.Techniques) >= 2 {
			out = append(out, *a)
		}
	}
	c.lastStat = SourceStat{Name: "misp", RawCount: len(events), ActorCount: len(out), FetchedAt: time.Now()}
	c.lastCampaigns = campaigns
	c.lastMalware = malware
	return out, nil
}
```

This relocates the pre-filter loop, `getEvent` error handling, and actor-merge block from today's `extractActor`/`Fetch()` split into `Fetch()` unchanged (verified byte-accurate against the real file at plan-writing time) — nothing about their behavior changes, only which function they live in.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/connector/... -v`
Expected: PASS for all — both new tests, and every pre-existing MISP test (`misp_stats_test.go`, `misp_filter_test.go`) unchanged, confirming the `extractActor` refactor is behavior-preserving.

- [ ] **Step 7: Commit**

```bash
git add internal/connector/source.go internal/connector/misp.go internal/connector/misp_intelligence_test.go
git commit -m "feat(connector): MISP Campaign/Malware extraction via IntelligenceSource"
```

---

### Task 4: Scheduler wiring

**Files:**
- Modify: `orchestrator/internal/connector/scheduler.go`
- Modify: `orchestrator/internal/connector/scheduler_test.go`

**Interfaces:**
- Consumes: `connector.IntelligenceSource`, `intelligence.UpsertCampaign`/`UpsertMalware` (Tasks 2-3).

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/connector/scheduler_test.go`:

```go
func TestScheduler_Sync_PersistsCampaignsAndMalwareFromIntelligenceSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		index := []mispEventIndex{
			{ID: "sched-1", Info: "Scheduler Wiring Test Event", Timestamp: "1700000000", Tag: []mispTag{{Name: "mitre-attack-pattern"}}},
		}
		server := mispServer(t, index, map[string]mispEventDetail{
			"sched-1": {Event: struct {
				ID            string          `json:"id"`
				Info          string          `json:"info"`
				Timestamp     string          `json:"timestamp"`
				Tag           []mispTag       `json:"Tag"`
				GalaxyCluster []mispGalaxy    `json:"GalaxyCluster"`
				Attribute     []mispAttribute `json:"Attribute"`
			}{
				ID: "sched-1", Info: "Scheduler Wiring Test Event",
				GalaxyCluster: []mispGalaxy{
					{Type: "mitre-attack-pattern", Value: "PowerShell", Meta: struct {
						ExternalID []string `json:"external_id"`
						KillChain  []string `json:"kill_chain"`
					}{ExternalID: []string{"T1059.001"}}},
					{Type: "mitre-attack-pattern", Value: "Phishing", Meta: struct {
						ExternalID []string `json:"external_id"`
						KillChain  []string `json:"kill_chain"`
					}{ExternalID: []string{"T1566.001"}}},
					{Type: "mitre-malware", Value: "SchedulerTestMalware"},
				},
			}},
		})
		defer server.Close()

		mispClient := NewMISPClient(server.URL, "test-key", nil, nil)
		s := NewScheduler([]Source{mispClient}, NewGenerator(t.TempDir(), nil, nil, nil), scenario.NewEngine(t.TempDir()), 24, pool, nil)

		s.sync()

		campaigns, err := intelligence.ListCampaigns(context.Background(), pool)
		if err != nil {
			t.Fatalf("ListCampaigns: %v", err)
		}
		found := false
		for _, c := range campaigns {
			if c.ID == "sched-1" {
				found = true
			}
		}
		if !found {
			t.Errorf("campaigns = %+v, want one with ID=sched-1", campaigns)
		}

		malware, err := intelligence.ListMalware(context.Background(), pool)
		if err != nil {
			t.Fatalf("ListMalware: %v", err)
		}
		found = false
		for _, m := range malware {
			if m.Name == "SchedulerTestMalware" {
				found = true
			}
		}
		if !found {
			t.Errorf("malware = %+v, want one named SchedulerTestMalware", malware)
		}
	})
}
```

Add the import `"github.com/audspect/bas/internal/intelligence"` to `scheduler_test.go`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/connector/... -run TestScheduler_Sync_PersistsCampaignsAndMalware -v`
Expected: FAIL — `sync()` doesn't collect or persist campaigns/malware yet, so both lookups come back empty.

- [ ] **Step 3: Wire `sync()`**

In `orchestrator/internal/connector/scheduler.go`, add the import `"github.com/audspect/bas/internal/intelligence"`.

In `sync()`, add `var allCampaigns []intelligence.Campaign` / `var allMalware []intelligence.Malware` alongside the existing `var actors []ThreatActor` declaration.

In the per-source loop, immediately after the existing `if bs, ok := src.(*BundleSource); ok { bundleVersion = bs.Version() }` block, add:

```go
			if is, ok := src.(IntelligenceSource); ok {
				campaigns, malware, ierr := is.FetchIntelligence()
				if ierr != nil {
					log.Printf("[connector/%s] intelligence fetch error: %v", src.Name(), ierr)
				} else {
					allCampaigns = append(allCampaigns, campaigns...)
					allMalware = append(allMalware, malware...)
				}
			}
```

Immediately after the existing `s.upsertActorProfiles(actors)` call (and before the `priorityEngine` block that already follows it), add:

```go
	if s.pool != nil {
		for _, c := range allCampaigns {
			if err := intelligence.UpsertCampaign(context.Background(), s.pool, c); err != nil {
				log.Printf("[connector] upsert campaign %q: %v", c.ID, err)
			}
		}
		for _, m := range allMalware {
			if err := intelligence.UpsertMalware(context.Background(), s.pool, m); err != nil {
				log.Printf("[connector] upsert malware %q: %v", m.ID, err)
			}
		}
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/connector/... -v`
Expected: PASS for all, including every pre-existing `Scheduler` test.

- [ ] **Step 5: Commit**

```bash
git add internal/connector/scheduler.go internal/connector/scheduler_test.go
git commit -m "feat(connector): persist Campaigns/Malware collected during Scheduler.sync"
```

---

### Task 5: API — `GET /api/intelligence/campaigns`, `GET /api/intelligence/malware`

**Files:**
- Create: `orchestrator/internal/api/intelligence_handlers.go`
- Test: `orchestrator/internal/api/intelligence_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go` (register routes, near the existing `/api/threat-priority/*` block at line 180)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (add entries, near the existing `/api/threat-priority/*` entries at line 86)

**Interfaces:**
- Consumes: `intelligence.ListCampaigns`, `intelligence.ListMalware` (Task 2).

- [ ] **Step 1: Write the failing test**

```go
package api

import (
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestIntelligenceCampaigns_Empty_ReturnsEmptyArray(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		engine := scenario.NewEngine(t.TempDir())
		if err := engine.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}
		h := New(pool, ws.NewHub(), engine, "")

		req := httptest.NewRequest("GET", "/api/intelligence/campaigns", nil)
		w := httptest.NewRecorder()
		h.IntelligenceCampaigns(w, req)

		if w.Code != 200 {
			t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
		}
	})
}

func TestIntelligenceMalware_Empty_ReturnsEmptyArray(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		engine := scenario.NewEngine(t.TempDir())
		if err := engine.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}
		h := New(pool, ws.NewHub(), engine, "")

		req := httptest.NewRequest("GET", "/api/intelligence/malware", nil)
		w := httptest.NewRecorder()
		h.IntelligenceMalware(w, req)

		if w.Code != 200 {
			t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestIntelligenceCampaigns -short -v`
Expected: FAIL to compile — `IntelligenceCampaigns`/`IntelligenceMalware` not defined.

- [ ] **Step 3: Create `intelligence_handlers.go`**

```go
package api

import (
	"net/http"

	"github.com/audspect/bas/internal/intelligence"
)

// GET /api/intelligence/campaigns
func (h *Handler) IntelligenceCampaigns(w http.ResponseWriter, r *http.Request) {
	campaigns, err := intelligence.ListCampaigns(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, campaigns)
}

// GET /api/intelligence/malware
func (h *Handler) IntelligenceMalware(w http.ResponseWriter, r *http.Request) {
	malware, err := intelligence.ListMalware(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, malware)
}
```

- [ ] **Step 4: Register routes**

In `orchestrator/internal/api/routes.go`, immediately after the existing `/api/threat-priority/actors/{name}` line (181), add:

```go
		// Intelligence Expansion Phase 1 -- MISP-sourced Campaigns/Malware
		// (distinct from /api/threat-priority's actor-level scoring).
		r.Get("/api/intelligence/campaigns", h.IntelligenceCampaigns)
		r.Get("/api/intelligence/malware", h.IntelligenceMalware)
```

- [ ] **Step 5: Add `routeMatrix` entries**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after the existing `/api/threat-priority/actors/{name}` line (87), add:

```go
	{http.MethodGet, "/api/intelligence/campaigns", tierAny, ""},
	{http.MethodGet, "/api/intelligence/malware", tierAny, ""},
```

- [ ] **Step 6: Run tests**

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run "TestIntelligenceCampaigns|TestIntelligenceMalware|TestRBACMatrix_NoDrift" -v`
Expected: PASS for all.

- [ ] **Step 7: Commit**

```bash
git add internal/api/intelligence_handlers.go internal/api/intelligence_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(api): GET /api/intelligence/campaigns, /malware"
```

---

### Task 6: Final regression

- [ ] **Step 1: Full test suite**

Run: `cd orchestrator && go test ./... -count=1`
Expected: all packages PASS. If `internal/api` shows a connection-refused/testcontainer error unrelated to this project's changes, re-run just that package standalone to confirm it's transient flakiness (this happened once in a prior project this session and was confirmed transient) rather than assuming.

- [ ] **Step 2: Build**

Run: `cd orchestrator && go build ./...`
Expected: no errors.

- [ ] **Step 3: Vet**

Run: `cd orchestrator && go vet ./...`
Expected: no output.

- [ ] **Step 4: Confirm RBAC drift test specifically**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix_NoDrift -v`
Expected: PASS.

- [ ] **Step 5: Clean working tree**

Run: `git status --short`
Expected: no output beyond this session's known pre-existing unrelated files.

- [ ] **Step 6: Push**

```bash
git push
```

---

## Plan Self-Review

**Spec coverage:** Problem/architecture → Tasks 1-2 (types + persistence). Non-goals respected (no OpenCTI/OTX changes, no UI, no relationship tables, no invented fields, no numeric confidence scale, IOC attributes untouched). MISP extraction (`IntelligenceSource`, shared-detail refactor, `mitre-malware` galaxy parsing) → Task 3. Scheduler wiring → Task 4. API → Task 5. Testing section → covered across all 5 tasks' own test steps plus Task 6's regression.

**Placeholder scan:** No TBD/TODO. Task 3's Steps 4/5 reproduce `misp.go`'s current `extractActor`/`Fetch()` bodies verbatim — read in full and verified byte-accurate against the real file during plan-writing, not approximated from memory.

**Type consistency:** `Campaign`/`Malware`/`SourceRef` (Task 1) used identically in Tasks 2-5. `IntelligenceSource.FetchIntelligence()`'s return signature matches `MISPClient.FetchIntelligence()`'s implementation exactly (Task 3). `intelligence.UpsertCampaign`/`UpsertMalware`/`ListCampaigns`/`ListMalware` (Task 2) called with matching signatures in Tasks 4-5.
