# Threat-Intel Connector Per-Source Stat Tracking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** track MISP's and OpenCTI's raw fetch numbers separately (not just one combined total), so a future UI can show each connector's own real numbers instead of a merged figure nobody can attribute to a specific source.

**Architecture:** a new optional `StatsSource` interface (`Stats() SourceStat`), implemented by `MISPClient`, `OpenCTIClient`, and `BundleSource`, each storing its last fetch's raw/filtered counts on itself. The scheduler's existing per-source fetch loop checks for this interface via type assertion (the same pattern already used there for `*BundleSource`'s version) and threads the results into `ConnectorStatus.BySource`, replacing the whole map fresh on every sync tick.

**Tech Stack:** Go, `net/http/httptest` for MISP/OpenCTI test mocking, existing `internal/connector` package conventions.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-22-connector-per-source-stats-design.md` — read it first.
- This is sub-project 1 of a 4-part initiative (see the spec's intro) — backend-only, produces no user-visible UI change on its own. Sub-project 2 (rich status cards) is a separate, later plan.
- `BySource` is a full-replace snapshot each sync tick, not an accumulator — matches `TotalActors`'s existing `=` semantics, not `ScenariosCreated`'s `+=` semantics.
- No new API calls to MISP/OpenCTI for fields not already computed today (Feeds, Server Version, Tags) — explicitly out of scope, deferred to sub-project 2.

---

### Task 1: `SourceStat` type, `StatsSource` interface, and `BundleSource.Stats()`

**Files:**
- Modify: `orchestrator/internal/connector/types.go` (new `SourceStat` type, new `StatsSource` interface, `ConnectorStatus.BySource` field)
- Modify: `orchestrator/internal/connector/bundle.go` (`BundleSource.lastStat` field + `Stats()` method)
- Test: `orchestrator/internal/connector/bundle_test.go`

**Interfaces:**
- Produces: `type SourceStat struct{ Name, RawCount, ActorCount, FetchedAt, Error }`, `type StatsSource interface{ Stats() SourceStat }`, `ConnectorStatus.BySource map[string]SourceStat` — consumed by Task 2 (MISP/OpenCTI implement `StatsSource`) and Task 3 (scheduler wiring).

- [ ] **Step 1: Write the failing test for `BundleSource.Stats()`**

In `orchestrator/internal/connector/bundle_test.go`, find:
```go
func TestBundleSource_Fetch_Valid(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, validBundle)
	bs := NewBundleSource(dir, func(string) error { return nil }) // verify passes

	actors, err := bs.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 1 || actors[0].Name != "APT36" {
		t.Fatalf("actors = %+v", actors)
	}
	if len(actors[0].Techniques) != 2 || actors[0].Techniques[0].ID != "T1059.001" {
		t.Fatalf("techniques = %+v", actors[0].Techniques)
	}
	if actors[0].Source != "bundle" {
		t.Fatalf("source = %q, want bundle", actors[0].Source)
	}
	if bs.Version() != "2026-07-17" {
		t.Fatalf("version = %q", bs.Version())
	}
}
```
Replace with:
```go
func TestBundleSource_Fetch_Valid(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, validBundle)
	bs := NewBundleSource(dir, func(string) error { return nil }) // verify passes

	actors, err := bs.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 1 || actors[0].Name != "APT36" {
		t.Fatalf("actors = %+v", actors)
	}
	if len(actors[0].Techniques) != 2 || actors[0].Techniques[0].ID != "T1059.001" {
		t.Fatalf("techniques = %+v", actors[0].Techniques)
	}
	if actors[0].Source != "bundle" {
		t.Fatalf("source = %q, want bundle", actors[0].Source)
	}
	if bs.Version() != "2026-07-17" {
		t.Fatalf("version = %q", bs.Version())
	}

	stat := bs.Stats()
	if stat.Name != "bundle" || stat.RawCount != 1 || stat.ActorCount != 1 || stat.Error != "" {
		t.Fatalf("Stats() = %+v, want Name=bundle RawCount=1 ActorCount=1 Error=\"\"", stat)
	}
	if stat.FetchedAt.IsZero() {
		t.Fatal("Stats().FetchedAt should be set after a successful Fetch")
	}
}

func TestBundleSource_Stats_RecordsErrorOnFailedFetch(t *testing.T) {
	bs := NewBundleSource(t.TempDir(), func(string) error { return nil })
	if _, err := bs.Fetch(); err == nil {
		t.Fatal("expected error for missing bundle")
	}
	stat := bs.Stats()
	if stat.Name != "bundle" || stat.Error == "" {
		t.Fatalf("Stats() = %+v, want Name=bundle with Error set", stat)
	}
	if stat.RawCount != 0 || stat.ActorCount != 0 {
		t.Fatalf("Stats() = %+v, want zero counts on a failed fetch", stat)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/connector/... -run TestBundleSource -v`
Expected: FAIL — `bs.Stats undefined (type *BundleSource has no field or method Stats)`.

- [ ] **Step 3: Add `SourceStat`, `StatsSource`, and `ConnectorStatus.BySource`**

In `orchestrator/internal/connector/types.go`, find:
```go
// ConnectorStatus is the live state of the connector — returned by the API.
type ConnectorStatus struct {
	MISPEnabled      bool      `json:"mispEnabled"`
	OpenCTIEnabled   bool      `json:"openctiEnabled"`
	BundleEnabled    bool      `json:"bundleEnabled"`
	BundleVersion    string    `json:"bundleVersion,omitempty"`
	LastSyncAt       time.Time `json:"lastSyncAt"`
	LastSyncStatus   string    `json:"lastSyncStatus"` // "ok" | "error" | "never"
	LastError        string    `json:"lastError,omitempty"`
	ScenariosCreated int       `json:"scenariosCreated"`
	ScenariosUpdated int       `json:"scenariosUpdated"`
	TotalActors      int       `json:"totalActors"`
	NextSyncAt       time.Time `json:"nextSyncAt"`
}
```
Replace with:
```go
// SourceStat is one threat-intel source's numbers from its most recent fetch.
// RawCount and ActorCount differ because MISP/OpenCTI results are filtered to
// actors with 2+ mapped ATT&CK techniques before being merged — RawCount is
// what the source returned before that filter (MISP: events; OpenCTI: raw
// threat-actor nodes), ActorCount is what passed it. The bundle source applies
// no such filter, so its RawCount and ActorCount are always equal.
type SourceStat struct {
	Name       string    `json:"name"` // "misp" | "opencti" | "bundle"
	RawCount   int       `json:"rawCount"`
	ActorCount int       `json:"actorCount"`
	FetchedAt  time.Time `json:"fetchedAt"`
	Error      string    `json:"error,omitempty"` // set instead of counts when this source's fetch failed
}

// StatsSource is implemented by sources that can report their last fetch's raw
// numbers. Checked via type assertion in Scheduler.sync (the same pattern
// already used there for *BundleSource's Version()) — sources that don't
// implement it are simply skipped, not an error.
type StatsSource interface {
	Stats() SourceStat
}

// ConnectorStatus is the live state of the connector — returned by the API.
type ConnectorStatus struct {
	MISPEnabled      bool                  `json:"mispEnabled"`
	OpenCTIEnabled   bool                  `json:"openctiEnabled"`
	BundleEnabled    bool                  `json:"bundleEnabled"`
	BundleVersion    string                `json:"bundleVersion,omitempty"`
	LastSyncAt       time.Time             `json:"lastSyncAt"`
	LastSyncStatus   string                `json:"lastSyncStatus"` // "ok" | "error" | "never"
	LastError        string                `json:"lastError,omitempty"`
	ScenariosCreated int                   `json:"scenariosCreated"`
	ScenariosUpdated int                   `json:"scenariosUpdated"`
	TotalActors      int                   `json:"totalActors"`
	NextSyncAt       time.Time             `json:"nextSyncAt"`
	BySource         map[string]SourceStat `json:"bySource,omitempty"` // keyed by Source.Name()
}
```

- [ ] **Step 4: Add `lastStat` field and `Stats()` to `BundleSource`**

In `orchestrator/internal/connector/bundle.go`, find:
```go
// BundleSource reads a signed threat-intel bundle from a local directory. The
// signature verifier is injected (production passes integrity.VerifyScenarioFile)
// so the crypto is reused and the source can be unit-tested without the private key.
type BundleSource struct {
	path    string
	verify  func(path string) error
	version string
}
```
Replace with:
```go
// BundleSource reads a signed threat-intel bundle from a local directory. The
// signature verifier is injected (production passes integrity.VerifyScenarioFile)
// so the crypto is reused and the source can be unit-tested without the private key.
type BundleSource struct {
	path     string
	verify   func(path string) error
	version  string
	lastStat SourceStat
}
```

Find:
```go
// Fetch verifies the bundle signature (when a verifier is set), then parses it.
// A tampered, unsigned, missing, or malformed bundle returns an error and no actors.
func (b *BundleSource) Fetch() ([]ThreatActor, error) {
	if b.verify != nil {
		if err := b.verify(b.path); err != nil {
			return nil, fmt.Errorf("ti bundle verify: %w", err)
		}
	}
	raw, err := os.ReadFile(b.path)
	if err != nil {
		return nil, fmt.Errorf("read ti bundle: %w", err)
	}
	var bundle Bundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, fmt.Errorf("parse ti bundle %s: %w", b.path, err)
	}
	// Stamp provenance so status/downstream can distinguish bundle-provided actors.
	for i := range bundle.Actors {
		if bundle.Actors[i].Source == "" {
			bundle.Actors[i].Source = "bundle"
		}
	}
	b.version = bundle.Version
	return bundle.Actors, nil
}
```
Replace with:
```go
// Fetch verifies the bundle signature (when a verifier is set), then parses it.
// A tampered, unsigned, missing, or malformed bundle returns an error and no actors.
func (b *BundleSource) Fetch() ([]ThreatActor, error) {
	if b.verify != nil {
		if err := b.verify(b.path); err != nil {
			b.lastStat = SourceStat{Name: "bundle", Error: err.Error(), FetchedAt: time.Now()}
			return nil, fmt.Errorf("ti bundle verify: %w", err)
		}
	}
	raw, err := os.ReadFile(b.path)
	if err != nil {
		b.lastStat = SourceStat{Name: "bundle", Error: err.Error(), FetchedAt: time.Now()}
		return nil, fmt.Errorf("read ti bundle: %w", err)
	}
	var bundle Bundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		b.lastStat = SourceStat{Name: "bundle", Error: err.Error(), FetchedAt: time.Now()}
		return nil, fmt.Errorf("parse ti bundle %s: %w", b.path, err)
	}
	// Stamp provenance so status/downstream can distinguish bundle-provided actors.
	for i := range bundle.Actors {
		if bundle.Actors[i].Source == "" {
			bundle.Actors[i].Source = "bundle"
		}
	}
	b.version = bundle.Version
	b.lastStat = SourceStat{Name: "bundle", RawCount: len(bundle.Actors), ActorCount: len(bundle.Actors), FetchedAt: time.Now()}
	return bundle.Actors, nil
}

// Stats implements StatsSource.
func (b *BundleSource) Stats() SourceStat { return b.lastStat }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/connector/... -run TestBundleSource -v`
Expected: all PASS (including the two new tests).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/connector/types.go orchestrator/internal/connector/bundle.go orchestrator/internal/connector/bundle_test.go
git commit -m "feat(connector): add SourceStat/StatsSource types, BundleSource.Stats()"
```

---

### Task 2: `MISPClient.Stats()` and `OpenCTIClient.Stats()`

**Files:**
- Modify: `orchestrator/internal/connector/misp.go`
- Modify: `orchestrator/internal/connector/opencti.go`
- Test: `orchestrator/internal/connector/misp_stats_test.go` (new)
- Test: `orchestrator/internal/connector/opencti_stats_test.go` (new)

**Interfaces:**
- Consumes: `SourceStat`, `StatsSource` (Task 1).
- Produces: `(*MISPClient).Stats() SourceStat`, `(*OpenCTIClient).Stats() SourceStat` — consumed by Task 3's scheduler wiring (via the `StatsSource` type assertion, not a direct reference).

- [ ] **Step 1: Write the failing test for `MISPClient.Stats()`**

Create `orchestrator/internal/connector/misp_stats_test.go`:
```go
package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestMISPClient_Stats_CountsRawEventsAndFilteredActors uses events with no
// "mitre-attack" tag, so extractActor short-circuits before its second HTTP
// call (getEvent) — this keeps the test to a single mocked endpoint while
// still exercising the real RawCount/ActorCount split: all 3 events count as
// RawCount, none pass the mitre-tag pre-filter, so ActorCount is 0.
func TestMISPClient_Stats_CountsRawEventsAndFilteredActors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/events/index" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
		events := []mispEventIndex{
			{ID: "1", Info: "event one", Tag: []mispTag{{Name: "tlp:amber"}}},
			{ID: "2", Info: "event two", Tag: nil},
			{ID: "3", Info: "event three", Tag: []mispTag{{Name: "some-other-tag"}}},
		}
		json.NewEncoder(w).Encode(events)
	}))
	defer server.Close()

	c := NewMISPClient(server.URL, "test-key", nil, nil)
	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 0 {
		t.Fatalf("actors = %+v, want none (no event has a mitre-attack tag)", actors)
	}

	stat := c.Stats()
	if stat.Name != "misp" || stat.RawCount != 3 || stat.ActorCount != 0 || stat.Error != "" {
		t.Fatalf("Stats() = %+v, want Name=misp RawCount=3 ActorCount=0 Error=\"\"", stat)
	}
	if stat.FetchedAt.IsZero() {
		t.Fatal("Stats().FetchedAt should be set after a successful Fetch")
	}
}

func TestMISPClient_Stats_RecordsErrorOnFailedFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewMISPClient(server.URL, "test-key", nil, nil)
	if _, err := c.Fetch(); err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	stat := c.Stats()
	if stat.Name != "misp" || stat.Error == "" {
		t.Fatalf("Stats() = %+v, want Name=misp with Error set", stat)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/connector/... -run TestMISPClient_Stats -v`
Expected: FAIL — `c.Stats undefined (type *MISPClient has no field or method Stats)`.

- [ ] **Step 3: Add `lastStat` field and `Stats()` to `MISPClient`**

In `orchestrator/internal/connector/misp.go`, find:
```go
// MISPClient fetches threat-actor TTP profiles from a MISP instance.
type MISPClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	sectors    []string
	regions    []string
}
```
Replace with:
```go
// MISPClient fetches threat-actor TTP profiles from a MISP instance.
type MISPClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	sectors    []string
	regions    []string
	lastStat   SourceStat
}
```

Find:
```go
// Fetch returns all threat actors with MITRE ATT&CK technique mappings.
func (c *MISPClient) Fetch() ([]ThreatActor, error) {
	events, err := c.listEvents()
	if err != nil {
		return nil, fmt.Errorf("misp list events: %w", err)
	}
	log.Printf("[connector/misp] fetched %d events", len(events))
```
Replace with:
```go
// Fetch returns all threat actors with MITRE ATT&CK technique mappings.
func (c *MISPClient) Fetch() ([]ThreatActor, error) {
	events, err := c.listEvents()
	if err != nil {
		c.lastStat = SourceStat{Name: "misp", Error: err.Error(), FetchedAt: time.Now()}
		return nil, fmt.Errorf("misp list events: %w", err)
	}
	log.Printf("[connector/misp] fetched %d events", len(events))
```

Find:
```go
	out := make([]ThreatActor, 0, len(actorMap))
	for _, a := range actorMap {
		if len(a.Techniques) >= 2 {
			out = append(out, *a)
		}
	}
	return out, nil
}
```
Replace with:
```go
	out := make([]ThreatActor, 0, len(actorMap))
	for _, a := range actorMap {
		if len(a.Techniques) >= 2 {
			out = append(out, *a)
		}
	}
	c.lastStat = SourceStat{Name: "misp", RawCount: len(events), ActorCount: len(out), FetchedAt: time.Now()}
	return out, nil
}

// Stats implements StatsSource.
func (c *MISPClient) Stats() SourceStat { return c.lastStat }
```

- [ ] **Step 4: Run the MISP tests to verify they pass**

Run: `cd orchestrator && go test ./internal/connector/... -run TestMISPClient_Stats -v`
Expected: both PASS.

- [ ] **Step 5: Write the failing test for `OpenCTIClient.Stats()`**

Create `orchestrator/internal/connector/opencti_stats_test.go`:
```go
package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestOpenCTIClient_Stats_CountsRawNodesAndFilteredActors returns two threat-
// actor nodes with no attack-pattern edges, so convertActor builds an actor
// with 0 techniques and Fetch's "2+ techniques" filter drops both — RawCount
// is 2, ActorCount is 0. A single mocked GraphQL endpoint is enough since
// OpenCTI's Fetch, unlike MISP's, makes only one HTTP round trip.
func TestOpenCTIClient_Stats_CountsRawNodesAndFilteredActors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
		resp := octiThreatActorsResp{}
		resp.Data.ThreatActors.Edges = make([]struct {
			Node octiThreatActorNode `json:"node"`
		}, 2)
		resp.Data.ThreatActors.Edges[0].Node = octiThreatActorNode{ID: "1", Name: "Actor One"}
		resp.Data.ThreatActors.Edges[1].Node = octiThreatActorNode{ID: "2", Name: "Actor Two"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := NewOpenCTIClient(server.URL, "test-key", nil)
	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 0 {
		t.Fatalf("actors = %+v, want none (no node has 2+ techniques)", actors)
	}

	stat := c.Stats()
	if stat.Name != "opencti" || stat.RawCount != 2 || stat.ActorCount != 0 || stat.Error != "" {
		t.Fatalf("Stats() = %+v, want Name=opencti RawCount=2 ActorCount=0 Error=\"\"", stat)
	}
	if stat.FetchedAt.IsZero() {
		t.Fatal("Stats().FetchedAt should be set after a successful Fetch")
	}
}

func TestOpenCTIClient_Stats_RecordsErrorOnFailedFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewOpenCTIClient(server.URL, "test-key", nil)
	if _, err := c.Fetch(); err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	stat := c.Stats()
	if stat.Name != "opencti" || stat.Error == "" {
		t.Fatalf("Stats() = %+v, want Name=opencti with Error set", stat)
	}
}
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/connector/... -run TestOpenCTIClient_Stats -v`
Expected: FAIL — `c.Stats undefined (type *OpenCTIClient has no field or method Stats)`.

- [ ] **Step 7: Add `lastStat` field and `Stats()` to `OpenCTIClient`**

In `orchestrator/internal/connector/opencti.go`, find:
```go
// OpenCTIClient fetches threat-actor TTP profiles from an OpenCTI instance.
type OpenCTIClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	// sectors is currently unused: unlike MISP, OpenCTI's GraphQL query
	// (octiThreatActorNode) never fetches sector/region relationship data,
	// so ThreatActor.Sectors/Regions are always empty for OpenCTI-sourced
	// actors. Wiring a filter check against always-empty data here would
	// silently reject every OpenCTI actor once ThreatIntelSectors is
	// configured — a regression, not a fix. Left unused deliberately,
	// documented rather than silently fixed incorrectly. Properly
	// supporting this needs OpenCTI's actual sector/region GraphQL schema,
	// which can't be verified without a live instance. See
	// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	sectors []string
}
```
Replace with:
```go
// OpenCTIClient fetches threat-actor TTP profiles from an OpenCTI instance.
type OpenCTIClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	// sectors is currently unused: unlike MISP, OpenCTI's GraphQL query
	// (octiThreatActorNode) never fetches sector/region relationship data,
	// so ThreatActor.Sectors/Regions are always empty for OpenCTI-sourced
	// actors. Wiring a filter check against always-empty data here would
	// silently reject every OpenCTI actor once ThreatIntelSectors is
	// configured — a regression, not a fix. Left unused deliberately,
	// documented rather than silently fixed incorrectly. Properly
	// supporting this needs OpenCTI's actual sector/region GraphQL schema,
	// which can't be verified without a live instance. See
	// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	sectors  []string
	lastStat SourceStat
}
```

Find:
```go
// Fetch returns threat actors with their MITRE ATT&CK technique mappings.
func (c *OpenCTIClient) Fetch() ([]ThreatActor, error) {
	actorsRaw, err := c.queryThreatActors()
	if err != nil {
		return nil, fmt.Errorf("opencti query actors: %w", err)
	}
	log.Printf("[connector/opencti] fetched %d threat actors", len(actorsRaw))

	var actors []ThreatActor
	for _, raw := range actorsRaw {
		actor := c.convertActor(raw)
		if actor == nil || len(actor.Techniques) < 2 {
			continue
		}
		actors = append(actors, *actor)
	}
	return actors, nil
}
```
Replace with:
```go
// Fetch returns threat actors with their MITRE ATT&CK technique mappings.
func (c *OpenCTIClient) Fetch() ([]ThreatActor, error) {
	actorsRaw, err := c.queryThreatActors()
	if err != nil {
		c.lastStat = SourceStat{Name: "opencti", Error: err.Error(), FetchedAt: time.Now()}
		return nil, fmt.Errorf("opencti query actors: %w", err)
	}
	log.Printf("[connector/opencti] fetched %d threat actors", len(actorsRaw))

	var actors []ThreatActor
	for _, raw := range actorsRaw {
		actor := c.convertActor(raw)
		if actor == nil || len(actor.Techniques) < 2 {
			continue
		}
		actors = append(actors, *actor)
	}
	c.lastStat = SourceStat{Name: "opencti", RawCount: len(actorsRaw), ActorCount: len(actors), FetchedAt: time.Now()}
	return actors, nil
}

// Stats implements StatsSource.
func (c *OpenCTIClient) Stats() SourceStat { return c.lastStat }
```

- [ ] **Step 8: Run the OpenCTI tests to verify they pass**

Run: `cd orchestrator && go test ./internal/connector/... -run TestOpenCTIClient_Stats -v`
Expected: both PASS.

- [ ] **Step 9: Run the full connector package test suite**

Run: `cd orchestrator && go test ./internal/connector/... -v 2>&1 | tail -60`
Expected: all PASS, no regressions in the existing MISP/OpenCTI/Bundle/Scheduler/Generator tests.

- [ ] **Step 10: Commit**

```bash
git add orchestrator/internal/connector/misp.go orchestrator/internal/connector/opencti.go orchestrator/internal/connector/misp_stats_test.go orchestrator/internal/connector/opencti_stats_test.go
git commit -m "feat(connector): add MISPClient.Stats() and OpenCTIClient.Stats()"
```

---

### Task 3: Scheduler wiring

**Files:**
- Modify: `orchestrator/internal/connector/scheduler.go`
- Test: `orchestrator/internal/connector/scheduler_test.go`

**Interfaces:**
- Consumes: `SourceStat`, `StatsSource` (Task 1); `(*MISPClient).Stats()`, `(*OpenCTIClient).Stats()`, `(*BundleSource).Stats()` (Task 2, indirectly via the `StatsSource` interface — the scheduler never references these concrete types).
- Produces: `ConnectorStatus.BySource` populated on every sync — the final consumer-visible deliverable of this whole plan (`GET /api/connector/status` now returns it; no handler code change needed since `GetConnectorStatus` already returns `h.scheduler.Status()` verbatim).

- [ ] **Step 1: Write the failing test for per-source stat aggregation**

In `orchestrator/internal/connector/scheduler_test.go`, find:
```go
type fakeSource struct {
	name   string
	actors []ThreatActor
	err    error
}

func (f fakeSource) Name() string                  { return f.name }
func (f fakeSource) Fetch() ([]ThreatActor, error) { return f.actors, f.err }
```
Replace with:
```go
type fakeSource struct {
	name   string
	actors []ThreatActor
	err    error
	stats  SourceStat
}

func (f fakeSource) Name() string                  { return f.name }
func (f fakeSource) Fetch() ([]ThreatActor, error) { return f.actors, f.err }
func (f fakeSource) Stats() SourceStat             { return f.stats }
```

Add this new test after `TestNewScheduler_StatusFlags`:
```go
func TestScheduler_Sync_PopulatesBySourcePerSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	mispStat := SourceStat{Name: "misp", RawCount: 5, ActorCount: 2, FetchedAt: time.Now()}
	s := NewScheduler([]Source{
		fakeSource{
			name:   "misp",
			actors: []ThreatActor{{Name: "APT36", Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}}}},
			stats:  mispStat,
		},
		fakeSource{
			name: "opencti",
			err:  errors.New("opencti unreachable"),
			stats: SourceStat{Name: "opencti", Error: "opencti unreachable", FetchedAt: time.Now()},
		},
	}, NewGenerator(t.TempDir(), nil, nil), scenario.NewEngine(t.TempDir()), 24, sharedDB.Pool)

	s.sync()

	st := s.Status()
	if len(st.BySource) != 2 {
		t.Fatalf("BySource = %+v, want 2 entries", st.BySource)
	}
	misp, ok := st.BySource["misp"]
	if !ok || misp.RawCount != 5 || misp.ActorCount != 2 || misp.Error != "" {
		t.Fatalf("BySource[misp] = %+v, want RawCount=5 ActorCount=2 Error=\"\"", misp)
	}
	opencti, ok := st.BySource["opencti"]
	if !ok || opencti.Error != "opencti unreachable" {
		t.Fatalf("BySource[opencti] = %+v, want Error=\"opencti unreachable\"", opencti)
	}
}
```

`scheduler_test.go`'s import block does not yet have `"errors"` or `"time"`. Find:
```go
import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
)
```
Replace with:
```go
import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/connector/... -run TestScheduler_Sync_PopulatesBySourcePerSource -v`
Expected: FAIL — `st.BySource` is `nil`/empty (field exists from Task 1, but nothing populates it yet), or a compile error if `fakeSource` isn't yet updated — confirm via the actual failure message and proceed once it's a genuine assertion failure, not a compile error.

- [ ] **Step 3: Wire per-source stat capture into `Scheduler.sync`**

In `orchestrator/internal/connector/scheduler.go`, find:
```go
func (s *Scheduler) sync() {
	log.Println("[connector] starting threat-intel sync")
	start := time.Now()

	var actors []ThreatActor
	var bundleVersion string

	// Fetch every configured source. The bundle (air-gapped floor) and live
	// providers (MISP/OpenCTI overlay) are treated uniformly; a single source
	// failing is logged and skipped, never aborting the others.
	for _, src := range s.sources {
		got, err := src.Fetch()
		if err != nil {
			log.Printf("[connector/%s] fetch error: %v", src.Name(), err)
			s.setError(src.Name() + ": " + err.Error())
			continue
		}
		log.Printf("[connector/%s] %d actors fetched", src.Name(), len(got))
		actors = append(actors, got...)
		if bs, ok := src.(*BundleSource); ok {
			bundleVersion = bs.Version()
		}
	}

	if len(actors) == 0 {
		log.Println("[connector] no actors returned from any source")
		s.setOK(0, 0, 0, bundleVersion)
		return
	}
```
Replace with:
```go
func (s *Scheduler) sync() {
	log.Println("[connector] starting threat-intel sync")
	start := time.Now()

	var actors []ThreatActor
	var bundleVersion string
	bySource := map[string]SourceStat{}

	// Fetch every configured source. The bundle (air-gapped floor) and live
	// providers (MISP/OpenCTI overlay) are treated uniformly; a single source
	// failing is logged and skipped, never aborting the others.
	for _, src := range s.sources {
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
	}

	if len(actors) == 0 {
		log.Println("[connector] no actors returned from any source")
		s.setOK(0, 0, 0, bundleVersion, bySource)
		return
	}
```

Find:
```go
	elapsed := time.Since(start).Round(time.Millisecond)
	log.Printf("[connector] sync complete in %s — created:%d updated:%d skipped:%d",
		elapsed, result.Created, result.Updated, result.Skipped)

	s.setOK(result.Created, result.Updated, len(actors), bundleVersion)
}
```
Replace with:
```go
	elapsed := time.Since(start).Round(time.Millisecond)
	log.Printf("[connector] sync complete in %s — created:%d updated:%d skipped:%d",
		elapsed, result.Created, result.Updated, result.Skipped)

	s.setOK(result.Created, result.Updated, len(actors), bundleVersion, bySource)
}
```

Find:
```go
func (s *Scheduler) setOK(created, updated, total int, bundleVersion string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.LastSyncAt = time.Now()
	s.status.LastSyncStatus = "ok"
	s.status.LastError = ""
	s.status.ScenariosCreated += created
	s.status.ScenariosUpdated += updated
	s.status.TotalActors = total
	if bundleVersion != "" {
		s.status.BundleVersion = bundleVersion
	}
	s.status.NextSyncAt = time.Now().Add(s.interval)
}

func (s *Scheduler) setError(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.LastSyncAt = time.Now()
	s.status.LastSyncStatus = "error"
	s.status.LastError = msg
	s.status.NextSyncAt = time.Now().Add(s.interval)
}
```
Replace with:
```go
func (s *Scheduler) setOK(created, updated, total int, bundleVersion string, bySource map[string]SourceStat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.LastSyncAt = time.Now()
	s.status.LastSyncStatus = "ok"
	s.status.LastError = ""
	s.status.ScenariosCreated += created
	s.status.ScenariosUpdated += updated
	s.status.TotalActors = total
	if bundleVersion != "" {
		s.status.BundleVersion = bundleVersion
	}
	s.status.BySource = bySource
	s.status.NextSyncAt = time.Now().Add(s.interval)
}

func (s *Scheduler) setError(msg string, bySource map[string]SourceStat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.LastSyncAt = time.Now()
	s.status.LastSyncStatus = "error"
	s.status.LastError = msg
	s.status.BySource = bySource
	s.status.NextSyncAt = time.Now().Add(s.interval)
}
```

Note: `setError` is called from inside the per-source loop on each failing source, not just once at the end — this means `bySource` (still being built up as the loop continues to later sources) gets assigned to `s.status.BySource` on every intermediate error too, not just a final complete map. That's fine: each call is a full-replace of the field with the *accumulated-so-far* map at that point, and the very last call before `sync()` returns (whether via the early `len(actors) == 0` return or the final `setOK`) always carries the complete, final map — matching the "full snapshot" semantics from the spec.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/connector/... -run TestScheduler_Sync_PopulatesBySourcePerSource -v`
Expected: PASS.

- [ ] **Step 5: Run the full connector package test suite**

Run: `cd orchestrator && go test ./internal/connector/... -v 2>&1 | tail -80`
Expected: all PASS — including `TestNewScheduler_StatusFlags`, `TestMergeActors_UnionsTechniques`, `TestScheduler_SyncUpsertsActorProfiles`, and everything from Tasks 1-2.

- [ ] **Step 6: Run the full orchestrator build to catch any other caller of `setOK`/`setError`**

Run: `cd orchestrator && go build ./... 2>&1`
Expected: no errors. (`setOK`/`setError` are unexported — only `scheduler.go` itself can call them, so no other file needs updating, but this confirms it.)

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/connector/scheduler.go orchestrator/internal/connector/scheduler_test.go
git commit -m "feat(connector): wire per-source stats into Scheduler.sync -> ConnectorStatus.BySource"
git push
```

---

## Self-Review Notes

**Spec coverage:** Task 1 covers `SourceStat`/`StatsSource`/`ConnectorStatus.BySource` and `BundleSource.Stats()` in full. Task 2 covers `MISPClient.Stats()`/`OpenCTIClient.Stats()` in full, including the error-path capture the spec calls for ("a failed source is distinguishable from one that returned zero actors"). Task 3 covers the scheduler wiring and the "snapshot, not accumulator" semantics the spec specifies. The spec's "explicitly out of scope" items (new MISP/OpenCTI API calls for Feeds/Server Version/Tags, UI changes, OTX) are correctly not touched anywhere in this plan.

**Placeholder scan:** none — every step has complete code or an exact command with expected output.

**Type consistency:** `SourceStat{Name, RawCount, ActorCount, FetchedAt, Error}` (Task 1) is used identically across all three producers (Task 1's `BundleSource.Stats()`, Task 2's `MISPClient.Stats()`/`OpenCTIClient.Stats()`) and the one consumer (Task 3's `Scheduler.sync`/`setOK`/`setError`). `setOK`'s and `setError`'s new `bySource map[string]SourceStat` parameter matches the accumulator variable's declared type in `sync()` exactly. `fakeSource.Stats()` (Task 3) matches the `StatsSource` interface signature defined in Task 1.
