# OTX as a Distinct Activity Signal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop OTX from producing `ThreatActor` rows (curated actor attribution) and make it the first implementation of a new `ActivitySource` interface that reports pulse-mention activity evidence instead, persisted separately and scored as its own, deliberately lower-weighted factor.

**Architecture:** `OTXSource` leaves the `Source` interface entirely and implements a new `ActivitySource` (`FetchActivity() ([]ActivitySignal, error)`). `Scheduler` gains a second, independent `activitySources` list wired in via new `WithActivitySources`/`ReconfigureActivitySources` methods (not constructor/`Reconfigure` parameters — this avoids touching the 13 existing `NewScheduler(...)` call sites and 4 existing `Reconfigure(...)` call sites). `sync()` resolves each signal against the already-merged curated roster (reusing `actorKey`, unmodified) and persists to a new `threat_actor_activity` table, creating a minimal actor stub when nothing curated matches. A new `ActivityFactor` reads that table and contributes a small, separately-weighted signal to Threat Prioritization scoring. No new UI work is needed — the actor detail view's existing generic factors list already renders any registered factor.

**Tech Stack:** Go (`internal/connector`, `internal/threatpriority`), Postgres via pgx, existing `sharedDB`/`RunWithPool` test harness.

## Global Constraints

- Zero changes to `internal/connector/actor_merge.go` — the merge/provenance grouping code shipped and tested this session stays byte-for-byte as-is.
- Zero changes to `IntelFreshnessFactor`/`ConfidenceFactor`/`RelevanceFactor` (`internal/threatpriority/standalone_factors.go`) — OTX no longer writing to `threat_actor_profiles`/`threat_actor_sources` fixes the `LastSeen`-leak bug and the fake-"medium"-confidence problem as a side effect of removing OTX from that pipeline entirely, not by adding defensive code to those factors.
- No fuzzy/similarity matching anywhere — `resolveActivitySignalActor` (Task 2) reuses `actorKey`'s exact-match normalization only.
- `PulseCount` is a snapshot of currently-subscribed pulses matching an actor as of the latest sync, never a cross-sync cumulative count (no pulse ID exists to dedupe against).
- No changes to `internal/ioc/otx.go` — a separate, already-distinct on-demand IOC-lookup client, untouched by this work.
- Straight to Final in one plan — no dual-write transition period, no dead code left behind.

---

### Task 1: `ActivitySource` interface + OTX rewrite

**Files:**
- Modify: `orchestrator/internal/connector/source.go` (14 lines — add the new interface + type)
- Modify: `orchestrator/internal/connector/otx.go` (full rewrite of `Fetch()` → `FetchActivity()`)
- Modify: `orchestrator/internal/connector/otx_test.go` (full rewrite — every existing test asserts on the old `[]ThreatActor` shape)

**Interfaces:**
- Produces: `type ActivitySource interface { Name() string; FetchActivity() ([]ActivitySignal, error) }` and `type ActivitySignal struct { ActorName string; PulseCount int; FirstObserved time.Time; LastObserved time.Time }` — consumed by Task 2's `Scheduler`.
- `OTXSource` keeps its existing `Name() string { return "otx" }` and `Stats() SourceStat` methods unchanged (it still implements `StatsSource`), and its unexported `fetchPulsesPage`/`normalizeAdversary`/`otxPulse`/`otxPulsesResponse`/`otxAPIBaseURL`/`otxPageLimit`/`otxMaxPages` all stay as-is.

- [ ] **Step 1: Write the failing tests (full replacement of `otx_test.go`)**

Replace the entire contents of `orchestrator/internal/connector/otx_test.go`:

```go
package connector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/reporting/attackdata"
)

// TestOTXSource_Stats_CountsSubscribedPulses is a basic single-page smoke
// test: verifies the request path/header and that a pulse with no adversary
// contributes to RawCount but not ActorCount. RawCount here means "pulses
// fetched this sync" (bounded by pagination), not the account's total
// subscribed-pulse count.
func TestOTXSource_Stats_CountsSubscribedPulses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pulses/subscribed" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
		if got := r.Header.Get("X-OTX-API-KEY"); got != "test-key" {
			t.Fatalf("X-OTX-API-KEY header = %q, want test-key", got)
		}
		json.NewEncoder(w).Encode(otxPulsesResponse{
			Count:   47,
			Results: []otxPulse{{Name: "some pulse", Modified: "2026-01-15T00:00:00Z"}},
		})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	signals, err := c.FetchActivity()
	if err != nil {
		t.Fatalf("FetchActivity: %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("signals = %+v, want none (pulse has no adversary)", signals)
	}

	stat := c.Stats()
	if stat.Name != "otx" || stat.RawCount != 1 || stat.ActorCount != 0 || stat.Error != "" {
		t.Fatalf("Stats() = %+v, want Name=otx RawCount=1 ActorCount=0 Error=\"\"", stat)
	}
	if stat.FetchedAt.IsZero() {
		t.Fatal("Stats().FetchedAt should be set after a successful FetchActivity")
	}
}

func TestOTXSource_Stats_RecordsErrorOnFailedFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	if _, err := c.FetchActivity(); err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	stat := c.Stats()
	if stat.Name != "otx" || stat.Error == "" {
		t.Fatalf("Stats() = %+v, want Name=otx with Error set", stat)
	}
}

// TestOTXSource_FetchActivity_MatchesKnownGroup uses "Wizard Spider" -- an
// established, real MITRE group name already relied on elsewhere in this
// codebase as a stable test fixture (see attackdata_test.go and
// ti_suggest_pack_test.go). The adversary field is deliberately
// lowercase-with-padding to exercise normalization; the signal's ActorName
// must come back in the index's canonical casing.
func TestOTXSource_FetchActivity_MatchesKnownGroup(t *testing.T) {
	if len(attackdata.GroupTechniqueIndex()["Wizard Spider"]) == 0 {
		t.Fatal("test fixture assumption broken: \"Wizard Spider\" not found in GroupTechniqueIndex()")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(otxPulsesResponse{
			Count: 1,
			Results: []otxPulse{
				{Name: "pulse one", Adversary: "  wizard spider  ", Modified: "2026-01-15T00:00:00Z"},
			},
		})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	signals, err := c.FetchActivity()
	if err != nil {
		t.Fatalf("FetchActivity: %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("signals = %+v, want 1", signals)
	}
	sig := signals[0]
	if sig.ActorName != "Wizard Spider" {
		t.Fatalf("ActorName = %q, want \"Wizard Spider\"", sig.ActorName)
	}
	if sig.PulseCount != 1 {
		t.Fatalf("PulseCount = %d, want 1", sig.PulseCount)
	}
	wantTime := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	if !sig.FirstObserved.Equal(wantTime) || !sig.LastObserved.Equal(wantTime) {
		t.Fatalf("FirstObserved=%v LastObserved=%v, want both %v (single pulse)", sig.FirstObserved, sig.LastObserved, wantTime)
	}
}

// TestOTXSource_FetchActivity_AccumulatesPulseCountAndSpread is new
// behavior this rewrite introduces: today's Fetch() only ever tracked the
// latest Modified date per matched actor. FetchActivity must now count
// every matching pulse and track both the earliest and latest Modified
// date seen this sync.
func TestOTXSource_FetchActivity_AccumulatesPulseCountAndSpread(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(otxPulsesResponse{
			Count: 3,
			Results: []otxPulse{
				{Name: "pulse one", Adversary: "Wizard Spider", Modified: "2026-01-10T00:00:00Z"},
				{Name: "pulse two", Adversary: "Wizard Spider", Modified: "2026-01-20T00:00:00Z"},
				{Name: "pulse three", Adversary: "Wizard Spider", Modified: "2026-01-15T00:00:00Z"},
			},
		})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	signals, err := c.FetchActivity()
	if err != nil {
		t.Fatalf("FetchActivity: %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("signals = %+v, want 1 (all three pulses match the same actor)", signals)
	}
	sig := signals[0]
	if sig.PulseCount != 3 {
		t.Fatalf("PulseCount = %d, want 3", sig.PulseCount)
	}
	wantFirst := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	wantLast := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	if !sig.FirstObserved.Equal(wantFirst) {
		t.Errorf("FirstObserved = %v, want %v (the earliest of the three)", sig.FirstObserved, wantFirst)
	}
	if !sig.LastObserved.Equal(wantLast) {
		t.Errorf("LastObserved = %v, want %v (the latest of the three)", sig.LastObserved, wantLast)
	}
}

func TestOTXSource_FetchActivity_SkipsUnmatchedAdversary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(otxPulsesResponse{
			Count: 1,
			Results: []otxPulse{
				{Name: "pulse one", Adversary: "Some Made Up Actor Name Zzyzx", Modified: "2026-01-15T00:00:00Z"},
			},
		})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	signals, err := c.FetchActivity()
	if err != nil {
		t.Fatalf("FetchActivity: %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("signals = %+v, want none (adversary name doesn't match any MITRE group)", signals)
	}
}

func TestOTXSource_FetchActivity_SkipsEmptyAdversary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(otxPulsesResponse{
			Count:   1,
			Results: []otxPulse{{Name: "pulse one", Adversary: "", Modified: "2026-01-15T00:00:00Z"}},
		})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	signals, err := c.FetchActivity()
	if err != nil {
		t.Fatalf("FetchActivity: %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("signals = %+v, want none (empty adversary)", signals)
	}
}

func TestOTXSource_FetchActivity_PaginatesUpToCap(t *testing.T) {
	var requestedPages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPages = append(requestedPages, r.URL.Query().Get("page"))
		results := make([]otxPulse, 50)
		for i := range results {
			results[i] = otxPulse{Name: fmt.Sprintf("pulse %d", i), Modified: "2026-01-15T00:00:00Z"}
		}
		json.NewEncoder(w).Encode(otxPulsesResponse{Count: 550, Results: results})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	if _, err := c.FetchActivity(); err != nil {
		t.Fatalf("FetchActivity: %v", err)
	}
	if len(requestedPages) != 10 {
		t.Fatalf("requested %d pages, want 10 (capped)", len(requestedPages))
	}
	if c.Stats().RawCount != 500 {
		t.Fatalf("RawCount = %d, want 500", c.Stats().RawCount)
	}
}

func TestOTXSource_FetchActivity_StopsOnShortPage(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		results := make([]otxPulse, 30)
		for i := range results {
			results[i] = otxPulse{Name: fmt.Sprintf("pulse %d", i), Modified: "2026-01-15T00:00:00Z"}
		}
		json.NewEncoder(w).Encode(otxPulsesResponse{Count: 30, Results: results})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	if _, err := c.FetchActivity(); err != nil {
		t.Fatalf("FetchActivity: %v", err)
	}
	if requestCount != 1 {
		t.Fatalf("requested %d pages, want 1 (short page ends pagination)", requestCount)
	}
	if c.Stats().RawCount != 30 {
		t.Fatalf("RawCount = %d, want 30", c.Stats().RawCount)
	}
}

func TestOTXSource_FetchActivity_PartialFailureReturnsSignalsGatheredSoFar(t *testing.T) {
	var page int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			results := make([]otxPulse, 50)
			results[0] = otxPulse{Name: "pulse one", Adversary: "Wizard Spider", Modified: "2026-01-15T00:00:00Z"}
			for i := 1; i < 50; i++ {
				results[i] = otxPulse{Name: fmt.Sprintf("pulse %d", i), Modified: "2026-01-15T00:00:00Z"}
			}
			json.NewEncoder(w).Encode(otxPulsesResponse{Count: 100, Results: results})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	signals, err := c.FetchActivity()
	if err == nil {
		t.Fatal("expected error from page 2 failure")
	}
	if len(signals) != 1 || signals[0].ActorName != "Wizard Spider" {
		t.Fatalf("signals = %+v, want 1 signal (Wizard Spider, from page 1)", signals)
	}
	if c.Stats().Error == "" {
		t.Fatal("Stats().Error should be set")
	}
	if c.Stats().RawCount != 50 {
		t.Fatalf("RawCount = %d, want 50 (only page 1 succeeded)", c.Stats().RawCount)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/connector/... -run TestOTXSource -v`
Expected: FAIL to compile — `c.FetchActivity undefined (type *OTXSource has no field or method FetchActivity)`.

- [ ] **Step 3: Add `ActivitySource`/`ActivitySignal` to `source.go`**

In `orchestrator/internal/connector/source.go`, append below the existing `IntelligenceSource` interface:

```go

// ActivitySource performs a periodic sync producing activity evidence
// about already-known/identifiable actors -- e.g. "this MITRE group was
// mentioned in N currently-subscribed pulses" -- never curated attribution.
// Deliberately a separate interface from Source: an ActivitySource's data
// doesn't belong in threat_actor_profiles/threat_actor_sources' curated
// fields (Confidence, Sectors, Regions, LastSeen), only in its own
// threat_actor_activity table. See
// docs/superpowers/specs/2026-08-12-otx-activity-signal-design.md.
type ActivitySource interface {
	Name() string
	FetchActivity() ([]ActivitySignal, error)
}

// ActivitySignal is one actor's activity evidence gathered in a single
// sync -- PulseCount/FirstObserved/LastObserved all describe pulses
// examined THIS sync (a snapshot, not a cross-sync cumulative count; no
// pulse carries a stable ID to dedupe against across syncs).
type ActivitySignal struct {
	ActorName     string
	PulseCount    int
	FirstObserved time.Time
	LastObserved  time.Time
}
```

This requires adding `"time"` to `source.go`'s import block:

```go
package connector

import (
	"time"

	"github.com/audspect/bas/internal/intelligence"
)
```

- [ ] **Step 4: Rewrite `OTXSource.Fetch()` as `FetchActivity()` in `otx.go`**

In `orchestrator/internal/connector/otx.go`, replace the doc comment above the struct (lines 13-25) with:

```go
// OTXSource performs a periodic sync against AlienVault OTX, reporting
// pulse-mention activity evidence -- never curated actor attribution. Each
// subscribed pulse's adversary field is matched against
// attackdata.GroupTechniqueIndex()'s MITRE-authoritative group names; on a
// match, the pulse contributes to that actor's ActivitySignal (a count and
// an observed date range), never a ThreatActor. See
// docs/superpowers/specs/2026-08-12-otx-activity-signal-design.md, which
// supersedes docs/superpowers/specs/2026-07-22-otx-technique-mapping-design.md
// for everything concerning what Fetch (now FetchActivity) returns.
//
// This is a distinct client from internal/ioc/otx.go's otxProvider, which
// performs synchronous on-demand single-indicator lookups (IP/domain/hash/
// CVE) for LookupIOC -- a different concern from this package's periodic
// sync, matching this codebase's existing package split between
// internal/ioc and internal/connector.
```

Replace `Fetch() ([]ThreatActor, error)` (the whole function body, lines 73-137) with:

```go
// otxActivityAccumulator tracks one actor's pulse count and observed date
// range while paging through subscribed pulses this sync.
type otxActivityAccumulator struct {
	count       int
	first, last time.Time
}

// FetchActivity pages through the account's subscribed pulses (capped at
// otxMaxPages x otxPageLimit) and builds one ActivitySignal per matched
// MITRE group, counting every matching pulse and tracking the earliest/
// latest Modified date seen this sync. A page-1 failure returns nil, err.
// A later-page failure returns whatever signals were gathered from the
// pages that did succeed, alongside the error.
func (c *OTXSource) FetchActivity() ([]ActivitySignal, error) {
	groupTechs := attackdata.GroupTechniqueIndex()
	normalizedGroups := make(map[string]string, len(groupTechs))
	for name := range groupTechs {
		normalizedGroups[normalizeAdversary(name)] = name
	}

	accByActor := make(map[string]*otxActivityAccumulator)
	var totalFetched int

	for page := 1; page <= otxMaxPages; page++ {
		pulses, err := c.fetchPulsesPage(page)
		if err != nil {
			if page == 1 {
				c.lastStat = SourceStat{Name: "otx", Error: err.Error(), FetchedAt: time.Now()}
				return nil, fmt.Errorf("otx fetch page 1: %w", err)
			}
			out := otxSignalsFromMap(accByActor)
			c.lastStat = SourceStat{Name: "otx", RawCount: totalFetched, ActorCount: len(out), Error: err.Error(), FetchedAt: time.Now()}
			return out, fmt.Errorf("otx fetch page %d: %w", page, err)
		}

		totalFetched += len(pulses)
		for _, p := range pulses {
			if strings.TrimSpace(p.Adversary) == "" {
				continue
			}
			groupName, ok := normalizedGroups[normalizeAdversary(p.Adversary)]
			if !ok {
				continue
			}
			modified, parseErr := time.Parse(time.RFC3339, p.Modified)
			if parseErr != nil {
				continue // can't order an unparseable timestamp -- skip counting this pulse
			}

			acc, ok := accByActor[groupName]
			if !ok {
				acc = &otxActivityAccumulator{first: modified, last: modified}
				accByActor[groupName] = acc
			}
			acc.count++
			if modified.Before(acc.first) {
				acc.first = modified
			}
			if modified.After(acc.last) {
				acc.last = modified
			}
		}

		if len(pulses) < otxPageLimit {
			break
		}
	}

	out := otxSignalsFromMap(accByActor)
	c.lastStat = SourceStat{Name: "otx", RawCount: totalFetched, ActorCount: len(out), FetchedAt: time.Now()}
	return out, nil
}
```

Replace `otxActorsFromMap` with:

```go
func otxSignalsFromMap(m map[string]*otxActivityAccumulator) []ActivitySignal {
	out := make([]ActivitySignal, 0, len(m))
	for name, acc := range m {
		out = append(out, ActivitySignal{
			ActorName: name, PulseCount: acc.count,
			FirstObserved: acc.first, LastObserved: acc.last,
		})
	}
	return out
}
```

`normalizeAdversary`, `fetchPulsesPage`, `otxPulse`/`otxPulsesResponse`, `Name()`, `Stats()`, `NewOTXSource`, `otxAPIBaseURL`/`otxPageLimit`/`otxMaxPages`, and the `OTXSource` struct itself are all unchanged.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./internal/connector/... && go test ./internal/connector/... -run TestOTXSource -v`
Expected: `go build` succeeds. All 9 tests PASS.

- [ ] **Step 6: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/connector/source.go orchestrator/internal/connector/otx.go orchestrator/internal/connector/otx_test.go
git commit -m "feat(connector): OTX reports activity signals instead of curated actors"
git push
```

---

### Task 2: `threat_actor_activity` table + `Scheduler` wiring

**Files:**
- Modify: `orchestrator/internal/db/content_schema.go` (append to `stmts`, after the `threat_actor_sources` table)
- Modify: `orchestrator/internal/connector/types.go` (add `OTXEnabled` to `ConnectorStatus`)
- Modify: `orchestrator/internal/connector/scheduler.go` (`activitySources` field, `WithActivitySources`/`ReconfigureActivitySources`, `resolveActivitySignalActor`, `upsertActivitySignals`, `sync()` wiring)
- Modify: `orchestrator/internal/connector/seed.go` (drop the `"otx"` case from `LoadSourcesFromDB`; add `LoadActivitySourcesFromDB`)
- Modify: `orchestrator/cmd/server/main.go` (wire `LoadActivitySourcesFromDB` + `.WithActivitySources(...)`)
- Modify: `orchestrator/internal/api/threat_intel_config_handlers.go` (wire `LoadActivitySourcesFromDB` + `.ReconfigureActivitySources(...)` alongside the existing `Reconfigure` call)
- Test: `orchestrator/internal/connector/scheduler_test.go` (append only)

**Interfaces:**
- Consumes: `ActivitySource`/`ActivitySignal` (Task 1), `actorKey(name string) string` (`internal/connector/actor_merge.go`, unmodified, reused not reimplemented).
- Produces: `func (s *Scheduler) WithActivitySources(sources []ActivitySource) *Scheduler`, `func (s *Scheduler) ReconfigureActivitySources(sources []ActivitySource)`, `func LoadActivitySourcesFromDB(ctx context.Context, pool *pgxpool.Pool) ([]ActivitySource, error)`, the `threat_actor_activity` table (read by Task 3).

**Why builder methods instead of constructor/`Reconfigure` parameters:** `NewScheduler(...)` has 13 existing call sites and `Reconfigure(...)` has 4 (test files plus `cmd/server/main.go` and `internal/api/threat_intel_config_handlers.go`). This codebase already has a `With*`-builder convention for optional wiring (`Handler.WithThreatPriority`, `Handler.WithJobsDispatcher` in `internal/api/handlers.go`). Following it here means zero existing test files change for a signature they don't care about, and only the 2 production call sites that actually need OTX wiring are touched.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/connector/scheduler_test.go`:

```go

type fakeActivitySource struct {
	name    string
	signals []ActivitySignal
	err     error
}

func (f fakeActivitySource) Name() string                       { return f.name }
func (f fakeActivitySource) FetchActivity() ([]ActivitySignal, error) { return f.signals, f.err }

// TestUpsertActivitySignals_MatchesExistingActor_LeavesCuratedFieldsUntouched
// is the core regression guard for the bug this whole sub-project exists to
// fix: an activity signal for an actor that already has curated
// intelligence must NOT touch that actor's Confidence or LastSeen.
func TestUpsertActivitySignals_MatchesExistingActor_LeavesCuratedFieldsUntouched(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		curatedSeen := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		s.upsertActorProfiles([]ThreatActor{{
			Name: "ACT-Wizard Spider", Confidence: "high", LastSeen: curatedSeen,
			Aliases: []string{}, Sectors: []string{}, Regions: []string{},
		}})

		first := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
		last := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
		s.upsertActivitySignals("otx", []ActivitySignal{
			{ActorName: "ACT-Wizard Spider", PulseCount: 3, FirstObserved: first, LastObserved: last},
		}, []ThreatActor{{Name: "ACT-Wizard Spider"}})

		var confidence string
		var lastSeen time.Time
		if err := pool.QueryRow(t.Context(),
			`SELECT confidence, last_seen FROM threat_actor_profiles WHERE name = $1`, "ACT-Wizard Spider",
		).Scan(&confidence, &lastSeen); err != nil {
			t.Fatalf("query profile: %v", err)
		}
		if confidence != "high" || !lastSeen.Equal(curatedSeen) {
			t.Fatalf("profile confidence/lastSeen = %q/%v, want untouched (high/%v)", confidence, lastSeen, curatedSeen)
		}

		var pulseCount int
		var gotFirst, gotLast time.Time
		if err := pool.QueryRow(t.Context(),
			`SELECT pulse_count, first_observed, last_observed FROM threat_actor_activity WHERE actor_name = $1 AND source = 'otx'`,
			"ACT-Wizard Spider",
		).Scan(&pulseCount, &gotFirst, &gotLast); err != nil {
			t.Fatalf("query activity: %v", err)
		}
		if pulseCount != 3 || !gotFirst.Equal(first) || !gotLast.Equal(last) {
			t.Fatalf("activity row = pulseCount=%d first=%v last=%v, want 3/%v/%v", pulseCount, gotFirst, gotLast, first, last)
		}
	})
}

// TestUpsertActivitySignals_NoMatch_CreatesMinimalStub covers the
// user-approved orphan path: a MITRE-named actor no curated source has
// ever reported gets a bare threat_actor_profiles row so its activity has
// somewhere to attach.
func TestUpsertActivitySignals_NoMatch_CreatesMinimalStub(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		ts := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
		s.upsertActivitySignals("otx", []ActivitySignal{
			{ActorName: "ACT-Orphan Group", PulseCount: 1, FirstObserved: ts, LastObserved: ts},
		}, nil) // no curated actors at all

		var confidence string
		var lastSeen *time.Time
		if err := pool.QueryRow(t.Context(),
			`SELECT confidence, last_seen FROM threat_actor_profiles WHERE name = $1`, "ACT-Orphan Group",
		).Scan(&confidence, &lastSeen); err != nil {
			t.Fatalf("expected a minimal stub profile row: %v", err)
		}
		if confidence != "" || lastSeen != nil {
			t.Fatalf("stub confidence/lastSeen = %q/%v, want empty/nil (nothing curated ever said this)", confidence, lastSeen)
		}

		var pulseCount int
		if err := pool.QueryRow(t.Context(),
			`SELECT pulse_count FROM threat_actor_activity WHERE actor_name = $1 AND source = 'otx'`, "ACT-Orphan Group",
		).Scan(&pulseCount); err != nil {
			t.Fatalf("expected an activity row attached to the stub: %v", err)
		}
		if pulseCount != 1 {
			t.Fatalf("pulseCount = %d, want 1", pulseCount)
		}
	})
}

// TestUpsertActivitySignals_LeastGreatestAcrossTwoSyncs proves
// first_observed/last_observed never regress due to OTX subscription
// churn -- a pulse rolling off the feed must not make an actor's earliest
// or latest recorded activity look narrower than it really is.
func TestUpsertActivitySignals_LeastGreatestAcrossTwoSyncs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		s.upsertActorProfiles([]ThreatActor{{
			Name: "ACT-Churn Actor", Aliases: []string{}, Sectors: []string{}, Regions: []string{},
		}})
		merged := []ThreatActor{{Name: "ACT-Churn Actor"}}

		aug10 := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
		s.upsertActivitySignals("otx", []ActivitySignal{
			{ActorName: "ACT-Churn Actor", PulseCount: 1, FirstObserved: aug10, LastObserved: aug10},
		}, merged)

		aug5 := time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)
		aug15 := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
		s.upsertActivitySignals("otx", []ActivitySignal{
			{ActorName: "ACT-Churn Actor", PulseCount: 2, FirstObserved: aug5, LastObserved: aug15},
		}, merged)

		var pulseCount int
		var gotFirst, gotLast time.Time
		if err := pool.QueryRow(t.Context(),
			`SELECT pulse_count, first_observed, last_observed FROM threat_actor_activity WHERE actor_name = $1 AND source = 'otx'`,
			"ACT-Churn Actor",
		).Scan(&pulseCount, &gotFirst, &gotLast); err != nil {
			t.Fatalf("query: %v", err)
		}
		if pulseCount != 2 {
			t.Errorf("pulseCount = %d, want 2 (plain overwrite, a snapshot of the latest sync)", pulseCount)
		}
		if !gotFirst.Equal(aug5) {
			t.Errorf("first_observed = %v, want %v (LEAST of aug10 and aug5)", gotFirst, aug5)
		}
		if !gotLast.Equal(aug15) {
			t.Errorf("last_observed = %v, want %v (GREATEST of aug10 and aug15)", gotLast, aug15)
		}
	})
}

// TestScheduler_Sync_ProcessesActivitySignalsEvenWithZeroCuratedActors
// proves an OTX-only deployment (no MISP/OpenCTI/Bundle configured, or all
// three returned nothing this sync) still gets its activity signals
// processed -- the pre-existing "no actors returned from any source" early
// return must not swallow activity-only syncs.
func TestScheduler_Sync_ProcessesActivitySignalsEvenWithZeroCuratedActors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := NewScheduler(nil, NewGenerator(t.TempDir(), nil, nil, nil), scenario.NewEngine(t.TempDir()), 24, pool, nil)
		ts := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
		s.WithActivitySources([]ActivitySource{fakeActivitySource{
			name: "otx",
			signals: []ActivitySignal{
				{ActorName: "SYNC-ACT-ONLY", PulseCount: 5, FirstObserved: ts, LastObserved: ts},
			},
		}})

		s.sync()

		var pulseCount int
		if err := pool.QueryRow(t.Context(),
			`SELECT pulse_count FROM threat_actor_activity WHERE actor_name = $1 AND source = 'otx'`, "SYNC-ACT-ONLY",
		).Scan(&pulseCount); err != nil {
			t.Fatalf("expected an activity row even with zero curated sources: %v", err)
		}
		if pulseCount != 5 {
			t.Fatalf("pulseCount = %d, want 5", pulseCount)
		}
	})
}

func TestWithActivitySources_SetsOTXEnabledStatus(t *testing.T) {
	s := NewScheduler(nil, nil, nil, 24, nil, nil)
	s.WithActivitySources([]ActivitySource{fakeActivitySource{name: "otx"}})
	if !s.Status().OTXEnabled {
		t.Error("OTXEnabled should be true after WithActivitySources with an otx source")
	}
}

func TestReconfigureActivitySources_UpdatesOTXEnabledStatus(t *testing.T) {
	s := NewScheduler(nil, nil, nil, 24, nil, nil)
	s.WithActivitySources([]ActivitySource{fakeActivitySource{name: "otx"}})
	s.ReconfigureActivitySources(nil)
	if s.Status().OTXEnabled {
		t.Error("OTXEnabled should be false after reconfiguring OTX out")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/connector/... -run 'TestUpsertActivitySignals|TestScheduler_Sync_ProcessesActivitySignals|TestWithActivitySources|TestReconfigureActivitySources' -v`
Expected: FAIL to compile — `s.upsertActivitySignals undefined`, `s.WithActivitySources undefined`, `s.ReconfigureActivitySources undefined`.

- [ ] **Step 3: Add the table**

In `orchestrator/internal/db/content_schema.go`, append to the `stmts` slice immediately after the `threat_actor_sources` table (the last entry before the closing `}`):

```go

		// threat_actor_activity: one row per (actor, activity source) --
		// pulse-mention evidence (OTX today), deliberately separate from
		// threat_actor_sources' curated intelligence. first_observed/
		// last_observed use LEAST/GREATEST on upsert so subscription churn
		// (a pulse rolling off OTX's feed) never narrows the recorded range.
		// pulse_count is a plain overwrite -- a snapshot of the latest
		// sync, not a cross-sync cumulative count. See
		// docs/superpowers/specs/2026-08-12-otx-activity-signal-design.md.
		`CREATE TABLE IF NOT EXISTS threat_actor_activity (
			actor_name     text        NOT NULL REFERENCES threat_actor_profiles(name) ON DELETE CASCADE,
			source         text        NOT NULL,
			pulse_count    int         NOT NULL DEFAULT 0,
			first_observed timestamptz,
			last_observed  timestamptz,
			updated_at     timestamptz NOT NULL DEFAULT NOW(),
			PRIMARY KEY (actor_name, source)
		)`,
```

- [ ] **Step 4: Add `OTXEnabled` to `ConnectorStatus`**

In `orchestrator/internal/connector/types.go`, add a field to `ConnectorStatus` (after `BundleEnabled`):

```go
type ConnectorStatus struct {
	MISPEnabled      bool                  `json:"mispEnabled"`
	OpenCTIEnabled   bool                  `json:"openctiEnabled"`
	BundleEnabled    bool                  `json:"bundleEnabled"`
	// OTXEnabled reflects Scheduler.activitySources, set by
	// WithActivitySources/ReconfigureActivitySources -- tracked separately
	// from the other three because OTX is not in the sources/Reconfigure
	// list at all (it's an ActivitySource, not a Source). Previously this
	// field didn't exist, so the frontend's `s.otxEnabled` check
	// (index.html:15196) always read undefined/false regardless of actual
	// OTX config -- fixed as a direct consequence of restructuring OTX's
	// wiring here.
	OTXEnabled       bool                  `json:"otxEnabled"`
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

- [ ] **Step 5: Add `activitySources` field, builder methods, and the resolve/upsert functions to `scheduler.go`**

Add `activitySources []ActivitySource` to the `Scheduler` struct (after `sources []Source`):

```go
type Scheduler struct {
	sources         []Source
	activitySources []ActivitySource // OTX today -- see WithActivitySources
	generator       *Generator
	...
```

Add, immediately after `Reconfigure`'s closing brace:

```go

// WithActivitySources attaches activity-evidence sources (currently just
// OTX) -- kept structurally separate from sources/Reconfigure because
// ActivitySource is a different interface (FetchActivity, not Fetch): it
// contributes activity evidence about already-known actors, never curated
// attribution. Safe to call once after NewScheduler, before Start. Chainable.
func (s *Scheduler) WithActivitySources(sources []ActivitySource) *Scheduler {
	s.mu.Lock()
	s.activitySources = sources
	s.status.OTXEnabled = false
	for _, src := range sources {
		if src.Name() == "otx" {
			s.status.OTXEnabled = true
		}
	}
	s.mu.Unlock()
	return s
}

// ReconfigureActivitySources live-updates the activity-source list,
// mirroring Reconfigure's live-update semantics for curated sources but
// kept as a separate method since ActivitySource is a distinct interface.
// Does not itself trigger a sync -- callers that want one call TriggerSync
// explicitly, same as internal/api/threat_intel_config_handlers.go already
// does after Reconfigure.
func (s *Scheduler) ReconfigureActivitySources(sources []ActivitySource) {
	s.mu.Lock()
	s.activitySources = sources
	s.status.OTXEnabled = false
	for _, src := range sources {
		if src.Name() == "otx" {
			s.status.OTXEnabled = true
		}
	}
	s.mu.Unlock()
}
```

Add, immediately after `upsertActivitySignals`'s home -- right after `upsertActorSources`'s closing brace in the file (the function this task adds directly below it):

```go

// resolveActivitySignalActor looks up an activity signal's actor name
// against the already-merged curated roster, reusing actorKey's exact-match
// normalization (actor_merge.go) -- no fuzzy/similarity matching,
// consistent with MergeActors' own matching discipline. Returns the merged
// actor's own Name (its canonical casing) on a match.
func resolveActivitySignalActor(signalName string, merged []ThreatActor) (string, bool) {
	key := actorKey(signalName)
	for _, m := range merged {
		if actorKey(m.Name) == key {
			return m.Name, true
		}
		for _, alias := range m.Aliases {
			if actorKey(alias) == key {
				return m.Name, true
			}
		}
	}
	return "", false
}

// upsertActivitySignals resolves each signal against the merged curated
// roster and persists to threat_actor_activity. A signal matching nothing
// curated gets a minimal threat_actor_profiles stub (bare name; every
// other column keeps the table's own default -- '' confidence, NULL
// last_seen) so the activity has somewhere to attach.
// internal/reporting/insights.go's ResolveActorTechniques independently
// re-derives the actor's MITRE technique list from its Name at scoring
// time, so the stub needs nothing else. A single signal failing is logged
// and skipped, never aborting the rest -- same discipline
// upsertActorProfiles/upsertActorSources already apply. No-op when pool is
// nil.
func (s *Scheduler) upsertActivitySignals(source string, signals []ActivitySignal, merged []ThreatActor) {
	if s.pool == nil {
		return
	}
	ctx := context.Background()
	for _, sig := range signals {
		actorName, found := resolveActivitySignalActor(sig.ActorName, merged)
		if !found {
			actorName = sig.ActorName
			if _, err := s.pool.Exec(ctx,
				`INSERT INTO threat_actor_profiles (name, updated_at) VALUES ($1, NOW())
				 ON CONFLICT (name) DO NOTHING`,
				actorName); err != nil {
				log.Printf("[connector] create activity stub profile %q: %v", actorName, err)
				continue
			}
		}
		_, err := s.pool.Exec(ctx,
			`INSERT INTO threat_actor_activity (actor_name, source, pulse_count, first_observed, last_observed, updated_at)
			 VALUES ($1,$2,$3,$4,$5,NOW())
			 ON CONFLICT (actor_name, source) DO UPDATE SET
			   pulse_count = EXCLUDED.pulse_count,
			   first_observed = LEAST(threat_actor_activity.first_observed, EXCLUDED.first_observed),
			   last_observed = GREATEST(threat_actor_activity.last_observed, EXCLUDED.last_observed),
			   updated_at = NOW()`,
			actorName, source, sig.PulseCount, sig.FirstObserved, sig.LastObserved)
		if err != nil {
			log.Printf("[connector] upsert activity signal %q/%q: %v", actorName, source, err)
		}
	}
}
```

- [ ] **Step 6: Wire the activity pass into `sync()`**

In `orchestrator/internal/connector/scheduler.go`'s `sync()`, replace:

```go
	s.mu.RLock()
	sources := s.sources
	s.mu.RUnlock()
	for _, src := range sources {
```

with:

```go
	s.mu.RLock()
	sources := s.sources
	activitySources := s.activitySources
	s.mu.RUnlock()
	for _, src := range sources {
```

Then replace:

```go
	if len(actors) == 0 {
		log.Println("[connector] no actors returned from any source")
		s.setOK(0, 0, 0, bundleVersion, bySource)
		return
	}

	// Merge actors with the same name across sources — bundle floor + live
	// overlay compose here, since MergeActors unions their techniques.
	// rawActors keeps the pre-merge list alive: the merged result
	// deliberately flattens away each source's own assertions, which
	// upsertActorSources below persists separately.
	rawActors := actors
	merged, groups := MergeActorsWithProvenance(rawActors)
	actors = merged

	// Persist actor profiles (sectors/regions) for reporting's priority-score
	// weighting — see docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	s.upsertActorProfiles(actors)
	// Per-source provenance. MUST run after upsertActorProfiles -- these rows
	// carry a foreign key to threat_actor_profiles(name).
	s.upsertActorSources(rawActors, actors, groups)
```

with:

```go
	// Fetch activity sources (OTX) independently of curated sources' outcome
	// -- a signal must still be processed, and can still create an orphan
	// stub, even when zero curated sources returned anything (e.g. an
	// OTX-only deployment). See
	// docs/superpowers/specs/2026-08-12-otx-activity-signal-design.md.
	type activityFetch struct {
		source  string
		signals []ActivitySignal
	}
	var activityResults []activityFetch
	for _, asrc := range activitySources {
		signals, err := asrc.FetchActivity()
		if ss, ok := asrc.(StatsSource); ok {
			bySource[asrc.Name()] = ss.Stats()
		}
		if err != nil {
			log.Printf("[connector/%s] fetch error: %v", asrc.Name(), err)
			continue
		}
		log.Printf("[connector/%s] %d activity signals fetched", asrc.Name(), len(signals))
		activityResults = append(activityResults, activityFetch{source: asrc.Name(), signals: signals})
	}

	if len(actors) == 0 && len(activityResults) == 0 {
		log.Println("[connector] no actors returned from any source")
		s.setOK(0, 0, 0, bundleVersion, bySource)
		return
	}

	// Merge actors with the same name across sources — bundle floor + live
	// overlay compose here, since MergeActors unions their techniques.
	// rawActors keeps the pre-merge list alive: the merged result
	// deliberately flattens away each source's own assertions, which
	// upsertActorSources below persists separately.
	rawActors := actors
	merged, groups := MergeActorsWithProvenance(rawActors)
	actors = merged

	// Persist actor profiles (sectors/regions) for reporting's priority-score
	// weighting — see docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	s.upsertActorProfiles(actors)
	// Per-source provenance. MUST run after upsertActorProfiles -- these rows
	// carry a foreign key to threat_actor_profiles(name).
	s.upsertActorSources(rawActors, actors, groups)
	// Activity evidence -- resolved against the now-merged curated roster,
	// or given a minimal stub if nothing curated matches. MUST also run
	// after upsertActorProfiles for the same FK reason.
	for _, r := range activityResults {
		s.upsertActivitySignals(r.source, r.signals, actors)
	}
```

`MergeActorsWithProvenance(nil)` and `upsertActorProfiles(nil)`/`upsertActorSources(nil, nil, nil)` are all safe no-ops on empty input (covered by Task 1/2 of the source-provenance plan's own tests), so this is correct even when `actors` is empty and only activity signals exist. `s.generator.Write(actors)` further down is unconditional and already tolerates an empty/nil slice (confirmed: it just `MkdirAll`s and iterates zero times) -- no other change needed in the rest of `sync()`.

- [ ] **Step 7: Split `seed.go`**

In `orchestrator/internal/connector/seed.go`, remove the `case "otx":` branch from `LoadSourcesFromDB`'s switch (leaving only `"misp"`/`"opencti"`), and update its doc comment:

```go
// LoadSourcesFromDB builds the misp/opencti curated Sources from whatever
// is currently enabled in threat_intel_config. Called once at startup
// (after SeedFromEnv has had a chance to populate the table) and again,
// indirectly, every time a config save triggers Scheduler.Reconfigure --
// this is the one place that turns curated DB rows into live Source
// objects, so both callers stay in sync by construction. OTX is loaded
// separately by LoadActivitySourcesFromDB -- it's an ActivitySource, not a
// Source.
func LoadSourcesFromDB(ctx context.Context, pool *pgxpool.Pool, sectors, regions []string) ([]Source, error) {
	rows, err := pool.Query(ctx, `SELECT connector, base_url, api_key FROM threat_intel_config WHERE enabled = true`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []Source
	for rows.Next() {
		var conn, baseURL, apiKey string
		if err := rows.Scan(&conn, &baseURL, &apiKey); err != nil {
			return nil, err
		}
		switch conn {
		case "misp":
			if baseURL != "" && apiKey != "" {
				sources = append(sources, NewMISPClient(baseURL, apiKey, sectors, regions))
			}
		case "opencti":
			if baseURL != "" && apiKey != "" {
				sources = append(sources, NewOpenCTIClient(baseURL, apiKey, sectors))
			}
		}
	}
	return sources, rows.Err()
}

// LoadActivitySourcesFromDB builds the otx ActivitySource from whatever is
// currently enabled in threat_intel_config, mirroring LoadSourcesFromDB's
// pattern for the curated sources but querying only the otx row and
// returning the distinct ActivitySource type.
func LoadActivitySourcesFromDB(ctx context.Context, pool *pgxpool.Pool) ([]ActivitySource, error) {
	rows, err := pool.Query(ctx,
		`SELECT api_key FROM threat_intel_config WHERE enabled = true AND connector = 'otx'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []ActivitySource
	for rows.Next() {
		var apiKey string
		if err := rows.Scan(&apiKey); err != nil {
			return nil, err
		}
		if apiKey != "" {
			sources = append(sources, NewOTXSource(apiKey))
		}
	}
	return sources, rows.Err()
}
```

`SeedFromEnv` is unchanged.

- [ ] **Step 8: Wire production call sites**

In `orchestrator/cmd/server/main.go`, after the existing:

```go
	scheduler := connector.NewScheduler(tiSources, gen, engine, cfg.ThreatIntelPollHours, pool, priorityEngine)
```

add:

```go
	tiActivitySources, err := connector.LoadActivitySourcesFromDB(context.Background(), pool)
	if err != nil {
		log.Printf("[!] threat-intel activity source load warning: %v", err)
	}
	scheduler.WithActivitySources(tiActivitySources)
```

In `orchestrator/internal/api/threat_intel_config_handlers.go`, inside the existing `if h.scheduler != nil { sources, lerr := connector.LoadSourcesFromDB(...); if lerr == nil { h.scheduler.Reconfigure(sources); h.scheduler.TriggerSync() } else {...} }` block, add activity-source reloading alongside it:

```go
	if h.scheduler != nil {
		sources, lerr := connector.LoadSourcesFromDB(r.Context(), h.db, nil, nil)
		if lerr == nil {
			h.scheduler.Reconfigure(sources)
			h.scheduler.TriggerSync()
		} else {
			log.Printf("[api] threat-intel config: scheduler reload failed after save: %v", lerr)
		}
		if activitySources, aerr := connector.LoadActivitySourcesFromDB(r.Context(), h.db); aerr == nil {
			h.scheduler.ReconfigureActivitySources(activitySources)
		} else {
			log.Printf("[api] threat-intel config: activity source reload failed after save: %v", aerr)
		}
	}
```

(Re-read the exact surrounding lines in this file at execution time -- the `else` branch's existing log line was referenced but not fully re-quoted in this plan's research; preserve whatever it currently does and add the new activity-source block as a sibling, not a replacement.)

- [ ] **Step 9: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./internal/connector/... && go test ./internal/connector/... -run 'TestUpsertActivitySignals|TestScheduler_Sync|TestWithActivitySources|TestReconfigureActivitySources|TestReconfigure_' -v`
Expected: all new tests PASS, plus every pre-existing `TestScheduler_Sync*`/`TestReconfigure_*`/`TestUpsertActorProfiles_*` test still PASSes unmodified.

Then the whole package: `cd orchestrator && go build ./... && go test ./internal/connector/...`
Expected: `ok github.com/audspect/bas/internal/connector`.

Then confirm the rest of the module still builds (main.go / api handler changes): `cd orchestrator && go build ./... && go vet ./...`
Expected: no errors.

- [ ] **Step 10: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/db/content_schema.go orchestrator/internal/connector/types.go orchestrator/internal/connector/scheduler.go orchestrator/internal/connector/scheduler_test.go orchestrator/internal/connector/seed.go orchestrator/cmd/server/main.go orchestrator/internal/api/threat_intel_config_handlers.go
git commit -m "feat(connector): persist and wire OTX activity signals separately from curated actors"
git push
```

---

### Task 3: `ActivityFactor` scoring

**Files:**
- Modify: `orchestrator/internal/threatpriority/models.go` (add `ActivitySignal` type + `Context.Activity` field)
- Modify: `orchestrator/internal/threatpriority/engine.go` (add `loadActivity`, wire into `scoreActor`)
- Modify: `orchestrator/internal/threatpriority/standalone_factors.go` (add `ActivityFactor`)
- Modify: `orchestrator/internal/threatpriority/score.go` (add `activityWeight` constant)
- Modify: `orchestrator/internal/threatpriority/registry.go` (register the factor, update doc comment)
- Test: `orchestrator/internal/threatpriority/standalone_factors_test.go` (append only)

**Interfaces:**
- Consumes: the `threat_actor_activity` table (Task 2).
- Produces: `ActivityFactor{}` registered in `DefaultFactors()` -- its `FactorResult` (Name="OTX Activity") flows through `ActorPriority.Factors` automatically via the existing generic mechanism; no API or frontend change needed (see Self-Review Notes).

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/threatpriority/standalone_factors_test.go`:

```go

func TestActivityFactor_Recent(t *testing.T) {
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	last := now.Add(-3 * 24 * time.Hour)
	f := ActivityFactor{}
	raw, explanation, available, err := f.Score(context.Background(), Context{
		Now: now, Activity: &ActivitySignal{PulseCount: 4, LastObserved: &last},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available || raw != 100 {
		t.Fatalf("raw=%.2f available=%v, want 100/true", raw, available)
	}
	if explanation == "" {
		t.Fatal("expected a non-empty explanation")
	}
}

func TestActivityFactor_Stale(t *testing.T) {
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	last := now.Add(-20 * 24 * time.Hour)
	f := ActivityFactor{}
	raw, _, available, _ := f.Score(context.Background(), Context{
		Now: now, Activity: &ActivitySignal{PulseCount: 2, LastObserved: &last},
	})
	if !available || raw != 60 {
		t.Fatalf("raw=%.2f available=%v, want 60/true (8-29 day bucket)", raw, available)
	}
}

func TestActivityFactor_VeryStale(t *testing.T) {
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	last := now.Add(-90 * 24 * time.Hour)
	f := ActivityFactor{}
	raw, _, available, _ := f.Score(context.Background(), Context{
		Now: now, Activity: &ActivitySignal{PulseCount: 1, LastObserved: &last},
	})
	if !available || raw != 20 {
		t.Fatalf("raw=%.2f available=%v, want 20/true (30+ day bucket)", raw, available)
	}
}

func TestActivityFactor_NoActivity_Unavailable(t *testing.T) {
	f := ActivityFactor{}
	_, _, available, _ := f.Score(context.Background(), Context{Activity: nil})
	if available {
		t.Fatal("expected available=false with no Activity")
	}
}

func TestActivityFactor_WeightIsLowerThanCuratedStandaloneFactors(t *testing.T) {
	if ActivityFactor{}.Weight(Context{}) >= IntelFreshnessFactor{}.Weight(Context{}) {
		t.Fatal("ActivityFactor's weight must be lower than the curated standalone factors' -- activity evidence is a weaker signal than curated intelligence")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/threatpriority/... -run TestActivityFactor -v`
Expected: FAIL to compile — `undefined: ActivityFactor`, `Context{}.Activity undefined field`.

- [ ] **Step 3: Add `ActivitySignal` and `Context.Activity` to `models.go`**

In `orchestrator/internal/threatpriority/models.go`, add below `ActorProfile`:

```go

// ActivitySignal mirrors a threat_actor_activity row -- OTX pulse-mention
// evidence about an actor, distinct from ActorProfile's curated
// intelligence. A deliberately lightweight local type (not
// internal/connector.ActivitySignal, which is shaped for the fetch-time
// per-sync result, not the DB-read shape) -- same pattern ActorProfile
// already uses to mirror threat_actor_profiles without importing
// internal/connector.
type ActivitySignal struct {
	PulseCount    int
	FirstObserved *time.Time
	LastObserved  *time.Time
}
```

Add `Activity *ActivitySignal` to `Context`:

```go
type Context struct {
	ActorName      string
	TechniqueIDs   []string
	Profile        *ActorProfile
	Activity       *ActivitySignal
	Sectors        []string
	Regions        []string
	Now            time.Time
	ValidatedCount int

	shared *sharedIndexes
}
```

- [ ] **Step 4: Add `loadActivity` and wire it into `scoreActor` in `engine.go`**

Add, immediately after `loadProfile`'s closing brace:

```go

// loadActivity returns actorName's OTX activity record, or nil if none
// exists yet. Filters explicitly to source='otx' rather than an unfiltered
// LIMIT 1 -- today it's the only activity source, and an explicit filter
// fails loudly (returns nil) instead of silently picking an arbitrary row
// if a second activity source is ever added without updating this query.
func (e *Engine) loadActivity(ctx context.Context, name string) (*ActivitySignal, error) {
	if e.pool == nil {
		return nil, nil
	}
	row := e.pool.QueryRow(ctx,
		`SELECT pulse_count, first_observed, last_observed FROM threat_actor_activity WHERE actor_name=$1 AND source='otx'`, name)
	var a ActivitySignal
	if err := row.Scan(&a.PulseCount, &a.FirstObserved, &a.LastObserved); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}
```

In `scoreActor`, add the load call alongside the existing `validatedCount` computation, and thread it into `Context{...}`:

```go
func (e *Engine) scoreActor(ctx context.Context, profile *ActorProfile, shared *sharedIndexes) (ActorPriority, error) {
	techIDs, _, _ := reporting.ResolveActorTechniques(profile.Name, profile.Aliases)

	validatedCount := 0
	for _, id := range techIDs {
		upper := strings.ToUpper(id)
		if _, ok := shared.preventionVerdict[upper]; ok {
			validatedCount++
			continue
		}
		if _, ok := shared.validationVerdict[upper]; ok {
			validatedCount++
		}
	}

	activity, err := e.loadActivity(ctx, profile.Name)
	if err != nil {
		return ActorPriority{}, err
	}

	tctx := Context{
		ActorName: profile.Name, TechniqueIDs: techIDs, Profile: profile, Activity: activity,
		Sectors: e.sectors, Regions: e.regions, Now: time.Now().UTC(),
		ValidatedCount: validatedCount, shared: shared,
	}
	...
```

(Everything from `results := make([]FactorResult, ...)` onward in `scoreActor` is unchanged.)

- [ ] **Step 5: Add `activityWeight` to `score.go`**

In `orchestrator/internal/threatpriority/score.go`, add alongside `flatWeight`:

```go
const (
	// flatWeight is each curated standalone factor's (IntelFreshness,
	// Relevance, Confidence) fixed share of the composite.
	flatWeight = 0.05
	// activityWeight is ActivityFactor's fixed share -- half of
	// flatWeight, deliberately: OTX activity is a weaker, noisier signal
	// than curated intelligence, and giving it equal weight would recreate
	// exactly the "OTX pretends to be curated intel" mismatch this
	// sub-project exists to fix, just at the weighting layer instead of
	// the data layer. Composite() renormalizes proportionally across
	// whatever's Available for a given actor, so this can be tuned later
	// without a migration.
	activityWeight = 0.025
	// coverageValidationPool is what's left after the 3 curated standalone
	// factors (3 * 0.05 = 0.15): 1.0 - 0.15 = 0.85, split between Coverage
	// and Validation per blendWeights. ActivityFactor's extra 0.025 is not
	// subtracted here -- Composite() only cares about relative proportions
	// among whatever factors are Available for a given actor, so the
	// nominal weights not summing to exactly 1.0 causes no error.
	coverageValidationPool = 0.85
	numCoverageFactors     = 4.0
	numValidationFactors   = 2.0
)
```

- [ ] **Step 6: Add `ActivityFactor` to `standalone_factors.go`**

Append to `orchestrator/internal/threatpriority/standalone_factors.go`:

```go

// ActivityFactor scores OTX pulse-mention recency -- a weaker, noisier
// signal than curated intelligence (see activityWeight). Deliberately
// mirrors IntelFreshnessFactor's day-bucket shape with its own, tighter
// boundaries (<7d/<30d/older) -- pulse activity ages faster than a
// curated sighting.
type ActivityFactor struct{}

func (ActivityFactor) Name() string          { return "OTX Activity" }
func (ActivityFactor) Weight(Context) float64 { return activityWeight }
func (ActivityFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	if tctx.Activity == nil || tctx.Activity.LastObserved == nil {
		return 0, "No OTX activity recorded", false, nil
	}
	age := tctx.Now.Sub(*tctx.Activity.LastObserved)
	days := int(age.Hours() / 24)
	explanation := fmt.Sprintf("%d OTX pulses, most recently %d days ago", tctx.Activity.PulseCount, days)
	switch {
	case age < 7*24*time.Hour:
		return 100, explanation, true, nil
	case age < 30*24*time.Hour:
		return 60, explanation, true, nil
	default:
		return 20, explanation, true, nil
	}
}
```

- [ ] **Step 7: Register in `DefaultFactors()`**

In `orchestrator/internal/threatpriority/registry.go`:

```go
// DefaultFactors returns the 10 built-in factors in a stable order: 4
// Coverage, 2 Validation, 3 curated standalone, 1 activity. Order only
// affects the sequence of entries in ActorPriority.Factors, not scoring
// (each factor's Weight/Score is independent of the others).
func DefaultFactors() []ScoreFactor {
	return []ScoreFactor{
		SimulationCoverageFactor{},
		DetectionCoverageFactor{},
		PurpleCoverageFactor{},
		ComplianceCoverageFactor{},
		PreventionSuccessFactor{},
		ValidationSuccessFactor{},
		IntelFreshnessFactor{},
		RelevanceFactor{},
		ConfidenceFactor{},
		ActivityFactor{},
	}
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./internal/threatpriority/... && go test ./internal/threatpriority/... -v 2>&1 | tail -80`
Expected: all 5 new `TestActivityFactor_*` tests PASS, and every pre-existing test in the package still PASSes unmodified (in particular `TestDefaultFactors_*` if one exists that counts factors -- re-check at execution time and update its expected count from 9 to 10 if so, per this plan's "no test edits except appends" constraint being specifically about the source-provenance plan's `actor_merge_test.go`, not a global rule -- a factor-count assertion elsewhere in this package legitimately needs updating here since DefaultFactors() itself changed).

- [ ] **Step 9: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/threatpriority/models.go orchestrator/internal/threatpriority/engine.go orchestrator/internal/threatpriority/standalone_factors.go orchestrator/internal/threatpriority/standalone_factors_test.go orchestrator/internal/threatpriority/score.go orchestrator/internal/threatpriority/registry.go
git commit -m "feat(threatpriority): score OTX activity as its own, lower-weighted factor"
git push
```

---

## Self-Review Notes

- **Spec coverage:** `ActivitySource`/`ActivitySignal` + OTX leaving `Source` -- Task 1. `threat_actor_activity` table + `LEAST`/`GREATEST` upsert semantics + orphan-stub creation -- Task 2. Resolution against the merged roster reusing `actorKey` (zero changes to `actor_merge.go`) -- Task 2. `ActivityFactor` + `activityWeight` (deliberately half of `flatWeight`) -- Task 3. Every scope item in the spec's "In scope" list has a task; every "Explicitly out of scope" item (no `actor_merge.go` changes, no `IntelFreshnessFactor`/`ConfidenceFactor`/`RelevanceFactor` changes, no cumulative pulse counting, no `internal/ioc/otx.go` changes) is upheld throughout and called out inline where relevant.
- **A spec gap closed during planning, not skipped:** the spec's UI section assumed a dedicated new "Recent Activity" frontend element fed by a new API field, but code inspection during planning found `orchestrator/wwwroot/index.html:5461-5468`'s `renderThreatPriorityDetail` already renders `d.factors` generically (name/explanation/rawScore, `tp-detail-factors`) -- exactly what every other standalone factor (IntelFreshness, Relevance, Confidence) already relies on for display, with no dedicated card of their own. Registering `ActivityFactor` in `DefaultFactors()` (Task 3) makes "OTX Activity" appear there automatically, with zero new API field, handler wiring, or frontend code. This is a **better** outcome under this codebase's own established convention (existing factors don't get bespoke UI either), not a shortfall against the spec's intent -- the spec's UI section is satisfied without the API/frontend tasks it implied would be needed. No Task 4/Task 5 exist in this plan as a direct result.
- **A design refinement made during planning:** the spec's `ActivitySignal` (in its Data Model section) listed only `ActorName`/`PulseCount`/`LastObserved`. The spec's own SQL for `threat_actor_activity` already includes both `first_observed` and `last_observed` with `LEAST`/`GREATEST` upsert semantics -- which only produce meaningful, real per-sync values if `ActivitySignal` also carries a `FirstObserved`. Task 1 adds that field and has `FetchActivity()` track both the min and max Modified date per actor while paging (a genuinely new behavior over today's `Fetch()`, which only ever tracked the max) -- necessary to make the spec's own upsert semantics actually correct rather than degenerate (`first_observed` always equal to `last_observed` on every sync, which would defeat the point of tracking it separately).
- **A second gap closed during planning:** `Scheduler.NewScheduler`/`Reconfigure`'s status-flag switch (`MISPEnabled`/`OpenCTIEnabled`/`BundleEnabled`) never had an `"otx"` case, and `ConnectorStatus` never had an `OTXEnabled` field at all -- meaning the frontend's `s.otxEnabled` check (`index.html:15196`) has always read `undefined`/falsy regardless of actual OTX configuration, a pre-existing bug unrelated to this sub-project's original ask. Since Task 2 is already restructuring exactly this area (moving OTX out of the sources/Reconfigure machinery into its own `WithActivitySources`/`ReconfigureActivitySources`), adding the missing `OTXEnabled` field and setting it correctly in the new methods is directly in scope (the natural, adjacent completion of the code already being touched), not unrelated scope creep -- flagged explicitly here per this session's "flag unrelated bugs, fix genuine ones you're already touching" convention.
- **Placeholder scan:** no TBD/TODO; every step has literal, runnable code and exact commands. Task 2 Step 8's `threat_intel_config_handlers.go` edit includes an explicit note to re-read the file's exact current surrounding lines at execution time (the `else` branch's current log line was referenced, not re-quoted, in this plan's research phase) -- this is a scoped instruction to preserve existing behavior while inserting new code, not a placeholder for missing logic.
- **Type consistency:** `ActivitySource`/`ActivitySignal` (`internal/connector`) defined once in Task 1, consumed identically in Task 2's `Scheduler` methods and tests. `threatpriority.ActivitySignal` (a deliberately distinct, smaller type in a different package) defined once in Task 3, consumed identically in `engine.go` and the factor tests. `WithActivitySources`/`ReconfigureActivitySources`/`upsertActivitySignals`/`resolveActivitySignalActor`/`LoadActivitySourcesFromDB` signatures match exactly between their Task 2 definitions and every call site (tests, `main.go`, `threat_intel_config_handlers.go`). `activityWeight` defined once in Task 3 Step 5, used only in `ActivityFactor.Weight`.
