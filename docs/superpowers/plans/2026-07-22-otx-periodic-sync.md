# OTX Periodic Sync Job Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** give OTX a real periodic sync job by joining it to the existing MISP/OpenCTI/Bundle threat-intel scheduler as a fourth `connector.Source`, reusing sub-project 1's `Stats()`/`BySource` machinery — `Fetch()` records a real subscribed-pulse count but returns zero actors (technique mapping is sub-project 4's job).

**Architecture:** a new `OTXSource` type in `internal/connector/otx.go` implements the existing `Source` (`Name()`, `Fetch()`) and `StatsSource` (`Stats()`) interfaces, exactly like `MISPClient`/`OpenCTIClient`. It's wired into `cmd/server/main.go`'s existing `tiSources` list under the same `cfg.OTXAPIKey` gate already used for the unrelated on-demand-lookup `iocProvider`. No changes to `Scheduler`, `ConnectorStatus`, the HTTP handler, or the frontend — sub-project 1's generic `StatsSource` type-assertion in `Scheduler.sync()` already picks up any source that implements it.

**Tech Stack:** Go, `net/http`, `encoding/json`, `net/http/httptest` for tests.

## Global Constraints

- `Fetch()` returns `nil, nil` (zero actors, no error) on success — actor/technique extraction is explicitly out of scope (sub-project 4).
- Reuses `cfg.OTXAPIKey` (`OTX_API_KEY` env var) — no new config field.
- Reuses `cfg.ThreatIntelPollHours` — no new per-source interval.
- `connectorStatusResponse.OTXEnabled` in `internal/api/handlers.go` stays wired to `h.iocProvider != nil` — do not add a duplicate `OTXEnabled` field to `connector.ConnectorStatus`.
- No frontend changes — OTX's Settings row stays the existing simple "✓ Enabled / ✗ Not configured" row.

---

### Task 1: `OTXSource` — periodic-sync client with pulse-count stats

**Files:**
- Create: `orchestrator/internal/connector/otx.go`
- Test: `orchestrator/internal/connector/otx_test.go`

**Interfaces:**
- Consumes: `Source` interface (`orchestrator/internal/connector/source.go:6-10`: `Fetch() ([]ThreatActor, error)`, `Name() string`) and `StatsSource` interface (`orchestrator/internal/connector/types.go`: `Stats() SourceStat`), plus the `SourceStat` struct — all pre-existing, unchanged by this task.
- Produces: `NewOTXSource(apiKey string) *OTXSource`, `(*OTXSource).Name() string`, `(*OTXSource).Fetch() ([]ThreatActor, error)`, `(*OTXSource).Stats() SourceStat` — consumed by Task 2's wiring in `main.go`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/connector/otx_test.go`:

```go
package connector

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestOTXSource_Stats_CountsSubscribedPulses mirrors
// TestMISPClient_Stats_CountsRawEventsAndFilteredActors /
// TestOpenCTIClient_Stats_CountsRawNodesAndFilteredActors: a single mocked
// endpoint, asserting Fetch()'s return value and the resulting Stats().
// OTX's Fetch never extracts actors (that's sub-project 4), so ActorCount
// is always 0 here — that's the correct, honest state for this sub-project,
// not a bug.
func TestOTXSource_Stats_CountsSubscribedPulses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pulses/subscribed" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
		if got := r.Header.Get("X-OTX-API-KEY"); got != "test-key" {
			t.Fatalf("X-OTX-API-KEY header = %q, want test-key", got)
		}
		w.Write([]byte(`{"count": 47, "results": [{"name": "some pulse"}]}`))
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 0 {
		t.Fatalf("actors = %+v, want none (OTX Fetch never extracts actors yet)", actors)
	}

	stat := c.Stats()
	if stat.Name != "otx" || stat.RawCount != 47 || stat.ActorCount != 0 || stat.Error != "" {
		t.Fatalf("Stats() = %+v, want Name=otx RawCount=47 ActorCount=0 Error=\"\"", stat)
	}
	if stat.FetchedAt.IsZero() {
		t.Fatal("Stats().FetchedAt should be set after a successful Fetch")
	}
}

func TestOTXSource_Stats_RecordsErrorOnFailedFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	if _, err := c.Fetch(); err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	stat := c.Stats()
	if stat.Name != "otx" || stat.Error == "" {
		t.Fatalf("Stats() = %+v, want Name=otx with Error set", stat)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/connector/... -run TestOTXSource -v`
Expected: FAIL — `otx.go` doesn't exist yet, compile error `undefined: NewOTXSource`.

- [ ] **Step 3: Write `orchestrator/internal/connector/otx.go`**

```go
package connector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OTXSource performs a periodic sync against AlienVault OTX, recording the
// account's subscribed-pulse count via Stats(). It does not yet extract
// threat actors or ATT&CK techniques from those pulses — Fetch always
// returns zero actors. That mapping is a separate, later piece of work;
// see docs/superpowers/specs/2026-07-22-otx-periodic-sync-design.md.
//
// This is a distinct client from internal/ioc/otx.go's otxProvider, which
// performs synchronous on-demand single-indicator lookups (IP/domain/hash/
// CVE) for LookupIOC — a different concern from this package's periodic
// sync + scenario generation, matching this codebase's existing package
// split between internal/ioc and internal/connector.
type OTXSource struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string // overridden by tests; otxAPIBaseURL in production
	lastStat   SourceStat
}

const otxAPIBaseURL = "https://otx.alienvault.com/api/v1"

// NewOTXSource creates an OTX periodic-sync client.
func NewOTXSource(apiKey string) *OTXSource {
	return &OTXSource{
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    otxAPIBaseURL,
	}
}

// Name identifies this source. Implements Source.
func (c *OTXSource) Name() string { return "otx" }

type otxPulsesResponse struct {
	Count int `json:"count"`
}

// Fetch records the account's subscribed-pulse count via Stats() and always
// returns zero actors — a clean no-op contribution to MergeActors until
// pulse-to-technique mapping is built.
func (c *OTXSource) Fetch() ([]ThreatActor, error) {
	// limit=1 keeps the request cheap: only the total "count" field is
	// needed, not individual pulse objects.
	req, err := http.NewRequest("GET", c.baseURL+"/pulses/subscribed?limit=1", nil)
	if err != nil {
		c.lastStat = SourceStat{Name: "otx", Error: err.Error(), FetchedAt: time.Now()}
		return nil, fmt.Errorf("otx build request: %w", err)
	}
	req.Header.Set("X-OTX-API-KEY", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.lastStat = SourceStat{Name: "otx", Error: err.Error(), FetchedAt: time.Now()}
		return nil, fmt.Errorf("otx request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("OTX returned HTTP %d", resp.StatusCode)
		c.lastStat = SourceStat{Name: "otx", Error: err.Error(), FetchedAt: time.Now()}
		return nil, err
	}

	var parsed otxPulsesResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		wrapped := fmt.Errorf("otx decode response: %w", err)
		c.lastStat = SourceStat{Name: "otx", Error: wrapped.Error(), FetchedAt: time.Now()}
		return nil, wrapped
	}

	c.lastStat = SourceStat{Name: "otx", RawCount: parsed.Count, ActorCount: 0, FetchedAt: time.Now()}
	return nil, nil
}

// Stats implements StatsSource.
func (c *OTXSource) Stats() SourceStat { return c.lastStat }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/connector/... -run TestOTXSource -v`
Expected: PASS for both `TestOTXSource_Stats_CountsSubscribedPulses` and `TestOTXSource_Stats_RecordsErrorOnFailedFetch`.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/connector/otx.go orchestrator/internal/connector/otx_test.go
git commit -m "feat(connector): add OTX periodic-sync source (stats-only, zero actors)"
```

---

### Task 2: Wire `OTXSource` into the scheduler + scheduler-level test

**Files:**
- Modify: `orchestrator/cmd/server/main.go:224-232`
- Modify: `orchestrator/internal/connector/scheduler_test.go` (add one test)
- Modify: `orchestrator/internal/api/handlers.go:3879-3883` (comment only)

**Interfaces:**
- Consumes: `connector.NewOTXSource(apiKey string) *OTXSource` from Task 1; `cfg.OTXAPIKey` (`orchestrator/config/config.go:23`, already exists, no change needed); `fakeSource` struct and `StatsSource`/`Source` satisfaction already established in `scheduler_test.go`.
- Produces: nothing new consumed by a later task — this is the last task.

- [ ] **Step 1: Add a scheduler-level test for a zero-actor `StatsSource`**

In `orchestrator/internal/connector/scheduler_test.go`, add this test after `TestScheduler_Sync_PopulatesBySourcePerSource` (which ends at line 74):

```go
func TestScheduler_Sync_ZeroActorSourceDoesNotDisruptOthers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	otxStat := SourceStat{Name: "otx", RawCount: 47, ActorCount: 0, FetchedAt: time.Now()}
	s := NewScheduler([]Source{
		fakeSource{
			name:   "misp",
			actors: []ThreatActor{{Name: "APT36", Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}}}},
			stats:  SourceStat{Name: "misp", RawCount: 5, ActorCount: 1, FetchedAt: time.Now()},
		},
		fakeSource{
			name:   "otx",
			actors: nil,
			stats:  otxStat,
		},
	}, NewGenerator(t.TempDir(), nil, nil), scenario.NewEngine(t.TempDir()), 24, sharedDB.Pool)

	s.sync()

	st := s.Status()
	if len(st.BySource) != 2 {
		t.Fatalf("BySource = %+v, want 2 entries", st.BySource)
	}
	otx, ok := st.BySource["otx"]
	if !ok || otx.RawCount != 47 || otx.ActorCount != 0 || otx.Error != "" {
		t.Fatalf("BySource[otx] = %+v, want RawCount=47 ActorCount=0 Error=\"\"", otx)
	}
	if st.TotalActors != 1 {
		t.Fatalf("TotalActors = %d, want 1 (otx contributes zero, misp contributes 1)", st.TotalActors)
	}
}
```

- [ ] **Step 2: Run the new test to verify it fails**

Run: `cd orchestrator && go test ./internal/connector/... -run TestScheduler_Sync_ZeroActorSourceDoesNotDisruptOthers -v`
Expected: this test actually compiles and passes already against the current `Scheduler.sync()` — `fakeSource` and the generic `StatsSource` type-assertion loop already handle a zero-actor source correctly (this test only *validates* that Task 1's `OTXSource` shape is safe to add, it doesn't require new scheduler code). If it passes immediately, that's expected — proceed to Step 3, which is a genuine code change (`main.go` wiring), not gated by this test's pass/fail status. If a Docker daemon isn't running, this test is skipped via `-short`; run `go test ./internal/connector/... -short -run TestScheduler_Sync_ZeroActorSourceDoesNotDisruptOthers -v` to confirm it at least compiles, and rely on Task 1's Docker-free tests plus a full non-short run before Step 6's final commit.

- [ ] **Step 3: Wire `OTXSource` into `main.go`**

In `orchestrator/cmd/server/main.go`, find this block (lines 224-232):

```go
	if cfg.OpenCTIUrl != "" && cfg.OpenCTIApiKey != "" {
		tiSources = append(tiSources, connector.NewOpenCTIClient(cfg.OpenCTIUrl, cfg.OpenCTIApiKey, cfg.ThreatIntelSectors))
		log.Printf("[+] OpenCTI connector configured: %s", cfg.OpenCTIUrl)
	}
	// Air-gapped floor: only add the bundle source when a signed ti-bundle.json is
	// actually present. Verified with the release key via integrity.VerifyScenarioFile.
	if cfg.TIBundleDir != "" {
		if _, err := os.Stat(filepath.Join(cfg.TIBundleDir, connector.BundleFileName)); err == nil {
			tiSources = append(tiSources, connector.NewBundleSource(cfg.TIBundleDir, integrity.VerifyScenarioFile))
			log.Printf("[+] Threat-intel bundle found in %s (air-gapped source)", cfg.TIBundleDir)
		}
	}
	gen := connector.NewGenerator(cfg.ScenariosDir, cfg.ThreatIntelSectors, cfg.ThreatIntelRegions)
```

Replace with:

```go
	if cfg.OpenCTIUrl != "" && cfg.OpenCTIApiKey != "" {
		tiSources = append(tiSources, connector.NewOpenCTIClient(cfg.OpenCTIUrl, cfg.OpenCTIApiKey, cfg.ThreatIntelSectors))
		log.Printf("[+] OpenCTI connector configured: %s", cfg.OpenCTIUrl)
	}
	// Air-gapped floor: only add the bundle source when a signed ti-bundle.json is
	// actually present. Verified with the release key via integrity.VerifyScenarioFile.
	if cfg.TIBundleDir != "" {
		if _, err := os.Stat(filepath.Join(cfg.TIBundleDir, connector.BundleFileName)); err == nil {
			tiSources = append(tiSources, connector.NewBundleSource(cfg.TIBundleDir, integrity.VerifyScenarioFile))
			log.Printf("[+] Threat-intel bundle found in %s (air-gapped source)", cfg.TIBundleDir)
		}
	}
	if cfg.OTXAPIKey != "" {
		tiSources = append(tiSources, connector.NewOTXSource(cfg.OTXAPIKey))
		log.Printf("[+] OTX connector configured (periodic sync)")
	}
	gen := connector.NewGenerator(cfg.ScenariosDir, cfg.ThreatIntelSectors, cfg.ThreatIntelRegions)
```

- [ ] **Step 4: Update the stale doc comment in `handlers.go`**

In `orchestrator/internal/api/handlers.go`, find (lines 3879-3883):

```go
// connectorStatusResponse adds OTX's enabled flag alongside the MISP/OpenCTI
// bundle-sync status from the connector package. OTX has no sync/schedule of
// its own (it's a synchronous on-demand lookup, not a periodic bundle sync),
// so it doesn't belong in connector.ConnectorStatus itself — this wraps the
// response instead, keeping that struct scoped to what the scheduler tracks.
```

Replace with:

```go
// connectorStatusResponse adds OTX's enabled flag alongside the MISP/OpenCTI
// bundle-sync status from the connector package. OTX now does have a
// periodic sync (connector.OTXSource, joined to the scheduler's source
// list), but "enabled" here specifically means "the on-demand lookup
// provider (h.iocProvider) is configured" — the same OTX_API_KEY gate the
// scheduler's OTXSource uses, so the two states always agree in practice.
// Kept as a wrapper field rather than a second OTXEnabled field on
// connector.ConnectorStatus to avoid two sources of truth for one boolean.
```

- [ ] **Step 5: Build to confirm everything compiles**

Run: `cd orchestrator && go build ./...`
Expected: no errors.

- [ ] **Step 6: Run the full connector package test suite**

Run: `cd orchestrator && go test ./internal/connector/... -v`
Expected: PASS — all existing tests plus Task 1's `TestOTXSource_*` and this task's `TestScheduler_Sync_ZeroActorSourceDoesNotDisruptOthers`. If Docker isn't running locally, the `sharedDB`-backed tests (`TestNewScheduler_StatusFlags`, `TestScheduler_Sync_PopulatesBySourcePerSource`, `TestScheduler_SyncUpsertsActorProfiles`, and this task's new test) will fail to set up a container — in that case run `go test ./internal/connector/... -short -v` instead to confirm everything else passes, and note in the completion report that the container-backed subset needs a real run before merging (matches this session's established Docker Desktop verification pattern).

- [ ] **Step 7: Commit**

```bash
git add orchestrator/cmd/server/main.go orchestrator/internal/connector/scheduler_test.go orchestrator/internal/api/handlers.go
git commit -m "feat(connector): join OTX to the threat-intel scheduler as a periodic-sync source"
```

---

## Self-Review Notes

**Spec coverage:** `OTXSource` (Task 1) ✓; `main.go` wiring under `cfg.OTXAPIKey` (Task 2 Step 3) ✓; no `Scheduler`/`ConnectorStatus` structural change (verified — Task 2 only touches `main.go`, a test file, and a comment) ✓; stale doc-comment update (Task 2 Step 4) ✓; no frontend change (verified — no `wwwroot` file touched anywhere in this plan) ✓; test coverage for both the client (Task 1) and scheduler-level integration (Task 2) ✓.

**Placeholder scan:** no TBD/TODO; all code blocks are complete, runnable Go.

**Type consistency:** `NewOTXSource(apiKey string) *OTXSource` (Task 1) matches its call site `connector.NewOTXSource(cfg.OTXAPIKey)` (Task 2); `Name()`/`Fetch()`/`Stats()` signatures match `Source`/`StatsSource` exactly as used by `MISPClient`/`OpenCTIClient` and by `Scheduler.sync()`'s existing generic loop.
