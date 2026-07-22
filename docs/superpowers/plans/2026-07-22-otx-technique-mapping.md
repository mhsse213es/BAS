# OTX Pulse-to-Technique Mapping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** make `OTXSource.Fetch()` return real `ThreatActor`s by matching each subscribed pulse's `adversary` field against `attackdata.GroupTechniqueIndex()`'s MITRE-authoritative group names, instead of always returning zero actors.

**Architecture:** `Fetch()` pages through `/pulses/subscribed` (capped at 10 pages × 50 = 500 pulses, most-recent-first), exact-matches each pulse's normalized `adversary` string against a normalized copy of `attackdata.GroupTechniqueIndex()`'s keys, and on a match builds a `ThreatActor` whose `Techniques` come from the index (MITRE's own data), not from the pulse itself. Pulses matching the same group merge into one actor. A partial-page failure returns whatever actors were gathered from successful pages so far, alongside the error.

**Tech Stack:** Go, `net/http`, `encoding/json`, `net/http/httptest` for tests, `github.com/audspect/bas/internal/reporting/attackdata` (new import for this package).

## Global Constraints

- `Fetch()` matches `adversary` exactly (case/whitespace-normalized) against `GroupTechniqueIndex()` keys — no substring/fuzzy matching.
- Pagination is capped at 10 pages of `limit=50` (500 pulses max per sync) and stops early on a short page (fewer results than the limit).
- `RawCount` now means "pulses actually fetched this sync" (bounded by the cap), not the account's total subscribed-pulse count — a documented change from sub-project 3's `Count`-field-based `RawCount`.
- A page-1 failure returns `nil, err` (unchanged from sub-project 3). A page-2+ failure returns the actors gathered from prior successful pages, alongside the error.
- No changes to `Scheduler`, `ConnectorStatus`, the HTTP handler, or the frontend.

---

### Task 1: Rewrite `OTXSource.Fetch()` for pulse pagination and technique mapping

**Files:**
- Modify: `orchestrator/internal/connector/otx.go` (full rewrite of `Fetch()` and its supporting types; `NewOTXSource`, `Name()`, `Stats()` keep their existing signatures)
- Modify: `orchestrator/internal/connector/otx_test.go` (full rewrite: 2 existing tests updated for the new pagination behavior, 6 new tests added)

**Interfaces:**
- Consumes: `attackdata.GroupTechniqueIndex() map[string][]string` (`github.com/audspect/bas/internal/reporting/attackdata`, pre-existing, unchanged) — the known-good test fixture group name `"Wizard Spider"` is already used elsewhere in this codebase (`orchestrator/internal/reporting/attackdata/attackdata_test.go`'s `TestGroupTechniqueIndex_ContainsKnownGroupAndTechnique`, `orchestrator/internal/api/ti_suggest_pack_test.go`).
- Produces: `(*OTXSource).Fetch() ([]ThreatActor, error)` — same signature as before, now with real behavior. `Name()`, `Stats()`, `NewOTXSource(apiKey string) *OTXSource` are unchanged from sub-project 3 — nothing downstream (the scheduler wiring in `cmd/server/main.go`, `Scheduler.sync()`) needs any change.

- [ ] **Step 1: Replace the test file with the full updated + new test suite**

Replace the entire contents of `orchestrator/internal/connector/otx_test.go`:

```go
package connector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/reporting/attackdata"
)

// TestOTXSource_Stats_CountsSubscribedPulses is a basic single-page smoke
// test: verifies the request path/header and that a pulse with no adversary
// contributes to RawCount but not ActorCount. RawCount here means "pulses
// fetched this sync" (bounded by pagination), not the account's total
// subscribed-pulse count — see the RawCount semantics note in
// docs/superpowers/specs/2026-07-22-otx-technique-mapping-design.md.
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

	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 0 {
		t.Fatalf("actors = %+v, want none (pulse has no adversary)", actors)
	}

	stat := c.Stats()
	if stat.Name != "otx" || stat.RawCount != 1 || stat.ActorCount != 0 || stat.Error != "" {
		t.Fatalf("Stats() = %+v, want Name=otx RawCount=1 ActorCount=0 Error=\"\"", stat)
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

// TestOTXSource_Fetch_MatchesKnownGroupToAuthoritativeTechniques uses "Wizard
// Spider" — an established, real MITRE group name already relied on
// elsewhere in this codebase as a stable test fixture (see
// attackdata_test.go and ti_suggest_pack_test.go). The adversary field is
// deliberately lowercase-with-padding to exercise normalization; the actor's
// Name must come back in the index's canonical casing.
func TestOTXSource_Fetch_MatchesKnownGroupToAuthoritativeTechniques(t *testing.T) {
	wantTechs := attackdata.GroupTechniqueIndex()["Wizard Spider"]
	if len(wantTechs) == 0 {
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

	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 1 {
		t.Fatalf("actors = %+v, want 1", actors)
	}
	a := actors[0]
	if a.Name != "Wizard Spider" || a.Source != "otx" || a.Confidence != "medium" {
		t.Fatalf("actor = %+v, want Name=\"Wizard Spider\" Source=otx Confidence=medium", a)
	}
	if len(a.Techniques) != len(wantTechs) {
		t.Fatalf("got %d techniques, want %d (from GroupTechniqueIndex)", len(a.Techniques), len(wantTechs))
	}
	if a.LastSeen.IsZero() {
		t.Fatal("LastSeen should be set from the pulse's Modified timestamp")
	}
}

func TestOTXSource_Fetch_SkipsUnmatchedAdversary(t *testing.T) {
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

	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 0 {
		t.Fatalf("actors = %+v, want none (adversary name doesn't match any MITRE group)", actors)
	}
}

func TestOTXSource_Fetch_SkipsEmptyAdversary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(otxPulsesResponse{
			Count:   1,
			Results: []otxPulse{{Name: "pulse one", Adversary: "", Modified: "2026-01-15T00:00:00Z"}},
		})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 0 {
		t.Fatalf("actors = %+v, want none (empty adversary)", actors)
	}
}

func TestOTXSource_Fetch_PaginatesUpToCap(t *testing.T) {
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

	if _, err := c.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(requestedPages) != 10 {
		t.Fatalf("requested %d pages, want 10 (capped)", len(requestedPages))
	}
	if c.Stats().RawCount != 500 {
		t.Fatalf("RawCount = %d, want 500", c.Stats().RawCount)
	}
}

func TestOTXSource_Fetch_StopsOnShortPage(t *testing.T) {
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

	if _, err := c.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if requestCount != 1 {
		t.Fatalf("requested %d pages, want 1 (short page ends pagination)", requestCount)
	}
	if c.Stats().RawCount != 30 {
		t.Fatalf("RawCount = %d, want 30", c.Stats().RawCount)
	}
}

func TestOTXSource_Fetch_PartialFailureReturnsActorsGatheredSoFar(t *testing.T) {
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

	actors, err := c.Fetch()
	if err == nil {
		t.Fatal("expected error from page 2 failure")
	}
	if len(actors) != 1 || actors[0].Name != "Wizard Spider" {
		t.Fatalf("actors = %+v, want 1 actor (Wizard Spider, from page 1)", actors)
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
Expected: FAIL — compile error, `otxPulse`/`otxPulsesResponse` fields don't match the current `otx.go` (which only has `Count int` on `otxPulsesResponse` and no `otxPulse` type), and `Fetch()`'s current implementation doesn't paginate or match adversaries.

- [ ] **Step 3: Replace `orchestrator/internal/connector/otx.go`**

Replace the entire file with:

```go
package connector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/audspect/bas/internal/reporting/attackdata"
)

// OTXSource performs a periodic sync against AlienVault OTX. It treats OTX
// purely as an activity/attribution signal: each subscribed pulse's
// adversary field is matched against attackdata.GroupTechniqueIndex()'s
// MITRE-authoritative group names, and on a match the resulting ThreatActor
// gets MITRE's own technique list for that group — not anything parsed from
// the pulse's own tags, which aren't a reliable source of ATT&CK IDs. See
// docs/superpowers/specs/2026-07-22-otx-technique-mapping-design.md.
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

// otxPageLimit/otxMaxPages bound each sync to at most 500 pulses
// (10 pages x 50), regardless of how many pulses the account is actually
// subscribed to. This assumes /pulses/subscribed returns pulses ordered
// most-recently-modified-first by default -- unverified against a live OTX
// account; see the design spec's "Open assumption" note.
const otxPageLimit = 50
const otxMaxPages = 10

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

type otxPulse struct {
	Name      string `json:"name"`
	Adversary string `json:"adversary"`
	Modified  string `json:"modified"` // RFC3339
}

type otxPulsesResponse struct {
	Count   int        `json:"count"`
	Results []otxPulse `json:"results"`
}

// Fetch pages through the account's subscribed pulses (capped at
// otxMaxPages x otxPageLimit) and builds one ThreatActor per matched MITRE
// group. A page-1 failure returns nil, err. A later-page failure returns
// whatever actors were gathered from the pages that did succeed, alongside
// the error -- Scheduler.sync() currently discards actors on any Fetch
// error, so this doesn't yet change sync behavior, but the data is there
// for that gap to be closed separately later.
func (c *OTXSource) Fetch() ([]ThreatActor, error) {
	groupTechs := attackdata.GroupTechniqueIndex()
	normalizedGroups := make(map[string]string, len(groupTechs))
	for name := range groupTechs {
		normalizedGroups[normalizeAdversary(name)] = name
	}

	actorMap := make(map[string]*ThreatActor)
	var totalFetched int

	for page := 1; page <= otxMaxPages; page++ {
		pulses, err := c.fetchPulsesPage(page)
		if err != nil {
			if page == 1 {
				c.lastStat = SourceStat{Name: "otx", Error: err.Error(), FetchedAt: time.Now()}
				return nil, fmt.Errorf("otx fetch page 1: %w", err)
			}
			out := otxActorsFromMap(actorMap)
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

			existing, ok := actorMap[groupName]
			if !ok {
				techs := make([]TechniqueRef, 0, len(groupTechs[groupName]))
				for _, id := range groupTechs[groupName] {
					techs = append(techs, TechniqueRef{ID: id})
				}
				a := &ThreatActor{
					Name:       groupName,
					Techniques: techs,
					Source:     "otx",
					Confidence: "medium",
				}
				if parseErr == nil {
					a.LastSeen = modified
				}
				actorMap[groupName] = a
				continue
			}
			if parseErr == nil && modified.After(existing.LastSeen) {
				existing.LastSeen = modified
			}
		}

		if len(pulses) < otxPageLimit {
			break
		}
	}

	out := otxActorsFromMap(actorMap)
	c.lastStat = SourceStat{Name: "otx", RawCount: totalFetched, ActorCount: len(out), FetchedAt: time.Now()}
	return out, nil
}

// Stats implements StatsSource.
func (c *OTXSource) Stats() SourceStat { return c.lastStat }

func normalizeAdversary(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

func otxActorsFromMap(m map[string]*ThreatActor) []ThreatActor {
	out := make([]ThreatActor, 0, len(m))
	for _, a := range m {
		out = append(out, *a)
	}
	return out
}

func (c *OTXSource) fetchPulsesPage(page int) ([]otxPulse, error) {
	url := fmt.Sprintf("%s/pulses/subscribed?limit=%d&page=%d", c.baseURL, otxPageLimit, page)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-OTX-API-KEY", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OTX returned HTTP %d", resp.StatusCode)
	}

	var parsed otxPulsesResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return parsed.Results, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/connector/... -run TestOTXSource -v`
Expected: PASS for all 8 `TestOTXSource_*` tests.

- [ ] **Step 5: Build and run the full connector suite**

Run: `cd orchestrator && go build ./... && go test ./internal/connector/... -v`
Expected: no build errors; all tests pass, including the pre-existing MISP/OpenCTI/Bundle/Scheduler tests (unaffected by this change) alongside the 8 OTX tests. If Docker isn't running locally, the `sharedDB`-backed scheduler tests will fail to set up a container — run `go test ./internal/connector/... -short -v` instead to confirm everything else passes, and note in the completion report that the container-backed subset needs a real run before merging.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/connector/otx.go orchestrator/internal/connector/otx_test.go
git commit -m "feat(connector): map OTX pulses to ThreatActors via MITRE's authoritative Groups index"
```

---

## Self-Review Notes

**Spec coverage:** pagination cap (10×50) ✓; exact-match normalization against `GroupTechniqueIndex()` ✓; MITRE-authoritative techniques (not tag-parsed) ✓; actor merge-by-group across pulses with `LastSeen` tracking ✓; `RawCount` semantics change documented in both the code comment and this plan's Global Constraints ✓; page-1-failure vs partial-failure error handling, including the explicit note that `Scheduler.sync()` still discards partial-failure actors today (unchanged, out of scope) ✓; test coverage for match/no-match/empty-adversary/pagination-cap/short-page/partial-failure, all six new scenarios from the spec's Testing section ✓; no `Scheduler`/`ConnectorStatus`/handler/frontend changes (verified — this plan touches only `otx.go` and `otx_test.go`) ✓.

**Placeholder scan:** no TBD/TODO; all code blocks are complete, runnable Go.

**Type consistency:** `NewOTXSource`, `Name()`, `Stats()` signatures unchanged from sub-project 3 (verified against the existing file read during brainstorming) — no ripple effects into `cmd/server/main.go`'s wiring or `scheduler.go`'s generic `StatsSource`/`Source` handling. `otxPulsesResponse`/`otxPulse` field names used identically across the implementation (Step 3) and every test (Step 1).
