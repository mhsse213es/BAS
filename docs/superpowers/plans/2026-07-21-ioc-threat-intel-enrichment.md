# IOC Threat-Intel Enrichment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Background-enrich extracted IOCs (`run_iocs`, sub-project B) against the configured threat-intel provider (`ioc.Provider`, sub-project A), cache results in a provider-aware, TTL'd, failure-tracking cache, and surface an honest, actionable "Threat Intelligence" section in single-run HTML/PDF reports.

**Architecture:** `SubmitScenarioResult` fires `go h.enrichRunIOCs(ctx, runID)` right after extraction persists `run_iocs`. That background job reads the run's indicators, skips any with a fresh cache row, and calls `ioc.Lookup` (a new shared dispatch function) for the rest — writing success or failure into a new global `ioc_enrichment` cache table, keyed `(indicator_type, indicator_value, provider)`. Report generation (`Engine.BuildFromRun`) only ever reads that cache via a plain SQL join — it never calls a provider live, so report pages stay fast and never depend on the provider's uptime.

**Tech Stack:** Go, PostgreSQL via `pgxpool`, existing `internal/ioc`/`internal/db`/`internal/api`/`internal/reporting` packages — no new dependencies.

## Global Constraints

- This is **enrichment**, not correlation — nothing here is named "correlate."
- The cache table is global (not per-run, not per-tenant) and provider-aware: `UNIQUE(indicator_type, indicator_value, provider)`.
- A cache row carries lookup metadata beyond just the threat data: `provider_version`, `schema_version`, `lookup_duration_ms`, `last_success_at`, `last_failure_at`, `last_error`, `ttl_expires_at`.
- **Failures are cached too**, with the same TTL as successes, so a struggling/rate-limited provider isn't hammered by every run. A failure never clears a previously-cached success's threat data — only the failure-tracking columns are written on the failure path.
- TTL is 24 hours, applied uniformly to both success and failure paths.
- The report never labels anything "confidence" — tiers are `pending | unknown | suspicious | malicious-associated`, derived from the existing pulse-count thresholds (0 / 1–2 / 3+) but under honest, non-authoritative names.
- Report scope is single-run only (`BuildFromRun`) — `Build` and `BuildFromCampaign` are untouched.
- True multi-provider fan-out (querying 2+ providers per indicator) is explicitly out of scope — `enrichRunIOCs` calls whichever single provider is configured, matching sub-project A's single-active-provider model.
- No manual "re-check now" endpoint — automatic background enrichment only.
- First Seen / Last Seen / References are NOT added — not currently parsed by the OTX client, not fabricated here.
- `Tags` IS added to `ioc.Result` — OTX's response already carries per-pulse tags (`internal/ioc/otx.go:53`) that are currently parsed and discarded; this is a small, additive, low-risk extension of already-shipped sub-project A code.

---

### Task 1: Extend `internal/ioc` — `Provider.Name()`, `Result.Tags`, shared `Lookup` dispatch

**Files:**
- Modify: `orchestrator/internal/ioc/provider.go`
- Modify: `orchestrator/internal/ioc/otx.go`
- Modify: `orchestrator/internal/ioc/otx_test.go`
- Create: `orchestrator/internal/ioc/lookup.go`
- Create: `orchestrator/internal/ioc/lookup_test.go`
- Modify: `orchestrator/internal/api/handlers.go:3547-3583` (refactor `LookupIOC` to use the new shared dispatch)

**Interfaces:**
- Produces: `Provider.Name() string` (new interface method), `Result.Tags []string` (new field), `func Lookup(ctx context.Context, p Provider, indicatorType, value string) (*Result, error)` (new) — all consumed by Task 3's `enrichRunIOCs`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/ioc/otx_test.go`:

```go
func TestOTXLookup_TagsAggregatedAcrossPulses(t *testing.T) {
	p := testProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"indicator":"evil.example.com","pulse_info":{"count":2,"pulses":[{"name":"A","tags":["apt","emotet"]},{"name":"B","tags":["emotet","banking"]}],"related":{"alienvault":{"adversary":[],"malware_families":[],"industries":[]}}}}`))
	})

	got, err := p.LookupDomain(context.Background(), "evil.example.com")
	if err != nil {
		t.Fatalf("LookupDomain: %v", err)
	}
	wantTags := map[string]bool{"apt": true, "emotet": true, "banking": true}
	if len(got.Tags) != len(wantTags) {
		t.Fatalf("Tags = %v, want 3 unique tags", got.Tags)
	}
	for _, tag := range got.Tags {
		if !wantTags[tag] {
			t.Errorf("unexpected tag %q", tag)
		}
	}
}

func TestOTXProvider_Name(t *testing.T) {
	p := testProvider(t, func(w http.ResponseWriter, r *http.Request) {})
	if got := p.Name(); got != "otx" {
		t.Errorf("Name() = %q, want otx", got)
	}
}
```

Create `orchestrator/internal/ioc/lookup_test.go`:

```go
package ioc

import (
	"context"
	"testing"
)

type stubProvider struct {
	name string
}

func (s *stubProvider) Name() string { return s.name }
func (s *stubProvider) LookupIP(ctx context.Context, v string) (*Result, error) {
	return &Result{Indicator: v, Type: "ip"}, nil
}
func (s *stubProvider) LookupDomain(ctx context.Context, v string) (*Result, error) {
	return &Result{Indicator: v, Type: "domain"}, nil
}
func (s *stubProvider) LookupURL(ctx context.Context, v string) (*Result, error) {
	return &Result{Indicator: v, Type: "url"}, nil
}
func (s *stubProvider) LookupHash(ctx context.Context, v string) (*Result, error) {
	return &Result{Indicator: v, Type: "hash"}, nil
}
func (s *stubProvider) LookupCVE(ctx context.Context, v string) (*Result, error) {
	return &Result{Indicator: v, Type: "cve"}, nil
}

func TestLookup_DispatchesToCorrectMethod(t *testing.T) {
	p := &stubProvider{name: "stub"}
	cases := []string{"ip", "domain", "url", "hash", "cve"}
	for _, typ := range cases {
		got, err := Lookup(context.Background(), p, typ, "v")
		if err != nil {
			t.Fatalf("Lookup(%q): %v", typ, err)
		}
		if got.Type != typ {
			t.Errorf("Lookup(%q) returned Type %q", typ, got.Type)
		}
	}
}

func TestLookup_UnknownType_ReturnsError(t *testing.T) {
	p := &stubProvider{name: "stub"}
	_, err := Lookup(context.Background(), p, "not-a-type", "v")
	if err == nil {
		t.Fatal("Lookup with an unknown type returned no error")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd orchestrator
go test ./internal/ioc/... -run "TestOTXLookup_TagsAggregatedAcrossPulses|TestOTXProvider_Name|TestLookup_" -v
```
Expected: FAIL to compile — `undefined: Lookup`, `p.Name undefined (type *otxProvider has no field or method Name)`, `got.Tags undefined`.

- [ ] **Step 3: Add `Name()` to the `Provider` interface and `Tags` to `Result`**

In `orchestrator/internal/ioc/provider.go`, replace:

```go
// Provider is one threat-intelligence source's lookup client. Implementations
// do no database I/O -- callers own persistence, mirroring internal/detectverify.
type Provider interface {
	LookupIP(ctx context.Context, ip string) (*Result, error)
	LookupDomain(ctx context.Context, domain string) (*Result, error)
	LookupURL(ctx context.Context, url string) (*Result, error)
	LookupHash(ctx context.Context, hash string) (*Result, error)
	LookupCVE(ctx context.Context, cveID string) (*Result, error)
}

// Result is one indicator's enrichment, normalized across providers.
type Result struct {
	Indicator       string          `json:"indicator"`
	Type            string          `json:"type"` // ip | domain | url | hash | cve
	Provider        string          `json:"provider"`
	PulseCount      int             `json:"pulseCount"`
	PulseNames      []string        `json:"pulseNames,omitempty"`
	MalwareFamilies []string        `json:"malwareFamilies,omitempty"`
	AdversaryNames  []string        `json:"adversaryNames,omitempty"`
	Industries      []string        `json:"industries,omitempty"`
	Confidence      string          `json:"confidence"` // unknown | low | high
	RawResponse     json.RawMessage `json:"raw,omitempty"`
}
```

with:

```go
// Provider is one threat-intelligence source's lookup client. Implementations
// do no database I/O -- callers own persistence, mirroring internal/detectverify.
type Provider interface {
	LookupIP(ctx context.Context, ip string) (*Result, error)
	LookupDomain(ctx context.Context, domain string) (*Result, error)
	LookupURL(ctx context.Context, url string) (*Result, error)
	LookupHash(ctx context.Context, hash string) (*Result, error)
	LookupCVE(ctx context.Context, cveID string) (*Result, error)
	// Name identifies which provider produced a Result -- used to key the
	// enrichment cache (internal/db/ioc_enrichment.go) so different providers'
	// results for the same indicator never collide.
	Name() string
}

// Result is one indicator's enrichment, normalized across providers.
type Result struct {
	Indicator       string          `json:"indicator"`
	Type            string          `json:"type"` // ip | domain | url | hash | cve
	Provider        string          `json:"provider"`
	PulseCount      int             `json:"pulseCount"`
	PulseNames      []string        `json:"pulseNames,omitempty"`
	MalwareFamilies []string        `json:"malwareFamilies,omitempty"`
	AdversaryNames  []string        `json:"adversaryNames,omitempty"`
	Industries      []string        `json:"industries,omitempty"`
	Tags            []string        `json:"tags,omitempty"`
	Confidence      string          `json:"confidence"` // unknown | low | high
	RawResponse     json.RawMessage `json:"raw,omitempty"`
}
```

- [ ] **Step 4: Implement `Name()` and tag aggregation in the OTX client**

In `orchestrator/internal/ioc/otx.go`, find:

```go
func newOTXProvider(cfg Config) *otxProvider {
	return &otxProvider{
		apiKey:     cfg.APIKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    otxBaseURL,
	}
}

func (p *otxProvider) LookupIP(ctx context.Context, ip string) (*Result, error) {
```

Replace with:

```go
func newOTXProvider(cfg Config) *otxProvider {
	return &otxProvider{
		apiKey:     cfg.APIKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    otxBaseURL,
	}
}

func (p *otxProvider) Name() string { return "otx" }

func (p *otxProvider) LookupIP(ctx context.Context, ip string) (*Result, error) {
```

Replace the tag-discarding pulse-name loop and the final `Result` construction:

```go
	pulseNames := make([]string, 0, len(raw.PulseInfo.Pulses))
	for _, pulse := range raw.PulseInfo.Pulses {
		pulseNames = append(pulseNames, pulse.Name)
	}

	confidence := ConfidenceUnknown
	switch {
	case raw.PulseInfo.Count >= 3:
		confidence = ConfidenceHigh
	case raw.PulseInfo.Count >= 1:
		confidence = ConfidenceLow
	}

	return &Result{
		Indicator:       value,
		Type:            resultType,
		Provider:        "otx",
		PulseCount:      raw.PulseInfo.Count,
		PulseNames:      pulseNames,
		MalwareFamilies: raw.PulseInfo.Related.Alienvault.MalwareFamilies,
		AdversaryNames:  raw.PulseInfo.Related.Alienvault.Adversary,
		Industries:      raw.PulseInfo.Related.Alienvault.Industries,
		Confidence:      confidence,
		RawResponse:     json.RawMessage(body),
	}, nil
}
```

with:

```go
	pulseNames := make([]string, 0, len(raw.PulseInfo.Pulses))
	tagSet := map[string]bool{}
	var tags []string
	for _, pulse := range raw.PulseInfo.Pulses {
		pulseNames = append(pulseNames, pulse.Name)
		for _, tag := range pulse.Tags {
			if !tagSet[tag] {
				tagSet[tag] = true
				tags = append(tags, tag)
			}
		}
	}

	confidence := ConfidenceUnknown
	switch {
	case raw.PulseInfo.Count >= 3:
		confidence = ConfidenceHigh
	case raw.PulseInfo.Count >= 1:
		confidence = ConfidenceLow
	}

	return &Result{
		Indicator:       value,
		Type:            resultType,
		Provider:        p.Name(),
		PulseCount:      raw.PulseInfo.Count,
		PulseNames:      pulseNames,
		MalwareFamilies: raw.PulseInfo.Related.Alienvault.MalwareFamilies,
		AdversaryNames:  raw.PulseInfo.Related.Alienvault.Adversary,
		Industries:      raw.PulseInfo.Related.Alienvault.Industries,
		Tags:            tags,
		Confidence:      confidence,
		RawResponse:     json.RawMessage(body),
	}, nil
}
```

Also replace the 404 branch's hardcoded provider string:

```go
	if resp.StatusCode == http.StatusNotFound {
		return &Result{Indicator: value, Type: resultType, Provider: "otx", Confidence: ConfidenceUnknown}, nil
	}
```

with:

```go
	if resp.StatusCode == http.StatusNotFound {
		return &Result{Indicator: value, Type: resultType, Provider: p.Name(), Confidence: ConfidenceUnknown}, nil
	}
```

- [ ] **Step 5: Create the shared dispatch function**

Create `orchestrator/internal/ioc/lookup.go`:

```go
package ioc

import (
	"context"
	"fmt"
)

// Lookup dispatches to the right Provider method for indicatorType, sharing
// one switch between the HTTP lookup endpoint (LookupIOC) and the background
// enrichment pipeline (enrichRunIOCs).
func Lookup(ctx context.Context, p Provider, indicatorType, value string) (*Result, error) {
	switch indicatorType {
	case "ip":
		return p.LookupIP(ctx, value)
	case "domain":
		return p.LookupDomain(ctx, value)
	case "url":
		return p.LookupURL(ctx, value)
	case "hash":
		return p.LookupHash(ctx, value)
	case "cve":
		return p.LookupCVE(ctx, value)
	default:
		return nil, fmt.Errorf("ioc: unsupported indicator type %q", indicatorType)
	}
}
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd orchestrator
go test ./internal/ioc/... -v
```
Expected: all `PASS`, including the pre-existing sub-project A/B tests (unaffected).

- [ ] **Step 7: Refactor `LookupIOC` to use the shared dispatch**

In `orchestrator/internal/api/handlers.go`, replace the `LookupIOC` handler (currently lines 3547-3583):

```go
func (h *Handler) LookupIOC(w http.ResponseWriter, r *http.Request) {
	if h.iocProvider == nil {
		jsonError(w, "threat intel not configured — set OTX_API_KEY and restart", http.StatusServiceUnavailable)
		return
	}
	iocType := r.URL.Query().Get("type")
	value := r.URL.Query().Get("value")
	if value == "" {
		jsonError(w, "value is required", http.StatusBadRequest)
		return
	}

	var (
		result *ioc.Result
		err    error
	)
	switch iocType {
	case "ip":
		result, err = h.iocProvider.LookupIP(r.Context(), value)
	case "domain":
		result, err = h.iocProvider.LookupDomain(r.Context(), value)
	case "url":
		result, err = h.iocProvider.LookupURL(r.Context(), value)
	case "hash":
		result, err = h.iocProvider.LookupHash(r.Context(), value)
	case "cve":
		result, err = h.iocProvider.LookupCVE(r.Context(), value)
	default:
		jsonError(w, "type must be one of: ip, domain, url, hash, cve", http.StatusBadRequest)
		return
	}
	if err != nil {
		jsonError(w, "lookup failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	respond(w, result)
}
```

with:

```go
func (h *Handler) LookupIOC(w http.ResponseWriter, r *http.Request) {
	if h.iocProvider == nil {
		jsonError(w, "threat intel not configured — set OTX_API_KEY and restart", http.StatusServiceUnavailable)
		return
	}
	iocType := r.URL.Query().Get("type")
	value := r.URL.Query().Get("value")
	if value == "" {
		jsonError(w, "value is required", http.StatusBadRequest)
		return
	}
	switch iocType {
	case "ip", "domain", "url", "hash", "cve":
	default:
		jsonError(w, "type must be one of: ip, domain, url, hash, cve", http.StatusBadRequest)
		return
	}

	result, err := ioc.Lookup(r.Context(), h.iocProvider, iocType, value)
	if err != nil {
		jsonError(w, "lookup failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	respond(w, result)
}
```

This preserves the exact same validation, error messages, and status codes — only the dispatch mechanics change.

- [ ] **Step 8: Build and vet**

```bash
cd orchestrator
go build ./... && echo BUILD_OK
go vet ./... && echo VET_OK
```
Expected: `BUILD_OK`, `VET_OK`.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/ioc/provider.go orchestrator/internal/ioc/otx.go orchestrator/internal/ioc/otx_test.go orchestrator/internal/ioc/lookup.go orchestrator/internal/ioc/lookup_test.go orchestrator/internal/api/handlers.go
git commit -m "feat(ioc): add Provider.Name(), Result.Tags, shared Lookup dispatch"
```

---

### Task 2: `ioc_enrichment` cache table + DB layer

**Files:**
- Create: `orchestrator/internal/db/ioc_enrichment.go`
- Create: `orchestrator/internal/db/ioc_enrichment_test.go`
- Modify: `orchestrator/internal/testutil/testdb.go:70-79` (schema bootstrap for tests)
- Modify: `orchestrator/cmd/server/main.go:86-88` (schema bootstrap for the server)

**Interfaces:**
- Consumes: `ioc.Result` (Task 1).
- Produces: `type Enrichment struct {...}`, `func EnsureIOCEnrichmentSchema(ctx, pool) error`, `func GetIOCEnrichment(ctx, pool, indicatorType, indicatorValue, provider string) (*Enrichment, error)`, `func UpsertIOCEnrichmentSuccess(ctx, pool, indicatorType, indicatorValue, provider string, result *ioc.Result, lookupDurationMs int, ttlExpiresAt time.Time) error`, `func UpsertIOCEnrichmentFailure(ctx, pool, indicatorType, indicatorValue, provider string, lookupErr error, ttlExpiresAt time.Time) error` — all used by Task 3.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/db/ioc_enrichment_test.go`. Reuses the `sharedDB` package var already declared in `orchestrator/internal/db/tenant_test.go` (same `db_test` package).

```go
package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/ioc"
)

func TestUpsertIOCEnrichmentSuccess_RoundTrip(t *testing.T) {
	ctx := context.Background()
	const typ, val, provider = "ip", "45.33.32.156", "otx"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM ioc_enrichment WHERE indicator_type=$1 AND indicator_value=$2 AND provider=$3`, typ, val, provider)
	})

	result := &ioc.Result{
		Indicator: val, Type: typ, Provider: provider,
		PulseCount: 3, PulseNames: []string{"Emotet Campaign"},
		MalwareFamilies: []string{"Emotet"}, AdversaryNames: []string{"TA542"},
		Industries: []string{"Financial Services"}, Tags: []string{"emotet"},
	}
	ttl := time.Now().Add(24 * time.Hour)
	if err := db.UpsertIOCEnrichmentSuccess(ctx, sharedDB.Pool, typ, val, provider, result, 250, ttl); err != nil {
		t.Fatalf("UpsertIOCEnrichmentSuccess: %v", err)
	}

	got, err := db.GetIOCEnrichment(ctx, sharedDB.Pool, typ, val, provider)
	if err != nil {
		t.Fatalf("GetIOCEnrichment: %v", err)
	}
	if got == nil {
		t.Fatal("GetIOCEnrichment returned nil for a row that was just upserted")
	}
	if got.PulseCount != 3 || len(got.MalwareFamilies) != 1 || got.MalwareFamilies[0] != "Emotet" {
		t.Errorf("got %+v", got)
	}
	if got.LastSuccessAt == nil {
		t.Error("LastSuccessAt was not set")
	}
	if got.LastFailureAt != nil {
		t.Error("LastFailureAt should be nil -- this row has never failed")
	}
	if !got.TTLExpiresAt.After(time.Now()) {
		t.Error("TTLExpiresAt should be in the future")
	}
}

func TestGetIOCEnrichment_NoRow_ReturnsNilNoError(t *testing.T) {
	got, err := db.GetIOCEnrichment(context.Background(), sharedDB.Pool, "ip", "203.0.113.99", "otx")
	if err != nil {
		t.Fatalf("GetIOCEnrichment: %v", err)
	}
	if got != nil {
		t.Errorf("got %+v, want nil for an indicator that was never looked up", got)
	}
}

func TestUpsertIOCEnrichmentFailure_PreservesPriorSuccessData(t *testing.T) {
	ctx := context.Background()
	const typ, val, provider = "domain", "evil.example.com", "otx"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM ioc_enrichment WHERE indicator_type=$1 AND indicator_value=$2 AND provider=$3`, typ, val, provider)
	})

	result := &ioc.Result{Indicator: val, Type: typ, Provider: provider, PulseCount: 5, MalwareFamilies: []string{"TrickBot"}}
	if err := db.UpsertIOCEnrichmentSuccess(ctx, sharedDB.Pool, typ, val, provider, result, 100, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("seed success: %v", err)
	}

	if err := db.UpsertIOCEnrichmentFailure(ctx, sharedDB.Pool, typ, val, provider, errors.New("rate limited"), time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("UpsertIOCEnrichmentFailure: %v", err)
	}

	got, err := db.GetIOCEnrichment(ctx, sharedDB.Pool, typ, val, provider)
	if err != nil {
		t.Fatalf("GetIOCEnrichment: %v", err)
	}
	if got.PulseCount != 5 || len(got.MalwareFamilies) != 1 || got.MalwareFamilies[0] != "TrickBot" {
		t.Errorf("prior success data was overwritten by a later failure: %+v", got)
	}
	if got.LastFailureAt == nil || got.LastError != "rate limited" {
		t.Errorf("failure was not recorded: %+v", got)
	}
	if got.LastSuccessAt == nil {
		t.Error("LastSuccessAt should still be set from the earlier success")
	}
}

func TestUpsertIOCEnrichmentFailure_FirstEverAttempt(t *testing.T) {
	ctx := context.Background()
	const typ, val, provider = "hash", "deadbeefdeadbeefdeadbeefdeadbeef", "otx"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM ioc_enrichment WHERE indicator_type=$1 AND indicator_value=$2 AND provider=$3`, typ, val, provider)
	})

	if err := db.UpsertIOCEnrichmentFailure(ctx, sharedDB.Pool, typ, val, provider, errors.New("timeout"), time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("UpsertIOCEnrichmentFailure: %v", err)
	}

	got, err := db.GetIOCEnrichment(ctx, sharedDB.Pool, typ, val, provider)
	if err != nil {
		t.Fatalf("GetIOCEnrichment: %v", err)
	}
	if got == nil {
		t.Fatal("a failed lookup must still create a cache row (so retries respect the TTL)")
	}
	if got.PulseCount != 0 || got.LastSuccessAt != nil {
		t.Errorf("got %+v, want zero-value success fields on a never-successful row", got)
	}
	if got.LastError != "timeout" {
		t.Errorf("LastError = %q, want timeout", got.LastError)
	}
}

func TestIOCEnrichment_ProviderAwareKeying(t *testing.T) {
	ctx := context.Background()
	const typ, val = "ip", "198.51.100.42"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM ioc_enrichment WHERE indicator_type=$1 AND indicator_value=$2`, typ, val)
	})

	otxResult := &ioc.Result{Indicator: val, Type: typ, Provider: "otx", PulseCount: 3}
	otherResult := &ioc.Result{Indicator: val, Type: typ, Provider: "other-provider", PulseCount: 0}
	if err := db.UpsertIOCEnrichmentSuccess(ctx, sharedDB.Pool, typ, val, "otx", otxResult, 10, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("seed otx: %v", err)
	}
	if err := db.UpsertIOCEnrichmentSuccess(ctx, sharedDB.Pool, typ, val, "other-provider", otherResult, 10, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("seed other-provider: %v", err)
	}

	otx, err := db.GetIOCEnrichment(ctx, sharedDB.Pool, typ, val, "otx")
	if err != nil || otx == nil || otx.PulseCount != 3 {
		t.Fatalf("otx row wrong: %+v, err=%v", otx, err)
	}
	other, err := db.GetIOCEnrichment(ctx, sharedDB.Pool, typ, val, "other-provider")
	if err != nil || other == nil || other.PulseCount != 0 {
		t.Fatalf("other-provider row wrong: %+v, err=%v", other, err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd orchestrator
go test ./internal/db/... -run TestUpsertIOCEnrichmentSuccess -v
```
Expected: FAIL to compile — `undefined: db.UpsertIOCEnrichmentSuccess`. (Docker must be running; `docker info` first if unsure.)

- [ ] **Step 3: Implement the schema + storage layer**

Create `orchestrator/internal/db/ioc_enrichment.go`:

```go
package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/ioc"
)

// EnsureIOCEnrichmentSchema creates the ioc_enrichment cache table. Idempotent
// -- safe to call on every startup.
func EnsureIOCEnrichmentSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS ioc_enrichment (
			id                 BIGSERIAL PRIMARY KEY,
			indicator_type     TEXT NOT NULL,
			indicator_value    TEXT NOT NULL,
			provider           TEXT NOT NULL,
			provider_version   TEXT NOT NULL DEFAULT '',
			schema_version     SMALLINT NOT NULL DEFAULT 1,
			pulse_count        INT NOT NULL DEFAULT 0,
			pulse_names        JSONB NOT NULL DEFAULT '[]',
			malware_families   JSONB NOT NULL DEFAULT '[]',
			adversary_names    JSONB NOT NULL DEFAULT '[]',
			industries         JSONB NOT NULL DEFAULT '[]',
			tags               JSONB NOT NULL DEFAULT '[]',
			raw_response       JSONB,
			lookup_duration_ms INT,
			last_success_at    TIMESTAMPTZ,
			last_failure_at    TIMESTAMPTZ,
			last_error         TEXT,
			ttl_expires_at     TIMESTAMPTZ NOT NULL,
			UNIQUE(indicator_type, indicator_value, provider)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ioc_enrichment_ttl ON ioc_enrichment(ttl_expires_at)`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("ioc enrichment schema: %w", err)
		}
	}
	return nil
}

// Enrichment is one cached provider lookup result for one indicator.
type Enrichment struct {
	IndicatorType    string
	IndicatorValue   string
	Provider         string
	ProviderVersion  string
	SchemaVersion    int
	PulseCount       int
	PulseNames       []string
	MalwareFamilies  []string
	AdversaryNames   []string
	Industries       []string
	Tags             []string
	LookupDurationMs int
	LastSuccessAt    *time.Time
	LastFailureAt    *time.Time
	LastError        string
	TTLExpiresAt     time.Time
}

const currentEnrichmentSchemaVersion = 1

// GetIOCEnrichment returns the cached row for (indicatorType, indicatorValue,
// provider), or nil if none exists yet. Callers compare TTLExpiresAt against
// time.Now() themselves to decide whether it's still fresh enough to skip a
// re-lookup.
func GetIOCEnrichment(ctx context.Context, pool *pgxpool.Pool, indicatorType, indicatorValue, provider string) (*Enrichment, error) {
	var e Enrichment
	var pulseNamesJSON, malwareJSON, adversaryJSON, industriesJSON, tagsJSON []byte
	var lastError *string
	err := pool.QueryRow(ctx,
		`SELECT indicator_type, indicator_value, provider, provider_version, schema_version,
		        pulse_count, pulse_names, malware_families, adversary_names, industries, tags,
		        lookup_duration_ms, last_success_at, last_failure_at, last_error, ttl_expires_at
		 FROM ioc_enrichment WHERE indicator_type = $1 AND indicator_value = $2 AND provider = $3`,
		indicatorType, indicatorValue, provider,
	).Scan(&e.IndicatorType, &e.IndicatorValue, &e.Provider, &e.ProviderVersion, &e.SchemaVersion,
		&e.PulseCount, &pulseNamesJSON, &malwareJSON, &adversaryJSON, &industriesJSON, &tagsJSON,
		&e.LookupDurationMs, &e.LastSuccessAt, &e.LastFailureAt, &lastError, &e.TTLExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("ioc enrichment get: %w", err)
	}
	_ = json.Unmarshal(pulseNamesJSON, &e.PulseNames)
	_ = json.Unmarshal(malwareJSON, &e.MalwareFamilies)
	_ = json.Unmarshal(adversaryJSON, &e.AdversaryNames)
	_ = json.Unmarshal(industriesJSON, &e.Industries)
	_ = json.Unmarshal(tagsJSON, &e.Tags)
	if lastError != nil {
		e.LastError = *lastError
	}
	return &e, nil
}

// UpsertIOCEnrichmentSuccess caches a successful lookup, starting a fresh TTL.
// Only success-related columns are written -- a prior failure's
// last_failure_at/last_error stay as historical record.
func UpsertIOCEnrichmentSuccess(ctx context.Context, pool *pgxpool.Pool, indicatorType, indicatorValue, provider string, result *ioc.Result, lookupDurationMs int, ttlExpiresAt time.Time) error {
	pulseNamesJSON, _ := json.Marshal(result.PulseNames)
	malwareJSON, _ := json.Marshal(result.MalwareFamilies)
	adversaryJSON, _ := json.Marshal(result.AdversaryNames)
	industriesJSON, _ := json.Marshal(result.Industries)
	tagsJSON, _ := json.Marshal(result.Tags)

	_, err := pool.Exec(ctx,
		`INSERT INTO ioc_enrichment
		 (indicator_type, indicator_value, provider, provider_version, schema_version,
		  pulse_count, pulse_names, malware_families, adversary_names, industries, tags,
		  raw_response, lookup_duration_ms, last_success_at, ttl_expires_at)
		 VALUES ($1,$2,$3,'',$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb,$10::jsonb,$11::jsonb,$12,NOW(),$13)
		 ON CONFLICT (indicator_type, indicator_value, provider) DO UPDATE SET
		   schema_version = EXCLUDED.schema_version,
		   pulse_count = EXCLUDED.pulse_count,
		   pulse_names = EXCLUDED.pulse_names,
		   malware_families = EXCLUDED.malware_families,
		   adversary_names = EXCLUDED.adversary_names,
		   industries = EXCLUDED.industries,
		   tags = EXCLUDED.tags,
		   raw_response = EXCLUDED.raw_response,
		   lookup_duration_ms = EXCLUDED.lookup_duration_ms,
		   last_success_at = NOW(),
		   ttl_expires_at = EXCLUDED.ttl_expires_at`,
		indicatorType, indicatorValue, provider, currentEnrichmentSchemaVersion,
		result.PulseCount, pulseNamesJSON, malwareJSON, adversaryJSON, industriesJSON, tagsJSON,
		[]byte(result.RawResponse), lookupDurationMs, ttlExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("ioc enrichment upsert success: %w", err)
	}
	return nil
}

// UpsertIOCEnrichmentFailure records a failed lookup attempt without clearing
// any previously-cached successful data, starting a fresh TTL so a struggling
// provider isn't retried on every single run's enrichment pass.
func UpsertIOCEnrichmentFailure(ctx context.Context, pool *pgxpool.Pool, indicatorType, indicatorValue, provider string, lookupErr error, ttlExpiresAt time.Time) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO ioc_enrichment
		 (indicator_type, indicator_value, provider, schema_version, pulse_count,
		  last_failure_at, last_error, ttl_expires_at)
		 VALUES ($1,$2,$3,$4,0,NOW(),$5,$6)
		 ON CONFLICT (indicator_type, indicator_value, provider) DO UPDATE SET
		   last_failure_at = NOW(),
		   last_error = EXCLUDED.last_error,
		   ttl_expires_at = EXCLUDED.ttl_expires_at`,
		indicatorType, indicatorValue, provider, currentEnrichmentSchemaVersion,
		lookupErr.Error(), ttlExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("ioc enrichment upsert failure: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Wire schema bootstrap into the Docker-Postgres test harness**

In `orchestrator/internal/testutil/testdb.go`, find (around line 75-79):

```go
	if err := db.EnsureIOCSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("testutil: EnsureIOCSchema: %w", err)
	}

	return &TestDB{
```

Replace with:

```go
	if err := db.EnsureIOCSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("testutil: EnsureIOCSchema: %w", err)
	}
	if err := db.EnsureIOCEnrichmentSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("testutil: EnsureIOCEnrichmentSchema: %w", err)
	}

	return &TestDB{
```

- [ ] **Step 5: Wire schema bootstrap into server startup**

In `orchestrator/cmd/server/main.go`, find (around line 86-89):

```go
	if err := db.EnsureIOCSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] ioc schema bootstrap: %v", err)
	}
	log.Println("[+] Schema verified")
```

Replace with:

```go
	if err := db.EnsureIOCSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] ioc schema bootstrap: %v", err)
	}
	if err := db.EnsureIOCEnrichmentSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] ioc enrichment schema bootstrap: %v", err)
	}
	log.Println("[+] Schema verified")
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd orchestrator
go test ./internal/db/... -run "TestUpsertIOCEnrichment|TestGetIOCEnrichment|TestIOCEnrichment" -v
```
Expected: all `PASS`.

- [ ] **Step 7: Run the full db package suite to confirm no regressions**

```bash
cd orchestrator
go test ./internal/db/... -v 2>&1 | tail -50
```
Expected: all tests `PASS`, including sub-project B's `ioc_test.go` and every pre-existing test.

- [ ] **Step 8: Build and vet**

```bash
cd orchestrator
go vet ./internal/db/... ./internal/testutil/... ./cmd/server/...
go build ./...
```
Expected: no vet output, build succeeds.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/db/ioc_enrichment.go orchestrator/internal/db/ioc_enrichment_test.go orchestrator/internal/testutil/testdb.go orchestrator/cmd/server/main.go
git commit -m "feat(ioc): add ioc_enrichment cache table (provider-aware, TTL, failure-tracking)"
```

---

### Task 3: Background enrichment job — `Handler.enrichRunIOCs`

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (add `enrichRunIOCs`, wire into `SubmitScenarioResult`)
- Create: `orchestrator/internal/api/ioc_enrichment_test.go`

**Interfaces:**
- Consumes: `ioc.Lookup`, `Provider.Name()` (Task 1); `db.GetIOCEnrichment`, `db.UpsertIOCEnrichmentSuccess`, `db.UpsertIOCEnrichmentFailure` (Task 2); `db.GetRunIOCs` (sub-project B, already exists).
- Produces: `func (h *Handler) enrichRunIOCs(ctx context.Context, runID string)` — called via `go h.enrichRunIOCs(...)` from `SubmitScenarioResult`. No new HTTP surface.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/api/ioc_enrichment_test.go`. Uses a stub `ioc.Provider` injected via the existing `WithIOCProvider` builder (no real OTX calls) and the existing `sharedDB` Docker-Postgres harness (declared in `testmain_test.go`, same `api` test package).

```go
package api

import (
	"context"
	"errors"
	"testing"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/ioc"
)

type stubIOCProvider struct {
	name       string
	failValues map[string]bool // value -> whether this call should error
	calls      int
}

func (s *stubIOCProvider) Name() string { return s.name }
func (s *stubIOCProvider) lookup(v string) (*ioc.Result, error) {
	s.calls++
	if s.failValues[v] {
		return nil, errors.New("stub provider error")
	}
	return &ioc.Result{Indicator: v, Provider: s.name, PulseCount: 3}, nil
}
func (s *stubIOCProvider) LookupIP(ctx context.Context, v string) (*ioc.Result, error)     { return s.lookup(v) }
func (s *stubIOCProvider) LookupDomain(ctx context.Context, v string) (*ioc.Result, error) { return s.lookup(v) }
func (s *stubIOCProvider) LookupURL(ctx context.Context, v string) (*ioc.Result, error)    { return s.lookup(v) }
func (s *stubIOCProvider) LookupHash(ctx context.Context, v string) (*ioc.Result, error)   { return s.lookup(v) }
func (s *stubIOCProvider) LookupCVE(ctx context.Context, v string) (*ioc.Result, error)    { return s.lookup(v) }

func seedRunIOC(t *testing.T, runID string, indicators []ioc.RunIndicator) {
	t.Helper()
	if err := db.UpsertRunIOCs(context.Background(), sharedDB.Pool, runID, "test-scenario", indicators); err != nil {
		t.Fatalf("seedRunIOC: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(context.Background(), `DELETE FROM run_iocs WHERE run_id = $1`, runID)
	})
}

func TestEnrichRunIOCs_NoProviderConfigured_NoOp(t *testing.T) {
	const runID = "test-enrich-noprovider"
	seedRunIOC(t, runID, []ioc.RunIndicator{{Type: "ip", Value: "45.33.32.156"}})

	h := New(sharedDB.Pool, nil, nil, "secret") // iocProvider left nil
	h.enrichRunIOCs(context.Background(), runID)

	got, err := db.GetIOCEnrichment(context.Background(), sharedDB.Pool, "ip", "45.33.32.156", "otx")
	if err != nil {
		t.Fatalf("GetIOCEnrichment: %v", err)
	}
	if got != nil {
		t.Errorf("got %+v, want no cache row written when no provider is configured", got)
	}
}

func TestEnrichRunIOCs_NewIndicator_CallsProviderAndCaches(t *testing.T) {
	const runID = "test-enrich-new"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(context.Background(), `DELETE FROM ioc_enrichment WHERE indicator_value = $1`, "198.51.100.10")
	})
	seedRunIOC(t, runID, []ioc.RunIndicator{{Type: "ip", Value: "198.51.100.10"}})

	stub := &stubIOCProvider{name: "otx", failValues: map[string]bool{}}
	h := New(sharedDB.Pool, nil, nil, "secret").WithIOCProvider(stub)
	h.enrichRunIOCs(context.Background(), runID)

	if stub.calls != 1 {
		t.Fatalf("provider called %d times, want 1", stub.calls)
	}
	got, err := db.GetIOCEnrichment(context.Background(), sharedDB.Pool, "ip", "198.51.100.10", "otx")
	if err != nil || got == nil || got.PulseCount != 3 {
		t.Fatalf("got %+v, err=%v", got, err)
	}
}

func TestEnrichRunIOCs_FreshCacheHit_SkipsProviderCall(t *testing.T) {
	const runID = "test-enrich-cachehit"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(context.Background(), `DELETE FROM ioc_enrichment WHERE indicator_value = $1`, "198.51.100.20")
	})
	seedRunIOC(t, runID, []ioc.RunIndicator{{Type: "ip", Value: "198.51.100.20"}})

	stub := &stubIOCProvider{name: "otx", failValues: map[string]bool{}}
	h := New(sharedDB.Pool, nil, nil, "secret").WithIOCProvider(stub)
	h.enrichRunIOCs(context.Background(), runID) // first pass populates the cache
	h.enrichRunIOCs(context.Background(), runID) // second pass should hit the cache

	if stub.calls != 1 {
		t.Errorf("provider called %d times, want exactly 1 (second pass should be a cache hit)", stub.calls)
	}
}

func TestEnrichRunIOCs_FailedLookup_CachesFailureNotSuccess(t *testing.T) {
	const runID = "test-enrich-fail"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(context.Background(), `DELETE FROM ioc_enrichment WHERE indicator_value = $1`, "198.51.100.30")
	})
	seedRunIOC(t, runID, []ioc.RunIndicator{{Type: "ip", Value: "198.51.100.30"}})

	stub := &stubIOCProvider{name: "otx", failValues: map[string]bool{"198.51.100.30": true}}
	h := New(sharedDB.Pool, nil, nil, "secret").WithIOCProvider(stub)
	h.enrichRunIOCs(context.Background(), runID)

	got, err := db.GetIOCEnrichment(context.Background(), sharedDB.Pool, "ip", "198.51.100.30", "otx")
	if err != nil || got == nil {
		t.Fatalf("got %+v, err=%v -- a failed lookup must still create a cache row", got, err)
	}
	if got.LastFailureAt == nil || got.LastError != "stub provider error" {
		t.Errorf("failure not recorded correctly: %+v", got)
	}
	if got.LastSuccessAt != nil {
		t.Error("LastSuccessAt should be nil -- this lookup only ever failed")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd orchestrator
go test ./internal/api/... -run TestEnrichRunIOCs -v
```
Expected: FAIL to compile — `h.enrichRunIOCs undefined`.

- [ ] **Step 3: Implement `enrichRunIOCs` and wire it into `SubmitScenarioResult`**

In `orchestrator/internal/api/handlers.go`, find (around line 1896-1906):

```go
	h.persistVariantResults(r.Context(), raw.RunID, raw.ScenarioID, simResults, dispatchedMeta)

	// IOC extraction — parse stdout/stderr/details for indicators (IPs, domains,
	// URLs, hashes, CVEs). Non-fatal: extraction failure must not fail result
	// ingestion, since this is enrichment, not core scoring. Runs on partial
	// runs too — completed steps' output is still real evidence.
	indicators := ioc.BuildRunIndicators(raw.Results, raw.Checks, stepMap)
	if err := db.UpsertRunIOCs(r.Context(), h.db, raw.RunID, raw.ScenarioID, indicators); err != nil {
		log.Printf("[!] ioc extraction: failed to persist for run %s: %v", raw.RunID, err)
	}

	// Pre-compute per-technique variant summary then, if the run belongs to a
```

Replace with:

```go
	h.persistVariantResults(r.Context(), raw.RunID, raw.ScenarioID, simResults, dispatchedMeta)

	// IOC extraction — parse stdout/stderr/details for indicators (IPs, domains,
	// URLs, hashes, CVEs). Non-fatal: extraction failure must not fail result
	// ingestion, since this is enrichment, not core scoring. Runs on partial
	// runs too — completed steps' output is still real evidence.
	indicators := ioc.BuildRunIndicators(raw.Results, raw.Checks, stepMap)
	if err := db.UpsertRunIOCs(r.Context(), h.db, raw.RunID, raw.ScenarioID, indicators); err != nil {
		log.Printf("[!] ioc extraction: failed to persist for run %s: %v", raw.RunID, err)
	}
	// Threat-intel enrichment — background, never blocks this response. Uses a
	// fresh context because the HTTP request context will be cancelled by the
	// time the goroutine runs (same pattern as refreshComplianceSnapshots below).
	go h.enrichRunIOCs(context.Background(), raw.RunID)

	// Pre-compute per-technique variant summary then, if the run belongs to a
```

Then add the new method near the other background-job methods. Find the end of `refreshComplianceSnapshots` and the start of the next handler (around line 3995-4007):

```go
			FailingControls:  s.FailingControls,
			ManualControls:   s.ManualControls,
		})
	}
}

// GET /api/compliance/scores[?agentId=X]
// Returns compliance scores for all frameworks for one agent (agentId provided)
// or fleet-wide worst-case per framework (no agentId — CISO dashboard view).
// Scores come from compliance_snapshots — O(1) read, no recomputation.
// Falls back to zero-state entries when no runs have completed yet, so the
// dashboard can always render all 6 framework tiles.
func (h *Handler) GetComplianceDashboardScores(w http.ResponseWriter, r *http.Request) {
```

Replace with:

```go
			FailingControls:  s.FailingControls,
			ManualControls:   s.ManualControls,
		})
	}
}

const iocEnrichmentTTL = 24 * time.Hour

// enrichRunIOCs is the enrichment pipeline entry point: for every distinct
// indicator extracted from a run, ask the configured threat-intel provider
// about it -- unless a fresh cache row already exists. Never blocks the HTTP
// response (always called via `go`). No-op when no provider is configured.
func (h *Handler) enrichRunIOCs(ctx context.Context, runID string) {
	if h.iocProvider == nil {
		return
	}
	indicators, err := db.GetRunIOCs(ctx, h.db, runID, "", "")
	if err != nil {
		log.Printf("[!] ioc enrichment: failed to load indicators for run %s: %v", runID, err)
		return
	}
	providerName := h.iocProvider.Name()
	for _, ind := range indicators {
		cached, err := db.GetIOCEnrichment(ctx, h.db, ind.Type, ind.Value, providerName)
		if err != nil {
			log.Printf("[!] ioc enrichment: cache read failed for %s %s: %v", ind.Type, ind.Value, err)
			continue
		}
		if cached != nil && cached.TTLExpiresAt.After(time.Now()) {
			continue // fresh cache hit -- no external call
		}

		start := time.Now()
		result, lookupErr := ioc.Lookup(ctx, h.iocProvider, ind.Type, ind.Value)
		durationMs := int(time.Since(start).Milliseconds())
		ttlExpiresAt := time.Now().Add(iocEnrichmentTTL)

		if lookupErr != nil {
			if err := db.UpsertIOCEnrichmentFailure(ctx, h.db, ind.Type, ind.Value, providerName, lookupErr, ttlExpiresAt); err != nil {
				log.Printf("[!] ioc enrichment: failed to cache failure for %s %s: %v", ind.Type, ind.Value, err)
			}
			continue
		}
		if err := db.UpsertIOCEnrichmentSuccess(ctx, h.db, ind.Type, ind.Value, providerName, result, durationMs, ttlExpiresAt); err != nil {
			log.Printf("[!] ioc enrichment: failed to cache result for %s %s: %v", ind.Type, ind.Value, err)
		}
	}
}

// GET /api/compliance/scores[?agentId=X]
// Returns compliance scores for all frameworks for one agent (agentId provided)
// or fleet-wide worst-case per framework (no agentId — CISO dashboard view).
// Scores come from compliance_snapshots — O(1) read, no recomputation.
// Falls back to zero-state entries when no runs have completed yet, so the
// dashboard can always render all 6 framework tiles.
func (h *Handler) GetComplianceDashboardScores(w http.ResponseWriter, r *http.Request) {
```

**Important:** that `GetComplianceDashboardScores` comment + signature is the same one from the "Find" block above — it must still appear exactly once, now after `enrichRunIOCs` instead of immediately after `refreshComplianceSnapshots`. Don't duplicate it and don't drop it.

Check that `"time"` is already imported in `handlers.go` (it is — used extensively elsewhere in the file, e.g. `time.Now()` in the perf-metrics block).

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd orchestrator
go test ./internal/api/... -run TestEnrichRunIOCs -v
```
Expected: all `PASS`.

- [ ] **Step 5: Build and vet**

```bash
cd orchestrator
go build ./... && echo BUILD_OK
go vet ./... && echo VET_OK
```
Expected: `BUILD_OK`, `VET_OK`.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/ioc_enrichment_test.go
git commit -m "feat(ioc): background enrichRunIOCs job, wired into SubmitScenarioResult"
```

---

### Task 4: Report data — `FullReport.ThreatIntel` + `populateThreatIntel`

**Files:**
- Modify: `orchestrator/internal/reporting/engine.go` (Engine field + `WithThreatIntelProvider`, `FullReport.ThreatIntel` field, new types, `populateThreatIntel`, `BuildFromRun` wiring)
- Create: `orchestrator/internal/reporting/threat_intel_test.go`
- Modify: `orchestrator/cmd/server/main.go:318-327` (wire `WithThreatIntelProvider`)

**Interfaces:**
- Consumes: `run_iocs`/`ioc_enrichment` tables (Task 2/3, read via raw SQL — matches this file's existing convention of self-contained queries, not calling `internal/db` helpers).
- Produces: `Engine.WithThreatIntelProvider(name string) *Engine`, `FullReport.ThreatIntel *ThreatIntelSection`, `ThreatIntelSection`/`ThreatIntelSummary`/`ThreatIntelIndicator` types — consumed by Task 5's HTML template.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/reporting/threat_intel_test.go`. Uses the existing `sharedDB` Docker-Postgres harness declared in this package's `testmain_test.go`.

```go
package reporting_test

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/ioc"
	"github.com/audspect/bas/internal/reporting"
)

func seedRunIOCForReport(t *testing.T, runID string) {
	t.Helper()
	indicators := []ioc.RunIndicator{
		{Type: "ip", Value: "45.33.32.156", Confidence: 95, Source: "stdout", TechniqueIDs: []string{"T1071"}, SimulationIDs: []string{"T1071::A"}},
		{Type: "domain", Value: "evil.example.com", Confidence: 80, Source: "stdout", TechniqueIDs: []string{"T1071"}, SimulationIDs: []string{"T1071::A"}},
		{Type: "hash", Value: "44d88612fea8a8f36de82e1278abb02f", Confidence: 100, Source: "details", TechniqueIDs: []string{"T1105"}, SimulationIDs: []string{"T1105::B"}},
	}
	if err := db.UpsertRunIOCs(context.Background(), sharedDB.Pool, runID, "test-scenario", indicators); err != nil {
		t.Fatalf("seedRunIOCForReport: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(context.Background(), `DELETE FROM run_iocs WHERE run_id = $1`, runID)
	})
}

func seedEnrichment(t *testing.T, typ, val string, pulseCount int) {
	t.Helper()
	result := &ioc.Result{Indicator: val, Type: typ, Provider: "otx", PulseCount: pulseCount}
	if err := db.UpsertIOCEnrichmentSuccess(context.Background(), sharedDB.Pool, typ, val, "otx", result, 10, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("seedEnrichment: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(context.Background(), `DELETE FROM ioc_enrichment WHERE indicator_type=$1 AND indicator_value=$2`, typ, val)
	})
}

// seedScenarioRun inserts the minimal agents + scenario_runs rows BuildFromRun
// needs to find the run at all (it errors with "run not found" otherwise).
// Every other scenario_runs column BuildFromRun reads is either nullable or
// has a table-level default (results/reverted default to '[]', score/
// completed_at/detection_summary/detection_rate/undetected_rate/mttd_ms are
// nullable, all perf_*/alerts_*/noise_score/steps_*_base columns default to
// 0) -- confirmed against the CREATE TABLE + ALTER TABLE statements in
// internal/db/postgres.go.
func seedScenarioRun(t *testing.T, runID, agentID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := sharedDB.Pool.Exec(ctx,
		`INSERT INTO agents (agent_id) VALUES ($1) ON CONFLICT (agent_id) DO NOTHING`, agentID,
	); err != nil {
		t.Fatalf("seedScenarioRun: insert agent: %v", err)
	}
	if _, err := sharedDB.Pool.Exec(ctx,
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, status) VALUES ($1, 'test-scenario', $2, 'completed')`,
		runID, agentID,
	); err != nil {
		t.Fatalf("seedScenarioRun: insert scenario_run: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(context.Background(), `DELETE FROM scenario_runs WHERE id = $1`, runID)
		_, _ = sharedDB.Pool.Exec(context.Background(), `DELETE FROM agents WHERE agent_id = $1`, agentID)
	})
}

func TestPopulateThreatIntel_MixedTiers(t *testing.T) {
	const runID = "test-report-threatintel"
	seedScenarioRun(t, runID, "test-agent-threatintel")
	seedRunIOCForReport(t, runID)
	seedEnrichment(t, "ip", "45.33.32.156", 5)   // malicious-associated
	seedEnrichment(t, "domain", "evil.example.com", 1) // suspicious
	// hash "44d88612..." is left un-enriched -> pending

	e := reporting.NewEngine(sharedDB.Pool).WithThreatIntelProvider("otx")
	report, err := e.BuildFromRun(context.Background(), runID, "")
	if err != nil {
		t.Fatalf("BuildFromRun: %v", err)
	}
	if report.ThreatIntel == nil {
		t.Fatal("ThreatIntel is nil, want a populated section")
	}
	s := report.ThreatIntel.Summary
	if s.ExtractedCount != 3 {
		t.Errorf("ExtractedCount = %d, want 3", s.ExtractedCount)
	}
	if s.MaliciousAssociatedCount != 1 || s.SuspiciousCount != 1 || s.PendingCount != 1 {
		t.Errorf("got %+v", s)
	}
	if len(report.ThreatIntel.Indicators) != 3 {
		t.Fatalf("got %d indicators, want 3", len(report.ThreatIntel.Indicators))
	}
	if report.ThreatIntel.Indicators[0].Tier != "malicious-associated" {
		t.Errorf("Indicators[0].Tier = %q, want malicious-associated (worst-first sort)", report.ThreatIntel.Indicators[0].Tier)
	}
}

func TestPopulateThreatIntel_NoProviderConfigured_NilSection(t *testing.T) {
	const runID = "test-report-threatintel-noprovider"
	seedScenarioRun(t, runID, "test-agent-threatintel-noprovider")
	seedRunIOCForReport(t, runID)

	e := reporting.NewEngine(sharedDB.Pool) // WithThreatIntelProvider never called
	report, err := e.BuildFromRun(context.Background(), runID, "")
	if err != nil {
		t.Fatalf("BuildFromRun: %v", err)
	}
	if report.ThreatIntel != nil {
		t.Error("ThreatIntel should be nil when no provider is configured")
	}
}

func TestPopulateThreatIntel_NoIOCs_NilSection(t *testing.T) {
	const runID = "test-report-threatintel-noiocs"
	seedScenarioRun(t, runID, "test-agent-threatintel-noiocs")

	e := reporting.NewEngine(sharedDB.Pool).WithThreatIntelProvider("otx")
	report, err := e.BuildFromRun(context.Background(), runID, "")
	if err != nil {
		t.Fatalf("BuildFromRun: %v", err)
	}
	if report.ThreatIntel != nil {
		t.Error("ThreatIntel should be nil for a run with no run_iocs rows")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd orchestrator
go test ./internal/reporting/... -run TestPopulateThreatIntel -v
```
Expected: FAIL to compile — `e.WithThreatIntelProvider undefined`, `report.ThreatIntel undefined`.

- [ ] **Step 3: Add the Engine field, builder method, and report types**

In `orchestrator/internal/reporting/engine.go`, find the `Engine` struct and `WithSectorRegion` (around lines 56-100):

```go
type Engine struct {
	db            *pgxpool.Pool
	scenarios     ScenarioResolver     // nil until WithScenarios is called; Detection Validation stays inactive while nil
	verifications VerificationResolver // nil until WithVerifications is called; only automatic verdicts contribute while nil
	rules         RuleLibraryResolver  // nil until WithRuleLibrary is called; Attack Path Detection Coverage stays inactive while nil
	// sectors/regions are the deployment's own configured values
	// (config.Config.ThreatIntelSectors/ThreatIntelRegions), set via
	// WithSectorRegion. Empty means priority scores never get the
	// sector/region bonus. See
	// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	sectors []string
	regions []string
}
```

Replace with:

```go
type Engine struct {
	db            *pgxpool.Pool
	scenarios     ScenarioResolver     // nil until WithScenarios is called; Detection Validation stays inactive while nil
	verifications VerificationResolver // nil until WithVerifications is called; only automatic verdicts contribute while nil
	rules         RuleLibraryResolver  // nil until WithRuleLibrary is called; Attack Path Detection Coverage stays inactive while nil
	// sectors/regions are the deployment's own configured values
	// (config.Config.ThreatIntelSectors/ThreatIntelRegions), set via
	// WithSectorRegion. Empty means priority scores never get the
	// sector/region bonus. See
	// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	sectors []string
	regions []string
	// threatIntelProvider is the configured ioc.Provider's name (e.g. "otx"),
	// set via WithThreatIntelProvider. Empty means the Threat Intelligence
	// section stays inactive -- matches the same "nil/empty means feature off"
	// convention as the fields above.
	threatIntelProvider string
}
```

Find `WithSectorRegion` and the start of the next method (around line 94-106):

```go
// WithSectorRegion attaches the deployment's own sector/region, used to
// weight technique priority scores toward actors that target them. Returns
// the engine for chaining.
func (e *Engine) WithSectorRegion(sectors, regions []string) *Engine {
	e.sectors = sectors
	e.regions = regions
	return e
}

// Sectors returns the configured deployment sectors, for callers (like
```

Replace with:

```go
// WithSectorRegion attaches the deployment's own sector/region, used to
// weight technique priority scores toward actors that target them. Returns
// the engine for chaining.
func (e *Engine) WithSectorRegion(sectors, regions []string) *Engine {
	e.sectors = sectors
	e.regions = regions
	return e
}

// WithThreatIntelProvider attaches the name of the configured ioc.Provider
// (e.g. "otx") so populateThreatIntel knows which provider's ioc_enrichment
// rows to read -- the cache is provider-keyed, so an unfiltered join would be
// ambiguous if a provider is ever switched and old rows linger. Returns the
// engine for chaining.
func (e *Engine) WithThreatIntelProvider(name string) *Engine {
	e.threatIntelProvider = name
	return e
}

// Sectors returns the configured deployment sectors, for callers (like
```
```

Find the end of the `FullReport` struct (around line 234-238):

```go
	// Coverage reports Scenario Coverage (executed/total) and Eligible Coverage
	// (executed/eligible) so a policy-constrained run reads as complete against
	// what it could run, not incomplete against everything the scenario defines.
	Coverage CoverageSummary `json:"coverage"`
}
```

Replace with:

```go
	// Coverage reports Scenario Coverage (executed/total) and Eligible Coverage
	// (executed/eligible) so a policy-constrained run reads as complete against
	// what it could run, not incomplete against everything the scenario defines.
	Coverage CoverageSummary `json:"coverage"`
	// ThreatIntel is the configured provider's enrichment of this run's
	// extracted IOCs (run_iocs). Nil when no provider is configured or the run
	// has no IOCs. Populated by BuildFromRun only (single-run reports).
	ThreatIntel *ThreatIntelSection `json:"threatIntel,omitempty"`
}

// ThreatIntelSection is the report's "did this execution produce artifacts
// known to threat intelligence" answer -- summary-first, then per-indicator
// detail. No field here is called "confidence": tiers are derived from raw
// pulse counts under honest, non-authoritative names.
type ThreatIntelSection struct {
	Provider   string                 `json:"provider"` // "otx"
	Summary    ThreatIntelSummary     `json:"summary"`
	Indicators []ThreatIntelIndicator `json:"indicators"` // sorted worst-tier-first
}

type ThreatIntelSummary struct {
	ExtractedCount           int `json:"extractedCount"`
	PendingCount             int `json:"pendingCount"`
	UnknownCount             int `json:"unknownCount"`
	SuspiciousCount          int `json:"suspiciousCount"`
	MaliciousAssociatedCount int `json:"maliciousAssociatedCount"`
}

type ThreatIntelIndicator struct {
	Type            string   `json:"type"` // ip | domain | url | hash | cve
	Value           string   `json:"value"`
	TechniqueIDs    []string `json:"techniqueIds"`
	SimulationIDs   []string `json:"simulationIds"`
	Tier            string   `json:"tier"` // pending | unknown | suspicious | malicious-associated
	PulseCount      int      `json:"pulseCount"`
	PulseNames      []string `json:"pulseNames,omitempty"`
	MalwareFamilies []string `json:"malwareFamilies,omitempty"`
	AdversaryNames  []string `json:"adversaryNames,omitempty"`
	Industries      []string `json:"industries,omitempty"`
	Tags            []string `json:"tags,omitempty"`
}
```

- [ ] **Step 4: Implement `populateThreatIntel`**

Find the end of `populateKEVExposure` and the start of the next section (around line 3300-3312):

```go
	report.KEVExposure = &exp

	// Enrich TopFindings with KEV flags.
	for i := range report.TopFindings {
		if kr, ok := kevMap[report.TopFindings[i].TechniqueID]; ok {
			report.TopFindings[i].KEV = true
			report.TopFindings[i].KEVCount = kr.count
		}
	}
}

// ── EPSS Priority Scores ──────────────────────────────────────────────────────
```

Replace with:

```go
	report.KEVExposure = &exp

	// Enrich TopFindings with KEV flags.
	for i := range report.TopFindings {
		if kr, ok := kevMap[report.TopFindings[i].TechniqueID]; ok {
			report.TopFindings[i].KEV = true
			report.TopFindings[i].KEVCount = kr.count
		}
	}
}

// populateThreatIntel joins run_iocs with ioc_enrichment for the configured
// provider and classifies each indicator into an honest, non-"confidence"
// tier based on raw pulse count. Leaves report.ThreatIntel nil when no
// provider is configured or the run has no extracted IOCs.
func (e *Engine) populateThreatIntel(ctx context.Context, report *FullReport, runID string) {
	if e.threatIntelProvider == "" {
		return
	}
	rows, err := e.db.Query(ctx, `
		SELECT ri.indicator_type, ri.indicator_value, ri.technique_ids, ri.simulation_ids,
		       ie.pulse_count, ie.pulse_names, ie.malware_families, ie.adversary_names,
		       ie.industries, ie.tags, ie.last_success_at
		FROM run_iocs ri
		LEFT JOIN ioc_enrichment ie
		  ON ie.indicator_type = ri.indicator_type
		 AND ie.indicator_value = ri.indicator_value
		 AND ie.provider = $2
		WHERE ri.run_id = $1`, runID, e.threatIntelProvider)
	if err != nil {
		return
	}
	defer rows.Close()

	var allIndicators []ThreatIntelIndicator
	var extracted, pending, unknown, suspicious, malicious int
	for rows.Next() {
		var techniqueIDsJSON, simulationIDsJSON []byte
		var pulseNamesJSON, malwareJSON, adversaryJSON, industriesJSON, tagsJSON []byte
		var pulseCount *int
		var lastSuccessAt *time.Time
		var ind ThreatIntelIndicator
		if err := rows.Scan(&ind.Type, &ind.Value, &techniqueIDsJSON, &simulationIDsJSON,
			&pulseCount, &pulseNamesJSON, &malwareJSON, &adversaryJSON, &industriesJSON, &tagsJSON,
			&lastSuccessAt); err != nil {
			continue
		}
		_ = json.Unmarshal(techniqueIDsJSON, &ind.TechniqueIDs)
		_ = json.Unmarshal(simulationIDsJSON, &ind.SimulationIDs)

		extracted++
		// No row at all (pulseCount nil), or a row that only ever recorded
		// failures (lastSuccessAt nil) -- either way we have no confirmed
		// pulse data to show, so this indicator is "pending", not "unknown".
		if pulseCount == nil || lastSuccessAt == nil {
			ind.Tier = "pending"
			pending++
		} else {
			ind.PulseCount = *pulseCount
			_ = json.Unmarshal(pulseNamesJSON, &ind.PulseNames)
			_ = json.Unmarshal(malwareJSON, &ind.MalwareFamilies)
			_ = json.Unmarshal(adversaryJSON, &ind.AdversaryNames)
			_ = json.Unmarshal(industriesJSON, &ind.Industries)
			_ = json.Unmarshal(tagsJSON, &ind.Tags)
			switch {
			case ind.PulseCount >= 3:
				ind.Tier = "malicious-associated"
				malicious++
			case ind.PulseCount >= 1:
				ind.Tier = "suspicious"
				suspicious++
			default:
				ind.Tier = "unknown"
				unknown++
			}
		}
		allIndicators = append(allIndicators, ind)
	}
	if extracted == 0 {
		return
	}

	tierRank := map[string]int{"malicious-associated": 0, "suspicious": 1, "unknown": 2, "pending": 3}
	sort.Slice(allIndicators, func(i, j int) bool {
		return tierRank[allIndicators[i].Tier] < tierRank[allIndicators[j].Tier]
	})

	report.ThreatIntel = &ThreatIntelSection{
		Provider: e.threatIntelProvider,
		Summary: ThreatIntelSummary{
			ExtractedCount:           extracted,
			PendingCount:             pending,
			UnknownCount:             unknown,
			SuspiciousCount:          suspicious,
			MaliciousAssociatedCount: malicious,
		},
		Indicators: allIndicators,
	}
}

// ── EPSS Priority Scores ──────────────────────────────────────────────────────
```

**Important:** that last `// ── EPSS Priority Scores ──` divider line is the same one from the "Find" block above — it must still appear exactly once, now after `populateThreatIntel` instead of immediately after `populateKEVExposure`. Don't duplicate it and don't drop it.

`context`, `encoding/json`, `sort`, and `time` are already imported in `engine.go` — no import changes needed.

- [ ] **Step 5: Wire the call into `BuildFromRun`**

In `orchestrator/internal/reporting/engine.go`, find (around line 1753):

```go
	e.populateKEVExposure(ctx, report)
	e.populatePriorityScores(ctx, report)

	return report, nil
}

// BuildFromCampaign constructs a fleet-wide FullReport for a campaign by
```

Replace with:

```go
	e.populateKEVExposure(ctx, report)
	e.populateThreatIntel(ctx, report, runID)
	e.populatePriorityScores(ctx, report)

	return report, nil
}

// BuildFromCampaign constructs a fleet-wide FullReport for a campaign by
```

**Caution:** `populateKEVExposure(ctx, report)` also appears inside `Build` (line ~1461) and `BuildFromCampaign` (line ~1960) — do NOT add `populateThreatIntel` there. Per the spec, this is single-run-report-only; only the `BuildFromRun` occurrence (the one immediately followed by `BuildFromCampaign`'s function signature) gets the new call. Use the surrounding `return report, nil` + next function comment shown above to confirm you're editing the right occurrence.

- [ ] **Step 6: Wire `WithThreatIntelProvider` in `main.go`**

In `orchestrator/cmd/server/main.go`, find (around line 318-327):

```go
	var iocProvider ioc.Provider
	if cfg.OTXAPIKey != "" {
		var err error
		iocProvider, err = ioc.NewProvider(ioc.Config{Provider: "otx", APIKey: cfg.OTXAPIKey})
		if err != nil {
			log.Printf("[!] ioc provider init warning: %v", err)
		} else {
			log.Println("[+] IOC threat-intel provider ready (OTX)")
		}
	}
```

Replace with:

```go
	var iocProvider ioc.Provider
	if cfg.OTXAPIKey != "" {
		var err error
		iocProvider, err = ioc.NewProvider(ioc.Config{Provider: "otx", APIKey: cfg.OTXAPIKey})
		if err != nil {
			log.Printf("[!] ioc provider init warning: %v", err)
		} else {
			log.Println("[+] IOC threat-intel provider ready (OTX)")
			reportingEngine.WithThreatIntelProvider(iocProvider.Name())
		}
	}
```

`reportingEngine` is already in scope here — it's constructed earlier at line ~200 and used again later at line ~338 (`.WithReporting(reportingEngine)`); calling a `With*` method on it in between is safe since it's a pointer and both call sites reference the same underlying `*Engine`.

- [ ] **Step 7: Run tests to verify they pass**

```bash
cd orchestrator
go test ./internal/reporting/... -run TestPopulateThreatIntel -v
```
Expected: all `PASS`.

- [ ] **Step 8: Run the full reporting package suite to confirm no regressions**

```bash
cd orchestrator
go test ./internal/reporting/... 2>&1 | tail -20
```
Expected: `ok`.

- [ ] **Step 9: Build and vet**

```bash
cd orchestrator
go build ./... && echo BUILD_OK
go vet ./... && echo VET_OK
```
Expected: `BUILD_OK`, `VET_OK`.

- [ ] **Step 10: Commit**

```bash
git add orchestrator/internal/reporting/engine.go orchestrator/internal/reporting/threat_intel_test.go orchestrator/cmd/server/main.go
git commit -m "feat(ioc): populate FullReport.ThreatIntel from run_iocs + ioc_enrichment"
```

---

### Task 5: HTML/PDF report section + live end-to-end verification

**Files:**
- Modify: `orchestrator/internal/reporting/html.go` (new "Threat Intelligence" page section)

**Interfaces:**
- Consumes: `FullReport.ThreatIntel` (Task 4), reaches the template via the existing JSON-marshal-to-map step (`html.go`'s `json.Marshal(payload)` / `json.Unmarshal(raw, &data)`, already confirmed present around line 520-525) — no template-wiring code changes needed beyond the new markup block itself.

- [ ] **Step 1: Add the template section**

In `orchestrator/internal/reporting/html.go`, find the end of the last existing report section (Section 20, "Technical Appendix — ATT&CK Glossary") — its closing structure looks like:

```go
<div class="pf">
  <span>{{.agent.hostname}} — ATT&amp;CK Glossary</span>
  <span>Generated {{fmtTime .generatedAt}} &nbsp;·&nbsp; Audspect BAS Platform &nbsp;·&nbsp; CONFIDENTIAL</span>
</div>
</div>
</div>

</body>
</html>`
```

Insert a new section immediately before the blank line + `</body>`:

```go
<div class="pf">
  <span>{{.agent.hostname}} — ATT&amp;CK Glossary</span>
  <span>Generated {{fmtTime .generatedAt}} &nbsp;·&nbsp; Audspect BAS Platform &nbsp;·&nbsp; CONFIDENTIAL</span>
</div>
</div>
</div>

<!-- ═══ 21. THREAT INTELLIGENCE ═══════════════════════════════════════════ -->
{{if .threatIntel}}
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 21</div>
<div class="stitle">Threat Intelligence</div>

<p style="color:#6e7681;margin-bottom:14px">Indicators of compromise (IPs, domains, URLs, file hashes, CVEs) observed in this run's execution evidence, checked against {{.threatIntel.provider}} threat intelligence. Answers: did this execution produce artifacts already known to the security community?</p>

<div class="score-row">
  <div class="scard">
    <div class="scard-label">Extracted IOCs</div>
    <div class="scard-value">{{.threatIntel.summary.extractedCount}}</div>
  </div>
  <div class="scard" style="border-left:3px solid {{if gt .threatIntel.summary.maliciousAssociatedCount 0.0}}#da3633{{else}}#6e7681{{end}}">
    <div class="scard-label">Malicious-Associated</div>
    <div class="scard-value" style="color:{{if gt .threatIntel.summary.maliciousAssociatedCount 0.0}}#da3633{{else}}#6e7681{{end}}">{{.threatIntel.summary.maliciousAssociatedCount}}</div>
  </div>
  <div class="scard" style="border-left:3px solid {{if gt .threatIntel.summary.suspiciousCount 0.0}}#d29922{{else}}#6e7681{{end}}">
    <div class="scard-label">Suspicious</div>
    <div class="scard-value" style="color:{{if gt .threatIntel.summary.suspiciousCount 0.0}}#d29922{{else}}#6e7681{{end}}">{{.threatIntel.summary.suspiciousCount}}</div>
  </div>
  <div class="scard">
    <div class="scard-label">Unknown</div>
    <div class="scard-value">{{.threatIntel.summary.unknownCount}}</div>
  </div>
  <div class="scard">
    <div class="scard-label">Pending</div>
    <div class="scard-value">{{.threatIntel.summary.pendingCount}}</div>
  </div>
</div>

<table>
  <thead><tr><th>Type</th><th>Indicator</th><th>Technique(s)</th><th>Tier</th><th>Pulses</th><th>Malware / Adversary / Tags</th></tr></thead>
  {{range .threatIntel.indicators}}
  <tr>
    <td>{{upper .type}}</td>
    <td style="font-family:monospace;font-size:0.78rem">{{.value}}</td>
    <td style="font-size:0.78rem">{{range $i,$t := .techniqueIds}}{{if $i}}, {{end}}{{$t}}{{end}}</td>
    <td><strong style="{{if eq .tier "malicious-associated"}}color:#da3633{{else if eq .tier "suspicious"}}color:#d29922{{else if eq .tier "pending"}}color:#6e7681{{else}}color:#374151{{end}}">{{if eq .tier "malicious-associated"}}Malicious-Associated{{else if eq .tier "suspicious"}}Suspicious{{else if eq .tier "pending"}}Pending{{else}}Unknown{{end}}</strong></td>
    <td>{{.pulseCount}}</td>
    <td style="font-size:0.78rem">{{range $i,$m := .malwareFamilies}}{{if $i}}, {{end}}{{$m}}{{end}}{{if and .malwareFamilies .adversaryNames}} &nbsp;·&nbsp; {{end}}{{range $i,$a := .adversaryNames}}{{if $i}}, {{end}}{{$a}}{{end}}{{if and (or .malwareFamilies .adversaryNames) .tags}} &nbsp;·&nbsp; {{end}}{{range $i,$g := .tags}}{{if $i}}, {{end}}{{$g}}{{end}}</td>
  </tr>
  {{end}}
</table>

<div class="pf">
  <span>{{.agent.hostname}} — Threat Intelligence</span>
  <span>Generated {{fmtTime .generatedAt}} &nbsp;·&nbsp; Audspect BAS Platform &nbsp;·&nbsp; CONFIDENTIAL</span>
</div>
</div>
</div>
{{end}}

</body>
</html>`
```

- [ ] **Step 2: Run the reporting package's HTML rendering tests**

```bash
cd orchestrator
go test ./internal/reporting/... -run "TestHTML|TestHtml|Html" -v 2>&1 | tail -40
```
Expected: all `PASS` — these tests render a `FullReport` through the real template and check for parse/execution errors, so a template syntax mistake (unclosed `{{if}}`, bad field reference) will surface here immediately.

- [ ] **Step 3: Build and vet**

```bash
cd orchestrator
go build ./... && echo BUILD_OK
go vet ./... && echo VET_OK
```
Expected: `BUILD_OK`, `VET_OK`.

- [ ] **Step 4: Live end-to-end verification**

Matches sub-project B's methodology. Start a throwaway Postgres + the server:

```bash
docker rm -f ioc-enrich-live-pg 2>/dev/null
docker run -d --name ioc-enrich-live-pg -e POSTGRES_PASSWORD=postgres -p 55433:5432 postgres:16-alpine
sleep 3
cd orchestrator
DATABASE_URL="postgres://postgres:postgres@localhost:55433/postgres?sslmode=disable" \
JWT_SECRET="dev-secret" \
BAS_LICENSE_PATH="C:/Users/Administrator/Downloads/Audspect_Cloud/audspect-dev.lic" \
HTTP_PORT="8098" \
OTX_API_KEY="" \
nohup go run ./cmd/server > /tmp/ioc_enrich_live_server.log 2>&1 &
disown
sleep 12
cat /tmp/ioc_enrich_live_server.log
```

With `OTX_API_KEY` unset, `enrichRunIOCs` and `populateThreatIntel` both no-op (per the "no provider configured" degrade path) — this proves the whole pipeline stays inert and harmless without a key, matching sub-project A's precedent. Verify:

```bash
docker exec -i ioc-enrich-live-pg psql -U postgres -c "INSERT INTO agents (agent_id) VALUES ('test-agent-ti');"
docker exec -i ioc-enrich-live-pg psql -U postgres -c "INSERT INTO scenario_runs (id, scenario_id, agent_id, status) VALUES ('test-run-ti-live', 'test-scenario', 'test-agent-ti', 'running');"

TOKEN=$(curl -s -X POST http://localhost:8098/api/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"ChangeMe!2024"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

curl -s -X POST http://localhost:8098/api/scenarios/result \
  -H "Content-Type: application/json" \
  -d '{"runId":"test-run-ti-live","scenarioId":"test-scenario","agentId":"test-agent-ti","results":[{"taskId":"T1071::live-test","exitCode":0,"stdout":"beacon to 45.33.32.156","stderr":"","durationMs":100,"executedAt":"2026-07-21T00:00:00Z"}]}'

sleep 1
curl -s "http://localhost:8098/api/scenarios/runs/test-run-ti-live/report.json" -H "Authorization: Bearer $TOKEN" | grep -o '"threatIntel":[^}]*}' || echo "threatIntel absent (expected -- no OTX_API_KEY set)"
```

Expected: `run_iocs` gets the extracted IP (confirms sub-project B's path still works), and `report.json` has no `threatIntel` key (or it's absent from the grep) since `OTX_API_KEY` was empty — confirming the degrade path. A real-key run (optional, skip if no key is available — same caveat as every prior sub-project) would instead show `enrichRunIOCs` populate `ioc_enrichment` and `report.json` include a populated `threatIntel` section.

Clean up:

```bash
kill %1 2>/dev/null
docker rm -f ioc-enrich-live-pg
```

Also kill any orphaned `server.exe` still bound to port 8098 the same way sub-project B's live-verification did (`Get-NetTCPConnection -LocalPort 8098` → `Stop-Process -Id <pid> -Force` if found).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/reporting/html.go
git commit -m "feat(ioc): render Threat Intelligence section in HTML/PDF reports"
```

---

## Final Verification (after all tasks)

- [ ] Run the complete suite once more and confirm nothing regressed:

```bash
cd orchestrator
go build ./... && echo BUILD_OK
go vet ./... && echo VET_OK
go test ./... 2>&1 | tail -60
```
Expected: `BUILD_OK`, `VET_OK`, all packages `ok`. If `internal/pathcorrelation` (or any other Docker-backed package unrelated to this work) fails, re-run that package alone before concluding it's a real regression — sub-project B hit a transient Docker-parallelism flake here that turned out unrelated.

- [ ] Then proceed to **superpowers:finishing-a-development-branch** to wrap up.
