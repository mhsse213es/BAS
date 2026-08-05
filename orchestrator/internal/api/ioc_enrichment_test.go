package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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

// TestGetRunIOCs_HTTP_ReturnsEnrichedFieldsWhenProviderConfigured pins the
// GetRunIOCs HTTP handler (GET /api/scenarios/runs/{runId}/iocs) end-to-end:
// after enrichRunIOCs populates the cache, the endpoint's response must
// include the enrichment (tier/pulseCount), not just the raw indicator --
// this is what the run drawer's Indicators (IOCs) tab consumes.
func TestGetRunIOCs_HTTP_ReturnsEnrichedFieldsWhenProviderConfigured(t *testing.T) {
	const runID = "test-get-run-iocs-http-enriched"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(context.Background(), `DELETE FROM ioc_enrichment WHERE indicator_value = $1`, "198.51.100.40")
	})
	seedRunIOC(t, runID, []ioc.RunIndicator{{Type: "ip", Value: "198.51.100.40", Confidence: 90, Source: "stdout"}})

	stub := &stubIOCProvider{name: "otx", failValues: map[string]bool{}}
	h := New(sharedDB.Pool, nil, nil, "secret").WithIOCProvider(stub)
	h.enrichRunIOCs(context.Background(), runID) // populates ioc_enrichment (stub returns PulseCount: 3)

	req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/"+runID+"/iocs", nil), "runId", runID)
	rec := httptest.NewRecorder()
	h.GetRunIOCs(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var got []struct {
		Value      string `json:"value"`
		Tier       string `json:"tier"`
		PulseCount int    `json:"pulseCount"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d indicators, want 1: %+v", len(got), got)
	}
	if got[0].Tier != "malicious-associated" || got[0].PulseCount != 3 {
		t.Errorf("got %+v, want tier=malicious-associated pulseCount=3 (stub returns PulseCount:3, tier threshold is >=3)", got[0])
	}
}

// TestGetRunIOCs_HTTP_NoProviderConfigured_OmitsTier confirms the endpoint
// still works (and never errors) with no threat-intel provider wired up --
// the common case for an air-gapped deployment.
func TestGetRunIOCs_HTTP_NoProviderConfigured_OmitsTier(t *testing.T) {
	const runID = "test-get-run-iocs-http-noprovider"
	seedRunIOC(t, runID, []ioc.RunIndicator{{Type: "domain", Value: "example.test", Confidence: 80, Source: "stdout"}})

	h := New(sharedDB.Pool, nil, nil, "secret") // iocProvider left nil

	req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/"+runID+"/iocs", nil), "runId", runID)
	rec := httptest.NewRecorder()
	h.GetRunIOCs(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var got []struct {
		Value string `json:"value"`
		Tier  string `json:"tier"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].Tier != "" {
		t.Errorf("got %+v, want 1 indicator with empty tier (no provider configured)", got)
	}
}
