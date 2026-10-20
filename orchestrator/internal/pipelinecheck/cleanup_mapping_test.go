package pipelinecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// mappedFixture is a mapping in which both marker fields exist.
const mappedFixture = `{"logs-bas":{"mappings":{"audspect.test_run":{"full_name":"audspect.test_run"},"tags":{"full_name":"tags"},"@timestamp":{"full_name":"@timestamp","mapping":{"@timestamp":{"type":"date"}}}}}}`

// keywordTimestampFixture maps the marker fields but types the event time as a keyword. Retention
// comparisons on it would be lexical, so the preview must refuse.
const keywordTimestampFixture = `{"logs-bas":{"mappings":{"audspect.test_run":{"full_name":"audspect.test_run"},"tags":{"full_name":"tags"},"@timestamp":{"full_name":"@timestamp","mapping":{"@timestamp":{"type":"keyword"}}}}}}`

// A keyword event time is refused before any search, so retention is never judged lexically.
func TestCleanupPreview_KeywordEventTimeRefused(t *testing.T) {
	var searches atomic.Int32
	srv := mappingServer(t, http.StatusOK, keywordTimestampFixture, searchResult(0), &searches)
	defer srv.Close()
	p := PreviewElasticCleanup(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID)
	if p.Status != "error" || !strings.Contains(p.Reason, "not mapped as a date") || searches.Load() != 0 {
		t.Fatalf("keyword event time: preview = %+v searches=%d, want refusal before any search", p, searches.Load())
	}
}

// unmappedFixture is a mapping with no marker fields. It is what a search on a field that was
// never indexed sees.
const unmappedFixture = `{"logs-bas":{"mappings":{}}}`

// onlyRunMappedFixture maps the run field but not the tag field.
const onlyRunMappedFixture = `{"logs-bas":{"mappings":{"audspect.test_run":{"full_name":"audspect.test_run"}}}}`

// mappingServer answers the mapping request with mapStatus and mapBody, and counts searches
// separately, so a test can show whether a search was sent at all.
func mappingServer(t *testing.T, mapStatus int, mapBody, searchBody string, searches *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/_mapping") {
			w.WriteHeader(mapStatus)
			_, _ = w.Write([]byte(mapBody))
			return
		}
		searches.Add(1)
		_, _ = w.Write([]byte(searchBody))
	}))
}

// A search on an unmapped marker field returns zero hits with no error. The preview must not report
// that as an empty result. It fails before searching.
func TestCleanupPreview_UnmappedFieldsNotReportedAsEmpty(t *testing.T) {
	var searches atomic.Int32
	srv := mappingServer(t, http.StatusOK, unmappedFixture, searchResult(0), &searches)
	defer srv.Close()
	p := PreviewElasticCleanup(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID)
	if p.Status != "error" || !strings.Contains(p.Reason, "not mapped") {
		t.Fatalf("preview = %+v, want an error saying the fields are not mapped", p)
	}
	if searches.Load() != 0 {
		t.Fatalf("%d searches sent against an unmapped index, want none", searches.Load())
	}
}

// Having only one of the two marker fields mapped is not enough.
func TestCleanupPreview_PartialMappingRefused(t *testing.T) {
	var searches atomic.Int32
	srv := mappingServer(t, http.StatusOK, onlyRunMappedFixture, searchResult(0), &searches)
	defer srv.Close()
	p := PreviewElasticCleanup(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID)
	if p.Status != "error" || searches.Load() != 0 {
		t.Fatalf("partial mapping: preview = %+v searches=%d, want refusal with no search", p, searches.Load())
	}
}

// A mapping request that fails is an error, not an empty mapping.
func TestCleanupPreview_MappingFailureIsError(t *testing.T) {
	var searches atomic.Int32
	srv := mappingServer(t, http.StatusNotFound, `{}`, searchResult(0), &searches)
	defer srv.Close()
	p := PreviewElasticCleanup(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID)
	if p.Status != "error" || !strings.Contains(p.Reason, "index not found") || searches.Load() != 0 {
		t.Fatalf("mapping 404: preview = %+v searches=%d", p, searches.Load())
	}
}

// A record whose marker field holds several values is ambiguous. It is retained, not confirmed.
func TestCleanupPreview_AmbiguousMarkerRetained(t *testing.T) {
	var searches atomic.Int32
	body := `{"hits":{"total":{"value":1,"relation":"eq"},"hits":[{"_id":"multi","_source":{"audspect":{"test_run":["` +
		previewRunID + `","bas-ffffffffffffffffffffffffffffffff"]},"tags":["audspect-bas-test"]}}]}}`
	srv := mappingServer(t, http.StatusOK, mappedFixture, body, &searches)
	defer srv.Close()
	p := PreviewElasticCleanup(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID)
	if p.Status != "previewed" || len(p.Candidates) != 0 || len(p.Retained) != 1 {
		t.Fatalf("ambiguous marker: preview = %+v, want the record retained, not confirmed", p)
	}
}

// A record with the exact marker and the tag among other tags is confirmed.
func TestCleanupPreview_ExtraTagsDoNotBlockConfirmation(t *testing.T) {
	var searches atomic.Int32
	body := `{"hits":{"total":{"value":1,"relation":"eq"},"hits":[{"_id":"extra","_source":{"audspect":{"test_run":"` +
		previewRunID + `"},"@timestamp":"2026-01-01T00:00:00Z","tags":["team-a","audspect-bas-test"]}}]}}`
	srv := mappingServer(t, http.StatusOK, mappedFixture, body, &searches)
	defer srv.Close()
	p := PreviewElasticCleanup(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID)
	if p.Status != "previewed" || len(p.Candidates) != 1 || p.Candidates[0] != "extra" {
		t.Fatalf("extra tags: preview = %+v, want the record confirmed", p)
	}
}
