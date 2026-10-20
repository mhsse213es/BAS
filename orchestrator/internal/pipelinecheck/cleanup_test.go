package pipelinecheck

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const previewRunID = "bas-0123456789abcdef0123456789abcdef"

// previewServer answers every request with one status and body, and counts the requests.
func previewServer(t *testing.T, status int, body string, seen *atomic.Int32, bodyOut *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		b, _ := io.ReadAll(r.Body)
		if bodyOut != nil {
			*bodyOut = string(b)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

// hit builds one search hit with the stored marker fields a real record would carry.
func hit(id, runID, tags string) string {
	return `{"_id":"` + id + `","_source":{"audspect":{"test_run":"` + runID + `"},"tags":` + tags + `}}`
}

func searchResult(total int, hits ...string) string {
	return `{"hits":{"total":{"value":` + itoa(total) + `,"relation":"eq"},"hits":[` + strings.Join(hits, ",") + `]}}`
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// An invalid run identifier is refused before any request is made.
func TestCleanupPreview_RefusesMalformedRunIDWithoutRequest(t *testing.T) {
	var seen atomic.Int32
	srv := previewServer(t, 200, `{}`, &seen, nil)
	defer srv.Close()
	for _, id := range []string{"", "*", "bas-*", "bas-abc", "BAS-0123456789ABCDEF0123456789ABCDEF", previewRunID + " OR 1=1"} {
		p := PreviewElasticCleanup(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", id)
		if p.Status != "error" {
			t.Fatalf("run %q: status = %s, want error", id, p.Status)
		}
	}
	if seen.Load() != 0 {
		t.Fatalf("%d requests sent for malformed run identifiers, want none", seen.Load())
	}
}

// Wildcard and list index names are refused before any request is made.
func TestCleanupPreview_RefusesPatternIndexWithoutRequest(t *testing.T) {
	var seen atomic.Int32
	srv := previewServer(t, 200, `{}`, &seen, nil)
	defer srv.Close()
	for _, idx := range []string{"logs-*", "logs-a,logs-b", "*", "_all", "", ".security"} {
		p := PreviewElasticCleanup(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, idx, previewRunID)
		if p.Status != "error" {
			t.Fatalf("index %q: status = %s, want error", idx, p.Status)
		}
	}
	if seen.Load() != 0 {
		t.Fatalf("%d requests sent for pattern indexes, want none", seen.Load())
	}
}

// The search requires the run identifier AND the marker tag, and reads only the marker fields.
func TestCleanupPreview_QueryRequiresRunIDAndTag(t *testing.T) {
	var seen atomic.Int32
	var sent string
	srv := previewServer(t, 200, searchResult(0), &seen, &sent)
	defer srv.Close()
	PreviewElasticCleanup(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID)

	var body map[string]any
	if err := json.Unmarshal([]byte(sent), &body); err != nil {
		t.Fatalf("sent body is not JSON: %v", err)
	}
	filters, _ := body["query"].(map[string]any)["bool"].(map[string]any)["filter"].([]any)
	if len(filters) != 2 {
		t.Fatalf("filters = %d, want exactly the run identifier and the tag", len(filters))
	}
	raw, _ := json.Marshal(filters)
	for _, want := range []string{`"audspect.test_run":"` + previewRunID + `"`, `"tags":"` + MarkerTag + `"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("query %s lacks %s", raw, want)
		}
	}
	src, _ := json.Marshal(body["_source"])
	if string(src) != `["audspect.test_run","tags"]` {
		t.Fatalf("_source = %s, want only the marker fields", src)
	}
}

// A record is listed only when its stored marker matches exactly.
func TestCleanupPreview_ListsOnlyExactlyConfirmedRecords(t *testing.T) {
	var seen atomic.Int32
	resp := searchResult(2,
		hit("doc-1", previewRunID, `["audspect-bas-test"]`),
		hit("doc-2", previewRunID, `"audspect-bas-test"`),
	)
	srv := previewServer(t, 200, resp, &seen, nil)
	defer srv.Close()
	p := PreviewElasticCleanup(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID)
	if p.Status != "previewed" || len(p.Candidates) != 2 || p.Candidates[0] != "doc-1" || p.Candidates[1] != "doc-2" || len(p.Retained) != 0 {
		t.Fatalf("preview = %+v, want doc-1 and doc-2 confirmed, nothing retained", p)
	}
}

// A loose match is not enough. A record that the search returned for a different run, or
// without the tag, is retained, never listed.
func TestCleanupPreview_LooseMatchesAreRetainedNotListed(t *testing.T) {
	var seen atomic.Int32
	other := "bas-ffffffffffffffffffffffffffffffff"
	resp := searchResult(3,
		hit("confirmed", previewRunID, `["audspect-bas-test"]`),
		hit("other-run", other, `["audspect-bas-test"]`),
		`{"_id":"no-marker","_source":{"tags":["audspect-bas-test"]}}`,
	)
	srv := previewServer(t, 200, resp, &seen, nil)
	defer srv.Close()
	p := PreviewElasticCleanup(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID)
	if len(p.Candidates) != 1 || p.Candidates[0] != "confirmed" {
		t.Fatalf("candidates = %v, want only [confirmed]", p.Candidates)
	}
	if len(p.Retained) != 2 {
		t.Fatalf("retained = %v, want the other-run and no-marker records", p.Retained)
	}
}

// No matching records is a real answer, previewed with an empty list. It is not an error.
func TestCleanupPreview_NoMatchesIsPreviewedEmpty(t *testing.T) {
	var seen atomic.Int32
	srv := previewServer(t, 200, searchResult(0), &seen, nil)
	defer srv.Close()
	p := PreviewElasticCleanup(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID)
	if p.Status != "previewed" || len(p.Candidates) != 0 {
		t.Fatalf("preview = %+v, want previewed with no candidates", p)
	}
}

// More matches than the limit is refused, never truncated to a partial list.
func TestCleanupPreview_OverLimitRefusedNotTruncated(t *testing.T) {
	var seen atomic.Int32
	srv := previewServer(t, 200, searchResult(5000, hit("doc-1", previewRunID, `["audspect-bas-test"]`)), &seen, nil)
	defer srv.Close()
	p := PreviewElasticCleanup(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID)
	if p.Status != "error" || len(p.Candidates) != 0 || !strings.Contains(p.Reason, "above the preview limit") {
		t.Fatalf("preview = %+v, want refusal with no candidates", p)
	}
}

// Authentication, permission and missing-index failures are distinct, and none lists records.
func TestCleanupPreview_FailureModesAreDistinct(t *testing.T) {
	cases := map[int]string{
		http.StatusUnauthorized: "authentication failed",
		http.StatusForbidden:    "permission denied",
		http.StatusNotFound:     "index not found",
	}
	for status, want := range cases {
		var seen atomic.Int32
		srv := previewServer(t, status, `{}`, &seen, nil)
		p := PreviewElasticCleanup(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID)
		srv.Close()
		if p.Status != "error" || !strings.Contains(p.Reason, want) || len(p.Candidates) != 0 {
			t.Fatalf("HTTP %d: preview = %+v, want error mentioning %q", status, p, want)
		}
	}
}

// An unreachable connector is an error, not an empty preview.
func TestCleanupPreview_UnreachableIsError(t *testing.T) {
	p := PreviewElasticCleanup(context.Background(), http.DefaultClient, ElasticConfig{BaseURL: "http://127.0.0.1:1"}, "logs-bas", previewRunID)
	if p.Status != "error" {
		t.Fatalf("status = %s, want error for an unreachable connector", p.Status)
	}
}

// Run identifiers are server-generated, unique, and always in the valid form.
func TestNewTestRunID_UniqueAndValid(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id, err := NewTestRunID()
		if err != nil {
			t.Fatal(err)
		}
		if !ValidTestRunID(id) {
			t.Fatalf("generated id %q is not valid", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}
