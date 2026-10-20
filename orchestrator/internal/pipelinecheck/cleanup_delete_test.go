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
	"time"
)

// testCutoff is the retention cutoff the delete tests pass: records older than the window.
var testCutoff = time.Now().UTC().Add(-RetentionWindow)

// deleteServer answers the mapping request as mapped, records the delete body, and returns deleteBody.
func deleteServer(t *testing.T, deleteBody string, sent *string, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/_mapping") {
			_, _ = w.Write([]byte(mappedFixture))
			return
		}
		calls.Add(1)
		b, _ := io.ReadAll(r.Body)
		*sent = string(b)
		_, _ = w.Write([]byte(deleteBody))
	}))
}

// The delete is limited to the given IDs, the run identifier and the marker tag.
func TestDeleteCandidates_QueryIsExactAndBounded(t *testing.T) {
	var sent string
	var calls atomic.Int32
	srv := deleteServer(t, `{"deleted":2,"version_conflicts":0,"failures":[]}`, &sent, &calls)
	defer srv.Close()
	res, err := DeleteElasticCandidates(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL},
		"logs-bas", previewRunID, []string{"doc-1", "doc-2"}, testCutoff)
	if err != nil || res.Status != "deleted" {
		t.Fatalf("delete: res=%+v err=%v", res, err)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(sent), &body); err != nil {
		t.Fatal(err)
	}
	filters, _ := body["query"].(map[string]any)["bool"].(map[string]any)["filter"].([]any)
	raw, _ := json.Marshal(filters)
	for _, want := range []string{`"values":["doc-1","doc-2"]`, `"audspect.test_run":"` + previewRunID + `"`, `"tags":"` + MarkerTag + `"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("delete query %s lacks %s", raw, want)
		}
	}
}

// A version conflict is partial, never complete.
func TestDeleteCandidates_ConflictIsPartialNotComplete(t *testing.T) {
	var sent string
	var calls atomic.Int32
	srv := deleteServer(t, `{"deleted":1,"version_conflicts":1,"failures":[]}`, &sent, &calls)
	defer srv.Close()
	res, _ := DeleteElasticCandidates(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL},
		"logs-bas", previewRunID, []string{"doc-1", "doc-2"}, testCutoff)
	if res.Status != "partial" || res.Deleted != 1 || res.Conflicts != 1 {
		t.Fatalf("conflict: res=%+v, want partial with one deleted and one conflict", res)
	}
}

// Server-side failures are an error.
func TestDeleteCandidates_FailuresAreError(t *testing.T) {
	var sent string
	var calls atomic.Int32
	srv := deleteServer(t, `{"deleted":0,"version_conflicts":0,"failures":[{"cause":"x"}]}`, &sent, &calls)
	defer srv.Close()
	res, _ := DeleteElasticCandidates(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL},
		"logs-bas", previewRunID, []string{"doc-1"}, testCutoff)
	if res.Status != "error" {
		t.Fatalf("failures: res=%+v, want error", res)
	}
}

// Malformed run identifiers, pattern indexes and oversized sets are refused without any request.
func TestDeleteCandidates_RefusedBeforeRequest(t *testing.T) {
	var sent string
	var calls atomic.Int32
	srv := deleteServer(t, `{}`, &sent, &calls)
	defer srv.Close()
	cfg := ElasticConfig{BaseURL: srv.URL}
	ids := []string{"doc-1"}
	if _, err := DeleteElasticCandidates(context.Background(), srv.Client(), cfg, "logs-bas", "bas-*", ids, testCutoff); err == nil {
		t.Fatal("malformed run identifier accepted")
	}
	if _, err := DeleteElasticCandidates(context.Background(), srv.Client(), cfg, "logs-*", previewRunID, ids, testCutoff); err == nil {
		t.Fatal("pattern index accepted")
	}
	big := make([]string, cleanupPreviewLimit+1)
	if _, err := DeleteElasticCandidates(context.Background(), srv.Client(), cfg, "logs-bas", previewRunID, big, testCutoff); err == nil {
		t.Fatal("oversized set accepted")
	}
	if calls.Load() != 0 {
		t.Fatalf("%d delete requests sent for refused input", calls.Load())
	}
}

// An empty set deletes nothing and sends nothing.
func TestDeleteCandidates_EmptySetDeletesNothing(t *testing.T) {
	var sent string
	var calls atomic.Int32
	srv := deleteServer(t, `{}`, &sent, &calls)
	defer srv.Close()
	res, err := DeleteElasticCandidates(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID, nil, testCutoff)
	if err != nil || res.Status != "deleted" || calls.Load() != 0 {
		t.Fatalf("empty set: res=%+v err=%v calls=%d", res, err, calls.Load())
	}
}
