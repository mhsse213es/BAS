package pipelinecheck

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// remainingServer answers the mapping request as mapped (or unmapped), and the search with the given
// hits and status.
func remainingServer(t *testing.T, mapBody string, searchStatus int, hits ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/_mapping") {
			_, _ = w.Write([]byte(mapBody))
			return
		}
		w.WriteHeader(searchStatus)
		hitJSON := make([]string, 0, len(hits))
		for _, id := range hits {
			hitJSON = append(hitJSON, fmt.Sprintf(`{"_id":%q}`, id))
		}
		_, _ = w.Write([]byte(`{"hits":{"hits":[` + strings.Join(hitJSON, ",") + `]}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// All approved records gone: suggested deleted, nothing remaining.
func TestRemaining_AllGoneSuggestsDeleted(t *testing.T) {
	srv := remainingServer(t, mappedFixture, http.StatusOK)
	r := CheckRemainingElastic(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID, []string{"a", "b"})
	if r.Status != "checked" || r.Suggested != "deleted" || len(r.Remaining) != 0 {
		t.Fatalf("all gone: %+v", r)
	}
}

// Every approved record still present: suggested not deleted.
func TestRemaining_AllPresentSuggestsNotDeleted(t *testing.T) {
	srv := remainingServer(t, mappedFixture, http.StatusOK, "a", "b")
	r := CheckRemainingElastic(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID, []string{"a", "b"})
	if r.Suggested != "not_deleted" || len(r.Remaining) != 2 {
		t.Fatalf("all present: %+v", r)
	}
}

// Some present: suggested partial, and the remaining IDs are named.
func TestRemaining_SomePresentSuggestsPartial(t *testing.T) {
	srv := remainingServer(t, mappedFixture, http.StatusOK, "b")
	r := CheckRemainingElastic(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID, []string{"a", "b"})
	if r.Suggested != "partial" || len(r.Remaining) != 1 || r.Remaining[0] != "b" {
		t.Fatalf("some present: %+v", r)
	}
}

// A failed search is an error with no suggestion. It is never read as "all gone".
func TestRemaining_SearchFailureHasNoSuggestion(t *testing.T) {
	srv := remainingServer(t, mappedFixture, http.StatusInternalServerError)
	r := CheckRemainingElastic(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID, []string{"a"})
	if r.Status != "error" || r.Suggested != "" {
		t.Fatalf("failed search: %+v, want error with no suggestion", r)
	}
}

// An unmapped index is an error, not an empty result that would suggest deletion.
func TestRemaining_UnmappedIsErrorNotDeleted(t *testing.T) {
	srv := remainingServer(t, unmappedFixture, http.StatusOK)
	r := CheckRemainingElastic(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID, []string{"a"})
	if r.Status != "error" || r.Suggested != "" {
		t.Fatalf("unmapped: %+v, want error with no suggestion", r)
	}
}

// Only approved records are ever reported. A hit outside the approved set is ignored, even if the
// search returns it, so the count cannot be inflated by a record that was never approved.
func TestRemaining_IgnoresHitsOutsideApprovedSet(t *testing.T) {
	srv := remainingServer(t, mappedFixture, http.StatusOK, "a", "recent")
	r := CheckRemainingElastic(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID, []string{"a", "b"})
	if len(r.Remaining) != 1 || r.Remaining[0] != "a" || r.Suggested != "partial" {
		t.Fatalf("a hit outside the approved set was reported: %+v", r)
	}
}
