package pipelinecheck

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// retentionNow is the fixed server time the boundary tests judge against.
var retentionNow = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

// retentionCutoff is the newest event time that is still eligible: exactly RetentionWindow before now.
var retentionCutoff = retentionNow.Add(-RetentionWindow)

// tsHit builds one confirmed record whose @timestamp is the given raw JSON fragment. An empty fragment
// omits the field.
func tsHit(id, ts string) string {
	field := ""
	if ts != "" {
		field = `"@timestamp":` + ts + `,`
	}
	return `{"_id":"` + id + `","_source":{"audspect":{"test_run":"` + previewRunID + `"},` + field + `"tags":["audspect-bas-test"]}}`
}

func previewAt(t *testing.T, hits ...string) CleanupPreview {
	t.Helper()
	var seen atomic.Int32
	srv := previewServer(t, 200, searchResult(len(hits), hits...), &seen, nil)
	t.Cleanup(srv.Close)
	return PreviewElasticCleanupAt(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID, retentionNow)
}

// The cutoff is strict: eligible only when the event time is strictly earlier than now minus the
// window. A record exactly at the cutoff is held, one second earlier is eligible, and one second
// later is held.
func TestRetention_ExactBoundary(t *testing.T) {
	at := `"` + retentionCutoff.Format(time.RFC3339Nano) + `"`
	younger := `"` + retentionCutoff.Add(time.Second).Format(time.RFC3339Nano) + `"`
	older := `"` + retentionCutoff.Add(-time.Second).Format(time.RFC3339Nano) + `"`
	p := previewAt(t, tsHit("at", at), tsHit("younger", younger), tsHit("older", older))
	if !contains(p.Candidates, "older") {
		t.Fatalf("candidates = %v, want the one-second-earlier record", p.Candidates)
	}
	if contains(p.Candidates, "at") || !contains(p.RetentionHeld, "at") {
		t.Fatalf("exactly-at-cutoff record must be held: candidates=%v held=%v", p.Candidates, p.RetentionHeld)
	}
	if !contains(p.RetentionHeld, "younger") || contains(p.Candidates, "younger") {
		t.Fatalf("held = %v, candidates = %v; a record one second inside the window must be held", p.RetentionHeld, p.Candidates)
	}
}

// A timestamp with a zone offset is compared as an instant. 17:00 at +05:00 is 12:00 UTC, which is
// exactly the cutoff, so it is held. 16:59:59 at +05:00 is one second earlier and eligible.
func TestRetention_ZoneOffsetComparedAsInstant(t *testing.T) {
	p := previewAt(t, tsHit("exact", `"2026-09-20T17:00:00+05:00"`), tsHit("earlier", `"2026-09-20T16:59:59+05:00"`))
	if contains(p.Candidates, "exact") || !contains(p.RetentionHeld, "exact") {
		t.Fatalf("offset form of the exact cutoff must be held: %+v", p)
	}
	if !contains(p.Candidates, "earlier") {
		t.Fatalf("one second earlier by offset not eligible: %+v", p)
	}
}

// Missing, null, empty, malformed, non-string and future event times are all held, never eligible.
func TestRetention_InvalidTimestampsHeld(t *testing.T) {
	hits := []string{
		tsHit("missing", ""),
		tsHit("null", `null`),
		tsHit("empty", `""`),
		tsHit("malformed", `"not-a-time"`),
		tsHit("date-only", `"2026-09-01"`),
		tsHit("number", `1756000000`),
		tsHit("future", `"2026-10-21T00:00:00Z"`),
	}
	p := previewAt(t, hits...)
	if len(p.Candidates) != 0 {
		t.Fatalf("invalid timestamps produced candidates: %v", p.Candidates)
	}
	if len(p.RetentionHeld) != len(hits) {
		t.Fatalf("held = %v, want all %d invalid records held", p.RetentionHeld, len(hits))
	}
}

// Each candidate carries the event time it was judged on, so the approval can bind it.
func TestRetention_CandidatesCarryEventTime(t *testing.T) {
	ts := `"2026-08-01T00:00:00Z"`
	p := previewAt(t, tsHit("old", ts))
	if len(p.Records) != 1 || p.Records[0].ID != "old" || p.Records[0].EventTime != "2026-08-01T00:00:00Z" {
		t.Fatalf("records = %+v, want the candidate with its stored event time", p.Records)
	}
}

// The preview asks the search for the event time field, so the judgement is made on what is stored.
func TestRetention_PreviewRequestsEventTime(t *testing.T) {
	var seen atomic.Int32
	var sent string
	srv := previewServer(t, 200, searchResult(0), &seen, &sent)
	defer srv.Close()
	PreviewElasticCleanupAt(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, "logs-bas", previewRunID, retentionNow)
	if !strings.Contains(sent, `"@timestamp"`) {
		t.Fatalf("search did not request the event time field: %s", sent)
	}
}

// The delete query carries the same cutoff, so a record that is no longer eligible at deletion is
// not removed even if it reached the delete step.
func TestRetention_DeleteQueryCarriesCutoff(t *testing.T) {
	var seen atomic.Int32
	var sent string
	srv := deleteServer(t, `{"deleted":0,"version_conflicts":0,"failures":[]}`, &sent, &seen)
	defer srv.Close()
	if _, err := DeleteElasticCandidates(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL},
		"logs-bas", previewRunID, []string{"doc-1"}, retentionCutoff); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sent, `"range"`) || !strings.Contains(sent, retentionCutoff.UTC().Format(time.RFC3339Nano)) {
		t.Fatalf("delete query lacks the retention cutoff: %s", sent)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
