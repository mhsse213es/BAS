package pipelinecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

var ingestWindow = IngestionQuery{
	Index:      "logs-*",
	Field:      "event.id",
	Identifier: "bas-probe-0001",
	From:       time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC),
	To:         time.Date(2026, 10, 20, 9, 10, 0, 0, time.UTC),
}

func fixedClock() time.Time { return time.Date(2026, 10, 20, 9, 11, 0, 0, time.UTC) }

// fakeES serves one canned response and records the request it received.
func fakeES(t *testing.T, status int, body string, seen *http.Request) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen = *r
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestElasticIngestion_MatchesAreVerifiedWithEvidence(t *testing.T) {
	body := `{"hits":{"total":{"value":2,"relation":"eq"},"hits":[
	  {"_id":"doc-1","_source":{"@timestamp":"2026-10-20T09:02:03Z"}},
	  {"_id":"doc-2","_source":{"@timestamp":"2026-10-20T09:02:05Z"}}]}}`
	srv := fakeES(t, 200, body, nil)
	defer srv.Close()

	r := CheckElasticIngestion(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL, Username: "u", Password: "p"}, ingestWindow, fixedClock)
	if r.Status != StatusVerified || r.Stage != StageIngestion {
		t.Fatalf("status=%s stage=%s reason=%s, want VERIFIED ingestion", r.Status, r.Stage, r.Reason)
	}
	if r.Evidence.MatchCount != 2 || len(r.Evidence.EventIDs) != 2 || len(r.Evidence.SourceTimes) != 2 {
		t.Fatalf("evidence incomplete: %+v", r.Evidence)
	}
	if !strings.Contains(r.Reason, "raw ingestion only") {
		t.Fatalf("a raw match must not be described as more than ingestion: %q", r.Reason)
	}
}

// Zero matches is INCONCLUSIVE, distinct from a failed query.
func TestElasticIngestion_ZeroMatchesIsInconclusive(t *testing.T) {
	srv := fakeES(t, 200, `{"hits":{"total":{"value":0,"relation":"eq"},"hits":[]}}`, nil)
	defer srv.Close()
	r := CheckElasticIngestion(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, ingestWindow, fixedClock)
	if r.Status != StatusInconclusive {
		t.Fatalf("status=%s, want INCONCLUSIVE for zero matches", r.Status)
	}
	if r.Evidence.HTTPStatus != 200 {
		t.Fatalf("zero matches must keep the successful response as evidence, got status %d", r.Evidence.HTTPStatus)
	}
}

func TestElasticIngestion_FailureModesAreErrorsWithDistinctReasons(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"unauthenticated", 401, `{}`, "authentication failed (401)"},
		{"forbidden", 403, `{}`, "permission denied (403)"},
		{"no index", 404, `{}`, "no index matches"},
		{"server error", 500, `{}`, "status 500"},
		{"malformed body", 200, `not json`, "not a valid search result"},
		{"missing total", 200, `{"hits":{"hits":[]}}`, "did not report a match total"},
		{"total not a number", 200, `{"hits":{"total":"many"}}`, "did not report a match total"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := fakeES(t, c.status, c.body, nil)
			defer srv.Close()
			r := CheckElasticIngestion(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, ingestWindow, fixedClock)
			if r.Status != StatusError {
				t.Fatalf("status=%s, want ERROR", r.Status)
			}
			if !strings.Contains(r.Reason, c.want) {
				t.Fatalf("reason=%q, want it to contain %q", r.Reason, c.want)
			}
		})
	}
}

// A connector that cannot be reached is ERROR, not zero matches.
func TestElasticIngestion_UnreachableIsErrorNotZero(t *testing.T) {
	srv := fakeES(t, 200, `{}`, nil)
	url := srv.URL
	srv.Close()
	r := CheckElasticIngestion(context.Background(), http.DefaultClient, ElasticConfig{BaseURL: url}, ingestWindow, fixedClock)
	if r.Status != StatusError || r.Evidence.HTTPStatus != 0 {
		t.Fatalf("status=%s http=%d, want ERROR with no response", r.Status, r.Evidence.HTTPStatus)
	}
}

// Credentials go in a header, and never into the evidence or the reason.
func TestElasticIngestion_CredentialsStayOutOfEvidence(t *testing.T) {
	var seen http.Request
	srv := fakeES(t, 401, `{}`, &seen)
	defer srv.Close()
	r := CheckElasticIngestion(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL, Username: "svc-audit", Password: "S3cret-Pass"}, ingestWindow, fixedClock)
	if u, p, ok := seen.BasicAuth(); !ok || u != "svc-audit" || p != "S3cret-Pass" {
		t.Fatalf("basic auth not sent in header")
	}
	if strings.Contains(r.Reason, "S3cret") || strings.Contains(r.Evidence.ErrorDetail, "S3cret") || strings.Contains(srv.URL, "S3cret") {
		t.Fatalf("credential leaked into the report")
	}
}

func TestElasticIngestion_APIKeyHeader(t *testing.T) {
	var seen http.Request
	srv := fakeES(t, 200, `{"hits":{"total":{"value":0}}}`, &seen)
	defer srv.Close()
	CheckElasticIngestion(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL, APIKey: "abc123"}, ingestWindow, fixedClock)
	if got := seen.Header.Get("Authorization"); got != "ApiKey abc123" {
		t.Fatalf("authorization=%q, want the ApiKey header", got)
	}
}

// The query is bounded by the window and filters on the exact identifier.
func TestElasticIngestion_QueryIsBoundedAndExact(t *testing.T) {
	var seen http.Request
	srv := fakeES(t, 200, `{"hits":{"total":{"value":0}}}`, &seen)
	defer srv.Close()
	CheckElasticIngestion(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, ingestWindow, fixedClock)
	if seen.Method != http.MethodPost || !strings.Contains(seen.URL.Path, "/logs-%2A/_search") && !strings.Contains(seen.URL.Path, "/logs-*/_search") {
		t.Fatalf("unexpected request %s %s", seen.Method, seen.URL.Path)
	}
	if seen.URL.Query().Get("allow_no_indices") != "false" {
		t.Fatalf("allow_no_indices must be false so a missing index is an error, not zero")
	}
}

func TestElasticIngestion_InvalidWindowIsErrorBeforeAnyRequest(t *testing.T) {
	bad := ingestWindow
	bad.To = bad.From
	called := false
	srv := fakeES(t, 200, `{}`, nil)
	defer srv.Close()
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	r := CheckElasticIngestion(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, bad, fixedClock)
	if r.Status != StatusError || called {
		t.Fatalf("status=%s called=%v, want ERROR and no request", r.Status, called)
	}
}

// Live check against a real Elasticsearch. It runs only when AUDSPECT_ES_LAB_URL,
// AUDSPECT_ES_LAB_USER and AUDSPECT_ES_LAB_PASS are set, so the suite passes elsewhere.
// It creates a unique index, a read-only user and a role, exercises each outcome against
// the real connector, and removes everything it created.
func TestElasticIngestion_LabInstance(t *testing.T) {
	base := os.Getenv("AUDSPECT_ES_LAB_URL")
	user := os.Getenv("AUDSPECT_ES_LAB_USER")
	pass := os.Getenv("AUDSPECT_ES_LAB_PASS")
	if base == "" || user == "" {
		t.Skip("lab Elasticsearch environment not set")
	}
	admin := ElasticConfig{BaseURL: base, Username: user, Password: pass}
	client := &http.Client{Timeout: 20 * time.Second}
	stamp := time.Now().UnixNano()
	index := fmt.Sprintf("audspect-probe-%d", stamp)
	probeID := fmt.Sprintf("bas-probe-%d", stamp)
	roleName := fmt.Sprintf("audspect-noread-%d", stamp)
	userName := fmt.Sprintf("audspect-probe-noread-%d", stamp)
	const noreadPass = "NoRead-Lab-2026!"

	labCall(t, client, admin, http.MethodPut, "/"+index, map[string]any{})
	t.Cleanup(func() { labCall(t, client, admin, http.MethodDelete, "/"+index, nil) })
	labCall(t, client, admin, http.MethodPost, "/"+index+"/_doc?refresh=true", map[string]any{
		"event": map[string]any{"id": probeID}, "@timestamp": time.Now().UTC().Format(time.RFC3339),
	})

	now := time.Now().UTC()
	q := IngestionQuery{Index: index, Field: "event.id", Identifier: probeID, From: now.Add(-time.Hour), To: now.Add(time.Minute)}

	// 1. The probe event is found: VERIFIED, with its document ID and timestamp as evidence.
	r := CheckElasticIngestion(context.Background(), client, admin, q, time.Now)
	if r.Status != StatusVerified || r.Evidence.MatchCount != 1 || len(r.Evidence.EventIDs) != 1 || len(r.Evidence.SourceTimes) != 1 {
		t.Fatalf("matching probe: status=%s count=%d reason=%s", r.Status, r.Evidence.MatchCount, r.Reason)
	}

	// 2. An identifier that was never sent: the index exists, so zero matches is INCONCLUSIVE.
	q.Identifier = probeID + "-absent"
	r = CheckElasticIngestion(context.Background(), client, admin, q, time.Now)
	if r.Status != StatusInconclusive || r.Evidence.HTTPStatus != 200 {
		t.Fatalf("absent identifier: status=%s http=%d", r.Status, r.Evidence.HTTPStatus)
	}

	// 3. Wrong credentials: ERROR, reported as authentication, never as zero matches.
	q.Identifier = probeID
	wrong := ElasticConfig{BaseURL: base, Username: user, Password: "not-the-password"}
	r = CheckElasticIngestion(context.Background(), client, wrong, q, time.Now)
	if r.Status != StatusError || !strings.Contains(r.Reason, "authentication failed") {
		t.Fatalf("wrong credentials: status=%s reason=%s", r.Status, r.Reason)
	}

	// 4. A user with no read privilege on the index: ERROR, reported as permission denied.
	labCall(t, client, admin, http.MethodPut, "/_security/role/"+roleName, map[string]any{
		"indices": []map[string]any{{"names": []string{"unrelated-*"}, "privileges": []string{"read"}}},
	})
	labCall(t, client, admin, http.MethodPut, "/_security/user/"+userName, map[string]any{
		"password": noreadPass, "roles": []string{roleName},
	})
	t.Cleanup(func() {
		labCall(t, client, admin, http.MethodDelete, "/_security/user/"+userName, nil)
		labCall(t, client, admin, http.MethodDelete, "/_security/role/"+roleName, nil)
	})
	noread := ElasticConfig{BaseURL: base, Username: userName, Password: noreadPass}
	r = CheckElasticIngestion(context.Background(), client, noread, q, time.Now)
	if r.Status != StatusError || !strings.Contains(r.Reason, "permission denied") {
		t.Fatalf("no read privilege: status=%s http=%d reason=%s", r.Status, r.Evidence.HTTPStatus, r.Reason)
	}
}

// labCall performs one administrative request against the lab. It fails the test on error
// except for DELETE during cleanup, which may find nothing left to delete.
func labCall(t *testing.T, c *http.Client, cfg ElasticConfig, method, path string, body any) {
	t.Helper()
	var buf io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, strings.TrimRight(cfg.BaseURL, "/")+path, buf)
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(cfg.Username, cfg.Password)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("lab %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && method != http.MethodDelete {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("lab %s %s: status %d: %s", method, path, resp.StatusCode, b)
	}
}

// The identifier is matched as a phrase. A term query on a text field fails for any value
// with punctuation, because the analyser splits it, so the phrase form is required.
func TestElasticIngestion_IdentifierMatchedAsPhrase(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hits":{"total":{"value":0}}}`))
	}))
	defer srv.Close()
	CheckElasticIngestion(context.Background(), srv.Client(), ElasticConfig{BaseURL: srv.URL}, ingestWindow, fixedClock)
	var got struct {
		Query struct {
			Bool struct {
				Filter []map[string]any `json:"filter"`
			} `json:"bool"`
		} `json:"query"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("query body not valid JSON: %v", err)
	}
	if len(got.Query.Bool.Filter) == 0 {
		t.Fatalf("no filter clause in query: %s", body)
	}
	if _, ok := got.Query.Bool.Filter[0]["match_phrase"]; !ok {
		t.Fatalf("identifier must use match_phrase, got %v", got.Query.Bool.Filter[0])
	}
}
