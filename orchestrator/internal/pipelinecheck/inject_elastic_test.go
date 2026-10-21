package pipelinecheck

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// writeServer records each write it receives and answers with the given status and body.
func writeServer(t *testing.T, status int, body string, calls *atomic.Int32, gotBody *string, gotPath *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		b, _ := io.ReadAll(r.Body)
		*gotBody = string(b)
		*gotPath = r.Method + " " + r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func testInjectDoc(t *testing.T, runID string) map[string]any {
	t.Helper()
	doc, err := TagDocument(map[string]any{"@timestamp": "2026-10-21T00:00:00Z", "event": map[string]any{"action": "probe"}}, runID)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// A confirmed create is EXECUTED. The write goes to the one named index, with op_type=create and a
// refresh, and the body carries the tag and the run identifier.
func TestElasticInjector_WritesTaggedDocumentOnce(t *testing.T) {
	var calls atomic.Int32
	var body, path string
	srv := writeServer(t, http.StatusCreated, `{"result":"created","_id":"x"}`, &calls, &body, &path)
	defer srv.Close()
	inj := ElasticInjector{Client: srv.Client(), Cfg: ElasticConfig{BaseURL: srv.URL, APIKey: "k"}}
	out, err := inj.Inject(context.Background(), InjectionRequest{RunID: previewRunID, Index: "logs-bas", Document: testInjectDoc(t, previewRunID)})
	if err != nil || out.Status != "EXECUTED" {
		t.Fatalf("inject: %+v err=%v", out, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("%d writes, want exactly one", calls.Load())
	}
	if !strings.HasPrefix(path, "PUT /logs-bas/_doc/"+previewRunID+"-") || !strings.Contains(path, "op_type=create") || !strings.Contains(path, "refresh=true") {
		t.Fatalf("request = %s, want a create-only refreshed PUT to logs-bas", path)
	}
	if !strings.Contains(body, `"tags":["audspect-bas-test"]`) || !strings.Contains(body, `"test_run":"`+previewRunID+`"`) {
		t.Fatalf("body lacks the marker: %s", body)
	}
}

// Anything other than a confirmed create is an error. The caller records that as failed, not as a pass.
func TestElasticInjector_RefusedOrUnconfirmedIsError(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
	}{
		{http.StatusUnauthorized, `{}`},
		{http.StatusConflict, `{}`},
		{http.StatusOK, `{"result":"updated"}`},
		{http.StatusInternalServerError, `{}`},
	} {
		var calls atomic.Int32
		var body, path string
		srv := writeServer(t, c.status, c.body, &calls, &body, &path)
		inj := ElasticInjector{Client: srv.Client(), Cfg: ElasticConfig{BaseURL: srv.URL}}
		out, err := inj.Inject(context.Background(), InjectionRequest{RunID: previewRunID, Index: "logs-bas", Document: testInjectDoc(t, previewRunID)})
		srv.Close()
		if err == nil || out.Status == "EXECUTED" {
			t.Fatalf("status %d body %s: out=%+v err=%v, want an error and no EXECUTED", c.status, c.body, out, err)
		}
	}
}

// A pattern index and a malformed run identifier are refused before any request.
func TestElasticInjector_RefusedBeforeRequest(t *testing.T) {
	var calls atomic.Int32
	var body, path string
	srv := writeServer(t, http.StatusCreated, `{"result":"created"}`, &calls, &body, &path)
	defer srv.Close()
	inj := ElasticInjector{Client: srv.Client(), Cfg: ElasticConfig{BaseURL: srv.URL}}
	if _, err := inj.Inject(context.Background(), InjectionRequest{RunID: previewRunID, Index: "logs-*", Document: testInjectDoc(t, previewRunID)}); err == nil {
		t.Fatal("pattern index accepted")
	}
	if _, err := inj.Inject(context.Background(), InjectionRequest{RunID: "bas-*", Index: "logs-bas", Document: map[string]any{}}); err == nil {
		t.Fatal("malformed run identifier accepted")
	}
	if calls.Load() != 0 {
		t.Fatalf("%d writes for refused input", calls.Load())
	}
}

// Lab: the write lands in the real Elasticsearch, the record carries the marker, and retention holds it
// because it is brand new. That is the expected result for a fresh test record.
func TestElasticInjector_LabWriteIsTaggedAndHeldByRetention(t *testing.T) {
	base := os.Getenv("AUDSPECT_ES_LAB_URL")
	if base == "" {
		t.Skip("AUDSPECT_ES_LAB_URL not set")
	}
	cfg := ElasticConfig{BaseURL: base, Username: os.Getenv("AUDSPECT_ES_LAB_USER"), Password: os.Getenv("AUDSPECT_ES_LAB_PASS")}
	runID, err := NewTestRunID()
	if err != nil {
		t.Fatal(err)
	}
	inj := ElasticInjector{Client: http.DefaultClient, Cfg: cfg}
	out, err := inj.Inject(context.Background(), InjectionRequest{RunID: runID, Index: "lab-inject-probe", Document: testInjectDoc(t, runID)})
	if err != nil || out.Status != "EXECUTED" {
		t.Fatalf("lab inject: %+v err=%v", out, err)
	}
	p := PreviewElasticCleanup(context.Background(), http.DefaultClient, cfg, "lab-inject-probe", runID)
	if p.Status != "previewed" || len(p.Candidates) != 0 || len(p.RetentionHeld) != 1 {
		t.Fatalf("preview of the fresh record = %+v, want it confirmed and held by retention", p)
	}
}
