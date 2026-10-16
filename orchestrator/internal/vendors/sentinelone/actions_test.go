package sentinelone

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsolate_PostsDisconnectWithFilterIDs(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"success": true}})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	id, err := c.Isolate(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	if id != "agent-1" {
		t.Errorf("id = %q, want agent-1", id)
	}
	if gotPath != "/web/api/v2.1/agents/actions/disconnect" {
		t.Errorf("path = %q", gotPath)
	}
	filter, _ := gotBody["filter"].(map[string]any)
	ids, _ := filter["ids"].([]any)
	if len(ids) != 1 || ids[0] != "agent-1" {
		t.Errorf("body = %+v, want filter.ids == [agent-1]", gotBody)
	}
}

func TestRelease_PostsConnect(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"success": true}})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	if _, err := c.Release(context.Background(), "agent-1"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if gotPath != "/web/api/v2.1/agents/actions/connect" {
		t.Errorf("path = %q", gotPath)
	}
}

func TestIsolate_HTTPError_ReturnsClassifiedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	if _, err := c.Isolate(context.Background(), "agent-1"); err == nil {
		t.Fatal("expected an error")
	}
}

// TestQuarantineFile_InterpretsParamAsThreatID_PostsMitigateQuarantine
// proves QuarantineFile's "param" is interpreted as a SentinelOne threat
// ID (the only identifier SentinelOne's real mitigation API actually
// keys on), not a file path or hash the way Defender/CrowdStrike use it
// -- an intentional, documented deviation, same discipline as
// crowdstrike.Client.QuarantineFile's own "rm approximates quarantine"
// doc comment.
func TestQuarantineFile_InterpretsParamAsThreatID_PostsMitigateQuarantine(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"success": true}})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	id, err := c.QuarantineFile(context.Background(), "agent-1", "threat-42")
	if err != nil {
		t.Fatalf("QuarantineFile: %v", err)
	}
	if id != "threat-42" {
		t.Errorf("id = %q, want threat-42", id)
	}
	if gotPath != "/web/api/v2.1/threats/mitigate/quarantine" {
		t.Errorf("path = %q", gotPath)
	}
	filter, _ := gotBody["filter"].(map[string]any)
	ids, _ := filter["ids"].([]any)
	if len(ids) != 1 || ids[0] != "threat-42" {
		t.Errorf("body = %+v, want filter.ids == [threat-42]", gotBody)
	}
}

func TestQuarantineFile_HTTPError_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	if _, err := c.QuarantineFile(context.Background(), "agent-1", "threat-42"); err == nil {
		t.Fatal("expected an error")
	}
}

// TestKillProcess_ReturnsExplicitUnsupportedError is the key test for a
// deliberate safety decision: SentinelOne's real mitigation API has no
// confirmed way to map an arbitrary live OS process ID to a specific
// threat ID, and approximating that mapping incorrectly would risk
// mitigating the wrong threat on a real endpoint -- a destructive
// action. KillProcess must fail loudly, never guess.
func TestKillProcess_ReturnsExplicitUnsupportedError(t *testing.T) {
	c := newTestClient(t, "http://unused.invalid")
	_, err := c.KillProcess(context.Background(), "agent-1", 4242)
	if err == nil {
		t.Fatal("expected an explicit unsupported error, got nil")
	}
}
