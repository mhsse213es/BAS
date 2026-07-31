package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNotifyServerUnenroll_SendsAgentIDAndToken(t *testing.T) {
	var gotBody map[string]string
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agents/unenroll" {
			t.Errorf("path = %q, want /api/agents/unenroll", r.URL.Path)
		}
		gotToken = r.Header.Get("X-Agent-Token")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := notifyServerUnenroll(srv.URL, "shh", "agent-123"); err != nil {
		t.Fatalf("notifyServerUnenroll: %v", err)
	}
	if gotBody["agentId"] != "agent-123" {
		t.Errorf("agentId sent = %q, want agent-123", gotBody["agentId"])
	}
	if gotToken != "shh" {
		t.Errorf("X-Agent-Token = %q, want shh", gotToken)
	}
}

func TestNotifyServerUnenroll_ServerError_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if err := notifyServerUnenroll(srv.URL, "shh", "agent-123"); err == nil {
		t.Error("expected an error when the server returns 404, got nil")
	}
}

func TestNotifyServerUnenroll_MissingServerURL_ReturnsErrorWithoutRequest(t *testing.T) {
	if err := notifyServerUnenroll("", "shh", "agent-123"); err == nil {
		t.Error("expected an error for an empty serverURL, got nil")
	}
}
