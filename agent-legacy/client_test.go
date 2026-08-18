package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_Enroll_SendsExpectedFieldsAndParsesResponse(t *testing.T) {
	var gotReq EnrollRequest
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agents/enroll" {
			t.Errorf("path = %s, want /api/agents/enroll", r.URL.Path)
		}
		gotToken = r.Header.Get("X-Agent-Token")
		json.NewDecoder(r.Body).Decode(&gotReq)
		json.NewEncoder(w).Encode(EnrollResponse{AgentID: gotReq.AgentID, State: "active", Trusted: false})
	}))
	defer srv.Close()

	c := NewClient(Config{ServerURL: srv.URL, AgentSecret: "s3cr3t", EnvLabel: "Test"})
	id := Identity{AgentID: "test-host", Hostname: "test-host", IPAddress: "10.0.0.5", Username: "svc", OSVersion: "Windows/amd64 (6.1.7601)"}

	resp, err := c.Enroll(id)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if gotToken != "s3cr3t" {
		t.Errorf("X-Agent-Token = %q, want s3cr3t", gotToken)
	}
	if gotReq.AgentID != "test-host" || gotReq.OSVersion != "Windows/amd64 (6.1.7601)" {
		t.Errorf("EnrollRequest sent = %+v, missing expected identity fields", gotReq)
	}
	if resp.State != "active" {
		t.Errorf("State = %q, want active", resp.State)
	}
}

func TestClient_SendHeartbeat_PostsToHeartbeatEndpoint(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewEncoder(w).Encode(HeartbeatResponse{State: "active"})
	}))
	defer srv.Close()

	c := NewClient(Config{ServerURL: srv.URL})
	id := Identity{AgentID: "test-host", Hostname: "test-host"}
	resp, err := c.SendHeartbeat(id, "idle")
	if err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	if gotPath != "/api/heartbeat" {
		t.Errorf("path = %s, want /api/heartbeat", gotPath)
	}
	if resp.State != "active" {
		t.Errorf("State = %q, want active", resp.State)
	}
}
