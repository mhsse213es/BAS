package defender

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetMachineAction_ReturnsNormalizedRecord(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var gotPath, gotAuthHeader string
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuthHeader = r.Header.Get("Authorization")
		json.NewEncoder(w).Encode(map[string]any{
			"id": "action-1", "type": "Isolate", "status": "Succeeded", "machineId": "machine-123",
		})
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	action, err := c.GetMachineAction(context.Background(), "action-1")
	if err != nil {
		t.Fatalf("GetMachineAction: %v", err)
	}
	if gotPath != "/machineactions/action-1" {
		t.Errorf("path = %q, want %q", gotPath, "/machineactions/action-1")
	}
	if gotAuthHeader != "Bearer tok" {
		t.Errorf("Authorization header = %q, want %q", gotAuthHeader, "Bearer tok")
	}
	if action.Status != "Succeeded" || action.MachineID != "machine-123" {
		t.Errorf("action = %+v, want status=Succeeded machineId=machine-123", action)
	}
}

func TestGetMachineAction_HTTPError(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"code":"NotFound"}}`))
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	if _, err := c.GetMachineAction(context.Background(), "missing"); err == nil {
		t.Fatal("GetMachineAction: want error for HTTP 404, got nil")
	}
}

func TestPollMachineActionUntilTerminal_RetriesThenSucceeds(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var calls int
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		status := "Pending"
		if calls >= 3 {
			status = "Succeeded"
		}
		json.NewEncoder(w).Encode(map[string]any{"id": "action-1", "type": "Isolate", "status": status})
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	action, err := c.PollMachineActionUntilTerminal(context.Background(), "action-1", 5, time.Millisecond)
	if err != nil {
		t.Fatalf("PollMachineActionUntilTerminal: %v", err)
	}
	if action.Status != "Succeeded" {
		t.Errorf("Status = %q, want Succeeded", action.Status)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3 (should stop re-reading once terminal)", calls)
	}
}

func TestPollMachineActionUntilTerminal_ExhaustsAttemptsStillPending(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"id": "action-1", "type": "Isolate", "status": "Pending"})
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	action, err := c.PollMachineActionUntilTerminal(context.Background(), "action-1", 2, time.Millisecond)
	if err != nil {
		t.Fatalf("PollMachineActionUntilTerminal: %v", err)
	}
	if action.Status != "Pending" {
		t.Errorf("Status = %q, want Pending (must never guess a terminal outcome from a non-terminal read)", action.Status)
	}
}
