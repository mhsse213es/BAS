package statusclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClient_Status_DecodesResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization = %q, want Bearer test-token", got)
		}
		json.NewEncoder(w).Encode(StatusResponse{
			AgentVersion:    "2.1.0",
			Hostname:        "TESTHOST",
			ServerConnected: true,
			UptimeSec:       120,
		})
	}))
	defer srv.Close()

	c := New(srv.Listener.Addr().String(), "test-token")
	got, err := c.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got.Hostname != "TESTHOST" || !got.ServerConnected || got.UptimeSec != 120 {
		t.Fatalf("got %+v, want hostname=TESTHOST serverConnected=true uptimeSec=120", got)
	}
}

func TestClient_Status_RetriesOnceThenFails(t *testing.T) {
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(srv.Listener.Addr().String(), "")
	_, err := c.Status(context.Background())
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2 (1 initial + 1 retry)", attempts)
	}
}

func TestClient_Status_RespectsContextTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()

	c := New(srv.Listener.Addr().String(), "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := c.Status(ctx)
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
}
