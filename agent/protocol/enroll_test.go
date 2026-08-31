package protocol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnroll_SendsExpectedRequestShape(t *testing.T) {
	var gotBody EnrollRequest
	var gotHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Agent-Token")
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(EnrollResponse{AgentID: "a1", State: "active", Trusted: true})
	}))
	defer server.Close()

	req := EnrollRequest{AgentID: "a1", Hostname: "H", EnvLabel: "prod"}
	resp, err := Enroll(context.Background(), server.Client(), server.URL, "secret123", req)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if gotBody.AgentID != "a1" || gotBody.Hostname != "H" || gotBody.EnvLabel != "prod" {
		t.Errorf("server received %+v, want AgentID=a1 Hostname=H EnvLabel=prod", gotBody)
	}
	if gotHeader != "secret123" {
		t.Errorf("X-Agent-Token = %q, want secret123", gotHeader)
	}
	if resp.State != "active" || !resp.Trusted {
		t.Errorf("resp = %+v, want State=active Trusted=true", resp)
	}
}

func TestEnroll_ServerErrorReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := Enroll(context.Background(), server.Client(), server.URL, "", EnrollRequest{})
	if err == nil {
		t.Fatal("Enroll: want error on server 500, got nil")
	}
}

func TestEnroll_MalformedResponseBodyDoesNotError(t *testing.T) {
	// Old server versions return 200 with no body -- must not fail the call.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := Enroll(context.Background(), server.Client(), server.URL, "", EnrollRequest{})
	if err != nil {
		t.Fatalf("Enroll with empty 200 body: %v, want nil", err)
	}
}
