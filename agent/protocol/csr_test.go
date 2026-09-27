package protocol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubmitCSR_SendsBootstrapSecretAndCSR(t *testing.T) {
	var gotToken, gotAgentID, gotCSR string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Agent-Token")
		var body CSRRequest
		json.NewDecoder(r.Body).Decode(&body)
		gotAgentID = body.AgentID
		gotCSR = body.CSRPEM
		json.NewEncoder(w).Encode(CSRResponse{CertPEM: "cert-pem-here", CAPEM: "ca-pem-here", ExpiresAt: "2027-01-01T00:00:00Z"})
	}))
	defer srv.Close()

	resp, err := SubmitCSR(context.Background(), srv.Client(), srv.URL, "bootstrap-secret-123", CSRRequest{
		AgentID: "abc123deadbeef01",
		CSRPEM:  "csr-pem-here",
	})
	if err != nil {
		t.Fatalf("SubmitCSR: %v", err)
	}
	if gotToken != "bootstrap-secret-123" {
		t.Errorf("X-Agent-Token = %q, want bootstrap-secret-123", gotToken)
	}
	if gotAgentID != "abc123deadbeef01" || gotCSR != "csr-pem-here" {
		t.Errorf("request body = {%q, %q}, want the values passed to SubmitCSR", gotAgentID, gotCSR)
	}
	if resp.CertPEM != "cert-pem-here" {
		t.Errorf("resp.CertPEM = %q, want cert-pem-here", resp.CertPEM)
	}
}

func TestSubmitCSR_ServerErrorReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()

	_, err := SubmitCSR(context.Background(), srv.Client(), srv.URL, "secret", CSRRequest{AgentID: "x", CSRPEM: "y"})
	if err == nil {
		t.Fatal("expected an error on a 409 response, got nil")
	}
}
