package trellixdlp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func tokenMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Review Focus: Trellix's IAM uses HTTP Basic auth for the
		// client-credentials grant, not Entra's form-encoded client_secret
		// field -- confirm the request actually carries it.
		auth := r.Header.Get("Authorization")
		wantPrefix := "Basic " + base64.StdEncoding.EncodeToString([]byte("c1:s1"))
		if auth != wantPrefix {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	}))
}

func newTestClient(t *testing.T, tokenURL, eventsURL string) *Client {
	t.Helper()
	c := New(Config{ClientID: "c1", ClientSecret: "s1"})
	c.TokenURL = tokenURL
	c.EventsURL = eventsURL
	return c
}

func TestQueryDLPIncidents_ReturnsNormalizedIncidents(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	ts := time.Date(2026, 7, 14, 10, 2, 0, 0, time.UTC)
	eventsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") != "incidents" {
			t.Errorf("query type = %q, want %q", r.URL.Query().Get("type"), "incidents")
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer tok" {
			t.Errorf("Authorization = %q, want %q", auth, "Bearer tok")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"events": []map[string]any{
				{
					"id": "inc-1", "timestamp": ts.Format(time.RFC3339),
					"severity": "high", "policyName": "BFSI Credit Card Policy",
					"action": "block", "status": "resolved",
				},
			},
		})
	}))
	defer eventsSrv.Close()

	c := newTestClient(t, tokenSrv.URL, eventsSrv.URL)
	incidents, err := c.QueryDLPIncidents(context.Background(), ts.Add(-time.Hour), ts.Add(time.Hour))
	if err != nil {
		t.Fatalf("QueryDLPIncidents: %v", err)
	}
	if len(incidents) != 1 {
		t.Fatalf("incidents = %+v, want 1", incidents)
	}
	inc := incidents[0]
	if inc.ID != "inc-1" || inc.PolicyName != "BFSI Credit Card Policy" || inc.Action != "block" {
		t.Errorf("incident = %+v, want id=inc-1 policyName=\"BFSI Credit Card Policy\" action=block", inc)
	}
	if !inc.Timestamp.Equal(ts) {
		t.Errorf("Timestamp = %v, want %v", inc.Timestamp, ts)
	}
}

func TestQueryDLPIncidents_EmptyEvents_ReturnsEmptyNotError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	eventsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"events": []map[string]any{}})
	}))
	defer eventsSrv.Close()

	c := newTestClient(t, tokenSrv.URL, eventsSrv.URL)
	incidents, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("QueryDLPIncidents: %v", err)
	}
	if len(incidents) != 0 {
		t.Fatalf("incidents = %+v, want empty", incidents)
	}
}

func TestQueryDLPIncidents_PermissionDenied_NamesTheMissingScope(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	eventsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"forbidden"}`))
	}))
	defer eventsSrv.Close()

	c := newTestClient(t, tokenSrv.URL, eventsSrv.URL)
	_, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err == nil {
		t.Fatal("want an error for HTTP 403, got nil")
	}
	if !strings.Contains(err.Error(), "license") && !strings.Contains(err.Error(), "scope") {
		t.Errorf("error = %q, want it to mention the missing license/scope", err.Error())
	}
}

func TestQueryDLPIncidents_TokenFetchFails_ReturnsError(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer tokenSrv.Close()
	eventsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("events endpoint must never be called when the token fetch itself failed")
	}))
	defer eventsSrv.Close()

	c := newTestClient(t, tokenSrv.URL, eventsSrv.URL)
	_, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err == nil {
		t.Fatal("want an error when the token endpoint rejects the credentials, got nil")
	}
}

func TestTestConnection_Success(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	eventsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"events": []map[string]any{}})
	}))
	defer eventsSrv.Close()

	c := newTestClient(t, tokenSrv.URL, eventsSrv.URL)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Errorf("TestConnection: %v", err)
	}
}

// Review Focus: the token must be cached and reused, not re-fetched on
// every call -- same caching contract as msauth.EntraTokenSource, mirrored
// here since Trellix needs its own token source (different grant
// mechanics: Basic-auth header, not Entra's form-encoded client_secret).
func TestQueryDLPIncidents_CachesToken_DoesNotRefetchPerCall(t *testing.T) {
	tokenCalls := 0
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	}))
	defer tokenSrv.Close()
	eventsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"events": []map[string]any{}})
	}))
	defer eventsSrv.Close()

	c := newTestClient(t, tokenSrv.URL, eventsSrv.URL)
	for i := 0; i < 3; i++ {
		if _, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now()); err != nil {
			t.Fatalf("QueryDLPIncidents call %d: %v", i, err)
		}
	}
	if tokenCalls != 1 {
		t.Errorf("token endpoint called %d times, want exactly 1 (cached)", tokenCalls)
	}
}
