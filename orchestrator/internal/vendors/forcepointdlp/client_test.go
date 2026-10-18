package forcepointdlp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func refreshTokenMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["username"] != "admin" || body["password"] != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid_credentials"}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"refreshToken": "rtok"})
	}))
}

func accessTokenMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["refreshToken"] != "rtok" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid_refresh_token"}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"accessToken": "atok"})
	}))
}

func newTestClient(t *testing.T, refreshURL, accessURL, incidentsURL string) *Client {
	t.Helper()
	c := New(Config{Username: "admin", Password: "pw"})
	c.RefreshTokenURL = refreshURL
	c.AccessTokenURL = accessURL
	c.IncidentsURL = incidentsURL
	return c
}

func TestQueryDLPIncidents_ChainsRefreshThenAccessToken(t *testing.T) {
	refreshSrv := refreshTokenMock(t)
	defer refreshSrv.Close()
	accessSrv := accessTokenMock(t)
	defer accessSrv.Close()

	ts := time.Date(2026, 7, 14, 10, 2, 0, 0, time.UTC)
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		if _, hasIDs := req["ids"]; hasIDs {
			t.Error("request must be filters-mode, must not include an ids list")
		}
		if req["type"] != "INCIDENTS" {
			t.Errorf("type = %v, want INCIDENTS", req["type"])
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer atok" {
			t.Errorf("Authorization = %q, want %q", auth, "Bearer atok")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"incidents": []map[string]any{
				{"id": "fp-1", "timestamp": ts.Format(time.RFC3339), "policy": "BFSI Credit Card Policy", "severity": "high", "action": "block", "status": "open"},
			},
		})
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, refreshSrv.URL, accessSrv.URL, incidentsSrv.URL)
	incidents, err := c.QueryDLPIncidents(context.Background(), ts.Add(-time.Hour), ts.Add(time.Hour))
	if err != nil {
		t.Fatalf("QueryDLPIncidents: %v", err)
	}
	if len(incidents) != 1 || incidents[0].ID != "fp-1" || incidents[0].Policy != "BFSI Credit Card Policy" {
		t.Errorf("incidents = %+v, want 1 incident id=fp-1 policy=\"BFSI Credit Card Policy\"", incidents)
	}
}

func TestQueryDLPIncidents_EmptyIncidents_ReturnsEmptyNotError(t *testing.T) {
	refreshSrv := refreshTokenMock(t)
	defer refreshSrv.Close()
	accessSrv := accessTokenMock(t)
	defer accessSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"incidents": []map[string]any{}})
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, refreshSrv.URL, accessSrv.URL, incidentsSrv.URL)
	incidents, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("QueryDLPIncidents: %v", err)
	}
	if len(incidents) != 0 {
		t.Fatalf("incidents = %+v, want empty", incidents)
	}
}

func TestQueryDLPIncidents_PermissionDenied_NamesTheMissingScope(t *testing.T) {
	refreshSrv := refreshTokenMock(t)
	defer refreshSrv.Close()
	accessSrv := accessTokenMock(t)
	defer accessSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"forbidden"}`))
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, refreshSrv.URL, accessSrv.URL, incidentsSrv.URL)
	_, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err == nil {
		t.Fatal("want an error for HTTP 403, got nil")
	}
	if !strings.Contains(err.Error(), "license") && !strings.Contains(err.Error(), "role") && !strings.Contains(err.Error(), "Application") {
		t.Errorf("error = %q, want it to mention the likely cause (license/role/Application account type)", err.Error())
	}
}

func TestQueryDLPIncidents_RefreshTokenFails_NeverCallsAccessTokenOrIncidents(t *testing.T) {
	refreshSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_credentials"}`))
	}))
	defer refreshSrv.Close()
	accessSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("access-token endpoint must never be called when the refresh-token step itself failed")
	}))
	defer accessSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("incidents endpoint must never be called when the refresh-token step itself failed")
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, refreshSrv.URL, accessSrv.URL, incidentsSrv.URL)
	_, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err == nil {
		t.Fatal("want an error when the refresh-token endpoint rejects the credentials, got nil")
	}
}

func TestTestConnection_Success(t *testing.T) {
	refreshSrv := refreshTokenMock(t)
	defer refreshSrv.Close()
	accessSrv := accessTokenMock(t)
	defer accessSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"incidents": []map[string]any{}})
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, refreshSrv.URL, accessSrv.URL, incidentsSrv.URL)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Errorf("TestConnection: %v", err)
	}
}

func TestQueryDLPIncidents_CachesAccessToken_DoesNotRefetchPerCall(t *testing.T) {
	refreshSrv := refreshTokenMock(t)
	defer refreshSrv.Close()
	accessCalls := 0
	accessSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessCalls++
		json.NewEncoder(w).Encode(map[string]string{"accessToken": "atok"})
	}))
	defer accessSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"incidents": []map[string]any{}})
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, refreshSrv.URL, accessSrv.URL, incidentsSrv.URL)
	for i := 0; i < 3; i++ {
		if _, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now()); err != nil {
			t.Fatalf("QueryDLPIncidents call %d: %v", i, err)
		}
	}
	if accessCalls != 1 {
		t.Errorf("access-token endpoint called %d times, want exactly 1 (cached)", accessCalls)
	}
}
