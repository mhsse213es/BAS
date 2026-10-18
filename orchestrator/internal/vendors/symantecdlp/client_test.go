package symantecdlp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func loginMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if !strings.Contains(ct, "application/x-www-form-urlencoded") {
			t.Errorf("Content-Type = %q, want form-urlencoded (forms-based auth, not JSON/OAuth)", ct)
		}
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if form.Get("username") != "svcacct" || form.Get("password") != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid_credentials"}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"sessionToken": "sess-1"})
	}))
}

func newTestClient(t *testing.T, loginURL, incidentsURL string) *Client {
	t.Helper()
	c := New(Config{Username: "svcacct", Password: "pw"})
	c.LoginURL = loginURL
	c.IncidentsURL = incidentsURL
	return c
}

func TestQueryDLPIncidents_LogsInWithFormsAuth_NotJSONOrBasic(t *testing.T) {
	loginSrv := loginMock(t)
	defer loginSrv.Close()

	ts := time.Date(2026, 7, 14, 10, 2, 0, 0, time.UTC)
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("Authorization header = %q, want empty (session carried another way, not Bearer/Basic)", auth)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"incidents": []map[string]any{
				{"incidentId": "sym-1", "detectionDate": ts.Format(time.RFC3339), "status": "new", "severity": "high", "incidentType": "Network"},
			},
		})
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, loginSrv.URL, incidentsSrv.URL)
	incidents, err := c.QueryDLPIncidents(context.Background(), ts.Add(-time.Hour), ts.Add(time.Hour))
	if err != nil {
		t.Fatalf("QueryDLPIncidents: %v", err)
	}
	if len(incidents) != 1 || incidents[0].ID != "sym-1" || incidents[0].IncidentType != "Network" {
		t.Errorf("incidents = %+v, want 1 incident id=sym-1 incidentType=Network", incidents)
	}
}

func TestQueryDLPIncidents_EmptyIncidents_ReturnsEmptyNotError(t *testing.T) {
	loginSrv := loginMock(t)
	defer loginSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"incidents": []map[string]any{}})
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, loginSrv.URL, incidentsSrv.URL)
	incidents, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("QueryDLPIncidents: %v", err)
	}
	if len(incidents) != 0 {
		t.Fatalf("incidents = %+v, want empty", incidents)
	}
}

func TestQueryDLPIncidents_PermissionDenied_NamesTheMissingScope(t *testing.T) {
	loginSrv := loginMock(t)
	defer loginSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"forbidden"}`))
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, loginSrv.URL, incidentsSrv.URL)
	_, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err == nil {
		t.Fatal("want an error for HTTP 403, got nil")
	}
	if !strings.Contains(err.Error(), "license") && !strings.Contains(err.Error(), "role") && !strings.Contains(err.Error(), "permission") {
		t.Errorf("error = %q, want it to mention the likely cause (license/role/permission)", err.Error())
	}
}

func TestQueryDLPIncidents_LoginFails_NeverCallsIncidentsOrRetries(t *testing.T) {
	loginAttempts := 0
	loginSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginAttempts++
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_credentials"}`))
	}))
	defer loginSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("incidents endpoint must never be called when login itself failed")
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, loginSrv.URL, incidentsSrv.URL)
	_, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err == nil {
		t.Fatal("want an error when login rejects the credentials, got nil")
	}
	if loginAttempts != 1 {
		t.Errorf("login attempted %d times, want exactly 1 -- must never retry a rejected login (account lockout risk)", loginAttempts)
	}
}

func TestTestConnection_Success(t *testing.T) {
	loginSrv := loginMock(t)
	defer loginSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"incidents": []map[string]any{}})
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, loginSrv.URL, incidentsSrv.URL)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Errorf("TestConnection: %v", err)
	}
}

func TestQueryDLPIncidents_CachesSession_DoesNotReloginPerCall(t *testing.T) {
	loginCalls := 0
	loginSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginCalls++
		json.NewEncoder(w).Encode(map[string]string{"sessionToken": "sess-1"})
	}))
	defer loginSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"incidents": []map[string]any{}})
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, loginSrv.URL, incidentsSrv.URL)
	for i := 0; i < 3; i++ {
		if _, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now()); err != nil {
			t.Fatalf("QueryDLPIncidents call %d: %v", i, err)
		}
	}
	if loginCalls != 1 {
		t.Errorf("login endpoint called %d times, want exactly 1 (cached session)", loginCalls)
	}
}
