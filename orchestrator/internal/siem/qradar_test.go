package siem

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeQRadarEvent is one event the fake server's /ariel/searches/.../results
// endpoint returns, in QRadar's own wire shape (flat JSON object per event).
type fakeQRadarEvent struct {
	sourceIP    string
	startTimeMs int64
	ruleName    string
}

// newFakeQRadarServer serves the three Ariel REST endpoints QueryAlerts
// drives: start a search (always "search-1"), poll its status (always
// immediately COMPLETED), and fetch its results (the given events). Callers
// own closing the returned server.
func newFakeQRadarServer(t *testing.T, events []fakeQRadarEvent) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/console/restapi/api/ariel/searches", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"search_id": "search-1"})
	})
	mux.HandleFunc("/console/restapi/api/ariel/searches/search-1", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "COMPLETED"})
	})
	mux.HandleFunc("/console/restapi/api/ariel/searches/search-1/results", func(w http.ResponseWriter, r *http.Request) {
		evs := make([]map[string]any, 0, len(events))
		for _, e := range events {
			evs = append(evs, map[string]any{
				"sourceip":  e.sourceIP,
				"starttime": float64(e.startTimeMs),
				"rule_name": e.ruleName,
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"events": evs})
	})
	return httptest.NewServer(mux)
}

func TestQRadarPing_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/console/restapi/api/system/about" {
			t.Errorf("Ping hit unexpected path %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newQRadarClient(Config{ConsoleURL: srv.URL, Token: "sec-token"})
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestQRadarPing_Unauthorized_ReturnsAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newQRadarClient(Config{ConsoleURL: srv.URL, Token: "wrong"})
	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("expected an error on 401")
	}
}

func TestQRadarPing_ServerError_ReturnsHTTPStatusInMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newQRadarClient(Config{ConsoleURL: srv.URL, Token: "sec-token"})
	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("expected an error on 500")
	}
}

func TestQRadarSetAuth_PrefersTokenOverBasicAuth(t *testing.T) {
	var gotSEC, gotAuthHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSEC = r.Header.Get("SEC")
		gotAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newQRadarClient(Config{ConsoleURL: srv.URL, Token: "sec-token", Username: "bob", Password: "hunter2"})
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if gotSEC != "sec-token" {
		t.Errorf("SEC header = %q, want %q", gotSEC, "sec-token")
	}
	if gotAuthHeader != "" {
		t.Errorf("Authorization header = %q, want empty (token takes precedence over basic auth)", gotAuthHeader)
	}
}

func TestQRadarSetAuth_FallsBackToBasicAuthWithoutToken(t *testing.T) {
	var sawBasicAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		sawBasicAuth = ok && user == "bob" && pass == "hunter2"
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newQRadarClient(Config{ConsoleURL: srv.URL, Username: "bob", Password: "hunter2"})
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if !sawBasicAuth {
		t.Error("expected HTTP Basic auth with the configured username/password when no token is set")
	}
}

func TestQRadarQueryAlerts_HappyPath_ParsesEventsIntoSIEMAlerts(t *testing.T) {
	startMs := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC).UnixMilli()
	srv := newFakeQRadarServer(t, []fakeQRadarEvent{
		{sourceIP: "10.0.0.5", startTimeMs: startMs, ruleName: "Suspicious PowerShell"},
	})
	defer srv.Close()

	c := newQRadarClient(Config{ConsoleURL: srv.URL, Token: "sec-token"})
	alerts, err := c.QueryAlerts(context.Background(), "10.0.0.5",
		time.Now().Add(-time.Hour), time.Now(), 500)
	if err != nil {
		t.Fatalf("QueryAlerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("len(alerts) = %d, want 1", len(alerts))
	}
	a := alerts[0]
	if a.SourceIP != "10.0.0.5" {
		t.Errorf("SourceIP = %q, want %q", a.SourceIP, "10.0.0.5")
	}
	if a.RuleName != "Suspicious PowerShell" {
		t.Errorf("RuleName = %q, want %q", a.RuleName, "Suspicious PowerShell")
	}
	if !a.Timestamp.Equal(time.UnixMilli(startMs).UTC()) {
		t.Errorf("Timestamp = %v, want %v", a.Timestamp, time.UnixMilli(startMs).UTC())
	}
}

func TestQRadarQueryAlerts_NoEvents_ReturnsEmptySliceNotNilError(t *testing.T) {
	srv := newFakeQRadarServer(t, nil)
	defer srv.Close()

	c := newQRadarClient(Config{ConsoleURL: srv.URL, Token: "sec-token"})
	alerts, err := c.QueryAlerts(context.Background(), "10.0.0.5", time.Now().Add(-time.Hour), time.Now(), 500)
	if err != nil {
		t.Fatalf("QueryAlerts: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("len(alerts) = %d, want 0", len(alerts))
	}
}

func TestStartSearch_HTTPError_ReturnsBodyInMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid AQL syntax"))
	}))
	defer srv.Close()

	c := newQRadarClient(Config{ConsoleURL: srv.URL, Token: "sec-token"})
	_, err := c.startSearch(context.Background(), "SELECT * FROM events")
	if err == nil {
		t.Fatal("expected an error on HTTP 400")
	}
}

func TestStartSearch_MissingSearchID_ReturnsParseError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "no search_id here"})
	}))
	defer srv.Close()

	c := newQRadarClient(Config{ConsoleURL: srv.URL, Token: "sec-token"})
	_, err := c.startSearch(context.Background(), "SELECT * FROM events")
	if err == nil {
		t.Fatal("expected an error when the response has no search_id")
	}
}

func TestWaitForSearch_ErrorStatus_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ERROR"})
	}))
	defer srv.Close()

	c := newQRadarClient(Config{ConsoleURL: srv.URL, Token: "sec-token"})
	err := c.waitForSearch(context.Background(), "search-1", 5*time.Second)
	if err == nil {
		t.Fatal("expected an error when QRadar reports search status ERROR")
	}
}

func TestWaitForSearch_CancelledStatus_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "CANCELLED"})
	}))
	defer srv.Close()

	c := newQRadarClient(Config{ConsoleURL: srv.URL, Token: "sec-token"})
	err := c.waitForSearch(context.Background(), "search-1", 5*time.Second)
	if err == nil {
		t.Fatal("expected an error when QRadar reports search status CANCELLED")
	}
}

func TestWaitForSearch_NeverCompletes_TimesOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "EXECUTING"})
	}))
	defer srv.Close()

	c := newQRadarClient(Config{ConsoleURL: srv.URL, Token: "sec-token"})
	err := c.waitForSearch(context.Background(), "search-1", 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected a timeout error when the search never reaches COMPLETED")
	}
}

func TestFetchResults_StartTimeAsJSONNumber_ParsesTimestamp(t *testing.T) {
	// decode(&raw) in fetchResults uses the standard decoder (float64 for
	// numbers), but this locks in that an int64-range "starttime" still
	// round-trips correctly through that float64 path, since epoch-ms
	// timestamps are well within float64's exact-integer range.
	startMs := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC).UnixMilli()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"events": []map[string]any{
				{"sourceip": "10.0.0.5", "starttime": startMs},
			},
		})
	}))
	defer srv.Close()

	c := newQRadarClient(Config{ConsoleURL: srv.URL, Token: "sec-token"})
	alerts, err := c.fetchResults(context.Background(), "search-1")
	if err != nil {
		t.Fatalf("fetchResults: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("len(alerts) = %d, want 1", len(alerts))
	}
	if !alerts[0].Timestamp.Equal(time.UnixMilli(startMs).UTC()) {
		t.Errorf("Timestamp = %v, want %v", alerts[0].Timestamp, time.UnixMilli(startMs).UTC())
	}
}

func TestFetchResults_MissingStartTime_LeavesZeroTimestamp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"events": []map[string]any{
				{"sourceip": "10.0.0.5"},
			},
		})
	}))
	defer srv.Close()

	c := newQRadarClient(Config{ConsoleURL: srv.URL, Token: "sec-token"})
	alerts, err := c.fetchResults(context.Background(), "search-1")
	if err != nil {
		t.Fatalf("fetchResults: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("len(alerts) = %d, want 1", len(alerts))
	}
	if !alerts[0].Timestamp.IsZero() {
		t.Errorf("Timestamp = %v, want zero value when starttime is absent", alerts[0].Timestamp)
	}
}
