package phishidentity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRiskySignInsForUser_HTTPTestServer_RealOAuthAndHTTPPath(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	var gotAuthHeader string
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{"id": "s1", "userId": "u1", "createdDateTime": "2026-10-18T10:00:00Z", "riskState": "confirmedCompromised"},
				{"id": "s2", "userId": "u1", "createdDateTime": "2026-10-18T10:01:00Z", "riskState": "none"},       // not risky, must be filtered out
				{"id": "s3", "userId": "u1", "createdDateTime": "2026-10-18T10:02:00Z", "riskState": "remediated"}, // already remediated, must be filtered out
				{"id": "s4", "userId": "u2", "createdDateTime": "2026-10-18T10:03:00Z", "riskState": "atRisk"},     // wrong user
			},
		})
	}))
	defer graphSrv.Close()

	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	events, err := client.RiskySignInsForUser(t.Context(), "u1")
	if err != nil {
		t.Fatalf("RiskySignInsForUser() error = %v", err)
	}
	if gotAuthHeader != "Bearer tok" {
		t.Errorf("Authorization header = %q, want %q", gotAuthHeader, "Bearer tok")
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1 (non-risky, remediated, and wrong-user records must be filtered out)", len(events))
	}
	if events[0].ID != "s1" {
		t.Errorf("events[0].ID = %q, want %q", events[0].ID, "s1")
	}
}

func TestDetectSessionTheftResponseHeuristic_RevokedAfterRiskyEvent(t *testing.T) {
	risky := []RiskySignInEvent{{ID: "s1", CreatedDateTime: time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC), RiskState: "confirmedCompromised"}}
	sessionsValidFrom := time.Date(2026, 10, 18, 10, 5, 0, 0, time.UTC)

	verdict, detail := DetectSessionTheftResponseHeuristic(risky, sessionsValidFrom, 10*time.Minute)
	if verdict != SessionTheftRevokedAfterRiskyEvent {
		t.Errorf("verdict = %q (%s), want %q", verdict, detail, SessionTheftRevokedAfterRiskyEvent)
	}
}

func TestDetectSessionTheftResponseHeuristic_NotRevokedWithinWindow(t *testing.T) {
	risky := []RiskySignInEvent{{ID: "s1", CreatedDateTime: time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC), RiskState: "atRisk"}}
	sessionsValidFrom := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC) // outside the window

	verdict, _ := DetectSessionTheftResponseHeuristic(risky, sessionsValidFrom, 10*time.Minute)
	if verdict != SessionTheftNotRevoked {
		t.Errorf("verdict = %q, want %q", verdict, SessionTheftNotRevoked)
	}
}

func TestDetectSessionTheftResponseHeuristic_NoRiskyEvent_Unknown(t *testing.T) {
	verdict, _ := DetectSessionTheftResponseHeuristic(nil, time.Now(), 10*time.Minute)
	if verdict != SessionTheftUnknown {
		t.Errorf("verdict = %q, want %q (absence of evidence must never be read as revoked or not_revoked)", verdict, SessionTheftUnknown)
	}
}

func TestDetectSessionTheftResponseHeuristic_ZeroSessionsValidFrom_Unknown(t *testing.T) {
	risky := []RiskySignInEvent{{ID: "s1", CreatedDateTime: time.Now(), RiskState: "atRisk"}}
	verdict, _ := DetectSessionTheftResponseHeuristic(risky, time.Time{}, 10*time.Minute)
	if verdict != SessionTheftUnknown {
		t.Errorf("verdict = %q, want %q", verdict, SessionTheftUnknown)
	}
}
