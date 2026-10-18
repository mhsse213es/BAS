package phishidentity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMFADenialEventsForUser_HTTPTestServer_RealOAuthAndHTTPPath(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	var gotAuthHeader string
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{"id": "s1", "userId": "u1", "createdDateTime": "2026-10-18T10:00:00Z",
					"status": map[string]any{"errorCode": 500121, "additionalDetails": "MFA denied; user declined the authentication"}},
				{"id": "s2", "userId": "u1", "createdDateTime": "2026-10-18T10:01:00Z",
					"status": map[string]any{"errorCode": 0, "additionalDetails": ""}}, // not an MFA denial, must be filtered out
				{"id": "s3", "userId": "u2", "createdDateTime": "2026-10-18T10:02:00Z",
					"status": map[string]any{"errorCode": 500121, "additionalDetails": "MFA denied; user did not respond to mobile app notification"}}, // wrong user
			},
		})
	}))
	defer graphSrv.Close()

	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	events, err := client.MFADenialEventsForUser(t.Context(), "u1")
	if err != nil {
		t.Fatalf("MFADenialEventsForUser() error = %v", err)
	}
	if gotAuthHeader != "Bearer tok" {
		t.Errorf("Authorization header = %q, want %q", gotAuthHeader, "Bearer tok")
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1 (the non-MFA-denial and wrong-user records must be re-filtered out)", len(events))
	}
	if events[0].ID != "s1" {
		t.Errorf("events[0].ID = %q, want %q", events[0].ID, "s1")
	}
}

func TestDetectMFAFatigueHeuristic_Burst_Suspected(t *testing.T) {
	base := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	var events []MFADenialEvent
	for i := 0; i < 5; i++ {
		events = append(events, MFADenialEvent{ID: "s", UserID: "u1", CreatedDateTime: base.Add(time.Duration(i) * time.Minute)})
	}

	verdict, detail := DetectMFAFatigueHeuristic(events, 5, 10*time.Minute)
	if verdict != MFAFatigueSuspected {
		t.Errorf("verdict = %q (%s), want %q", verdict, detail, MFAFatigueSuspected)
	}
}

func TestDetectMFAFatigueHeuristic_SparseEvents_NotObserved(t *testing.T) {
	base := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	events := []MFADenialEvent{
		{ID: "s1", UserID: "u1", CreatedDateTime: base},
		{ID: "s2", UserID: "u1", CreatedDateTime: base.Add(time.Hour)},
	}

	verdict, _ := DetectMFAFatigueHeuristic(events, 5, 10*time.Minute)
	if verdict != MFAFatigueNotObserved {
		t.Errorf("verdict = %q, want %q", verdict, MFAFatigueNotObserved)
	}
}

func TestDetectMFAFatigueHeuristic_NoEvents_Unknown(t *testing.T) {
	verdict, _ := DetectMFAFatigueHeuristic(nil, 5, 10*time.Minute)
	if verdict != MFAFatigueUnknown {
		t.Errorf("verdict = %q, want %q (absence of evidence must never be read as suspected or not_observed)", verdict, MFAFatigueUnknown)
	}
}
