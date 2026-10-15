package emailgwefficacy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/audspect/bas/internal/vendors/defender"
)

func analyzedEmailGraphServer(t *testing.T, records []map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"value": records})
	}))
}

func newAnalyzedEmailProvider(t *testing.T, tokenURL, graphURL string) *AnalyzedEmailEvidenceProvider {
	t.Helper()
	client := defender.New(defender.Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenURL
	client.BaseURL = graphURL
	return NewAnalyzedEmailEvidenceProviderFromClient(client)
}

func TestAnalyzedEmailEvidenceProvider_QuarantinedMessage_MapsToQuarantine(t *testing.T) {
	tokenSrv := defenderTokenMock(t)
	defer tokenSrv.Close()
	loggedTime := time.Date(2026, 7, 14, 10, 2, 0, 0, time.UTC)
	graphSrv := analyzedEmailGraphServer(t, []map[string]any{
		{
			"id": "email-1", "loggedDateTime": loggedTime.Format(time.RFC3339),
			"recipientEmailAddress": "finance-test@example-lab.test", "policy": "Anti-phish policy",
			"latestDelivery": map[string]any{"action": "blocked", "location": "quarantine"},
		},
	})
	defer graphSrv.Close()

	provider := newAnalyzedEmailProvider(t, tokenSrv.URL, graphSrv.URL)
	msg := MessageRef{Recipient: "finance-test@example-lab.test"}
	records, err := provider.EnforcementEvidenceFor(msg, TimeWindow{Start: loggedTime.Add(-time.Hour), End: loggedTime.Add(time.Hour)})
	if err != nil {
		t.Fatalf("EnforcementEvidenceFor: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %+v, want 1", records)
	}
	rec := records[0]
	if rec.Action != string(ExpectedQuarantine) {
		t.Errorf("Action = %q, want %q", rec.Action, ExpectedQuarantine)
	}
	if rec.Source != SourceLive {
		t.Errorf("Source = %q, want %q", rec.Source, SourceLive)
	}
	if rec.Provenance.Kind != ProvenanceObserved || rec.Provenance.Confidence != ConfidenceHigh {
		t.Errorf("Provenance = %+v, want {Observed, High}", rec.Provenance)
	}
}

func TestAnalyzedEmailEvidenceProvider_DeliveredMessage_MapsToDeliver(t *testing.T) {
	tokenSrv := defenderTokenMock(t)
	defer tokenSrv.Close()
	loggedTime := time.Now()
	graphSrv := analyzedEmailGraphServer(t, []map[string]any{
		{
			"id": "email-2", "loggedDateTime": loggedTime.Format(time.RFC3339),
			"recipientEmailAddress": "finance-test@example-lab.test",
			"latestDelivery":        map[string]any{"action": "delivered", "location": "inbox_folder"},
		},
	})
	defer graphSrv.Close()

	provider := newAnalyzedEmailProvider(t, tokenSrv.URL, graphSrv.URL)
	records, err := provider.EnforcementEvidenceFor(MessageRef{Recipient: "finance-test@example-lab.test"}, TimeWindow{Start: loggedTime.Add(-time.Hour), End: loggedTime.Add(time.Hour)})
	if err != nil {
		t.Fatalf("EnforcementEvidenceFor: %v", err)
	}
	if len(records) != 1 || records[0].Action != string(ExpectedDeliver) {
		t.Fatalf("records = %+v, want 1 record with Action %q", records, ExpectedDeliver)
	}
}

func TestAnalyzedEmailEvidenceProvider_BlockedNotQuarantined_MapsToReject(t *testing.T) {
	tokenSrv := defenderTokenMock(t)
	defer tokenSrv.Close()
	loggedTime := time.Now()
	graphSrv := analyzedEmailGraphServer(t, []map[string]any{
		{
			"id": "email-3", "loggedDateTime": loggedTime.Format(time.RFC3339),
			"recipientEmailAddress": "finance-test@example-lab.test",
			"latestDelivery":        map[string]any{"action": "blocked", "location": "dropped"},
		},
	})
	defer graphSrv.Close()

	provider := newAnalyzedEmailProvider(t, tokenSrv.URL, graphSrv.URL)
	records, err := provider.EnforcementEvidenceFor(MessageRef{Recipient: "finance-test@example-lab.test"}, TimeWindow{Start: loggedTime.Add(-time.Hour), End: loggedTime.Add(time.Hour)})
	if err != nil {
		t.Fatalf("EnforcementEvidenceFor: %v", err)
	}
	if len(records) != 1 || records[0].Action != string(ExpectedReject) {
		t.Fatalf("records = %+v, want 1 record with Action %q", records, ExpectedReject)
	}
}

func TestAnalyzedEmailEvidenceProvider_UnknownDeliveryAction_RecordExcludedNotGuessed(t *testing.T) {
	tokenSrv := defenderTokenMock(t)
	defer tokenSrv.Close()
	loggedTime := time.Now()
	graphSrv := analyzedEmailGraphServer(t, []map[string]any{
		{
			"id": "email-4", "loggedDateTime": loggedTime.Format(time.RFC3339),
			"recipientEmailAddress": "finance-test@example-lab.test",
			"latestDelivery":        map[string]any{"action": "unknown", "location": "unknown"},
			"originalDelivery":      map[string]any{"action": "unknownFutureValue", "location": "unknown"},
		},
	})
	defer graphSrv.Close()

	provider := newAnalyzedEmailProvider(t, tokenSrv.URL, graphSrv.URL)
	records, err := provider.EnforcementEvidenceFor(MessageRef{Recipient: "finance-test@example-lab.test"}, TimeWindow{Start: loggedTime.Add(-time.Hour), End: loggedTime.Add(time.Hour)})
	if err != nil {
		t.Fatalf("EnforcementEvidenceFor: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("records = %+v, want 0 -- an unmappable delivery action/location must never be guessed into a literal verdict", records)
	}
}

func TestAnalyzedEmailEvidenceProvider_LatestUnknown_FallsBackToOriginal(t *testing.T) {
	tokenSrv := defenderTokenMock(t)
	defer tokenSrv.Close()
	loggedTime := time.Now()
	graphSrv := analyzedEmailGraphServer(t, []map[string]any{
		{
			"id": "email-5", "loggedDateTime": loggedTime.Format(time.RFC3339),
			"recipientEmailAddress": "finance-test@example-lab.test",
			"latestDelivery":        map[string]any{"action": "unknown", "location": "unknown"},
			"originalDelivery":      map[string]any{"action": "blocked", "location": "quarantine"},
		},
	})
	defer graphSrv.Close()

	provider := newAnalyzedEmailProvider(t, tokenSrv.URL, graphSrv.URL)
	records, err := provider.EnforcementEvidenceFor(MessageRef{Recipient: "finance-test@example-lab.test"}, TimeWindow{Start: loggedTime.Add(-time.Hour), End: loggedTime.Add(time.Hour)})
	if err != nil {
		t.Fatalf("EnforcementEvidenceFor: %v", err)
	}
	if len(records) != 1 || records[0].Action != string(ExpectedQuarantine) {
		t.Fatalf("records = %+v, want 1 record falling back to originalDelivery's quarantine mapping", records)
	}
}

func TestAnalyzedEmailEvidenceProvider_HTTPError_ReturnsError(t *testing.T) {
	tokenSrv := defenderTokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer graphSrv.Close()

	provider := newAnalyzedEmailProvider(t, tokenSrv.URL, graphSrv.URL)
	_, err := provider.EnforcementEvidenceFor(MessageRef{Recipient: "finance-test@example-lab.test"}, TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now()})
	if err == nil {
		t.Fatal("expected an error from a 403 Graph response")
	}
}

// TestDefenderMailEvidenceProvider_SPFScenario_EndToEnd_BothLegsSourceLive
// proves the full composed MailEvidenceProvider against
// VerifyMailExpectation for Phase 3a's own SPFAlignmentExpectation
// known-bad case -- Phase 3's exit criteria: both Enforcement and
// Detection evidence present and tagged SourceLive, httptest-backed
// (no live tenant needed), one real adapter call path for each leg
// instead of two separate fixtures.
func TestDefenderMailEvidenceProvider_SPFScenario_EndToEnd_BothLegsSourceLive(t *testing.T) {
	tokenSrv := defenderTokenMock(t)
	defer tokenSrv.Close()
	now := time.Now()

	mux := http.NewServeMux()
	mux.HandleFunc("/security/collaboration/analyzedEmails", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "email-1", "loggedDateTime": now.Format(time.RFC3339),
					"recipientEmailAddress": "finance-test@example-lab.test",
					"policy":                "Anti-phish policy",
					"latestDelivery":        map[string]any{"action": "blocked", "location": "quarantine"},
					"authenticationDetails": map[string]any{"senderPolicyFramework": "fail"},
					"alertIds":              []string{"alert-1"},
				},
			},
		})
	})
	mux.HandleFunc("/security/alerts_v2", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "alert-1", "title": "Spoofed sender delivered to finance-test@example-lab.test",
					"severity": "high", "createdDateTime": now.Format(time.RFC3339),
				},
			},
		})
	})
	graphSrv := httptest.NewServer(mux)
	defer graphSrv.Close()

	client := defender.New(defender.Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL
	provider := NewDefenderMailEvidenceProviderFromClient(client)

	exp := SPFAlignmentExpectation(false) // known-bad: spoofed sender, expected quarantine
	window := TimeWindow{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, window)

	if result.Prevention.Verdict != VerdictConfirmedSuccess {
		t.Errorf("Prevention.Verdict = %q, want %q", result.Prevention.Verdict, VerdictConfirmedSuccess)
	}
	if result.DetectionVerdict.Verdict != VerdictConfirmedSuccess {
		t.Errorf("DetectionVerdict.Verdict = %q, want %q", result.DetectionVerdict.Verdict, VerdictConfirmedSuccess)
	}
	if len(result.Enforcement) != 1 || result.Enforcement[0].Source != SourceLive {
		t.Errorf("Enforcement = %+v, want exactly 1 record tagged SourceLive", result.Enforcement)
	}
	if len(result.Detection) != 1 || result.Detection[0].Source != SourceLive {
		t.Errorf("Detection = %+v, want exactly 1 record tagged SourceLive", result.Detection)
	}
}

// TestAnalyzedEmailEvidenceProvider_RealAPI_SkipsWithoutCredentials is
// the live-tenant integration test, gated exactly like
// DefenderDetectionProvider's own real-API test -- see
// docs/emailgw-mastery-qa-log.md item #1b.
func TestAnalyzedEmailEvidenceProvider_RealAPI_SkipsWithoutCredentials(t *testing.T) {
	tenantID := os.Getenv("AUDSPECT_EMAILGW_DEFENDER_TENANT_ID")
	clientID := os.Getenv("AUDSPECT_EMAILGW_DEFENDER_CLIENT_ID")
	clientSecret := os.Getenv("AUDSPECT_EMAILGW_DEFENDER_CLIENT_SECRET")
	if tenantID == "" || clientID == "" || clientSecret == "" {
		t.Skip("AUDSPECT_EMAILGW_DEFENDER_{TENANT_ID,CLIENT_ID,CLIENT_SECRET} not set -- skipping real Graph API test (docs/emailgw-mastery-qa-log.md item #1b)")
	}

	provider := NewAnalyzedEmailEvidenceProvider(defender.Config{TenantID: tenantID, ClientID: clientID, ClientSecret: clientSecret})
	_, err := provider.EnforcementEvidenceFor(
		MessageRef{Recipient: "smoke-test@example-lab.test"},
		TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now()},
	)
	if err != nil {
		t.Fatalf("EnforcementEvidenceFor against the real tenant: %v", err)
	}
}
