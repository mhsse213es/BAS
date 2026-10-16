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

// TestDefenderMailEvidenceProvider_LegitimateMail_EndToEnd_NoFalsePositive
// is this adapter's Phase 6 false-positive regression test: a
// correctly-aligned, legitimately-delivered message (SPF pass, no
// alerts) must resolve to ConfirmedSuccess, never a fabricated
// ConfirmedFailure -- the same "a delivered message is not
// automatically proof of a vulnerability" discipline §4 of the
// architecture spec requires, proven here against the real adapter
// rather than the fixture provider scenarios_test.go already covers.
func TestDefenderMailEvidenceProvider_LegitimateMail_EndToEnd_NoFalsePositive(t *testing.T) {
	tokenSrv := defenderTokenMock(t)
	defer tokenSrv.Close()
	now := time.Now()

	mux := http.NewServeMux()
	mux.HandleFunc("/security/collaboration/analyzedEmails", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "email-2", "loggedDateTime": now.Format(time.RFC3339),
					"recipientEmailAddress": "finance-test@example-lab.test",
					"policy":                "Default anti-phish policy",
					"latestDelivery":        map[string]any{"action": "delivered", "location": "inbox_folder"},
					"authenticationDetails": map[string]any{"senderPolicyFramework": "pass"},
					"alertIds":              []string{},
				},
			},
		})
	})
	mux.HandleFunc("/security/alerts_v2", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{}})
	})
	graphSrv := httptest.NewServer(mux)
	defer graphSrv.Close()

	client := defender.New(defender.Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL
	provider := NewDefenderMailEvidenceProviderFromClient(client)

	exp := SPFAlignmentExpectation(true) // known-good: aligned sender, expected deliver
	window := TimeWindow{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, window)

	if result.Prevention.Verdict != VerdictConfirmedSuccess {
		t.Errorf("Prevention.Verdict = %q, want %q -- legitimate, correctly-delivered mail must never be reported as a gateway failure", result.Prevention.Verdict, VerdictConfirmedSuccess)
	}
	if len(result.Enforcement) != 1 || result.Enforcement[0].Source != SourceLive {
		t.Errorf("Enforcement = %+v, want exactly 1 record tagged SourceLive", result.Enforcement)
	}
}

// TestDefenderMailEvidenceProvider_ResponseEvidence_EndToEnd_SuccessfullyRemediated
// proves ResponseVerdict against the real composed adapter: an alert
// whose investigationState resolves to successfullyRemediated must
// produce ConfirmedSuccess with a captured record, the Response
// dimension's own first live end-to-end proof (the generic model and
// the fixture-level mapping are covered separately in verify_test.go/
// defender.go's own unit tests; this is the same "one real adapter
// call path, not two fixtures" standard the SPF end-to-end test above
// holds Enforcement/Detection to).
func TestDefenderMailEvidenceProvider_ResponseEvidence_EndToEnd_SuccessfullyRemediated(t *testing.T) {
	tokenSrv := defenderTokenMock(t)
	defer tokenSrv.Close()
	now := time.Now()
	resolved := now.Add(10 * time.Minute)

	mux := http.NewServeMux()
	mux.HandleFunc("/security/collaboration/analyzedEmails", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{}})
	})
	mux.HandleFunc("/security/alerts_v2", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "alert-1", "title": "Malicious email delivered to finance-test@example-lab.test",
					"severity": "high", "createdDateTime": now.Format(time.RFC3339),
					"investigationState": "successfullyRemediated",
					"resolvedDateTime":   resolved.Format(time.RFC3339),
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

	msg := MessageRef{Recipient: "finance-test@example-lab.test", MessageClass: "post-delivery-threat-response"}
	window := TimeWindow{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}
	records, err := provider.ResponseEvidenceFor(msg, window)
	if err != nil {
		t.Fatalf("ResponseEvidenceFor: %v", err)
	}
	if len(records) != 1 || !records[0].Completed || records[0].Source != SourceLive {
		t.Fatalf("records = %+v, want exactly 1 Completed record tagged SourceLive", records)
	}
	if records[0].DurationToComplete != 10*time.Minute {
		t.Errorf("DurationToComplete = %v, want 10m", records[0].DurationToComplete)
	}
	if records[0].CorrelationID != "alert-1" {
		t.Errorf("CorrelationID = %q, want %q -- response evidence must carry the real alert id it was correlated by", records[0].CorrelationID, "alert-1")
	}
}

// TestDefenderMailEvidenceProvider_ResponseEvidence_EndToEnd_PartiallyRemediatedIsFailure
// proves the strict mapping end-to-end: partiallyRemediated is not a
// weaker success -- it is ConfirmedFailure, per the explicit decision
// that ResponseEvidence.Completed means fully completed.
func TestDefenderMailEvidenceProvider_ResponseEvidence_EndToEnd_PartiallyRemediatedIsFailure(t *testing.T) {
	tokenSrv := defenderTokenMock(t)
	defer tokenSrv.Close()
	now := time.Now()

	mux := http.NewServeMux()
	mux.HandleFunc("/security/collaboration/analyzedEmails", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{}})
	})
	mux.HandleFunc("/security/alerts_v2", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "alert-1", "title": "Malicious email delivered to finance-test@example-lab.test",
					"severity": "high", "createdDateTime": now.Format(time.RFC3339),
					"investigationState": "partiallyRemediated",
					"resolvedDateTime":   now.Add(time.Minute).Format(time.RFC3339),
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

	msg := MessageRef{Recipient: "finance-test@example-lab.test", MessageClass: "post-delivery-threat-response"}
	window := TimeWindow{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}
	records, err := provider.ResponseEvidenceFor(msg, window)
	if err != nil {
		t.Fatalf("ResponseEvidenceFor: %v", err)
	}
	if len(records) != 1 || records[0].Completed {
		t.Fatalf("records = %+v, want exactly 1 record with Completed=false", records)
	}
}

// TestDefenderMailEvidenceProvider_ResponseEvidence_EndToEnd_RunningState_NoEvidenceYet
// proves a non-terminal investigationState (the remediation hasn't
// resolved yet) produces no ResponseEvidence at all -- never a
// placeholder "not completed" record -- so VerifyMailExpectation's
// own no-evidence-found path reports Inconclusive, not
// ConfirmedFailure.
func TestDefenderMailEvidenceProvider_ResponseEvidence_EndToEnd_RunningState_NoEvidenceYet(t *testing.T) {
	tokenSrv := defenderTokenMock(t)
	defer tokenSrv.Close()
	now := time.Now()

	mux := http.NewServeMux()
	mux.HandleFunc("/security/collaboration/analyzedEmails", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{}})
	})
	mux.HandleFunc("/security/alerts_v2", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "alert-1", "title": "Malicious email delivered to finance-test@example-lab.test",
					"severity": "high", "createdDateTime": now.Format(time.RFC3339),
					"investigationState": "running",
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

	msg := MessageRef{Recipient: "finance-test@example-lab.test", MessageClass: "post-delivery-threat-response"}
	window := TimeWindow{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}
	records, err := provider.ResponseEvidenceFor(msg, window)
	if err != nil {
		t.Fatalf("ResponseEvidenceFor: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("records = %+v, want 0 -- a non-terminal investigationState must never produce a placeholder record", records)
	}
}

// TestDefenderMailEvidenceProvider_EG010_DetectionToResponseChain_EndToEnd
// is EG-010's own scenario: a known test event followed through the
// full chain -- alert generation, then triage/response resolution --
// proven from ONE real alert record serving as the source for BOTH
// DetectionVerdict (an alert exists for this message) and
// ResponseVerdict (that same alert's investigationState resolved to
// successfullyRemediated), not two independently-fabricated fixtures.
// This is what closes EG-010: the detection half already existed
// (DefenderDetectionProvider.DetectionEvidenceFor); only the response
// half was missing, and it reads from the exact same Graph alert.
func TestDefenderMailEvidenceProvider_EG010_DetectionToResponseChain_EndToEnd(t *testing.T) {
	tokenSrv := defenderTokenMock(t)
	defer tokenSrv.Close()
	now := time.Now()
	resolved := now.Add(3 * time.Minute)

	mux := http.NewServeMux()
	mux.HandleFunc("/security/collaboration/analyzedEmails", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "email-1", "loggedDateTime": now.Format(time.RFC3339),
					"recipientEmailAddress": "helpdesk-test@example-lab.test",
					"policy":                "Default anti-phish policy",
					"latestDelivery":        map[string]any{"action": "delivered", "location": "inbox_folder"},
					"authenticationDetails": map[string]any{"senderPolicyFramework": "pass"},
					"alertIds":              []string{"alert-1"},
				},
			},
		})
	})
	mux.HandleFunc("/security/alerts_v2", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "alert-1", "title": "Malicious email delivered to helpdesk-test@example-lab.test",
					"severity": "high", "createdDateTime": now.Format(time.RFC3339),
					"investigationState": "successfullyRemediated",
					"resolvedDateTime":   resolved.Format(time.RFC3339),
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

	exp := PostDeliveryThreatResponseExpectation()
	window := TimeWindow{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}
	result := VerifyMailExpectation(exp, OriginDeliveryObservation{}, provider, window)

	if result.DetectionVerdict.Verdict != VerdictConfirmedSuccess {
		t.Errorf("DetectionVerdict.Verdict = %q, want %q -- the chain's alert-generation half", result.DetectionVerdict.Verdict, VerdictConfirmedSuccess)
	}
	if result.ResponseVerdict.Verdict != VerdictConfirmedSuccess {
		t.Errorf("ResponseVerdict.Verdict = %q, want %q -- the chain's triage/response half", result.ResponseVerdict.Verdict, VerdictConfirmedSuccess)
	}
	if len(result.Detection) != 1 || result.Detection[0].CorrelationID != "alert-1" {
		t.Errorf("Detection = %+v, want exactly 1 record correlated to alert-1", result.Detection)
	}
	if len(result.Response) != 1 || result.Response[0].DurationToComplete != 3*time.Minute {
		t.Errorf("Response = %+v, want exactly 1 record with a 3m remediation duration -- same alert, both dimensions", result.Response)
	}
	if result.Response[0].CorrelationID != "alert-1" {
		t.Errorf("Response[0].CorrelationID = %q, want %q", result.Response[0].CorrelationID, "alert-1")
	}
	if correlated, ok := result.DetectionResponseCorrelated(); !ok || !correlated {
		t.Errorf("DetectionResponseCorrelated() = (%v, %v), want (true, true) -- EG-010's whole claim is that these are the same alert", correlated, ok)
	}
}

// TestDetectionResponseCorrelated_DifferentAlerts_ReportsNotCorrelated
// proves the helper actually catches a mismatch, not just the
// same-alert happy path above -- a tenant with two unrelated alerts
// resolving inside the same evidence-collection window must never be
// silently treated as one correlated chain.
func TestDetectionResponseCorrelated_DifferentAlerts_ReportsNotCorrelated(t *testing.T) {
	result := EfficacyResult{
		Detection: []DetectionEvidence{{CorrelationID: "alert-1", Timestamp: time.Now()}},
		Response:  []ResponseEvidence{{CorrelationID: "alert-2", Timestamp: time.Now()}},
	}
	correlated, ok := result.DetectionResponseCorrelated()
	if !ok {
		t.Fatalf("ok = false, want true -- both sides have a non-empty CorrelationID to compare")
	}
	if correlated {
		t.Errorf("correlated = true, want false -- alert-1 != alert-2")
	}
}

func TestDetectionResponseCorrelated_MissingEvidenceOnEitherSide_ReportsNotOK(t *testing.T) {
	cases := []struct {
		name   string
		result EfficacyResult
	}{
		{"no detection", EfficacyResult{Response: []ResponseEvidence{{CorrelationID: "alert-1", Timestamp: time.Now()}}}},
		{"no response", EfficacyResult{Detection: []DetectionEvidence{{CorrelationID: "alert-1", Timestamp: time.Now()}}}},
		{"neither", EfficacyResult{}},
		{"detection missing id", EfficacyResult{
			Detection: []DetectionEvidence{{Timestamp: time.Now()}},
			Response:  []ResponseEvidence{{CorrelationID: "alert-1", Timestamp: time.Now()}},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, ok := c.result.DetectionResponseCorrelated(); ok {
				t.Errorf("ok = true, want false -- nothing real to compare in this case")
			}
		})
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
