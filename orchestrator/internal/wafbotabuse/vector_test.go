package wafbotabuse

import "testing"

func validMalicious() RequestTemplate {
	return RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "header+timing", Payload: "50 requests in 2 seconds, missing JS-challenge cookie and User-Agent", Description: "non-human-paced automated burst"}
}

func validBenign() RequestTemplate {
	return RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "header+timing", Payload: "single human-paced request with JS-challenge cookie and User-Agent present", Description: "single human-paced request with normal browser signals"}
}

func validStandards() StandardsMapping {
	return StandardsMapping{CWEIDs: []string{"CWE-799"}}
}

func TestNewBotAbuseVector_Valid_Succeeds(t *testing.T) {
	benign := validBenign()
	v, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "Non-Human-Paced Automation Burst", SeverityHigh,
		"search endpoint accepts unauthenticated GET requests with no declared per-client pacing requirement", validMalicious(), &benign, "", validStandards(), "manually authored")
	if err != nil {
		t.Fatalf("NewBotAbuseVector: %v", err)
	}
	if v.ID != "BOTABUSE-001" {
		t.Errorf("ID = %q, want %q", v.ID, "BOTABUSE-001")
	}
}

func TestNewBotAbuseVector_EmptyID_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewBotAbuseVector("", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewBotAbuseVector_VersionLessThanOne_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewBotAbuseVector("BOTABUSE-001", 0, CategoryBoundedAutomation, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for version < 1, got nil")
	}
}

func TestNewBotAbuseVector_UnknownCategory_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, BotAbuseCategory("bogus_category"), "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for unknown Category, got nil")
	}
}

func TestNewBotAbuseVector_UnknownSeverity_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", Severity("bogus_severity"), "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for unknown Severity, got nil")
	}
}

func TestNewBotAbuseVector_EmptyMaliciousMethod_Rejected(t *testing.T) {
	benign := validBenign()
	malicious := validMalicious()
	malicious.Method = ""
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", malicious, &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Method, got nil")
	}
}

func TestNewBotAbuseVector_EmptyMaliciousPath_Rejected(t *testing.T) {
	benign := validBenign()
	malicious := validMalicious()
	malicious.Path = ""
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", malicious, &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Path, got nil")
	}
}

func TestNewBotAbuseVector_EmptyMaliciousDescription_Rejected(t *testing.T) {
	benign := validBenign()
	malicious := validMalicious()
	malicious.Description = ""
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", malicious, &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Description, got nil")
	}
}

// Review Focus: a malformed CWE ID must be rejected at construction, not
// silently stored and surfaced later in a client-facing report.
func TestNewBotAbuseVector_MalformedCWEID_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", validMalicious(), &benign, "",
		StandardsMapping{CWEIDs: []string{"not-a-cwe-id"}}, "x")
	if err == nil {
		t.Fatal("want error for malformed CWE ID, got nil")
	}
}

func TestNewBotAbuseVector_StandardsAllEmpty_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", validMalicious(), &benign, "",
		StandardsMapping{}, "x")
	if err == nil {
		t.Fatal("want error when Standards has no mapping field set, got nil")
	}
}

func TestNewBotAbuseVector_EmptyProvenance_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "")
	if err == nil {
		t.Fatal("want error for empty Provenance, got nil")
	}
}

// Review Focus: both BenignCounterpart and NoBenignCounterpartReason set is
// a contradictory double-statement and must be rejected.
func TestNewBotAbuseVector_BothBenignAndReasonSet_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", validMalicious(), &benign, "no benign exists", validStandards(), "x")
	if err == nil {
		t.Fatal("want error when both BenignCounterpart and NoBenignCounterpartReason are set, got nil")
	}
}

// Review Focus: neither set is a silent omission and must be rejected.
func TestNewBotAbuseVector_NeitherBenignNorReasonSet_Rejected(t *testing.T) {
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", validMalicious(), nil, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error when neither BenignCounterpart nor NoBenignCounterpartReason is set, got nil")
	}
}

func TestNewBotAbuseVector_BenignCounterpartInvalid_Rejected(t *testing.T) {
	benign := validBenign()
	benign.Description = ""
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for an invalid BenignCounterpart (empty Description), got nil")
	}
}
