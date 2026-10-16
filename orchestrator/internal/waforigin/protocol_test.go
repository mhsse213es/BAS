package waforigin

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func protocolMalicious() RequestTemplate {
	return RequestTemplate{Method: "GET", Path: "/", PayloadLocation: "tls+header", Payload: "TLS 1.0 handshake with a forged X-Forwarded-Proto: https header while the connection actually arrived over plaintext",
		Description: "deprecated TLS version combined with a forged proxy-trust header"}
}

func protocolBenign() RequestTemplate {
	return RequestTemplate{Method: "GET", Path: "/", PayloadLocation: "tls+header", Payload: "TLS 1.2+ handshake with a correctly-set X-Forwarded-Proto header matching the actual connection",
		Description: "declared-minimum TLS version with correctly-set proxy headers"}
}

func protocolStandards() StandardsMapping {
	return StandardsMapping{CWEIDs: []string{"CWE-319"}}
}

func TestNewProtocolBehaviorVector_Valid_Succeeds(t *testing.T) {
	benign := protocolBenign()
	v, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "TLS Downgrade with Forged Proxy Header", "origin trusts X-Forwarded-Proto without verifying the actual TLS version negotiated",
		protocolMalicious(), &benign, "", protocolStandards(), "manually authored")
	if err != nil {
		t.Fatalf("NewProtocolBehaviorVector: %v", err)
	}
	if v.ID != "WAFORIGIN-004" {
		t.Errorf("ID = %q, want %q", v.ID, "WAFORIGIN-004")
	}
}

func TestNewProtocolBehaviorVector_EmptyID_Rejected(t *testing.T) {
	benign := protocolBenign()
	_, err := NewProtocolBehaviorVector("", 1, "x", "x", protocolMalicious(), &benign, "", protocolStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewProtocolBehaviorVector_VersionLessThanOne_Rejected(t *testing.T) {
	benign := protocolBenign()
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 0, "x", "x", protocolMalicious(), &benign, "", protocolStandards(), "x")
	if err == nil {
		t.Fatal("want error for version < 1, got nil")
	}
}

func TestNewProtocolBehaviorVector_EmptyMaliciousMethod_Rejected(t *testing.T) {
	benign := protocolBenign()
	malicious := protocolMalicious()
	malicious.Method = ""
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", malicious, &benign, "", protocolStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Method, got nil")
	}
}

func TestNewProtocolBehaviorVector_EmptyMaliciousPath_Rejected(t *testing.T) {
	benign := protocolBenign()
	malicious := protocolMalicious()
	malicious.Path = ""
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", malicious, &benign, "", protocolStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Path, got nil")
	}
}

func TestNewProtocolBehaviorVector_EmptyMaliciousDescription_Rejected(t *testing.T) {
	benign := protocolBenign()
	malicious := protocolMalicious()
	malicious.Description = ""
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", malicious, &benign, "", protocolStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Description, got nil")
	}
}

func TestNewProtocolBehaviorVector_MalformedCWEID_Rejected(t *testing.T) {
	benign := protocolBenign()
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", protocolMalicious(), &benign, "",
		StandardsMapping{CWEIDs: []string{"not-a-cwe-id"}}, "x")
	if err == nil {
		t.Fatal("want error for malformed CWE ID, got nil")
	}
}

func TestNewProtocolBehaviorVector_StandardsAllEmpty_Rejected(t *testing.T) {
	benign := protocolBenign()
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", protocolMalicious(), &benign, "", StandardsMapping{}, "x")
	if err == nil {
		t.Fatal("want error when Standards has no mapping field set, got nil")
	}
}

func TestNewProtocolBehaviorVector_EmptyProvenance_Rejected(t *testing.T) {
	benign := protocolBenign()
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", protocolMalicious(), &benign, "", protocolStandards(), "")
	if err == nil {
		t.Fatal("want error for empty Provenance, got nil")
	}
}

// Review Focus: both set, exactly like wafbotabuse's precedent.
func TestNewProtocolBehaviorVector_BothBenignAndReasonSet_Rejected(t *testing.T) {
	benign := protocolBenign()
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", protocolMalicious(), &benign, "no benign exists", protocolStandards(), "x")
	if err == nil {
		t.Fatal("want error when both BenignCounterpart and NoBenignCounterpartReason are set, got nil")
	}
}

// Review Focus: neither set, exactly like wafbotabuse's precedent.
func TestNewProtocolBehaviorVector_NeitherBenignNorReasonSet_Rejected(t *testing.T) {
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", protocolMalicious(), nil, "", protocolStandards(), "x")
	if err == nil {
		t.Fatal("want error when neither BenignCounterpart nor NoBenignCounterpartReason is set, got nil")
	}
}

func TestNewProtocolBehaviorVector_BenignCounterpartInvalid_Rejected(t *testing.T) {
	benign := protocolBenign()
	benign.Description = ""
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", protocolMalicious(), &benign, "", protocolStandards(), "x")
	if err == nil {
		t.Fatal("want error for an invalid BenignCounterpart (empty Description), got nil")
	}
}

func TestProtocolBehaviorVector_Expectations_WithBenignCounterpart_ReturnsTwoLegs(t *testing.T) {
	benign := protocolBenign()
	v, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", protocolMalicious(), &benign, "", protocolStandards(), "x")
	if err != nil {
		t.Fatalf("NewProtocolBehaviorVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	if len(legs) != 2 {
		t.Fatalf("len(legs) = %d, want 2", len(legs))
	}
	if legs[0].Leg != LegMaliciousProtocol || legs[0].Expectation.Claim != wafval.ClaimPrevention {
		t.Errorf("legs[0] = %+v, want LegMaliciousProtocol with ClaimPrevention", legs[0])
	}
	if legs[1].Leg != LegBenignProtocol || legs[1].Expectation.Claim != wafval.ClaimFalsePositive {
		t.Errorf("legs[1] = %+v, want LegBenignProtocol with ClaimFalsePositive", legs[1])
	}
}

func TestProtocolBehaviorVector_Expectations_NoBenignCounterpart_ReturnsOneLeg(t *testing.T) {
	v, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", protocolMalicious(), nil, "no legitimate lookalike for this probe", protocolStandards(), "x")
	if err != nil {
		t.Fatalf("NewProtocolBehaviorVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	if len(legs) != 1 {
		t.Fatalf("len(legs) = %d, want 1", len(legs))
	}
	if legs[0].Leg != LegMaliciousProtocol || legs[0].Expectation.Claim != wafval.ClaimPrevention {
		t.Errorf("legs[0] = %+v, want LegMaliciousProtocol with ClaimPrevention", legs[0])
	}
}
