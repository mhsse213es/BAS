package dlpprofile

import "testing"

func TestNewComplianceReference_Valid_Succeeds(t *testing.T) {
	c, err := NewComplianceReference("RBI Cyber Security Framework for banks", Unverified,
		"framework name and general existence only, drawn from secondary sources; no specific circular verified against RBI's own text", "")
	if err != nil {
		t.Fatalf("NewComplianceReference: %v", err)
	}
	if c.Framework != "RBI Cyber Security Framework for banks" {
		t.Errorf("Framework = %q, want %q", c.Framework, "RBI Cyber Security Framework for banks")
	}
}

// Review Focus: not every framework reference has one canonical URL.
func TestNewComplianceReference_EmptySourceURL_Succeeds(t *testing.T) {
	c, err := NewComplianceReference("CERT-In Cyber Security Directions", Unverified,
		"framework name and the widely-reported 6-hour incident-reporting requirement only", "")
	if err != nil {
		t.Fatalf("NewComplianceReference: %v", err)
	}
	if c.SourceURL != "" {
		t.Errorf("SourceURL = %q, want empty", c.SourceURL)
	}
}

func TestNewComplianceReference_EmptyFramework_Rejected(t *testing.T) {
	_, err := NewComplianceReference("", Unverified, "x", "")
	if err == nil {
		t.Fatal("want error for empty framework, got nil")
	}
}

func TestNewComplianceReference_EmptyNote_Rejected(t *testing.T) {
	_, err := NewComplianceReference("x", Unverified, "", "")
	if err == nil {
		t.Fatal("want error for empty note, got nil")
	}
}

func TestNewComplianceReference_InvalidStatus_Rejected(t *testing.T) {
	_, err := NewComplianceReference("x", VerificationStatus("bogus_status"), "y", "")
	if err == nil {
		t.Fatal("want error for an unknown VerificationStatus, got nil")
	}
}

func TestNewComplianceReference_VerifiedStatus_Succeeds(t *testing.T) {
	c, err := NewComplianceReference("x", Verified, "explicitly confirmed against a primary source for this test", "")
	if err != nil {
		t.Fatalf("NewComplianceReference: %v", err)
	}
	if c.VerificationStatus != Verified {
		t.Errorf("VerificationStatus = %q, want %q", c.VerificationStatus, Verified)
	}
}
