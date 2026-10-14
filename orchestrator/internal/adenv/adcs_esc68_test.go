package adenv

import "testing"

func TestIsESC6Vulnerable(t *testing.T) {
	if IsESC6Vulnerable(CertificateAuthority{Name: "CA01"}) {
		t.Fatal("a CA without EDITF_ATTRIBUTESUBJECTALTNAME2 is not ESC6-vulnerable")
	}
	if !IsESC6Vulnerable(CertificateAuthority{Name: "CA01", EditfAttributeSubjectAltName2: true}) {
		t.Fatal("a CA with EDITF_ATTRIBUTESUBJECTALTNAME2 set IS ESC6-vulnerable")
	}
}

func TestIsESC8Vulnerable(t *testing.T) {
	// Web enrollment reachable and EPA not enforced -> relayable (ESC8).
	if !IsESC8Vulnerable(CertificateAuthority{Name: "CA01", WebEnrollmentEnabled: true, RequireEPA: false}) {
		t.Fatal("HTTP web enrollment without EPA must be ESC8-vulnerable")
	}
	// EPA enforced mitigates the relay.
	if IsESC8Vulnerable(CertificateAuthority{Name: "CA01", WebEnrollmentEnabled: true, RequireEPA: true}) {
		t.Fatal("web enrollment WITH EPA enforced is not ESC8-vulnerable")
	}
	// No web enrollment endpoint -> nothing to relay to.
	if IsESC8Vulnerable(CertificateAuthority{Name: "CA01", WebEnrollmentEnabled: false}) {
		t.Fatal("a CA with no web enrollment endpoint is not ESC8-vulnerable")
	}
}
