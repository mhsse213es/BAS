package adlab

import (
	"testing"

	"github.com/audspect/bas/internal/adenv"
)

func TestResolve_ESC6RequiresFlagEnrollmentAndAuthEKU(t *testing.T) {
	authTmpl := adenv.CertTemplate{Name: "User", EKUs: []string{"Client Authentication"}, EnrollmentRights: []string{"attacker"}}
	// flagged CA publishing an enrollable auth template -> reachable
	env := adenv.Environment{PKI: adenv.PKI{
		CAs:       []adenv.CertificateAuthority{{Name: "CA", EditfAttributeSubjectAltName2: true, PublishedTemplates: []string{"User"}}},
		Templates: []adenv.CertTemplate{authTmpl},
	}}
	if !NewEnvResolver(env, "attacker").Resolve("esc6_vulnerable_ca") {
		t.Fatal("ESC6 must resolve: flagged CA + enrollable client-auth template")
	}
	// same template but CA lacks the flag -> not reachable
	noFlag := adenv.Environment{PKI: adenv.PKI{
		CAs:       []adenv.CertificateAuthority{{Name: "CA", PublishedTemplates: []string{"User"}}},
		Templates: []adenv.CertTemplate{authTmpl},
	}}
	if NewEnvResolver(noFlag, "attacker").Resolve("esc6_vulnerable_ca") {
		t.Fatal("ESC6 must NOT resolve without the CA SAN flag")
	}
	// flagged CA but attacker cannot enroll -> not reachable
	noEnroll := adenv.Environment{PKI: adenv.PKI{
		CAs:       []adenv.CertificateAuthority{{Name: "CA", EditfAttributeSubjectAltName2: true, PublishedTemplates: []string{"User"}}},
		Templates: []adenv.CertTemplate{{Name: "User", EKUs: []string{"Client Authentication"}, EnrollmentRights: []string{"someone-else"}}},
	}}
	if NewEnvResolver(noEnroll, "attacker").Resolve("esc6_vulnerable_ca") {
		t.Fatal("ESC6 must NOT resolve when the attacker cannot enroll")
	}
}

func TestResolve_ESC8RelayableCA(t *testing.T) {
	relayable := adenv.Environment{PKI: adenv.PKI{CAs: []adenv.CertificateAuthority{{Name: "CA", WebEnrollmentEnabled: true}}}}
	if !NewEnvResolver(relayable, "attacker").Resolve("esc8_relayable_ca") {
		t.Fatal("ESC8 must resolve for HTTP web enrollment without EPA")
	}
	withEPA := adenv.Environment{PKI: adenv.PKI{CAs: []adenv.CertificateAuthority{{Name: "CA", WebEnrollmentEnabled: true, RequireEPA: true}}}}
	if NewEnvResolver(withEPA, "attacker").Resolve("esc8_relayable_ca") {
		t.Fatal("ESC8 must NOT resolve when EPA is enforced")
	}
}
