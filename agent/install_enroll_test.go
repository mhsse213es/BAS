package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
)

const installTestAgentID = "abc123deadbeef01"

// A token given to ensureCertificate for a first enrolment is sent as X-Enrollment-Token (audit F-03).
func TestEnsureCertificate_SendsTheEnrollmentTokenOnFirstEnrollment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	seedDeploymentCA(t, dir, ca)
	rec := &csrRecord{}
	srv := newMockOrchestrator(t, ca, tls.NoClientCert, http.StatusOK, rec)
	t.Setenv("BAS_ENROLL_PORT", portOf(t, srv.URL))

	cfg := Config{ServerURL: "https://127.0.0.1:9443", AgentSecret: "secret", EnrollmentToken: "bas_enr_example"}
	if _, err := ensureCertificate(context.Background(), cfg, installTestAgentID); err != nil {
		t.Fatal(err)
	}
	if rec.enrollToken != "bas_enr_example" {
		t.Errorf("X-Enrollment-Token = %q, want the configured token", rec.enrollToken)
	}
	if rec.token != "secret" {
		t.Errorf("X-Agent-Token = %q, the shared secret must still be sent", rec.token)
	}
}

// Without a token nothing extra is sent, so secret-mode servers behave exactly as before.
func TestEnsureCertificate_NoTokenHeaderWithoutAToken(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	seedDeploymentCA(t, dir, ca)
	rec := &csrRecord{}
	srv := newMockOrchestrator(t, ca, tls.NoClientCert, http.StatusOK, rec)
	t.Setenv("BAS_ENROLL_PORT", portOf(t, srv.URL))

	if _, err := ensureCertificate(context.Background(), Config{ServerURL: "https://127.0.0.1:9443", AgentSecret: "secret"}, installTestAgentID); err != nil {
		t.Fatal(err)
	}
	if rec.enrollToken != "" {
		t.Errorf("X-Enrollment-Token = %q, want none", rec.enrollToken)
	}
}

func TestLoadConfig_ReadsTheEnrollmentTokenFromTheEnvironmentOnly(t *testing.T) {
	t.Setenv("BAS_ENROLLMENT_TOKEN", "bas_enr_from_env")
	if got := loadConfig().EnrollmentToken; got != "bas_enr_from_env" {
		t.Errorf("EnrollmentToken = %q", got)
	}
}

// --install with a token enrols immediately, so the single-use token never has to be stored.
func TestEnrollAtInstall_EnrolsNowAndStoresNoToken(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	seedDeploymentCA(t, dir, ca)
	rec := &csrRecord{}
	srv := newMockOrchestrator(t, ca, tls.NoClientCert, http.StatusOK, rec)

	cfg := Config{ServerURL: "https://127.0.0.1:9443", AgentSecret: "secret", EnrollmentToken: "bas_enr_example"}
	if err := enrollAtInstall(context.Background(), cfg, portOf(t, srv.URL), installTestAgentID); err != nil {
		t.Fatal(err)
	}
	if rec.calls != 1 || rec.enrollToken != "bas_enr_example" {
		t.Errorf("calls=%d token=%q, want one call carrying the token", rec.calls, rec.enrollToken)
	}
	if !isEnrolled() {
		t.Error("the agent should be marked enrolled after the install-time enrolment")
	}
	if c := mustLoadCert(t); c.Subject.CommonName == "" {
		t.Error("a certificate should be stored")
	}
}

func TestEnrollAtInstall_RefusedTokenFailsTheInstallAndLeavesNothingEnrolled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	seedDeploymentCA(t, dir, ca)
	srv := newMockOrchestrator(t, ca, tls.NoClientCert, http.StatusUnauthorized, &csrRecord{})

	cfg := Config{ServerURL: "https://127.0.0.1:9443", AgentSecret: "secret", EnrollmentToken: "bas_enr_bad"}
	err := enrollAtInstall(context.Background(), cfg, portOf(t, srv.URL), installTestAgentID)
	if err == nil {
		t.Fatal("a refused token must fail the install")
	}
	if isEnrolled() {
		t.Error("a refused enrolment must not mark the agent enrolled")
	}
}
