package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Interop with the server's real rotation output. Set BAS_ROTATION_FIXTURE to a PKI directory in which
// `orchestrator ca-rotation start --yes` has been run; the test is skipped otherwise.
func TestAcceptCARoot_AcceptsWhatTheServerRotationActuallyProduces(t *testing.T) {
	dir := os.Getenv("BAS_ROTATION_FIXTURE")
	if dir == "" {
		t.Skip("BAS_ROTATION_FIXTURE not set")
	}
	read := func(n string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	certDir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", certDir)
	if err := os.WriteFile(filepath.Join(certDir, "deployment-ca.pem"), read("ca-cert.pem"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := acceptCARoot(trustPayload(read("next-ca-cert.pem"), read("next-ca-cross.pem"))); err != nil {
		t.Fatalf("the agent refused the server's real rotation output: %v", err)
	}
	if n := len(trustedRootFingerprints()); n != 2 {
		t.Errorf("%d roots trusted, want 2", n)
	}
}
