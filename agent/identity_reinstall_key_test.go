package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A reinstall against a CA the identity was not issued by must keep the private key where it is, so the
// reinstalled agent proves it is the same identity by signing its new request with that key. Only the
// certificate and enrolment marker are moved aside.
func TestClearStaleIdentity_KeepsPrivateKeyInPlace(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	_, keyA, certA := newCA(t, "A")
	caB, _, _ := newCA(t, "B")
	writeLeaf(t, dir, keyA, certA)

	moved, err := clearStaleIdentity(caB)
	if err != nil {
		t.Fatalf("clearStaleIdentity: %v", err)
	}
	if !moved {
		t.Fatal("identity issued by CA A was not moved when CA B is installed")
	}
	if _, err := os.Stat(filepath.Join(dir, "agent-key.pem")); err != nil {
		t.Fatalf("agent-key.pem was moved aside; the reinstall needs it to prove identity: %v", err)
	}
	for _, name := range []string{"agent-cert.pem", "enrollment-state"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s is still in the certificate directory", name)
		}
	}
}
