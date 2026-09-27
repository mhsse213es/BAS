// orchestrator/internal/pki/ca_test.go
package pki

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateCA_GeneratesOnFirstCall(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	if ca.Certificate() == nil {
		t.Fatal("Certificate() returned nil")
	}
	if !ca.Certificate().IsCA {
		t.Error("generated certificate is not marked IsCA")
	}
	for _, name := range []string{"ca-key.pem", "ca-cert.pem"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
		}
	}
}

func TestLoadOrGenerateCA_LoadsExistingOnSecondCall(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("first LoadOrGenerateCA: %v", err)
	}
	second, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("second LoadOrGenerateCA: %v", err)
	}
	if first.Certificate().SerialNumber.Cmp(second.Certificate().SerialNumber) != 0 {
		t.Error("second call generated a NEW CA instead of loading the existing one — " +
			"this would invalidate every already-issued agent certificate")
	}
}

func TestLoadOrGenerateCA_CorruptKeyFileFailsLoudly(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrGenerateCA(dir); err != nil {
		t.Fatalf("initial generate: %v", err)
	}
	// Corrupt the key file to simulate disk corruption / truncated write.
	if err := os.WriteFile(filepath.Join(dir, "ca-key.pem"), []byte("not a pem file"), 0600); err != nil {
		t.Fatalf("corrupt key file: %v", err)
	}
	if _, err := LoadOrGenerateCA(dir); err == nil {
		t.Fatal("expected LoadOrGenerateCA to fail loudly on a corrupt key file, got nil error — " +
			"silently regenerating here would invalidate the whole fleet's certificates without warning")
	}
}
