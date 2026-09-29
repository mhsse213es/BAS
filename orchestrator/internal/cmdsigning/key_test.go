package cmdsigning

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateSigningKey_GeneratesOnFirstCall(t *testing.T) {
	dir := t.TempDir()
	sk, err := LoadOrGenerateSigningKey(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateSigningKey: %v", err)
	}
	if sk.PrivateKey() == nil {
		t.Fatal("PrivateKey() is nil")
	}
	if sk.PrivateKey().N.BitLen() != 4096 {
		t.Errorf("key size = %d bits, want 4096", sk.PrivateKey().N.BitLen())
	}
	if len(sk.CertPEM()) == 0 {
		t.Error("CertPEM() is empty")
	}
	if sk.KeyID() == "" {
		t.Error("KeyID() is empty")
	}
	if _, err := os.Stat(filepath.Join(dir, "command-signing.key")); err != nil {
		t.Errorf("private key file not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "command-signing.crt")); err != nil {
		t.Errorf("cert file not written: %v", err)
	}
}

func TestLoadOrGenerateSigningKey_LoadsExistingOnSecondCall(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrGenerateSigningKey(dir)
	if err != nil {
		t.Fatalf("first LoadOrGenerateSigningKey: %v", err)
	}
	second, err := LoadOrGenerateSigningKey(dir)
	if err != nil {
		t.Fatalf("second LoadOrGenerateSigningKey: %v", err)
	}
	if first.KeyID() != second.KeyID() {
		t.Errorf("KeyID changed across reload: %q vs %q -- a new key was generated instead of loading the existing one", first.KeyID(), second.KeyID())
	}
	if !first.PrivateKey().Equal(second.PrivateKey()) {
		t.Error("private key changed across reload")
	}
}

// TestLoadOrGenerateSigningKey_MismatchedCertKeyPairIsHardError pins the
// final whole-branch review's Minor finding: command-signing.crt and
// command-signing.key from two different generations (e.g. a partial
// restore, a manual file swap) must be rejected at startup, not signed
// with silently -- an agent's pinned cert would then never verify
// anything this orchestrator signs.
func TestLoadOrGenerateSigningKey_MismatchedCertKeyPairIsHardError(t *testing.T) {
	dirA := t.TempDir()
	if _, err := LoadOrGenerateSigningKey(dirA); err != nil {
		t.Fatalf("LoadOrGenerateSigningKey(dirA): %v", err)
	}
	dirB := t.TempDir()
	if _, err := LoadOrGenerateSigningKey(dirB); err != nil {
		t.Fatalf("LoadOrGenerateSigningKey(dirB): %v", err)
	}

	// Swap in dirB's certificate alongside dirA's key -- a genuinely
	// mismatched pair, not a corrupt file.
	otherCert, err := os.ReadFile(filepath.Join(dirB, "command-signing.crt"))
	if err != nil {
		t.Fatalf("read dirB cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dirA, "command-signing.crt"), otherCert, 0644); err != nil {
		t.Fatalf("overwrite dirA cert: %v", err)
	}

	if _, err := LoadOrGenerateSigningKey(dirA); err == nil {
		t.Fatal("expected an error for a mismatched command-signing cert/key pair, got nil")
	}
}

func TestLoadOrGenerateSigningKey_CorruptKeyFileIsHardError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "command-signing.key"), []byte("not a pem key"), 0600); err != nil {
		t.Fatalf("write corrupt key: %v", err)
	}
	if _, err := LoadOrGenerateSigningKey(dir); err == nil {
		t.Fatal("expected an error for a corrupt command-signing.key, got nil -- silently regenerating would invalidate every agent's trust in the old key with no warning")
	}
}
