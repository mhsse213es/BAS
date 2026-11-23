package auditarchive

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writeKeyPair(t *testing.T, k *rsa.PrivateKey) (privPath, pubPath string) {
	t.Helper()
	dir := t.TempDir()
	privPath = filepath.Join(dir, "archive.key")
	pubPath = filepath.Join(dir, "archive.pub")
	privDER := x509.MarshalPKCS1PrivateKey(k)
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	return privPath, pubPath
}

// A sealed archive verifies with the key pair loaded from files.
func TestLoadKeys_SealWithPrivateVerifyWithPublic(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privPath, pubPath := writeKeyPair(t, k)
	priv, err := LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	pub, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	body, _ := EncodeRows(sampleRows())
	m, err := Seal(body, Manifest{BatchID: "k-1"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(body, m, pub); err != nil {
		t.Fatalf("archive sealed with the loaded private key must verify with the loaded public key: %v", err)
	}
}

func TestLoadPrivateKey_RejectsMissingFile(t *testing.T) {
	if _, err := LoadPrivateKey(filepath.Join(t.TempDir(), "absent.key")); err == nil {
		t.Fatal("a missing key file must be an error")
	}
}
