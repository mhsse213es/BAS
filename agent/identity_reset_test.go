// agent/identity_reset_test.go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newCA returns a self-signed CA certificate PEM and its key.
func newCA(t *testing.T, name string) ([]byte, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key, cert
}

// writeLeaf writes an agent certificate signed by caKey/caCert into dir.
func writeLeaf(t *testing.T, dir string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "agent-cert.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent-key.pem"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "enrollment-state"), []byte("enrolled"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestClearStaleIdentity_DifferentCAMovesIdentityAside(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	caA, keyA, certA := newCA(t, "A")
	caB, _, _ := newCA(t, "B")
	_ = caA
	writeLeaf(t, dir, keyA, certA)

	moved, err := clearStaleIdentity(caB)
	if err != nil {
		t.Fatalf("clearStaleIdentity: %v", err)
	}
	if !moved {
		t.Fatal("identity issued by CA A was not moved when CA B is installed")
	}
	for _, name := range identityFiles {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s is still in the certificate directory", name)
		}
	}
}

func TestClearStaleIdentity_SameCAKeepsIdentity(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	caA, keyA, certA := newCA(t, "A")
	writeLeaf(t, dir, keyA, certA)

	moved, err := clearStaleIdentity(caA)
	if err != nil {
		t.Fatalf("clearStaleIdentity: %v", err)
	}
	if moved {
		t.Fatal("identity issued by the installed CA was moved")
	}
	if _, err := os.Stat(filepath.Join(dir, "agent-cert.pem")); err != nil {
		t.Fatalf("agent-cert.pem was removed: %v", err)
	}
}

func TestClearStaleIdentity_NoIdentityIsNoop(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	caA, _, _ := newCA(t, "A")
	moved, err := clearStaleIdentity(caA)
	if err != nil || moved {
		t.Fatalf("moved=%v err=%v, want no-op", moved, err)
	}
}
