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

	"audspect/agent/preflight"
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

func TestIdentityStatus_ReportsStaleWithoutMovingAnything(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	_, keyA, certA := newCA(t, "A")
	caB, _, _ := newCA(t, "B")
	writeLeaf(t, dir, keyA, certA)
	if got := identityStatus(caB); got != preflight.CodeIdentityStale {
		t.Fatalf("identityStatus = %d, want %d (stale)", got, preflight.CodeIdentityStale)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent-cert.pem")); err != nil {
		t.Fatalf("a status check must not move the identity: %v", err)
	}
}

func TestIdentityStatus_CurrentOrAbsentIsOK(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	caA, keyA, certA := newCA(t, "A")
	if got := identityStatus(caA); got != 0 {
		t.Fatalf("no identity: identityStatus = %d, want 0", got)
	}
	writeLeaf(t, dir, keyA, certA)
	if got := identityStatus(caA); got != 0 {
		t.Fatalf("matching identity: identityStatus = %d, want 0", got)
	}
}

func TestResetIdentity_StaleIsMovedCAUpdatedAndTokenSpent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	_, keyA, certA := newCA(t, "A")
	caB, _, _ := newCA(t, "B")
	writeLeaf(t, dir, keyA, certA)
	spent := ""
	reset, err := resetIdentity(deployment{Server: "https://s:9443", CARootPEM: caB}, "tok-1", func(tok string) error { spent = tok; return nil })
	if err != nil || !reset {
		t.Fatalf("reset=%v err=%v, want true,nil", reset, err)
	}
	if spent != "tok-1" {
		t.Errorf("token spent = %q, want tok-1", spent)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent-cert.pem")); !os.IsNotExist(err) {
		t.Error("the stale certificate is still in place")
	}
}

func TestResetIdentity_CurrentIdentityChangesNothingAndSpendsNoToken(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	caA, keyA, certA := newCA(t, "A")
	writeLeaf(t, dir, keyA, certA)
	reset, err := resetIdentity(deployment{CARootPEM: caA}, "tok-2", func(string) error { t.Fatal("token spent for a current identity"); return nil })
	if err != nil || reset {
		t.Fatalf("reset=%v err=%v, want false,nil", reset, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent-cert.pem")); err != nil {
		t.Errorf("a current identity was touched: %v", err)
	}
}

func TestResetIdentity_EnrollFailureIsReturned(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	_, keyA, certA := newCA(t, "A")
	caB, _, _ := newCA(t, "B")
	writeLeaf(t, dir, keyA, certA)
	_, err := resetIdentity(deployment{CARootPEM: caB}, "t", func(string) error { return os.ErrPermission })
	if err == nil {
		t.Fatal("an enrolment failure must be returned, not hidden")
	}
}

func TestIdentityStatus_UnreadableCertificateIsKeptNotCalledStale(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	caB, _, _ := newCA(t, "B")
	// a directory where the certificate file should be: it exists but cannot be read as a file
	if err := os.Mkdir(filepath.Join(dir, "agent-cert.pem"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := identityStatus(caB); got != 0 {
		t.Fatalf("identityStatus = %d, want 0: an identity that cannot be read must never trigger a reset", got)
	}
}
