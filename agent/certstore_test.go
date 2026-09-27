package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestLoadOrGenerateAgentKey_PersistsAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir) // test override — see Step 3's certPaths()

	key1, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("first loadOrGenerateAgentKey: %v", err)
	}
	key2, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("second loadOrGenerateAgentKey: %v", err)
	}
	if key1.X.Cmp(key2.X) != 0 || key1.Y.Cmp(key2.Y) != 0 {
		t.Error("second call generated a NEW key instead of loading the persisted one")
	}
}

func TestGenerateCSR_ProducesParsableCSRForAgentID(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	key, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("loadOrGenerateAgentKey: %v", err)
	}
	csrPEM, err := generateCSR(key, "abc123deadbeef01")
	if err != nil {
		t.Fatalf("generateCSR: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatal("generateCSR did not produce a CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature invalid: %v", err)
	}
	if csr.Subject.CommonName != "abc123deadbeef01" {
		t.Errorf("CSR CommonName = %q, want abc123deadbeef01", csr.Subject.CommonName)
	}
}

func TestSaveAndLoadAgentCertificate_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)

	if _, err := loadAgentCertificate(); err == nil {
		t.Fatal("expected an error loading a certificate before one has been saved")
	}

	// A minimal self-signed cert stands in for a CA-issued one here —
	// saveAgentCertificate/loadAgentCertificate only care about PEM
	// round-tripping, not signature validity (that's the CA's/server's job
	// on the way in, and TLS's job on every subsequent handshake).
	certPEM := selfSignedTestCertPEM(t, "abc123deadbeef01")
	if err := saveAgentCertificate(certPEM); err != nil {
		t.Fatalf("saveAgentCertificate: %v", err)
	}
	loaded, err := loadAgentCertificate()
	if err != nil {
		t.Fatalf("loadAgentCertificate: %v", err)
	}
	if loaded.Subject.CommonName != "abc123deadbeef01" {
		t.Errorf("loaded cert CommonName = %q, want abc123deadbeef01", loaded.Subject.CommonName)
	}
}

func TestCertExpiringSoon(t *testing.T) {
	now := time.Now()
	fresh := &x509.Certificate{NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(364 * 24 * time.Hour)} // ~0.3% elapsed
	old := &x509.Certificate{NotBefore: now.Add(-300 * 24 * time.Hour), NotAfter: now.Add(65 * 24 * time.Hour)}  // ~82% elapsed

	if certExpiringSoon(fresh) {
		t.Error("a freshly issued certificate should not be reported as expiring soon")
	}
	if !certExpiringSoon(old) {
		t.Error("a certificate at ~82% of its lifetime should be reported as expiring soon (75% threshold)")
	}
}

func TestSaveDeploymentCARoot_WritesToCanonicalPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)

	pem := []byte("-----BEGIN CERTIFICATE-----\nfakedata\n-----END CERTIFICATE-----\n")
	if err := saveDeploymentCARoot(pem); err != nil {
		t.Fatalf("saveDeploymentCARoot: %v", err)
	}
	_, caPath, _, _ := certPaths()
	got, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read back CA root: %v", err)
	}
	if string(got) != string(pem) {
		t.Errorf("written content does not match input")
	}
}

// selfSignedTestCertPEM builds a throwaway self-signed cert for round-trip
// testing only — not used anywhere outside this test file.
func selfSignedTestCertPEM(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := loadOrGenerateAgentKey() // reuses BAS_CERT_DIR set by the caller
	if err != nil {
		t.Fatalf("key for self-signed test cert: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create self-signed test cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
