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

	ca := newTestCA(t)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	if err := saveDeploymentCARoot(caPEM); err != nil {
		t.Fatalf("saveDeploymentCARoot: %v", err)
	}
	_, caPath, _, _ := certPaths()
	got, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read back CA root: %v", err)
	}
	if string(got) != string(caPEM) {
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

func TestSaveDeploymentCARoot_RejectsNonCertificateInput(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	key, _ := loadOrGenerateAgentKey()
	keyDER, _ := x509.MarshalECPrivateKey(key)
	for name, in := range map[string][]byte{
		"not PEM":          []byte("<html>404 Not Found</html>"),
		"garbage in block": []byte("-----BEGIN CERTIFICATE-----\nZmFrZWRhdGE=\n-----END CERTIFICATE-----\n"),
		"private key":      pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		"empty":            nil,
	} {
		if err := saveDeploymentCARoot(in); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
	_, caPath, _, _ := certPaths()
	if _, err := os.Stat(caPath); err == nil {
		t.Error("an invalid CA root was written to disk")
	}
}

func TestSaveAgentCertificate_RejectsCertificateForDifferentKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	if _, err := loadOrGenerateAgentKey(); err != nil {
		t.Fatalf("loadOrGenerateAgentKey: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := newTestCA(t)
	foreign := leafCertPEMForKeyPublic(t, ca, "abc123deadbeef01", other)
	if err := saveAgentCertificate(foreign); err == nil {
		t.Fatal("expected saveAgentCertificate to reject a certificate for a different key")
	}
	if _, err := loadAgentCertificate(); err == nil {
		t.Error("the mismatched certificate was persisted")
	}
	if err := saveAgentCertificate([]byte("not a cert")); err == nil {
		t.Error("expected saveAgentCertificate to reject non-PEM input")
	}
}

func TestIsEnrolled_FalseBeforeMarkEnrolled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	if isEnrolled() {
		t.Error("expected isEnrolled to be false with no marker written yet")
	}
}

func TestIsEnrolled_TrueAfterMarkEnrolled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	if err := markEnrolled(); err != nil {
		t.Fatalf("markEnrolled: %v", err)
	}
	if !isEnrolled() {
		t.Error("expected isEnrolled to be true after markEnrolled")
	}
}

// TestIsEnrolled_NotInferredFromCertFileAlone locks in the core invariant:
// a certificate file existing on disk (even a real, valid one) must never
// by itself count as "enrolled" -- only the explicit persisted marker does.
// This is what protects against a corrupted/partial certificate write being
// mistaken for a successfully-enrolled identity.
func TestIsEnrolled_NotInferredFromCertFileAlone(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	key, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("loadOrGenerateAgentKey: %v", err)
	}
	ca := newTestCA(t)
	certPEM := leafCertPEMForKeyPublic(t, ca, "abc123deadbeef01", key)
	if err := saveAgentCertificate(certPEM); err != nil {
		t.Fatalf("saveAgentCertificate: %v", err)
	}
	// A real, valid, key-matched certificate is now on disk -- but
	// markEnrolled was never called.
	if isEnrolled() {
		t.Error("expected isEnrolled to be false: a certificate file on disk must not by itself imply enrollment")
	}
}

func TestIsEnrolled_CorruptedMarkerTreatedAsNotEnrolled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(enrollmentStatePath(), []byte("garbage-not-the-expected-marker"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if isEnrolled() {
		t.Error("expected a corrupted/unrecognized marker file to be treated as not-enrolled, not fail open")
	}
}

func TestSaveAndLoadCommandSigningCert_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t) // reuse this package's existing test helper (bootstrap_test.go)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})

	if err := saveCommandSigningCert(certPEM); err != nil {
		t.Fatalf("saveCommandSigningCert: %v", err)
	}
	loaded, err := loadCommandSigningCert()
	if err != nil {
		t.Fatalf("loadCommandSigningCert: %v", err)
	}
	if loaded.SerialNumber.Cmp(ca.cert.SerialNumber) != 0 {
		t.Error("loaded certificate does not match what was saved")
	}
}

func TestLoadCommandSigningCert_MissingFileReturnsNotExist(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	if _, err := loadCommandSigningCert(); !os.IsNotExist(err) {
		t.Errorf("expected an os.ErrNotExist-wrapping error when no cert was ever saved, got: %v", err)
	}
}

func TestSaveCommandSigningCert_RejectsInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	if err := saveCommandSigningCert([]byte("not a cert")); err == nil {
		t.Error("expected saveCommandSigningCert to reject non-PEM input")
	}
}

// TestSaveCommandSigningCert_RefusesToReplaceAlreadyPinnedCert locks in
// the pin-once invariant: once a command-signing certificate is
// persisted, a genuinely different one must be refused, not silently
// swapped in on the next renewal.
func TestSaveCommandSigningCert_RefusesToReplaceAlreadyPinnedCert(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	firstPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	if err := saveCommandSigningCert(firstPEM); err != nil {
		t.Fatalf("saveCommandSigningCert (first): %v", err)
	}

	otherCA := newTestCA(t) // a genuinely different certificate/serial
	secondPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherCA.cert.Raw})
	if err := saveCommandSigningCert(secondPEM); err == nil {
		t.Fatal("expected saveCommandSigningCert to refuse replacing an already-pinned certificate with a different one")
	}

	loaded, err := loadCommandSigningCert()
	if err != nil {
		t.Fatalf("loadCommandSigningCert: %v", err)
	}
	if loaded.SerialNumber.Cmp(ca.cert.SerialNumber) != 0 {
		t.Error("the originally-pinned certificate was overwritten despite the refusal")
	}
}

// TestSaveCommandSigningCert_IdenticalRedeliveryIsNoop confirms a
// renewal response carrying the SAME already-pinned certificate (the
// normal case -- every renewal response includes it, whether or not it
// changed) is accepted as a no-op, not treated as a replacement attempt.
func TestSaveCommandSigningCert_IdenticalRedeliveryIsNoop(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	if err := saveCommandSigningCert(certPEM); err != nil {
		t.Fatalf("saveCommandSigningCert (first): %v", err)
	}
	if err := saveCommandSigningCert(certPEM); err != nil {
		t.Errorf("expected re-delivering the identical certificate to succeed as a no-op, got: %v", err)
	}
}
