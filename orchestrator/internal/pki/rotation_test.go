package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/audspect/bas/internal/pki/pkitest"
)

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatalf("%s: no PEM block", path)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func fp(c *x509.Certificate) [32]byte { return sha256.Sum256(c.Raw) }

func fileBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustCSR(t *testing.T) []byte {
	t.Helper()
	csr, err := pkitest.GenerateTestCSR("agent")
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

func newStableDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := LoadOrGenerateCA(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func state(t *testing.T, dir string) RotationState {
	t.Helper()
	s, err := RotationStatus(dir)
	if err != nil {
		t.Fatalf("RotationStatus: %v", err)
	}
	return s
}

func TestRotation_StartPreparesANextCASignedByTheCurrentOneAndBacksUp(t *testing.T) {
	dir := newStableDir(t)
	curKey := fileBytes(t, filepath.Join(dir, "ca-key.pem"))
	curCert := fileBytes(t, filepath.Join(dir, "ca-cert.pem"))

	backup, err := StartRotation(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if state(t, dir) != RotationPrepared {
		t.Fatalf("state = %s, want prepared", state(t, dir))
	}
	// The live CA is untouched.
	if !bytes.Equal(curKey, fileBytes(t, filepath.Join(dir, "ca-key.pem"))) || !bytes.Equal(curCert, fileBytes(t, filepath.Join(dir, "ca-cert.pem"))) {
		t.Error("starting a rotation must not change the current CA")
	}
	// A recoverable backup of the current CA exists.
	if !bytes.Equal(curKey, fileBytes(t, filepath.Join(backup, "ca-key.pem"))) {
		t.Error("the backup must hold the current CA key")
	}

	current := readCert(t, filepath.Join(dir, "ca-cert.pem"))
	next := readCert(t, filepath.Join(dir, "next-ca-cert.pem"))
	cross := readCert(t, filepath.Join(dir, "next-ca-cross.pem"))
	if !next.IsCA || next.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("the next CA must be a CA that can sign")
	}
	if next.Subject.CommonName == current.Subject.CommonName {
		t.Errorf("the next CA needs a distinguishable name, both are %q", next.Subject.CommonName)
	}
	if fp(next) == fp(current) {
		t.Error("the next CA must be a different CA")
	}
	// The cross-certificate is the next CA's key vouched for by the CURRENT CA: this is what lets an
	// agent that only knows the current root accept the next root, and nothing else.
	roots := x509.NewCertPool()
	roots.AddCert(current)
	if _, err := cross.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("the cross-certificate must chain to the current CA: %v", err)
	}
	if !cross.PublicKey.(*ecdsa.PublicKey).Equal(next.PublicKey) {
		t.Error("the cross-certificate must carry the next CA's public key")
	}
	if !cross.IsCA {
		t.Error("the cross-certificate must be a CA certificate")
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(filepath.Join(dir, "next-ca-key.pem")); st.Mode().Perm() != 0o600 {
			t.Errorf("next CA key mode %v, want 0600", st.Mode().Perm())
		}
	}
}

func TestRotation_NeverStartsFromAMissingCAOrWhileOneIsInProgress(t *testing.T) {
	empty := t.TempDir()
	if _, err := StartRotation(empty, time.Now()); err == nil {
		t.Error("a missing CA must never be treated as a rotation request")
	}
	if exists(filepath.Join(empty, "next-ca-key.pem")) || exists(filepath.Join(empty, "ca-key.pem")) {
		t.Error("nothing may be created when there is no current CA")
	}

	dir := newStableDir(t)
	if _, err := StartRotation(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := StartRotation(dir, time.Now()); err == nil {
		t.Error("a second rotation must not start while one is in progress")
	}
}

func TestRotation_AbortReturnsToStable(t *testing.T) {
	dir := newStableDir(t)
	cur := fileBytes(t, filepath.Join(dir, "ca-cert.pem"))
	StartRotation(dir, time.Now())
	if _, err := AbortRotation(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	if state(t, dir) != RotationStable {
		t.Errorf("state = %s, want stable", state(t, dir))
	}
	if !bytes.Equal(cur, fileBytes(t, filepath.Join(dir, "ca-cert.pem"))) {
		t.Error("abort must leave the current CA untouched")
	}
	for _, f := range []string{"next-ca-key.pem", "next-ca-cert.pem", "next-ca-cross.pem"} {
		if exists(filepath.Join(dir, f)) {
			t.Errorf("%s was left behind", f)
		}
	}
}

func TestRotation_PromoteKeepsTheOldCATrustedForCertificatesAlreadyIssued(t *testing.T) {
	dir := newStableDir(t)
	oldCA, _ := LoadOrGenerateCA(dir)
	csr := mustCSR(t)
	issuedUnderOld, err := oldCA.IssueClientCertificate("0123456789abcdef", csr)
	if err != nil {
		t.Fatal(err)
	}
	oldFP := fp(oldCA.Certificate())

	StartRotation(dir, time.Now())
	nextFP := fp(readCert(t, filepath.Join(dir, "next-ca-cert.pem")))
	if _, err := PromoteRotation(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	if state(t, dir) != RotationPromoted {
		t.Fatalf("state = %s, want promoted", state(t, dir))
	}
	newCA, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("the promoted CA must load as the current CA: %v", err)
	}
	if fp(newCA.Certificate()) != nextFP {
		t.Error("the current CA must now be the former next CA")
	}
	if fp(readCert(t, filepath.Join(dir, "previous-ca-cert.pem"))) != oldFP {
		t.Error("the old CA must be kept as the previous CA")
	}

	// An agent certificate issued before the promotion is still accepted; new ones come from the new CA.
	roots, err := TrustedClientRoots(dir)
	if err != nil || len(roots) != 2 {
		t.Fatalf("TrustedClientRoots = %d roots, err %v; want both CAs", len(roots), err)
	}
	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	blk, _ := pem.Decode(issuedUnderOld.CertPEM)
	oldAgentCert, _ := x509.ParseCertificate(blk.Bytes)
	if _, err := oldAgentCert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("a certificate issued under the old CA must still verify during the transition: %v", err)
	}
	issuedUnderNew, err := newCA.IssueClientCertificate("0123456789abcdef", csr)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ = pem.Decode(issuedUnderNew.CertPEM)
	newAgentCert, _ := x509.ParseCertificate(blk.Bytes)
	newOnly := x509.NewCertPool()
	newOnly.AddCert(newCA.Certificate())
	if _, err := newAgentCert.Verify(x509.VerifyOptions{Roots: newOnly, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("new certificates must chain to the new CA: %v", err)
	}
}

func TestRotation_RollbackRestoresTheOriginalCAAsCurrent(t *testing.T) {
	dir := newStableDir(t)
	orig := fileBytes(t, filepath.Join(dir, "ca-cert.pem"))
	origKey := fileBytes(t, filepath.Join(dir, "ca-key.pem"))
	StartRotation(dir, time.Now())
	PromoteRotation(dir, time.Now())
	if _, err := RollbackRotation(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	if state(t, dir) != RotationPrepared {
		t.Errorf("state after rollback = %s, want prepared", state(t, dir))
	}
	if !bytes.Equal(orig, fileBytes(t, filepath.Join(dir, "ca-cert.pem"))) || !bytes.Equal(origKey, fileBytes(t, filepath.Join(dir, "ca-key.pem"))) {
		t.Error("rollback must restore the original CA exactly as current")
	}
	if exists(filepath.Join(dir, "previous-ca-cert.pem")) {
		t.Error("no previous CA should remain after a rollback")
	}
}

func TestRotation_RetireRemovesTheOldCAFromTrustButKeepsABackup(t *testing.T) {
	dir := newStableDir(t)
	oldKey := fileBytes(t, filepath.Join(dir, "ca-key.pem"))
	StartRotation(dir, time.Now())
	PromoteRotation(dir, time.Now())
	backup, err := RetireRotation(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if state(t, dir) != RotationStable {
		t.Errorf("state = %s, want stable", state(t, dir))
	}
	roots, _ := TrustedClientRoots(dir)
	if len(roots) != 1 {
		t.Errorf("trusted roots after retire = %d, want 1", len(roots))
	}
	if exists(filepath.Join(dir, "previous-ca-key.pem")) || exists(filepath.Join(dir, "previous-ca-cert.pem")) {
		t.Error("the old CA must be gone from the live directory")
	}
	if !bytes.Equal(oldKey, fileBytes(t, filepath.Join(backup, "previous-ca-key.pem"))) {
		t.Error("the backup taken before retirement must still hold the old CA key")
	}
}

func TestRotation_StepsOutOfOrderAreRefused(t *testing.T) {
	dir := newStableDir(t)
	if _, err := PromoteRotation(dir, time.Now()); err == nil {
		t.Error("promote without a prepared rotation must fail")
	}
	if _, err := RetireRotation(dir, time.Now()); err == nil {
		t.Error("retire without a promoted rotation must fail")
	}
	if _, err := RollbackRotation(dir, time.Now()); err == nil {
		t.Error("rollback without a promoted rotation must fail")
	}
	StartRotation(dir, time.Now())
	if _, err := RetireRotation(dir, time.Now()); err == nil {
		t.Error("retire before promote must fail")
	}
}

func TestRotation_HalfPresentFilesFailClosed(t *testing.T) {
	dir := newStableDir(t)
	StartRotation(dir, time.Now())
	os.Remove(filepath.Join(dir, "next-ca-key.pem"))
	if _, err := RotationStatus(dir); err == nil {
		t.Error("a next CA with only its certificate must be reported as an error, not guessed at")
	}
	if _, err := PromoteRotation(dir, time.Now()); err == nil {
		t.Error("promote must refuse a damaged rotation")
	}
}
