package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"testing"
	"time"
)

func readKey(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	k, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func enrolledNearExpiry(t *testing.T) (ca testCA, oldKey *ecdsa.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca = newTestCA(t)
	seedDeploymentCA(t, dir, ca)
	key, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := saveAgentCertificate(caSignedCertPEM(t, ca, &key.PublicKey, "abc123deadbeef01", -300*24*time.Hour, 65*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := markEnrolled(); err != nil {
		t.Fatal(err)
	}
	return ca, key
}

// Renewal must not reuse the old private key (audit F-07): a key that leaked earlier would otherwise
// stay valid for as long as the agent keeps renewing.
func TestRenewal_GeneratesAFreshKey(t *testing.T) {
	ca, oldKey := enrolledNearExpiry(t)
	rec := &csrRecord{}
	srv := newMockOrchestrator(t, ca, tls.RequireAndVerifyClientCert, http.StatusOK, rec)
	t.Setenv("BAS_MTLS_PORT", portOf(t, srv.URL))
	t.Setenv("BAS_ENROLL_PORT", unusedPort(t))

	if _, err := ensureCertificate(context.Background(), Config{ServerURL: "http://127.0.0.1:9000", AgentSecret: "secret"}, "abc123deadbeef01"); err != nil {
		t.Fatal(err)
	}
	_, _, _, keyPath := certPaths()
	newKey := readKey(t, keyPath)
	if newKey.PublicKey.Equal(&oldKey.PublicKey) {
		t.Fatal("the private key was reused across a renewal")
	}
	cert := mustLoadCert(t)
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&newKey.PublicKey) {
		t.Fatal("the stored certificate does not belong to the stored key")
	}
}

func TestRenewalFailure_LeavesTheOldKeyUntouched(t *testing.T) {
	ca, _ := enrolledNearExpiry(t)
	_, _, _, keyPath := certPaths()
	before, _ := os.ReadFile(keyPath)
	srv := newMockOrchestrator(t, ca, tls.RequireAndVerifyClientCert, http.StatusInternalServerError, &csrRecord{})
	t.Setenv("BAS_MTLS_PORT", portOf(t, srv.URL))

	if _, err := ensureCertificate(context.Background(), Config{ServerURL: "https://127.0.0.1:9443", AgentSecret: "secret"}, "abc123deadbeef01"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(keyPath)
	if !bytes.Equal(before, after) {
		t.Fatal("a failed renewal changed the stored key")
	}
	if _, err := os.Stat(keyPath + ".new"); err == nil {
		t.Error("a failed renewal left a pending key behind")
	}
}

func pemKey(t *testing.T, k *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// A crash at any point of the key+certificate swap must leave a pair that works after the next start.
func TestRecoverPendingRotation(t *testing.T) {
	setup := func(t *testing.T) (ca testCA, oldKey, newKey *ecdsa.PrivateKey, certPath, keyPath string) {
		ca, oldKey = enrolledNearExpiry(t)
		var err error
		newKey, err = newAgentKey()
		if err != nil {
			t.Fatal(err)
		}
		_, _, certPath, keyPath = certPaths()
		return
	}
	newCert := func(t *testing.T, ca testCA, k *ecdsa.PrivateKey) []byte {
		return caSignedCertPEM(t, ca, &k.PublicKey, "abc123deadbeef01", -time.Hour, 365*24*time.Hour)
	}
	assertPair := func(t *testing.T, want *ecdsa.PrivateKey, certPath, keyPath string) {
		t.Helper()
		got := readKey(t, keyPath)
		if !got.PublicKey.Equal(&want.PublicKey) {
			t.Fatal("stored key is not the expected one")
		}
		if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
			t.Fatalf("stored certificate and key do not form a working pair: %v", err)
		}
		for _, p := range []string{certPath + ".new", keyPath + ".new"} {
			if _, err := os.Stat(p); err == nil {
				t.Errorf("%s was left behind", p)
			}
		}
	}

	t.Run("crash before any rename", func(t *testing.T) {
		ca, _, newKey, certPath, keyPath := setup(t)
		os.WriteFile(keyPath+".new", pemKey(t, newKey), 0600)
		os.WriteFile(certPath+".new", newCert(t, ca, newKey), 0644)
		if err := recoverPendingRotation(); err != nil {
			t.Fatal(err)
		}
		assertPair(t, newKey, certPath, keyPath)
	})
	t.Run("crash between the two renames", func(t *testing.T) {
		ca, _, newKey, certPath, keyPath := setup(t)
		os.WriteFile(keyPath, pemKey(t, newKey), 0600) // key already swapped, old certificate still in place
		os.WriteFile(certPath+".new", newCert(t, ca, newKey), 0644)
		if err := recoverPendingRotation(); err != nil {
			t.Fatal(err)
		}
		assertPair(t, newKey, certPath, keyPath)
	})
	t.Run("stale pending files that match nothing are discarded", func(t *testing.T) {
		ca, oldKey, _, certPath, keyPath := setup(t)
		stranger, _ := newAgentKey()
		os.WriteFile(keyPath+".new", pemKey(t, stranger), 0600)
		os.WriteFile(certPath+".new", newCert(t, ca, oldKey), 0644) // matches neither pending key... but matches the CURRENT key
		os.Remove(certPath + ".new")
		os.WriteFile(certPath+".new", []byte("garbage"), 0644)
		if err := recoverPendingRotation(); err != nil {
			t.Fatal(err)
		}
		assertPair(t, oldKey, certPath, keyPath)
	})
}
