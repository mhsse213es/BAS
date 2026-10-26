package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// nextCAWithCross makes the "next" CA and the cross-certificate for its key that signer vouches for,
// exactly what the server's rotation prepares.
func nextCAWithCross(t *testing.T, signer testCA) (next testCA, rootPEM, crossPEM []byte) {
	t.Helper()
	next = newTestCA(t)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: next.cert.Subject,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer.cert, &next.key.PublicKey, signer.key)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: next.cert.Raw})
	crossPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return next, rootPEM, crossPEM
}

func trustPayload(rootPEM, crossPEM []byte) []byte {
	b, _ := json.Marshal(map[string]string{"rootPem": string(rootPEM), "crossPem": string(crossPEM)})
	return b
}

func fpOf(c *x509.Certificate) string { s := sha256.Sum256(c.Raw); return hex.EncodeToString(s[:]) }

func pinnedSetup(t *testing.T) (dir string, old testCA) {
	t.Helper()
	dir = t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	old = newTestCA(t)
	seedDeploymentCA(t, dir, old)
	return dir, old
}

func TestAcceptCARoot_AppendsANewRootVouchedForByThePinnedOne(t *testing.T) {
	_, old := pinnedSetup(t)
	next, rootPEM, crossPEM := nextCAWithCross(t, old)
	if err := acceptCARoot(trustPayload(rootPEM, crossPEM)); err != nil {
		t.Fatal(err)
	}
	fps := trustedRootFingerprints()
	if len(fps) != 2 || !contains(fps, fpOf(old.cert)) || !contains(fps, fpOf(next.cert)) {
		t.Errorf("fingerprints = %v, want the old and the new root", fps)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestAcceptCARoot_IsIdempotent(t *testing.T) {
	_, old := pinnedSetup(t)
	_, rootPEM, crossPEM := nextCAWithCross(t, old)
	for i := 0; i < 2; i++ {
		if err := acceptCARoot(trustPayload(rootPEM, crossPEM)); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(trustedRootFingerprints()); n != 2 {
		t.Errorf("%d roots after delivering the same root twice, want 2", n)
	}
}

// Even a correctly signed command must not add a root the pinned CA has not vouched for.
func TestAcceptCARoot_RefusesARootTheCurrentCADidNotVouchFor(t *testing.T) {
	dir, old := pinnedSetup(t)
	before, _ := os.ReadFile(dir + string(os.PathSeparator) + "deployment-ca.pem")
	stranger := newTestCA(t)
	_, rootPEM, crossFromStranger := nextCAWithCross(t, stranger)
	if err := acceptCARoot(trustPayload(rootPEM, crossFromStranger)); err == nil {
		t.Error("a cross-certificate from a CA that is not pinned must be refused")
	}
	// A cross-certificate that vouches for a different key than the root presented.
	_, _, crossForOtherKey := nextCAWithCross(t, old)
	otherRoot := newTestCA(t)
	otherPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherRoot.cert.Raw})
	if err := acceptCARoot(trustPayload(otherPEM, crossForOtherKey)); err == nil {
		t.Error("a root whose key the cross-certificate does not cover must be refused")
	}
	if err := acceptCARoot(trustPayload(rootPEM, nil)); err == nil {
		t.Error("a root without a cross-certificate must be refused")
	}
	if err := acceptCARoot([]byte("not json")); err == nil {
		t.Error("a malformed payload must be refused")
	}
	after, _ := os.ReadFile(dir + string(os.PathSeparator) + "deployment-ca.pem")
	if string(before) != string(after) {
		t.Error("a refused root must leave the pinned file untouched")
	}
}

func TestAcceptCARoot_RefusesAnExpiredOrNonCARoot(t *testing.T) {
	_, old := pinnedSetup(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	leafTmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "not a CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, leafTmpl, old.cert, &key.PublicKey, old.key)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := acceptCARoot(trustPayload(leafPEM, leafPEM)); err == nil || !strings.Contains(err.Error(), "CA") {
		t.Errorf("a certificate that is not a CA must be refused, got %v", err)
	}
}

func TestAcceptCARoot_NeedsAPinnedRootToExtend(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	old := newTestCA(t)
	_, rootPEM, crossPEM := nextCAWithCross(t, old)
	if err := acceptCARoot(trustPayload(rootPEM, crossPEM)); err == nil {
		t.Error("with no pinned root nothing can vouch for the new one; it must be refused")
	}
}

// After a root is accepted, the already-running connection config trusts a server certificate from it
// without any restart: the pool is read at verification time.
func TestMTLSConfig_PicksUpANewlyAcceptedRootWithoutRebuilding(t *testing.T) {
	_, old := pinnedSetup(t)
	cfg, err := mtlsTLSConfig(Config{})
	if err != nil || cfg == nil {
		t.Fatalf("mtlsTLSConfig: %v", err)
	}
	next, rootPEM, crossPEM := nextCAWithCross(t, old)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "srv"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, leaf, next.cert, &srvKey.PublicKey, next.key)

	if err := cfg.VerifyPeerCertificate([][]byte{der}, nil); err == nil {
		t.Fatal("a server certificate from the not-yet-trusted new CA must be refused")
	}
	if err := acceptCARoot(trustPayload(rootPEM, crossPEM)); err != nil {
		t.Fatal(err)
	}
	if err := cfg.VerifyPeerCertificate([][]byte{der}, nil); err != nil {
		t.Errorf("after accepting the root the same config must trust it: %v", err)
	}
}
