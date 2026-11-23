package deployconfig

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// The golden fixture is byte-identical in agent/deployconfig/testdata. The orchestrator
// verifies it against the committed public certificate (testdata/test-signing-cert.pem) and
// checks that the config encoding matches what Build produces. No private key is committed:
// tests that need to sign generate a key in memory for that run only.
//
// Regenerate both copies with:  DEPLOYCONFIG_UPDATE_GOLDEN=1 go test ./internal/deployconfig
// then copy testdata/golden.json to agent/deployconfig/testdata/golden.json. Regeneration
// replaces the committed certificate too.

const (
	goldenPath = "testdata/golden.json"
	certPath   = "testdata/test-signing-cert.pem"
)

type goldenFile struct {
	Envelope    string `json:"envelope"`
	Fingerprint string `json:"fingerprint"`
	Now         string `json:"now"`
}

var goldenConfig = Config{
	ServerURL:  "https://bas.example.com:9443",
	EnrollPort: "9444",
	IssuedAt:   time.Date(2026, 10, 25, 11, 59, 0, 0, time.UTC),
}

type testSigner struct {
	key  *rsa.PrivateKey
	cert []byte
}

func (s testSigner) PrivateKey() *rsa.PrivateKey { return s.key }
func (s testSigner) CertPEM() []byte             { return s.cert }

// ephemeralSigner returns an in-memory signing key and a matching self-signed certificate.
// The key is never written to disk.
func ephemeralSigner(t *testing.T) testSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	return testSigner{key: key, cert: selfSignedCertPEM(t, key)}
}

func selfSignedCertPEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TEST ONLY deployment config signer"},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2046, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// committedCert returns the public certificate that signed the golden fixture.
func committedCert(t *testing.T) []byte {
	t.Helper()
	cb, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.ReplaceAll(cb, []byte{13, 10}, []byte{10})
}

// verifyEnvelopeSignature checks the envelope's domain-separated signature against the public key in certPEM.
func verifyEnvelopeSignature(t *testing.T, env []byte, certPEM []byte) {
	t.Helper()
	cert, err := parseCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("certificate key is not RSA")
	}
	var e struct {
		Config    string `json:"config"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	cfg, err := base64.StdEncoding.DecodeString(e.Config)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append([]byte(SigningDomain), cfg...))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("golden signature does not verify with the committed certificate: %v", err)
	}
}

func envelopeConfig(t *testing.T, env []byte) string {
	t.Helper()
	var e struct {
		Config string `json:"config"`
	}
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	return e.Config
}

func TestBuildMatchesGolden(t *testing.T) {
	if os.Getenv("DEPLOYCONFIG_UPDATE_GOLDEN") == "1" {
		regenerateGolden(t)
		return
	}
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	var want goldenFile
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	cert := committedCert(t)
	fp, err := Fingerprint(cert)
	if err != nil {
		t.Fatal(err)
	}
	if fp != want.Fingerprint {
		t.Fatalf("fingerprint drifted from the golden fixture: got %s want %s", fp, want.Fingerprint)
	}
	// The config encoding does not depend on the key, so a fresh key must produce the same config bytes.
	probe, err := Build(ephemeralSigner(t), goldenConfig)
	if err != nil {
		t.Fatal(err)
	}
	if envelopeConfig(t, probe) != envelopeConfig(t, []byte(want.Envelope)) {
		t.Fatal("config encoding drifted from the golden fixture")
	}
	verifyEnvelopeSignature(t, []byte(want.Envelope), cert)
}

// regenerateGolden writes a new golden fixture and its certificate. The private key stays in memory only.
func regenerateGolden(t *testing.T) {
	t.Helper()
	s := ephemeralSigner(t)
	env, err := Build(s, goldenConfig)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := Fingerprint(s.CertPEM())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, s.CertPEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(goldenFile{Envelope: string(env), Fingerprint: fp, Now: "2026-10-25T12:00:00Z"}, "", "  ")
	if err := os.WriteFile(goldenPath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Log("golden fixtures regenerated; copy testdata/golden.json to agent/deployconfig/testdata/")
}

func TestBuildSignsWithDomainSeparation(t *testing.T) {
	s := ephemeralSigner(t)
	env, err := Build(s, goldenConfig)
	if err != nil {
		t.Fatal(err)
	}
	var e struct {
		Version   int    `json:"version"`
		Config    string `json:"config"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(env, &e); err != nil || e.Version != 1 {
		t.Fatalf("bad envelope: %v %+v", err, e)
	}
	cfg, _ := base64.StdEncoding.DecodeString(e.Config)
	sig, _ := base64.StdEncoding.DecodeString(e.Signature)
	with := sha256.Sum256(append([]byte(SigningDomain), cfg...))
	if err := rsa.VerifyPKCS1v15(&s.key.PublicKey, crypto.SHA256, with[:], sig); err != nil {
		t.Fatalf("signature does not verify with the domain prefix: %v", err)
	}
	without := sha256.Sum256(cfg)
	if err := rsa.VerifyPKCS1v15(&s.key.PublicKey, crypto.SHA256, without[:], sig); err == nil {
		t.Fatal("signature also verifies WITHOUT the domain prefix; it must be domain-separated")
	}
}

func TestFingerprintFormat(t *testing.T) {
	fp, err := Fingerprint(committedCert(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(fp) != 64 || fp != strings.ToLower(fp) {
		t.Fatalf("want 64 lowercase hex characters, got %q", fp)
	}
	if _, err := Fingerprint([]byte("not a pem")); err == nil {
		t.Fatal("non-PEM must fail")
	}
}

func TestBuildRefusesToSignInvalidConfig(t *testing.T) {
	s := ephemeralSigner(t)
	cases := map[string]func(c *Config){
		"http scheme":    func(c *Config) { c.ServerURL = "http://bas.example.com" },
		"empty url":      func(c *Config) { c.ServerURL = "" },
		"userinfo":       func(c *Config) { c.ServerURL = "https://u:p@bas.example.com" },
		"no host":        func(c *Config) { c.ServerURL = "https://" },
		"port zero":      func(c *Config) { c.EnrollPort = "0" },
		"port non-num":   func(c *Config) { c.EnrollPort = "x" },
		"garbage CA":     func(c *Config) { c.CARootPEM = "nope" },
		"zero issued at": func(c *Config) { c.IssuedAt = time.Time{} },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := goldenConfig
			mut(&c)
			if env, err := Build(s, c); err == nil {
				t.Fatalf("signed an invalid config: %s", env)
			}
		})
	}
}

func TestBuildRejectsWeakKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	good := ephemeralSigner(t)
	if _, err := Build(testSigner{key: key, cert: good.cert}, goldenConfig); err == nil {
		t.Fatal("a signer whose key is weaker than 3072 bits must be refused")
	}
}
