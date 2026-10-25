package deployconfig

import (
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
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The golden fixture is byte-identical in agent/deployconfig/testdata. The
// orchestrator must regenerate it exactly (RSA PKCS#1 v1.5 is deterministic) and
// the agent must verify it, so neither side can drift from the wire format
// without a test failing. The private key in testdata is a throwaway used only
// by this test; it signs nothing real.
//
// Regenerate both copies with:  DEPLOYCONFIG_UPDATE_GOLDEN=1 go test ./internal/deployconfig
// then copy testdata/golden.json to agent/deployconfig/testdata/golden.json.

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

func loadOrCreateTestSigner(t *testing.T, update bool) testSigner {
	t.Helper()
	keyPath := filepath.Join("testdata", "test-signing-key.pem")
	certPath := filepath.Join("testdata", "test-signing-cert.pem")
	if kb, err := os.ReadFile(keyPath); err == nil && !update {
		cb, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode(kb)
		key, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return testSigner{key: key, cert: cb}
	}
	if !update {
		t.Skip("golden fixtures missing; run with DEPLOYCONFIG_UPDATE_GOLDEN=1 to create them")
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TEST ONLY deployment config signer"},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2046, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return testSigner{key: key, cert: certPEM}
}

func TestBuildMatchesGolden(t *testing.T) {
	update := os.Getenv("DEPLOYCONFIG_UPDATE_GOLDEN") == "1"
	s := loadOrCreateTestSigner(t, update)
	env, err := Build(s, goldenConfig)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := Fingerprint(s.CertPEM())
	if err != nil {
		t.Fatal(err)
	}
	got := goldenFile{Envelope: string(env), Fingerprint: fp, Now: "2026-10-25T12:00:00Z"}
	path := filepath.Join("testdata", "golden.json")
	if update {
		b, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("golden fixtures regenerated")
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want goldenFile
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if got.Envelope != want.Envelope || got.Fingerprint != want.Fingerprint {
		t.Fatalf("envelope or fingerprint drifted from the golden fixture:\n got  %s\n want %s", got.Envelope, want.Envelope)
	}
}

func TestBuildSignsWithDomainSeparation(t *testing.T) {
	s := loadOrCreateTestSigner(t, false)
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
	s := loadOrCreateTestSigner(t, false)
	fp, err := Fingerprint(s.CertPEM())
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
	s := loadOrCreateTestSigner(t, false)
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
	good := loadOrCreateTestSigner(t, false)
	if _, err := Build(testSigner{key: key, cert: good.cert}, goldenConfig); err == nil {
		t.Fatal("a signer whose key is weaker than 3072 bits must be refused")
	}
}
