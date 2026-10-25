package deployconfig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

// signer mirrors what the orchestrator does, so these tests pin the wire format
// from the agent's side. The orchestrator has its own test against the same
// golden vector.
type signer struct {
	key     *rsa.PrivateKey
	certPEM []byte
	certDER []byte
}

func newSigner(t *testing.T, bits int) *signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test signing"},
		NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{key: key, certDER: der, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (s *signer) fingerprint() string {
	sum := sha256.Sum256(s.certDER)
	return hex.EncodeToString(sum[:])
}

func caPEM(t *testing.T, isCA bool) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "deployment CA"},
		NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour),
		IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

type cfgJSON struct {
	ServerURL  string `json:"serverURL"`
	EnrollPort string `json:"enrollPort,omitempty"`
	CARootPEM  string `json:"caRootPem,omitempty"`
	IssuedAt   string `json:"issuedAt"`
}

func goodCfg(t *testing.T) cfgJSON {
	return cfgJSON{ServerURL: "https://bas.example.com:9443", EnrollPort: "9444", CARootPEM: caPEM(t, true), IssuedAt: testNow.Add(-time.Minute).Format(time.RFC3339)}
}

// seal builds an envelope. sigDomain lets a test sign with the wrong domain.
func (s *signer) seal(t *testing.T, version int, configBytes []byte, domain string) []byte {
	t.Helper()
	sum := sha256.Sum256(append([]byte(domain), configBytes...))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(map[string]any{
		"version": version, "config": base64.StdEncoding.EncodeToString(configBytes),
		"signingCertPem": string(s.certPEM), "signature": base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func (s *signer) sealCfg(t *testing.T, c cfgJSON) []byte {
	t.Helper()
	b, _ := json.Marshal(c)
	return s.seal(t, 1, b, SigningDomain)
}

func TestVerifyValid(t *testing.T) {
	s := newSigner(t, 3072)
	c := goodCfg(t)
	got, err := Verify(s.sealCfg(t, c), s.fingerprint(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerURL != c.ServerURL || got.EnrollPort != "9444" || got.CARootPEM != c.CARootPEM {
		t.Fatalf("unexpected config: %+v", got)
	}
}

func TestVerifyAcceptsFormattedFingerprint(t *testing.T) {
	s := newSigner(t, 3072)
	env := s.sealCfg(t, goodCfg(t))
	fp := s.fingerprint()
	var colons []string
	for i := 0; i < len(fp); i += 2 {
		colons = append(colons, strings.ToUpper(fp[i:i+2]))
	}
	for _, in := range []string{strings.ToUpper(fp), strings.Join(colons, ":"), "  " + fp + "\n"} {
		if _, err := Verify(env, in, testNow); err != nil {
			t.Fatalf("fingerprint %q: %v", in, err)
		}
	}
}

func TestVerifyRequiresFingerprint(t *testing.T) {
	s := newSigner(t, 3072)
	env := s.sealCfg(t, goodCfg(t))
	for name, fp := range map[string]string{"empty": "", "spaces": "   ", "too short": "abcd", "not hex": strings.Repeat("zz", 32), "too long": s.fingerprint() + "00"} {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(env, fp, testNow)
			if err == nil || !strings.Contains(err.Error(), "fingerprint") {
				t.Fatalf("got %v, want a fingerprint error", err)
			}
		})
	}
}

// The core of Option A: an attacker who replaces the ZIP can substitute their
// own key, certificate and signature. Only the independently supplied
// fingerprint stops them.
func TestVerifyRejectsAttackerKeyEvenWhenSelfConsistent(t *testing.T) {
	legit := newSigner(t, 3072)
	attacker := newSigner(t, 3072)
	evil := goodCfg(t)
	evil.ServerURL = "https://evil.example.net"
	env := attacker.sealCfg(t, evil) // valid signature under the attacker's own certificate
	got, err := Verify(env, legit.fingerprint(), testNow)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("got %v, want a fingerprint-mismatch error", err)
	}
	if got != (Config{}) {
		t.Fatalf("no config may be returned on failure, got %+v", got)
	}
}

func TestVerifyRejectsTamperedConfig(t *testing.T) {
	s := newSigner(t, 3072)
	good, _ := json.Marshal(goodCfg(t))
	tampered := strings.Replace(string(good), "bas.example.com", "bas.example.org", 1)
	// Re-seal with the legitimate signature of the ORIGINAL bytes but swap the config.
	orig := s.seal(t, 1, good, SigningDomain)
	var env map[string]any
	_ = json.Unmarshal(orig, &env)
	env["config"] = base64.StdEncoding.EncodeToString([]byte(tampered))
	b, _ := json.Marshal(env)
	got, err := Verify(b, s.fingerprint(), testNow)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("got %v, want a signature error", err)
	}
	if got != (Config{}) {
		t.Fatalf("no config may be returned on failure")
	}
}

func TestVerifyRejectsMissingOrEmptySignature(t *testing.T) {
	s := newSigner(t, 3072)
	var env map[string]any
	_ = json.Unmarshal(s.sealCfg(t, goodCfg(t)), &env)
	env["signature"] = ""
	b, _ := json.Marshal(env)
	if _, err := Verify(b, s.fingerprint(), testNow); err == nil {
		t.Fatal("empty signature must fail")
	}
	delete(env, "signature")
	b, _ = json.Marshal(env)
	if _, err := Verify(b, s.fingerprint(), testNow); err == nil {
		t.Fatal("missing signature must fail")
	}
}

// A signature made for another purpose with the same key (the command-signing
// key signs every dispatched command) must not validate as a deployment config.
func TestVerifyRejectsWrongSigningDomain(t *testing.T) {
	s := newSigner(t, 3072)
	b, _ := json.Marshal(goodCfg(t))
	for _, domain := range []string{"", "audspect-command-v1\n", "audspect-deployment-config-v2\n"} {
		env := s.seal(t, 1, b, domain)
		if _, err := Verify(env, s.fingerprint(), testNow); err == nil || !strings.Contains(err.Error(), "signature") {
			t.Fatalf("domain %q: got %v, want a signature error", domain, err)
		}
	}
}

func TestVerifyRejectsUnsupportedVersion(t *testing.T) {
	s := newSigner(t, 3072)
	b, _ := json.Marshal(goodCfg(t))
	for _, v := range []int{0, 2, -1} {
		if _, err := Verify(s.seal(t, v, b, SigningDomain), s.fingerprint(), testNow); err == nil || !strings.Contains(err.Error(), "version") {
			t.Fatalf("version %d: got %v, want a version error", v, err)
		}
	}
}

func TestVerifyRejectsUnknownFields(t *testing.T) {
	s := newSigner(t, 3072)
	good, _ := json.Marshal(goodCfg(t))
	withExtra := strings.Replace(string(good), "{", `{"proxy":"http://x",`, 1)
	if _, err := Verify(s.seal(t, 1, []byte(withExtra), SigningDomain), s.fingerprint(), testNow); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unknown config field: got %v", err)
	}
	var env map[string]any
	_ = json.Unmarshal(s.sealCfg(t, goodCfg(t)), &env)
	env["extra"] = "x"
	b, _ := json.Marshal(env)
	if _, err := Verify(b, s.fingerprint(), testNow); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unknown envelope field: got %v", err)
	}
}

func TestVerifyRejectsInvalidConfigContent(t *testing.T) {
	s := newSigner(t, 3072)
	cases := map[string]func(c *cfgJSON){
		"http scheme":        func(c *cfgJSON) { c.ServerURL = "http://bas.example.com" },
		"no host":            func(c *cfgJSON) { c.ServerURL = "https://" },
		"userinfo":           func(c *cfgJSON) { c.ServerURL = "https://u:p@bas.example.com" },
		"empty url":          func(c *cfgJSON) { c.ServerURL = "" },
		"port zero":          func(c *cfgJSON) { c.EnrollPort = "0" },
		"port too large":     func(c *cfgJSON) { c.EnrollPort = "65536" },
		"port not numeric":   func(c *cfgJSON) { c.EnrollPort = "nine" },
		"garbage CA":         func(c *cfgJSON) { c.CARootPEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" },
		"CA not a CA cert":   func(c *cfgJSON) { c.CARootPEM = caPEM(t, false) },
		"issuedAt missing":   func(c *cfgJSON) { c.IssuedAt = "" },
		"issuedAt bad":       func(c *cfgJSON) { c.IssuedAt = "yesterday" },
		"issuedAt in future": func(c *cfgJSON) { c.IssuedAt = testNow.Add(time.Hour).Format(time.RFC3339) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := goodCfg(t)
			mut(&c)
			got, err := Verify(s.sealCfg(t, c), s.fingerprint(), testNow)
			if err == nil {
				t.Fatalf("expected an error, got config %+v", got)
			}
			if got != (Config{}) {
				t.Fatal("no config may be returned on failure")
			}
		})
	}
}

func TestVerifyAllowsMissingCA(t *testing.T) {
	s := newSigner(t, 3072)
	c := goodCfg(t)
	c.CARootPEM = ""
	got, err := Verify(s.sealCfg(t, c), s.fingerprint(), testNow)
	if err != nil || got.CARootPEM != "" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestVerifyRejectsWeakSigningKey(t *testing.T) {
	s := newSigner(t, 2048)
	if _, err := Verify(s.sealCfg(t, goodCfg(t)), s.fingerprint(), testNow); err == nil || !strings.Contains(err.Error(), "key") {
		t.Fatalf("got %v, want a weak-key error", err)
	}
}

func TestVerifyRejectsBadEnvelopes(t *testing.T) {
	s := newSigner(t, 3072)
	fp := s.fingerprint()
	for name, in := range map[string][]byte{
		"empty": nil, "not json": []byte("nope"), "json array": []byte("[]"),
		"oversize": []byte(strings.Repeat("a", MaxEnvelopeBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(in, fp, testNow); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	var env map[string]any
	_ = json.Unmarshal(s.sealCfg(t, goodCfg(t)), &env)
	env["signingCertPem"] = "not a pem"
	b, _ := json.Marshal(env)
	if _, err := Verify(b, fp, testNow); err == nil {
		t.Fatal("a non-PEM certificate must fail")
	}
	env["signingCertPem"] = string(s.certPEM) + string(s.certPEM)
	b, _ = json.Marshal(env)
	if _, err := Verify(b, fp, testNow); err == nil {
		t.Fatal("more than one certificate must fail")
	}
}

func TestErrorsNeverIncludeConfigContent(t *testing.T) {
	s := newSigner(t, 3072)
	c := goodCfg(t)
	c.ServerURL = "https://u:p4ssw0rd-LEAK@bas.example.com"
	_, err := Verify(s.sealCfg(t, c), s.fingerprint(), testNow)
	if err == nil || strings.Contains(err.Error(), "p4ssw0rd-LEAK") {
		t.Fatalf("error must exist and must not echo the content: %v", err)
	}
}

func TestFingerprintOfCert(t *testing.T) {
	s := newSigner(t, 3072)
	got, err := Fingerprint(s.certPEM)
	if err != nil || got != s.fingerprint() {
		t.Fatalf("got %q, %v; want %q", got, err, s.fingerprint())
	}
	if _, err := Fingerprint([]byte("nope")); err == nil {
		t.Fatal("non-PEM must fail")
	}
}
