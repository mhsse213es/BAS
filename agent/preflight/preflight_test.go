package preflight

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testSecret = "s3cr3t-value-DO-NOT-LEAK"

// fakeOrchestrator stands in for the enrollment listener. It records how many
// times /ws/agent was reached so tests can prove the secret was never sent.
type fakeOrchestrator struct {
	srv        *httptest.Server
	wsHits     atomic.Int32
	healthCode int
	wsCode     int
}

func newFake(t *testing.T) *fakeOrchestrator {
	t.Helper()
	f := &fakeOrchestrator{healthCode: http.StatusOK, wsCode: http.StatusBadRequest}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(f.healthCode)
		case "/ws/agent":
			f.wsHits.Add(1)
			if r.Header.Get("X-Agent-Token") != testSecret {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(f.wsCode)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOrchestrator) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
}

func (f *fakeOrchestrator) port(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Port()
}

func (f *fakeOrchestrator) params(t *testing.T) Params {
	return Params{ServerURL: f.srv.URL, EnrollPort: f.port(t), Secret: testSecret, CARootPEM: f.caPEM()}
}

func ctx5(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

func assertNoSecret(t *testing.T, r Result) {
	t.Helper()
	if strings.Contains(r.Message, testSecret) {
		t.Fatalf("message leaks the secret: %q", r.Message)
	}
}

func TestRunOKWhenReachableAndSecretAccepted(t *testing.T) {
	f := newFake(t)
	r := Run(ctx5(t), f.params(t))
	if r.Code != CodeOK || !r.OK() {
		t.Fatalf("got %d %q, want OK", r.Code, r.Message)
	}
	assertNoSecret(t, r)
}

func TestRunSecretRejectedOn401(t *testing.T) {
	f := newFake(t)
	p := f.params(t)
	p.Secret = "wrong-secret-value"
	r := Run(ctx5(t), p)
	if r.Code != CodeSecretRejected {
		t.Fatalf("got %d %q, want CodeSecretRejected", r.Code, r.Message)
	}
	if strings.Contains(r.Message, "wrong-secret-value") {
		t.Fatalf("message leaks the supplied secret: %q", r.Message)
	}
}

func TestRunUnreachableWhenNothingListens(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	r := Run(ctx5(t), Params{ServerURL: "https://127.0.0.1", EnrollPort: strconv.Itoa(port), Secret: testSecret})
	if r.Code != CodeUnreachable {
		t.Fatalf("got %d %q, want CodeUnreachable", r.Code, r.Message)
	}
	assertNoSecret(t, r)
}

func TestRunUnreachableWhenHealthIsNot200(t *testing.T) {
	f := newFake(t)
	f.healthCode = http.StatusServiceUnavailable
	r := Run(ctx5(t), f.params(t))
	if r.Code != CodeUnreachable {
		t.Fatalf("got %d %q, want CodeUnreachable", r.Code, r.Message)
	}
	if f.wsHits.Load() != 0 {
		t.Fatal("secret was sent to a server whose health check failed")
	}
}

func TestRunTrustFailureWhenCANotSigned(t *testing.T) {
	f := newFake(t)
	p := f.params(t)
	p.CARootPEM = unrelatedCAPEM(t) // httptest servers share one cert, so make a genuinely different CA
	r := Run(ctx5(t), p)
	if r.Code != CodeTrustFailure {
		t.Fatalf("got %d %q, want CodeTrustFailure", r.Code, r.Message)
	}
	if f.wsHits.Load() != 0 {
		t.Fatal("the secret was sent to a server the supplied CA does not vouch for")
	}
	assertNoSecret(t, r)
}

func TestRunInvalidCAPEM(t *testing.T) {
	f := newFake(t)
	p := f.params(t)
	p.CARootPEM = []byte("-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n")
	r := Run(ctx5(t), p)
	if r.Code != CodeInvalidCA {
		t.Fatalf("got %d %q, want CodeInvalidCA", r.Code, r.Message)
	}
	if f.wsHits.Load() != 0 {
		t.Fatal("contacted the server despite an unusable CA")
	}
}

func TestRunNoCAFallsBackToPreTrustAndSaysSo(t *testing.T) {
	f := newFake(t)
	p := f.params(t)
	p.CARootPEM = nil
	r := Run(ctx5(t), p)
	if r.Code != CodeOK {
		t.Fatalf("got %d %q, want OK", r.Code, r.Message)
	}
	if !strings.Contains(r.Message, "no deployment CA") {
		t.Fatalf("message must say the server identity was not verified: %q", r.Message)
	}
}

func TestRunInvalidInput(t *testing.T) {
	cases := map[string]Params{
		"empty url":        {ServerURL: "", Secret: testSecret},
		"http scheme":      {ServerURL: "http://h.example", Secret: testSecret},
		"ftp scheme":       {ServerURL: "ftp://h.example", Secret: testSecret},
		"no host":          {ServerURL: "https://", Secret: testSecret},
		"userinfo in url":  {ServerURL: "https://user:" + testSecret + "@h.example", Secret: testSecret},
		"port zero":        {ServerURL: "https://h.example", EnrollPort: "0", Secret: testSecret},
		"port too big":     {ServerURL: "https://h.example", EnrollPort: "70000", Secret: testSecret},
		"port not numeric": {ServerURL: "https://h.example", EnrollPort: "abc", Secret: testSecret},
		"empty secret":     {ServerURL: "https://h.example", Secret: ""},
		"control char":     {ServerURL: "https://h.example", Secret: "ab\x00cd"},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			r := Run(ctx5(t), p)
			if r.Code != CodeInvalidInput {
				t.Fatalf("got %d %q, want CodeInvalidInput", r.Code, r.Message)
			}
			assertNoSecret(t, r)
		})
	}
}

func TestEnrollmentProbeURLUsesEnrollPort(t *testing.T) {
	got, err := EnrollmentProbeURL("https://h.example:9443", "9555")
	if err != nil || got != "https://h.example:9555" {
		t.Fatalf("got %q, %v", got, err)
	}
	got, err = EnrollmentProbeURL("https://h.example:9443", "")
	if err != nil || got != "https://h.example:9444" {
		t.Fatalf("default port: got %q, %v", got, err)
	}
}

func TestCodesAreDistinct(t *testing.T) {
	seen := map[int]string{}
	for name, c := range map[string]int{"ok": CodeOK, "input": CodeInvalidInput, "unreachable": CodeUnreachable,
		"secret": CodeSecretRejected, "trust": CodeTrustFailure, "ca": CodeInvalidCA} {
		if prev, dup := seen[c]; dup {
			t.Fatalf("code %d used for both %s and %s", c, prev, name)
		}
		seen[c] = name
	}
}

// Keep the compiler honest that the CA helper really is a usable root.
func TestFakeCAIsAParsableRoot(t *testing.T) {
	f := newFake(t)
	if !x509.NewCertPool().AppendCertsFromPEM(f.caPEM()) {
		t.Fatal("fake CA PEM does not parse")
	}
}

// unrelatedCAPEM returns a freshly generated self-signed CA that did not sign
// anything the fake server presents.
func unrelatedCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "unrelated test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
