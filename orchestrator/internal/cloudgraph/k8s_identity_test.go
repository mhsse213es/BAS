package cloudgraph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestK8sIdentity_SPKIAndCAFingerprintMatchTheServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"gitVersion":"v1.30.0"}`))
	}))
	defer srv.Close()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	got, err := TLSServerIdentity(context.Background(), srv.URL, caPEM)
	if err != nil {
		t.Fatalf("verified server refused: %v", err)
	}
	want := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	if got != hex.EncodeToString(want[:]) {
		t.Errorf("SPKI hash mismatch: got %s", got)
	}

	fp, err := CAFingerprint(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	cafp := sha256.Sum256(srv.Certificate().Raw)
	if fp != hex.EncodeToString(cafp[:]) {
		t.Errorf("CA fingerprint mismatch: got %s", fp)
	}

	client, err := NewK8sDiscoveryClient(K8sDiscoveryConfig{ClusterName: "lab", APIServer: srv.URL, Token: "t", CAPEM: caPEM})
	if err != nil {
		t.Fatal(err)
	}
	ver, err := client.ServerVersion(context.Background())
	if err != nil || ver != "v1.30.0" {
		t.Errorf("version: got %q, %v", ver, err)
	}
}

func TestK8sIdentity_UnverifiedCertificateIsRefused(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	wrongCA := unrelatedCAPEM(t)

	if _, err := TLSServerIdentity(context.Background(), srv.URL, wrongCA); err == nil {
		t.Fatal("a certificate that does not verify against the CA must produce no identity")
	}
	if _, err := CAFingerprint([]byte("not pem")); err == nil {
		t.Error("a CA with no certificate must be refused")
	}
	if _, err := TLSServerIdentity(context.Background(), "http://plain.example", nil); err == nil {
		t.Error("plain http must be refused")
	}
}
