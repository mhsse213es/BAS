package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/integrity"
)

// setupSigned installs a throwaway public key as the compiled key and returns
// a dir holding two scenarios signed by signFile (the same code path as
// production signing), one in a subdirectory.
func setupSigned(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "k.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}), 0600); err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	old := integrity.ScenarioPublicKeyPEM
	integrity.ScenarioPublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	t.Cleanup(func() { integrity.ScenarioPublicKeyPEM = old })

	dir := filepath.Join(tmp, "scenarios")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"a.yaml", filepath.Join("sub", "b.yaml")} {
		p := filepath.Join(dir, rel)
		if err := os.WriteFile(p, []byte("name: "+rel+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		signFile(keyPath, p)
	}
	return dir
}

func TestVerifyAllValid(t *testing.T) {
	dir := setupSigned(t)
	var out bytes.Buffer
	if rc := verifyAll(dir, false, &out); rc != 0 || !strings.Contains(out.String(), "ok=2 fail=0") {
		t.Fatalf("rc=%d out=%s", rc, out.String())
	}
}

func TestVerifyAllTamperedNamed(t *testing.T) {
	dir := setupSigned(t)
	bad := filepath.Join(dir, "sub", "b.yaml")
	if err := os.WriteFile(bad, []byte("name: tampered\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	rc := verifyAll(dir, false, &out)
	if rc == 0 || !strings.Contains(out.String(), "b.yaml") || !strings.Contains(out.String(), "ok=1 fail=1") {
		t.Fatalf("rc=%d out=%s", rc, out.String())
	}
}

func TestVerifyAllMissingSig(t *testing.T) {
	dir := setupSigned(t)
	if err := os.Remove(filepath.Join(dir, "a.yaml.sig")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	rc := verifyAll(dir, false, &out)
	if rc == 0 || !strings.Contains(out.String(), "a.yaml") {
		t.Fatalf("rc=%d out=%s", rc, out.String())
	}
}

func TestVerifyAllSkipsCustomIntel(t *testing.T) {
	dir := setupSigned(t)
	for _, d := range []string{"custom", "intel"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, d, "u.yaml"), []byte("x: 1\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if rc := verifyAll(dir, false, &out); rc != 0 || !strings.Contains(out.String(), "ok=2 fail=0") {
		t.Fatalf("rc=%d out=%s", rc, out.String())
	}
	// Nested custom/ is NOT exempt.
	if err := os.MkdirAll(filepath.Join(dir, "sub", "custom"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "custom", "u.yaml"), []byte("x: 1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if rc := verifyAll(dir, false, &out); rc == 0 {
		t.Fatal("nested custom/ unsigned yaml should fail")
	}
}

func TestVerifyAllEmptyAndMissingDir(t *testing.T) {
	setupSigned(t)
	var out bytes.Buffer
	if rc := verifyAll(t.TempDir(), false, &out); rc == 0 {
		t.Fatal("empty dir passed")
	}
	if rc := verifyAll(filepath.Join(t.TempDir(), "nope"), false, &out); rc == 0 {
		t.Fatal("missing dir passed")
	}
}

func TestVerifyAllAllowDevPlaceholder(t *testing.T) {
	dir := setupSigned(t)
	integrity.ScenarioPublicKeyPEM = "SIGNING_KEYGEN_REQUIRED"
	var out bytes.Buffer
	if rc := verifyAll(dir, true, &out); rc != 0 {
		t.Fatalf("rc=%d out=%s", rc, out.String())
	}
}

func TestVerifyAllPlaceholderFails(t *testing.T) {
	dir := setupSigned(t)
	integrity.ScenarioPublicKeyPEM = "SIGNING_KEYGEN_REQUIRED" // restored by setupSigned cleanup
	var out bytes.Buffer
	if rc := verifyAll(dir, false, &out); rc == 0 {
		t.Fatalf("placeholder key passed vacuously: %s", out.String())
	}
}
