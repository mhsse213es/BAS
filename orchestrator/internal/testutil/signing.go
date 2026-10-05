package testutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"testing"

	"github.com/audspect/bas/internal/integrity"
)

// TestSigner stands in for the vendor key, whose private half is not
// available to tests or CI.
type TestSigner struct{ key *rsa.PrivateKey }

func NewTestSigner(t *testing.T) *TestSigner {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("testutil: rsa key: %v", err)
	}
	return &TestSigner{key: k}
}

func (s *TestSigner) Sign(content []byte) []byte {
	h := sha256.Sum256(content)
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, h[:])
	if err != nil {
		panic(err)
	}
	return sig
}

// WriteSigned writes content to path and its base64 signature to path+".sig".
func (s *TestSigner) WriteSigned(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sig", []byte(base64.StdEncoding.EncodeToString(s.Sign(content))), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (s *TestSigner) Verifier() integrity.Verifier { return integrity.NewKeyVerifier(&s.key.PublicKey) }

type devVerifier struct{}

func (devVerifier) Verify([]byte, []byte) (bool, error) { return false, nil }
func (devVerifier) SigningEnabled() bool                { return false }

// DevVerifier simulates a dev build (placeholder key).
func DevVerifier() integrity.Verifier { return devVerifier{} }
