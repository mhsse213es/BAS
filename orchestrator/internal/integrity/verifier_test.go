package integrity_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/integrity"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(t *testing.T, k *rsa.PrivateKey, b []byte) []byte {
	t.Helper()
	h := sha256.Sum256(b)
	s, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestKeyVerifier_VerifiesOnlyMatchingSignature(t *testing.T) {
	k := testKey(t)
	v := integrity.NewKeyVerifier(&k.PublicKey)
	content := []byte("id: x\n")
	ok, err := v.Verify(content, sign(t, k, content))
	if !ok || err != nil {
		t.Fatalf("valid signature: ok=%v err=%v", ok, err)
	}
	ok, err = v.Verify([]byte("id: y\n"), sign(t, k, content))
	if ok || err == nil {
		t.Fatalf("tampered content must fail: ok=%v err=%v", ok, err)
	}
	if !v.SigningEnabled() {
		t.Fatal("key verifier must report signing enabled")
	}
}

// A15: a (false, nil) verification must never be mistaken for proof.
func TestReadBuiltinSignature_DevBuildIsNotVerified(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.yaml")
	content := []byte("id: a\n")
	_ = os.WriteFile(p, content, 0o644)
	sig, verified, err := integrity.ReadBuiltinSignature(devVerifier{}, p, content)
	if err != nil || verified || sig != nil {
		t.Fatalf("dev build without .sig: sig=%v verified=%v err=%v", sig, verified, err)
	}
}

func TestReadBuiltinSignature_MissingSigWhenEnabledIsErrUnsigned(t *testing.T) {
	k := testKey(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "a.yaml")
	content := []byte("id: a\n")
	_ = os.WriteFile(p, content, 0o644)
	if _, _, err := integrity.ReadBuiltinSignature(integrity.NewKeyVerifier(&k.PublicKey), p, content); err == nil {
		t.Fatal("missing .sig with signing enabled must error")
	}
	_ = os.WriteFile(p+".sig", []byte(base64.StdEncoding.EncodeToString(sign(t, k, content))), 0o644)
	sig, verified, err := integrity.ReadBuiltinSignature(integrity.NewKeyVerifier(&k.PublicKey), p, content)
	if err != nil || !verified || len(sig) == 0 {
		t.Fatalf("valid .sig: verified=%v err=%v", verified, err)
	}
}

type devVerifier struct{}

func (devVerifier) Verify([]byte, []byte) (bool, error) { return false, nil }
func (devVerifier) SigningEnabled() bool                { return false }

// A16: signingEnabled must depend only on the compiled-in constant. The
// variable is exported (signer.go rewrites it at keygen time), so the guard
// is a source scan: no non-test Go file outside integrity may assign it, and
// the integrity package must not read env/config.
func TestSigningEnabledNotRuntimeConfigurable(t *testing.T) {
	root := filepath.Join("..", "..")
	assign := regexp.MustCompile(`ScenarioPublicKeyPEM\s*=`)
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, _ := os.ReadFile(path)
		if !assign.Match(b) {
			return nil
		}
		slash := filepath.ToSlash(path)
		if strings.HasSuffix(slash, "internal/integrity/signing.go") || strings.HasSuffix(slash, "scripts/signer.go") {
			return nil // the declaration itself, and the offline keygen rewriter
		}
		t.Errorf("%s assigns ScenarioPublicKeyPEM at runtime", path)
		return nil
	})
	for _, f := range []string{"signing.go", "verifier.go"} {
		b, _ := os.ReadFile(f)
		if strings.Contains(string(b), "os.Getenv") || strings.Contains(string(b), "config.") {
			t.Errorf("%s must not consult env/config", f)
		}
	}
}
