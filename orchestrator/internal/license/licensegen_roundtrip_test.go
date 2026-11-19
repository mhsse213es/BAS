package license

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// issue runs the real packaging/licensing/licensegen and returns the licence file bytes.
func issue(t *testing.T, priv *rsa.PrivateKey, extra ...string) []byte {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "private.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "x.lic")
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{"run", filepath.Join("packaging", "licensing", "licensegen", "main.go"),
		"-customer", "Round Trip", "-id", "rt-1", "-days", "30", "-key", keyPath, "-out", out}, extra...)
	cmd := exec.Command("go", args...)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("licensegen %v: %v\n%s", extra, err, b)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A licence issued with -addons aleef verifies with the orchestrator's own verification code and
// carries the add-on; one issued without does not; editing Features after signing fails verification.
func TestLicensegenAddonRoundTrip(t *testing.T) {
	priv, pubPEM := GenerateTestKeypair()
	orig := PublicKeyPEM
	PublicKeyPEM = pubPEM
	defer func() { PublicKeyPEM = orig }()

	with, err := verify(issue(t, priv, "-addons", "aleef", "-tier", "Core"))
	if err != nil {
		t.Fatalf("verify with add-on: %v", err)
	}
	if !with.HasAddon("aleef") || !with.Permits(ProductAleef) || with.Tier != "Core" || !with.Permits(ProductAV) {
		t.Fatalf("licence with add-on: %+v", with)
	}
	if got := with.SpecialAddons(); len(got) != 1 || got[0].Category != "special" || got[0].Name != "aleef" {
		t.Fatalf("SpecialAddons = %+v", got)
	}

	raw := issue(t, priv)
	without, err := verify(raw)
	if err != nil {
		t.Fatalf("verify without add-on: %v", err)
	}
	if without.HasAddon("aleef") || without.Permits(ProductAleef) {
		t.Fatalf("licence without -addons grants Aleef: %+v", without)
	}

	// Tamper: add the token to a licence that was signed without it.
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["features"] = append(m["features"].([]any), "addon:aleef")
	forged, _ := json.Marshal(m)
	if _, err := verify(forged); err == nil {
		t.Fatal("a licence with Features edited after signing verified")
	}
}
