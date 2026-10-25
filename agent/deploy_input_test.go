package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"audspect/agent/deployconfig"
	"audspect/agent/preflight"
)

// goldenFor loads the shared golden envelope the orchestrator signs.
func goldenFor(t *testing.T) (path, fp string, now time.Time) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("deployconfig", "testdata", "golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g struct{ Envelope, Fingerprint, Now string }
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	now, _ = time.Parse(time.RFC3339, g.Now)
	path = filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, []byte(g.Envelope), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, g.Fingerprint, now
}

func TestResolveDeploymentWithoutConfigPassesFlagsThrough(t *testing.T) {
	d, err := resolveDeployment(deployFlags{Server: "https://h:9443", EnrollPort: "9444"}, time.Now())
	if err != nil || d.Server != "https://h:9443" || d.EnrollPort != "9444" {
		t.Fatalf("got %+v, %v", d, err)
	}
}

func TestResolveDeploymentFingerprintWithoutConfigIsAnError(t *testing.T) {
	if _, err := resolveDeployment(deployFlags{Fingerprint: "ab"}, time.Now()); err == nil {
		t.Fatal("--config-fingerprint without --config must fail")
	}
}

func TestResolveDeploymentVerifiedConfig(t *testing.T) {
	path, fp, now := goldenFor(t)
	d, err := resolveDeployment(deployFlags{ConfigPath: path, Fingerprint: fp}, now)
	if err != nil {
		t.Fatal(err)
	}
	if d.Server != "https://bas.example.com:9443" || d.EnrollPort != "9444" || len(d.CARootPEM) != 0 {
		t.Fatalf("got %+v", d)
	}
}

func TestResolveDeploymentFailsClosed(t *testing.T) {
	path, fp, now := goldenFor(t)
	cases := map[string]deployFlags{
		"no fingerprint":     {ConfigPath: path},
		"wrong fingerprint":  {ConfigPath: path, Fingerprint: strings.Repeat("0", 64)},
		"missing file":       {ConfigPath: filepath.Join(t.TempDir(), "nope.json"), Fingerprint: fp},
		"conflicting server": {ConfigPath: path, Fingerprint: fp, Server: "https://other:9443"},
		"conflicting port":   {ConfigPath: path, Fingerprint: fp, EnrollPort: "1"},
		"conflicting ca":     {ConfigPath: path, Fingerprint: fp, CARootPath: "x.pem"},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			d, err := resolveDeployment(f, now)
			if err == nil {
				t.Fatalf("expected an error, got %+v", d)
			}
			if d.Server != "" || d.EnrollPort != "" || len(d.CARootPEM) != 0 {
				t.Fatalf("nothing may be returned on failure: %+v", d)
			}
		})
	}
	// An oversized file must be refused without reading it all.
	big := filepath.Join(t.TempDir(), "big.json")
	_ = os.WriteFile(big, bytes.Repeat([]byte("a"), deployconfig.MaxEnvelopeBytes+10), 0o600)
	if _, err := resolveDeployment(deployFlags{ConfigPath: big, Fingerprint: fp}, now); err == nil {
		t.Fatal("oversized config must fail")
	}
}

func TestPreflightCLIWithConfigRejectsUntrustedKeyDistinctCode(t *testing.T) {
	path, _, _ := goldenFor(t)
	var out bytes.Buffer
	code := runPreflightCLI(preflightCLIArgs{
		ConfigPath: path, ConfigFingerprint: strings.Repeat("0", 64), SecretStdin: true,
	}, strings.NewReader("s3cret-value\n"), &out)
	if code != preflight.CodeConfigRejected {
		t.Fatalf("code %d, want %d (%s)", code, preflight.CodeConfigRejected, out.String())
	}
	if strings.Contains(out.String(), "s3cret-value") {
		t.Fatal("secret leaked")
	}
}
