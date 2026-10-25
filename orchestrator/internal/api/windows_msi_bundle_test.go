package api

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/cmdsigning"
	"github.com/audspect/bas/internal/integrity"
)

func readZip(t *testing.T, b []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = string(data)
	}
	return out
}

const testFP = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestBuildMSIBundleContents(t *testing.T) {
	b, err := buildMSIBundle([]byte("MSIBYTES"), []byte(`{"version":1}`), testFP)
	if err != nil {
		t.Fatal(err)
	}
	files := readZip(t, b)
	for _, want := range []string{"AudspectAgent-x64.msi", "deployment.json", "install.cmd", "install.ps1", "README.txt"} {
		if _, ok := files[want]; !ok {
			t.Fatalf("missing %s in %v", want, zipNames(files))
		}
	}
	if files["AudspectAgent-x64.msi"] != "MSIBYTES" || files["deployment.json"] != `{"version":1}` {
		t.Fatal("msi or deployment.json bytes were altered")
	}
	ps := files["install.ps1"]
	if !strings.Contains(ps, testFP) {
		t.Fatal("install.ps1 must pass the fingerprint explicitly")
	}
	// The secret is read at run time into the child's environment, never written anywhere.
	if !strings.Contains(ps, "AUDSPECT_AGENT_SECRET") || !strings.Contains(ps, "-AsSecureString") {
		t.Fatal("install.ps1 must prompt for the secret securely and hand it over by environment")
	}
	if strings.Contains(ps, "AGENT_SECRET=") {
		t.Fatal("the secret must never be a msiexec command-line property")
	}
	if !strings.Contains(ps, "YES") {
		t.Fatal("install.ps1 must require the operator to confirm the fingerprint")
	}
	if !strings.Contains(files["README.txt"], testFP) {
		t.Fatal("README must show the fingerprint to compare with the dashboard")
	}
}

func TestBuildMSIBundleRejectsBadFingerprint(t *testing.T) {
	for _, fp := range []string{"", "abc", strings.Repeat("g", 64), testFP + "00", "x\" & calc & \""} {
		if _, err := buildMSIBundle([]byte("m"), []byte("{}"), fp); err == nil {
			t.Fatalf("fingerprint %q must be rejected (it is embedded in a script)", fp)
		}
	}
}

func zipNames(m map[string]string) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	return k
}

// msiFixture stages an agents dir with the MSI and a manifest line for it.
func msiFixture(t *testing.T, content string, manifestHash string) *Handler {
	t.Helper()
	dir := t.TempDir()
	if content != "" {
		if err := os.WriteFile(filepath.Join(dir, windowsMSIFile), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	manifest := filepath.Join(dir, "BINARIES.sha256")
	lines := "deadbeef  something-else\n"
	if manifestHash != "" {
		lines += manifestHash + "  " + windowsMSIFile + "\n"
	}
	if err := os.WriteFile(manifest, []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := agentArtifactDir
	agentArtifactDir = dir
	t.Cleanup(func() { agentArtifactDir = prev })
	sk, err := cmdsigning.LoadOrGenerateSigningKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := (&Handler{agentSecret: "TOPSECRET-AGENT-VALUE"}).WithAdvertisedPorts(9443, 9444).WithCommandSigningKey(sk)
	return h.WithManifest(integrity.LoadManifest(manifest))
}

func sha(s string) string { x := sha256.Sum256([]byte(s)); return hex.EncodeToString(x[:]) }

func TestServeWindowsMSI_ServesVerifiedBundleWithoutSecret(t *testing.T) {
	h := msiFixture(t, "REAL-MSI", sha("REAL-MSI"))
	rec := httptest.NewRecorder()
	h.serveWindowsMSI(rec, httptest.NewRequest(http.MethodGet, "https://bas.example.com:8443/api/agents/download/windows-amd64-msi", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/zip" || !strings.Contains(rec.Header().Get("Content-Disposition"), "AudspectAgent-x64.zip") {
		t.Fatalf("headers: %v", rec.Header())
	}
	if strings.Contains(rec.Body.String(), "TOPSECRET-AGENT-VALUE") {
		t.Fatal("the agent secret must not be in the bundle")
	}
	files := readZip(t, rec.Body.Bytes())
	if files["AudspectAgent-x64.msi"] != "REAL-MSI" {
		t.Fatal("the MSI in the bundle is not the verified artifact")
	}
	if !strings.Contains(files["deployment.json"], `"signature"`) || !strings.Contains(files["install.ps1"], "-ConfigFingerprint") && !strings.Contains(files["install.ps1"], "CONFIG_FINGERPRINT") {
		t.Fatal("bundle is missing the signed config or the fingerprint wiring")
	}
}

func TestServeWindowsMSI_RefusesTamperedOrUnlistedOrMissing(t *testing.T) {
	cases := map[string]struct {
		content, hash string
		want          int
	}{
		"hash mismatch":   {"TAMPERED", sha("REAL-MSI"), http.StatusInternalServerError},
		"not in manifest": {"REAL-MSI", "", http.StatusInternalServerError},
		"file missing":    {"", sha("REAL-MSI"), http.StatusNotFound},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := msiFixture(t, c.content, c.hash)
			rec := httptest.NewRecorder()
			h.serveWindowsMSI(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
			if rec.Code != c.want {
				t.Fatalf("status %d, want %d: %s", rec.Code, c.want, rec.Body.String())
			}
			if strings.Contains(rec.Header().Get("Content-Type"), "zip") {
				t.Fatal("nothing may be served")
			}
		})
	}
}

func TestServeWindowsMSI_RequiresManifestAndSigningKey(t *testing.T) {
	h := msiFixture(t, "REAL-MSI", sha("REAL-MSI"))
	noManifest := (&Handler{}).WithAdvertisedPorts(9443, 9444).WithCommandSigningKey(h.signingKey)
	rec := httptest.NewRecorder()
	noManifest.serveWindowsMSI(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no manifest: status %d, want 503 (the MSI is never served unverified)", rec.Code)
	}
	noKey := (&Handler{}).WithManifest(h.manifest)
	rec = httptest.NewRecorder()
	noKey.serveWindowsMSI(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no signing key: status %d, want 503", rec.Code)
	}
}
