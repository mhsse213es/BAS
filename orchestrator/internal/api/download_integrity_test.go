package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/integrity"
)

// withAgentsDir points ./agents at a temp directory for one test, since
// DownloadAgent resolves the binary relative to the working directory.
func withAgentsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
	if err := os.MkdirAll("agents", 0o755); err != nil {
		t.Fatalf("mkdir agents: %v", err)
	}
	return dir
}

// writeAgentAndManifest writes a fake agent binary plus a BINARIES.sha256
// listing the hash of manifestContent (which may differ from what is on disk,
// to simulate tampering).
func writeAgentAndManifest(t *testing.T, onDisk, manifestContent string) *integrity.Manifest {
	t.Helper()
	const name = "bas-agent-linux-amd64"
	if err := os.WriteFile(filepath.Join("agents", name), []byte(onDisk), 0o755); err != nil {
		t.Fatalf("write agent: %v", err)
	}
	sum := sha256.Sum256([]byte(manifestContent))
	line := hex.EncodeToString(sum[:]) + "  " + name + "\n"
	mpath := filepath.Join("agents", "BINARIES.sha256")
	if err := os.WriteFile(mpath, []byte(line), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return integrity.LoadManifest(mpath)
}

func downloadLinuxAgent(h *Handler) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.DownloadAgent(rec, withURLParam(
		httptest.NewRequest(http.MethodGet, "/api/agents/download/linux-amd64", nil),
		"platform", "linux-amd64"))
	return rec
}

// A binary that does not match the SIGNED manifest must never be handed to an
// endpoint.
//
// This is the supply-chain case: an attacker with write access to ./agents
// swaps a binary, and every endpoint that downloads afterwards installs it.
// Nothing caught it before — the manifest itself was untouched so no tamper
// event fired, and the `trusted` flag on enrol/heartbeat is derived from a hash
// the AGENT self-reports, which a malicious agent simply lies about.
func TestDownloadAgent_RefusesTamperedBinary(t *testing.T) {
	withAgentsDir(t)
	m := writeAgentAndManifest(t, "TAMPERED-PAYLOAD", "legitimate-agent-bytes")

	h := (&Handler{}).WithManifest(m)
	rec := downloadLinuxAgent(h)

	if rec.Code == http.StatusOK {
		t.Fatalf("a tampered binary was served with 200; body=%q", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "TAMPERED-PAYLOAD") {
		t.Error("tampered bytes leaked to the client")
	}
}

// The legitimate binary must still download normally.
func TestDownloadAgent_ServesVerifiedBinary(t *testing.T) {
	withAgentsDir(t)
	const good = "legitimate-agent-bytes"
	m := writeAgentAndManifest(t, good, good)

	h := (&Handler{}).WithManifest(m)
	rec := downloadLinuxAgent(h)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != good {
		t.Errorf("body = %q, want the verified binary bytes unchanged", rec.Body.String())
	}
}

// A binary absent from the manifest must be refused rather than served
// unverified — otherwise adding a file to ./agents would bypass the check.
func TestDownloadAgent_RefusesBinaryMissingFromManifest(t *testing.T) {
	withAgentsDir(t)
	// Manifest lists a different filename entirely.
	if err := os.WriteFile(filepath.Join("agents", "bas-agent-linux-amd64"), []byte("x"), 0o755); err != nil {
		t.Fatalf("write agent: %v", err)
	}
	mpath := filepath.Join("agents", "BINARIES.sha256")
	if err := os.WriteFile(mpath, []byte("abc123  some-other-file\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	h := (&Handler{}).WithManifest(integrity.LoadManifest(mpath))
	if rec := downloadLinuxAgent(h); rec.Code == http.StatusOK {
		t.Error("an unlisted binary was served; it must be refused")
	}
}

// With no manifest loaded (dev build), downloads must still work — verification
// is a hardening layer, not a hard dependency.
func TestDownloadAgent_NoManifestStillServes(t *testing.T) {
	withAgentsDir(t)
	if err := os.WriteFile(filepath.Join("agents", "bas-agent-linux-amd64"), []byte("dev-build"), 0o755); err != nil {
		t.Fatalf("write agent: %v", err)
	}

	h := (&Handler{}).WithManifest(integrity.LoadManifest(filepath.Join("agents", "does-not-exist")))
	rec := downloadLinuxAgent(h)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 when no manifest is present", rec.Code)
	}
}
