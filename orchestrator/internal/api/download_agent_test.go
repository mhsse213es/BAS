package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/ws"
)

func TestDownloadAgent_UnknownPlatform(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, "")
	req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/agents/download/not-a-real-platform", nil), "platform", "not-a-real-platform")
	rec := httptest.NewRecorder()
	h.DownloadAgent(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestDownloadAgent_KnownPlatformNoFilePresent(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, "")
	req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/agents/download/linux-amd64", nil), "platform", "linux-amd64")
	rec := httptest.NewRecorder()
	h.DownloadAgent(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (no binaries are checked into git — this is today's real dev/CI behavior)", rec.Code)
	}
}

func TestDownloadAgent_PathTraversalAttemptRejectedAsUnknownPlatform(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, "")
	traversalValues := []string{
		"../../../../etc/passwd",
		"..%2f..%2f..%2fetc%2fpasswd",
		"linux-amd64/../../secret",
	}
	for _, v := range traversalValues {
		t.Run(v, func(t *testing.T) {
			req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/agents/download/x", nil), "platform", v)
			rec := httptest.NewRecorder()
			h.DownloadAgent(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 (must resolve as unknown platform via the allowlist map, never reach os.Open with this value)", rec.Code)
			}
		})
	}
}

func TestDownloadAgent_WindowsLegacyPlatform_KnownButFileMissing(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, "")
	req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/agents/download/windows-legacy-amd64", nil), "platform", "windows-legacy-amd64")
	rec := httptest.NewRecorder()
	h.DownloadAgent(rec, req)
	// Platform IS recognized (not 404 "unknown platform") -- it's the
	// backing file that's absent in this bare-handler test, same distinction
	// TestDownloadAgent_KnownPlatformNoFilePresent already draws for
	// windows-amd64. A 404 here with "unknown platform" in the body would
	// mean the agentFiles map entry is missing; any other outcome
	// (including a different-flavored error about the missing file) proves
	// the map entry exists.
	if rec.Code == http.StatusNotFound && strings.Contains(rec.Body.String(), "unknown platform") {
		t.Fatalf("windows-legacy-amd64 not recognized as a platform: %s", rec.Body.String())
	}
}

func TestDownloadAgent_SuccessPath(t *testing.T) {
	entry, ok := agentFiles["linux-amd64"]
	if !ok {
		t.Fatal("agentFiles missing linux-amd64 — update this test if the allowlist changed")
	}
	dir := "./agents"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir fixture dir: %v", err)
	}
	fixturePath := filepath.Join(dir, entry.filename)
	content := []byte("fake-agent-binary-content-for-test")
	if err := os.WriteFile(fixturePath, content, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(fixturePath)
	})

	h := New(nil, ws.NewHub(), nil, "")
	req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/agents/download/linux-amd64", nil), "platform", "linux-amd64")
	rec := httptest.NewRecorder()
	h.DownloadAgent(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != entry.mimeType {
		t.Fatalf("Content-Type = %q, want %q", got, entry.mimeType)
	}
	wantDisposition := `attachment; filename="` + entry.filename + `"`
	if got := rec.Header().Get("Content-Disposition"); got != wantDisposition {
		t.Fatalf("Content-Disposition = %q, want %q", got, wantDisposition)
	}
	if rec.Body.String() != string(content) {
		t.Fatalf("body = %q, want %q", rec.Body.String(), string(content))
	}
}
