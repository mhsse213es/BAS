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

// writeAllAgentFixturesAndManifest writes a real fixture file for every
// agentFiles entry and a manifest that correctly lists all of them -- the
// shape production's BINARIES.sha256 has once all 11 download-endpoint
// artifacts are covered. Content is "content-of-<filename>" per file, so
// a test can assert on exactly which file it got back.
func writeAllAgentFixturesAndManifest(t *testing.T) *integrity.Manifest {
	t.Helper()
	var lines []string
	for _, entry := range agentFiles {
		content := "content-of-" + entry.filename
		if err := os.WriteFile(filepath.Join("agents", entry.filename), []byte(content), 0o755); err != nil {
			t.Fatalf("write %s: %v", entry.filename, err)
		}
		sum := sha256.Sum256([]byte(content))
		lines = append(lines, hex.EncodeToString(sum[:])+"  "+entry.filename)
	}
	mpath := filepath.Join("agents", "BINARIES.sha256")
	if err := os.WriteFile(mpath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return integrity.LoadManifest(mpath)
}

func downloadPlatform(h *Handler, platform string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.DownloadAgent(rec, withURLParam(
		httptest.NewRequest(http.MethodGet, "/api/agents/download/"+platform, nil),
		"platform", platform))
	return rec
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

// The C3 regression: 5 of the 11 platforms DownloadAgent can serve were
// permanently refused in production because BINARIES.sha256 never listed
// them, even though this refusal logic was already correct. This test
// proves every platform serves correctly once the manifest lists all 11.
func TestDownloadAgent_AllPlatformsServedAndVerified(t *testing.T) {
	withAgentsDir(t)
	h := (&Handler{}).WithManifest(writeAllAgentFixturesAndManifest(t))

	for platform, entry := range agentFiles {
		platform, entry := platform, entry
		t.Run(platform, func(t *testing.T) {
			rec := downloadPlatform(h, platform)
			if rec.Code != http.StatusOK {
				t.Fatalf("platform %q: status = %d, want 200; body=%q", platform, rec.Code, rec.Body.String())
			}
			want := "content-of-" + entry.filename
			if rec.Body.String() != want {
				t.Errorf("platform %q: body = %q, want %q", platform, rec.Body.String(), want)
			}
		})
	}
}

// Removing one platform's file from the manifest must refuse only that
// platform, leaving the other 10 unaffected -- not a fail-open-the-whole-set
// bug, and not a refuse-everything-when-one-is-missing bug.
func TestDownloadAgent_OnePlatformMissingFromManifestRefusesOnlyThatOne(t *testing.T) {
	withAgentsDir(t)
	writeAllAgentFixturesAndManifest(t)

	// linux-amd64-deb is one of the 5 platforms C3 actually found broken
	// in production -- a regression here is literally the defect recurring.
	const missingPlatform = "linux-amd64-deb"
	missingFile := agentFiles[missingPlatform].filename
	mpath := filepath.Join("agents", "BINARIES.sha256")
	content, err := os.ReadFile(mpath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var kept []string
	for _, line := range strings.Split(strings.TrimRight(string(content), "\n"), "\n") {
		if !strings.HasSuffix(line, "  "+missingFile) {
			kept = append(kept, line)
		}
	}
	if err := os.WriteFile(mpath, []byte(strings.Join(kept, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("rewrite manifest: %v", err)
	}

	h := (&Handler{}).WithManifest(integrity.LoadManifest(mpath))
	for platform := range agentFiles {
		rec := downloadPlatform(h, platform)
		if platform == missingPlatform {
			if rec.Code == http.StatusOK {
				t.Errorf("platform %q: served despite being absent from the manifest", platform)
			}
			continue
		}
		if rec.Code != http.StatusOK {
			t.Errorf("platform %q: status = %d, want 200 (must be unaffected by %q's absence)", platform, rec.Code, missingPlatform)
		}
	}
}

// TestBinariesManifestDockerfileCoversAllAgentFiles parses the real
// orchestrator/Dockerfile's binaries-manifest stage and asserts its
// sha256sum argument list covers every agentFiles entry. The two tests
// above build their own manifest FROM agentFiles, so they only prove the
// handler serves whatever is listed -- they can never catch agentFiles
// and the Dockerfile drifting apart, which is exactly how C3 happened (5
// platforms were served but never reached BINARIES.sha256, and nothing
// caught it). This test reads the actual build input instead, so adding
// a 12th platform to agentFiles without a matching Dockerfile entry
// fails here.
func TestBinariesManifestDockerfileCoversAllAgentFiles(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatalf("read orchestrator/Dockerfile: %v", err)
	}
	lines := strings.Split(string(data), "\n")

	start := -1
	for i, line := range lines {
		if strings.Contains(line, "sha256sum") {
			start = i
			break
		}
	}
	if start == -1 {
		t.Fatal("orchestrator/Dockerfile has no sha256sum command -- has the binaries-manifest stage been renamed or restructured? Update this test's parsing to match.")
	}

	listed := map[string]bool{}
	for i := start; i < len(lines); i++ {
		line := lines[i]
		done := strings.Contains(line, "> /agents/BINARIES.sha256")
		line = strings.ReplaceAll(line, "> /agents/BINARIES.sha256", "")
		line = strings.ReplaceAll(line, "\\", "")
		for _, tok := range strings.Fields(line) {
			switch tok {
			case "RUN", "cd", "/agents", "&&", "sha256sum":
				continue
			}
			listed[tok] = true
		}
		if done {
			break
		}
	}

	for _, entry := range agentFiles {
		if !listed[entry.filename] {
			t.Errorf("orchestrator/Dockerfile's binaries-manifest sha256sum command does not list %q -- "+
				"agentFiles can serve this platform but BINARIES.sha256 would never cover it, "+
				"which is exactly the C3 defect recurring", entry.filename)
		}
	}
}

// TestDockerfileAgentBuilderStageObfuscatesWithGarble guards against the
// agent-builder stage silently regressing to a plain `go build` (as it
// did for ~5 months, 2026-05-27 to 2026-10-01, on a now-stale "x/sys
// assembly incompatible with garble" assumption -- see D2's design doc).
// It pairs every `-o /agents/bas-agent-...` output in the stage with an
// immediately-preceding, correctly-scoped garble invocation, rather than
// checking a fixed count, so a future platform added to this stage
// without obfuscation fails here too.
func TestDockerfileAgentBuilderStageObfuscatesWithGarble(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatalf("read orchestrator/Dockerfile: %v", err)
	}
	content := string(data)

	start := strings.Index(content, "AS agent-builder")
	if start == -1 {
		t.Fatal("orchestrator/Dockerfile has no 'AS agent-builder' stage -- has it been renamed? Update this test's parsing to match.")
	}
	end := strings.Index(content, "AS agent-legacy-builder")
	if end == -1 || end < start {
		t.Fatal("orchestrator/Dockerfile has no 'AS agent-legacy-builder' stage after agent-builder -- has stage order changed? Update this test's parsing to match.")
	}
	stage := content[start:end]

	// Checked against the whole file, not the stage-scoped substring: this
	// stale comment sits on the line immediately ABOVE "FROM ... AS
	// agent-builder", so it precedes (and is excluded by) `start`, which is
	// indexed from "AS agent-builder" itself. The string is unique to this
	// one historical comment in this file, so a whole-file check carries no
	// risk of a false match elsewhere.
	if strings.Contains(content, "x/sys assembly is incompatible with garble") {
		t.Error("orchestrator/Dockerfile still carries the stale x/sys-incompatibility comment -- D2's spike found this claim no longer holds for the pinned garble version; remove it")
	}

	for _, line := range strings.Split(stage, "\n") {
		if !strings.Contains(line, "-o /agents/bas-agent-") {
			continue
		}
		// Each build line is independent (joined by "&&" across the RUN
		// block's backslash continuations), so the garble invocation must
		// appear on the SAME line as its own "-o" output, not merely
		// somewhere earlier in the stage.
		if !strings.Contains(line, "garble -literals build") {
			t.Errorf("agent-builder line producing a bas-agent binary is not garble-wrapped: %q", strings.TrimSpace(line))
		}
		if !strings.Contains(line, "GOGARBLE='audspect/*'") {
			t.Errorf("agent-builder line producing a bas-agent binary is missing the GOGARBLE='audspect/*' scope: %q", strings.TrimSpace(line))
		}
	}

	if !strings.Contains(stage, "go install mvdan.cc/garble@v0.17.0") {
		t.Error("agent-builder stage does not install garble v0.17.0 -- each Dockerfile stage is independent and does not inherit the orchestrator builder stage's install")
	}
}

// TestDockerfileAgentLegacyBuilderStageObfuscatesWithGarble mirrors
// TestDockerfileAgentBuilderStageObfuscatesWithGarble for the legacy
// Windows agent, which needs a different garble pin (v0.10.1) and a
// different base image (golang:1.20.14-alpine, not golang:1.26-alpine +
// GOTOOLCHAIN=go1.20.14 -- the latter downloads go1.20.14 as a module
// toolchain, which breaks garble's internal `go list` call under any
// pre-GOTOOLCHAIN-era garble version; see D2's design doc Gap 2).
func TestDockerfileAgentLegacyBuilderStageObfuscatesWithGarble(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatalf("read orchestrator/Dockerfile: %v", err)
	}
	content := string(data)

	start := strings.Index(content, "AS agent-legacy-builder")
	if start == -1 {
		t.Fatal("orchestrator/Dockerfile has no 'AS agent-legacy-builder' stage -- has it been renamed? Update this test's parsing to match.")
	}
	end := strings.Index(content, "AS packager")
	if end == -1 || end < start {
		t.Fatal("orchestrator/Dockerfile has no 'AS packager' stage after agent-legacy-builder -- has stage order changed? Update this test's parsing to match.")
	}
	// Widen to the start of the FROM line itself, not just "AS
	// agent-legacy-builder": the base image name (golang:1.20.14-alpine)
	// precedes "AS agent-legacy-builder" on that same line, so anchoring
	// exactly at the match would exclude it from `stage` entirely.
	lineStart := strings.LastIndex(content[:start], "\n") + 1
	stage := content[lineStart:end]

	if !strings.Contains(stage, "golang:1.20.14-alpine") {
		t.Error("agent-legacy-builder no longer uses the native golang:1.20.14-alpine base image -- this is required to avoid the GOTOOLCHAIN module-download panic with garble v0.10.1 (D2 Gap 2)")
	}
	if strings.Contains(stage, "ENV GOTOOLCHAIN=go1.20.14") {
		t.Error("agent-legacy-builder still sets ENV GOTOOLCHAIN=go1.20.14 -- no longer needed once the base image is natively go1.20.14, and reintroduces the module-toolchain-download panic (D2 Gap 2) if left in")
	}
	if strings.Contains(stage, "gcompat") {
		t.Error("agent-legacy-builder still installs gcompat -- that shim was only needed for the glibc-linked auto-downloaded toolchain; golang:1.20.14-alpine's own Go binary is already musl-native")
	}
	if !strings.Contains(stage, "git") || !strings.Contains(stage, "zip") {
		t.Error("agent-legacy-builder's apk add line is missing git or zip -- these are still required (git for go mod download, zip for the setup.zip artifact) even though gcompat is removed")
	}

	// Matched as a block, not a single split line: unlike agent-builder's
	// multi-platform &&-chain (where each platform's whole command,
	// GOGARBLE included, fits on one line), this stage builds only one
	// platform, so the Dockerfile reasonably splits env vars and the
	// garble invocation across a backslash line continuation.
	const buildCmdStart = "CGO_ENABLED=0 GOOS=windows GOARCH=amd64"
	const buildCmdEnd = "-o /agents-legacy/bas-agent-windows-legacy-amd64.exe"
	cmdStart := strings.Index(stage, buildCmdStart)
	cmdEnd := strings.Index(stage, buildCmdEnd)
	if cmdStart == -1 || cmdEnd == -1 || cmdEnd < cmdStart {
		t.Error("agent-legacy-builder has no recognizable CGO_ENABLED=0 GOOS=windows GOARCH=amd64 ... -o /agents-legacy/bas-agent-windows-legacy-amd64.exe build command")
	} else {
		buildCmd := stage[cmdStart : cmdEnd+len(buildCmdEnd)]
		if !strings.Contains(buildCmd, "garble -literals build") {
			t.Errorf("agent-legacy-builder's agent build command is not garble-wrapped: %q", buildCmd)
		}
		if !strings.Contains(buildCmd, "GOGARBLE='audspect/*'") {
			t.Errorf("agent-legacy-builder's agent build command is missing the GOGARBLE='audspect/*' scope: %q", buildCmd)
		}
	}

	if !strings.Contains(stage, "go install mvdan.cc/garble@v0.10.1") {
		t.Error("agent-legacy-builder stage does not install garble v0.10.1 -- v0.17.0 (the modern pin) does not install under a go1.20 toolchain")
	}
}
