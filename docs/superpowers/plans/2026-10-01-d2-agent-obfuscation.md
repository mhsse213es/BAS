# D2 — Agent Binary Obfuscation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Obfuscate every customer-shipped agent artifact (5 modern platforms + legacy Windows) with garble across all three production build paths, without breaking C4's build-once-sign-once invariant.

**Architecture:** Garble is inserted as the first step of each build path's existing, single authoritative build invocation per artifact — never a second, independent build. Modern artifacts use garble v0.17.0 (already pinned for the orchestrator); the legacy Windows agent uses garble v0.10.1 (the newest version that still installs under a pre-GOTOOLCHAIN-era go1.20 toolchain). Both are scoped with `GOGARBLE='audspect/*'` so third-party dependencies (`golang.org/x/sys`, `windigo`, `sspi`, `gorilla/websocket`) are never touched.

**Tech Stack:** Go 1.26.8 (host, already upgraded), Go 1.26.7 (`golang:1.26-alpine`), Go 1.20.14 (legacy, dedicated real install — not module-toolchain), garble v0.17.0 / v0.10.1, Docker, PowerShell (Windows release build), bash (Linux compose build).

**Spec:** `docs/superpowers/specs/2026-10-01-d2-agent-obfuscation-design.md`

## Global Constraints

- Agent obfuscation is scoped `GOGARBLE='audspect/*'` — distinct from the orchestrator's own `GOGARBLE='github.com/audspect/*'` (different module path: `agent/go.mod` and `agent-legacy/go.mod` both declare `module audspect/...`, no `github.com/` prefix).
- Modern agent (5 platforms + Windows installer-embedded copy): garble **v0.17.0**, same pin as the orchestrator's `builder` stage.
- Legacy Windows agent: garble **v0.10.1** — the newest version confirmed (by spike) to install and build successfully under a real (non-module-toolchain) go1.20.14 GOROOT.
- Default to `-literals` alone. Do not add `-tiny` anywhere in this plan — validated to work during the spike, but not adopted without a specific justification (none exists yet).
- The legacy agent's toolchain version does not change. It stays exactly go1.20.14. Only *how* that version is reached changes (a real GOROOT install, never an auto-downloaded module toolchain).
- No signing-mechanism changes (GPG, Authenticode, RSA-signed manifest) — this plan only changes what bytes exist before those existing mechanisms run.
- `packaging/build.sh`'s artifact scope does not expand — it still builds only the 5 modern platforms it builds today (no legacy agent, no Linux packages added to it).
- Obfuscation must precede C4's single build-then-sign step for the modern Windows agent. `windows-build.ps1`'s existing byte-equality assertion (`installer\bas_agent.exe` vs. `bas-agent-windows-amd64.exe`, ~line 383-386) must still pass unmodified after this plan.
- The installer's *own* source (producing `Audspect_Agent.exe` / `BASAgent-Setup-$Version.exe`) is **not** obfuscated — out of D2's scope. It has no Audspect detection/scenario logic; only the agent bytes it embeds (already garbled) matter.

## Review Focus

1. **A future 6th `agentFiles` platform added to the Dockerfile without its build line being garble-wrapped.** C3's existing `TestBinariesManifestDockerfileCoversAllAgentFiles` only checks filename coverage in the manifest, not whether each build line is garble-wrapped. Task 1/2's new test structurally pairs every `-o /agents/...` occurrence in the agent stages with an immediately-preceding `garble -literals build`, so it scales to a future platform rather than checking a fixed count of 5.
2. **`GOGARBLE` scope silently regressing to unscoped/global in a future edit**, re-exposing `golang.org/x/sys` (or `windigo`/`sspi`) to obfuscation and reintroducing a reflection/assembly breakage like the one the orchestrator already hit with `fpdf`. Task 1/2's test asserts the exact scoped string `GOGARBLE='audspect/*'` is present on every build line, not just that `garble` appears somewhere in the stage.
3. **The dedicated legacy GOROOT silently replaced by a module-toolchain auto-download** that resolves to the same version string (`go1.20.14`) but is garble-incompatible (Gap 2 from the spec). `windows-build.ps1`'s existing version-string assertion alone cannot distinguish these. Task 5 adds a GOROOT-path assertion alongside the existing version check.
4. **A customer/release build running on a host that is missing the dedicated legacy GOROOT.** Without a clear prerequisite check, this would silently fall through to the module-toolchain auto-download and die on Gap 2's confusing `go list` panic, far from its real cause. Task 5 adds an explicit, clear prerequisite failure before that can happen.
5. **Removing `gcompat` from `agent-legacy-builder`'s `apk add` line accidentally also drops `git` or `zip`** (all three are on one line today, an easy copy-paste mistake). Task 2's functional verification explicitly checks that the stage still produces both the `.exe` and the `.zip` setup artifact, not just the `.exe`.

---

### Task 1: `orchestrator/Dockerfile` — modern agent obfuscation

**Files:**
- Modify: `orchestrator/Dockerfile:23-53`
- Test: `orchestrator/internal/api/download_integrity_test.go` (append)

**Interfaces:**
- Consumes: nothing from another task.
- Produces: `agent-builder` stage's 5 raw binaries + the `bas-agent-windows-amd64-setup.zip` are garble-obfuscated. Later Dockerfile stages (`packager`, `binaries-manifest`, final image) consume these same `COPY --from=agent-builder ...` paths unchanged — this task does not touch any `COPY --from=` line.

- [ ] **Step 1: Write the failing structural test**

Append to `orchestrator/internal/api/download_integrity_test.go`:

```go
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

	if strings.Contains(stage, "x/sys assembly is incompatible with garble") {
		t.Error("agent-builder stage still carries the stale x/sys-incompatibility comment -- D2's spike found this claim no longer holds for the pinned garble version; remove it")
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestDockerfileAgentBuilderStageObfuscatesWithGarble -v`
Expected: FAIL — every `-o /agents/bas-agent-...` line reports missing `garble -literals build`, and the stale-comment check also fails (comment is still present).

- [ ] **Step 3: Edit the Dockerfile**

Replace `orchestrator/Dockerfile:23-53`:

```dockerfile
# ── Agent + Installer Builder ────────────────────────────────────────────────
# Plain stripped build: golang.org/x/sys assembly is incompatible with garble.
FROM golang:1.26-alpine AS agent-builder
RUN apk add --no-cache git
WORKDIR /agent
COPY agent/go.mod agent/go.sum ./
RUN go mod download
COPY agent/ .
# All platform binaries
RUN CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /agents/bas-agent-linux-amd64   . && \
    CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o /agents/bas-agent-linux-arm64   . && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /agents/bas-agent-windows-amd64.exe . && \
    CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /agents/bas-agent-darwin-amd64  . && \
    CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o /agents/bas-agent-darwin-arm64  .
# BINARIES.sha256 is generated later, in the binaries-manifest stage, once
# both this stage's and agent-legacy-builder's binaries exist to hash together.
# Windows GUI installer — embeds the single Windows agent binary built above.
# The agent contains the tray + status-window UI (run via --tray / --status-window),
# so there is no separate tray executable to build.
WORKDIR /installer
COPY installer/go.mod installer/go.sum ./
RUN go mod download
COPY installer/ .
RUN apk add --no-cache zip && \
    cp /agents/bas-agent-windows-amd64.exe ./bas_agent.exe && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -H windowsgui" \
    -o /agents/Audspect_Agent.exe . && \
    EXE_MB=$(( $(stat -c%s /agents/Audspect_Agent.exe) / 1024 / 1024 )) && \
    if [ "$EXE_MB" -gt 25 ]; then echo "Audspect_Agent.exe is ${EXE_MB}MB, expected ~14MB - something is being embedded that shouldn't be" >&2; exit 1; fi && \
    cd /agents && zip -q bas-agent-windows-amd64-setup.zip Audspect_Agent.exe && rm Audspect_Agent.exe
```

with:

```dockerfile
# ── Agent + Installer Builder ────────────────────────────────────────────────
FROM golang:1.26-alpine AS agent-builder
# Pinned to the same v0.17.0 used by the orchestrator's own builder stage
# below -- v0.18.0 requires go >= 1.27, which this image's go1.26.7 cannot
# satisfy under GOTOOLCHAIN=local (see that stage's comment for the full
# rationale). Each Dockerfile stage is independent, so this stage needs
# its own install -- it cannot reuse the builder stage's.
RUN apk add --no-cache git && \
    go install mvdan.cc/garble@v0.17.0
WORKDIR /agent
COPY agent/go.mod agent/go.sum ./
RUN go mod download
COPY agent/ .
# GOGARBLE scopes obfuscation to our own module only -- golang.org/x/sys,
# windigo, sspi, and gorilla/websocket stay un-obfuscated, same reasoning
# as the orchestrator's own GOGARBLE scoping below (a third-party
# dependency's reflection/assembly code is never garble's business to
# rewrite). All platform binaries.
RUN CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 GOGARBLE='audspect/*' garble -literals build -ldflags="-s -w" -o /agents/bas-agent-linux-amd64   . && \
    CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 GOGARBLE='audspect/*' garble -literals build -ldflags="-s -w" -o /agents/bas-agent-linux-arm64   . && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOGARBLE='audspect/*' garble -literals build -ldflags="-s -w" -o /agents/bas-agent-windows-amd64.exe . && \
    CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 GOGARBLE='audspect/*' garble -literals build -ldflags="-s -w" -o /agents/bas-agent-darwin-amd64  . && \
    CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 GOGARBLE='audspect/*' garble -literals build -ldflags="-s -w" -o /agents/bas-agent-darwin-arm64  .
# BINARIES.sha256 is generated later, in the binaries-manifest stage, once
# both this stage's and agent-legacy-builder's binaries exist to hash together.
# Windows GUI installer — embeds the single Windows agent binary built above
# (already garbled; the installer's own source is out of D2's scope, since
# it has no Audspect detection/scenario logic, only unpacking and
# service-install plumbing). The agent contains the tray + status-window UI
# (run via --tray / --status-window), so there is no separate tray
# executable to build.
WORKDIR /installer
COPY installer/go.mod installer/go.sum ./
RUN go mod download
COPY installer/ .
RUN apk add --no-cache zip && \
    cp /agents/bas-agent-windows-amd64.exe ./bas_agent.exe && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -H windowsgui" \
    -o /agents/Audspect_Agent.exe . && \
    EXE_MB=$(( $(stat -c%s /agents/Audspect_Agent.exe) / 1024 / 1024 )) && \
    if [ "$EXE_MB" -gt 25 ]; then echo "Audspect_Agent.exe is ${EXE_MB}MB, expected ~14MB - something is being embedded that shouldn't be" >&2; exit 1; fi && \
    cd /agents && zip -q bas-agent-windows-amd64-setup.zip Audspect_Agent.exe && rm Audspect_Agent.exe
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestDockerfileAgentBuilderStageObfuscatesWithGarble -v`
Expected: PASS

- [ ] **Step 5: Real build verification (Tier B — proves obfuscation actually happens, not just that the text matches)**

Run (from repo root):
```bash
docker build -q --target agent-builder -t d2-task1-verify -f orchestrator/Dockerfile .
docker create --name d2-task1-extract d2-task1-verify
docker cp d2-task1-extract:/agents/bas-agent-linux-amd64 /tmp/d2-task1-linux-amd64
docker cp d2-task1-extract:/agents/bas-agent-windows-amd64-setup.zip /tmp/d2-task1-setup.zip
docker rm d2-task1-extract
chmod +x /tmp/d2-task1-linux-amd64
echo "plaintext-string-count (expect 0):"
strings /tmp/d2-task1-linux-amd64 | grep -c "agent log file" || true
echo "run smoke test (expect usage output, exit 0):"
/tmp/d2-task1-linux-amd64 -h
echo "exit=$?"
unzip -l /tmp/d2-task1-setup.zip
rm -f /tmp/d2-task1-linux-amd64 /tmp/d2-task1-setup.zip
docker rmi d2-task1-verify
```
Expected: `plaintext-string-count` is `0` (the string `"agent log file"` — a literal from `agent/main.go`'s log setup — is encrypted by `-literals` and must not appear verbatim; a plain, non-garbled build would report `1`). The binary runs and prints the standard flag-usage text with exit 0. `unzip -l` lists `Audspect_Agent.exe` inside the zip without error.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/Dockerfile orchestrator/internal/api/download_integrity_test.go
git commit -m "fix(agent): obfuscate modern agent-builder stage with garble (D2)

The 'x/sys assembly incompatible with garble' blocker is stale -- it was
true for garble v0.12.1 (2026-05-27); the current pin (v0.17.0, moved
for Go 1.26 support) builds all 5 platforms clean, verified by a real
docker build + strings diff + run smoke test.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
```

---

### Task 2: `orchestrator/Dockerfile` — legacy agent obfuscation

**Files:**
- Modify: `orchestrator/Dockerfile:55-83`
- Test: `orchestrator/internal/api/download_integrity_test.go` (append)

**Interfaces:**
- Consumes: nothing from Task 1 (independent Dockerfile stage).
- Produces: `agent-legacy-builder` stage's `.exe` and `.zip` are garble-obfuscated, base image changed to `golang:1.20.14-alpine`. `binaries-manifest`'s existing `COPY --from=agent-legacy-builder ...` lines (Dockerfile ~110-112) are unchanged — this task does not touch them.

- [ ] **Step 1: Write the failing structural test**

Append to `orchestrator/internal/api/download_integrity_test.go` (same file as Task 1's test):

```go
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
	stage := content[start:end]

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

	for _, line := range strings.Split(stage, "\n") {
		if !strings.Contains(line, "-o /agents-legacy/bas-agent-windows-legacy-amd64.exe") {
			continue
		}
		if !strings.Contains(line, "garble -literals build") {
			t.Errorf("agent-legacy-builder's agent build line is not garble-wrapped: %q", strings.TrimSpace(line))
		}
		if !strings.Contains(line, "GOGARBLE='audspect/*'") {
			t.Errorf("agent-legacy-builder's agent build line is missing the GOGARBLE='audspect/*' scope: %q", strings.TrimSpace(line))
		}
	}

	if !strings.Contains(stage, "go install mvdan.cc/garble@v0.10.1") {
		t.Error("agent-legacy-builder stage does not install garble v0.10.1 -- v0.17.0 (the modern pin) does not install under a go1.20 toolchain")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestDockerfileAgentLegacyBuilderStageObfuscatesWithGarble -v`
Expected: FAIL — base image check fails (still `golang:1.26-alpine`), `GOTOOLCHAIN`/`gcompat` checks fail (still present), garble-wrap check fails (still plain `go build`).

- [ ] **Step 3: Edit the Dockerfile**

Replace `orchestrator/Dockerfile:55-83`:

```dockerfile
# ── Legacy Windows Agent Builder ─────────────────────────────────────────────
# Separately toolchained via GOTOOLCHAIN=go1.20.14 (go.mod itself stays at a
# bare `go 1.20` -- the `toolchain` directive predates Go 1.21 and go1.20.14
# can't parse it). go1.20.14 is the last Go release supporting Windows 7
# SP1/8/8.1/Server 2008 R2-2012 R2. See
# docs/superpowers/specs/2026-08-18-legacy-windows-agent-phase1-design.md.
FROM golang:1.26-alpine AS agent-legacy-builder
# gcompat: Go's GOTOOLCHAIN auto-download fetches a glibc-linked go1.20.14
# binary from go.dev -- Alpine's musl libc can't exec it without this shim
# ("go: exec go1.20.14: no such file or directory" without it, a confusing
# error for what's actually a missing dynamic linker).
RUN apk add --no-cache git zip gcompat
WORKDIR /agent-legacy
COPY agent-legacy/go.mod agent-legacy/go.sum ./
ENV GOTOOLCHAIN=go1.20.14
RUN go mod download
COPY agent-legacy/ .
# Hard assertion: fail the image build outright if the resolved toolchain
# isn't exactly go1.20.14, rather than silently shipping a binary built
# against a newer runtime than the legacy OSes this agent targets support.
RUN GOVERSION=$(go version) && \
    echo "Resolved toolchain: $GOVERSION" && \
    case "$GOVERSION" in \
      *go1.20.14*) ;; \
      *) echo "FATAL: expected go1.20.14, got: $GOVERSION" >&2; exit 1 ;; \
    esac
RUN CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /agents-legacy/bas-agent-windows-legacy-amd64.exe .
RUN cd /agents-legacy && zip -q bas-agent-windows-legacy-amd64-setup.zip bas-agent-windows-legacy-amd64.exe
```

with:

```dockerfile
# ── Legacy Windows Agent Builder ─────────────────────────────────────────────
# go1.20.14 is the last Go release supporting Windows 7 SP1/8/8.1/Server
# 2008 R2-2012 R2. See
# docs/superpowers/specs/2026-08-18-legacy-windows-agent-phase1-design.md.
# Uses golang:1.20.14-alpine directly rather than GOTOOLCHAIN=go1.20.14 on
# top of a newer base image: the latter downloads go1.20.14 as a *module*
# toolchain under GOMODCACHE, and garble v0.10.1 (the newest version that
# still installs under a go1.20 toolchain -- it predates Go's
# module-toolchain feature entirely) panics parsing `go list -json`
# output because of the "toolchain ... invoked to provide ..." banner
# that mechanism prints. A native GOROOT install has no such banner.
# See D2's design doc, Gap 2.
FROM golang:1.20.14-alpine AS agent-legacy-builder
RUN apk add --no-cache git zip && \
    go install mvdan.cc/garble@v0.10.1
WORKDIR /agent-legacy
COPY agent-legacy/go.mod agent-legacy/go.sum ./
RUN go mod download
COPY agent-legacy/ .
# Hard assertion: fail the image build outright if the resolved toolchain
# isn't exactly go1.20.14 -- now asserting the base image itself (a
# stronger guarantee than the previous GOTOOLCHAIN-driven assertion,
# which could not distinguish a correct native install from a
# garble-incompatible module-downloaded one carrying the same version
# string).
RUN GOVERSION=$(go version) && \
    echo "Resolved toolchain: $GOVERSION" && \
    case "$GOVERSION" in \
      *go1.20.14*) ;; \
      *) echo "FATAL: expected go1.20.14, got: $GOVERSION" >&2; exit 1 ;; \
    esac
# GOGARBLE scopes obfuscation to our own module only -- golang.org/x/sys
# (an older version than the modern agent's, v0.15.0) stays un-obfuscated,
# same reasoning as agent-builder above.
RUN CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOGARBLE='audspect/*' \
    garble -literals build -ldflags="-s -w" -o /agents-legacy/bas-agent-windows-legacy-amd64.exe .
RUN cd /agents-legacy && zip -q bas-agent-windows-legacy-amd64-setup.zip bas-agent-windows-legacy-amd64.exe
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestDockerfileAgentLegacyBuilderStageObfuscatesWithGarble -v`
Expected: PASS

- [ ] **Step 5: Real build verification (Tier B)**

Run (from repo root):
```bash
docker build -q --target agent-legacy-builder -t d2-task2-verify -f orchestrator/Dockerfile .
docker create --name d2-task2-extract d2-task2-verify
docker cp d2-task2-extract:/agents-legacy/bas-agent-windows-legacy-amd64.exe /tmp/d2-task2-legacy.exe
docker cp d2-task2-extract:/agents-legacy/bas-agent-windows-legacy-amd64-setup.zip /tmp/d2-task2-setup.zip
docker rm d2-task2-extract
echo "plaintext-string-count (expect 0):"
strings /tmp/d2-task2-legacy.exe | grep -c "Override BAS_SERVER_URL" || true
unzip -l /tmp/d2-task2-setup.zip
```
Then, on the Windows host (not inside the Linux container — the artifact is a Windows PE):
```bash
cp /tmp/d2-task2-legacy.exe /tmp/d2-task2-legacy-run.exe
chmod +x /tmp/d2-task2-legacy-run.exe
/tmp/d2-task2-legacy-run.exe -h
echo "exit=$?"
rm -f /tmp/d2-task2-legacy.exe /tmp/d2-task2-legacy-run.exe /tmp/d2-task2-setup.zip
docker rmi d2-task2-verify
```
Expected: `plaintext-string-count` is `0` (the flag-help string `"Override BAS_SERVER_URL"` is a literal in `agent-legacy/main.go`; `-literals` encrypts it). `unzip -l` lists `bas-agent-windows-legacy-amd64.exe` inside the zip without error. The binary runs natively on Windows and prints flag-usage text with exit 0.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/Dockerfile orchestrator/internal/api/download_integrity_test.go
git commit -m "fix(agent): obfuscate legacy agent-builder stage with garble (D2)

Switches agent-legacy-builder's base image from golang:1.26-alpine +
GOTOOLCHAIN=go1.20.14 to golang:1.20.14-alpine directly. The former
downloads go1.20.14 as a module toolchain, which prints a banner line
that garble v0.10.1's go-list JSON parser (written before Go's
module-toolchain feature existed) cannot handle -- a real panic,
reproduced and root-caused during D2's spike. A native base image has
no such banner. gcompat (only needed for that auto-download's glibc
shim) is no longer required.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
```

---

### Task 3: `packaging/build.sh` — Linux compose bundle agent obfuscation

**Files:**
- Modify: `packaging/build.sh:36-49`

**Interfaces:**
- Consumes: nothing from Tasks 1-2 (independent build path).
- Produces: `GOBUILD_AGENT` variable, consumed unchanged by the existing cross-compile loop (`packaging/build.sh:79-90`) — this task does not touch that loop.

- [ ] **Step 1: Write the failing test**

This is a bash variable-construction test, not a Go test — there is no existing shell-test framework in this repo (confirmed: no `.bats`/`shellspec` files exist), and introducing one is out of scope for this hardening change. The test is a short, throwaway verification script run directly, matching how this exact logic was already validated during D2's spike.

Create `/tmp/d2-task3-test.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
# Source only the GOBUILD_ORCH/GOBUILD_AGENT construction logic, in
# isolation, by extracting lines 36-49 of build.sh into a temp file and
# sourcing that -- avoids needing a full build.sh run (which requires
# Docker, git describe, etc.) just to check these two variables.
sed -n '36,49p' packaging/build.sh > /tmp/d2-task3-snippet.sh
VERSION="test"
source /tmp/d2-task3-snippet.sh
echo "GOBUILD_AGENT=${GOBUILD_AGENT}"
if [[ "${GOBUILD_AGENT}" != *"garble"* ]]; then
  echo "FAIL: GOBUILD_AGENT does not invoke garble when garble is on PATH"
  exit 1
fi
if [[ "${GOBUILD_AGENT}" != *"GOGARBLE"* ]]; then
  echo "FAIL: GOBUILD_AGENT (or its call site) does not scope with GOGARBLE"
  exit 1
fi
echo "PASS"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash /tmp/d2-task3-test.sh`
Expected: `FAIL: GOBUILD_AGENT does not invoke garble when garble is on PATH` (current `GOBUILD_AGENT="go build -trimpath -ldflags=-s -w"` has no garble).

- [ ] **Step 3: Edit `packaging/build.sh`**

Replace `packaging/build.sh:36-49`:

```bash
# ── Garble detection ──────────────────────────────────────────────────────────
# garble @latest — required for the Go toolchain in go.mod (v0.16.0+ for Go 1.26;
# older garble cannot build Go 1.26).  Install with:
#   go install mvdan.cc/garble@latest
if command -v garble &>/dev/null; then
  log "garble found — orchestrator will be obfuscated (-literals -tiny)"
  GOBUILD_ORCH="garble -literals -tiny build -ldflags=-s -w -X main.Version=${VERSION}"
else
  warn "garble not found — building orchestrator without obfuscation."
  echo "  Install: go install mvdan.cc/garble@latest"
  GOBUILD_ORCH="go build -trimpath -ldflags=-s -w -X main.Version=${VERSION}"
fi
# Agent uses plain stripped build: golang.org/x/sys assembly is incompatible with garble.
GOBUILD_AGENT="go build -trimpath -ldflags=-s -w"
```

with:

```bash
# ── Garble detection ──────────────────────────────────────────────────────────
# garble v0.17.0 — pinned, not @latest: v0.18.0 (2026-09-19) bumped its
# go.mod requirement to go >= 1.27, which breaks under a go1.26 toolchain.
# Install with:
#   go install mvdan.cc/garble@v0.17.0
if command -v garble &>/dev/null; then
  log "garble found — orchestrator and agent will be obfuscated (-literals)"
  GOBUILD_ORCH="garble -literals -tiny build -ldflags=-s -w -X main.Version=${VERSION}"
  # GOGARBLE scopes to our own module (audspect/agent, no github.com/
  # prefix -- different module path than the orchestrator's
  # github.com/audspect/bas). golang.org/x/sys, windigo, sspi, and
  # gorilla/websocket stay un-obfuscated, same reasoning as the
  # orchestrator's own scoping below.
  GOBUILD_AGENT="GOGARBLE='audspect/*' garble -literals build -ldflags=-s -w"
else
  warn "garble not found — building orchestrator and agent without obfuscation."
  echo "  Install: go install mvdan.cc/garble@v0.17.0"
  GOBUILD_ORCH="go build -trimpath -ldflags=-s -w -X main.Version=${VERSION}"
  GOBUILD_AGENT="go build -trimpath -ldflags=-s -w"
fi
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bash /tmp/d2-task3-test.sh`
Expected: `PASS`

- [ ] **Step 5: Real build verification**

Run (from repo root, requires garble installed and on PATH — already true on this host):
```bash
cd agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOGARBLE='audspect/*' garble -literals build -ldflags="-s -w" -o /tmp/d2-task3-agent .
cd ..
strings /tmp/d2-task3-agent | grep -c "agent log file" || true
chmod +x /tmp/d2-task3-agent
/tmp/d2-task3-agent -h
echo "exit=$?"
rm -f /tmp/d2-task3-agent /tmp/d2-task3-test.sh /tmp/d2-task3-snippet.sh
```
Expected: string count `0`, binary runs with usage output, exit `0`. (This replicates exactly what `GOBUILD_AGENT` now constructs — the full `bash packaging/build.sh` run additionally requires Docker/git-describe context not needed to verify this specific change.)

- [ ] **Step 6: Commit**

```bash
git add packaging/build.sh
git commit -m "fix(agent): obfuscate Linux compose-bundle agent build with garble (D2)

Mirrors the orchestrator's existing garble-or-plain-fallback pattern.
GOGARBLE scoped to 'audspect/*' (the agent module's own path, distinct
from the orchestrator's 'github.com/audspect/*').

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
```

---

### Task 4: `packaging/windows-build.ps1` — modern agent obfuscation

**Files:**
- Modify: `packaging/windows-build.ps1:290-314`

**Interfaces:**
- Consumes: nothing from Tasks 1-3 (independent build path).
- Produces: `installer\bas_agent.exe` is garble-obfuscated. C4's existing downstream consumers (signing at ~line 325-338, `Copy-Item` to `bas-agent-windows-amd64.exe` at ~line 372, byte-equality assertion at ~line 383-386) consume these same bytes unchanged — this task does not touch any of those lines.

- [ ] **Step 1: Write the failing test**

No Pester suite currently covers `windows-build.ps1`'s own agent-build logic (Pester coverage exists only for `sign-orchestrator-artifacts.ps1`). Following the same reasoning as Task 3, this is a real, throwaway verification run of the exact build command this task changes — matching how this precise command was already validated during D2's spike.

- [ ] **Step 2: Run test to verify it fails**

Run:
```powershell
cd C:\Users\Administrator\Downloads\Audspect_Cloud\agent
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
go build -ldflags="-s -w -H windowsgui" -o C:\Users\Administrator\Downloads\Audspect_Cloud\installer\bas_agent.exe .
$env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""
Select-String -Path C:\Users\Administrator\Downloads\Audspect_Cloud\installer\bas_agent.exe -Pattern "agent log file" -Encoding ascii
```
Expected: `Select-String` reports a match (plaintext string found — current build is not obfuscated).

- [ ] **Step 3: Edit `packaging/windows-build.ps1`**

Replace `packaging/windows-build.ps1:290-314`:

```powershell
Push-Location $AgentDir
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
# -H windowsgui: without this the agent is a console-subsystem binary, and
# Windows auto-allocates a visible console for it whenever something launches
# it without an inherited console (e.g. the tray's Run-key entry firing at
# logon) -- that console shows raw log output and, since the tray icon lives
# in the same process, closing it kills the tray too. platformPreStart's
# ensureConsole()/AllocConsole() already exists specifically to open a
# console on demand for genuine interactive use (--install/--uninstall/plain
# console mode); this flag just lets that mechanism do its job everywhere
# instead of the OS pre-empting it.
#
# C4: delete any pre-existing output first. `go build -o` skips rewriting
# the destination when it decides the new binary is unchanged from what's
# already there (a build-cache optimization to avoid bumping mtimes) --
# verified empirically to leave a PREVIOUSLY SIGNED bas_agent.exe from an
# earlier build completely untouched, cert and all, even though this run
# goes on to log "will not be signed". Without this delete, the signed/
# unsigned state of the embed source would depend on workspace history
# instead of this run's own cert/thumbprint -- exactly the non-determinism
# C4 exists to eliminate.
if (Test-Path "$InstallerDir\bas_agent.exe") { Remove-Item -Force "$InstallerDir\bas_agent.exe" }
go build -ldflags="-s -w -H windowsgui" -o "$InstallerDir\bas_agent.exe" . 2>&1
if ($LASTEXITCODE -ne 0) { Err "Agent build failed." }
$env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""
Pop-Location
Log "  Agent binary built: installer\bas_agent.exe"
```

with:

```powershell
Push-Location $AgentDir
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
$env:GOGARBLE = "audspect/*"
# -H windowsgui: without this the agent is a console-subsystem binary, and
# Windows auto-allocates a visible console for it whenever something launches
# it without an inherited console (e.g. the tray's Run-key entry firing at
# logon) -- that console shows raw log output and, since the tray icon lives
# in the same process, closing it kills the tray too. platformPreStart's
# ensureConsole()/AllocConsole() already exists specifically to open a
# console on demand for genuine interactive use (--install/--uninstall/plain
# console mode); this flag just lets that mechanism do its job everywhere
# instead of the OS pre-empting it.
#
# C4: delete any pre-existing output first. `go build -o` skips rewriting
# the destination when it decides the new binary is unchanged from what's
# already there (a build-cache optimization to avoid bumping mtimes) --
# verified empirically to leave a PREVIOUSLY SIGNED bas_agent.exe from an
# earlier build completely untouched, cert and all, even though this run
# goes on to log "will not be signed". Without this delete, the signed/
# unsigned state of the embed source would depend on workspace history
# instead of this run's own cert/thumbprint -- exactly the non-determinism
# C4 exists to eliminate.
#
# D2: garble (not plain go build) produces this binary -- it is the ONE
# authoritative build C4's signing/embedding below consumes. GOGARBLE
# scopes obfuscation to our own module, leaving golang.org/x/sys,
# windigo, and sspi un-obfuscated (same reasoning as the Dockerfile's
# agent-builder stage).
if (Test-Path "$InstallerDir\bas_agent.exe") { Remove-Item -Force "$InstallerDir\bas_agent.exe" }
garble -literals build -ldflags="-s -w -H windowsgui" -o "$InstallerDir\bas_agent.exe" . 2>&1
if ($LASTEXITCODE -ne 0) { Err "Agent build failed." }
$env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""; $env:GOGARBLE = ""
Pop-Location
Log "  Agent binary built: installer\bas_agent.exe (obfuscated)"
```

- [ ] **Step 4: Run test to verify it passes**

Run (same commands as Step 2, but with the new garble-wrapped build):
```powershell
cd C:\Users\Administrator\Downloads\Audspect_Cloud\agent
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"; $env:GOGARBLE = "audspect/*"
garble -literals build -ldflags="-s -w -H windowsgui" -o C:\Users\Administrator\Downloads\Audspect_Cloud\installer\bas_agent.exe .
$env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""; $env:GOGARBLE = ""
Select-String -Path C:\Users\Administrator\Downloads\Audspect_Cloud\installer\bas_agent.exe -Pattern "agent log file" -Encoding ascii
```
Expected: `Select-String` returns nothing (no plaintext match — now obfuscated).

- [ ] **Step 5: Functional smoke test**

Run:
```powershell
Copy-Item C:\Users\Administrator\Downloads\Audspect_Cloud\installer\bas_agent.exe C:\Users\Administrator\Downloads\Audspect_Cloud\installer\bas_agent-test.exe
& C:\Users\Administrator\Downloads\Audspect_Cloud\installer\bas_agent-test.exe -h
Remove-Item C:\Users\Administrator\Downloads\Audspect_Cloud\installer\bas_agent.exe, C:\Users\Administrator\Downloads\Audspect_Cloud\installer\bas_agent-test.exe -Force
```
Expected: usage output listing `-ca-root`, `-console`, `-env`, `-install`, `-secret`, `-server`, `-status-window`, `-tray`, `-uninstall`, `-update` flags, exit code `0`. The presence of `-tray`/`-status-window`/`-console` confirms the windigo-dependent build tags still compiled correctly under garble.

- [ ] **Step 6: Commit**

```bash
git add packaging/windows-build.ps1
git commit -m "fix(agent): obfuscate Windows agent build with garble, preserving C4 ordering (D2)

garble replaces the plain go build at the exact point C4 already treats
as the single authoritative build -- signing, installer-embedding, and
the standalone copy downstream are untouched and still consume the same
(now garbled) bytes. GOGARBLE scoped to 'audspect/*'.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
```

---

### Task 5: `packaging/windows-build.ps1` — legacy agent obfuscation + dedicated toolchain

**Files:**
- Modify: `packaging/windows-build.ps1:390-424`

**Interfaces:**
- Consumes: nothing from Tasks 1-4 (independent build path).
- Produces: `$OutDir\bas-agent-windows-legacy-amd64.exe` is garble-obfuscated. Downstream signing (~line 442, 455-462) and re-zip (~line 475-477) consume this file unchanged — this task does not touch those lines.

- [ ] **Step 1: Provision the dedicated go1.20.14 GOROOT (host prerequisite)**

This mirrors the main-toolchain upgrade already performed on this host for Gap 1 — a one-time, persistent host setup step, not something `windows-build.ps1` provisions on the fly (a release build should never trigger a network install mid-run).

Run:
```powershell
$ProgressPreference = "SilentlyContinue"
Invoke-WebRequest -Uri "https://go.dev/dl/go1.20.14.windows-amd64.zip" -OutFile "$env:TEMP\go1.20.14.windows-amd64.zip"
$hash = (Get-FileHash -Path "$env:TEMP\go1.20.14.windows-amd64.zip" -Algorithm SHA256).Hash.ToLower()
if ($hash -ne "0e0d0190406ead891d94ecf00f961bb5cfa15ddd47499d2649f12eee80aee110") {
    Write-Error "go1.20.14.windows-amd64.zip checksum mismatch: got $hash"
    exit 1
}
Expand-Archive -Path "$env:TEMP\go1.20.14.windows-amd64.zip" -DestinationPath "C:\" -Force
Remove-Item "$env:TEMP\go1.20.14.windows-amd64.zip"
Rename-Item -Path "C:\go" -NewName "go1.20.14" -ErrorAction Stop
& "C:\go1.20.14\bin\go.exe" version
```
Expected: checksum matches (verified against the real `go.dev/dl` JSON, same as the main 1.26.8 upgrade), `C:\go1.20.14\bin\go.exe version` prints `go version go1.20.14 windows/amd64`.

Then install garble v0.10.1 against it:
```powershell
$env:GOROOT = "C:\go1.20.14"
$env:GOTOOLCHAIN = "local"
$env:PATH = "C:\go1.20.14\bin;$env:PATH"
go install mvdan.cc/garble@v0.10.1
$env:GOROOT = ""; $env:GOTOOLCHAIN = ""
```
Expected: no error output; `garble` (v0.10.1) now installed at `$env:GOPATH\bin\garble` (or wherever `go env GOBIN`/`GOPATH\bin` resolves — the same `garble` binary name as the v0.17.0 install, so the script must select the right one explicitly by full path at call time, not rely on `PATH` ordering. Handle this in Step 3 by invoking garble via its full resolved path for this section only.)

Record the resolved path for Step 3:
```powershell
$LegacyGarbleBin = Join-Path (& "C:\go1.20.14\bin\go.exe" env GOPATH) "bin\garble.exe"
Test-Path $LegacyGarbleBin
```
Expected: `True`.

- [ ] **Step 2: Write the failing test**

Run (replicating `windows-build.ps1`'s current legacy section exactly, to confirm it still fails the same way the spike found):
```powershell
cd C:\Users\Administrator\Downloads\Audspect_Cloud\agent-legacy
$env:GOTOOLCHAIN = "go1.20.14"
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"; $env:GOWORK = "off"
garble -literals build -ldflags="-s -w" -o C:\Temp\d2-task5-test.exe .
$env:GOTOOLCHAIN = ""; $env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""; $env:GOWORK = ""
```
Expected: `panic: go list error: exit status 1` with `go: toolchain go1.26.8 invoked to provide go1.20.14` in the output — the exact Gap 2 failure, reproduced here to confirm the test setup correctly detects the problem before it's fixed.

- [ ] **Step 3: Edit `packaging/windows-build.ps1`**

Replace `packaging/windows-build.ps1:390-424`:

```powershell
# -- 5a2. Build Legacy Windows agent binary (amd64 only) ---------------------
# Separately toolchained via GOTOOLCHAIN=go1.20.14 (agent-legacy/go.mod stays
# at a bare `go 1.20` -- the `toolchain` directive predates Go 1.21 and
# go1.20.14 can't parse it). go1.20.14 is the last Go release supporting
# Windows 7 SP1/8/8.1/Server 2008 R2-2012 R2. See
# docs/superpowers/specs/2026-08-18-legacy-windows-agent-phase1-design.md.
Log "Building Legacy Windows agent binary (go1.20.14, amd64 only)..."
$LegacyAgentDir = Join-Path $RepoRoot "agent-legacy"
Push-Location $LegacyAgentDir
$env:GOTOOLCHAIN = "go1.20.14"
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
# go1.20.14 predates Go workspace support (added in Go 1.21) and cannot
# parse the repo-root go.work file at all -- it errors on the go.work
# `go` directive's version format before it can even determine
# agent-legacy is (or isn't) a workspace member. GOWORK=off makes this
# build step ignore go.work entirely, exactly as it did before go.work
# existed.
$env:GOWORK = "off"

$legacyGoVersion = (go version)
Log "  Resolved toolchain: $legacyGoVersion"
if ($legacyGoVersion -notmatch "go1\.20\.14") {
    Pop-Location
    Err "Legacy agent toolchain mismatch. Expected go1.20.14, got: $legacyGoVersion"
}

go build -trimpath -ldflags="-s -w" -o "$OutDir\bas-agent-windows-legacy-amd64.exe" . 2>&1
if ($LASTEXITCODE -ne 0) {
    Warn "Legacy Windows agent build failed."
} else {
    $legacySizeMB = [math]::Round((Get-Item "$OutDir\bas-agent-windows-legacy-amd64.exe").Length / 1MB, 1)
    Log "  bas-agent-windows-legacy-amd64.exe (${legacySizeMB}MB)"
}
$env:GOTOOLCHAIN = ""; $env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""; $env:GOWORK = ""
Pop-Location
```

with:

```powershell
# -- 5a2. Build Legacy Windows agent binary (amd64 only) ---------------------
# go1.20.14 is the last Go release supporting Windows 7 SP1/8/8.1/Server
# 2008 R2-2012 R2. See
# docs/superpowers/specs/2026-08-18-legacy-windows-agent-phase1-design.md.
#
# Uses a dedicated, real go1.20.14 GOROOT at C:\go1.20.14 (provisioned
# once on this build host -- see D2's implementation plan, Task 5, Step
# 1) rather than $env:GOTOOLCHAIN = "go1.20.14" on top of the main
# install: the latter downloads go1.20.14 as a *module* toolchain under
# GOMODCACHE, which garble v0.10.1 (the legacy-compatible pin; it
# predates Go's module-toolchain feature) cannot parse the output of --
# a real panic, reproduced during D2's spike. A real GOROOT has no such
# banner for garble to choke on. D2's design doc (Gap 2) has the full
# root cause.
Log "Building Legacy Windows agent binary (go1.20.14, amd64 only)..."
$LegacyAgentDir = Join-Path $RepoRoot "agent-legacy"
$LegacyGoRoot = "C:\go1.20.14"
# Fail loudly and specifically if the dedicated GOROOT is missing, rather
# than silently falling through to $env:GOTOOLCHAIN's auto-download path
# and dying on Gap 2's confusing `go list` panic far from its real cause.
if (-not (Test-Path "$LegacyGoRoot\bin\go.exe")) {
    Err "Legacy agent build requires a dedicated go1.20.14 install at $LegacyGoRoot (not found). Provision it: see D2's implementation plan, Task 5, Step 1. Do not rely on `$env:GOTOOLCHAIN='go1.20.14'` -- it downloads a module toolchain that garble v0.10.1 cannot build against."
}
$LegacyGarbleBin = Join-Path (& "$LegacyGoRoot\bin\go.exe" env GOPATH) "bin\garble.exe"
if (-not (Test-Path $LegacyGarbleBin)) {
    Err "Legacy agent build requires garble v0.10.1 installed against the dedicated go1.20.14 GOROOT (not found at $LegacyGarbleBin). Provision it: see D2's implementation plan, Task 5, Step 1."
}
Push-Location $LegacyAgentDir
$env:GOROOT = $LegacyGoRoot
$env:GOTOOLCHAIN = "local"
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
$env:GOGARBLE = "audspect/*"
# go1.20.14 predates Go workspace support (added in Go 1.21) and cannot
# parse the repo-root go.work file at all -- it errors on the go.work
# `go` directive's version format before it can even determine
# agent-legacy is (or isn't) a workspace member. GOWORK=off makes this
# build step ignore go.work entirely, exactly as it did before go.work
# existed.
$env:GOWORK = "off"

$legacyGoVersion = (& "$LegacyGoRoot\bin\go.exe" version)
Log "  Resolved toolchain: $legacyGoVersion (GOROOT=$env:GOROOT)"
if ($legacyGoVersion -notmatch "go1\.20\.14") {
    Pop-Location
    Err "Legacy agent toolchain mismatch. Expected go1.20.14, got: $legacyGoVersion"
}
if ((Get-Item $LegacyGoRoot).Target) {
    Pop-Location
    Err "C:\go1.20.14 resolves through a reparse point/symlink -- verify it is a real extracted install, not something that could resolve to the module-toolchain cache."
}

& $LegacyGarbleBin -literals build -ldflags="-s -w" -o "$OutDir\bas-agent-windows-legacy-amd64.exe" . 2>&1
if ($LASTEXITCODE -ne 0) {
    Warn "Legacy Windows agent build failed."
} else {
    $legacySizeMB = [math]::Round((Get-Item "$OutDir\bas-agent-windows-legacy-amd64.exe").Length / 1MB, 1)
    Log "  bas-agent-windows-legacy-amd64.exe (${legacySizeMB}MB, obfuscated)"
}
$env:GOROOT = ""; $env:GOTOOLCHAIN = ""; $env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""; $env:GOWORK = ""; $env:GOGARBLE = ""
Pop-Location
```

- [ ] **Step 4: Run test to verify it passes**

Run (the corrected sequence, standalone, before touching the real `windows-build.ps1` run end-to-end):
```powershell
cd C:\Users\Administrator\Downloads\Audspect_Cloud\agent-legacy
$env:GOROOT = "C:\go1.20.14"; $env:GOTOOLCHAIN = "local"
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"; $env:GOWORK = "off"; $env:GOGARBLE = "audspect/*"
$LegacyGarbleBin = Join-Path (& "C:\go1.20.14\bin\go.exe" env GOPATH) "bin\garble.exe"
& $LegacyGarbleBin version
& $LegacyGarbleBin -literals build -ldflags="-s -w" -o C:\Temp\d2-task5-test2.exe .
$env:GOROOT = ""; $env:GOTOOLCHAIN = ""; $env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""; $env:GOWORK = ""; $env:GOGARBLE = ""
Select-String -Path C:\Temp\d2-task5-test2.exe -Pattern "Override BAS_SERVER_URL" -Encoding ascii
```
Expected: build succeeds (no panic), `Select-String` returns nothing (no plaintext match).

- [ ] **Step 5: Functional smoke test**

Run:
```powershell
& C:\Temp\d2-task5-test2.exe -h
Remove-Item C:\Temp\d2-task5-test2.exe -Force
```
Expected: usage output listing `-env`, `-install`, `-secret`, `-server`, `-uninstall`, exit code `0`.

- [ ] **Step 6: Commit**

```bash
git add packaging/windows-build.ps1
git commit -m "fix(agent): obfuscate legacy Windows agent build, use dedicated go1.20.14 GOROOT (D2)

Same root cause as the Dockerfile fix (Task 2): \$env:GOTOOLCHAIN =
'go1.20.14' downloads a module toolchain that garble v0.10.1 cannot
parse the output of. Switches to a dedicated, real GOROOT at
C:\go1.20.14 (host prerequisite, provisioned this session) with
GOTOOLCHAIN=local. Adds explicit, clear prerequisite checks so a build
host missing this dedicated install fails fast with remediation
instructions instead of hitting the confusing panic far from its cause.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
```

---

### Task 6: Final cross-path verification

**Files:** none modified — verification only.

**Interfaces:**
- Consumes: the outputs of Tasks 1-5.
- Produces: nothing for a later task; this is the plan's closing gate.

- [ ] **Step 1: Full real Docker image build (not isolated stage targets)**

Run (from repo root):
```bash
docker build -q -t d2-task6-full -f orchestrator/Dockerfile .
docker create --name d2-task6-extract d2-task6-full
mkdir -p /tmp/d2-task6-agents
docker cp d2-task6-extract:/agents/. /tmp/d2-task6-agents/
docker rm d2-task6-extract
ls -la /tmp/d2-task6-agents/
```
Expected: build succeeds end-to-end (all stages wire together — `binaries-manifest`'s `COPY --from=` sources are unaffected by Tasks 1-2's changes). `/tmp/d2-task6-agents/` contains all 11 artifacts the `agentFiles` map expects (5 raw binaries, 2 setup zips, 3 Linux packages, legacy exe) plus `BINARIES.sha256` and `BINARIES.sha256.sig`.

- [ ] **Step 2: Level 1 sweep — confirm every shipped artifact is actually obfuscated**

Run:
```bash
for f in bas-agent-linux-amd64 bas-agent-linux-arm64 bas-agent-darwin-amd64 bas-agent-darwin-arm64; do
  echo "=== $f ==="
  strings "/tmp/d2-task6-agents/$f" | grep -c "agent log file" || true
done
strings /tmp/d2-task6-agents/bas-agent-windows-amd64.exe | grep -c "agent log file" || true
strings /tmp/d2-task6-agents/bas-agent-windows-legacy-amd64.exe | grep -c "Override BAS_SERVER_URL" || true
rm -rf /tmp/d2-task6-agents
docker rmi d2-task6-full
```
Expected: every count is `0`.

- [ ] **Step 3: Level 2 functional smoke, every applicable platform**

Run (linux-amd64 directly executable on this host's Docker; others already covered by Tasks 1/2/4/5's individual smoke tests — re-confirm linux-amd64 here as the full-image regression check):
```bash
docker build -q --target agent-builder -t d2-task6-smoke -f orchestrator/Dockerfile .
docker run --rm d2-task6-smoke sh -c '/agents/bas-agent-linux-amd64 -h'
docker rmi d2-task6-smoke
```
Expected: usage output, clean exit (process starts, logging initializes per the printed `agent log file` line — now encrypted at rest but still functionally logged at runtime — argument parsing works, process exits cleanly).

- [ ] **Step 4: C4 regression — byte-equality still holds**

Run (requires a full `windows-build.ps1` invocation; run without `-Customer`/`-CustomerID` for a dev-mode pass that still exercises the build+copy path):
```powershell
cd C:\Users\Administrator\Downloads\Audspect_Cloud
.\packaging\windows-build.ps1 -Version "d2-task6-test"
```
Expected: script completes without hitting the `Err` at `windows-build.ps1`'s C4 byte-equality check (~line 383-386) — `installer\bas_agent.exe` and `dist\bas-install-d2-task6-test\bas-agent-windows-amd64.exe` are byte-identical, now both garbled. Inspect the script's own log output for `"Agent binary built: installer\bas_agent.exe (obfuscated)"` and `"bas-agent-windows-legacy-amd64.exe (...MB, obfuscated)"` (Task 4/5's new log suffixes) to confirm both agent builds actually took the garble path, not a silent fallback.

- [ ] **Step 5: Level 3 — document the manual QA checklist (not automated in this plan)**

The following require a live orchestrator and/or interactive GUI session and are **not** automated by this plan — hand this checklist to the user for a manual pass before the obfuscated build ships to a customer:

```
D2 Level 3 manual QA checklist (modern Windows agent):
[ ] Tray icon appears and responds to clicks (--tray)
[ ] Status window opens and renders agent state (--status-window)
[ ] Agent enrolls against a real/staging orchestrator over mTLS
[ ] SSPI-based auth path exercised (if applicable to the test environment)
[ ] Orchestrator can dispatch a command to the obfuscated agent and receive a result
[ ] A scenario execution completes and reports telemetry back correctly

Legacy Windows agent (equivalent checks that actually exist for it):
[ ] Agent installs as a Windows service (-install) and starts
[ ] Agent enrolls against a real/staging orchestrator
[ ] Orchestrator can dispatch a command and receive a result
```

Report this checklist to the user in the plan's final summary; do not claim Level 3 complete without it being run.

- [ ] **Step 6: Run the full existing test suite to confirm no regression**

Run: `cd orchestrator && go test ./... -timeout 25m`
Expected: all pre-existing tests still pass, plus Tasks 1-2's two new tests. (The pre-existing, unrelated `TestRBACMatrix_NoDrift` failure on `GET /api/config/ca-root` — tracked separately as [[RBAC matrix drift - GET api-config-ca-root missing route entry]] — is expected to still fail; it predates this plan and is out of scope for it.)

---

## Final Verification

- [ ] All 6 tasks' individual test commands pass (re-run if time has passed since each task's own Step 4/5).
- [ ] Task 6 Steps 1-4, 6 all pass.
- [ ] Task 6 Step 5's manual QA checklist is handed to the user explicitly in the final summary — Level 3 is not claimed as done without it.
- [ ] `git status` is clean (no stray `/tmp/d2-*` artifacts, no modified `installer/bas_agent.exe` left in the working tree from manual verification runs).
- [ ] [[D2 - Agent binary not obfuscated]] vault note updated to closed afterward (outside this plan, matching how C3/C4 were closed in this same session — not a plan task).
