# C3: BINARIES.sha256 Manifest Package Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `BINARIES.sha256` list and correctly hash all 11 artifacts `/api/agents/download/{platform}` can serve, in both an unsigned (dev) build and a signed (customer) build, so the handler's existing fail-closed check stops permanently refusing 5 of them.

**Architecture:** Two independent fixes. `orchestrator/Dockerfile`'s `binaries-manifest` stage gains COPY lines for the 2 setup zips and 3 Linux packages (already built by earlier stages) and hashes all 11, giving every build a correct baseline. `packaging/signing/sign-orchestrator-artifacts.ps1`'s `Update-OrchestratorAgentArtifacts` — which already rebuilds and re-injects signed content for both setup zips during a customer build — gains 2 more entries in its `$replacements` map so the manifest stays truthful after that rebuild. No handler changes.

**Tech Stack:** Dockerfile (BuildKit multi-stage), PowerShell 5.1 + Pester 3.4.0, Go 1.26 (table-driven `testing`).

**Spec:** `docs/superpowers/specs/2026-10-01-c3-manifest-package-coverage-design.md`

## Global Constraints

- No changes to `DownloadAgent` (`orchestrator/internal/api/handlers.go:1158-1222`) or to the `agentFiles` map (lines 1140-1152) — the set of served artifacts and the refusal logic are both already correct.
- No package-native signing (`dpkg-sig`, `rpm --sign`, or any zip-specific mechanism). All 11 artifacts use the same whole-file-SHA-256-in-the-existing-RSA-signed-manifest mechanism the current 6 already use.
- No full live-stack HTTP/JWT/Postgres boot test (Tier C, explicitly out of scope per the spec's Non-goals).
- No change to the top-level `BASAgent-Setup-$Version.exe` / `dist/bas-install-*.zip` delivery pipeline — this plan is scoped to the orchestrator's own `/agents/BINARIES.sha256` and the live download endpoint only.
- Every "is this entry correct" assertion compares against the actual bytes present at that point in the pipeline (extracted from the real image, or the real on-disk file) — never "the hash changed" as a standalone check.

## Review Focus

- **An unsigned (dev/no-cert) build must have all 11 manifest entries present and correct straight out of `docker build`** — nothing downstream (`Update-OrchestratorAgentArtifacts`) runs for a dev build, so `binaries-manifest` is the only chance to get this right. Verified in Task 1's real-build check.
- **Every one of the 11 manifest entries must hash the exact bytes present in the final image's `/agents/` directory** — not a same-named file from an earlier build stage that happens to usually match. A COPY source typo in the new `binaries-manifest` lines could silently hash the wrong stage's copy. Verified in Task 1 by extracting and hashing the real final-image file for all 11, not trusting that stages agree.
- **A signed (customer) build's 2 setup-zip manifest entries must end up matching the actual post-signing bytes the image serves** — `Update-OrchestratorAgentArtifacts` already rebuilds these zips; a missing `$replacements` entry would leave a stale pre-signing hash that fails the handler's own integrity check for a legitimately signed artifact. Verified in Task 3.
- **A signed (customer) build must leave the 3 Linux-package (and 2 macOS, 2 Linux-raw) manifest entries byte-identical to their Docker-build values** — nothing in the Windows signing patch should touch Linux artifacts. Verified in Task 3.
- **The handler's existing refusal of an unknown platform key, and of a known platform whose file is simply absent, must be unaffected by broadening the manifest** — re-run of the existing `TestDownloadAgent_UnknownPlatform` / `TestDownloadAgent_KnownPlatformNoFilePresent` / `TestDownloadAgent_WindowsLegacyPlatform_KnownButFileMissing` tests, confirmed still green. Verified in Task 2.

---

## Task 1: Dockerfile manifest coverage

**Files:**
- Modify: `orchestrator/Dockerfile:90-99`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: the final image's `/agents/BINARIES.sha256`, with all 11 artifacts correctly hashed in an unsigned build — Task 3's fixture-based tests do not depend on this (they use their own `FROM scratch` fixture), but this is the real-world baseline Task 3's production code change (`$replacements`) assumes exists going into a customer build.

No Pester/Go harness exists for Dockerfile syntax (same precedent as D1/C2/C4's own `windows-build.ps1` tasks) — this task is verified by a real `docker build` and inspecting its output directly.

- [ ] **Step 1: Edit the `binaries-manifest` stage**

Replace `orchestrator/Dockerfile` lines 90-99:

```dockerfile
FROM alpine AS binaries-manifest
RUN mkdir /agents
COPY --from=agent-builder /agents/bas-agent-linux-amd64 /agents/bas-agent-linux-arm64 \
     /agents/bas-agent-windows-amd64.exe /agents/bas-agent-darwin-amd64 /agents/bas-agent-darwin-arm64 \
     /agents/
COPY --from=agent-legacy-builder /agents-legacy/bas-agent-windows-legacy-amd64.exe /agents/
RUN cd /agents && sha256sum \
      bas-agent-linux-amd64 bas-agent-linux-arm64 bas-agent-windows-amd64.exe \
      bas-agent-darwin-amd64 bas-agent-darwin-arm64 bas-agent-windows-legacy-amd64.exe \
    > /agents/BINARIES.sha256
```

with:

```dockerfile
FROM alpine AS binaries-manifest
RUN mkdir /agents
COPY --from=agent-builder /agents/bas-agent-linux-amd64 /agents/bas-agent-linux-arm64 \
     /agents/bas-agent-windows-amd64.exe /agents/bas-agent-darwin-amd64 /agents/bas-agent-darwin-arm64 \
     /agents/bas-agent-windows-amd64-setup.zip \
     /agents/
COPY --from=agent-legacy-builder /agents-legacy/bas-agent-windows-legacy-amd64.exe \
     /agents-legacy/bas-agent-windows-legacy-amd64-setup.zip \
     /agents/
COPY --from=packager /packages/bas-agent-linux-amd64.deb /packages/bas-agent-linux-arm64.deb \
     /packages/bas-agent-linux-amd64.rpm \
     /agents/
RUN cd /agents && sha256sum \
      bas-agent-linux-amd64 bas-agent-linux-arm64 bas-agent-windows-amd64.exe \
      bas-agent-darwin-amd64 bas-agent-darwin-arm64 bas-agent-windows-legacy-amd64.exe \
      bas-agent-windows-amd64-setup.zip bas-agent-windows-legacy-amd64-setup.zip \
      bas-agent-linux-amd64.deb bas-agent-linux-arm64.deb bas-agent-linux-amd64.rpm \
    > /agents/BINARIES.sha256
```

This adds a new stage dependency (`binaries-manifest` now also reads from
`packager`). BuildKit resolves build order from the `COPY --from=` graph,
not the stages' textual order in the file, so `packager` (already
defined earlier, at lines 101-110) needs no repositioning.

- [ ] **Step 2: Build the real image**

```powershell
docker build -t bas-orchestrator:c3-manifest-test -f orchestrator/Dockerfile .
```

Run from the repo root. Expect this to take 5-10 minutes (same cost as
the orchestrator's garbled Go build, unrelated to this change) — run it
in the background if your harness supports that, and wait for it to
finish before Step 3.

Expected: exits 0. No `COPY` failures (a typo'd source path in Step 1
would fail the build here, loudly, at the `binaries-manifest` stage —
Docker refuses to build a stage whose `COPY --from=` source doesn't
exist in the referenced stage).

- [ ] **Step 3: Verify the manifest lists all 11 artifacts with correct hashes**

```powershell
$cid = docker create bas-orchestrator:c3-manifest-test
$extractDir = Join-Path $env:TEMP "c3-manifest-check-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $extractDir | Out-Null

$expectedFiles = @(
    "bas-agent-linux-amd64", "bas-agent-linux-arm64",
    "bas-agent-windows-amd64.exe", "bas-agent-darwin-amd64", "bas-agent-darwin-arm64",
    "bas-agent-windows-legacy-amd64.exe",
    "bas-agent-windows-amd64-setup.zip", "bas-agent-windows-legacy-amd64-setup.zip",
    "bas-agent-linux-amd64.deb", "bas-agent-linux-arm64.deb", "bas-agent-linux-amd64.rpm"
)
foreach ($f in ($expectedFiles + "BINARIES.sha256")) {
    docker cp "${cid}:/agents/$f" "$extractDir\$f" | Out-Null
}
docker rm $cid | Out-Null

$manifestLines = Get-Content "$extractDir\BINARIES.sha256"
Write-Host "Manifest line count: $($manifestLines.Count) (want 11)"

$allMatch = $true
foreach ($f in $expectedFiles) {
    $actualHash = (Get-FileHash -Path "$extractDir\$f" -Algorithm SHA256).Hash.ToLower()
    $line = $manifestLines | Where-Object { $_ -match [regex]::Escape($f) + '$' }
    if (-not $line) {
        Write-Host "MISSING from manifest: $f"
        $allMatch = $false
        continue
    }
    $manifestHash = ($line -replace '\s.*$', '')
    if ($manifestHash -ne $actualHash) {
        Write-Host "HASH MISMATCH for $f`: manifest=$manifestHash actual=$actualHash"
        $allMatch = $false
    }
}
Write-Host "All 11 present and correct: $allMatch"
```

Expected: `Manifest line count: 11`, no `MISSING`/`HASH MISMATCH` lines,
`All 11 present and correct: True`.

- [ ] **Step 4: Clean up the test image and extracted files**

```powershell
docker rmi bas-orchestrator:c3-manifest-test -f
Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
```

- [ ] **Step 5: Commit**

```bash
git add orchestrator/Dockerfile
git commit -m "fix(manifest): cover all 11 download-endpoint artifacts in BINARIES.sha256"
```

---

## Task 2: Go test coverage for all 11 platforms

**Files:**
- Modify: `orchestrator/internal/api/download_integrity_test.go`

**Interfaces:**
- Consumes: the `agentFiles` map and `DownloadAgent` method (`handlers.go`, unchanged by this plan) — iterates `agentFiles` directly rather than hardcoding platform/filename strings, so it stays correct if `agentFiles` ever gains or loses an entry.
- Produces: nothing other tasks depend on.

This task adds regression coverage for a handler contract that is
**already correct** — `DownloadAgent`'s serve/refuse logic was never the
bug; it was only ever starved of manifest entries (Task 1's job). Treat
the "RED" step honestly: these tests are new, not failing-until-fixed.

- [ ] **Step 1: Write the new fixture helper and tests**

Add to `orchestrator/internal/api/download_integrity_test.go` (after
the existing `writeAgentAndManifest`, before `downloadLinuxAgent`):

```go
// writeAllAgentFixturesAndManifest writes a real fixture file for every
// agentFiles entry and a manifest that correctly lists all of them --
// the shape production's BINARIES.sha256 has once Task 1 of the C3 plan
// lands. Content is "content-of-<filename>" per file, so a test can
// assert on exactly which file it got back.
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
```

Then add these two tests at the end of the file, before the closing
of the file (after `TestDownloadAgent_NoManifestStillServes`):

```go
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
```

- [ ] **Step 2: Run the new tests**

```powershell
cd orchestrator
go test ./internal/api/... -run 'TestDownloadAgent_AllPlatformsServedAndVerified|TestDownloadAgent_OnePlatformMissingFromManifestRefusesOnlyThatOne' -v
```

Expected: both tests `PASS`, including all 11 subtests under
`TestDownloadAgent_AllPlatformsServedAndVerified`. This is not a
RED→GREEN bug fix — `DownloadAgent`'s logic was already correct; this
step proves the regression-guard itself works.

- [ ] **Step 3: Run the full existing download test files to confirm no regression**

```powershell
go test ./internal/api/... -run 'TestDownloadAgent' -v
```

Expected: every existing test still passes, in particular
`TestDownloadAgent_UnknownPlatform`, `TestDownloadAgent_KnownPlatformNoFilePresent`,
and `TestDownloadAgent_WindowsLegacyPlatform_KnownButFileMissing` — unaffected
by broadening the fixture/manifest shape in the two new tests above (they
build their own, separate fixtures).

- [ ] **Step 4: Run the full package test suite**

```powershell
go test ./internal/api/... 
```

Expected: all tests pass (no regressions elsewhere in the package).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/download_integrity_test.go
git commit -m "test: cover all 11 download-endpoint platforms against a realistic manifest"
```

---

## Task 3: Keep the setup-zip manifest entries truthful after signing

**Files:**
- Modify: `packaging/signing/sign-orchestrator-artifacts.ps1` (function `Update-OrchestratorAgentArtifacts`)
- Modify: `packaging/signing/verify-orchestrator-artifacts.Tests.ps1`

**Interfaces:**
- Consumes: nothing from Task 1 or Task 2 (this task's Pester fixture is an independent `FROM scratch` image, not the real Dockerfile — see rationale below).
- Produces: nothing other tasks depend on.

`Update-OrchestratorAgentArtifacts` already rebuilds and re-injects
signed content for both setup zips (existing code, lines ~108-120 and
~165-168) — that part is correct and already tested by this file's
first `It` block, unchanged by this task. The gap is narrower: its
`$replacements` map (used to regenerate `BINARIES.sha256` to match)
only covers the 2 raw `.exe` files, not the 2 zips it just rebuilt.

This task's test stays on the existing cheap `FROM scratch` fixture
(`New-FixtureOrchestratorImage`) rather than a real multi-stage build:
`Update-OrchestratorAgentArtifacts` operates on any image shaped like
`/agents/{the files it names}`, regardless of how that image was really
built, so there's no need to pay for a ~5-10 minute real build to
exercise this specific function's logic (Task 1 already paid that cost
for the thing only a real build can prove — the Dockerfile's own stage
wiring).

- [ ] **Step 1: Extend the fixture to include all 11 artifacts' placeholder entries**

In `packaging/signing/verify-orchestrator-artifacts.Tests.ps1`, replace
the `New-FixtureOrchestratorImage` function:

```powershell
function New-FixtureOrchestratorImage {
    param([string]$Tag)
    $ctx = Join-Path $env:TEMP "orch-patch-fixture-$(Get-Random)"
    New-Item -ItemType Directory -Force -Path "$ctx\agents" | Out-Null
    foreach ($f in @("bas-agent-windows-amd64.exe", "bas-agent-windows-legacy-amd64.exe",
                     "bas-agent-windows-legacy-amd64-setup.zip", "bas-agent-windows-amd64-setup.zip")) {
        Set-Content -Path "$ctx\agents\$f" -Value "placeholder"
    }
    $placeholderHash = ("0" * 64)
    Set-Content -Path "$ctx\agents\BINARIES.sha256" -Value (@(
        "$placeholderHash  bas-agent-linux-amd64",
        "$placeholderHash  bas-agent-linux-arm64",
        "$placeholderHash  bas-agent-windows-amd64.exe",
        "$placeholderHash  bas-agent-darwin-amd64",
        "$placeholderHash  bas-agent-darwin-arm64",
        "$placeholderHash  bas-agent-windows-legacy-amd64.exe"
    ) -join "`n")
    # CMD is required: "docker create <image>" with no override command
    # fails with "No command specified" on a FROM-scratch image that
    # defines neither CMD nor ENTRYPOINT. The binary path never has to
    # exist -- docker only validates it at `docker start`, which this
    # fixture never calls.
    Set-Content -Path "$ctx\Dockerfile" -Value "FROM scratch`nCOPY agents /agents`nCMD [`"/nonexistent`"]`n"
    docker build -q -t $Tag $ctx | Out-Null
    Remove-Item $ctx -Recurse -Force -ErrorAction SilentlyContinue
}
```

with:

```powershell
function New-FixtureOrchestratorImage {
    param([string]$Tag)
    $ctx = Join-Path $env:TEMP "orch-patch-fixture-$(Get-Random)"
    New-Item -ItemType Directory -Force -Path "$ctx\agents" | Out-Null
    foreach ($f in @("bas-agent-windows-amd64.exe", "bas-agent-windows-legacy-amd64.exe",
                     "bas-agent-windows-legacy-amd64-setup.zip", "bas-agent-windows-amd64-setup.zip",
                     "bas-agent-linux-amd64.deb", "bas-agent-linux-arm64.deb", "bas-agent-linux-amd64.rpm")) {
        Set-Content -Path "$ctx\agents\$f" -Value "placeholder"
    }
    # C3: the fixture's manifest now matches the post-Task-1 shape -- all
    # 11 entries present, so this function's own test can assert the 2
    # zip entries change on a signing patch while the 3 Linux package
    # entries (added here) stay untouched.
    $placeholderHash = ("0" * 64)
    Set-Content -Path "$ctx\agents\BINARIES.sha256" -Value (@(
        "$placeholderHash  bas-agent-linux-amd64",
        "$placeholderHash  bas-agent-linux-arm64",
        "$placeholderHash  bas-agent-windows-amd64.exe",
        "$placeholderHash  bas-agent-darwin-amd64",
        "$placeholderHash  bas-agent-darwin-arm64",
        "$placeholderHash  bas-agent-windows-legacy-amd64.exe",
        "$placeholderHash  bas-agent-windows-amd64-setup.zip",
        "$placeholderHash  bas-agent-windows-legacy-amd64-setup.zip",
        "$placeholderHash  bas-agent-linux-amd64.deb",
        "$placeholderHash  bas-agent-linux-arm64.deb",
        "$placeholderHash  bas-agent-linux-amd64.rpm"
    ) -join "`n")
    # CMD is required: "docker create <image>" with no override command
    # fails with "No command specified" on a FROM-scratch image that
    # defines neither CMD nor ENTRYPOINT. The binary path never has to
    # exist -- docker only validates it at `docker start`, which this
    # fixture never calls.
    Set-Content -Path "$ctx\Dockerfile" -Value "FROM scratch`nCOPY agents /agents`nCMD [`"/nonexistent`"]`n"
    docker build -q -t $Tag $ctx | Out-Null
    Remove-Item $ctx -Recurse -Force -ErrorAction SilentlyContinue
}
```

- [ ] **Step 2: Run the existing test suite to confirm the fixture change alone doesn't break anything**

```powershell
cd packaging/signing
Invoke-Pester verify-orchestrator-artifacts.Tests.ps1
```

Expected: the "regenerates BINARIES.sha256 with only the 2 Windows
entries changed..." test **still passes** at this point (it only
asserts the 2 exe entries and the darwin/linux-raw entries; the fixture
now also carries 3 Linux-package + the exact-same 2 zip placeholder
lines it never looks at, so adding them doesn't yet break anything —
this is the "write the failing test first" step's RED equivalent for
the *fixture*, confirming it's additive before Step 3 changes the
function under test).

- [ ] **Step 3: Write the failing test for the 2 zip entries**

In `packaging/signing/verify-orchestrator-artifacts.Tests.ps1`, replace
the `It "regenerates BINARIES.sha256 with only the 2 Windows entries
changed, matching the actual signed bytes, and re-signs it"` block
(the one immediately after the `"patches the image..."` block) with:

```powershell
It "regenerates BINARIES.sha256 so every signed-or-rebuilt entry matches the actual bytes the image now serves, and leaves every other entry untouched" {
    $extractDir = Join-Path $env:TEMP "orch-patch-manifest-$(Get-Random)"
    New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
    $cid = docker create $script:FixtureTag
    foreach ($f in @("BINARIES.sha256", "BINARIES.sha256.sig",
                     "bas-agent-windows-amd64.exe", "bas-agent-windows-legacy-amd64.exe",
                     "bas-agent-windows-amd64-setup.zip", "bas-agent-windows-legacy-amd64-setup.zip")) {
        docker cp "${cid}:/agents/$f" "$extractDir\$f" | Out-Null
    }
    docker rm $cid | Out-Null

    $manifestLines = Get-Content "$extractDir\BINARIES.sha256"
    function Get-ManifestHash($filename) {
        $line = $manifestLines | Where-Object { $_ -match [regex]::Escape($filename) + '$' }
        ($line -replace '\s.*$', '')
    }

    # Signed or rebuilt by Update-OrchestratorAgentArtifacts -- manifest
    # hash must equal SHA-256 of the actual bytes the image now serves,
    # extracted fresh from the image rather than assumed from whichever
    # source file the function happened to copy from.
    foreach ($f in @("bas-agent-windows-amd64.exe", "bas-agent-windows-legacy-amd64.exe",
                     "bas-agent-windows-amd64-setup.zip", "bas-agent-windows-legacy-amd64-setup.zip")) {
        $actual = (Get-FileHash -Path "$extractDir\$f" -Algorithm SHA256).Hash.ToLower()
        Get-ManifestHash $f | Should Be $actual
    }

    # Never touched by Update-OrchestratorAgentArtifacts -- must still be
    # the placeholder fixture hash, proving the function didn't
    # accidentally recompute, drop, or reorder these lines.
    $placeholderHash = ("0" * 64)
    foreach ($f in @("bas-agent-linux-amd64", "bas-agent-linux-arm64",
                     "bas-agent-darwin-amd64", "bas-agent-darwin-arm64",
                     "bas-agent-linux-amd64.deb", "bas-agent-linux-arm64.deb", "bas-agent-linux-amd64.rpm")) {
        Get-ManifestHash $f | Should Be $placeholderHash
    }

    # The .sig must exist and be non-empty -- if it were still the
    # pre-patch signature, verifying the now-different manifest bytes
    # against it would fail at orchestrator startup.
    (Get-Item "$extractDir\BINARIES.sha256.sig").Length | Should BeGreaterThan 0

    # I3 (carried over from C2): the customer ZIP's own copy, and the
    # orchestrator/agents staging copy windows-build.ps1 writes before
    # this function runs, must both match what the image now serves.
    (Get-Content (Join-Path $script:OutDir "BINARIES.sha256") -Raw) | Should Be (Get-Content "$extractDir\BINARIES.sha256" -Raw)
    (Get-Content (Join-Path $script:OutDir "BINARIES.sha256.sig") -Raw) | Should Be (Get-Content "$extractDir\BINARIES.sha256.sig" -Raw)
    $agentsStageManifest = Join-Path $script:OrchestratorDir "agents\BINARIES.sha256"
    (Get-Content $agentsStageManifest -Raw) | Should Be (Get-Content "$extractDir\BINARIES.sha256" -Raw)

    Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
}
```

- [ ] **Step 4: Run it and confirm it fails on the 2 zip assertions**

```powershell
Invoke-Pester verify-orchestrator-artifacts.Tests.ps1 -TestName "*every signed-or-rebuilt entry*"
```

Expected: **FAIL** — the two `Get-ManifestHash $f | Should Be $actual`
assertions for `bas-agent-windows-amd64-setup.zip` and
`bas-agent-windows-legacy-amd64-setup.zip` fail, because today's
`$replacements` map (lines 137-140 of `sign-orchestrator-artifacts.ps1`)
never updates those 2 lines — they're still the all-zero placeholder
from the fixture, not the actual rebuilt zip's hash. The 7 "untouched"
assertions and the 2 exe assertions still pass.

- [ ] **Step 5: Fix `Update-OrchestratorAgentArtifacts`**

In `packaging/signing/sign-orchestrator-artifacts.ps1`, replace the
`$replacements` block (currently 2 entries, around line 137-140):

```powershell
        $replacements = @{
            "bas-agent-windows-amd64.exe"        = (Get-FileHash -Path $artifacts["bas-agent-windows-amd64.exe"] -Algorithm SHA256).Hash.ToLower()
            "bas-agent-windows-legacy-amd64.exe" = (Get-FileHash -Path $artifacts["bas-agent-windows-legacy-amd64.exe"] -Algorithm SHA256).Hash.ToLower()
        }
```

with:

```powershell
        $replacements = @{
            "bas-agent-windows-amd64.exe"              = (Get-FileHash -Path $artifacts["bas-agent-windows-amd64.exe"] -Algorithm SHA256).Hash.ToLower()
            "bas-agent-windows-legacy-amd64.exe"       = (Get-FileHash -Path $artifacts["bas-agent-windows-legacy-amd64.exe"] -Algorithm SHA256).Hash.ToLower()
            # C3: both zips are rebuilt above (lines ~108-120) with freshly
            # signed content before this point -- their manifest entries
            # must be regenerated here too, or a signed build would ship a
            # manifest hashing the pre-signing zip while serving the
            # post-signing one. bas-agent-windows-amd64-setup.zip has no
            # $artifacts entry (it only ever exists as the freshly rebuilt
            # copy in $patchCtx, never a pre-existing $OutDir source), so
            # it's hashed from there directly.
            "bas-agent-windows-amd64-setup.zip"        = (Get-FileHash -Path (Join-Path $patchCtx "bas-agent-windows-amd64-setup.zip") -Algorithm SHA256).Hash.ToLower()
            "bas-agent-windows-legacy-amd64-setup.zip" = (Get-FileHash -Path $artifacts["bas-agent-windows-legacy-amd64-setup.zip"] -Algorithm SHA256).Hash.ToLower()
        }
```

- [ ] **Step 6: Run the test again and confirm it passes**

```powershell
Invoke-Pester verify-orchestrator-artifacts.Tests.ps1 -TestName "*every signed-or-rebuilt entry*"
```

Expected: **PASS** — all 4 signed/rebuilt entries now match the actual
image bytes, all 7 untouched entries remain the placeholder hash.

- [ ] **Step 7: Run the full file's test suite**

```powershell
Invoke-Pester verify-orchestrator-artifacts.Tests.ps1
```

Expected: all `It` blocks pass, including `"patches the image so each
extracted artifact carries a valid Authenticode signature"` (unaffected
— it tests the zip *rebuild*, not the manifest, which this task doesn't
touch) and the thumbprint-mismatch / missing-artifact / stale-signature
negative tests (unaffected — none of them reach the `$replacements`
code path).

- [ ] **Step 8: Run the full existing Pester suite**

```powershell
Invoke-Pester packaging\signing\sign-windows.Tests.ps1,packaging\signing\verify-windows-signature.Tests.ps1,packaging\signing\verify-release.Tests.ps1,packaging\signing\sign-orchestrator-artifacts.Tests.ps1,packaging\signing\verify-orchestrator-artifacts.Tests.ps1
```

Expected: `Passed: 29, Failed: 0` plus however many new assertions this
task added (the suite's total count will be higher than 29 — what
matters is `Failed: 0`).

- [ ] **Step 9: Commit**

```bash
git add packaging/signing/sign-orchestrator-artifacts.ps1 packaging/signing/verify-orchestrator-artifacts.Tests.ps1
git commit -m "fix(signing): keep setup-zip manifest entries truthful after the signing patch (C3)"
```

---

## Final Verification

```powershell
# Syntax (Dockerfile has no native syntax checker here; `docker build`
# in Task 1 Step 2 already proved it parses and builds).
powershell -Command "Invoke-Pester packaging\signing\sign-windows.Tests.ps1,packaging\signing\verify-windows-signature.Tests.ps1,packaging\signing\verify-release.Tests.ps1,packaging\signing\sign-orchestrator-artifacts.Tests.ps1,packaging\signing\verify-orchestrator-artifacts.Tests.ps1"
cd orchestrator
go test ./...
```

Expected: Pester suite green (`Failed: 0`); `go test ./...` passes with
no failures across the whole module, not just the `api` package Task 2
touched.

Task 1's own Step 2-3 (the real `docker build` + manifest inspection)
is this plan's equivalent of an integration test and should be
re-confirmed green here too if enough time has passed since it last ran
that the Dockerfile could plausibly have drifted (e.g. a rebase, or a
long gap between Task 1 and reaching this point).
