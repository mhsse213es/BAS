# C2 Orchestrator Artifact Provenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the orchestrator's `/api/agents/download` endpoint serve the exact same Authenticode-signed Windows artifacts `windows-build.ps1` already produces for the customer ZIP, instead of a second, independently-built, unsigned copy — and fix the `docker save` ordering bug that would otherwise make this patch never reach a real customer deployment.

**Architecture:** Extend the existing post-build "patch the image without recompiling" mechanism in `windows-build.ps1` (already used to bake `BINARIES.sha256.sig` in) to also inject the 4 signed Windows artifacts and a regenerated manifest, via one new PowerShell file split into a pure, directly-testable manifest-editing function and an orchestration function that stages/verifies/patches. Then move the orchestrator's `docker save` to run after that patch.

**Tech Stack:** PowerShell 5.1, Pester 3.4.0, Docker CLI (`create`/`cp`/`build`/`save`), `signtool.exe` (via existing `sign-windows.ps1`), `scripts/signer.go` (existing RSA content-integrity signer).

**Spec:** `docs/superpowers/specs/2026-10-01-c2-orchestrator-artifact-provenance-design.md`

## Global Constraints

- Reuse `$WindowsSigningRequired` exactly as D1 defined it
  (`packaging/windows-build.ps1` param block) — no new inferred-environment
  heuristic for deciding `Err` vs `Warn`.
- `Update-OrchestratorAgentArtifacts` takes no "required" parameter and
  makes no Err-vs-Warn decision itself — it returns `$true`/`$false` only,
  reporting failures via `Write-Error -ErrorAction Continue`. The call
  site in `windows-build.ps1` is the only place that branches on
  `$WindowsSigningRequired`, mirroring the existing
  `Invoke-AuthenticodeSigning` call site exactly.
- No restructuring of `orchestrator/Dockerfile` (Approach B was
  considered and rejected in the spec).
- No external artifact repository or live fetch-from-store model (this
  product ships as an offline ZIP to air-gapped on-prem customers).
- C2 consumes the signed artifacts D1 already produces. Do not add any
  second signing mechanism, and do not re-touch D1's own files
  (`sign-windows.ps1`, `verify-windows-signature.ps1`, `verify-release.ps1`)
  except to dot-source `verify-windows-signature.ps1` for re-verification.
- Do not touch: macOS (`darwin-amd64`/`darwin-arm64` stay unsigned —
  no signed equivalent exists), Linux raw binaries (no OS-native signing
  mechanism applies), C3 (`BINARIES.sha256` excluding `.zip`/`.deb`/`.rpm`
  filenames — a separate, already-logged finding; this plan's manifest
  regeneration preserves the existing 6-entry scope exactly, neither
  expanding nor narrowing it), and Docker/cosign image signing (a
  separate future finding).

## Review Focus

- **Partial injection failure leaves the image tag unchanged.** If any
  step after staging files fails (signing, manifest regen, or the patch
  `docker build` itself), `docker image inspect $OrchestratorTag` must
  still resolve to the *pre-patch* image — Docker's own `-t` semantics
  only move a tag on a fully successful build, but this must be verified
  directly against this function's actual sequence of calls, not assumed.
  Task 2's tests exercise this.
- **A replacement key with no matching manifest line must throw, not
  silently produce a manifest that doesn't match what's in the image.**
  Task 1's tests exercise this.
- **Re-verification must catch a signature `step 5d` itself didn't
  produce** — e.g. a stale file left on disk from a previous run, signed
  by a certificate that is no longer the one in use. Task 2's tests
  exercise this with a second, untrusted self-signed cert.
- **A dev build (`$WindowsSigningRequired = $false`) run with a real
  cert anyway must still succeed and inject the signed artifacts** —
  "not required" means failures are tolerated, not that success is
  declined or skipped. Task 3's end-to-end verification exercises this.
- **The saved `.tar` must reflect the patched (signed) bytes, not the
  pre-patch ones.** This is the `docker save` ordering bug itself — Task
  3's end-to-end verification `docker load`s the saved tar into a check
  and confirms the loaded image's artifacts are the signed ones, not just
  that the live local daemon's tag was patched.

---

## Task 1: Pure manifest-entry replacement function

**Files:**
- Create: `packaging/signing/sign-orchestrator-artifacts.ps1`
- Test: `packaging/signing/sign-orchestrator-artifacts.Tests.ps1`

**Interfaces:**
- Produces: `Update-BinaryManifestEntries(ManifestContent, Replacements)`
  → `[string]`. `ManifestContent` is the full text of a `sha256sum`-format
  manifest (`<hash><two spaces><filename>` per line, LF-joined).
  `Replacements` is a `[hashtable]` of `{filename -> new sha256 hex hash}`.
  Returns the manifest text with only matching lines rewritten, every
  other line byte-identical, same order, trailing newline. Throws
  (`[string]` message) if any key in `Replacements` has no matching line
  in `ManifestContent`. Consumed by Task 2.

- [ ] **Step 1: Write the failing tests**

Create `packaging/signing/sign-orchestrator-artifacts.Tests.ps1`:

```powershell
Import-Module Pester

Describe "Update-BinaryManifestEntries" {
    BeforeAll {
        $script:FakeManifest = @(
            "1c84399f0afd503d3f11efb9feb10dd406e25a0d863a59ead8bce97ad19f4693  bas-agent-linux-amd64",
            "f51262d1324c39175930fa19d792a1490c37b10c403a85b1da19fd94aee6791a  bas-agent-linux-arm64",
            "ec25ce6563807cebab327341c9e64563aca5067a69d662ffcaefac8eb9a112b9  bas-agent-windows-amd64.exe",
            "06705e14ce78d8f81eeee71f4f6b34a77388adaa75d465480f423e0d725689ae  bas-agent-darwin-amd64",
            "bdee267560b2f64b29398bc6c066ea4cbebfd4f4bd646a31f64f0138f1db7424  bas-agent-darwin-arm64",
            "944e9fdfc49888f61387a05a96d421279817d6cffca16fdbb48ba92265db58f1  bas-agent-windows-legacy-amd64.exe"
        ) -join "`n"
    }

    It "replaces only the targeted lines, leaves every other line byte-identical" {
        $replacements = @{
            "bas-agent-windows-amd64.exe"        = "1111111111111111111111111111111111111111111111111111111111111111"
            "bas-agent-windows-legacy-amd64.exe" = "2222222222222222222222222222222222222222222222222222222222222222"
        }
        $result = Update-BinaryManifestEntries -ManifestContent $script:FakeManifest -Replacements $replacements
        $lines = $result -split "`n" | Where-Object { $_ -ne "" }

        $lines.Count | Should Be 6
        ($lines | Where-Object { $_ -match "bas-agent-windows-amd64\.exe$" }) | Should Be "1111111111111111111111111111111111111111111111111111111111111111  bas-agent-windows-amd64.exe"
        ($lines | Where-Object { $_ -match "bas-agent-windows-legacy-amd64\.exe$" }) | Should Be "2222222222222222222222222222222222222222222222222222222222222222  bas-agent-windows-legacy-amd64.exe"
        ($lines | Where-Object { $_ -match "bas-agent-linux-amd64$" }) | Should Be "1c84399f0afd503d3f11efb9feb10dd406e25a0d863a59ead8bce97ad19f4693  bas-agent-linux-amd64"
        ($lines | Where-Object { $_ -match "bas-agent-linux-arm64$" }) | Should Be "f51262d1324c39175930fa19d792a1490c37b10c403a85b1da19fd94aee6791a  bas-agent-linux-arm64"
        ($lines | Where-Object { $_ -match "bas-agent-darwin-amd64$" }) | Should Be "06705e14ce78d8f81eeee71f4f6b34a77388adaa75d465480f423e0d725689ae  bas-agent-darwin-amd64"
        ($lines | Where-Object { $_ -match "bas-agent-darwin-arm64$" }) | Should Be "bdee267560b2f64b29398bc6c066ea4cbebfd4f4bd646a31f64f0138f1db7424  bas-agent-darwin-arm64"
    }

    It "preserves line order exactly" {
        $replacements = @{ "bas-agent-windows-amd64.exe" = "3333333333333333333333333333333333333333333333333333333333333333" }
        $result = Update-BinaryManifestEntries -ManifestContent $script:FakeManifest -Replacements $replacements
        $lines = $result -split "`n" | Where-Object { $_ -ne "" }
        $filenames = ($lines | ForEach-Object { ($_ -split "  ", 2)[1] }) -join ","
        $filenames | Should Be "bas-agent-linux-amd64,bas-agent-linux-arm64,bas-agent-windows-amd64.exe,bas-agent-darwin-amd64,bas-agent-darwin-arm64,bas-agent-windows-legacy-amd64.exe"
    }

    It "throws when a replacement key has no matching line in the input" {
        $replacements = @{ "bas-agent-nonexistent-file" = "4444444444444444444444444444444444444444444444444444444444444444" }
        { Update-BinaryManifestEntries -ManifestContent $script:FakeManifest -Replacements $replacements } | Should Throw
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `powershell -Command "Invoke-Pester packaging\signing\sign-orchestrator-artifacts.Tests.ps1"`
Expected: FAIL — `Update-BinaryManifestEntries` is not recognized as the name of a command (the file doesn't exist yet).

- [ ] **Step 3: Write minimal implementation**

Create `packaging/signing/sign-orchestrator-artifacts.ps1`:

```powershell
# Update-OrchestratorAgentArtifacts (defined further down this file, see
# Task 2) injects D1's Authenticode-signed Windows artifacts into the
# orchestrator Docker image after it's built, so the download endpoint
# serves the same signed bytes as the customer ZIP instead of a second,
# independently-built, unsigned copy. Update-BinaryManifestEntries is
# its pure manifest-editing core, kept separate so it can be tested
# without Docker.
# See docs/superpowers/specs/2026-10-01-c2-orchestrator-artifact-provenance-design.md.

function Update-BinaryManifestEntries {
    param(
        [Parameter(Mandatory)][string]$ManifestContent,
        [Parameter(Mandatory)][hashtable]$Replacements
    )

    $lines = $ManifestContent -split "`n" | Where-Object { $_ -ne "" }
    $matched = @{}
    $updated = foreach ($line in $lines) {
        $parts = $line -split "  ", 2
        if ($parts.Count -ne 2) { $line; continue }
        $filename = $parts[1]
        if ($Replacements.ContainsKey($filename)) {
            $matched[$filename] = $true
            "$($Replacements[$filename])  $filename"
        } else {
            $line
        }
    }

    foreach ($key in $Replacements.Keys) {
        if (-not $matched.ContainsKey($key)) {
            throw "Update-BinaryManifestEntries: no manifest line found for '$key' -- manifest shape may have changed."
        }
    }

    return ($updated -join "`n") + "`n"
}
```

- [ ] **Step 4: Dot-source the new file in the test and run again**

Add this line at the top of `packaging/signing/sign-orchestrator-artifacts.Tests.ps1`, right after `Import-Module Pester`:

```powershell
. "$PSScriptRoot\sign-orchestrator-artifacts.ps1"
```

Run: `powershell -Command "Invoke-Pester packaging\signing\sign-orchestrator-artifacts.Tests.ps1"`
Expected: PASS — 3/3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add packaging/signing/sign-orchestrator-artifacts.ps1 packaging/signing/sign-orchestrator-artifacts.Tests.ps1
git commit -m "feat(signing): add Update-BinaryManifestEntries for C2 manifest regen"
```

---

## Task 2: Orchestration function — inject signed artifacts into the image

**Files:**
- Modify: `packaging/signing/sign-orchestrator-artifacts.ps1`
- Test: `packaging/signing/verify-orchestrator-artifacts.Tests.ps1`

**Interfaces:**
- Consumes: `Update-BinaryManifestEntries(ManifestContent, Replacements)` (Task 1). `Invoke-AuthenticodeSigning` and `Test-AuthenticodeSignature` (existing, from `sign-windows.ps1` / `verify-windows-signature.ps1` — used only by this task's tests to build and verify fixture signed files; the production function below consumes only `Test-AuthenticodeSignature`).
- Produces: `Update-OrchestratorAgentArtifacts(OrchestratorTag, OutDir, Version, OrchestratorDir)` → `[bool]`. No "required" parameter (see Global Constraints). Consumed by Task 3.

- [ ] **Step 1: Write the failing tests**

Create `packaging/signing/verify-orchestrator-artifacts.Tests.ps1`:

```powershell
Import-Module Pester
. "$PSScriptRoot\sign-windows.ps1"
. "$PSScriptRoot\verify-windows-signature.ps1"
. "$PSScriptRoot\sign-orchestrator-artifacts.ps1"

# See sign-windows.Tests.ps1 for why this builds a genuinely unsigned Go
# binary instead of copying a system executable.
function New-UnsignedTestExe {
    $dir = Join-Path $env:TEMP "orch-patch-src-$(Get-Random)"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Set-Content -Path "$dir\main.go" -Value "package main`n`nfunc main() {}`n"
    Push-Location $dir
    $env:GOOS = "windows"; $env:GOARCH = "amd64"
    go build -o unsigned.exe main.go 2>&1 | Out-Null
    $env:GOOS = ""; $env:GOARCH = ""
    Pop-Location
    return "$dir\unsigned.exe"
}

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
    Set-Content -Path "$ctx\Dockerfile" -Value "FROM scratch`nCOPY agents /agents`n"
    docker build -q -t $Tag $ctx | Out-Null
    Remove-Item $ctx -Recurse -Force -ErrorAction SilentlyContinue
}

Describe "Update-OrchestratorAgentArtifacts" {
    BeforeAll {
        $script:TestCert = New-SelfSignedCertificate `
            -Subject "CN=BAS Orchestrator Patch Test" -Type CodeSigningCert `
            -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage DigitalSignature `
            -NotAfter (Get-Date).AddDays(1)
        foreach ($storeSpec in @(@("Root","LocalMachine"), @("TrustedPublisher","LocalMachine"))) {
            $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeSpec[0], $storeSpec[1])
            $s.Open("ReadWrite"); $s.Add($script:TestCert); $s.Close()
        }
        # A second, deliberately untrusted cert -- for the stale-file
        # re-verification test. Never imported into Root/TrustedPublisher.
        $script:UntrustedCert = New-SelfSignedCertificate `
            -Subject "CN=BAS Orchestrator Patch Untrusted" -Type CodeSigningCert `
            -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage DigitalSignature `
            -NotAfter (Get-Date).AddDays(1)

        $script:Version = "9.9.9-test"
        $script:OrchestratorDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..\orchestrator")).Path

        function script:New-SignedOutDir {
            $outDir = Join-Path $env:TEMP "orch-patch-outdir-$(Get-Random)"
            New-Item -ItemType Directory -Force -Path $outDir | Out-Null
            foreach ($name in @("bas-agent-windows-amd64.exe", "bas-agent-windows-legacy-amd64.exe")) {
                Copy-Item (New-UnsignedTestExe) (Join-Path $outDir $name)
            }
            Copy-Item (New-UnsignedTestExe) (Join-Path $outDir "BASAgent-Setup-$($script:Version).exe")
            foreach ($f in @("bas-agent-windows-amd64.exe", "bas-agent-windows-legacy-amd64.exe", "BASAgent-Setup-$($script:Version).exe")) {
                Invoke-AuthenticodeSigning -Path (Join-Path $outDir $f) -CertThumbprint $script:TestCert.Thumbprint -TimestampUrl "" | Out-Null
            }
            Compress-Archive -Path (Join-Path $outDir "bas-agent-windows-legacy-amd64.exe") -DestinationPath (Join-Path $outDir "bas-agent-windows-legacy-amd64-setup.zip") -Force
            return $outDir
        }

        $script:OutDir = New-SignedOutDir
        $script:FixtureTag = "bas-orchestrator-patch-fixture-$(Get-Random)"
        New-FixtureOrchestratorImage -Tag $script:FixtureTag
    }

    AfterAll {
        docker rmi $script:FixtureTag -f 2>$null | Out-Null
        Remove-Item $script:OutDir -Recurse -Force -ErrorAction SilentlyContinue
        foreach ($cert in @($script:TestCert, $script:UntrustedCert)) {
            foreach ($storeSpec in @(@("My","CurrentUser"), @("Root","LocalMachine"), @("TrustedPublisher","LocalMachine"))) {
                $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeSpec[0], $storeSpec[1])
                $s.Open("ReadWrite")
                $found = $s.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
                if ($found) { $s.Remove($found) }
                $s.Close()
            }
        }
    }

    It "patches the image so each extracted artifact carries a valid Authenticode signature" {
        $result = Update-OrchestratorAgentArtifacts -OrchestratorTag $script:FixtureTag -OutDir $script:OutDir -Version $script:Version -OrchestratorDir $script:OrchestratorDir
        $result | Should Be $true

        $extractDir = Join-Path $env:TEMP "orch-patch-extract-$(Get-Random)"
        New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
        $cid = docker create $script:FixtureTag
        docker cp "${cid}:/agents/bas-agent-windows-amd64.exe" "$extractDir\bas-agent-windows-amd64.exe" | Out-Null
        docker cp "${cid}:/agents/bas-agent-windows-legacy-amd64.exe" "$extractDir\bas-agent-windows-legacy-amd64.exe" | Out-Null
        docker rm $cid | Out-Null

        $sig1 = Get-AuthenticodeSignature -FilePath "$extractDir\bas-agent-windows-amd64.exe"
        $sig1.Status | Should Be "Valid"
        $sig1.SignerCertificate.Thumbprint | Should Be $script:TestCert.Thumbprint

        $sig2 = Get-AuthenticodeSignature -FilePath "$extractDir\bas-agent-windows-legacy-amd64.exe"
        $sig2.Status | Should Be "Valid"
        $sig2.SignerCertificate.Thumbprint | Should Be $script:TestCert.Thumbprint

        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "regenerates BINARIES.sha256 with only the 2 Windows entries changed" {
        $extractDir = Join-Path $env:TEMP "orch-patch-manifest-$(Get-Random)"
        New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
        $cid = docker create $script:FixtureTag
        docker cp "${cid}:/agents/BINARIES.sha256" "$extractDir\BINARIES.sha256" | Out-Null
        docker rm $cid | Out-Null

        $manifestLines = Get-Content "$extractDir\BINARIES.sha256"
        ($manifestLines | Where-Object { $_ -match "bas-agent-windows-amd64\.exe$" }) | Should Not Match ("^" + ("0" * 64))
        ($manifestLines | Where-Object { $_ -match "bas-agent-linux-amd64$" }) | Should Match ("^" + ("0" * 64))
        ($manifestLines | Where-Object { $_ -match "bas-agent-darwin-amd64$" }) | Should Match ("^" + ("0" * 64))

        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "returns false and does not throw when a signed artifact is missing" {
        $emptyOutDir = Join-Path $env:TEMP "orch-patch-empty-$(Get-Random)"
        New-Item -ItemType Directory -Force -Path $emptyOutDir | Out-Null
        { Update-OrchestratorAgentArtifacts -OrchestratorTag $script:FixtureTag -OutDir $emptyOutDir -Version $script:Version -OrchestratorDir $script:OrchestratorDir } | Should Not Throw
        $result = Update-OrchestratorAgentArtifacts -OrchestratorTag $script:FixtureTag -OutDir $emptyOutDir -Version $script:Version -OrchestratorDir $script:OrchestratorDir
        $result | Should Be $false
        Remove-Item $emptyOutDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "returns false when a staged artifact's signature fails re-verification (stale file, untrusted cert)" {
        $staleOutDir = New-SignedOutDir
        # Overwrite the standalone agent exe with one signed by the
        # deliberately-untrusted cert, simulating a stale file left over
        # from a different signing run.
        Invoke-AuthenticodeSigning -Path (Join-Path $staleOutDir "bas-agent-windows-amd64.exe") -CertThumbprint $script:UntrustedCert.Thumbprint -CertStoreLocation "Cert:\CurrentUser\My" -TimestampUrl "" | Out-Null

        $result = Update-OrchestratorAgentArtifacts -OrchestratorTag $script:FixtureTag -OutDir $staleOutDir -Version $script:Version -OrchestratorDir $script:OrchestratorDir
        $result | Should Be $false
        Remove-Item $staleOutDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "leaves the image tag unchanged when the patch fails after files were staged" {
        $beforeId = (docker image inspect $script:FixtureTag --format "{{.Id}}")
        $badOrchestratorDir = Join-Path $env:TEMP "orch-patch-bad-dir-$(Get-Random)"
        New-Item -ItemType Directory -Force -Path $badOrchestratorDir | Out-Null
        # No scripts/signer.go or private_key.pem here -- the RSA-signing
        # step fails after the 4 artifacts were already staged.
        $result = Update-OrchestratorAgentArtifacts -OrchestratorTag $script:FixtureTag -OutDir $script:OutDir -Version $script:Version -OrchestratorDir $badOrchestratorDir
        $result | Should Be $false
        $afterId = (docker image inspect $script:FixtureTag --format "{{.Id}}")
        $afterId | Should Be $beforeId
        Remove-Item $badOrchestratorDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `powershell -Command "Invoke-Pester packaging\signing\verify-orchestrator-artifacts.Tests.ps1"`
Expected: FAIL — `Update-OrchestratorAgentArtifacts` is not recognized as the name of a command.

- [ ] **Step 3: Write minimal implementation**

Append to `packaging/signing/sign-orchestrator-artifacts.ps1`:

```powershell
function Update-OrchestratorAgentArtifacts {
    param(
        [Parameter(Mandatory)][string]$OrchestratorTag,
        [Parameter(Mandatory)][string]$OutDir,
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][string]$OrchestratorDir
    )

    $artifacts = @{
        "bas-agent-windows-amd64.exe"              = Join-Path $OutDir "bas-agent-windows-amd64.exe"
        "bas-agent-windows-legacy-amd64.exe"       = Join-Path $OutDir "bas-agent-windows-legacy-amd64.exe"
        "bas-agent-windows-legacy-amd64-setup.zip" = Join-Path $OutDir "bas-agent-windows-legacy-amd64-setup.zip"
    }
    $installerPath = Join-Path $OutDir "BASAgent-Setup-$Version.exe"

    foreach ($path in (@($installerPath) + @($artifacts.Values))) {
        if (-not (Test-Path $path)) {
            Write-Error "Update-OrchestratorAgentArtifacts: expected signed artifact not found: $path" -ErrorAction Continue
            return $false
        }
    }

    # Re-verify signatures -- defense in depth. Do not trust that signing
    # succeeded just because it ran earlier in this same script invocation.
    foreach ($path in @($installerPath, $artifacts["bas-agent-windows-amd64.exe"], $artifacts["bas-agent-windows-legacy-amd64.exe"])) {
        $v = Test-AuthenticodeSignature -Path $path
        if (-not $v.Valid) {
            Write-Error "Update-OrchestratorAgentArtifacts: $path failed signature re-verification: $($v.Status) $($v.Reason)" -ErrorAction Continue
            return $false
        }
    }

    $patchCtx = Join-Path $env:TEMP "bas-orchestrator-patch-$(Get-Random)"
    New-Item -ItemType Directory -Force -Path $patchCtx | Out-Null
    try {
        Copy-Item $artifacts["bas-agent-windows-amd64.exe"] (Join-Path $patchCtx "bas-agent-windows-amd64.exe")
        Copy-Item $artifacts["bas-agent-windows-legacy-amd64.exe"] (Join-Path $patchCtx "bas-agent-windows-legacy-amd64.exe")
        Copy-Item $artifacts["bas-agent-windows-legacy-amd64-setup.zip"] (Join-Path $patchCtx "bas-agent-windows-legacy-amd64-setup.zip")

        # Rebuild the amd64 setup zip from the signed installer under the
        # Dockerfile's internal filename (Audspect_Agent.exe) -- same
        # installer/ source as BASAgent-Setup-$Version.exe, different
        # packaging between the two pipelines.
        $rezipDir = Join-Path $env:TEMP "bas-orchestrator-rezip-$(Get-Random)"
        New-Item -ItemType Directory -Force -Path $rezipDir | Out-Null
        Copy-Item $installerPath (Join-Path $rezipDir "Audspect_Agent.exe")
        Compress-Archive -Path (Join-Path $rezipDir "Audspect_Agent.exe") -DestinationPath (Join-Path $patchCtx "bas-agent-windows-amd64-setup.zip") -Force
        Remove-Item $rezipDir -Recurse -Force -ErrorAction SilentlyContinue

        $tmpCID = docker create $OrchestratorTag 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Update-OrchestratorAgentArtifacts: docker create failed for $OrchestratorTag" -ErrorAction Continue
            return $false
        }
        $manifestPath = Join-Path $patchCtx "BINARIES.sha256"
        docker cp "${tmpCID}:/agents/BINARIES.sha256" $manifestPath 2>$null | Out-Null
        $cpExit = $LASTEXITCODE
        docker rm $tmpCID 2>$null | Out-Null
        if ($cpExit -ne 0 -or -not (Test-Path $manifestPath)) {
            Write-Error "Update-OrchestratorAgentArtifacts: could not extract BINARIES.sha256 from $OrchestratorTag" -ErrorAction Continue
            return $false
        }

        $replacements = @{
            "bas-agent-windows-amd64.exe"        = (Get-FileHash -Path $artifacts["bas-agent-windows-amd64.exe"] -Algorithm SHA256).Hash.ToLower()
            "bas-agent-windows-legacy-amd64.exe" = (Get-FileHash -Path $artifacts["bas-agent-windows-legacy-amd64.exe"] -Algorithm SHA256).Hash.ToLower()
        }
        $manifestContent = Get-Content $manifestPath -Raw
        try {
            $updatedManifest = Update-BinaryManifestEntries -ManifestContent $manifestContent -Replacements $replacements
        } catch {
            Write-Error "Update-OrchestratorAgentArtifacts: manifest update failed: $($_.Exception.Message)" -ErrorAction Continue
            return $false
        }
        [System.IO.File]::WriteAllText($manifestPath, $updatedManifest)

        Push-Location $OrchestratorDir
        go run scripts/signer.go sign private_key.pem $manifestPath
        $signExit = $LASTEXITCODE
        Pop-Location
        if ($signExit -ne 0 -or -not (Test-Path "$manifestPath.sig")) {
            Write-Error "Update-OrchestratorAgentArtifacts: RSA signing of regenerated BINARIES.sha256 failed" -ErrorAction Continue
            return $false
        }

        [System.IO.File]::WriteAllText(
            (Join-Path $patchCtx "Dockerfile"),
            "FROM $OrchestratorTag`n" +
            "COPY bas-agent-windows-amd64.exe /agents/bas-agent-windows-amd64.exe`n" +
            "COPY bas-agent-windows-legacy-amd64.exe /agents/bas-agent-windows-legacy-amd64.exe`n" +
            "COPY bas-agent-windows-legacy-amd64-setup.zip /agents/bas-agent-windows-legacy-amd64-setup.zip`n" +
            "COPY bas-agent-windows-amd64-setup.zip /agents/bas-agent-windows-amd64-setup.zip`n" +
            "COPY BINARIES.sha256 /agents/BINARIES.sha256`n" +
            "COPY BINARIES.sha256.sig /agents/BINARIES.sha256.sig`n"
        )

        docker build -q -t $OrchestratorTag $patchCtx | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Update-OrchestratorAgentArtifacts: patch image build failed for $OrchestratorTag" -ErrorAction Continue
            return $false
        }
    } finally {
        Remove-Item -Recurse -Force $patchCtx -ErrorAction SilentlyContinue
    }

    return $true
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `powershell -Command "Invoke-Pester packaging\signing\sign-orchestrator-artifacts.Tests.ps1,packaging\signing\verify-orchestrator-artifacts.Tests.ps1"`
Expected: PASS — 8/8 tests pass (3 from Task 1, 5 from this task). Read the actual output; this task's tests build and tear down real Docker fixture images and real self-signed certificates, so confirm there's no leaked `bas-orchestrator-patch-fixture-*` image or leftover cert in `Cert:\LocalMachine\Root`/`TrustedPublisher` afterward (`docker images`, `Get-ChildItem Cert:\LocalMachine\Root | Where-Object Subject -match "BAS Orchestrator"`).

- [ ] **Step 5: Commit**

```bash
git add packaging/signing/sign-orchestrator-artifacts.ps1 packaging/signing/verify-orchestrator-artifacts.Tests.ps1
git commit -m "feat(signing): add Update-OrchestratorAgentArtifacts for C2 image patching"
```

---

## Task 3: Wire into `windows-build.ps1` and fix the `docker save` ordering

**Files:**
- Modify: `packaging/windows-build.ps1`

**Interfaces:**
- Consumes: `Update-OrchestratorAgentArtifacts(OrchestratorTag, OutDir, Version, OrchestratorDir)` (Task 2).

No isolated unit test for this task — like D1's own `windows-build.ps1`
wiring (Task 5 of the D1 plan), this script has no test harness of its
own. Verified by a real end-to-end dry run (Step 4 below), the same
precedent D1 established.

- [ ] **Step 1: Dot-source the new file**

In `packaging/windows-build.ps1`, find the existing dot-source line for
D1 (near the top of the "-- 5d. Sign Windows executables (D1)" section):

```powershell
. "$RepoRoot\packaging\signing\sign-windows.ps1"
```

Add immediately after it:

```powershell
. "$RepoRoot\packaging\signing\sign-orchestrator-artifacts.ps1"
```

- [ ] **Step 2: Replace step 5c's sig-only patch block with the new call**

Find this block in the "-- 5c. Extract BINARIES.sha256 from the Docker
image" section (it currently ends the section):

```powershell
        # Bake BINARIES.sha256.sig into the orchestrator image.
        # The sig is generated here (after the first build) so it cannot be
        # included in the initial docker build. A one-layer patch image adds it
        # without rebuilding the orchestrator — fast (no recompilation).
        if (Test-Path "$BinManifestPath.sig") {
            Log "Baking BINARIES.sha256.sig into orchestrator image..."
            $patchCtx = Join-Path $env:TEMP "bas-sig-patch-$(Get-Random)"
            New-Item -ItemType Directory -Force -Path $patchCtx | Out-Null
            Copy-Item "$BinManifestPath.sig" "$patchCtx\BINARIES.sha256.sig"
            [System.IO.File]::WriteAllText(
                "$patchCtx\Dockerfile",
                "FROM $OrchestratorTag`nCOPY BINARIES.sha256.sig /agents/BINARIES.sha256.sig`n"
            )
            docker build -q -t $OrchestratorTag $patchCtx | Out-Null
            if ($LASTEXITCODE -ne 0) { Warn "  Patch build failed - sig must be volume-mounted at deploy time." }
            else { Log "  BINARIES.sha256.sig baked into $OrchestratorTag." }
            Remove-Item -Recurse -Force $patchCtx -ErrorAction SilentlyContinue
        }
    }
}
```

Replace the `if (Test-Path "$BinManifestPath.sig") { ... }` block (keep
the two closing `}` after it, which close the outer `else`/`if` from
earlier in this section) with:

```powershell
        # C2: inject D1's signed Windows artifacts (and a manifest that
        # covers them) into the orchestrator image, in the same one-layer
        # patch this section already used for just the signature. This
        # replaces that narrower patch -- it's now folded into the richer
        # one below, which also bakes BINARIES.sha256.sig.
        $orchestratorPatched = Update-OrchestratorAgentArtifacts -OrchestratorTag $OrchestratorTag `
            -OutDir $OutDir -Version $Version -OrchestratorDir $OrchestratorDir
        if (-not $orchestratorPatched -and $WindowsSigningRequired) {
            Err "Failed to inject signed Windows artifacts into the orchestrator image, and Windows signing is required for this build."
        } elseif (-not $orchestratorPatched) {
            Warn "  Could not inject signed Windows artifacts into the orchestrator image (not required for this build) -- it will serve its own independently-built, unsigned copies."
        } else {
            Log "  Signed Windows artifacts + regenerated BINARIES.sha256 baked into $OrchestratorTag."
        }
    }
}
```

- [ ] **Step 3: Fix the `docker save` ordering**

In the "-- 4. Save Docker images" section, remove this block entirely:

```powershell
Log "  Saving $OrchestratorTag..."
docker save $OrchestratorTag -o "$OutDir\images\bas-orchestrator-$Version.tar"
if ($LASTEXITCODE -ne 0) { Err "Failed to save orchestrator image." }
$sizeMB = [math]::Round((Get-Item "$OutDir\images\bas-orchestrator-$Version.tar").Length / 1MB)
Log "  Saved: bas-orchestrator-$Version.tar (${sizeMB}MB)"

```

(Leave the `Log "Saving Docker images..."` header and the postgres/
headless-shell/caldera blocks that follow it untouched — they don't
depend on anything this plan changes.)

Then, immediately after the new `Update-OrchestratorAgentArtifacts` call
block from Step 2 above (i.e., right after its closing `}` and before the
"-- 5b. Build Linux agent binaries" section that currently follows), add:

```powershell
# Save the orchestrator image AFTER the patch above, not before --
# docker save produced the tar that install.sh actually `docker load`s on
# the customer's machine, and saving it before this patch (the original
# order) meant the shipped tar never contained the patched bytes at all,
# even though the local daemon's tag was correctly patched. One save
# call now covers every path: patched-and-required, patched-not-required,
# skipped-not-required, and plain dev build with no cert at all.
Log "  Saving $OrchestratorTag..."
docker save $OrchestratorTag -o "$OutDir\images\bas-orchestrator-$Version.tar"
if ($LASTEXITCODE -ne 0) { Err "Failed to save orchestrator image." }
$orchSizeMB = [math]::Round((Get-Item "$OutDir\images\bas-orchestrator-$Version.tar").Length / 1MB)
Log "  Saved: bas-orchestrator-$Version.tar (${orchSizeMB}MB)"
```

- [ ] **Step 4: Verify with a real end-to-end dry run**

This step empirically exercises all 5 Review Focus items for this plan,
the same way D1's own `windows-build.ps1` changes were verified (no
Pester harness exists for this file).

1. Generate a throwaway self-signed test certificate and trust it into
   `LocalMachine\Root` and `LocalMachine\TrustedPublisher` (same pattern
   used throughout D1's verification):
   ```powershell
   $cert = New-SelfSignedCertificate -Subject "CN=BAS C2 E2E Test" -Type CodeSigningCert `
       -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage DigitalSignature -NotAfter (Get-Date).AddDays(1)
   foreach ($storeSpec in @(@("Root","LocalMachine"), @("TrustedPublisher","LocalMachine"))) {
       $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeSpec[0], $storeSpec[1])
       $s.Open("ReadWrite"); $s.Add($cert); $s.Close()
   }
   ```
2. Run a build with Windows signing required:
   ```powershell
   .\packaging\windows-build.ps1 -Version "0.0.0-c2-e2e" -WindowsCertThumbprint $cert.Thumbprint -WindowsSigningRequired $true -GpgSigningRequired $false
   ```
   Expected: completes, logs "Signed Windows artifacts + regenerated
   BINARIES.sha256 baked into bas-orchestrator:0.0.0-c2-e2e."
3. Confirm the *live* image is patched:
   ```powershell
   $cid = docker create bas-orchestrator:0.0.0-c2-e2e
   docker cp "${cid}:/agents/bas-agent-windows-amd64.exe" "$env:TEMP\c2-check.exe"
   docker rm $cid
   (Get-AuthenticodeSignature -FilePath "$env:TEMP\c2-check.exe").Status
   ```
   Expected: `Valid`.
4. Confirm the **Review Focus item 5** (save-ordering) by `docker load`ing
   the saved tar into a freshly-removed tag and re-checking:
   ```powershell
   docker rmi bas-orchestrator:0.0.0-c2-e2e -f
   docker load -i "dist\bas-install-0.0.0-c2-e2e\images\bas-orchestrator-0.0.0-c2-e2e.tar"
   $cid = docker create bas-orchestrator:0.0.0-c2-e2e
   docker cp "${cid}:/agents/bas-agent-windows-amd64.exe" "$env:TEMP\c2-check-fromtar.exe"
   docker rm $cid
   (Get-AuthenticodeSignature -FilePath "$env:TEMP\c2-check-fromtar.exe").Status
   ```
   Expected: `Valid` — if this step were skipped and only step 3 were
   checked, the save-ordering bug would go uncaught (step 3 would also
   show `Valid` even with the bug present, since it reads the live
   daemon's tag before the fix, not the saved tar).
5. Confirm **Review Focus item 3** (dev build with a cert present still
   succeeds) by re-running without `-Customer`/`-CustomerID` (already the
   case above) and without `-WindowsSigningRequired $true`:
   ```powershell
   .\packaging\windows-build.ps1 -Version "0.0.0-c2-e2e-dev" -WindowsCertThumbprint $cert.Thumbprint -GpgSigningRequired $false -SkipBuild
   ```
   (Reuse an already-built orchestrator image via `-SkipBuild` for
   speed; `$WindowsSigningRequired` defaults to `$false` here since
   `-Customer`/`-CustomerID` are absent.) Expected: still logs "Signed
   Windows artifacts + regenerated BINARIES.sha256 baked into..." (not
   the Warn branch) — the artifacts get injected because they're
   present and valid, "not required" only changes what happens on
   failure.
6. Confirm the spec's **bare dev build acceptance criterion** ("behaves
   exactly as before this spec") with no certificate at all:
   ```powershell
   .\packaging\windows-build.ps1 -Version "0.0.0-c2-e2e-bare" -GpgSigningRequired $false -SkipBuild
   ```
   Expected: logs the `Warn "  Could not inject signed Windows
   artifacts..."` line (files exist but are unsigned, so
   re-verification fails; `$WindowsSigningRequired` is `$false` with no
   `-Customer`/`-CustomerID`, so this is a warning, not an abort), and
   the build completes successfully. This is the one spec acceptance
   criterion not otherwise exercised by Task 1/2's Pester tests or steps
   2-5 above.
7. Clean up: remove the test certificate from all three stores, delete
   `dist\bas-install-0.0.0-c2-e2e*`, `dist\bas-install-0.0.0-c2-e2e-dev*`,
   and `dist\bas-install-0.0.0-c2-e2e-bare*`, remove the
   `bas-orchestrator:0.0.0-c2-e2e*` image tags, delete the
   `$env:TEMP\c2-check*.exe` files. Revert any incidental
   `orchestrator/agents/BINARIES.sha256(.sig)` changes the rebuild left
   behind with `git checkout --` (the same test-pollution pattern
   encountered throughout D1's verification).

- [ ] **Step 5: Commit**

```bash
git add packaging/windows-build.ps1
git commit -m "feat(signing): wire C2 orchestrator artifact patch + fix docker save ordering"
```

---

## Task 4: Runbook update

**Files:**
- Modify: `packaging/docs/release-signing-runbook.md`

No test cycle — documentation only.

- [ ] **Step 1: Add a C2 section to the runbook**

Add this section to `packaging/docs/release-signing-runbook.md`, after
the existing "Running a production customer release" section and before
"macOS signing":

```markdown
## Orchestrator download endpoint (C2)

The orchestrator's own `/api/agents/download` endpoint used to serve
binaries built independently inside `orchestrator/Dockerfile` -- a
second, unsigned copy of the same software the customer ZIP already
signs. `windows-build.ps1` now patches the orchestrator image after
Windows signing (step "5c") so the endpoint serves the *same signed
bytes* as the ZIP: `bas-agent-windows-amd64.exe`,
`bas-agent-windows-legacy-amd64.exe`,
`bas-agent-windows-legacy-amd64-setup.zip` are copied in verbatim;
`bas-agent-windows-amd64-setup.zip` is rebuilt from the signed
`BASAgent-Setup-$Version.exe` under the image's internal filename
(`Audspect_Agent.exe`). `BINARIES.sha256` is regenerated for just the 2
changed entries and re-signed with the existing RSA key.

This only works if the orchestrator image already exists under
`$OrchestratorTag` when `windows-build.ps1` reaches this step (true for
a normal run; also true with `-SkipBuild` against a previously-built
tag, as the dev-build verification case uses).

**Still unsigned after this:** `darwin-amd64`/`darwin-arm64` (no macOS
signing pipeline exists yet -- see "macOS signing" below) and the Linux
raw binaries/`.deb`/`.rpm` packages (no OS-native signing mechanism
applies to Linux). A separate, already-logged bug
(`BINARIES.sha256` excludes `.zip`/`.deb`/`.rpm` filenames from its
integrity check entirely) means those packaged downloads may currently
fail integrity verification regardless of signing status -- that's
tracked independently, not fixed by this pipeline.

**Verifying the fix manually:**
```powershell
$cid = docker create bas-orchestrator:<version>
docker cp "${cid}:/agents/bas-agent-windows-amd64.exe" .\check.exe
docker rm $cid
(Get-AuthenticodeSignature -FilePath .\check.exe).Status   # expect: Valid
```
```

- [ ] **Step 2: Commit**

```bash
git add packaging/docs/release-signing-runbook.md
git commit -m "docs(signing): document C2 orchestrator artifact patch in the runbook"
```

---

## Final Verification

```bash
powershell -Command "Invoke-Pester packaging\signing\sign-windows.Tests.ps1,packaging\signing\verify-windows-signature.Tests.ps1,packaging\signing\verify-release.Tests.ps1,packaging\signing\sign-orchestrator-artifacts.Tests.ps1,packaging\signing\verify-orchestrator-artifacts.Tests.ps1"
powershell -Command "$null = [System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw packaging\windows-build.ps1), [ref]$null); Write-Host 'Syntax OK'"
```

Expected: all Pester tests pass — 28/28 (20 from D1, unaffected; 8 new
from this plan) — read the actual pass/fail counts, don't assume; and
the syntax check prints `Syntax OK`. Task 3's Step 4 end-to-end dry run
is this plan's equivalent of an integration test for `windows-build.ps1`
itself and should also be re-confirmed green at this point if time has
passed since it was last run.

Then use `superpowers:finishing-a-development-branch` as this session
has throughout tonight.
