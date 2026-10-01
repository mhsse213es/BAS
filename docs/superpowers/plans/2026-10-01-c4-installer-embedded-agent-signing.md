# C4: Installer-Embedded Agent Signing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the agent binary `installer\bas_agent.exe` embeds (via `go:embed`) and the standalone `bas-agent-windows-amd64.exe` artifact byte-identical and signed exactly once, instead of two independent builds that are only coincidentally expected to match.

**Architecture:** Build the agent once, sign that one file, build the installer (which now embeds signed bytes), then copy the same signed file to the standalone artifact path instead of rebuilding it. Add an unconditional hash-equality assertion between the two on-disk copies as a tripwire against regression.

**Tech Stack:** PowerShell 5.1, `signtool.exe` via the existing `Invoke-AuthenticodeSigning` (packaging/signing/sign-windows.ps1), Go (agent build, unchanged compiler flags).

**Spec:** `docs/superpowers/specs/2026-10-01-c4-installer-embedded-agent-signing-design.md`

## Global Constraints

- Single file touched: `packaging/windows-build.ps1`. No changes to `packaging/signing/sign-orchestrator-artifacts.ps1`, `Update-OrchestratorAgentArtifacts`, `orchestrator/Dockerfile`, or the legacy agent build (`agent-legacy/`).
- Signing gating semantics are unchanged from the existing D1 convention: cert present + sign fails → `Err` if `$WindowsSigningRequired`, else `Warn` and continue unsigned; no cert + required → `Err`; no cert + not required → `Warn`, continue unsigned.
- The hash-equality assertion between `installer\bas_agent.exe` and `$OutDir\bas-agent-windows-amd64.exe` is unconditional (not gated by `$WindowsSigningRequired`) — it is a build-construction invariant, not a signing policy.
- No Pester harness exists for `windows-build.ps1` (established precedent from D1/C2's own build-order task) — this task is verified entirely by a real end-to-end build dry run.
- `$WindowsArtifactsToSign` (the full 3-artifact list) must still be the list passed to step 7c's `Invoke-ReleaseVerification` — only the bulk-sign loop gets the narrower list.

## Review Focus

- **A dev build with a real certificate present (but `$WindowsSigningRequired = $false`) must still sign the embed source** — "not required" changes what happens on failure, not whether signing is attempted. Verified in Task 1's Step 7 (sub-step 5 of the E2E dry run).
- **The bulk-sign loop must sign exactly 2 artifacts (installer EXE, legacy agent), not 3 or 1** — a filter typo in the new exclusion list would either re-sign the pre-signed standalone (silently breaking the hash-equality invariant via a fresh timestamp token) or accidentally exclude a different artifact entirely. Verified in Task 1's Step 7 (sub-step 2): the "Signing N Windows executable(s)" log line must report 2.
- **A required build whose certificate thumbprint doesn't resolve must abort before the installer is ever built** — not proceed to embed an unsigned binary and fail later (or not fail at all). Verified in Task 1's Step 7 (sub-step 6): a bogus thumbprint must exit 1 and leave `BASAgent-Setup-$Version.exe` never created.
- **A bare dev build with no certificate at all must still complete, with both copies left consistently unsigned** — not abort, and not diverge from each other. Verified in Task 1's Step 7 (sub-step 7).

---

## Task 1: Sign the agent once, before the installer embeds it

**Files:**
- Modify: `packaging/windows-build.ps1:262-415` (section 5a: agent/installer build, and the `$WindowsArtifactsToSign` bulk-sign loop)

**Interfaces:**
- Consumes: `Invoke-AuthenticodeSigning(Path, CertThumbprint, [CertStoreLocation], [TimestampUrl], [SignToolPath]) -> [bool]` (existing, from `packaging/signing/sign-windows.ps1`, unchanged).
- Produces: nothing new consumed by other tasks — this plan has only one task, and no other file depends on this change's internals (C2's `Update-OrchestratorAgentArtifacts` already consumes `$OutDir\bas-agent-windows-amd64.exe` and `$OutDir\BASAgent-Setup-$Version.exe` by path, unchanged).

No test cycle in the classic RED/GREEN sense — like D1 and C2's own `windows-build.ps1` wiring tasks, this script has no test harness of its own. Each step below is a direct edit; Step 7 is the end-to-end dry run that proves all of them together.

- [ ] **Step 1: Move the `sign-windows.ps1` dot-source earlier**

Find, in the "-- 5d. Sign Windows executables (D1) --" section:

```powershell
. "$RepoRoot\packaging\signing\sign-windows.ps1"
```

Delete that line from its current position (immediately before the comment `# verify-windows-signature.ps1 defines Test-AuthenticodeSignature, which`). Insert it instead immediately before the "-- 5a. Build Windows agent binary + installer EXE --" section header, so the file reads:

```powershell
. "$RepoRoot\packaging\signing\sign-windows.ps1"

# -- 5a. Build Windows agent binary + installer EXE ---------------------------
Log "Building Windows agent binary..."
$AgentDir     = Join-Path $RepoRoot "agent"
$InstallerDir = Join-Path $RepoRoot "installer"
```

The "-- 5d --" section header now starts directly with the comment about `verify-windows-signature.ps1` (that file's own dot-source stays exactly where it is — nothing before this point needs `Test-AuthenticodeSignature`).

- [ ] **Step 2: Add `CGO_ENABLED=0` to the agent build, for parity with the Dockerfile**

Find:

```powershell
Push-Location $AgentDir
$env:GOOS = "windows"; $env:GOARCH = "amd64"
```

(This is the build that outputs to `installer\bas_agent.exe`.) Change to:

```powershell
Push-Location $AgentDir
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
```

And find the matching cleanup a few lines later:

```powershell
$env:GOOS = ""; $env:GOARCH = ""
Pop-Location
Log "  Agent binary built: installer\bas_agent.exe"
```

Change the first line to also clear `CGO_ENABLED`:

```powershell
$env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""
Pop-Location
Log "  Agent binary built: installer\bas_agent.exe"
```

- [ ] **Step 3: Sign the agent binary immediately after building it, before the installer embeds it**

Immediately after the block from Step 2 (right after `Log "  Agent binary built: installer\bas_agent.exe"`, and before the blank line that precedes `Log "Building installer EXE (embeds the single agent binary)..."`), insert:

```powershell

# C4: sign the agent binary HERE, before the installer embeds it via
# go:embed, so the installer's embedded copy and the standalone artifact
# built further below are the exact same signed bytes -- not two
# independent builds that happen to both get signed later. Mirrors the
# Dockerfile's own build-once-then-cp pattern (orchestrator/Dockerfile:
# 34,47), which never had this problem because it only ever builds the
# agent once.
if ($WindowsCertThumbprint) {
    $agentSigned = Invoke-AuthenticodeSigning -Path "$InstallerDir\bas_agent.exe" -CertThumbprint $WindowsCertThumbprint
    if (-not $agentSigned -and $WindowsSigningRequired) {
        Err "Authenticode signing failed for installer\bas_agent.exe and Windows signing is required for this build."
    } elseif (-not $agentSigned) {
        Warn "Authenticode signing failed for installer\bas_agent.exe (not required for this build -- continuing)."
    } else {
        Log "  installer\bas_agent.exe signed (embedded by the installer build below)."
    }
} elseif ($WindowsSigningRequired) {
    Err "Windows signing is required for this build (customer build) but -WindowsCertThumbprint / BAS_WINDOWS_CERT_THUMBPRINT is not set."
} else {
    Warn "No Windows signing certificate configured -- installer\bas_agent.exe will not be signed (dev build, not required)."
}
```

- [ ] **Step 4: Replace the second independent build with a copy, and assert byte-equality**

Find the entire block:

```powershell
# Also build standalone Windows agent (for manual / side-by-side deploy)
Log "Building standalone Windows agent binary..."
Push-Location $AgentDir
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
# -H windowsgui: see the comment on the installer-embedded agent build
# above -- same binary, same reason.
go build -ldflags="-s -w -H windowsgui" -o "$OutDir\bas-agent-windows-amd64.exe" . 2>&1
if ($LASTEXITCODE -ne 0) { Warn "Standalone Windows agent build failed." }
else {
    $wSizeMB = [math]::Round((Get-Item "$OutDir\bas-agent-windows-amd64.exe").Length / 1MB, 1)
    Log "  bas-agent-windows-amd64.exe (${wSizeMB}MB)"
}
$env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""
Pop-Location
```

Replace it entirely with:

```powershell
# Also stage the standalone Windows agent artifact (for manual / side-by-side
# deploy). Copied from the already-signed installer\bas_agent.exe, not
# rebuilt -- see the C4 comment above. A second independent build here
# would silently reintroduce the exact mismatch this fix removes (even
# with identical source and flags, re-signing a second time would embed a
# different RFC 3161 timestamp token and the two files would diverge).
Log "Staging standalone Windows agent binary..."
Copy-Item "$InstallerDir\bas_agent.exe" "$OutDir\bas-agent-windows-amd64.exe" -Force
if (-not (Test-Path "$OutDir\bas-agent-windows-amd64.exe")) {
    Warn "Standalone Windows agent staging failed."
} else {
    $wSizeMB = [math]::Round((Get-Item "$OutDir\bas-agent-windows-amd64.exe").Length / 1MB, 1)
    Log "  bas-agent-windows-amd64.exe (${wSizeMB}MB)"

    # C4's core invariant: the embed source and the standalone copy must be
    # byte-identical. Unconditional (not gated by $WindowsSigningRequired) --
    # this is a build-construction fact, not a signing policy, and under
    # this design it cannot legitimately fail.
    $embedHash = (Get-FileHash -Path "$InstallerDir\bas_agent.exe" -Algorithm SHA256).Hash
    $standaloneHash = (Get-FileHash -Path "$OutDir\bas-agent-windows-amd64.exe" -Algorithm SHA256).Hash
    if ($embedHash -ne $standaloneHash) {
        Err "installer\bas_agent.exe and bas-agent-windows-amd64.exe diverged after a copy -- this should be structurally impossible; investigate before shipping."
    }
}
```

This block sits between the installer-build block (unchanged) and the "-- 5a2. Build Legacy Windows agent binary --" section header (unchanged) — only its own content changes, nothing around it moves.

- [ ] **Step 5: Split the bulk-sign loop's list from the audit list**

Find:

```powershell
$WindowsArtifactsToSign = @(@(
    "$OutDir\BASAgent-Setup-$Version.exe",
    "$OutDir\bas-agent-windows-amd64.exe",
    "$OutDir\bas-agent-windows-legacy-amd64.exe"
) | Where-Object { Test-Path $_ })

if ($WindowsCertThumbprint) {
    Log "Signing $($WindowsArtifactsToSign.Count) Windows executable(s)..."
    foreach ($artifact in $WindowsArtifactsToSign) {
```

Insert a new line between the `$WindowsArtifactsToSign` assignment and the `if ($WindowsCertThumbprint)` block, and change the `if`/`foreach` to use the new list:

```powershell
$WindowsArtifactsToSign = @(@(
    "$OutDir\BASAgent-Setup-$Version.exe",
    "$OutDir\bas-agent-windows-amd64.exe",
    "$OutDir\bas-agent-windows-legacy-amd64.exe"
) | Where-Object { Test-Path $_ })

# bas-agent-windows-amd64.exe was already signed above, before the
# installer embedded it (C4) -- signing it again here would embed a
# fresh RFC 3161 timestamp and break the byte-identity that fix
# depends on. $WindowsArtifactsToSign (the full list) still carries it
# through to step 7c's release-verification audit below; this list is
# only for the signing loop immediately following.
$WindowsArtifactsToSignNow = @($WindowsArtifactsToSign | Where-Object { $_ -notlike "*bas-agent-windows-amd64.exe" })

if ($WindowsCertThumbprint) {
    Log "Signing $($WindowsArtifactsToSignNow.Count) Windows executable(s)..."
    foreach ($artifact in $WindowsArtifactsToSignNow) {
```

The rest of that `if`/`elseif`/`else` block (the `Invoke-AuthenticodeSigning` call inside the loop, and the `elseif ($WindowsSigningRequired)` / `else` branches around it) is unchanged — do not edit anything past the `foreach` line above.

Leave the later call at `$releaseOk = Invoke-ReleaseVerification -WindowsArtifacts $WindowsArtifactsToSign ...` (step 7c) exactly as it is — it must keep using `$WindowsArtifactsToSign` (the full list), not `$WindowsArtifactsToSignNow`.

- [ ] **Step 6: PowerShell syntax check**

Run:
```powershell
cd C:\Users\Administrator\Downloads\Audspect_Cloud
$errors = $null; $tokens = $null
[System.Management.Automation.Language.Parser]::ParseFile("packaging\windows-build.ps1", [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count -eq 0) { Write-Host "SYNTAX OK" } else { $errors | ForEach-Object { Write-Host $_.Message } }
```
Expected: `SYNTAX OK`

- [ ] **Step 7: Verify with a real end-to-end dry run**

No Pester harness exists for this file — this step is this task's entire test cycle, exercising every Review Focus item above.

1. Generate and trust a throwaway test certificate:
   ```powershell
   $cert = New-SelfSignedCertificate -Subject "CN=BAS C4 E2E Test" -Type CodeSigningCert `
       -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage DigitalSignature -NotAfter (Get-Date).AddDays(1)
   foreach ($storeSpec in @(@("Root","LocalMachine"), @("TrustedPublisher","LocalMachine"))) {
       $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeSpec[0], $storeSpec[1])
       $s.Open("ReadWrite"); $s.Add($cert); $s.Close()
   }
   ```
2. Run a required build with that cert:
   ```powershell
   .\packaging\windows-build.ps1 -Version "0.0.0-c4-e2e" -WindowsCertThumbprint $cert.Thumbprint -WindowsSigningRequired $true -GpgSigningRequired $false
   ```
   Expected: completes; logs `installer\bas_agent.exe signed (embedded by the installer build below).`; logs `Signing 2 Windows executable(s)...` (Review Focus item 2 — confirms `$WindowsArtifactsToSignNow` excluded exactly one artifact); does **not** log the "diverged" `Err` message.
3. Confirm the two on-disk copies are byte-identical (the core invariant, checked directly rather than only trusting the build's own internal assertion):
   ```powershell
   (Get-FileHash "installer\bas_agent.exe" -Algorithm SHA256).Hash -eq (Get-FileHash "dist\bas-install-0.0.0-c4-e2e\bas-agent-windows-amd64.exe" -Algorithm SHA256).Hash
   ```
   Expected: `True`
4. Confirm the orchestrator's served copy (C2's own patch, already working) still carries a valid signature now that its bytes actually match the embed source:
   ```powershell
   $cid = docker create bas-orchestrator:0.0.0-c4-e2e
   docker cp "${cid}:/agents/bas-agent-windows-amd64.exe" "$env:TEMP\c4-check.exe"
   docker rm $cid
   (Get-AuthenticodeSignature -FilePath "$env:TEMP\c4-check.exe").Status
   ```
   Expected: `Valid`
5. Confirm Review Focus item 1 (dev build with a cert present, not required, still signs) by re-running with `-SkipBuild` against the already-built image and no `-WindowsSigningRequired`:
   ```powershell
   docker tag bas-orchestrator:0.0.0-c4-e2e bas-orchestrator:0.0.0-c4-e2e-dev
   .\packaging\windows-build.ps1 -Version "0.0.0-c4-e2e-dev" -WindowsCertThumbprint $cert.Thumbprint -GpgSigningRequired $false -SkipBuild
   ```
   Expected: completes; logs `installer\bas_agent.exe signed...` (not the Warn branch).
6. Confirm Review Focus item 3 (a required build with a thumbprint that doesn't resolve aborts before the installer is built):
   ```powershell
   Remove-Item "dist\bas-install-0.0.0-c4-e2e-badcert" -Recurse -Force -ErrorAction SilentlyContinue
   & .\packaging\windows-build.ps1 -Version "0.0.0-c4-e2e-badcert" -WindowsCertThumbprint "0000000000000000000000000000000000000000" -WindowsSigningRequired $true -GpgSigningRequired $false
   $exitCode = $LASTEXITCODE
   Write-Host "Exit code: $exitCode"
   Test-Path "dist\bas-install-0.0.0-c4-e2e-badcert\BASAgent-Setup-0.0.0-c4-e2e-badcert.exe"
   ```
   Expected: exit code `1`; the `Test-Path` result is `False` (the installer was never built).
7. Confirm Review Focus item 4 (bare dev build, no cert at all, still completes with both copies consistently unsigned):
   ```powershell
   .\packaging\windows-build.ps1 -Version "0.0.0-c4-e2e-bare" -GpgSigningRequired $false
   (Get-AuthenticodeSignature -FilePath "installer\bas_agent.exe").Status
   (Get-AuthenticodeSignature -FilePath "dist\bas-install-0.0.0-c4-e2e-bare\bas-agent-windows-amd64.exe").Status
   ```
   Expected: build completes; both report `NotSigned` (or equivalent "no signature present" status, not `Valid`).
8. Clean up: remove the test certificate from all 3 stores; delete `dist\bas-install-0.0.0-c4-e2e*` and `dist\bas-install-0.0.0-c4-e2e-dev*`/`-bare*`/`-badcert*`; remove the `bas-orchestrator:0.0.0-c4-e2e*` and `bas-caldera:0.0.0-c4-e2e*` image tags; delete `$env:TEMP\c4-check.exe`; revert any incidental `orchestrator/agents/BINARIES.sha256(.sig)` changes with `git checkout --` (the same test-pollution pattern encountered throughout D1/C2's own verification).

- [ ] **Step 8: Commit**

```bash
git add packaging/windows-build.ps1
git commit -m "fix(signing): sign the agent once, before the installer embeds it (C4)"
```

---

## Final Verification

```powershell
$errors = $null; $tokens = $null
[System.Management.Automation.Language.Parser]::ParseFile("packaging\windows-build.ps1", [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count -eq 0) { Write-Host "Syntax OK" }
powershell -Command "Invoke-Pester packaging\signing\sign-windows.Tests.ps1,packaging\signing\verify-windows-signature.Tests.ps1,packaging\signing\verify-release.Tests.ps1,packaging\signing\sign-orchestrator-artifacts.Tests.ps1,packaging\signing\verify-orchestrator-artifacts.Tests.ps1"
```

Expected: `Syntax OK`; the full existing Pester suite still passes 29/29 (unaffected — this task touches no file any of those tests cover). Task 1's own Step 7 end-to-end dry run is this plan's equivalent of an integration test and should also be re-confirmed green at this point if time has passed since it was last run.

Then use `superpowers:finishing-a-development-branch`, as this session has throughout.
