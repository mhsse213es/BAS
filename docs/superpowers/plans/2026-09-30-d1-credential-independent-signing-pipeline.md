# D1 Credential-Independent Signing Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the entire D1 signing pipeline (invocation, verification, release gating, runbook, test fixtures) so it is ready to sign real artifacts the moment production credentials exist — without owning or fabricating a production certificate now.

**Architecture:** Extract Windows Authenticode signing/verification into standalone, parameterized, independently-testable scripts under `packaging/signing/`. Do the same for macOS codesign/notarize/staple, even though no macOS artifact is produced by the real pipeline yet. Wire the Windows scripts into `windows-build.ps1` behind an explicit, fail-closed `*_SIGNING_REQUIRED` gate that replaces today's silent "key happens to exist → sign, else warn and skip" behavior. Credentials (cert thumbprint/path, Apple Team ID/API key) are always parameters or environment variables passed in at call time — never hardcoded — so obtaining real credentials later is a configuration change, not a code change.

**Tech Stack:** Windows PowerShell 5.1 (`signtool.exe`, `New-SelfSignedCertificate`, `Get-AuthenticodeSignature`), Pester 3.4.0 (only version available on this build host — old `Should Be` syntax, not the newer `Should -Be`), bash (macOS scripts, GPG scripts already in the repo).

**Spec:** `docs/superpowers/specs/2026-09-30-d1-release-signing-architecture-design.md`

## Global Constraints

- No certificate or private key is ever placed in Git, the repository, the delivery ZIP, or an ordinary build artifact (spec, Key custody section).
- Credentials are always injected via parameter or environment variable at signing time — never hardcoded into a script (this plan's explicit scoping message).
- Do not buy or generate a production-shaped certificate to make the pipeline "work" — test against a locally generated self-signed test certificate instead, created and destroyed within the test run.
- `windows-build.ps1`'s existing behavior for a plain dev build (no `-Customer`/`-CustomerID`) must not start silently failing where it previously succeeded — the fail-closed gate applies to what this plan defines as a production build (see Task 4).
- macOS scripts in this plan are written correctly against Apple's documented `codesign`/`notarytool`/`stapler` interfaces but cannot be end-to-end tested in this session (no macOS host available) — their tests exercise argument construction and gating logic against mocked commands, not real `codesign` output. Say so explicitly in Task 3, don't claim more than was verified.
- Real production Authenticode signing and real Apple notarization remain blocked on Phase 0 (`docs/superpowers/plans/2026-09-30-d1-phase0-discovery-checklist.md`) — nothing in this plan requires those credentials to complete.

## Review Focus

- **Timestamp server unreachable** — `sign-windows.ps1`'s RFC 3161 timestamping depends on outbound network access to a timestamp authority; a sandboxed/offline test run must not hang or crash the whole test suite, and the production script must surface a clear, actionable error rather than a raw `signtool` exit code. Task 1's tests exercise this.
- **Self-signed test certificate leaking trust** — importing a self-signed test cert into `Cert:\LocalMachine\Root`/`TrustedPublisher` to make verification tests realistic is itself a system-trust-store mutation; it must be removed in every test's cleanup, including on a failed/aborted test run, or a stray test-only trusted root persists on the build host. Task 1's tests cover this explicitly.
- **Dev build regression** — replacing the current unconditional "warn and skip" GPG behavior with a required/optional gate must not make a bare dev invocation of `windows-build.ps1` (no `-Customer`) start failing where it previously succeeded silently. Task 4 tests this directly.
- **Tampered-after-signing detection** — a binary modified after Authenticode signing must be detected as invalid by `verify-windows-signature.ps1`, not just "unsigned" — this is the actual security property D1 exists for. Task 2 tests this with a real post-sign byte modification.
- **Multiple artifacts, one gate** — the real pipeline signs three separate Windows executables (`BASAgent-Setup-$Version.exe`, `bas-agent-windows-amd64.exe`, `bas-agent-windows-legacy-amd64.exe`); a partial failure (two sign, one doesn't) must block the release exactly like a total failure, not silently ship two-of-three signed. Task 5's wiring and Task 4's release-gate script both cover this.

## Artifact inventory

Every artifact `windows-build.ps1` produces, classified so this plan doesn't drift into a broad build-system refactor:

| Artifact | Customer-delivered? | Treatment |
|---|---|---|
| `BASAgent-Setup-$Version.exe` (installer, embeds the agent) | Yes — this is what the customer double-clicks | **MUST** be Authenticode signed (Task 5) |
| `bas-agent-windows-amd64.exe` (standalone agent) | Yes — documented "for manual / side-by-side deploy" | **MUST** be Authenticode signed (Task 5) |
| `bas-agent-windows-legacy-amd64.exe` (legacy, go1.20.14 toolchain) | Yes — zipped as `bas-agent-windows-legacy-amd64-setup.zip` for older environments | **MUST** be Authenticode signed (Task 5) |
| `bas-agent-linux-amd64` / `bas-agent-linux-arm64` (self-installing) | Yes — built by `windows-build.ps1` lines 356-377, shipped in the same bundle | No OS-native signing mechanism applies — Linux has no SmartScreen/Gatekeeper equivalent that gates a raw unsigned binary. Already covered by the existing whole-ZIP GPG signature + RSA-4096 content-integrity signature, same as the rest of the bundle. **No new work in this plan.** |
| Orchestrator Docker image (`bas-orchestrator:$Version`) | Yes, but delivered as a container image, not an installable executable | Out of scope for D1 (D1 is Windows/macOS executable trust). Already has its own optional cosign signing in `build.sh`, with the same silent-skip-if-missing pattern D1 flagged for GPG — a related but separate finding, not part of this plan. |
| macOS agent binaries | **No — not produced by `windows-build.ps1` today.** `packaging/build.sh` (the separate dev-path script) cross-compiles darwin binaries, but the real customer pipeline ships none. | D1-macOS track: build the signing/verification/notarization scripts (Task 3) so they're ready, but do not modify `windows-build.ps1` to manufacture a macOS distribution path that doesn't exist yet. Activate only when Audspect actually has a macOS customer artifact. |

The release flow this plan produces:

```
Build
  ↓
Windows artifacts
  ↓
RSA content-integrity signing (existing, unchanged)
  ↓
Authenticode signing            ← Task 1, wired in Task 5
  ↓
Authenticode verification       ← Task 2 + Task 4, release gate
  ↓
SHA-256 manifest (existing, unchanged)
  ↓
GPG final-package signing (existing, now required/optional-gated — Task 5)
  ↓
Final verification              ← Task 4's audit record
  ↓
Customer ZIP
```

---

### Task 1: Windows Authenticode signing script + tests

**Files:**
- Create: `packaging/signing/sign-windows.ps1`
- Test: `packaging/signing/sign-windows.Tests.ps1`

**Interfaces:**
- Produces: `function Invoke-AuthenticodeSigning { param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$CertThumbprint, [string]$CertStoreLocation = "Cert:\CurrentUser\My", [string]$TimestampUrl = "http://timestamp.digicert.com", [string]$SignToolPath) }` — returns `$true`/`$false`, writes `signtool`'s own output to the log. Task 5 consumes this exact signature.
- Consumes: nothing from other tasks.

- [ ] **Step 1: Write the failing test — signs a file with a self-signed test cert and the real signature is reported invalid until the cert is trusted**

```powershell
# packaging/signing/sign-windows.Tests.ps1
Import-Module Pester
. "$PSScriptRoot\sign-windows.ps1"

Describe "Invoke-AuthenticodeSigning" {
    BeforeAll {
        $script:TestCert = New-SelfSignedCertificate `
            -Subject "CN=BAS Signing Pipeline Test" `
            -Type CodeSigningCert `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -KeyUsage DigitalSignature `
            -NotAfter (Get-Date).AddDays(1)
        $script:TestFile = Join-Path $env:TEMP "sign-windows-test-$(Get-Random).exe"
        Copy-Item "$env:WINDIR\System32\notepad.exe" $script:TestFile
    }

    AfterAll {
        Remove-Item $script:TestFile -ErrorAction SilentlyContinue
        Remove-Item "Cert:\CurrentUser\My\$($script:TestCert.Thumbprint)" -ErrorAction SilentlyContinue
    }

    It "signs the file and signtool reports success" {
        $result = Invoke-AuthenticodeSigning -Path $script:TestFile `
            -CertThumbprint $script:TestCert.Thumbprint `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -TimestampUrl ""
        $result | Should Be $true
    }

    It "the signed file reports a signature is present (even if untrusted)" {
        $sig = Get-AuthenticodeSignature -FilePath $script:TestFile
        $sig.Status | Should Not Be "NotSigned"
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `powershell -Command "Invoke-Pester packaging\signing\sign-windows.Tests.ps1"`
Expected: FAIL — `Invoke-AuthenticodeSigning` is not recognized (the dot-sourced file doesn't exist yet).

- [ ] **Step 3: Write minimal implementation**

```powershell
# packaging/signing/sign-windows.ps1
#
# Invoke-AuthenticodeSigning wraps signtool.exe so the rest of the pipeline
# never shells out to signtool directly. Credentials (CertThumbprint) are
# always a parameter -- never hardcoded -- so pointing this at a real
# production certificate later is a config change, not a code change.
# See docs/superpowers/specs/2026-09-30-d1-release-signing-architecture-design.md.

function Find-SignTool {
    $candidates = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\Tools\bin\x64\signtool.exe",
        "${env:ProgramFiles(x86)}\Windows Kits\10\Tools\bin\i386\signtool.exe",
        "${env:ProgramFiles}\Windows Kits\10\Tools\bin\x64\signtool.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Invoke-AuthenticodeSigning {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$CertThumbprint,
        [string]$CertStoreLocation = "Cert:\CurrentUser\My",
        [string]$TimestampUrl = "http://timestamp.digicert.com",
        [string]$SignToolPath
    )

    if (-not (Test-Path $Path)) {
        Write-Error "Invoke-AuthenticodeSigning: file not found: $Path"
        return $false
    }

    $signtool = if ($SignToolPath) { $SignToolPath } else { Find-SignTool }
    if (-not $signtool) {
        Write-Error "Invoke-AuthenticodeSigning: signtool.exe not found. Install the Windows SDK."
        return $false
    }

    $storePath = "$CertStoreLocation\$CertThumbprint"
    if (-not (Test-Path $storePath)) {
        Write-Error "Invoke-AuthenticodeSigning: certificate $CertThumbprint not found in $CertStoreLocation."
        return $false
    }

    $args = @("sign", "/fd", "sha256", "/sha1", $CertThumbprint, "/s", ($CertStoreLocation -replace "^Cert:\\", ""))
    if ($TimestampUrl) {
        $args += @("/tr", $TimestampUrl, "/td", "sha256")
    }
    $args += $Path

    & $signtool @args
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Invoke-AuthenticodeSigning: signtool exited $LASTEXITCODE for $Path"
        return $false
    }
    return $true
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `powershell -Command "Invoke-Pester packaging\signing\sign-windows.Tests.ps1"`
Expected: 2/2 tests pass. (`-TimestampUrl ""` is used in the test to avoid a network dependency on the outbound timestamp call in this step — Step 5 below tests the timestamp path separately with a network-skip guard.)

- [ ] **Step 5: Write the network-dependent timestamp test, guarded to skip cleanly when offline**

```powershell
# Appended to packaging/signing/sign-windows.Tests.ps1, inside the same Describe block

It "signs with an RFC 3161 timestamp when the timestamp server is reachable" {
    $reachable = Test-Connection -ComputerName "timestamp.digicert.com" -Count 1 -Quiet -ErrorAction SilentlyContinue
    if (-not $reachable) {
        Set-TestInconclusive -Message "timestamp.digicert.com unreachable from this environment -- skipping"
        return
    }
    $timestampedFile = Join-Path $env:TEMP "sign-windows-ts-test-$(Get-Random).exe"
    Copy-Item "$env:WINDIR\System32\notepad.exe" $timestampedFile
    try {
        $result = Invoke-AuthenticodeSigning -Path $timestampedFile `
            -CertThumbprint $script:TestCert.Thumbprint `
            -CertStoreLocation "Cert:\CurrentUser\My"
        $result | Should Be $true
        $sig = Get-AuthenticodeSignature -FilePath $timestampedFile
        $sig.TimeStamperCertificate | Should Not Be $null
    } finally {
        Remove-Item $timestampedFile -ErrorAction SilentlyContinue
    }
}
```

Run: `powershell -Command "Invoke-Pester packaging\signing\sign-windows.Tests.ps1"`
Expected: 3/3 pass (or 2 pass + 1 inconclusive if this environment has no outbound network — read the actual output, don't assume which).

- [ ] **Step 6: Commit**

```bash
git add packaging/signing/sign-windows.ps1 packaging/signing/sign-windows.Tests.ps1
git commit -m "feat(signing): add Windows Authenticode signing script + tests"
```

---

### Task 2: Windows signature verification script + tests

**Files:**
- Create: `packaging/signing/verify-windows-signature.ps1`
- Test: `packaging/signing/verify-windows-signature.Tests.ps1`

**Interfaces:**
- Consumes: nothing from Task 1 directly (re-implements its own cert-trust setup in tests for isolation), but is designed to run against files `Invoke-AuthenticodeSigning` (Task 1) produced.
- Produces: `function Test-AuthenticodeSignature { param([Parameter(Mandatory)][string]$Path, [switch]$RequireTimestamp) }` — returns a hashtable `@{ Valid = $true/$false; Status = <Get-AuthenticodeSignature status string>; Reason = <string> }`. Task 5 (release gate) consumes this exact return shape.

- [ ] **Step 1: Write the failing test**

```powershell
# packaging/signing/verify-windows-signature.Tests.ps1
Import-Module Pester
. "$PSScriptRoot\verify-windows-signature.ps1"

Describe "Test-AuthenticodeSignature" {
    BeforeAll {
        $script:TestCert = New-SelfSignedCertificate `
            -Subject "CN=BAS Verify Pipeline Test" `
            -Type CodeSigningCert `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -KeyUsage DigitalSignature `
            -NotAfter (Get-Date).AddDays(1)
        # Trust the test cert as both root and publisher so a genuinely valid
        # chain is possible -- otherwise every self-signed test signature
        # reports UntrustedRoot regardless of whether the signing itself
        # worked, which would make this test meaningless.
        $rootStore = Get-Item "Cert:\LocalMachine\Root"
        $pubStore  = Get-Item "Cert:\LocalMachine\TrustedPublisher"
        foreach ($store in @($rootStore, $pubStore)) {
            $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($store.Name, $store.Location)
            $s.Open("ReadWrite")
            $s.Add($script:TestCert)
            $s.Close()
        }

        $script:SignedFile = Join-Path $env:TEMP "verify-test-signed-$(Get-Random).exe"
        Copy-Item "$env:WINDIR\System32\notepad.exe" $script:SignedFile
        $signtool = & "$PSScriptRoot\..\..\packaging\signing\Find-SignTool" 2>$null
        . "$PSScriptRoot\sign-windows.ps1"
        Invoke-AuthenticodeSigning -Path $script:SignedFile -CertThumbprint $script:TestCert.Thumbprint -TimestampUrl "" | Out-Null

        $script:UnsignedFile = Join-Path $env:TEMP "verify-test-unsigned-$(Get-Random).exe"
        Copy-Item "$env:WINDIR\System32\notepad.exe" $script:UnsignedFile

        $script:TamperedFile = Join-Path $env:TEMP "verify-test-tampered-$(Get-Random).exe"
        Copy-Item $script:SignedFile $script:TamperedFile
        Add-Content -Path $script:TamperedFile -Value "tampered" -Encoding Byte -ErrorAction SilentlyContinue
        [System.IO.File]::AppendAllText($script:TamperedFile, "TAMPERED")
    }

    AfterAll {
        foreach ($f in @($script:SignedFile, $script:UnsignedFile, $script:TamperedFile)) {
            Remove-Item $f -ErrorAction SilentlyContinue
        }
        foreach ($storeSpec in @(@("Root","LocalMachine"), @("TrustedPublisher","LocalMachine"), @("My","CurrentUser"))) {
            $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeSpec[0], $storeSpec[1])
            $s.Open("ReadWrite")
            $found = $s.Certificates | Where-Object { $_.Thumbprint -eq $script:TestCert.Thumbprint }
            if ($found) { $s.Remove($found) }
            $s.Close()
        }
    }

    It "reports Valid for a correctly signed, trusted file" {
        $result = Test-AuthenticodeSignature -Path $script:SignedFile
        $result.Valid | Should Be $true
        $result.Status | Should Be "Valid"
    }

    It "reports not valid for an unsigned file" {
        $result = Test-AuthenticodeSignature -Path $script:UnsignedFile
        $result.Valid | Should Be $false
    }

    It "reports not valid for a file tampered after signing" {
        $result = Test-AuthenticodeSignature -Path $script:TamperedFile
        $result.Valid | Should Be $false
        $result.Status | Should Be "HashMismatch"
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `powershell -Command "Invoke-Pester packaging\signing\verify-windows-signature.Tests.ps1"`
Expected: FAIL — `Test-AuthenticodeSignature` is not recognized.

- [ ] **Step 3: Write minimal implementation**

```powershell
# packaging/signing/verify-windows-signature.ps1
#
# Test-AuthenticodeSignature wraps Get-AuthenticodeSignature into a
# release-gate-friendly result. In production, a CA-issued cert chains to a
# root already in the Windows trust store, so a genuinely signed, untampered
# file reports Valid without any special setup -- the trust-store dance in
# this script's own tests exists only to make a *self-signed test* cert
# behave the same way for testing purposes.

function Test-AuthenticodeSignature {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$RequireTimestamp
    )

    if (-not (Test-Path $Path)) {
        return @{ Valid = $false; Status = "FileNotFound"; Reason = "File not found: $Path" }
    }

    $sig = Get-AuthenticodeSignature -FilePath $Path
    $statusStr = $sig.Status.ToString()

    if ($sig.Status -ne "Valid") {
        return @{ Valid = $false; Status = $statusStr; Reason = $sig.StatusMessage }
    }

    if ($RequireTimestamp -and -not $sig.TimeStamperCertificate) {
        return @{ Valid = $false; Status = "MissingTimestamp"; Reason = "Signature is valid but carries no RFC 3161 timestamp." }
    }

    return @{ Valid = $true; Status = $statusStr; Reason = "" }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `powershell -Command "Invoke-Pester packaging\signing\verify-windows-signature.Tests.ps1"`
Expected: 3/3 pass.

- [ ] **Step 5: Commit**

```bash
git add packaging/signing/verify-windows-signature.ps1 packaging/signing/verify-windows-signature.Tests.ps1
git commit -m "feat(signing): add Windows signature verification script + tests"
```

---

### Task 3: macOS codesign/notarize/staple scripts (structurally correct, mock-tested — no macOS host available)

**Files:**
- Create: `packaging/signing/sign-macos.sh`
- Create: `packaging/signing/verify-macos-signature.sh`
- Test: `packaging/signing/sign-macos.test.sh` (bash test harness with mocked `codesign`/`xcrun` commands — this repo has no existing shell-test framework, so this is a small self-contained assert-based script, not a formal framework)

**Interfaces:**
- Produces: `sign_macos <path> <identity> <team_id> <notary_profile>` (shell function, sourced) — signs, submits for notarization, staples, and returns 0/1. `verify_macos_signature <path>` — returns 0 if `codesign --verify` and `spctl --assess` both pass, non-zero otherwise, printing the reason.
- Consumes: nothing from earlier tasks.

**Honesty note for this task:** this session runs on a Windows host with no macOS available. The tests below mock `codesign`/`xcrun` as shell functions the script under test calls instead of the real Apple tools, and assert the *invocation* (correct flags, correct ordering: sign → notarize → staple, correct failure propagation) is right. They do **not** prove the real `codesign`/`notarytool`/`stapler` binaries would accept these exact invocations — that can only be verified on an actual Mac, which is part of what stays blocked on Phase 0 credentials and macOS build-host access. Say this in the task's commit message and in the runbook (Task 6), not just here.

- [ ] **Step 1: Write the failing mock-based test**

```bash
#!/usr/bin/env bash
# packaging/signing/sign-macos.test.sh
set -euo pipefail

TESTDIR="$(mktemp -d)"
trap 'rm -rf "$TESTDIR"' EXIT

# Mock codesign and xcrun as functions that log their invocation instead of
# doing real work -- this proves the script calls them correctly, not that
# Apple's real tools would accept the call (no macOS host in this session).
CALL_LOG="$TESTDIR/calls.log"
codesign() { echo "codesign $*" >> "$CALL_LOG"; return 0; }
xcrun() { echo "xcrun $*" >> "$CALL_LOG"; return 0; }
export -f codesign xcrun

# shellcheck disable=SC1091
source "$(dirname "$0")/sign-macos.sh"

touch "$TESTDIR/bas-agent-darwin-amd64"

echo "TEST: sign_macos calls codesign, then notarytool submit, then stapler staple, in order"
sign_macos "$TESTDIR/bas-agent-darwin-amd64" "Developer ID Application: Audspect (TEAMID)" "TEAMID" "notary-profile"
mapfile -t calls < "$CALL_LOG"
[ "${#calls[@]}" -eq 3 ] || { echo "FAIL: expected 3 calls, got ${#calls[@]}"; exit 1; }
[[ "${calls[0]}" == codesign* ]] || { echo "FAIL: call 1 was not codesign: ${calls[0]}"; exit 1; }
[[ "${calls[1]}" == *"notarytool submit"* ]] || { echo "FAIL: call 2 was not notarytool submit: ${calls[1]}"; exit 1; }
[[ "${calls[2]}" == *"stapler staple"* ]] || { echo "FAIL: call 3 was not stapler staple: ${calls[2]}"; exit 1; }
echo "PASS"

echo "TEST: sign_macos returns non-zero and skips later steps if codesign fails"
: > "$CALL_LOG"
codesign() { echo "codesign $*" >> "$CALL_LOG"; return 1; }
export -f codesign
if sign_macos "$TESTDIR/bas-agent-darwin-amd64" "Developer ID Application: Audspect (TEAMID)" "TEAMID" "notary-profile"; then
    echo "FAIL: sign_macos should have returned non-zero when codesign fails"
    exit 1
fi
mapfile -t calls < "$CALL_LOG"
[ "${#calls[@]}" -eq 1 ] || { echo "FAIL: expected sign_macos to stop after the failed codesign call, got ${#calls[@]} calls"; exit 1; }
echo "PASS"

echo "ALL TESTS PASSED"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash packaging/signing/sign-macos.test.sh`
Expected: FAIL — `sign-macos.sh` doesn't exist yet, `source` errors.

- [ ] **Step 3: Write minimal implementation**

```bash
#!/usr/bin/env bash
# packaging/signing/sign-macos.sh
#
# sign_macos wraps codesign -> notarytool submit -> stapler staple. Written
# against Apple's documented interface but not end-to-end tested against the
# real tools in this session -- no macOS host was available. Credentials
# (identity, team_id, notary_profile) are always parameters, never
# hardcoded, matching sign-windows.ps1's pattern. See
# docs/superpowers/specs/2026-09-30-d1-release-signing-architecture-design.md.

sign_macos() {
    local path="$1" identity="$2" team_id="$3" notary_profile="$4"

    if [ ! -f "$path" ]; then
        echo "sign_macos: file not found: $path" >&2
        return 1
    fi

    codesign --sign "$identity" --timestamp --options runtime "$path" || {
        echo "sign_macos: codesign failed for $path" >&2
        return 1
    }

    xcrun notarytool submit "$path" --keychain-profile "$notary_profile" --team-id "$team_id" --wait || {
        echo "sign_macos: notarytool submit failed for $path" >&2
        return 1
    }

    xcrun stapler staple "$path" || {
        echo "sign_macos: stapler staple failed for $path" >&2
        return 1
    }

    return 0
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bash packaging/signing/sign-macos.test.sh`
Expected: `ALL TESTS PASSED`.

- [ ] **Step 5: Write the verification script (no separate test — thin wrapper, exercised by Task 4's release-gate tests instead via a mock)**

```bash
#!/usr/bin/env bash
# packaging/signing/verify-macos-signature.sh
#
# Same honesty note as sign-macos.sh: written against Apple's documented
# interface, not verified against real codesign/spctl output in this
# session (no macOS host available).

verify_macos_signature() {
    local path="$1"

    if [ ! -f "$path" ]; then
        echo "verify_macos_signature: file not found: $path" >&2
        return 1
    fi

    if ! codesign --verify --deep --strict "$path" 2>&1; then
        echo "verify_macos_signature: codesign --verify failed for $path" >&2
        return 1
    fi

    if ! spctl --assess --type execute "$path" 2>&1; then
        echo "verify_macos_signature: spctl --assess failed for $path (not notarized or not stapled)" >&2
        return 1
    fi

    return 0
}
```

- [ ] **Step 6: Commit**

```bash
git add packaging/signing/sign-macos.sh packaging/signing/verify-macos-signature.sh packaging/signing/sign-macos.test.sh
git commit -m "feat(signing): add macOS codesign/notarize/staple scripts (mock-tested, no macOS host in this session)"
```

---

### Task 4: Release-gate configuration + release-verification/audit script

**Files:**
- Create: `packaging/signing/verify-release.ps1`
- Test: `packaging/signing/verify-release.Tests.ps1`

**Interfaces:**
- Consumes: `Test-AuthenticodeSignature` from `verify-windows-signature.ps1` (Task 2) — same signature.
- Produces: `function Invoke-ReleaseVerification { param([string[]]$WindowsArtifacts, [bool]$WindowsSigningRequired, [string]$AuditRecordPath) }` — returns `$true`/`$false`; on completion (pass or fail) writes a JSON audit record to `$AuditRecordPath` per the spec's Auditability section (version, artifact hashes, signer result, timestamp). Task 5 consumes this exact signature and the boolean return to gate the release.

- [ ] **Step 1: Write the failing test**

```powershell
# packaging/signing/verify-release.Tests.ps1
Import-Module Pester
. "$PSScriptRoot\sign-windows.ps1"
. "$PSScriptRoot\verify-windows-signature.ps1"
. "$PSScriptRoot\verify-release.ps1"

Describe "Invoke-ReleaseVerification" {
    BeforeAll {
        $script:TestCert = New-SelfSignedCertificate `
            -Subject "CN=BAS Release Gate Test" -Type CodeSigningCert `
            -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage DigitalSignature `
            -NotAfter (Get-Date).AddDays(1)
        $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
        $rootStore.Open("ReadWrite"); $rootStore.Add($script:TestCert); $rootStore.Close()
        $pubStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "LocalMachine")
        $pubStore.Open("ReadWrite"); $pubStore.Add($script:TestCert); $pubStore.Close()

        $script:SignedFile = Join-Path $env:TEMP "release-gate-signed-$(Get-Random).exe"
        Copy-Item "$env:WINDIR\System32\notepad.exe" $script:SignedFile
        Invoke-AuthenticodeSigning -Path $script:SignedFile -CertThumbprint $script:TestCert.Thumbprint -TimestampUrl "" | Out-Null

        $script:UnsignedFile = Join-Path $env:TEMP "release-gate-unsigned-$(Get-Random).exe"
        Copy-Item "$env:WINDIR\System32\notepad.exe" $script:UnsignedFile

        $script:AuditPath = Join-Path $env:TEMP "release-gate-audit-$(Get-Random).json"
    }

    AfterAll {
        foreach ($f in @($script:SignedFile, $script:UnsignedFile, $script:AuditPath)) {
            Remove-Item $f -ErrorAction SilentlyContinue
        }
        foreach ($storeSpec in @(@("Root","LocalMachine"), @("TrustedPublisher","LocalMachine"), @("My","CurrentUser"))) {
            $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeSpec[0], $storeSpec[1])
            $s.Open("ReadWrite")
            $found = $s.Certificates | Where-Object { $_.Thumbprint -eq $script:TestCert.Thumbprint }
            if ($found) { $s.Remove($found) }
            $s.Close()
        }
    }

    It "passes when all required artifacts are validly signed" {
        $result = Invoke-ReleaseVerification -WindowsArtifacts @($script:SignedFile) `
            -WindowsSigningRequired $true -AuditRecordPath $script:AuditPath
        $result | Should Be $true
    }

    It "fails when a required artifact is unsigned" {
        $result = Invoke-ReleaseVerification -WindowsArtifacts @($script:SignedFile, $script:UnsignedFile) `
            -WindowsSigningRequired $true -AuditRecordPath $script:AuditPath
        $result | Should Be $false
    }

    It "fails when ANY of multiple required artifacts is unsigned, not just when all are" {
        # Regression guard for Review Focus: "Multiple artifacts, one gate" --
        # two signed + one unsigned must still fail the whole release.
        $secondSigned = Join-Path $env:TEMP "release-gate-signed2-$(Get-Random).exe"
        Copy-Item "$env:WINDIR\System32\notepad.exe" $secondSigned
        Invoke-AuthenticodeSigning -Path $secondSigned -CertThumbprint $script:TestCert.Thumbprint -TimestampUrl "" | Out-Null
        try {
            $result = Invoke-ReleaseVerification -WindowsArtifacts @($script:SignedFile, $secondSigned, $script:UnsignedFile) `
                -WindowsSigningRequired $true -AuditRecordPath $script:AuditPath
            $result | Should Be $false
        } finally {
            Remove-Item $secondSigned -ErrorAction SilentlyContinue
        }
    }

    It "passes with an unsigned artifact when signing is not required (dev build)" {
        $result = Invoke-ReleaseVerification -WindowsArtifacts @($script:UnsignedFile) `
            -WindowsSigningRequired $false -AuditRecordPath $script:AuditPath
        $result | Should Be $true
    }

    It "writes an audit record with per-artifact results" {
        Invoke-ReleaseVerification -WindowsArtifacts @($script:SignedFile) `
            -WindowsSigningRequired $true -AuditRecordPath $script:AuditPath | Out-Null
        Test-Path $script:AuditPath | Should Be $true
        $audit = Get-Content $script:AuditPath -Raw | ConvertFrom-Json
        $audit.windowsArtifacts.Count | Should Be 1
        $audit.windowsArtifacts[0].path | Should Be $script:SignedFile
        $audit.windowsArtifacts[0].sha256 | Should Not BeNullOrEmpty
        $audit.windowsArtifacts[0].signatureValid | Should Be $true
        $audit.overallResult | Should Be $true
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `powershell -Command "Invoke-Pester packaging\signing\verify-release.Tests.ps1"`
Expected: FAIL — `Invoke-ReleaseVerification` is not recognized.

- [ ] **Step 3: Write minimal implementation**

```powershell
# packaging/signing/verify-release.ps1
#
# Invoke-ReleaseVerification is the release gate: it runs
# Test-AuthenticodeSignature (verify-windows-signature.ps1) over every
# artifact that must be signed, writes an audit record regardless of
# outcome (spec: Auditability), and returns false if ANY required artifact
# fails -- a partial pass (2 of 3 signed) is a failure, not a partial
# success. See docs/superpowers/specs/2026-09-30-d1-release-signing-architecture-design.md.

function Invoke-ReleaseVerification {
    param(
        [string[]]$WindowsArtifacts = @(),
        [bool]$WindowsSigningRequired = $true,
        [Parameter(Mandatory)][string]$AuditRecordPath
    )

    $artifactResults = @()
    $overallResult = $true

    foreach ($artifact in $WindowsArtifacts) {
        $hash = if (Test-Path $artifact) { (Get-FileHash -Path $artifact -Algorithm SHA256).Hash.ToLower() } else { $null }
        $verification = Test-AuthenticodeSignature -Path $artifact

        $artifactPassed = $true
        if ($WindowsSigningRequired -and -not $verification.Valid) {
            $artifactPassed = $false
            $overallResult = $false
        }

        $artifactResults += [PSCustomObject]@{
            path           = $artifact
            sha256         = $hash
            signatureValid = $verification.Valid
            status         = $verification.Status
            reason         = $verification.Reason
            passed         = $artifactPassed
        }
    }

    $audit = [PSCustomObject]@{
        timestamp        = (Get-Date).ToUniversalTime().ToString("o")
        windowsRequired   = $WindowsSigningRequired
        windowsArtifacts = $artifactResults
        overallResult    = $overallResult
    }
    $audit | ConvertTo-Json -Depth 6 | Set-Content -Path $AuditRecordPath -Encoding UTF8

    return $overallResult
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `powershell -Command "Invoke-Pester packaging\signing\verify-release.Tests.ps1"`
Expected: 5/5 pass.

- [ ] **Step 5: Commit**

```bash
git add packaging/signing/verify-release.ps1 packaging/signing/verify-release.Tests.ps1
git commit -m "feat(signing): add release-gate verification + audit record script"
```

---

### Task 5: Wire signing + the release gate into windows-build.ps1

**Files:**
- Modify: `packaging/windows-build.ps1` (the `param()` block near the top; the Windows agent build section around lines 231-348; the GPG section at lines 668-729)

**Interfaces:**
- Consumes: `Invoke-AuthenticodeSigning` (Task 1), `Invoke-ReleaseVerification` (Task 4) — dot-sourced.
- Produces: nothing consumed by a later task in this plan (final wiring task).

No `go test` cycle applies here — this task modifies a PowerShell orchestration script, verified by an actual end-to-end dry run against a self-signed test cert (Step 6 below), the same way Task 4's own tests already prove the gate logic works. Re-running Task 1-4's own test suites after this task's edits confirms nothing in those scripts broke.

- [ ] **Step 1: Add signing parameters to `windows-build.ps1`'s `param()` block**

Current (lines 20-26):
```powershell
param(
    [string] $Version    = "1.6.0",
    [string] $Customer   = "",
    [string] $CustomerID = "",
    [int]    $Days       = 365,
    [switch] $SkipBuild          # pass -SkipBuild to repackage without rebuilding image
)
```

Change to:
```powershell
param(
    [string] $Version    = "1.6.0",
    [string] $Customer   = "",
    [string] $CustomerID = "",
    [int]    $Days       = 365,
    [switch] $SkipBuild,         # pass -SkipBuild to repackage without rebuilding image

    # -- D1 release signing (docs/superpowers/specs/2026-09-30-d1-release-signing-architecture-design.md) --
    # Credentials are always parameters/env vars, never hardcoded. A customer
    # build (-Customer/-CustomerID both set) defaults every *Required flag to
    # $true -- a production release must not silently ship unsigned. A bare
    # dev build (no -Customer) defaults them to $false, unchanged from today's
    # behavior, so the existing local dev/test loop isn't broken by this task.
    [string] $WindowsCertThumbprint = $env:BAS_WINDOWS_CERT_THUMBPRINT,
    [Nullable[bool]] $WindowsSigningRequired = $null,
    [Nullable[bool]] $GpgSigningRequired     = $null
)

$IsCustomerBuild = ($Customer -ne "" -and $CustomerID -ne "")
if ($null -eq $WindowsSigningRequired) { $WindowsSigningRequired = $IsCustomerBuild }
if ($null -eq $GpgSigningRequired)     { $GpgSigningRequired     = $IsCustomerBuild }
```

- [ ] **Step 2: Sign the three Windows executables right after they're built**

Locate the three build outputs (already read this session): `$InstallerDir\bas_agent.exe` gets embedded into `$OutDir\BASAgent-Setup-$Version.exe` (built around line 289), `$OutDir\bas-agent-windows-amd64.exe` (line 306), and `$OutDir\bas-agent-windows-legacy-amd64.exe` (line 341). Add, immediately after line 348 (the legacy agent's `Compress-Archive` call) and before the `-- 5b` section that follows it:

```powershell
# -- 5d. Sign Windows executables (D1) ----------------------------------------
. "$RepoRoot\packaging\signing\sign-windows.ps1"

$WindowsArtifactsToSign = @(
    "$OutDir\BASAgent-Setup-$Version.exe",
    "$OutDir\bas-agent-windows-amd64.exe",
    "$OutDir\bas-agent-windows-legacy-amd64.exe"
) | Where-Object { Test-Path $_ }

if ($WindowsCertThumbprint) {
    Log "Signing $($WindowsArtifactsToSign.Count) Windows executable(s)..."
    foreach ($artifact in $WindowsArtifactsToSign) {
        $signed = Invoke-AuthenticodeSigning -Path $artifact -CertThumbprint $WindowsCertThumbprint
        if (-not $signed -and $WindowsSigningRequired) {
            Err "Authenticode signing failed for $artifact and Windows signing is required for this build."
        } elseif (-not $signed) {
            Warn "Authenticode signing failed for $artifact (not required for this build -- continuing)."
        }
    }
} elseif ($WindowsSigningRequired) {
    Err "Windows signing is required for this build (customer build) but -WindowsCertThumbprint / BAS_WINDOWS_CERT_THUMBPRINT is not set."
} else {
    Warn "No Windows signing certificate configured -- executables will not be signed (dev build, not required)."
}
```

- [ ] **Step 3: Replace the GPG section's silent-skip behavior with the required/optional gate**

Current behavior (lines 690-691, 701-703, 720-721) only ever `Warn`s and continues. Change each of those three `Warn` call sites in the existing `if (-not $gpgExe) { ... }` / `if ($LASTEXITCODE -ne 0) { ... }` / `if ($LASTEXITCODE -eq 0 ...) { ... } else { ... }` blocks (lines 690-729) so that when `$GpgSigningRequired` is `$true`, the same condition that previously logged `Warn "...bundle is unsigned."` now calls `Err` instead, aborting the build. When `$GpgSigningRequired` is `$false`, keep today's exact `Warn`-and-continue behavior unchanged. Concretely, wrap each of the three existing `Warn "...unsigned..."` lines:

```powershell
# Was: Warn "gpg not found - bundle is unsigned. Install Gpg4win or Git for Windows to enable signing."
if ($GpgSigningRequired) {
    Err "gpg not found and GPG signing is required for this build. Install Gpg4win or Git for Windows."
} else {
    Warn "gpg not found - bundle is unsigned. Install Gpg4win or Git for Windows to enable signing."
}
```

(apply the same `if ($GpgSigningRequired) { Err ... } else { Warn ... }` pattern to the other two existing `Warn` call sites at lines 702-703 and 721).

- [ ] **Step 4: Run the release gate before the ZIP is created**

Insert immediately before the existing `-- 9. Create ZIP for transfer` section (line 644):

```powershell
# -- 8b. Release gate (D1) -----------------------------------------------------
. "$RepoRoot\packaging\signing\verify-release.ps1"

$AuditRecordPath = Join-Path $OutDir "release-verification.json"
$releaseOk = Invoke-ReleaseVerification -WindowsArtifacts $WindowsArtifactsToSign `
    -WindowsSigningRequired $WindowsSigningRequired -AuditRecordPath $AuditRecordPath

if (-not $releaseOk) {
    Err "Release verification failed -- see $AuditRecordPath. Refusing to package an unsigned/invalid release."
}
Log "Release verification passed: $AuditRecordPath"
```

- [ ] **Step 5: Syntax-check the modified script**

Run: `powershell -Command "$null = [System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw packaging\windows-build.ps1), [ref]$null); Write-Host 'Syntax OK'"`
Expected: `Syntax OK`, no parser errors.

- [ ] **Step 6: End-to-end dry run against a self-signed test cert**

```powershell
$testCert = New-SelfSignedCertificate -Subject "CN=BAS E2E Test" -Type CodeSigningCert `
    -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage DigitalSignature -NotAfter (Get-Date).AddDays(1)
try {
    .\packaging\windows-build.ps1 -Version "0.0.0-e2e-test" `
        -WindowsCertThumbprint $testCert.Thumbprint -WindowsSigningRequired $true -GpgSigningRequired $false
    # Expected: build proceeds, signs all 3 executables with the test cert,
    # release-verification.json shows overallResult=true, ZIP is produced.
} finally {
    Remove-Item "Cert:\CurrentUser\My\$($testCert.Thumbprint)" -ErrorAction SilentlyContinue
}
```

Expected: the build completes, `dist\bas-install-0.0.0-e2e-test\release-verification.json` exists with `"overallResult": true`, and `Get-AuthenticodeSignature` on `dist\bas-install-0.0.0-e2e-test\BASAgent-Setup-0.0.0-e2e-test.exe` reports a signature is present (not `NotSigned`). If any step errors, use systematic-debugging before editing further — this is the one step in this plan that exercises the real, full script end to end.

- [ ] **Step 7: Commit**

```bash
git add packaging/windows-build.ps1
git commit -m "feat(signing): wire Authenticode signing + release gate into windows-build.ps1"
```

---

### Task 6: Release runbook

**Files:**
- Create: `packaging/docs/release-signing-runbook.md`

No test cycle — documentation only.

- [ ] **Step 1: Write the runbook**

```markdown
# Release Signing Runbook

This is the operational guide for D1 (release signing). See the architecture
spec at ../../docs/superpowers/specs/2026-09-30-d1-release-signing-architecture-design.md
for the *why*; this document is the *how*.

## Prerequisites (Phase 0 -- not yet complete)

Before signing a *production* release, Phase 0 discovery must be answered:
see ../../docs/superpowers/plans/2026-09-30-d1-phase0-discovery-checklist.md.
Until then, only test-certificate builds are possible.

## Running a signed build with a test certificate (available today)

1. Generate a throwaway self-signed test certificate:
   ```powershell
   $cert = New-SelfSignedCertificate -Subject "CN=BAS Local Test" -Type CodeSigningCert `
       -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage DigitalSignature -NotAfter (Get-Date).AddDays(1)
   ```
2. Run the build, pointing at the test cert's thumbprint:
   ```powershell
   .\packaging\windows-build.ps1 -Version "1.7.0-test" -WindowsCertThumbprint $cert.Thumbprint -WindowsSigningRequired $true
   ```
3. Check `dist\bas-install-<version>\release-verification.json` -- `overallResult` must be `true`.
4. Remove the test cert when done: `Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)"`.

Windows will still show "Unknown Publisher" for a self-signed-cert build --
that's expected. Only a certificate chaining to a public root (Phase 0)
produces real SmartScreen/publisher trust.

## Running a production customer release (blocked on Phase 0)

Once Phase 0 confirms a real Authenticode certificate is available:

```powershell
.\packaging\windows-build.ps1 -Version "1.7.0" -Customer "Acme Corp" -CustomerID "acme-prod-001" `
    -WindowsCertThumbprint "<real cert thumbprint>"
```

`-Customer`/`-CustomerID` being set makes this a customer build, which
defaults `WindowsSigningRequired`/`GpgSigningRequired` to `$true` --
the build aborts rather than producing an unsigned customer deliverable.

## macOS signing (not yet wired into any build -- no macOS artifact is
produced by windows-build.ps1 today)

`packaging/signing/sign-macos.sh` / `verify-macos-signature.sh` exist and
are written against Apple's documented interface, but were **not** tested
against real `codesign`/`notarytool` in the session that wrote them -- no
macOS host was available. Before relying on them for a real release:
verify them manually on an actual Mac with real Developer ID credentials,
the same way this plan's Task 1/2/4 were verified with `signtool.exe` and
a self-signed test cert on this Windows host.

## Troubleshooting

- **`signtool.exe not found`** -- install the Windows SDK (provides
  `signtool.exe` under `Windows Kits\10\Tools\bin\`).
- **Release verification fails with `HashMismatch`** -- the artifact was
  modified after signing; rebuild from a clean state.
- **Customer build fails with "Windows signing is required... but
  -WindowsCertThumbprint is not set"** -- pass a real certificate
  thumbprint; production customer builds cannot skip signing.
```

- [ ] **Step 2: Commit**

```bash
git add packaging/docs/release-signing-runbook.md
git commit -m "docs(signing): add release signing runbook"
```

---

## Final Verification

```bash
powershell -Command "Invoke-Pester packaging\signing\sign-windows.Tests.ps1,packaging\signing\verify-windows-signature.Tests.ps1,packaging\signing\verify-release.Tests.ps1"
bash packaging/signing/sign-macos.test.sh
powershell -Command "$null = [System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw packaging\windows-build.ps1), [ref]$null); Write-Host 'Syntax OK'"
```

Expected: all Pester tests pass (read the actual pass/fail counts, don't assume), the bash mock test prints `ALL TESTS PASSED`, and the PowerShell syntax check prints `Syntax OK`.

Then use `superpowers:finishing-a-development-branch` as this session has throughout tonight.
