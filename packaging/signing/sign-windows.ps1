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

    # -ErrorAction Continue on every Write-Error in this function: the caller
    # (windows-build.ps1) sets $ErrorActionPreference='Stop' globally, which
    # otherwise turns these into terminating exceptions before the caller's
    # own Err/Warn branching around this function's return value ever runs
    # (verified empirically -- a missing file crashed the whole build instead
    # of returning $false).
    if (-not (Test-Path $Path)) {
        Write-Error "Invoke-AuthenticodeSigning: file not found: $Path" -ErrorAction Continue
        return $false
    }

    $signtool = if ($SignToolPath) { $SignToolPath } else { Find-SignTool }
    if (-not $signtool) {
        Write-Error "Invoke-AuthenticodeSigning: signtool.exe not found. Install the Windows SDK." -ErrorAction Continue
        return $false
    }

    $storePath = "$CertStoreLocation\$CertThumbprint"
    if (-not (Test-Path $storePath)) {
        Write-Error "Invoke-AuthenticodeSigning: certificate $CertThumbprint not found in $CertStoreLocation." -ErrorAction Continue
        return $false
    }

    # signtool's /s wants just the store NAME (e.g. "My"), not a
    # "Location\Name" path -- CertOpenStore() fails on "CurrentUser\My"
    # (verified empirically). CurrentUser is signtool's default context;
    # /sm switches to LocalMachine.
    $storeParts = ($CertStoreLocation -replace "^Cert:\\", "") -split "\\"
    $storeName = $storeParts[-1]
    $signArgs = @("sign", "/fd", "sha256", "/sha1", $CertThumbprint, "/s", $storeName)
    if ($storeParts[0] -eq "LocalMachine") {
        $signArgs += "/sm"
    }
    if ($TimestampUrl) {
        $signArgs += @("/tr", $TimestampUrl, "/td", "sha256")
    }
    $signArgs += $Path

    # Capture signtool's combined output (instead of discarding it) so a
    # failure's Write-Error carries its actual diagnostic, not just an exit
    # code. 2>&1 merges native stderr into the output stream; under the
    # caller's EAP='Stop' that promotes each stderr line to a terminating
    # NativeCommandError before $LASTEXITCODE is even checked (same class of
    # issue as this repo's docker-build/gpg call sites), so run it under
    # 'Continue' -- the same pattern used everywhere else in this codebase.
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $signOutput = (& $signtool @signArgs 2>&1 | Out-String).Trim()
    } finally {
        $ErrorActionPreference = $prevEAP
    }

    if ($LASTEXITCODE -ne 0) {
        $timestampHint = if ($TimestampUrl) { " Timestamp authority '$TimestampUrl' may be unreachable -- retry with -TimestampUrl '' to isolate." } else { "" }
        Write-Error "Invoke-AuthenticodeSigning: signtool exited $LASTEXITCODE for $Path.$timestampHint signtool output: $signOutput" -ErrorAction Continue
        return $false
    }
    return $true
}
