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

    # Out-Null: signtool's own console text (progress/success messages) goes
    # to the success stream in PowerShell for a native command, and without
    # suppressing it, it pollutes this function's return value into an
    # array instead of a clean boolean (verified empirically).
    & $signtool @signArgs | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Invoke-AuthenticodeSigning: signtool exited $LASTEXITCODE for $Path"
        return $false
    }
    return $true
}
