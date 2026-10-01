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

    # TrimEnd("`r") tolerates CRLF-terminated input (e.g. a manifest whose
    # last line picked up a trailing CR from how it was written) without
    # changing behavior for the common bare-LF case.
    $lines = $ManifestContent -split "`n" | Where-Object { $_ -ne "" } | ForEach-Object { $_.TrimEnd("`r") }
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

function Update-OrchestratorAgentArtifacts {
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$OrchestratorTag,
        [Parameter(Mandatory)][string]$OutDir,
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][string]$OrchestratorDir,
        # Pinned to the certificate this build actually signed with (pass
        # $WindowsCertThumbprint from the caller). Empty skips the check --
        # a bare dev build with no cert configured has nothing to pin.
        # Without this, re-verification only proved *some* trusted
        # certificate signed the file, which a stale file left over from a
        # retired certificate would also satisfy.
        [string]$ExpectedThumbprint = ""
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
    # Pinning the thumbprint (not just chain trust) catches a stale file
    # signed by a certificate that is no longer the one in use.
    foreach ($path in @($installerPath, $artifacts["bas-agent-windows-amd64.exe"], $artifacts["bas-agent-windows-legacy-amd64.exe"])) {
        $v = Test-AuthenticodeSignature -Path $path
        if (-not $v.Valid) {
            Write-Error "Update-OrchestratorAgentArtifacts: $path failed signature re-verification: $($v.Status) $($v.Reason)" -ErrorAction Continue
            return $false
        }
        if ($ExpectedThumbprint -and $v.SignerThumbprint -ne $ExpectedThumbprint) {
            Write-Error "Update-OrchestratorAgentArtifacts: $path is validly signed but by $($v.SignerThumbprint), expected $ExpectedThumbprint" -ErrorAction Continue
            return $false
        }
    }

    # Native command stderr becomes a terminating NativeCommandError under
    # the caller's EAP='Stop' (windows-build.ps1 sets this) before
    # $LASTEXITCODE is even checked -- same class of issue as sign-windows.ps1
    # (see its comment at the signtool call site). Run every native call
    # under 'Continue' and capture its output explicitly into a variable
    # instead of letting it flow unassigned into this function's own return
    # value: an unassigned native call's stdout becomes part of the
    # function's output stream alongside the eventual `return`, so a
    # bare `go run ...` here previously turned `return $true`/`$false`
    # into a 2-element array, which PowerShell treats as truthy in a
    # boolean context *regardless of its contents* -- a failed patch could
    # read as success at the call site. Capturing into a variable prevents
    # that at the source, for every native call in this function, not just
    # the signer.
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'

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

        $createOutput = (docker create $OrchestratorTag 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Update-OrchestratorAgentArtifacts: docker create failed for $OrchestratorTag`: $createOutput" -ErrorAction Continue
            return $false
        }
        $tmpCID = $createOutput
        $manifestPath = Join-Path $patchCtx "BINARIES.sha256"
        $cpOutput = (docker cp "${tmpCID}:/agents/BINARIES.sha256" $manifestPath 2>&1 | Out-String).Trim()
        $cpExit = $LASTEXITCODE
        $null = (docker rm $tmpCID 2>&1 | Out-String)
        if ($cpExit -ne 0 -or -not (Test-Path $manifestPath)) {
            Write-Error "Update-OrchestratorAgentArtifacts: could not extract BINARIES.sha256 from $OrchestratorTag`: $cpOutput" -ErrorAction Continue
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
        try {
            $signOutput = (go run scripts/signer.go sign private_key.pem $manifestPath 2>&1 | Out-String).Trim()
            $signExit = $LASTEXITCODE
        } finally {
            Pop-Location
        }
        if ($signExit -ne 0 -or -not (Test-Path "$manifestPath.sig")) {
            Write-Error "Update-OrchestratorAgentArtifacts: RSA signing of regenerated BINARIES.sha256 failed: $signOutput" -ErrorAction Continue
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

        $buildOutput = (docker build -q -t $OrchestratorTag $patchCtx 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Update-OrchestratorAgentArtifacts: patch image build failed for $OrchestratorTag`: $buildOutput" -ErrorAction Continue
            return $false
        }

        # The manifest + sig shipped in the customer ZIP (written earlier,
        # from the pre-patch image) would otherwise still describe the
        # unpatched binaries -- overwrite both staged copies with the ones
        # that actually match what the image now serves.
        Copy-Item $manifestPath (Join-Path $OutDir "BINARIES.sha256") -Force
        Copy-Item "$manifestPath.sig" (Join-Path $OutDir "BINARIES.sha256.sig") -Force
        $agentsStageDir = Join-Path $OrchestratorDir "agents"
        if (Test-Path $agentsStageDir) {
            Copy-Item $manifestPath (Join-Path $agentsStageDir "BINARIES.sha256") -Force
            Copy-Item "$manifestPath.sig" (Join-Path $agentsStageDir "BINARIES.sha256.sig") -Force
        }
    } finally {
        Remove-Item -Recurse -Force $patchCtx -ErrorAction SilentlyContinue
        $ErrorActionPreference = $prevEAP
    }

    return $true
}
