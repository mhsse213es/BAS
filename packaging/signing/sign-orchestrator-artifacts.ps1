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
