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

function Add-ManifestEntryIfMissing {
    # Appends "<64 zeros>  <FileName>" when the manifest does not list the file, so that
    # Update-BinaryManifestEntries (which only replaces existing lines) can then set its real hash.
    # Used for artifacts the Docker image does not know about, such as the Windows MSI.
    param(
        [Parameter(Mandatory)][string]$ManifestContent,
        [Parameter(Mandatory)][string]$FileName
    )
    $lines = $ManifestContent -split "`n" | Where-Object { $_ -ne "" } | ForEach-Object { $_.TrimEnd("`r") }
    foreach ($line in $lines) {
        $parts = $line -split "  ", 2
        if ($parts.Count -eq 2 -and $parts[1] -eq $FileName) { return $ManifestContent }
    }
    return ($lines -join "`n") + "`n" + ("0" * 64) + "  $FileName`n"
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
    # The MSI is optional (windows-build.ps1 -BuildMsi). When present it is served by the orchestrator
    # as a per-request bundle, so it must be in the image and in the signed manifest.
    $msiName = "AudspectAgent-x64.msi"
    $msiPath = Join-Path $OutDir $msiName
    $includeMsi = Test-Path $msiPath

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
    # Dev build (no certificate configured): these files are unsigned by design,
    # so Authenticode re-verification cannot pass. Skip it here, and say so, so
    # the self-integrity manifest and BINARIES.sha256 still get generated and
    # injected. A certificate-configured build still runs the full check.
    $authenticodeChecked = [bool]$ExpectedThumbprint
    if (-not $authenticodeChecked) {
        Write-Host "[!]   Dev build: Authenticode re-verification skipped (no Windows certificate configured)."
    }
    $verifyPaths = @($installerPath, $artifacts["bas-agent-windows-amd64.exe"], $artifacts["bas-agent-windows-legacy-amd64.exe"])
    if ($includeMsi) { $verifyPaths += $msiPath }
    foreach ($path in $verifyPaths) {
        if (-not $authenticodeChecked) { break }
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
        if ($includeMsi) { Copy-Item $msiPath (Join-Path $patchCtx $msiName) }

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
        if ($cpExit -ne 0 -or -not (Test-Path $manifestPath)) {
            $null = (docker rm $tmpCID 2>&1 | Out-String)
            Write-Error "Update-OrchestratorAgentArtifacts: could not extract BINARIES.sha256 from $OrchestratorTag`: $cpOutput" -ErrorAction Continue
            return $false
        }

        # Self-integrity (see
        # docs/superpowers/specs/2026-10-18-orchestrator-self-integrity-design.md):
        # hash the orchestrator binary actually baked into THIS image --
        # not a locally-built copy, which could differ -- and sign it with
        # the same trusted-host private_key.pem, mirroring BINARIES.sha256
        # exactly. Still the same container ($tmpCID); removed once both
        # extractions are done.
        $selfBinaryPath = Join-Path $patchCtx "orchestrator-binary"
        $selfCpOutput = (docker cp "${tmpCID}:/orchestrator" $selfBinaryPath 2>&1 | Out-String).Trim()
        $selfCpExit = $LASTEXITCODE
        $null = (docker rm $tmpCID 2>&1 | Out-String)
        if ($selfCpExit -ne 0 -or -not (Test-Path $selfBinaryPath)) {
            Write-Error "Update-OrchestratorAgentArtifacts: could not extract /orchestrator from $OrchestratorTag`: $selfCpOutput" -ErrorAction Continue
            return $false
        }
        $selfHash = (Get-FileHash -Path $selfBinaryPath -Algorithm SHA256).Hash.ToLower()
        $selfManifestPath = Join-Path $patchCtx "SELFINTEGRITY.sha256"
        [System.IO.File]::WriteAllText($selfManifestPath, "$selfHash  orchestrator`n")

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
        if ($includeMsi) {
            $replacements[$msiName] = (Get-FileHash -Path (Join-Path $patchCtx $msiName) -Algorithm SHA256).Hash.ToLower()
        }
        $manifestContent = Get-Content $manifestPath -Raw
        if ($includeMsi) { $manifestContent = Add-ManifestEntryIfMissing -ManifestContent $manifestContent -FileName $msiName }
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

        Push-Location $OrchestratorDir
        try {
            $selfSignOutput = (go run scripts/signer.go sign private_key.pem $selfManifestPath 2>&1 | Out-String).Trim()
            $selfSignExit = $LASTEXITCODE
        } finally {
            Pop-Location
        }
        if ($selfSignExit -ne 0 -or -not (Test-Path "$selfManifestPath.sig")) {
            Write-Error "Update-OrchestratorAgentArtifacts: RSA signing of SELFINTEGRITY.sha256 failed: $selfSignOutput" -ErrorAction Continue
            return $false
        }

        [System.IO.File]::WriteAllText(
            (Join-Path $patchCtx "Dockerfile"),
            "FROM $OrchestratorTag`n" +
            "COPY bas-agent-windows-amd64.exe /agents/bas-agent-windows-amd64.exe`n" +
            "COPY bas-agent-windows-legacy-amd64.exe /agents/bas-agent-windows-legacy-amd64.exe`n" +
            "COPY bas-agent-windows-legacy-amd64-setup.zip /agents/bas-agent-windows-legacy-amd64-setup.zip`n" +
            "COPY bas-agent-windows-amd64-setup.zip /agents/bas-agent-windows-amd64-setup.zip`n" +
            $(if ($includeMsi) { "COPY $msiName /agents/$msiName`n" } else { "" }) +
            "COPY BINARIES.sha256 /agents/BINARIES.sha256`n" +
            "COPY BINARIES.sha256.sig /agents/BINARIES.sha256.sig`n" +
            "COPY SELFINTEGRITY.sha256 /SELFINTEGRITY.sha256`n" +
            "COPY SELFINTEGRITY.sha256.sig /SELFINTEGRITY.sha256.sig`n"
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
