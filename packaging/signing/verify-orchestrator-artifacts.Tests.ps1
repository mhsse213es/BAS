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
        foreach ($cert in @($script:TestCert, $script:UntrustedCert, $script:SecondTrustedCert)) {
            if (-not $cert) { continue }
            foreach ($storeSpec in @(@("My","CurrentUser"), @("Root","LocalMachine"), @("TrustedPublisher","LocalMachine"))) {
                $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeSpec[0], $storeSpec[1])
                $s.Open("ReadWrite")
                $found = $s.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
                if ($found) { $s.Remove($found) }
                $s.Close()
            }
        }
        # A successful patch now also overwrites orchestrator/agents/BINARIES.sha256(.sig)
        # (I3) -- those are real, tracked files in this repo, not test fixtures.
        # Revert any test-run pollution the same way windows-build.ps1's own
        # E2E verification does.
        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
        Push-Location $repoRoot
        git checkout -- orchestrator/agents/BINARIES.sha256 orchestrator/agents/BINARIES.sha256.sig 2>$null
        Pop-Location
    }

    It "patches the image so each extracted artifact carries a valid Authenticode signature" {
        $result = Update-OrchestratorAgentArtifacts -OrchestratorTag $script:FixtureTag -OutDir $script:OutDir -Version $script:Version -OrchestratorDir $script:OrchestratorDir -ExpectedThumbprint $script:TestCert.Thumbprint
        $result | Should Be $true
        # A leaked native-command stdout (the C1 regression class) turns
        # this into a 2+-element array, which PowerShell treats as truthy
        # regardless of contents -- assert the scalar type, not just the
        # value, so that class of bug fails this test even when the
        # array's own last element happens to be $true.
        ($result -is [bool]) | Should Be $true

        $extractDir = Join-Path $env:TEMP "orch-patch-extract-$(Get-Random)"
        New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
        $cid = docker create $script:FixtureTag
        foreach ($f in @("bas-agent-windows-amd64.exe", "bas-agent-windows-legacy-amd64.exe",
                         "bas-agent-windows-legacy-amd64-setup.zip", "bas-agent-windows-amd64-setup.zip")) {
            docker cp "${cid}:/agents/$f" "$extractDir\$f" | Out-Null
        }
        docker rm $cid | Out-Null

        $sig1 = Get-AuthenticodeSignature -FilePath "$extractDir\bas-agent-windows-amd64.exe"
        $sig1.Status | Should Be "Valid"
        $sig1.SignerCertificate.Thumbprint | Should Be $script:TestCert.Thumbprint

        $sig2 = Get-AuthenticodeSignature -FilePath "$extractDir\bas-agent-windows-legacy-amd64.exe"
        $sig2.Status | Should Be "Valid"
        $sig2.SignerCertificate.Thumbprint | Should Be $script:TestCert.Thumbprint

        # Both setup zips carry a signed exe inside them, not just a signed
        # exe alongside them -- unpack and check the actual payload a user
        # would run.
        Expand-Archive -Path "$extractDir\bas-agent-windows-legacy-amd64-setup.zip" -DestinationPath "$extractDir\legacy-unzipped" -Force
        $sig3 = Get-AuthenticodeSignature -FilePath "$extractDir\legacy-unzipped\bas-agent-windows-legacy-amd64.exe"
        $sig3.Status | Should Be "Valid"
        $sig3.SignerCertificate.Thumbprint | Should Be $script:TestCert.Thumbprint

        Expand-Archive -Path "$extractDir\bas-agent-windows-amd64-setup.zip" -DestinationPath "$extractDir\amd64-unzipped" -Force
        $sig4 = Get-AuthenticodeSignature -FilePath "$extractDir\amd64-unzipped\Audspect_Agent.exe"
        $sig4.Status | Should Be "Valid"
        $sig4.SignerCertificate.Thumbprint | Should Be $script:TestCert.Thumbprint

        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    }

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
        # accidentally recompute, drop, or reorder these lines. Includes the
        # 3 Linux packages (C3): nothing in the Windows signing patch should
        # ever touch them.
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

        # I3: the customer ZIP's own copy, and the orchestrator/agents
        # staging copy windows-build.ps1 writes before this function runs,
        # must both match what the image now serves -- not the stale
        # pre-patch extraction either of them started out as.
        (Get-Content (Join-Path $script:OutDir "BINARIES.sha256") -Raw) | Should Be (Get-Content "$extractDir\BINARIES.sha256" -Raw)
        (Get-Content (Join-Path $script:OutDir "BINARIES.sha256.sig") -Raw) | Should Be (Get-Content "$extractDir\BINARIES.sha256.sig" -Raw)
        $agentsStageManifest = Join-Path $script:OrchestratorDir "agents\BINARIES.sha256"
        (Get-Content $agentsStageManifest -Raw) | Should Be (Get-Content "$extractDir\BINARIES.sha256" -Raw)

        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "returns false when a staged artifact's signer thumbprint does not match -ExpectedThumbprint, even though the signature is validly trusted" {
        # A second, independently-trusted cert -- distinct from
        # $script:UntrustedCert (never trusted) and from $script:TestCert
        # (the expected one). Proves re-verification pins the exact
        # certificate, not just "signed by something this machine trusts".
        if (-not $script:SecondTrustedCert) {
            $script:SecondTrustedCert = New-SelfSignedCertificate `
                -Subject "CN=BAS Orchestrator Patch Second Trusted" -Type CodeSigningCert `
                -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage DigitalSignature `
                -NotAfter (Get-Date).AddDays(1)
            foreach ($storeSpec in @(@("Root","LocalMachine"), @("TrustedPublisher","LocalMachine"))) {
                $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeSpec[0], $storeSpec[1])
                $s.Open("ReadWrite"); $s.Add($script:SecondTrustedCert); $s.Close()
            }
        }

        $mismatchOutDir = New-SignedOutDir
        Invoke-AuthenticodeSigning -Path (Join-Path $mismatchOutDir "bas-agent-windows-amd64.exe") -CertThumbprint $script:SecondTrustedCert.Thumbprint -CertStoreLocation "Cert:\CurrentUser\My" -TimestampUrl "" | Out-Null

        $result = Update-OrchestratorAgentArtifacts -OrchestratorTag $script:FixtureTag -OutDir $mismatchOutDir -Version $script:Version -OrchestratorDir $script:OrchestratorDir -ExpectedThumbprint $script:TestCert.Thumbprint
        $result | Should Be $false
        Remove-Item $mismatchOutDir -Recurse -Force -ErrorAction SilentlyContinue
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
