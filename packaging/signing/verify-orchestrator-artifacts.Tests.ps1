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
