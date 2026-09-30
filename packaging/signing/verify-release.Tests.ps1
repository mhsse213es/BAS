Import-Module Pester
. "$PSScriptRoot\sign-windows.ps1"
. "$PSScriptRoot\verify-windows-signature.ps1"
. "$PSScriptRoot\verify-release.ps1"

function New-UnsignedTestExe {
    $dir = Join-Path $env:TEMP "release-gate-test-src-$(Get-Random)"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Set-Content -Path "$dir\main.go" -Value "package main`n`nfunc main() {}`n"
    Push-Location $dir
    $env:GOOS = "windows"; $env:GOARCH = "amd64"
    go build -o unsigned.exe main.go 2>&1 | Out-Null
    $env:GOOS = ""; $env:GOARCH = ""
    Pop-Location
    return "$dir\unsigned.exe"
}

Describe "Invoke-ReleaseVerification" {
    BeforeAll {
        $script:TestCert = New-SelfSignedCertificate `
            -Subject "CN=BAS Release Gate Test" -Type CodeSigningCert `
            -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage DigitalSignature `
            -NotAfter (Get-Date).AddDays(1)
        foreach ($storeSpec in @(@("Root","LocalMachine"), @("TrustedPublisher","LocalMachine"))) {
            $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeSpec[0], $storeSpec[1])
            $s.Open("ReadWrite")
            $s.Add($script:TestCert)
            $s.Close()
        }

        $script:SignedFile = New-UnsignedTestExe
        Invoke-AuthenticodeSigning -Path $script:SignedFile -CertThumbprint $script:TestCert.Thumbprint -TimestampUrl "" | Out-Null

        $script:UnsignedFile = New-UnsignedTestExe

        $script:AuditPath = Join-Path $env:TEMP "release-gate-audit-$(Get-Random).json"
    }

    AfterAll {
        foreach ($f in @($script:SignedFile, $script:UnsignedFile)) {
            Remove-Item (Split-Path $f) -Recurse -ErrorAction SilentlyContinue
        }
        Remove-Item $script:AuditPath -ErrorAction SilentlyContinue
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
        # Review Focus: "Multiple artifacts, one gate" -- two signed + one
        # unsigned must still fail the whole release.
        $secondSigned = New-UnsignedTestExe
        Invoke-AuthenticodeSigning -Path $secondSigned -CertThumbprint $script:TestCert.Thumbprint -TimestampUrl "" | Out-Null
        try {
            $result = Invoke-ReleaseVerification -WindowsArtifacts @($script:SignedFile, $secondSigned, $script:UnsignedFile) `
                -WindowsSigningRequired $true -AuditRecordPath $script:AuditPath
            $result | Should Be $false
        } finally {
            Remove-Item (Split-Path $secondSigned) -Recurse -ErrorAction SilentlyContinue
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
