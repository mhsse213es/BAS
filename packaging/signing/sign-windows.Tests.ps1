Import-Module Pester
. "$PSScriptRoot\sign-windows.ps1"

# New-UnsignedTestExe builds a trivial, genuinely unsigned Windows PE via the
# Go toolchain. A copy of a system binary like notepad.exe is NOT a valid
# fixture here: it already carries Microsoft's Authenticode signature, and
# signtool's default `sign` (no /as) does not replace an existing primary
# signature the way Get-AuthenticodeSignature reports it -- verified
# empirically, the "signed" file kept reporting Microsoft as the signer.
# Production artifacts (Go binaries) start genuinely unsigned too, so this
# fixture matches the real target better than a system binary would.
function New-UnsignedTestExe {
    $dir = Join-Path $env:TEMP "sign-windows-test-src-$(Get-Random)"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Set-Content -Path "$dir\main.go" -Value "package main`n`nfunc main() {}`n"
    Push-Location $dir
    $env:GOOS = "windows"; $env:GOARCH = "amd64"
    go build -o unsigned.exe main.go 2>&1 | Out-Null
    $env:GOOS = ""; $env:GOARCH = ""
    Pop-Location
    return "$dir\unsigned.exe"
}

Describe "Invoke-AuthenticodeSigning" {
    BeforeAll {
        $script:TestCert = New-SelfSignedCertificate `
            -Subject "CN=BAS Signing Pipeline Test" `
            -Type CodeSigningCert `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -KeyUsage DigitalSignature `
            -NotAfter (Get-Date).AddDays(1)
        $script:TestFile = New-UnsignedTestExe
    }

    AfterAll {
        Remove-Item (Split-Path $script:TestFile) -Recurse -ErrorAction SilentlyContinue
        Remove-Item "Cert:\CurrentUser\My\$($script:TestCert.Thumbprint)" -ErrorAction SilentlyContinue
    }

    It "reports NotSigned before signing (fixture sanity check)" {
        $sig = Get-AuthenticodeSignature -FilePath $script:TestFile
        $sig.Status | Should Be "NotSigned"
    }

    It "signs the file and signtool reports success" {
        $result = Invoke-AuthenticodeSigning -Path $script:TestFile `
            -CertThumbprint $script:TestCert.Thumbprint `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -TimestampUrl ""
        $result | Should Be $true
    }

    It "the signed file's signer is the test certificate" {
        $sig = Get-AuthenticodeSignature -FilePath $script:TestFile
        $sig.SignerCertificate.Thumbprint | Should Be $script:TestCert.Thumbprint
    }

    It "signs with an RFC 3161 timestamp when the timestamp server is reachable" {
        $reachable = Test-Connection -ComputerName "timestamp.digicert.com" -Count 1 -Quiet -ErrorAction SilentlyContinue
        if (-not $reachable) {
            Write-Host "SKIP: timestamp.digicert.com unreachable from this environment"
            return
        }
        $timestampedFile = New-UnsignedTestExe
        try {
            $result = Invoke-AuthenticodeSigning -Path $timestampedFile `
                -CertThumbprint $script:TestCert.Thumbprint `
                -CertStoreLocation "Cert:\CurrentUser\My"
            $result | Should Be $true
            $sig = Get-AuthenticodeSignature -FilePath $timestampedFile
            $sig.TimeStamperCertificate | Should Not Be $null
        } finally {
            Remove-Item (Split-Path $timestampedFile) -Recurse -ErrorAction SilentlyContinue
        }
    }
}
