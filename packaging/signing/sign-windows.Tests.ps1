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
        # RFC 3161 timestamping is an HTTP POST, not ICMP -- a host that blocks
        # ping but serves HTTP (common on corporate networks and this session's
        # own sandbox) was reported "unreachable" by Test-Connection and always
        # skipped, even when timestamp.digicert.com actually answered (verified:
        # ICMP fails here, a plain HTTP GET returns 404 -- the server is up).
        $reachable = $false
        try {
            Invoke-WebRequest -Uri "http://timestamp.digicert.com" -Method Head -TimeoutSec 5 -ErrorAction Stop | Out-Null
            $reachable = $true
        } catch [System.Net.WebException] {
            # Any HTTP response (even an error status) proves the host answered.
            if ($_.Exception.Response) { $reachable = $true }
        } catch {
            $reachable = $false
        }
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

    It "does not throw under the caller's ErrorActionPreference=Stop, returns false instead" {
        # Review finding: Write-Error inside this function became terminating
        # when called from windows-build.ps1 (which sets EAP=Stop globally),
        # so the Err/Warn branches around its call site never actually ran --
        # the whole script crashed with a raw exception instead.
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Stop"
        try {
            { Invoke-AuthenticodeSigning -Path "$($script:TestFile)-missing.exe" -CertThumbprint $script:TestCert.Thumbprint } | Should Not Throw
            $result = Invoke-AuthenticodeSigning -Path "$($script:TestFile)-missing.exe" -CertThumbprint $script:TestCert.Thumbprint
            $result | Should Be $false
        } finally {
            $ErrorActionPreference = $prevEAP
        }
    }

    It "surfaces a timestamp-specific hint when signing fails with a timestamp URL set" {
        $Error.Clear()
        $unreachableFile = New-UnsignedTestExe
        try {
            $result = Invoke-AuthenticodeSigning -Path $unreachableFile `
                -CertThumbprint $script:TestCert.Thumbprint `
                -TimestampUrl "http://127.0.0.1:9"
            $result | Should Be $false
            $Error[0].Exception.Message | Should Match "timestamp"
        } finally {
            Remove-Item (Split-Path $unreachableFile) -Recurse -ErrorAction SilentlyContinue
        }
    }
}
