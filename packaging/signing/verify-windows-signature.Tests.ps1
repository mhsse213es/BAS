Import-Module Pester
. "$PSScriptRoot\sign-windows.ps1"
. "$PSScriptRoot\verify-windows-signature.ps1"

# See sign-windows.Tests.ps1 for why this builds a genuinely unsigned Go
# binary instead of copying a system executable like notepad.exe (which is
# already Microsoft-signed and would make "unsigned" test cases wrong).
function New-UnsignedTestExe {
    $dir = Join-Path $env:TEMP "verify-windows-test-src-$(Get-Random)"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Set-Content -Path "$dir\main.go" -Value "package main`n`nfunc main() {}`n"
    Push-Location $dir
    $env:GOOS = "windows"; $env:GOARCH = "amd64"
    go build -o unsigned.exe main.go 2>&1 | Out-Null
    $env:GOOS = ""; $env:GOARCH = ""
    Pop-Location
    return "$dir\unsigned.exe"
}

Describe "Test-AuthenticodeSignature" {
    BeforeAll {
        $script:TestCert = New-SelfSignedCertificate `
            -Subject "CN=BAS Verify Pipeline Test" `
            -Type CodeSigningCert `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -KeyUsage DigitalSignature `
            -NotAfter (Get-Date).AddDays(1)
        # Trust the test cert as both root and publisher so a genuinely valid
        # chain is possible -- otherwise every self-signed test signature
        # reports UntrustedRoot regardless of whether the signing itself
        # worked, which would make this test meaningless.
        foreach ($storeSpec in @(@("Root","LocalMachine"), @("TrustedPublisher","LocalMachine"))) {
            $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeSpec[0], $storeSpec[1])
            $s.Open("ReadWrite")
            $s.Add($script:TestCert)
            $s.Close()
        }

        $script:SignedFile = New-UnsignedTestExe
        Invoke-AuthenticodeSigning -Path $script:SignedFile -CertThumbprint $script:TestCert.Thumbprint -TimestampUrl "" | Out-Null

        $script:UnsignedFile = New-UnsignedTestExe

        # Flip a byte in the middle of the already-signed content -- NOT
        # appended past the end. Appending past the end was tried first and
        # produced "NotSigned", not "HashMismatch" (it corrupts the
        # certificate table's own structure rather than just invalidating
        # the hash, verified empirically). A mid-file flip stays inside the
        # hashed region and reliably reproduces the real tamper signal.
        $script:TamperedFile = Join-Path (Split-Path $script:SignedFile) "tampered.exe"
        Copy-Item $script:SignedFile $script:TamperedFile
        $bytes = [System.IO.File]::ReadAllBytes($script:TamperedFile)
        $mid = [int]($bytes.Length * 0.5)
        $bytes[$mid] = $bytes[$mid] -bxor 0xFF
        [System.IO.File]::WriteAllBytes($script:TamperedFile, $bytes)
    }

    AfterAll {
        foreach ($f in @($script:SignedFile, $script:UnsignedFile, $script:TamperedFile)) {
            Remove-Item (Split-Path $f) -Recurse -ErrorAction SilentlyContinue
        }
        foreach ($storeSpec in @(@("Root","LocalMachine"), @("TrustedPublisher","LocalMachine"), @("My","CurrentUser"))) {
            $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeSpec[0], $storeSpec[1])
            $s.Open("ReadWrite")
            $found = $s.Certificates | Where-Object { $_.Thumbprint -eq $script:TestCert.Thumbprint }
            if ($found) { $s.Remove($found) }
            $s.Close()
        }
    }

    It "reports Valid for a correctly signed, trusted file" {
        $result = Test-AuthenticodeSignature -Path $script:SignedFile
        $result.Valid | Should Be $true
        $result.Status | Should Be "Valid"
    }

    It "reports not valid for an unsigned file" {
        $result = Test-AuthenticodeSignature -Path $script:UnsignedFile
        $result.Valid | Should Be $false
    }

    It "reports not valid for a file tampered after signing" {
        $result = Test-AuthenticodeSignature -Path $script:TamperedFile
        $result.Valid | Should Be $false
        $result.Status | Should Be "HashMismatch"
    }

    It "returns the signer's thumbprint for a valid signature" {
        $result = Test-AuthenticodeSignature -Path $script:SignedFile
        $result.SignerThumbprint | Should Be $script:TestCert.Thumbprint
    }

    It "reports MissingTimestamp when RequireTimestamp is set and the signature carries none" {
        $result = Test-AuthenticodeSignature -Path $script:SignedFile -RequireTimestamp
        $result.Valid | Should Be $false
        $result.Status | Should Be "MissingTimestamp"
    }
}
