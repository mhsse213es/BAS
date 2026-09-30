# Invoke-ReleaseVerification is the release gate: it runs
# Test-AuthenticodeSignature (verify-windows-signature.ps1) over every
# artifact that must be signed, writes an audit record regardless of
# outcome (spec: Auditability), and returns false if ANY required artifact
# fails -- a partial pass (2 of 3 signed) is a failure, not a partial
# success. See docs/superpowers/specs/2026-09-30-d1-release-signing-architecture-design.md.

function Invoke-ReleaseVerification {
    param(
        [string[]]$WindowsArtifacts = @(),
        [bool]$WindowsSigningRequired = $true,
        [bool]$RequireTimestamp = $false,
        [string]$ExpectedThumbprint = "",
        [string]$Version = "",
        [Parameter(Mandatory)][string]$AuditRecordPath
    )

    $artifactResults = @()
    $overallResult = $true

    foreach ($artifact in $WindowsArtifacts) {
        $hash = if (Test-Path $artifact) { (Get-FileHash -Path $artifact -Algorithm SHA256).Hash.ToLower() } else { $null }
        $verification = Test-AuthenticodeSignature -Path $artifact -RequireTimestamp:$RequireTimestamp

        # A signature can be technically Valid yet signed by the wrong
        # certificate -- e.g. a stray test cert left trusted on the build
        # host. Pin it to the certificate this build actually asked for.
        if ($ExpectedThumbprint -and $verification.Valid -and $verification.SignerThumbprint -ne $ExpectedThumbprint) {
            $verification = @{
                Valid             = $false
                Status            = "SignerMismatch"
                Reason            = "Signed by $($verification.SignerThumbprint), expected $ExpectedThumbprint"
                SignerThumbprint  = $verification.SignerThumbprint
                SignerSubject     = $verification.SignerSubject
            }
        }

        $artifactPassed = $true
        if ($WindowsSigningRequired -and -not $verification.Valid) {
            $artifactPassed = $false
            $overallResult = $false
        }

        $artifactResults += [PSCustomObject]@{
            # Filename only -- an absolute build-host path (C:\Users\...)
            # has no meaning to a customer reading this record and must not
            # leak into a file shipped inside the customer ZIP.
            path             = Split-Path -Leaf $artifact
            sha256           = $hash
            signatureValid   = $verification.Valid
            status           = $verification.Status
            reason           = $verification.Reason
            signerThumbprint = $verification.SignerThumbprint
            signerSubject    = $verification.SignerSubject
            passed           = $artifactPassed
        }
    }

    $audit = [PSCustomObject]@{
        version           = $Version
        timestamp         = (Get-Date).ToUniversalTime().ToString("o")
        windowsRequired   = $WindowsSigningRequired
        requireTimestamp  = $RequireTimestamp
        windowsArtifacts  = $artifactResults
        overallResult     = $overallResult
    }
    $audit | ConvertTo-Json -Depth 6 | Set-Content -Path $AuditRecordPath -Encoding UTF8

    return $overallResult
}
