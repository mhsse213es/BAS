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
        [Parameter(Mandatory)][string]$AuditRecordPath
    )

    $artifactResults = @()
    $overallResult = $true

    foreach ($artifact in $WindowsArtifacts) {
        $hash = if (Test-Path $artifact) { (Get-FileHash -Path $artifact -Algorithm SHA256).Hash.ToLower() } else { $null }
        $verification = Test-AuthenticodeSignature -Path $artifact

        $artifactPassed = $true
        if ($WindowsSigningRequired -and -not $verification.Valid) {
            $artifactPassed = $false
            $overallResult = $false
        }

        $artifactResults += [PSCustomObject]@{
            path           = $artifact
            sha256         = $hash
            signatureValid = $verification.Valid
            status         = $verification.Status
            reason         = $verification.Reason
            passed         = $artifactPassed
        }
    }

    $audit = [PSCustomObject]@{
        timestamp        = (Get-Date).ToUniversalTime().ToString("o")
        windowsRequired   = $WindowsSigningRequired
        windowsArtifacts = $artifactResults
        overallResult    = $overallResult
    }
    $audit | ConvertTo-Json -Depth 6 | Set-Content -Path $AuditRecordPath -Encoding UTF8

    return $overallResult
}
