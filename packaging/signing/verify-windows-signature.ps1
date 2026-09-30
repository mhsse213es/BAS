# Test-AuthenticodeSignature wraps Get-AuthenticodeSignature into a
# release-gate-friendly result. In production, a CA-issued cert chains to a
# root already in the Windows trust store, so a genuinely signed, untampered
# file reports Valid without any special setup -- the trust-store dance in
# this script's own tests exists only to make a *self-signed test* cert
# behave the same way for testing purposes.

function Test-AuthenticodeSignature {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$RequireTimestamp
    )

    if (-not (Test-Path $Path)) {
        return @{ Valid = $false; Status = "FileNotFound"; Reason = "File not found: $Path"; SignerThumbprint = ""; SignerSubject = "" }
    }

    $sig = Get-AuthenticodeSignature -FilePath $Path
    $statusStr = $sig.Status.ToString()
    $signerThumbprint = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { "" }
    $signerSubject    = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }

    if ($sig.Status -ne "Valid") {
        return @{ Valid = $false; Status = $statusStr; Reason = $sig.StatusMessage; SignerThumbprint = $signerThumbprint; SignerSubject = $signerSubject }
    }

    if ($RequireTimestamp -and -not $sig.TimeStamperCertificate) {
        return @{ Valid = $false; Status = "MissingTimestamp"; Reason = "Signature is valid but carries no RFC 3161 timestamp."; SignerThumbprint = $signerThumbprint; SignerSubject = $signerSubject }
    }

    return @{ Valid = $true; Status = $statusStr; Reason = ""; SignerThumbprint = $signerThumbprint; SignerSubject = $signerSubject }
}
