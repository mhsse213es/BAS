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

    $lines = $ManifestContent -split "`n" | Where-Object { $_ -ne "" }
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
