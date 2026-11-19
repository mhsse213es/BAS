<#
.SYNOPSIS
  Adds the previous signed release's hashes to a new BINARIES.sha256 as "#prev" lines.

.DESCRIPTION
  An agent built before this release still runs its old binary. If the new manifest
  dropped that hash, the server would quarantine the agent as an unknown binary.
  Carrying the previous release's hashes lets the server degrade such agents to
  outdated instead, and return them to active once they run a current binary
  (see orchestrator/internal/integrity/trust_state.go).

  Hashes already in the new manifest are not repeated. Earlier #prev lines are kept.
  Run this before the manifest is signed, because the signature covers the whole file.

.PARAMETER Manifest
  The new BINARIES.sha256 (modified in place).

.PARAMETER Previous
  The previous release's BINARIES.sha256 (for example from `git show HEAD:...`).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Manifest,
    [Parameter(Mandatory)] [string] $Previous
)

$ErrorActionPreference = 'Stop'

function Split-Entry([string] $line) {
    $parts = $line.Trim().Split(' ', [StringSplitOptions]::RemoveEmptyEntries)
    if ($parts.Count -lt 2) { return $null }
    return [pscustomobject]@{ Hash = $parts[0].ToLowerInvariant(); File = $parts[1] }
}

$current = @{}
foreach ($line in (Get-Content -LiteralPath $Manifest)) {
    $t = $line.Trim()
    if ($t -eq '') { continue }
    # A "#prev" line already names a hash in the manifest, so it must not be carried again (idempotent, as the
    # shell version is). Other comment lines, including #revoked, are not hashes here.
    if ($t.StartsWith('#prev ')) { $t = $t.Substring(6) }
    elseif ($t.StartsWith('#')) { continue }
    $e = Split-Entry $t
    if ($e) { $current[$e.Hash] = $true }
}

$carried = @{}
$add = @()
foreach ($line in (Get-Content -LiteralPath $Previous)) {
    $t = $line.Trim()
    if ($t -eq '') { continue }
    if ($t.StartsWith('#prev ')) { $t = $t.Substring(6) }
    elseif ($t.StartsWith('#')) { continue }
    $e = Split-Entry $t
    if (-not $e) { continue }
    if ($current.ContainsKey($e.Hash) -or $carried.ContainsKey($e.Hash)) { continue }
    $carried[$e.Hash] = $true
    $add += ('#prev {0}  {1}' -f $e.Hash, $e.File)
}

# Revocations ("#revoked <hash>  <file>") are carried forward automatically, so a revoked binary stays revoked in
# every later release. A hash already revoked in the new manifest is not repeated.
$revokedNow = @{}
foreach ($line in (Get-Content -LiteralPath $Manifest)) {
    $t = $line.Trim()
    if ($t.StartsWith('#revoked ')) {
        $p = $t.Split(' ', [StringSplitOptions]::RemoveEmptyEntries)
        if ($p.Count -ge 3) { $revokedNow[$p[1].ToLowerInvariant()] = $true }
    }
}
$revokeAdd = @()
foreach ($line in (Get-Content -LiteralPath $Previous)) {
    $t = $line.Trim()
    if (-not $t.StartsWith('#revoked ')) { continue }
    $p = $t.Split(' ', [StringSplitOptions]::RemoveEmptyEntries)
    if ($p.Count -lt 3) { continue }
    $h = $p[1].ToLowerInvariant()
    if ($revokedNow.ContainsKey($h)) { continue }
    $revokedNow[$h] = $true
    $revokeAdd += ('#revoked {0}  {1}' -f $h, $p[2])
}

# The previous release's version, from the bas-install-<version> folder its manifest sits in. The server defaults the
# fleet minimum agent version to it. Nothing is written when the folder carries no version, or a line already exists.
$versionAdd = @()
$prevDir = (Get-Item -LiteralPath $Previous).Directory.Name
if ($prevDir -match '^bas-install-([0-9]+(\.[0-9]+){0,3})$') {
    $hasVersion = $false
    foreach ($line in (Get-Content -LiteralPath $Manifest)) { if ($line.Trim().StartsWith('#prev-version ')) { $hasVersion = $true } }
    if (-not $hasVersion) { $versionAdd += ('#prev-version {0}' -f $Matches[1]) }
}

# A new revocation is made by listing the hash in packaging\revoked-binaries.txt (BAS_REVOKED_LIST overrides the path):
# "<64 hex>  [file name]  [note]" per line, "#" comments. Malformed lines are skipped.
$list = if ($env:BAS_REVOKED_LIST) { $env:BAS_REVOKED_LIST } else { Join-Path $PSScriptRoot 'revoked-binaries.txt' }
if (Test-Path -LiteralPath $list) {
    foreach ($line in (Get-Content -LiteralPath $list)) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        $p = $t.Split(' ', [StringSplitOptions]::RemoveEmptyEntries)
        $h = $p[0].ToLowerInvariant()
        if ($h -notmatch '^[0-9a-f]{64}$' -or $revokedNow.ContainsKey($h)) { continue }
        $revokedNow[$h] = $true
        $name = if ($p.Count -ge 2) { $p[1] } else { 'revoked' }
        $revokeAdd += ('#revoked {0}  {1}' -f $h, $name)
    }
}

$toWrite = @($add) + @($revokeAdd) + @($versionAdd)
if ($toWrite.Count -gt 0) {
    Add-Content -LiteralPath $Manifest -Value $toWrite -Encoding ascii
}
Write-Output $add.Count
