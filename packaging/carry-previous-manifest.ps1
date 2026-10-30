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
    if ($t -eq '' -or $t.StartsWith('#')) { continue }
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

if ($add.Count -gt 0) {
    Add-Content -LiteralPath $Manifest -Value $add -Encoding ascii
}
Write-Output $add.Count
