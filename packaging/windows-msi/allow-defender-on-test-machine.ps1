<#
.SYNOPSIS
  TEST MACHINES ONLY. Tells Windows Defender to skip the folders the Audspect agent installer uses.

.DESCRIPTION
  Builds that are not signed with a certificate Windows trusts can be flagged by Defender's cloud heuristics
  (seen as Trojan:Win32/Gracing.I). On a machine you own and are testing on, run this once as Administrator before
  running the MSI. It adds Defender exclusions for the installer's check folder, the install folder, and (optionally)
  the folder holding the MSI. Nothing here is part of the product or the MSI, and it must not be used on customer
  machines: a customer's security team should allow the vendor through its own policy.

  Remove the exclusions again with -Remove.

.EXAMPLE
  .\allow-defender-on-test-machine.ps1 -MsiFolder T:\
  .\allow-defender-on-test-machine.ps1 -Remove -MsiFolder T:\
#>
[CmdletBinding()]
param(
    [string] $MsiFolder,
    [switch] $Remove
)

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this from an elevated (Administrator) PowerShell.' }

$paths = @(
    (Join-Path $env:ProgramData 'Audspect'),          # includes ...\Audspect\preflight, created later by the MSI
    (Join-Path $env:ProgramFiles 'BASAgent')          # the install folder
)
if ($MsiFolder) { $paths += $MsiFolder }

foreach ($p in $paths) {
    if ($Remove) {
        Remove-MpPreference -ExclusionPath $p
        Write-Host "Removed exclusion: $p"
    } else {
        Add-MpPreference -ExclusionPath $p
        Write-Host "Added exclusion:   $p"
    }
}

Write-Host ''
Write-Host 'Current path exclusions:'
(Get-MpPreference).ExclusionPath | ForEach-Object { "  $_" }
if (-not $Remove) {
    Write-Host ''
    Write-Host 'If Windows Security still blocks the file, Tamper Protection may be refusing the change. Add the folders by hand in'
    Write-Host 'Windows Security > Virus & threat protection > Manage settings > Exclusions, or restore the file from Protection history.'
}
