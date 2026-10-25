#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
  Real-machine lifecycle test for the Audspect Agent MSI. Run it on a CLEAN lab machine (a VM you can
  discard), never on a machine whose agent you want to keep: it installs, upgrades, repairs and
  removes the "Audspect Agent" service.

.DESCRIPTION
  Needs a reachable lab orchestrator. Use the bundle downloaded from that orchestrator's dashboard
  (AudspectAgent-x64.zip, extracted) and the fingerprint shown in the dashboard.

  Each check prints PASS or FAIL. Results are real only for the OS this ran on, so run it once per
  supported OS (Windows 10, 11, Server 2019, 2022) and keep the transcripts.

.EXAMPLE
  .\Test-MsiLifecycle.ps1 -BundleDir C:\lab\bundle -Fingerprint <dashboard value> -Secret (Read-Host -AsSecureString) `
      -UpgradeMsi C:\lab\AudspectAgent-x64-newer.msi
#>
param(
    [Parameter(Mandatory)][string]$BundleDir,
    [Parameter(Mandatory)][string]$Fingerprint,
    [Parameter(Mandatory)][securestring]$Secret,
    [string]$UpgradeMsi,
    [string]$WrongSecret = 'definitely-not-the-secret'
)
$ErrorActionPreference = 'Stop'
$msi = Join-Path $BundleDir 'AudspectAgent-x64.msi'
$svcName = 'Audspect Agent'
$installDir = Join-Path $env:ProgramFiles 'BASAgent'
$failures = New-Object System.Collections.Generic.List[string]
function Check([bool]$ok, [string]$name) { if ($ok) { Write-Host "PASS  $name" } else { Write-Host "FAIL  $name"; $failures.Add($name) } }
function ServiceExists { [bool](Get-Service -Name $svcName -ErrorAction SilentlyContinue) }
function ArpEntry { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'Audspect Agent' } }

function Run-Msi([string[]]$args, [string]$secretValue, [string]$log) {
    $env:AUDSPECT_AGENT_SECRET = $secretValue
    try {
        $p = Start-Process msiexec.exe -ArgumentList $args -Wait -PassThru
        return $p.ExitCode
    } finally { Remove-Item Env:AUDSPECT_AGENT_SECRET -ErrorAction SilentlyContinue }
}
function Plain([securestring]$s) {
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}
$goodSecret = Plain $Secret
$log = { param($n) Join-Path $env:TEMP "audspect-lifecycle-$n.log" }

Check (-not (ServiceExists)) 'precondition: no Audspect Agent service exists (use a clean machine)'
if (ServiceExists) { Write-Host 'Aborting: this machine already has an agent.'; exit 2 }

# 1. Fail-closed cases: nothing may be installed.
$rc = Run-Msi @('/i', "`"$msi`"", '/qn', '/l*v', "`"$(& $log 'nofp')`"") $goodSecret
Check ($rc -ne 0 -and -not (ServiceExists)) 'silent install without CONFIG_FINGERPRINT fails and installs nothing'

$rc = Run-Msi @('/i', "`"$msi`"", '/qn', '/l*v', "`"$(& $log 'badfp')`"", "CONFIG_FINGERPRINT=$('0' * 64)") $goodSecret
Check ($rc -ne 0 -and -not (ServiceExists)) 'a wrong fingerprint is refused and installs nothing'

$rc = Run-Msi @('/i', "`"$msi`"", '/qn', '/l*v', "`"$(& $log 'badsecret')`"", "CONFIG_FINGERPRINT=$Fingerprint") $WrongSecret
Check ($rc -ne 0 -and -not (ServiceExists)) 'a wrong secret fails the pre-install check and installs nothing'

# 2. Successful silent install.
$rc = Run-Msi @('/i', "`"$msi`"", '/qn', '/l*v', "`"$(& $log 'install')`"", "CONFIG_FINGERPRINT=$Fingerprint") $goodSecret
Check ($rc -eq 0) "silent install succeeds (exit $rc)"
Check (ServiceExists) 'the Audspect Agent service is registered'
Check ((Get-Service $svcName -ErrorAction SilentlyContinue).Status -eq 'Running') 'the service is running'
Check (Test-Path (Join-Path $installDir 'bas_agent.exe')) 'bas_agent.exe is in the install folder'
Check ($null -ne (ArpEntry)) 'the agent appears in Apps & features'
$logText = Get-Content (& $log 'install') -Raw
Check (-not $logText.Contains($goodSecret)) 'the MSI log does not contain the agent secret'
$cmdlines = (Get-CimInstance Win32_Process -Filter "Name='msiexec.exe'" | ForEach-Object CommandLine) -join "`n"
Check (-not $cmdlines.Contains($goodSecret)) 'no msiexec command line contains the agent secret'

# 3. Enrollment state that an upgrade must preserve.
$paramKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName\Parameters"
$before = if (Test-Path $paramKey) { (Get-ItemProperty $paramKey | ConvertTo-Json -Compress) } else { '' }
Check ($before -ne '') 'service parameters exist after install'

# 4. Repair.
$rc = Run-Msi @('/fa', "`"$msi`"", '/qn', '/l*v', "`"$(& $log 'repair')`"") ''
Check ($rc -eq 0 -and (ServiceExists)) 'repair succeeds and keeps the service'

# 5. Upgrade without re-enrolling.
if ($UpgradeMsi) {
    $rc = Run-Msi @('/i', "`"$UpgradeMsi`"", '/qn', '/l*v', "`"$(& $log 'upgrade')`"") ''
    Check ($rc -eq 0) "upgrade to the newer MSI succeeds with no secret or fingerprint (exit $rc)"
    $after = (Get-ItemProperty $paramKey | ConvertTo-Json -Compress)
    Check ($before -eq $after) 'service parameters and the stored secret are unchanged by the upgrade'
    Check ((Get-Service $svcName).Status -eq 'Running') 'the service runs after the upgrade'
    Check (@(ArpEntry).Count -eq 1) 'exactly one Apps & features entry after the upgrade'
    $msi = $UpgradeMsi
} else {
    Write-Host 'SKIP  upgrade checks (pass -UpgradeMsi with a higher-versioned build)'
}

# 6. Uninstall.
$rc = Run-Msi @('/x', "`"$msi`"", '/qn', '/l*v', "`"$(& $log 'uninstall')`"") ''
Check ($rc -eq 0) "uninstall succeeds (exit $rc)"
Check (-not (ServiceExists)) 'the service is gone'
Check ($null -eq (ArpEntry)) 'the Apps & features entry is gone'
Check (-not (Test-Path (Join-Path $installDir 'bas_agent.exe'))) 'bas_agent.exe is removed (a reboot may be needed if it was in use)'

Write-Host ''
Write-Host "Logs: $env:TEMP\audspect-lifecycle-*.log"
if ($failures.Count -gt 0) { Write-Host "$($failures.Count) check(s) failed"; exit 1 }
Write-Host 'All lifecycle checks passed on this machine.'
Write-Host 'Still to do by hand on each OS: the interactive wizard, rollback after a forced failure, and the dashboard Uninstall Agent action.'
