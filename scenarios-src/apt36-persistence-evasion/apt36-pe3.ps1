Invoke-A36Test -Id 'pe3' -Technique 'T1543.003' -Telemetry @('sec:4697', 'sysmon:1') -Summary 'a Windows service is created, started, stopped and deleted, then its removal is independently verified (T1543.003)' -Attempt {
  if ($env:BAS_CONFIRM_APT36_SERVICE_CREATE -cne 'true') { return @{ Ran = $false; Note = 'lab_gate_not_set'; NotApplicable = 'lab gate BAS_CONFIRM_APT36_SERVICE_CREATE is not set to true; this step creates and removes a Windows service and is skipped without it' } }
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { return @{ Ran = $false; Note = 'not_admin'; NotApplicable = 'creating a service needs an administrator identity' } }
  $name = $script:A36Tag
  $sc = Join-Path $env:SystemRoot 'System32\sc.exe'
  $bin = Join-Path $env:SystemRoot 'System32\cmd.exe'
  $created = $false; $started = $false; $stopped = $false
  [void](Invoke-A36Proc -File $sc -ArgLine ('create "' + $name + '" binPath= "' + $bin + ' /c exit" start= demand') -TimeoutSec 20 -NoShell)
  $created = [bool](Get-Service -Name $name -ErrorAction SilentlyContinue)
  if ($created) {
    try { Start-Service -Name $name -ErrorAction Stop; Start-Sleep -Milliseconds 500; $started = $true } catch { $started = $false }
    try { Stop-Service -Name $name -Force -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Milliseconds 500
    $stopped = ((Get-Service -Name $name -ErrorAction SilentlyContinue).Status -ne 'Running')
  }
  [void](Invoke-A36Proc -File $sc -ArgLine ('delete "' + $name + '"') -TimeoutSec 20 -NoShell)
  Start-Sleep -Milliseconds 500
  $gone = -not [bool](Get-Service -Name $name -ErrorAction SilentlyContinue)
  return @{ Ran = $created; Note = "service_created=$created service_started=$started service_stopped=$stopped service_removed=$gone only_own_test_service_touched=true"; CleanupOk = $gone; NotApplicable = '' }
}
