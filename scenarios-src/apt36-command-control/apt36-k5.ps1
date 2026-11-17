Invoke-A36Test -Id 'k5' -Technique 'T1569.002' -Needle 'bas_a36_' -Telemetry @('sec:7045', 'sysmon:1') -Summary 'a run-tagged service is created, started, stopped and deleted on each configured remote target over the Service Control Manager, using the current identity only (T1569.002)' -Attempt {
  if ($env:BAS_CONFIRM_APT36_LATERAL_MOVEMENT -cne 'true') { return @{ Ran = $false; Note = 'lab_gate_not_set'; NotApplicable = 'lab gate BAS_CONFIRM_APT36_LATERAL_MOVEMENT is not set to true; this step creates and removes a service on a remote target and is skipped without it' } }
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { return @{ Ran = $false; Note = 'not_admin'; NotApplicable = 'remote service creation needs an administrator identity' } }
  $targets = @(); $bad = @()
  foreach ($t in @($env:BAS_LATERAL_TARGETS -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) { if ($t -match '^[A-Za-z0-9._-]{1,253}$') { $targets += $t } else { $bad += $t } }
  if ($targets.Count -eq 0) { return @{ Ran = $false; Note = "no_targets_configured invalid_ignored=$($bad.Count)"; NotApplicable = 'BAS_LATERAL_TARGETS is not set to any valid host name; this pack has not been run against a configured lab target yet' } }
  $sc = Join-Path $env:SystemRoot 'System32\sc.exe'
  $name = $script:A36Tag
  $results = @()
  foreach ($t in $targets) {
    $created = $false; $started = $false; $removed = $false
    try {
      [void](Invoke-A36Proc -File $sc -ArgLine ('\\' + $t + ' create "' + $name + '" binPath= "cmd.exe /c exit" start= demand') -TimeoutSec 20 -NoShell)
      $created = [bool](Get-Service -ComputerName $t -Name $name -ErrorAction SilentlyContinue)
      if ($created) {
        try { Start-Service -InputObject (Get-Service -ComputerName $t -Name $name) -ErrorAction Stop; $started = $true } catch { $started = $false }
        [void](Invoke-A36Proc -File $sc -ArgLine ('\\' + $t + ' stop "' + $name + '"') -TimeoutSec 20 -NoShell)
      }
    } catch {}
    [void](Invoke-A36Proc -File $sc -ArgLine ('\\' + $t + ' delete "' + $name + '"') -TimeoutSec 20 -NoShell)
    Start-Sleep -Milliseconds 500
    $removed = -not [bool](Get-Service -ComputerName $t -Name $name -ErrorAction SilentlyContinue)
    $results += "$t`:created=$created,started=$started,removed=$removed"
  }
  $anyCreated = @($results | Where-Object { $_ -match 'created=True' }).Count -gt 0
  $allRemoved = -not (@($results | Where-Object { $_ -match 'removed=False' }).Count -gt 0)
  return @{ Ran = $anyCreated; Note = "targets=$($targets.Count) invalid_ignored=$($bad.Count) current_identity_only=true per_target=$($results -join ' | ')"; CleanupOk = $allRemoved; NotApplicable = '' }
}
