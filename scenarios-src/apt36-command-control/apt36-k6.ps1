Invoke-A36Test -Id 'k6' -Technique 'T1053.005' -Needle 'bas_a36_' -Telemetry @('sec:4698', 'task:106', 'sysmon:1') -Summary 'a run-tagged one-time scheduled task is created on each configured remote target, queried and deleted over RPC, using the current identity only (T1053.005 remote)' -Attempt {
  if (-not (Test-A36Gate 'BAS_CONFIRM_APT36_LATERAL_MOVEMENT')) { return @{ Ran = $false; Note = 'lab_gate_not_set'; NotApplicable = 'lab gate BAS_CONFIRM_APT36_LATERAL_MOVEMENT is not set to true; this step creates and deletes a scheduled task on remote targets and is skipped without it' } }
  if (-not (Test-A36Admin)) { return @{ Ran = $false; Note = 'not_admin'; NotApplicable = 'remote task creation needs an administrator identity' } }
  $targets = @(); $bad = @()
  foreach ($t in @($env:BAS_LATERAL_TARGETS -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) { if ($t -match '^[A-Za-z0-9._-]{1,253}$') { $targets += $t } else { $bad += $t } }
  if ($targets.Count -eq 0) { return @{ Ran = $false; Note = "no_targets_configured invalid_ignored=$($bad.Count)"; NotApplicable = 'BAS_LATERAL_TARGETS is not set to any valid host name; this pack has not been run against a configured lab target yet' } }
  $st = Join-Path $env:SystemRoot 'System32\schtasks.exe'
  $name = $script:A36Tag
  $mk = 'C:\Users\Public\' + $name + '.txt'
  $results = @()
  foreach ($t in $targets) {
    $tr = 'cmd.exe /c echo ' + $script:A36Marker + ' > "' + $mk + '"'
    $c = Invoke-A36Proc -File $st -ArgLine ('/create /s ' + $t + ' /tn "' + $name + '" /tr "' + $tr.Replace('"', [string][char]92 + '"') + '" /sc once /st 23:59 /ru "' + $env:USERNAME + '" /f') -TimeoutSec 30 -NoShell
    $created = ($c.Exit -eq 0)
    $q = Invoke-A36Proc -File $st -ArgLine ('/query /s ' + $t + ' /tn "' + $name + '"') -TimeoutSec 20 -NoShell
    $seen = ($q.Exit -eq 0)
    [void](Invoke-A36Proc -File $st -ArgLine ('/delete /s ' + $t + ' /tn "' + $name + '" /f') -TimeoutSec 20 -NoShell)
    $q2 = Invoke-A36Proc -File $st -ArgLine ('/query /s ' + $t + ' /tn "' + $name + '"') -TimeoutSec 20 -NoShell
    $removed = ($q2.Exit -ne 0)
    $results += "$t`:created=$created,queried=$seen,removed=$removed"
  }
  $anyCreated = @($results | Where-Object { $_ -match 'created=True' }).Count -gt 0
  $allRemoved = -not (@($results | Where-Object { $_ -match 'removed=False' }).Count -gt 0)
  return @{ Ran = $anyCreated; Note = "targets=$($targets.Count) invalid_ignored=$($bad.Count) current_identity_only=true per_target=$($results -join ' | ')"; CleanupOk = $allRemoved; NotApplicable = '' }
}
