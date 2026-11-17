Invoke-A36Test -Id 's6' -Technique 'T1053.005' -Summary 'scheduled task created, run once, queried and deleted (T1053.005)' -Telemetry @('sec:4698', 'task:106', 'sysmon:1') -Attempt {
  $st = Join-Path $env:SystemRoot 'System32\schtasks.exe'
  $name = $script:A36Tag
  $mk = Join-Path $script:A36Work 'task-ran.txt'
  $tr = 'cmd.exe /c echo ' + $script:A36Marker + ' > "' + $mk + '"'
  $c = Invoke-A36Proc -File $st -ArgLine ('/create /tn "' + $name + '" /tr "' + $tr.Replace('"', [string][char]92 + '"') + '" /sc once /st 23:59 /f') -TimeoutSec 20 -NoShell
  $q = Invoke-A36Proc -File $st -ArgLine ('/query /tn "' + $name + '"') -TimeoutSec 15 -NoShell
  $created = ($q.Exit -eq 0)
  if ($created) {
    [void](Invoke-A36Proc -File $st -ArgLine ('/run /tn "' + $name + '"') -TimeoutSec 15 -NoShell)
    for ($i = 0; $i -lt 20 -and -not (Test-A36Marker $mk); $i++) { Start-Sleep -Milliseconds 500 }
  }
  $executed = Test-A36Marker $mk
  [void](Invoke-A36Proc -File $st -ArgLine ('/delete /tn "' + $name + '" /f') -TimeoutSec 15 -NoShell)
  $after = Invoke-A36Proc -File $st -ArgLine ('/query /tn "' + $name + '"') -TimeoutSec 15 -NoShell
  $gone = ($after.Exit -ne 0)
  return @{ Ran = $created; Note = "task_created=$created task_executed=$executed task_removed=$gone"; CleanupOk = $gone; NotApplicable = '' }
}
