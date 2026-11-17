Invoke-A29Test -Id 'p4' -Technique 'T1053.005' -Summary 'an existing test task has its action modified, restored and deleted (T1053.005)' -Telemetry @('sec:4702', 'task:140', 'sysmon:1') -Attempt {
  $st = Join-Path $env:SystemRoot 'System32\schtasks.exe'
  $name = $script:A29Tag
  $a1 = '/c echo ' + $script:A29Marker + ' original'
  $a2 = '/c echo ' + $script:A29Marker + ' modified'
  $cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
  $exists = $false; $modified = $false; $restored = $false
  try {
    Register-ScheduledTask -TaskName $name -Action (New-ScheduledTaskAction -Execute $cmd -Argument $a1) -Force -ErrorAction Stop | Out-Null
    $exists = [bool](Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue)
    if ($exists) {
      Set-ScheduledTask -TaskName $name -Action (New-ScheduledTaskAction -Execute $cmd -Argument $a2) -ErrorAction Stop | Out-Null
      $modified = ((Get-ScheduledTask -TaskName $name).Actions[0].Arguments -like '*modified*')
      Set-ScheduledTask -TaskName $name -Action (New-ScheduledTaskAction -Execute $cmd -Argument $a1) -ErrorAction Stop | Out-Null
      $restored = ((Get-ScheduledTask -TaskName $name).Actions[0].Arguments -like '*original*')
    }
  } catch {}
  Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
  $gone = -not [bool](Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue)
  return @{ Ran = ($exists -and $modified); Note = "task_created=$exists action_modified=$modified action_restored=$restored task_removed=$gone only_own_test_task_touched=true"; CleanupOk = $gone; NotApplicable = '' }
}
