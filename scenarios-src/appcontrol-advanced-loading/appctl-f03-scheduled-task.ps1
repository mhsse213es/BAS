$exeName = "bas_$($script:AppCtlTid.Substring(0,8)).exe"
Invoke-AppCtlTest -Family 'scheduled_task_launch' -Collection 'Exe' -Needle $exeName -Technique 'T1053.005' -Attempt {
  if ($env:BAS_CONFIRM_APPCONTROL_TASK_CREATE -cne 'true') { return @{ Ran = $false; Exit = -1; Note = 'lab_gate_not_set'; NotApplicable = 'lab gate BAS_CONFIRM_APPCONTROL_TASK_CREATE is not set to true; this step creates and removes a temporary scheduled task and is skipped without it' } }
  $exe = Join-Path $script:AppCtlWork $exeName
  if (-not (New-AppCtlExe -Path $exe)) { return @{ Ran = $false; Exit = -1; Note = 'compile_failed'; NotApplicable = (Get-AppCtlCompileReason) } }
  $mk = Join-Path $script:AppCtlWork 'task-marker.txt'
  $name = "BAS-SIM-APPCTL-$($script:AppCtlTid.Substring(0,8))"
  $reg = $false; $state = 'unknown'
  try {
    $act = New-ScheduledTaskAction -Execute $exe -Argument "`"$mk`""
    Register-ScheduledTask -TaskName $name -Action $act -Force -ErrorAction Stop | Out-Null
    $reg = $true
    Start-ScheduledTask -TaskName $name -ErrorAction Stop
    for ($i = 0; $i -lt 25 -and -not (Test-AppCtlMarker $mk); $i++) { Start-Sleep -Milliseconds 400 }
    $state = [string](Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue).State
  } catch { $state = 'error' } finally {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
  }
  $left = [bool](Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue)
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = 0; Note = "task_registered=$reg task_state=$state task_removed=$(-not $left)"; NotApplicable = '' }
}
