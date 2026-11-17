Invoke-AppCtlTest -Family 'wmi_process_create' -Collection 'Exe' -Needle 'cmd.exe' -Technique 'T1047' -Attempt {
  $mk = Join-Path $script:AppCtlWork 'wmi-marker.txt'
  $asr = 'unknown'
  try { $mp = Get-MpPreference -ErrorAction Stop; $ids = @($mp.AttackSurfaceReductionRules_Ids | ForEach-Object { "$_".ToUpper() }); $i = [array]::IndexOf($ids, 'D1E49AAC-8F56-4280-B9BA-993A6D77406C'); $asr = if ($i -ge 0) { "action=$(@($mp.AttackSurfaceReductionRules_Actions)[$i])" } else { 'not_configured' } } catch {}
  $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = "cmd.exe /d /c echo $($script:AppCtlMarker)> `"$mk`"" } -ErrorAction SilentlyContinue
  for ($i = 0; $i -lt 10 -and -not (Test-AppCtlMarker $mk); $i++) { Start-Sleep -Milliseconds 400 }
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = [int]$r.ReturnValue; Note = "asr_psexec_wmi_rule=$asr create_return=$($r.ReturnValue)"; NotApplicable = '' }
}
