$sn = "bas_$($script:AppCtlTid.Substring(0,8)).bat"
Invoke-AppCtlTest -Family 'cmd_batch_script' -Collection 'Script' -Needle $sn -Technique 'T1059.003' -Attempt {
  $mk = Join-Path $script:AppCtlWork 'batch-marker.txt'
  $bat = Join-Path $script:AppCtlWork $sn
  Set-Content -Path $bat -Value "@echo off`r`necho $($script:AppCtlMarker)> `"$mk`"" -Encoding ASCII
  $p = Invoke-AppCtlProc -File (Join-Path $env:SystemRoot 'System32\cmd.exe') -ArgLine "/d /c `"$bat`""
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $p.Exit; Note = "timed_out=$($p.TimedOut)"; NotApplicable = '' }
}
