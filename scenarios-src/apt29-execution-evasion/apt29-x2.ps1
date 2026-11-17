Invoke-A29Test -Id 'x2' -Technique 'T1218.011' -Summary 'rundll32 proxies execution through an INF section (T1218.011)' -Telemetry @('sysmon:1', 'sec:4688') -Attempt {
  $mk = Join-Path $script:A29Work 'rundll32-marker.txt'
  $inf = Join-Path $script:A29Work 'proxy.inf'
  $cmd = 'cmd.exe /c echo ' + $script:A29Marker + '> "' + $mk + '"'
  $body = "[Version]`r`nSignature=`"`$CHICAGO`$`"`r`n[DefaultInstall]`r`nRunPostSetupCommands=RunIt`r`n[RunIt]`r`n$cmd`r`n"
  Set-Content -Path $inf -Value $body -Encoding ASCII
  $p = Invoke-A29Proc -File (Join-Path $env:SystemRoot 'System32\rundll32.exe') -ArgLine ('advpack.dll,LaunchINFSection "' + $inf + '",DefaultInstall,1,N')
  for ($i = 0; $i -lt 10 -and -not (Test-A29Marker $mk); $i++) { Start-Sleep -Milliseconds 300 }
  return @{ Ran = (Test-A29Marker $mk); Note = "rundll32_started=$($p.Started) timed_out=$($p.TimedOut) export=advpack.dll,LaunchINFSection"; NotApplicable = '' }
}
