Invoke-AppCtlTest -Family 'rundll32_proxy' -Collection 'Exe' -Needle 'rundll32.exe' -Technique 'T1218.011' -Attempt {
  $mk = Join-Path $script:AppCtlWork 'rundll32-marker.txt'
  $inf = Join-Path $script:AppCtlWork 'proxy.inf'
  $cmd = "cmd.exe /c echo $($script:AppCtlMarker)> `"$mk`""
  $body = "[Version]`r`nSignature=`"`$CHICAGO`$`"`r`n[DefaultInstall]`r`nRunPostSetupCommands=RunIt`r`n[RunIt]`r`n$cmd`r`n"
  Set-Content -Path $inf -Value $body -Encoding ASCII
  $p = Invoke-AppCtlProc -File (Join-Path $env:SystemRoot 'System32\rundll32.exe') -ArgLine "advpack.dll,LaunchINFSection `"$inf`",DefaultInstall,1,N"
  Start-Sleep -Milliseconds 700
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $p.Exit; Note = "timed_out=$($p.TimedOut)"; NotApplicable = '' }
}
