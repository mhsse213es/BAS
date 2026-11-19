Invoke-AppCtlTest -Family 'cmstp_proxy' -Collection 'Exe' -Needle 'cmstp.exe' -Technique 'T1218.003' -Attempt {
  $mk = Join-Path $script:AppCtlWork 'cmstp-marker.txt'
  $inf = Join-Path $script:AppCtlWork 'proxy.inf'
  $body = "[version]`r`nSignature=`"`$chicago`$`"`r`nAdvancedINF=2.5`r`n[DefaultInstall_SingleUser]`r`nRunPreSetupCommands=RunIt:2`r`n[RunIt]`r`ncmd.exe /c echo $($script:AppCtlMarker)> `"$mk`"`r`n[Strings]`r`nServiceName=`"BasSim`"`r`nShortSvcName=`"BasSim`"`r`n"
  Set-Content -Path $inf -Value $body -Encoding ASCII
  $p = Invoke-AppCtlProc -File (Join-Path $env:SystemRoot 'System32\cmstp.exe') -ArgLine "/s /ns `"$inf`"" -TimeoutSec 15
  for ($i = 0; $i -lt 12 -and -not (Test-AppCtlMarker $mk); $i++) { Start-Sleep -Milliseconds 500 }
  Get-Process -Name cmstp -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $p.Exit; Note = "timed_out=$($p.TimedOut)"; NotApplicable = '' }
}
