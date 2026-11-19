$sn = "bas_$($script:AppCtlTid.Substring(0,8)).vbs"
Invoke-AppCtlTest -Family 'wscript_host' -Collection 'Script' -Needle $sn -Technique 'T1059.005' -Attempt {
  $mk = Join-Path $script:AppCtlWork 'wscript-marker.txt'
  $vbs = Join-Path $script:AppCtlWork $sn
  Set-Content -Path $vbs -Value "Set f = CreateObject(`"Scripting.FileSystemObject`").CreateTextFile(`"$mk`", True)`r`nf.Write `"$($script:AppCtlMarker)`"`r`nf.Close" -Encoding ASCII
  $p = Invoke-AppCtlProc -File (Join-Path $env:SystemRoot 'System32\wscript.exe') -ArgLine "//B //Nologo `"$vbs`""
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $p.Exit; Note = "timed_out=$($p.TimedOut)"; NotApplicable = '' }
}
