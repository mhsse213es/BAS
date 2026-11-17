Invoke-AppCtlTest -Family 'mshta_proxy' -Collection 'Exe' -Needle 'mshta.exe' -Technique 'T1218.005' -Attempt {
  $mk = Join-Path $script:AppCtlWork 'mshta-marker.txt'
  $hta = Join-Path $script:AppCtlWork 'proxy.hta'
  $body = "<html><head><script language=`"VBScript`">Sub Window_OnLoad`r`nSet f = CreateObject(`"Scripting.FileSystemObject`").CreateTextFile(`"$mk`", True)`r`nf.Write `"$($script:AppCtlMarker)`"`r`nf.Close`r`nwindow.close`r`nEnd Sub</script></head><body></body></html>"
  Set-Content -Path $hta -Value $body -Encoding ASCII
  $p = Invoke-AppCtlProc -File (Join-Path $env:SystemRoot 'System32\mshta.exe') -ArgLine "`"$hta`""
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $p.Exit; Note = "timed_out=$($p.TimedOut)"; NotApplicable = '' }
}
