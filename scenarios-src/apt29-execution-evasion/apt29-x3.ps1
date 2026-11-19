Invoke-A29Test -Id 'x3' -Technique 'T1218.005' -Summary 'mshta runs an HTA script that writes one marker file (T1218.005)' -Telemetry @('sysmon:1', 'sec:4688') -Attempt {
  $mk = Join-Path $script:A29Work 'mshta-marker.txt'
  $hta = Join-Path $script:A29Work 'proxy.hta'
  $body = "<html><head><script language=`"VBScript`">Sub Window_OnLoad`r`nSet f = CreateObject(`"Scripting.FileSystemObject`").CreateTextFile(`"$mk`", True)`r`nf.Write `"$($script:A29Marker)`"`r`nf.Close`r`nwindow.close`r`nEnd Sub</script></head><body></body></html>"
  Set-Content -Path $hta -Value $body -Encoding ASCII
  $p = Invoke-A29Proc -File (Join-Path $env:SystemRoot 'System32\mshta.exe') -ArgLine ('"' + $hta + '"')
  return @{ Ran = (Test-A29Marker $mk); Note = "mshta_started=$($p.Started) timed_out=$($p.TimedOut)"; NotApplicable = '' }
}
