Invoke-A36Test -Id 's7' -Technique 'T1218.005' -Summary 'mshta runs an HTA whose VBScript starts cmd.exe, which writes one marker file (T1218.005)' -Telemetry @('sysmon:1', 'sec:4688') -Attempt {
  $mk = Join-Path $script:A36Work 'hta-marker.txt'
  $hta = Join-Path $script:A36Work 'dropper.hta'
  $q = [string][char]34
  $sh = 'cmd.exe /c echo ' + $script:A36Marker + ' > ' + $q + $q + $mk + $q + $q
  $body = "<html><head><script language=`"VBScript`">Sub Window_OnLoad`r`nSet s = CreateObject(`"WScript.Shell`")`r`ns.Run `"$($sh.Replace('"', '""'))`", 0, True`r`nwindow.close`r`nEnd Sub</script></head><body></body></html>"
  Set-Content -LiteralPath $hta -Value $body -Encoding ASCII
  $p = Invoke-A36Proc -File (Join-Path $env:SystemRoot 'System32\mshta.exe') -ArgLine ('"' + $hta + '"') -TimeoutSec 25 -NoShell
  for ($i = 0; $i -lt 10 -and -not (Test-A36Marker $mk); $i++) { Start-Sleep -Milliseconds 300 }
  return @{ Ran = (Test-A36Marker $mk); Note = "mshta_started=$($p.Started) timed_out=$($p.TimedOut) child=cmd.exe_via_WScript.Shell"; NotApplicable = '' }
}
