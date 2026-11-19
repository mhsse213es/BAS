Invoke-AppCtlTest -Family 'regsvr32_proxy' -Collection 'Exe' -Needle 'regsvr32.exe' -Technique 'T1218.010' -Attempt {
  $mk = Join-Path $script:AppCtlWork 'regsvr32-marker.txt'
  $sct = Join-Path $script:AppCtlWork 'proxy.sct'
  $body = "<?XML version=`"1.0`"?><scriptlet><registration progid=`"BasSim`" classid=`"{$([guid]::NewGuid())}`"><script language=`"JScript`"><![CDATA[var f=new ActiveXObject('Scripting.FileSystemObject').CreateTextFile('$($mk.Replace([string][char]92,'/'))',true);f.Write('$($script:AppCtlMarker)');f.Close();]]></script></registration></scriptlet>"
  Set-Content -Path $sct -Value $body -Encoding ASCII
  $p = Invoke-AppCtlProc -File (Join-Path $env:SystemRoot 'System32\regsvr32.exe') -ArgLine "/s /n /u /i:`"$sct`" scrobj.dll"
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $p.Exit; Note = "timed_out=$($p.TimedOut)"; NotApplicable = '' }
}
