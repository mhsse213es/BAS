$sn = "bas_$($script:AppCtlTid.Substring(0,8)).js"
Invoke-AppCtlTest -Family 'user_writable_script_host' -Collection 'Script' -Needle $sn -Technique 'T1059.007' -Attempt {
  $mk = Join-Path $script:AppCtlWork 'js-marker.txt'
  $js = Join-Path $script:AppCtlWork $sn
  Set-Content -Path $js -Value "var f=new ActiveXObject('Scripting.FileSystemObject').CreateTextFile('$($mk.Replace([string][char]92, '/'))',true);f.Write('$($script:AppCtlMarker)');f.Close();" -Encoding ASCII
  $p = Invoke-AppCtlProc -File (Join-Path $env:SystemRoot 'System32\wscript.exe') -ArgLine "//B //Nologo `"$js`""
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $p.Exit; Note = "timed_out=$($p.TimedOut)"; NotApplicable = '' }
}
