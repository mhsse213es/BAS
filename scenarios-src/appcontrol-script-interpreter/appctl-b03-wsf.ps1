$sn = "bas_$($script:AppCtlTid.Substring(0,8)).wsf"
Invoke-AppCtlTest -Family 'wsf_script_host' -Collection 'Script' -Needle $sn -Technique 'T1059.005' -Attempt {
  $mk = Join-Path $script:AppCtlWork 'wsf-marker.txt'
  $wsf = Join-Path $script:AppCtlWork $sn
  $body = "<?xml version=`"1.0`"?><package><job id=`"BasSim`"><script language=`"JScript`"><![CDATA[var f=new ActiveXObject('Scripting.FileSystemObject').CreateTextFile('$($mk.Replace([string][char]92, '/'))',true);f.Write('$($script:AppCtlMarker)');f.Close();]]></script></job></package>"
  Set-Content -Path $wsf -Value $body -Encoding ASCII
  $p = Invoke-AppCtlProc -File (Join-Path $env:SystemRoot 'System32\cscript.exe') -ArgLine "//B //Nologo `"$wsf`""
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $p.Exit; Note = "timed_out=$($p.TimedOut)"; NotApplicable = '' }
}
