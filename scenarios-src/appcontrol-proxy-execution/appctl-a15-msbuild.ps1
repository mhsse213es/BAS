Invoke-AppCtlTest -Family 'msbuild_proxy' -Collection 'Exe' -Needle 'msbuild.exe' -Technique 'T1127.001' -Attempt {
  $msb = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe'
  if (-not (Test-Path $msb)) { return @{ Ran = $false; Exit = -1; Note = 'msbuild_absent'; NotApplicable = 'MSBuild.exe is not present on this host, so the path cannot be tested' } }
  $mk = Join-Path $script:AppCtlWork 'msbuild-marker.txt'
  $proj = Join-Path $script:AppCtlWork 'proxy.proj'
  $body = "<Project ToolsVersion=`"4.0`" xmlns=`"http://schemas.microsoft.com/developer/msbuild/2003`"><Target Name=`"Go`"><BasTask/></Target><UsingTask TaskName=`"BasTask`" TaskFactory=`"CodeTaskFactory`" AssemblyFile=`"`$(MSBuildToolsPath)\Microsoft.Build.Tasks.v4.0.dll`"><Task><Code Type=`"Fragment`" Language=`"cs`"><![CDATA[System.IO.File.WriteAllText(@`"$mk`", `"$($script:AppCtlMarker)`");]]></Code></Task></UsingTask></Project>"
  Set-Content -Path $proj -Value $body -Encoding ASCII
  $p = Invoke-AppCtlProc -File $msb -ArgLine "/nologo `"$proj`"" -TimeoutSec 60
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $p.Exit; Note = "timed_out=$($p.TimedOut)"; NotApplicable = '' }
}
