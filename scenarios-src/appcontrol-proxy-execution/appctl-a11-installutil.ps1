Invoke-AppCtlTest -Family 'installutil_proxy' -Collection 'Exe' -Needle 'installutil.exe' -Technique 'T1218.004' -Attempt {
  $iu = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe'
  if (-not (Test-Path $iu)) { return @{ Ran = $false; Exit = -1; Note = 'installutil_absent'; NotApplicable = 'InstallUtil.exe is not present on this host, so the path cannot be tested' } }
  $mk = Join-Path $script:AppCtlWork 'installutil-marker.txt'
  $dll = Join-Path $script:AppCtlWork 'proxy.dll'
  $src = 'using System; using System.ComponentModel; using System.Configuration.Install; [RunInstaller(true)] public class BasInst : Installer { public override void Uninstall(System.Collections.IDictionary s) { System.IO.File.WriteAllText(@"' + $mk + '", "' + $script:AppCtlMarker + '"); } }'
  try { Add-Type -TypeDefinition $src -ReferencedAssemblies 'System.Configuration.Install' -OutputAssembly $dll -OutputType Library -ErrorAction Stop } catch {}
  if (-not (Test-Path $dll)) { return @{ Ran = $false; Exit = -1; Note = 'assembly_build_failed'; NotApplicable = (Get-AppCtlCompileReason) } }
  $p = Invoke-AppCtlProc -File $iu -ArgLine "/U /LogToConsole=false `"$dll`"" -TimeoutSec 40
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $p.Exit; Note = "timed_out=$($p.TimedOut)"; NotApplicable = '' }
}
