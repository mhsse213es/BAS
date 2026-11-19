$dllName = "bas_$($script:AppCtlTid.Substring(0,8)).dll"
Invoke-AppCtlTest -Family 'dll_loading' -Collection 'Dll' -Needle $dllName -Technique 'T1129' -Attempt {
  $dll = Join-Path $script:AppCtlWork $dllName
  $src = 'public class BasLib { public static string Id() { return "' + $script:AppCtlMarker + '"; } }'
  try { Add-Type -TypeDefinition $src -OutputAssembly $dll -OutputType Library -ErrorAction Stop } catch {}
  if (-not (Test-Path $dll)) { return @{ Ran = $false; Exit = -1; Note = 'compile_failed'; NotApplicable = (Get-AppCtlCompileReason) } }
  $mk = Join-Path $script:AppCtlWork 'dll-marker.txt'
  $child = Join-Path $script:AppCtlWork 'load.ps1'
  Set-Content -Path $child -Value ("try { `$a = [Reflection.Assembly]::LoadFrom('" + $dll + "'); Set-Content -Path '" + $mk + "' -Value `$a.GetType('BasLib').GetMethod('Id').Invoke(`$null, `$null) } catch { }") -Encoding ASCII
  $p = Invoke-AppCtlProc -File (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgLine "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$child`"" -TimeoutSec 40
  $ran = (Test-AppCtlMarker $mk)
  return @{ Ran = $ran; Exit = $p.Exit; Note = "assembly_loaded_by_child_process=$ran"; NotApplicable = '' }
}
