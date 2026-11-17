$dllName = "bas_$($script:AppCtlTid.Substring(0,8)).dll"
$exeName = "bas_$($script:AppCtlTid.Substring(0,8)).exe"
Invoke-AppCtlTest -Family 'dll_search_order' -Collection 'Dll' -Needle $dllName -Technique 'T1574.001' -Attempt {
  $dll = Join-Path $script:AppCtlWork $dllName
  try { Add-Type -TypeDefinition 'public class BasLib { public static int Id() { return 7; } }' -OutputAssembly $dll -OutputType Library -ErrorAction Stop } catch {}
  if (-not (Test-Path $dll)) { return @{ Ran = $false; Exit = -1; Note = 'dll_build_failed'; NotApplicable = (Get-AppCtlCompileReason) } }
  $exe = Join-Path $script:AppCtlWork $exeName
  $src = 'using System; using System.Runtime.InteropServices; public class BasMain { [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern IntPtr LoadLibraryW(string n); public static void Main(string[] a) { IntPtr h = LoadLibraryW("' + $dllName + '"); if (h != IntPtr.Zero) System.IO.File.WriteAllText(a[0], "' + $script:AppCtlMarker + '"); } }'
  try { Add-Type -TypeDefinition $src -OutputAssembly $exe -OutputType ConsoleApplication -ErrorAction Stop } catch {}
  if (-not (Test-Path $exe)) { return @{ Ran = $false; Exit = -1; Note = 'exe_build_failed'; NotApplicable = (Get-AppCtlCompileReason) } }
  $mk = Join-Path $script:AppCtlWork 'sideload-marker.txt'
  $p = Invoke-AppCtlProc -File $exe -ArgLine "`"$mk`"" -NoShell
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $p.Exit; Note = "dll_resolved_by_name_from_application_directory=$(Test-AppCtlMarker $mk) started=$($p.Started). The host program also runs from the temp directory, so an Exe rule can stop the run before the DLL is reached."; NotApplicable = '' }
}
