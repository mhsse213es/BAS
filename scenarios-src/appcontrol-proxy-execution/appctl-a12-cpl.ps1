# AppLocker does not evaluate .cpl files (its DLL collection covers .dll and .ocx), so this path is tested against WDAC only.
$cplName = "bas_$($script:AppCtlTid.Substring(0,8)).cpl"
Invoke-AppCtlTest -Family 'control_panel_cpl' -Collection 'Dll' -Needle $cplName -Mechanisms @('wdac') -Technique 'T1218.002' -Attempt {
  $src = Join-Path $env:SystemRoot 'System32\timedate.cpl'
  if (-not (Test-Path $src)) { return @{ Ran = $false; Exit = -1; Note = 'cpl_absent'; NotApplicable = 'the benign signed Control Panel applet used as the artifact is not present' } }
  $cpl = Join-Path $script:AppCtlWork $cplName
  Copy-Item -Path $src -Destination $cpl -Force
  if (-not ('BasNative.K' -as [type])) { try { Add-Type -Namespace BasNative -Name K -MemberDefinition '[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern IntPtr LoadLibraryW(string p); [DllImport("kernel32.dll")] public static extern bool FreeLibrary(IntPtr h);' } catch {} }
  if (-not ('BasNative.K' -as [type])) { return @{ Ran = $false; Exit = -1; Note = 'native_helper_unavailable'; NotApplicable = (Get-AppCtlCompileReason) } }
  $h = [BasNative.K]::LoadLibraryW($cpl)
  $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if ($h -ne [IntPtr]::Zero) { [void][BasNative.K]::FreeLibrary($h) }
  return @{ Ran = ($h -ne [IntPtr]::Zero); Exit = $err; Note = "loadlibrary_ok=$($h -ne [IntPtr]::Zero) win32_error=$err"; NotApplicable = '' }
}
