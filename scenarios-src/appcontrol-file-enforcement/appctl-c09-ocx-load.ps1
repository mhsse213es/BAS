$ocxName = "bas_$($script:AppCtlTid.Substring(0,8)).ocx"
Invoke-AppCtlTest -Family 'ocx_module_loading' -Collection 'Dll' -Needle $ocxName -Technique 'T1129' -Attempt {
  $src = Join-Path $env:SystemRoot 'System32\version.dll'
  $ocx = Join-Path $script:AppCtlWork $ocxName
  Copy-Item -Path $src -Destination $ocx -Force
  if (-not ('BasNative.K' -as [type])) { try { Add-Type -Namespace BasNative -Name K -MemberDefinition '[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern IntPtr LoadLibraryW(string p); [DllImport("kernel32.dll")] public static extern bool FreeLibrary(IntPtr h);' } catch {} }
  if (-not ('BasNative.K' -as [type])) { return @{ Ran = $false; Exit = -1; Note = 'native_helper_unavailable'; NotApplicable = (Get-AppCtlCompileReason) } }
  $h = [BasNative.K]::LoadLibraryW($ocx)
  $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if ($h -ne [IntPtr]::Zero) { $err = 0; [void][BasNative.K]::FreeLibrary($h) }
  return @{ Ran = ($h -ne [IntPtr]::Zero); Exit = $err; Note = "loadlibrary_ok=$($h -ne [IntPtr]::Zero) extension=.ocx rll_not_tested=true"; NotApplicable = '' }
}
