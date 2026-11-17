Invoke-A36Test -Id 'cc1' -Technique 'T1003.001' -Telemetry @('sysmon:10', 'sec:4663') -Summary 'a query-only handle to lsass.exe is requested with PROCESS_QUERY_LIMITED_INFORMATION; no memory is read (T1003.001 precondition)' -Attempt {
  Add-Type -Name A36Native -Namespace BasSim -MemberDefinition '
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
  '
  $proc = Get-Process -Name lsass -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $proc) { return @{ Ran = $false; Note = 'lsass_not_found'; NotApplicable = 'lsass.exe process was not found on this host' } }
  $h = [BasSim.A36Native]::OpenProcess(0x1000, $false, $proc.Id)
  $granted = ($h -ne [IntPtr]::Zero)
  $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if ($granted) { [void][BasSim.A36Native]::CloseHandle($h) }
  return @{ Ran = $true; Note = "access_requested=PROCESS_QUERY_LIMITED_INFORMATION handle_granted=$granted win32_error=$err memory_read=false credentials_extracted=false this_is_a_posture_probe_only=true"; NotApplicable = '' }
}
