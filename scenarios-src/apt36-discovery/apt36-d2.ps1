Invoke-A36Test -Id 'd2' -Technique 'T1082' -Telemetry @('sysmon:1', 'sec:4688') -Summary 'system information is enumerated with systeminfo and a synthetic virtualization/sandbox check (T1082)' -Attempt {
  $si = Join-Path $env:SystemRoot 'System32\systeminfo.exe'
  $out = Join-Path $script:A36Work 'sysinfo.txt'
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = $si; $psi.Arguments = '/FO LIST'; $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.CreateNoWindow = $true
  $proc = [Diagnostics.Process]::Start($psi)
  $text = $proc.StandardOutput.ReadToEnd()
  $proc.WaitForExit(15000)
  Set-Content -LiteralPath $out -Value $text -Encoding ASCII
  $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
  $vm = ($cs -and ($cs.Manufacturer -match 'VMware|VirtualBox|QEMU|Microsoft Corporation'))
  $captured = ($text.Trim().Length -gt 0)
  return @{ Ran = $captured; Note = "systeminfo_captured=$captured manufacturer=$($cs.Manufacturer) sandbox_indicator_detected=$vm"; NotApplicable = '' }
}
