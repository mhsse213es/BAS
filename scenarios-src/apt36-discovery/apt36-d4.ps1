Invoke-A36Test -Id 'd4' -Technique 'T1016' -Telemetry @('sysmon:1', 'sec:4688') -Summary 'network configuration is enumerated with ipconfig and arp, output captured to a run-tagged file (T1016)' -Attempt {
  $out = Join-Path $script:A36Work 'netcfg.txt'
  $ipc = Join-Path $env:SystemRoot 'System32\ipconfig.exe'
  $arp = Join-Path $env:SystemRoot 'System32\arp.exe'
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = $ipc; $psi.Arguments = '/all'; $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.CreateNoWindow = $true
  $proc = [Diagnostics.Process]::Start($psi)
  $text = $proc.StandardOutput.ReadToEnd()
  $proc.WaitForExit(10000)
  $psi2 = New-Object Diagnostics.ProcessStartInfo
  $psi2.FileName = $arp; $psi2.Arguments = '-a'; $psi2.UseShellExecute = $false; $psi2.RedirectStandardOutput = $true; $psi2.CreateNoWindow = $true
  $proc2 = [Diagnostics.Process]::Start($psi2)
  $text2 = $proc2.StandardOutput.ReadToEnd()
  $proc2.WaitForExit(10000)
  Set-Content -LiteralPath $out -Value ($text + $text2) -Encoding ASCII
  $captured = ($text.Trim().Length -gt 0)
  return @{ Ran = $captured; Note = "ipconfig_captured=$captured arp_captured=$($text2.Trim().Length -gt 0)"; NotApplicable = '' }
}
