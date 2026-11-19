Invoke-A36Test -Id 'd1' -Technique 'T1057' -Telemetry @('sysmon:1', 'sec:4688') -Summary 'running processes are enumerated with tasklist and the output is parsed for security-product names (T1057)' -Attempt {
  $out = Join-Path $script:A36Work 'procs.txt'
  $tl = Join-Path $env:SystemRoot 'System32\tasklist.exe'
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = $tl; $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.CreateNoWindow = $true
  $proc = [Diagnostics.Process]::Start($psi)
  $text = $proc.StandardOutput.ReadToEnd()
  $proc.WaitForExit(10000)
  Set-Content -LiteralPath $out -Value $text -Encoding ASCII
  $count = @(($text -split "`r`n") | Where-Object { $_ -match '\.exe' }).Count
  return @{ Ran = ($count -gt 0); Note = "tasklist_captured=true processes_listed=$count"; NotApplicable = '' }
}
