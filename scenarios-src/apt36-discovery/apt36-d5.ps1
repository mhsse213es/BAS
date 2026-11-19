Invoke-A36Test -Id 'd5' -Technique 'T1135' -Telemetry @('sysmon:1', 'sec:4688') -Summary 'network shares reachable from this host are enumerated with net view, the lateral-movement preparation step (T1135)' -Attempt {
  $nv = Join-Path $env:SystemRoot 'System32\net.exe'
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = $nv; $psi.Arguments = 'view \\\\localhost'; $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
  $proc = [Diagnostics.Process]::Start($psi)
  $text = $proc.StandardOutput.ReadToEnd() + $proc.StandardError.ReadToEnd()
  $proc.WaitForExit(15000)
  $out = Join-Path $script:A36Work 'shares.txt'
  Set-Content -LiteralPath $out -Value $text -Encoding ASCII
  $shares = @(($text -split "`r`n") | Where-Object { $_ -match '^\w' -and $_ -notmatch '^(Shared resources|Share name|The command)' })
  return @{ Ran = ($text.Trim().Length -gt 0); Note = "target=localhost net_view_exit=$($proc.ExitCode) lines_returned=$($shares.Count)"; NotApplicable = '' }
}
