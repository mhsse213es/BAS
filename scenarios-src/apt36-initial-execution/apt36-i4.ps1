Invoke-A36Test -Id 'i4' -Technique 'T1059.001' -Telemetry @('sysmon:1', 'ps:4104', 'sec:4688') -Summary 'encoded PowerShell is launched as a hidden child process and writes one marker file (T1059.001)' -Attempt {
  $mk = Join-Path $script:A36Work 'enc-marker.txt'
  $script1 = "Set-Content -LiteralPath '" + $mk + "' -Value '" + $script:A36Marker + "'"
  $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script1))
  $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $p = Invoke-A36Proc -File $ps -ArgLine ('-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand ' + $enc) -TimeoutSec 20 -NoShell
  return @{ Ran = (Test-A36Marker $mk); Note = "powershell_started=$($p.Started) timed_out=$($p.TimedOut) child_exit=$($p.Exit) window_style=hidden"; NotApplicable = '' }
}
