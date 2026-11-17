Invoke-A29Test -Id 's2b' -Technique 'T1059.001' -Summary 'layered encoded PowerShell is decoded and executed locally (T1059.001, T1027, T1140)' -Telemetry @('sysmon:1', 'ps:4104', 'sec:4688') -Attempt {
  $mk = Join-Path $script:A29Work 'executed.txt'
  $inner = "Set-Content -LiteralPath '" + $mk + "' -Value '" + $script:A29Marker + "'"
  $layer1 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
  $outer = "Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('" + $layer1 + "')))"
  $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($outer))
  $p = Invoke-A29Proc -File (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgLine "-NoProfile -NonInteractive -EncodedCommand $enc" -TimeoutSec 30 -NoShell
  $ran = Test-A29Marker $mk
  return @{ Ran = $ran; Note = "child_started=$($p.Started) child_exit=$($p.Exit) decoded_payload_executed=$ran layers=2 network_used=false"; NotApplicable = '' }
}
