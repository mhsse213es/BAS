Invoke-A36Test -Id 's1' -Technique 'T1204.002' -Telemetry @('sysmon:1', 'sec:4688') -Summary 'a process named winword.exe launches PowerShell (T1204.002 execution, T1059.001); the parent is a renamed copy of cmd.exe, not Microsoft Word' -Attempt {
  $dir = Join-Path $script:A36Work 'office'
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
  $parent = Join-Path $dir 'winword.exe'
  Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $parent -Force
  $mk = Join-Path $script:A36Work 'child-marker.txt'
  $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $arg = '/c ""' + $ps + '" -NoProfile -NonInteractive -Command "Set-Content -LiteralPath ''' + $mk + ''' -Value ''' + $script:A36Marker + '''""'
  $p = Invoke-A36Proc -File $parent -ArgLine $arg -TimeoutSec 25 -NoShell
  $ran = Test-A36Marker $mk
  return @{ Ran = $ran; Note = "parent_image=winword.exe parent_is_microsoft_word=false child=powershell.exe started=$($p.Started) child_exit=$($p.Exit). Delivery (T1566.001) is not part of this step."; NotApplicable = '' }
}
