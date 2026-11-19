Invoke-A29Test -Id 'x4' -Technique 'T1027' -Summary 'character-code obfuscated PowerShell is deobfuscated and run (T1027, T1140)' -Telemetry @('sysmon:1', 'ps:4104', 'sec:4688') -Attempt {
  $mk = Join-Path $script:A29Work 'obf-marker.txt'
  $plain = "Set-Content -LiteralPath '" + $mk + "' -Value '" + $script:A29Marker + "'"
  $codes = (($plain.ToCharArray() | ForEach-Object { [int]$_ + 3 }) -join ',')
  $drv = '$c=@(' + $codes + ');$s=-join($c|%{[char]($_-3)});$b=[scriptblock]::Create($s);&$b'
  $scriptFile = Join-Path $script:A29Work 'obf.ps1'
  Set-Content -LiteralPath $scriptFile -Value $drv -Encoding ASCII
  $p = Invoke-A29Proc -File (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgLine ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $scriptFile + '"') -TimeoutSec 30 -NoShell
  $ran = Test-A29Marker $mk
  return @{ Ran = $ran; Note = "obfuscation=char_code_offset_plus_3 plaintext_in_script_file=false deobfuscated_and_executed=$ran child_exit=$($p.Exit)"; NotApplicable = '' }
}
