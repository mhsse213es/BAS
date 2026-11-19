Invoke-A29Test -Id 'c1' -Technique 'T1550.003' -Summary 'the Kerberos ticket cache is enumerated, the precondition for pass-the-ticket; no ticket is exported or replayed (T1550.003)' -Telemetry @('sysmon:1', 'sec:4688') -Attempt {
  $out = Join-Path $script:A29Work 'klist.txt'
  $klist = Join-Path $env:SystemRoot 'System32\klist.exe'
  $cmdLine = '/c ""' + $klist + '" tickets > "' + $out + '" 2>&1 & "' + $klist + '" tgt >> "' + $out + '" 2>&1"'
  $p = Invoke-A29Proc -File (Join-Path $env:SystemRoot 'System32\cmd.exe') -ArgLine $cmdLine -TimeoutSec 20 -NoShell
  $txt = [string](Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue)
  $count = ([regex]::Matches($txt, '(?im)^\s*#\d+>')).Count
  $ran = ($txt.Trim().Length -gt 0)
  return @{ Ran = $ran; Note = "klist_output_chars=$($txt.Length) tickets_listed=$count ticket_data_exported=false ticket_replayed=false. Pass-the-ticket itself is not performed."; NotApplicable = '' }
}
