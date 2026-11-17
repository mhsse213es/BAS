Invoke-A29Test -Id 'x6' -Technique 'T1036.005' -Summary 'a benign binary runs from a user path under a system process name (T1036.005)' -Telemetry @('sysmon:1', 'sec:4688') -Attempt {
  $dst = Join-Path $script:A29Work 'svchost.exe'
  Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\hostname.exe') -Destination $dst -Force
  $out = Join-Path $script:A29Work 'masq-out.txt'
  $p = Invoke-A29Proc -File (Join-Path $env:SystemRoot 'System32\cmd.exe') -ArgLine ('/c ""' + $dst + '" > "' + $out + '""') -TimeoutSec 20 -NoShell
  $txt = [string](Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue)
  $ran = ($txt.Trim().Length -gt 0)
  return @{ Ran = $ran; Note = "image_name=svchost.exe image_location=user_temp expected_location=System32 ran=$ran"; NotApplicable = '' }
}
