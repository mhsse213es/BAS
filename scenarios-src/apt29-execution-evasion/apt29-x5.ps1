Invoke-A29Test -Id 'x5' -Technique 'T1027.001' -Summary 'binary padding changes a benign binary hash while it still runs (T1027.001)' -Telemetry @('sysmon:1') -Attempt {
  $src = Join-Path $env:SystemRoot 'System32\hostname.exe'
  $dst = Join-Path $script:A29Work 'hostname_padded.exe'
  Copy-Item -LiteralPath $src -Destination $dst -Force
  $h1 = (Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash
  $fs = [IO.File]::Open($dst, [IO.FileMode]::Append)
  try { $pad = New-Object byte[] (2MB); $fs.Write($pad, 0, $pad.Length) } finally { $fs.Close() }
  $h2 = (Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash
  $out = Join-Path $script:A29Work 'padded-out.txt'
  $p = Invoke-A29Proc -File (Join-Path $env:SystemRoot 'System32\cmd.exe') -ArgLine ('/c ""' + $dst + '" > "' + $out + '""') -TimeoutSec 20 -NoShell
  $txt = [string](Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue)
  $ran = ($txt.Trim().Length -gt 0 -and $h1 -ne $h2)
  return @{ Ran = $ran; Note = "hash_changed=$($h1 -ne $h2) pad_bytes=2097152 padded_binary_ran=$($txt.Trim().Length -gt 0)"; NotApplicable = '' }
}
