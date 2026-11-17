Invoke-A29Test -Id 'x7' -Technique 'T1070.006' -Summary 'file timestamps are rewritten to an earlier date (T1070.006)' -Telemetry @('sysmon:2') -Attempt {
  $f = Join-Path $script:A29Work 'stomped.txt'
  Set-Content -LiteralPath $f -Value $script:A29Marker
  $then = (Get-Date).AddDays(-730)
  $ok = $false
  try {
    [IO.File]::SetCreationTime($f, $then); [IO.File]::SetLastWriteTime($f, $then); [IO.File]::SetLastAccessTime($f, $then)
    $it = Get-Item -LiteralPath $f
    $ok = ([Math]::Abs(($it.CreationTime - $then).TotalSeconds) -lt 5 -and [Math]::Abs(($it.LastWriteTime - $then).TotalSeconds) -lt 5)
  } catch {}
  return @{ Ran = $ok; Note = "created_back_dated_days=730 read_back_matches=$ok"; NotApplicable = '' }
}
