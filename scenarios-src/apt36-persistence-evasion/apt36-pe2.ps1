Invoke-A36Test -Id 'pe2' -Technique 'T1547.001' -Telemetry @('sysmon:11') -Summary 'a script is dropped in the user Startup folder then removed without logging on (T1547.001)' -Attempt {
  $dir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'
  if (-not (Test-Path -LiteralPath $dir)) { return @{ Ran = $false; Note = 'startup_folder_missing'; NotApplicable = 'the per-user Startup folder does not exist on this host' } }
  $f = Join-Path $dir ($script:A36Tag + '.cmd')
  $wrote = $false
  try { Set-Content -LiteralPath $f -Value ('@echo off' + [Environment]::NewLine + 'rem ' + $script:A36Marker + ' benign persistence test, echoes only') -Encoding ASCII -ErrorAction Stop; $wrote = (Test-Path -LiteralPath $f) } catch {}
  Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
  $gone = -not (Test-Path -LiteralPath $f)
  return @{ Ran = $wrote; Note = "startup_item_written=$wrote startup_item_removed=$gone executed_at_logon=false"; CleanupOk = $gone; NotApplicable = '' }
}
