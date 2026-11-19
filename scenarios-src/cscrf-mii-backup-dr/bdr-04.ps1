# CSCRF-BDR-04: a timed restore of a synthetic file completes within 900 s (15 min). Gated. Temp files only. Measures the file-level path only.
if (-not (Test-CgBackupGate)) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_CONFIRM_BACKUP_TEST not true; nothing restored [CSCRF-BDR-04]' } 'bdr-04' }
$dir = Join-Path $env:TEMP ('bas-bdr-rto-' + $script:CgRun)
New-CgUndoRecord 'bdr-04' @{ scenario = 'bdr-04'; dir = $dir }
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$orig = Join-Path $dir 'synthetic.bin'; $bak = Join-Path $dir 'backup.bin'
$bytes = New-Object byte[] 1048576; (New-Object System.Random).NextBytes($bytes)
[IO.File]::WriteAllBytes($orig, $bytes); Copy-Item -LiteralPath $orig -Destination $bak; Remove-Item -LiteralPath $orig -Force
$sw = [Diagnostics.Stopwatch]::StartNew()
Copy-Item -LiteralPath $bak -Destination $orig
$sw.Stop()
$secs = [math]::Round($sw.Elapsed.TotalSeconds, 2)
if ($sw.Elapsed.TotalSeconds -le 900) { Complete-CgStep @{ Outcome = 'pass'; Reason = "file-level restore took $secs s (budget 900 s) [CSCRF-BDR-04]" } 'bdr-04' }
Complete-CgStep @{ Outcome = 'fail'; Reason = "file-level restore took $secs s, over the 900 s budget [CSCRF-BDR-04]" } 'bdr-04'
