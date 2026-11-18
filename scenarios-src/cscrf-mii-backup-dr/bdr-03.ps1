# CSCRF-BDR-03: a synthetic file restored from its backup copy matches the original hash. Gated. Temp files only.
if (-not (Test-CgBackupGate)) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_CONFIRM_BACKUP_TEST not true; no file written [CSCRF-BDR-03]' } 'bdr-03' }
$dir = Join-Path $env:TEMP ('bas-bdr-' + $script:CgRun)
New-CgUndoRecord 'bdr-03' @{ scenario = 'bdr-03'; dir = $dir }
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$orig = Join-Path $dir 'synthetic.bin'; $bak = Join-Path $dir 'backup.bin'
$bytes = New-Object byte[] 1048576; (New-Object System.Random).NextBytes($bytes)
[IO.File]::WriteAllBytes($orig, $bytes)
$h1 = (Get-FileHash -LiteralPath $orig -Algorithm SHA256).Hash
Copy-Item -LiteralPath $orig -Destination $bak
Remove-Item -LiteralPath $orig -Force
Copy-Item -LiteralPath $bak -Destination $orig
$h2 = (Get-FileHash -LiteralPath $orig -Algorithm SHA256).Hash
if ($h1 -eq $h2) { Complete-CgStep @{ Outcome = 'pass'; Reason = 'synthetic file restored from its copy with a matching SHA256 [CSCRF-BDR-03]' } 'bdr-03' }
Complete-CgStep @{ Outcome = 'fail'; Reason = 'restored file hash does not match the original [CSCRF-BDR-03]' } 'bdr-03'
