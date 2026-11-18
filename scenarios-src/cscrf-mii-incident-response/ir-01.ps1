# CSCRF-IR-01: the EICAR test string is removed or flagged by endpoint protection. Gated. Harmless standard test string.
if (-not (Test-CgIrGate)) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_CONFIRM_IR_TEST not true; no test file written [CSCRF-IR-01]' } 'ir-01' }
$dir = Join-Path $env:TEMP ('bas-ir-' + $script:CgRun)
New-CgUndoRecord 'ir-01' @{ scenario = 'ir-01'; dir = $dir }
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$f = Join-Path $dir 'eicar-test.txt'
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -LiteralPath $f -Value $eicar -NoNewline -Encoding ASCII
Start-Sleep -Seconds 10
if (-not (Test-Path -LiteralPath $f)) { Complete-CgStep @{ Outcome = 'pass'; Reason = 'EICAR test file was removed by endpoint protection [CSCRF-IR-01]' } 'ir-01' }
$st = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($st -and -not $st.RealTimeProtectionEnabled) { Complete-CgStep @{ Outcome = 'fail'; Reason = 'EICAR test file was not removed; real-time protection is off [CSCRF-IR-01]' } 'ir-01' }
Complete-CgStep @{ Outcome = 'fail'; Reason = 'EICAR test file was not removed although real-time protection reports on [CSCRF-IR-01]' } 'ir-01'
