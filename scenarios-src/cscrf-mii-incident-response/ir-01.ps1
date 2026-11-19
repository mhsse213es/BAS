# CSCRF-IR-01: the EICAR test string is removed or quarantined by endpoint protection. Gated. Harmless standard test string.
# Endpoint protection can take 20 s or more to act after detection, so poll for up to 60 s before judging.
if (-not (Test-CgIrGate)) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_CONFIRM_IR_TEST not true; no test file written [CSCRF-IR-01]' } 'ir-01' }
$dir = Join-Path $env:TEMP ('bas-ir-' + $script:CgRun)
New-CgUndoRecord 'ir-01' @{ scenario = 'ir-01'; dir = $dir }
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$f = Join-Path $dir 'eicar-test.txt'
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -LiteralPath $f -Value $eicar -NoNewline -Encoding ASCII
$gone = $false
for ($i = 0; $i -lt 12 -and -not $gone; $i++) {
  Start-Sleep -Seconds 5
  if (-not (Test-Path -LiteralPath $f)) { $gone = $true }
}
$det = Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.Resources -match [regex]::Escape($f) } | Select-Object -First 1
if ($gone -and $det -and $det.ActionSuccess) { Complete-CgStep @{ Outcome = 'pass'; Reason = 'EICAR test file detected and removed by endpoint protection (quarantine action succeeded) [CSCRF-IR-01]' } 'ir-01' }
if ($gone) { Complete-CgStep @{ Outcome = 'pass'; Reason = 'EICAR test file removed within 60 s; the Defender detection record could not be matched to this path [CSCRF-IR-01]' } 'ir-01' }
$st = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($st -and -not $st.RealTimeProtectionEnabled) { Complete-CgStep @{ Outcome = 'fail'; Reason = 'EICAR test file was not removed in 60 s; real-time protection is off [CSCRF-IR-01]' } 'ir-01' }
Complete-CgStep @{ Outcome = 'fail'; Reason = 'EICAR test file was not removed in 60 s although real-time protection reports on [CSCRF-IR-01]' } 'ir-01'
