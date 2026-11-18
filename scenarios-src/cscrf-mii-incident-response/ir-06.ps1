# CSCRF-IR-06: the Security log can be exported as evidence (read only against the log). The export file is removed in undo.
$dir = Join-Path $env:TEMP ('bas-ir-ev-' + $script:CgRun)
New-CgUndoRecord 'ir-06' @{ scenario = 'ir-06'; dir = $dir }
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$out = Join-Path $dir 'security-export.evtx'
& wevtutil.exe epl Security $out /ow:true 2>&1 | Out-Null
$code = $LASTEXITCODE
if ($code -eq 0 -and (Test-Path -LiteralPath $out) -and ((Get-Item -LiteralPath $out).Length -gt 0)) {
  Complete-CgStep @{ Outcome = 'pass'; Reason = "Security log exported to evidence file ($([math]::Round((Get-Item -LiteralPath $out).Length / 1MB, 1)) MB) [CSCRF-IR-06]" } 'ir-06'
}
Complete-CgStep @{ Outcome = 'fail'; Reason = "Security log could not be exported as evidence (wevtutil exit $code) [CSCRF-IR-06]" } 'ir-06'
