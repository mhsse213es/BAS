# Cobalt Group BFSI - Process Injection Detection Readiness Check (eva-07)
# This step performs no injection technique. It spawns one benign, short-lived process tagged with
# a recognizable marker and checks whether any EDR/security process is present to observe it.
$marker = 'bas-sim-injection-readiness-' + $script:CgRun
$proc = $null
try {
  $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile', '-Command', ("Start-Sleep -Milliseconds 500 # $marker") -PassThru -WindowStyle Hidden -ErrorAction Stop
  $proc.WaitForExit(5000) | Out-Null
} catch {}

$edrProcs = @('MsMpEng', 'SenseIR', 'CSFalconService', 'CylanceSvc', 'SentinelAgent')
$edrPresent = $false
foreach ($name in $edrProcs) { if (Get-Process -Name $name -ErrorAction SilentlyContinue) { $edrPresent = $true } }

if ($proc -and $edrPresent) {
  $res = @{ Outcome = 'pass'; Reason = 'A marked benign process was spawned and EDR/security tooling is present to observe process-creation telemetry' }
} elseif ($proc) {
  $res = @{ Outcome = 'fail'; Reason = 'A marked benign process was spawned but no EDR/security tooling was detected to observe it' }
} else {
  $res = @{ Outcome = 'error'; Reason = 'Could not spawn the marked benign test process' }
}
Complete-CgStep $res 'EVA-07'
