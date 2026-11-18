# Cobalt Group BFSI - Security Software Discovery (eva-01)
$securityProcs = @('MsMpEng', 'MSASCui', 'SenseIR', 'SenseCncProxy', 'CSFalconService', 'CylanceSvc', 'SentinelAgent')
$found = @()
foreach ($name in $securityProcs) {
  if (Get-Process -Name $name -ErrorAction SilentlyContinue) { $found += $name }
}

if ($found.Count -gt 0) {
  $res = @{ Outcome = 'fail'; Reason = "Security software discovery enumerated $($found.Count) running security process(es): $($found -join ', ')" }
} else {
  $res = @{ Outcome = 'pass'; Reason = 'No known security-software processes were discovered on this host' }
}
Complete-CgStep $res 'EVA-01'
