# Cobalt Group BFSI - Email Collection Simulation (coll-03)
$outlookProcess = Get-Process -Name 'OUTLOOK' -ErrorAction SilentlyContinue
$profileKey = Test-Path 'HKCU:\Software\Microsoft\Office\Outlook' -ErrorAction SilentlyContinue

if ($outlookProcess -or $profileKey) {
  $res = @{ Outcome = 'fail'; Reason = 'Mail-client presence detected (process or profile key); email collection target exists' }
} else {
  $res = @{ Outcome = 'pass'; Reason = 'No local mail-client presence detected' }
}
Complete-CgStep $res 'COLL-03'
