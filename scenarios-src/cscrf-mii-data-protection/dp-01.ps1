# CSCRF-DP-01: the system volume is BitLocker-protected (read only). Requires an elevated session; ERROR if the query fails.
$v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
if (-not $v) { Complete-CgStep @{ Outcome = 'error'; Reason = 'BitLocker status could not be read (feature missing or not elevated) [CSCRF-DP-01]' } 'dp-01' }
if ($v.ProtectionStatus -eq 'On' -and $v.VolumeStatus -eq 'FullyEncrypted') { Complete-CgStep @{ Outcome = 'pass'; Reason = "system volume $($env:SystemDrive) is BitLocker protected and fully encrypted [CSCRF-DP-01]" } 'dp-01' }
Complete-CgStep @{ Outcome = 'fail'; Reason = "system volume $($env:SystemDrive) not protected (protection $($v.ProtectionStatus), volume $($v.VolumeStatus)) [CSCRF-DP-01]" } 'dp-01'
