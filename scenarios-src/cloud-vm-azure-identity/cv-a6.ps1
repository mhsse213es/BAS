$inst = Get-CvAzureInstance
if ($null -eq $inst) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'Azure IMDS is unreachable from this host, so this is not an Azure VM or IMDS is blocked on the host' } 'CV-A6' }
$child = 'try { $null = Invoke-RestMethod -Headers @{ Metadata = "true" } -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01" -UserAgent "bas-cv-a6" -TimeoutSec 3 -ErrorAction Stop; Write-Output CV_REACHED } catch { Write-Output CV_BLOCKED }'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
$childOut = (& powershell.exe -NoProfile -NonInteractive -EncodedCommand $enc 2>&1 | Out-String)
Write-Output ('EXEC T1552.005: a child powershell.exe process requested IMDS with a non-default user agent; result=' + $childOut.Trim())
if ($childOut -match 'CV_REACHED') {
  if (Test-CvGate 'BAS_CLOUD_EXPECT_IMDS_ACCESS') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'IMDS is reachable from a child process, which the operator documents as expected, so no control verdict is scored' } 'CV-A6' }
  Complete-CvStep @{ Outcome = 'fail'; Reason = 'IMDS answered a child process with an unrelated user agent, so metadata is reachable by any local process (no host-level restriction)' } 'CV-A6'
}
if ($childOut -match 'CV_BLOCKED') { Complete-CvStep @{ Outcome = 'pass'; Reason = 'IMDS access from a child process was blocked on the host' } 'CV-A6' }
Complete-CvStep @{ Outcome = 'error'; Reason = 'the child process produced no classifiable result' } 'CV-A6'
