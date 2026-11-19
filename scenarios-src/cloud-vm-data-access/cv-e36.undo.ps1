$rec = Read-CvUndoRecord 'cv-e36'
if ($null -eq $rec) { Write-Output 'UNDO CV-E36: no undo record, nothing to remove' }
elseif ($rec -eq 'unreadable') { Write-Output 'UNDO CV-E36: undo record is unreadable; left in place for manual review' }
else {
  $ok = $true; $notes = @()
  if ([string]$rec.azure_url -ne '') {
    $t = Get-CvAzureToken 'https://storage.azure.com/'
    if ($t.Token -eq '') { $ok = $false; $notes += 'no storage token for the Azure object' }
    else {
      $code = 0
      try { Invoke-RestMethod -Method Delete -Uri ([string]$rec.azure_url) -Headers @{ Authorization = ('Bearer ' + $t.Token); 'x-ms-version' = '2021-08-06' } -TimeoutSec 30 -ErrorAction Stop | Out-Null; $code = 200 } catch { try { $code = [int]$_.Exception.Response.StatusCode } catch {} }
      if (-not (($code -ge 200 -and $code -lt 300) -or $code -eq 404)) { $ok = $false; $notes += ('Azure delete returned ' + $code) }
    }
  }
  if ([string]$rec.s3_bucket -ne '') {
    if (-not (Test-CvAwsCli)) { $ok = $false; $notes += 'AWS CLI missing for the S3 object' }
    else {
      Set-CvAwsRegion
      $d = Invoke-CvAws @('s3api', 'delete-object', '--bucket', [string]$rec.s3_bucket, '--key', [string]$rec.s3_key)
      if ($d.Code -ne 0) { $ok = $false; $notes += 'S3 delete failed' }
    }
  }
  if ($ok) { Remove-CvUndoRecord 'cv-e36'; Write-Output 'UNDO CV-E36: every synthetic object in the record is gone; undo record removed' }
  else { Write-Output ('UNDO CV-E36: not verified (' + ($notes -join '; ') + '); undo record kept') }
}
