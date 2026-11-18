if (-not (Test-CvGate 'BAS_CONFIRM_CLOUD_EXFIL_SIM')) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'lab gate BAS_CONFIRM_CLOUD_EXFIL_SIM is not set to true; this step uploads a synthetic object to cloud storage and deletes it' } 'CV-E36' }
$payload = Join-Path $env:TEMP ($script:CvTag + '.txt')
$acct = Get-CvEnv 'BAS_CLOUD_TEST_STORAGE_ACCOUNT'
$bucket = Get-CvEnv 'BAS_CLOUD_TEST_BUCKET'
$key = 'bas-synthetic/' + $script:CvTag + '.txt'
$outcome = $null
$undo = @{ azure_url = ''; s3_bucket = ''; s3_key = '' }
try { New-CvUndoRecord 'cv-e36' $undo } catch { Complete-CvStep @{ Outcome = 'error'; Reason = 'the undo record could not be written (one from an earlier run may still be present), so nothing was uploaded' } 'CV-E36' }
try {
  ('BAS SYNTHETIC DATA - NOT REAL. ' * 40) | Set-Content -LiteralPath $payload -Encoding ASCII
  if ($acct -ne '' -and (Get-CvAzureInstance) -ne $null) {
    $t = Get-CvAzureToken 'https://storage.azure.com/'
    if ($t.Token -ne '') {
      $code = 0
      try {
        $h = @{ Authorization = ('Bearer ' + $t.Token); 'x-ms-version' = '2021-08-06'; 'x-ms-blob-type' = 'BlockBlob' }
        $undo.azure_url = ('https://' + $acct + '.blob.core.windows.net/bas-synthetic/' + $script:CvTag + '.txt'); Set-CvUndoRecord 'cv-e36' $undo
        $null = Invoke-RestMethod -Method Put -Uri ('https://' + $acct + '.blob.core.windows.net/bas-synthetic/' + $script:CvTag + '.txt') -Headers $h -InFile $payload -ContentType 'text/plain' -TimeoutSec 30 -ErrorAction Stop
        $code = 201
      } catch { try { $code = [int]$_.Exception.Response.StatusCode } catch {} }
      if ($code -eq 201) {
        $h2 = @{ Authorization = ('Bearer ' + $t.Token); 'x-ms-version' = '2021-08-06' }
        try { Invoke-RestMethod -Method Delete -Uri ('https://' + $acct + '.blob.core.windows.net/bas-synthetic/' + $script:CvTag + '.txt') -Headers $h2 -TimeoutSec 30 -ErrorAction Stop | Out-Null; $cleaned = $true } catch { $cleaned = $false }
        $cl = 'NOT verified, delete bas-synthetic/' + $script:CvTag + '.txt manually'
        if ($cleaned) { $cl = 'verified' }
        if (Test-CvGate 'BAS_CLOUD_EXPECT_EXFIL_SIM') { $outcome = @{ Outcome = 'skip'; Reason = ('a synthetic upload to Azure Blob storage succeeded and is documented as expected; cleanup ' + $cl) } }
        else { $outcome = @{ Outcome = 'fail'; Reason = ('a synthetic object was uploaded to Azure Blob storage from this VM; egress to cloud storage is not restricted; cleanup ' + $cl) } }
      } else {
        $outcome = (Resolve-CvHttp @{ Code = $code } 'upload of a synthetic object to Azure Blob storage' 'BAS_CLOUD_EXPECT_EXFIL_SIM')
      }
    }
  }
  if ($null -eq $outcome -and $bucket -ne '' -and (Test-CvAwsCli) -and (Get-CvAwsToken) -ne '') {
    Set-CvAwsRegion
    $undo.s3_bucket = $bucket; $undo.s3_key = $key; Set-CvUndoRecord 'cv-e36' $undo
    $up = Invoke-CvAws @('s3', 'cp', $payload, ('s3://' + $bucket + '/' + $key))
    if ($up.Code -eq 0) {
      $del = Invoke-CvAws @('s3api', 'delete-object', '--bucket', $bucket, '--key', $key)
      $cl = 'NOT verified, delete ' + $key + ' manually'
      if ($del.Code -eq 0) { $cl = 'verified' }
      if (Test-CvGate 'BAS_CLOUD_EXPECT_EXFIL_SIM') { $outcome = @{ Outcome = 'skip'; Reason = ('a synthetic upload to S3 succeeded and is documented as expected; cleanup ' + $cl) } }
      else { $outcome = @{ Outcome = 'fail'; Reason = ('a synthetic object was uploaded to S3 from this instance; egress to cloud storage is not restricted; cleanup ' + $cl) } }
    } else { $outcome = Resolve-CvAws $up 'upload of a synthetic object to S3' 'BAS_CLOUD_EXPECT_EXFIL_SIM' }
  }
} finally {
  Remove-Item -LiteralPath $payload -Force -ErrorAction SilentlyContinue
}
if ($null -eq $outcome) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no test storage target and identity path is configured on this host' } 'CV-E36' }
Complete-CvStep $outcome 'CV-E36'
