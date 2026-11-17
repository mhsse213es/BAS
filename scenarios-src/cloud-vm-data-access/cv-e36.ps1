if (-not (Test-CvGate 'BAS_CONFIRM_CLOUD_EXFIL_SIM')) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'lab gate BAS_CONFIRM_CLOUD_EXFIL_SIM is not set to true; this step uploads a synthetic object to cloud storage and deletes it' } 'CV-E36' }
$payload = Join-Path $env:TEMP ($script:CvTag + '.txt')
('BAS SYNTHETIC DATA - NOT REAL. ' * 40) | Set-Content -LiteralPath $payload -Encoding ASCII
$acct = Get-CvEnv 'BAS_CLOUD_TEST_STORAGE_ACCOUNT'
$bucket = Get-CvEnv 'BAS_CLOUD_TEST_BUCKET'
$key = 'bas-synthetic/' + $script:CvTag + '.txt'
$outcome = $null
if ($acct -ne '' -and (Get-CvAzureInstance) -ne $null) {
  $t = Get-CvAzureToken 'https://storage.azure.com/'
  if ($t.Token -ne '') {
    $code = 0
    try {
      $h = @{ Authorization = ('Bearer ' + $t.Token); 'x-ms-version' = '2021-08-06'; 'x-ms-blob-type' = 'BlockBlob' }
      $null = Invoke-RestMethod -Method Put -Uri ('https://' + $acct + '.blob.core.windows.net/bas-synthetic/' + $script:CvTag + '.txt') -Headers $h -InFile $payload -ContentType 'text/plain' -TimeoutSec 30 -ErrorAction Stop
      $code = 201
    } catch { try { $code = [int]$_.Exception.Response.StatusCode } catch {} }
    if ($code -eq 201) {
      $h2 = @{ Authorization = ('Bearer ' + $t.Token); 'x-ms-version' = '2021-08-06' }
      try { Invoke-RestMethod -Method Delete -Uri ('https://' + $acct + '.blob.core.windows.net/bas-synthetic/' + $script:CvTag + '.txt') -Headers $h2 -TimeoutSec 30 -ErrorAction Stop | Out-Null; $cleaned = $true } catch { $cleaned = $false }
      $outcome = @{ Outcome = 'fail'; Reason = ('a synthetic object was uploaded to Azure Blob storage from this VM; egress to cloud storage is not restricted; cleanup ' + $(if ($cleaned) { 'verified' } else { 'NOT verified, delete bas-synthetic/' + $script:CvTag + '.txt manually' })) }
    } else {
      $outcome = (Resolve-CvHttp @{ Code = $code } 'upload of a synthetic object to Azure Blob storage' 'BAS_CLOUD_EXPECT_EXFIL_SIM')
    }
  }
}
if ($null -eq $outcome -and $bucket -ne '' -and (Test-CvAwsCli) -and (Get-CvAwsToken) -ne '') {
  Set-CvAwsRegion
  $up = Invoke-CvAws @('s3', 'cp', $payload, ('s3://' + $bucket + '/' + $key))
  if ($up.Code -eq 0) {
    $del = Invoke-CvAws @('s3api', 'delete-object', '--bucket', $bucket, '--key', $key)
    $cleaned = ($del.Code -eq 0)
    $outcome = @{ Outcome = 'fail'; Reason = ('a synthetic object was uploaded to S3 from this instance; egress to cloud storage is not restricted; cleanup ' + $(if ($cleaned) { 'verified' } else { 'NOT verified, delete ' + $key + ' manually' })) }
  } else { $outcome = Resolve-CvAws $up 'upload of a synthetic object to S3' 'BAS_CLOUD_EXPECT_EXFIL_SIM' }
}
Remove-Item -LiteralPath $payload -Force -ErrorAction SilentlyContinue
if ($null -eq $outcome) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no test storage target and identity path is configured on this host' } 'CV-E36' }
Complete-CvStep $outcome 'CV-E36'
