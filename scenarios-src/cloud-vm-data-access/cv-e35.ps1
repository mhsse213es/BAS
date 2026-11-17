if (-not (Test-CvGate 'BAS_CONFIRM_CLOUD_SECRET_READ')) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'lab gate BAS_CONFIRM_CLOUD_SECRET_READ is not set to true; this step requests a secret value, which only a deliberate test run may do' } 'CV-E35' }
$vault = Get-CvEnv 'BAS_CLOUD_TEST_KEYVAULT'
$secret = Get-CvEnv 'BAS_CLOUD_TEST_SECRET_NAME'
if ($secret -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no synthetic test secret configured (BAS_CLOUD_TEST_SECRET_NAME); use a test secret holding synthetic data only' } 'CV-E35' }
if ($vault -ne '' -and (Get-CvAzureInstance) -ne $null) {
  $t = Get-CvAzureToken 'https://vault.azure.net'
  if ($t.Token -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no managed-identity token for Key Vault (no identity attached to this VM)' } 'CV-E35' }
  $res = Invoke-CvHttp 'GET' ('https://' + $vault + '.vault.azure.net/secrets/' + $secret + '?api-version=7.4') $t.Token
  $len = 0; if ($res.Code -eq 200) { $len = ([string]$res.Body.value).Length }
  $res.Body = $null
  Write-Output ('EXEC T1555: Key Vault secret value requested for the synthetic test secret; http=' + $res.Code + '. Only the length (' + $len + ') was observed; the value was discarded.')
  Complete-CvStep (Resolve-CvHttp $res 'Key Vault secret retrieval') 'CV-E35'
}
if ((Get-CvAwsToken) -ne '' -and (Test-CvAwsCli)) {
  Set-CvAwsRegion
  $r = Invoke-CvAws @('secretsmanager', 'get-secret-value', '--secret-id', $secret)
  $len = 0; if ($r.Code -eq 0) { try { $len = ([string](($r.Text | ConvertFrom-Json).SecretString)).Length } catch {} }
  $res = Resolve-CvAws $r 'Secrets Manager secret retrieval'
  $r = $null
  Write-Output ('EXEC T1555: Secrets Manager value requested for the synthetic test secret; value_length=' + $len + '. The value was discarded.')
  Complete-CvStep $res 'CV-E35'
}
Complete-CvStep @{ Outcome = 'skip'; Reason = 'no cloud identity path is available to retrieve the synthetic test secret on this host' } 'CV-E35'
