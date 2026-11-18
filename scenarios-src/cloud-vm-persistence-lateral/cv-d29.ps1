if (-not (Test-CvGate 'BAS_CONFIRM_CLOUD_IAM_WRITE')) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'lab gate BAS_CONFIRM_CLOUD_IAM_WRITE is not set to true; this step adds and then removes a client secret on a test application' } 'CV-D29' }
$app = Get-CvEnv 'BAS_CLOUD_TEST_APP_OBJECT_ID'
if ($app -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no test application configured (BAS_CLOUD_TEST_APP_OBJECT_ID); use a dedicated test application' } 'CV-D29' }
$t = Get-CvAzureToken 'https://graph.microsoft.com/'
if ($t.Token -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no managed-identity token for Microsoft Graph (no identity attached to this VM)' } 'CV-D29' }
$appUri = 'https://graph.microsoft.com/v1.0/applications/' + $app
$cur = Invoke-CvHttp 'GET' ($appUri + '?$select=passwordCredentials') $t.Token
if ($cur.Code -ne 200 -or $null -eq $cur.Body -or -not ($cur.Body.PSObject.Properties.Name -contains 'passwordCredentials')) { Complete-CvStep @{ Outcome = 'error'; Reason = 'the test application credentials could not be read before creation, so no secret was added' } 'CV-D29' }
$baseIds = @($cur.Body.passwordCredentials | ForEach-Object { [string]$_.keyId })
$cur = $null
try { New-CvUndoRecord 'cv-d29' @{ app = $app; baseline = $baseIds } } catch { Complete-CvStep @{ Outcome = 'error'; Reason = 'the undo record could not be written (one from an earlier run may still be present), so no secret was added' } 'CV-D29' }
$end = (Get-Date).ToUniversalTime().AddHours(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
$body = '{"passwordCredential":{"displayName":"' + $script:CvTag + '","endDateTime":"' + $end + '"}}'
$res = Invoke-CvHttp 'POST' ($appUri + '/addPassword') $t.Token $body
if ($res.Code -ne 200) { Complete-CvStep (Resolve-CvHttp $res 'service principal credential addition on the test application' 'BAS_CLOUD_EXPECT_KEY_CREATE') 'CV-D29' }
$keyId = [string]$res.Body.keyId
$res = $null
$rm = Invoke-CvHttp 'POST' ($appUri + '/removePassword') $t.Token ('{"keyId":"' + $keyId + '"}')
$after = Invoke-CvHttp 'GET' ($appUri + '?$select=passwordCredentials') $t.Token
$verified = $false; $extra = -1
if ($after.Code -eq 200 -and $null -ne $after.Body -and ($after.Body.PSObject.Properties.Name -contains 'passwordCredentials')) {
  $extra = @($after.Body.passwordCredentials | ForEach-Object { [string]$_.keyId } | Where-Object { $baseIds -notcontains $_ }).Count
  $verified = ($rm.Code -eq 200 -and $extra -eq 0)
}
Write-Output ('EXEC T1098.001: client secret added to the test application and removed; remove_http=' + $rm.Code + ' secrets_outside_baseline=' + $extra + '. The secret text was never recorded.')
if (-not $verified) { Complete-CvStep @{ Outcome = 'fail'; Reason = 'a client secret was added to the test application and cleanup was NOT verified; the step cleanup removes every secret outside the pre-run baseline' } 'CV-D29' }
if (Test-CvGate 'BAS_CLOUD_EXPECT_KEY_CREATE') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'client secret addition succeeded and is documented as expected; cleanup verified' } 'CV-D29' }
Complete-CvStep @{ Outcome = 'fail'; Reason = 'the workload identity could add a client secret to a service principal; cleanup verified' } 'CV-D29'
