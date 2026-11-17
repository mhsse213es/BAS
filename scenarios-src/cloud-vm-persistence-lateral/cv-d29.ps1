if (-not (Test-CvGate 'BAS_CONFIRM_CLOUD_IAM_WRITE')) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'lab gate BAS_CONFIRM_CLOUD_IAM_WRITE is not set to true; this step adds and then removes a client secret on a test application' } 'CV-D29' }
$app = Get-CvEnv 'BAS_CLOUD_TEST_APP_OBJECT_ID'
if ($app -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no test application configured (BAS_CLOUD_TEST_APP_OBJECT_ID); use a dedicated test application' } 'CV-D29' }
$t = Get-CvAzureToken 'https://graph.microsoft.com/'
if ($t.Token -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no managed-identity token for Microsoft Graph (no identity attached to this VM)' } 'CV-D29' }
$end = (Get-Date).ToUniversalTime().AddHours(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
$body = '{"passwordCredential":{"displayName":"' + $script:CvTag + '","endDateTime":"' + $end + '"}}'
$res = Invoke-CvHttp 'POST' ('https://graph.microsoft.com/v1.0/applications/' + $app + '/addPassword') $t.Token $body
if ($res.Code -ne 200) { Complete-CvStep (Resolve-CvHttp $res 'service principal credential addition on the test application' 'BAS_CLOUD_EXPECT_KEY_CREATE') 'CV-D29' }
$keyId = [string]$res.Body.keyId
$res = $null
$rm = Invoke-CvHttp 'POST' ('https://graph.microsoft.com/v1.0/applications/' + $app + '/removePassword') $t.Token ('{"keyId":"' + $keyId + '"}')
Write-Output ('EXEC T1098.001: client secret added to the test application and removed; remove_http=' + $rm.Code + '. The secret text was never recorded.')
if ($rm.Code -ne 200) { Complete-CvStep @{ Outcome = 'fail'; Reason = ('a client secret was added to the test application and cleanup was NOT verified; remove key id ' + $keyId + ' manually') } 'CV-D29' }
Complete-CvStep @{ Outcome = 'fail'; Reason = 'the workload identity could add a client secret to a service principal; cleanup verified' } 'CV-D29'
