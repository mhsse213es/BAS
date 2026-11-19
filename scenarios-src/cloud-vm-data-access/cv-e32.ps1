$acct = Get-CvEnv 'BAS_CLOUD_TEST_STORAGE_ACCOUNT'
if ((Get-CvAzureInstance) -eq $null) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'Azure IMDS is unreachable from this host, so this is not an Azure VM' } 'CV-E32' }
if ($acct -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no test storage account configured (BAS_CLOUD_TEST_STORAGE_ACCOUNT); use a synthetic-data account only' } 'CV-E32' }
$t = Get-CvAzureToken 'https://storage.azure.com/'
if ($t.Token -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no managed-identity token for Azure Storage (no identity attached to this VM)' } 'CV-E32' }
$res = Invoke-CvHttp 'GET' ('https://' + $acct + '.blob.core.windows.net/?comp=list') $t.Token '' '2021-08-06'
$n = 0; if ($res.Code -eq 200) { $n = @($res.Body.EnumerationResults.Containers.Container).Count }
Write-Output ('EXEC T1530: blob container names listed on the test account only; http=' + $res.Code + ' containers=' + $n + '. No blob was read.')
Complete-CvStep (Resolve-CvHttp $res 'Azure Blob container access') 'CV-E32'
