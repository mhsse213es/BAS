$inst = Get-CvAzureInstance
if ($null -eq $inst) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'Azure IMDS is unreachable from this host, so this is not an Azure VM' } 'CV-A12' }
$vault = Get-CvEnv 'BAS_CLOUD_TEST_KEYVAULT'
if ($vault -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no test Key Vault configured (BAS_CLOUD_TEST_KEYVAULT); use a dedicated test vault with synthetic secrets only' } 'CV-A12' }
$t = Get-CvAzureToken 'https://vault.azure.net'
if ($t.Token -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no managed-identity token for Key Vault (no identity attached to this VM)' } 'CV-A12' }
$res = Invoke-CvHttp 'GET' ('https://' + $vault + '.vault.azure.net/secrets?api-version=7.4') $t.Token
$n = 0; if ($res.Code -eq 200) { $n = @($res.Body.value).Count }
Write-Output ('EXEC T1555: Key Vault secret names listed with the managed identity; http=' + $res.Code + ' names=' + $n + '. Secret values were never requested.')
Complete-CvStep (Resolve-CvHttp $res 'Key Vault access with the managed identity') 'CV-A12'
