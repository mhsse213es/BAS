$inst = Get-CvAzureInstance
if ($null -eq $inst) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'Azure IMDS is unreachable from this host, so this is not an Azure VM' } 'CV-A13' }
$other = Get-CvEnv 'BAS_CLOUD_TEST_RG'
if ($other -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no test resource group configured (BAS_CLOUD_TEST_RG); the token-use check needs a resource group other than this VM''s own' } 'CV-A13' }
if ($other -ieq [string]$inst.compute.resourceGroupName) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'BAS_CLOUD_TEST_RG is this VM''s own resource group, so the check would not cross a boundary' } 'CV-A13' }
$t = Get-CvAzureToken 'https://management.azure.com/'
if ($t.Token -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no managed-identity token for the Azure management plane (no identity attached to this VM)' } 'CV-A13' }
$uri = 'https://management.azure.com/subscriptions/' + [string]$inst.compute.subscriptionId + '/resourceGroups/' + $other + '/resources?api-version=2021-04-01'
$res = Invoke-CvHttp 'GET' $uri $t.Token
Write-Output ('EXEC T1528: a token acquired in this step was used once for a read of a resource group outside this VM''s own scope; http=' + $res.Code + '. Read-only; the token was not stored.')
Complete-CvStep (Resolve-CvHttp $res 'token use outside the VM resource group') 'CV-A13'
