$inst = Get-CvAzureInstance
if ($null -eq $inst) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'Azure IMDS is unreachable from this host, so this is not an Azure VM' } 'CV-A11' }
$t = Get-CvAzureToken 'https://management.azure.com/'
if ($t.Token -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no managed-identity token for the Azure management plane (no identity attached to this VM)' } 'CV-A11' }
$uri = 'https://management.azure.com/subscriptions/' + [string]$inst.compute.subscriptionId + '/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01'
$res = Invoke-CvHttp 'GET' $uri $t.Token
$n = 0; if ($res.Code -eq 200) { $n = @($res.Body.value).Count }
Write-Output ('EXEC T1580: storage account inventory at subscription scope; http=' + $res.Code + ' accounts=' + $n)
Complete-CvStep (Resolve-CvHttp $res 'storage account discovery') 'CV-A11'
