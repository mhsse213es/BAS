$inst = Get-CvAzureInstance
if ($null -eq $inst) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'Azure IMDS is unreachable from this host, so this is not an Azure VM' } 'CV-A9' }
$t = Get-CvAzureToken 'https://management.azure.com/'
if ($t.Token -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no managed-identity token for the Azure management plane (no identity attached to this VM)' } 'CV-A9' }
$sub = [string]$inst.compute.subscriptionId
$uri = 'https://management.azure.com/subscriptions/' + $sub + '/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()'
$res = Invoke-CvHttp 'GET' $uri $t.Token
$n = 0; if ($res.Code -eq 200) { $n = @($res.Body.value).Count }
Write-Output ('EXEC T1069.003: role assignments visible at subscription scope; http=' + $res.Code + ' count=' + $n)
Complete-CvStep (Resolve-CvHttp $res 'role assignment discovery') 'CV-A9'
