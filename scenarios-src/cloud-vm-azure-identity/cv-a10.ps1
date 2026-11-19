$inst = Get-CvAzureInstance
if ($null -eq $inst) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'Azure IMDS is unreachable from this host, so this is not an Azure VM' } 'CV-A10' }
$t = Get-CvAzureToken 'https://management.azure.com/'
if ($t.Token -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no managed-identity token for the Azure management plane (no identity attached to this VM)' } 'CV-A10' }
$uri = 'https://management.azure.com/subscriptions/' + [string]$inst.compute.subscriptionId + '/resourceGroups/' + [string]$inst.compute.resourceGroupName + '/providers/Microsoft.Compute/virtualMachines/' + [string]$inst.compute.name + '/extensions?api-version=2023-03-01'
$res = Invoke-CvHttp 'GET' $uri $t.Token
$n = 0; if ($res.Code -eq 200) { $n = @($res.Body.value).Count }
Write-Output ('EXEC T1526: VM extension inventory for this VM only; http=' + $res.Code + ' extensions=' + $n)
Complete-CvStep (Resolve-CvHttp $res 'VM extension inventory discovery') 'CV-A10'
