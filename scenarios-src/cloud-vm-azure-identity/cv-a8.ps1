$inst = Get-CvAzureInstance
if ($null -eq $inst) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'Azure IMDS is unreachable from this host, so this is not an Azure VM' } 'CV-A8' }
$t = Get-CvAzureToken 'https://management.azure.com/'
if ($t.Token -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no managed-identity token for the Azure management plane (no identity attached to this VM)' } 'CV-A8' }
$res = Invoke-CvHttp 'GET' 'https://management.azure.com/subscriptions?api-version=2020-01-01' $t.Token
$n = 0; if ($res.Code -eq 200) { $n = @($res.Body.value).Count }
Write-Output ('EXEC T1580: subscription enumeration via the management plane; http=' + $res.Code + ' visible_subscriptions=' + $n)
Complete-CvStep (Resolve-CvHttp $res 'subscription and resource enumeration') 'CV-A8'
