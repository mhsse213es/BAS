if ((Get-CvAzureInstance) -ne $null) {
  $t = Get-CvAzureToken 'https://management.azure.com/'
  if ($t.Token -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no managed-identity token for the Azure management plane (no identity attached to this VM)' } 'CV-E34' }
  $inst = Get-CvAzureInstance
  $res = Invoke-CvHttp 'GET' ('https://management.azure.com/subscriptions/' + [string]$inst.compute.subscriptionId + '/providers/Microsoft.Sql/servers?api-version=2021-11-01') $t.Token
  $n = 0; if ($res.Code -eq 200) { $n = @($res.Body.value).Count }
  Write-Output ('EXEC T1526: database server inventory (Azure SQL); http=' + $res.Code + ' servers=' + $n)
  Complete-CvStep (Resolve-CvHttp $res 'cloud database discovery') 'CV-E34'
}
if ((Get-CvAwsToken) -ne '' -and (Test-CvAwsCli)) {
  Set-CvAwsRegion
  $r = Invoke-CvAws @('rds', 'describe-db-instances', '--max-items', '5')
  Write-Output ('EXEC T1526: database instance inventory (first page, RDS); exit=' + $r.Code)
  Complete-CvStep (Resolve-CvAws $r 'cloud database discovery') 'CV-E34'
}
Complete-CvStep @{ Outcome = 'skip'; Reason = 'neither Azure IMDS nor the AWS instance metadata service with a CLI is available on this host' } 'CV-E34'
