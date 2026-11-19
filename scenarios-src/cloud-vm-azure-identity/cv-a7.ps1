$inst = Get-CvAzureInstance
if ($null -eq $inst) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'Azure IMDS is unreachable from this host, so this is not an Azure VM' } 'CV-A7' }
$resources = @('https://management.azure.com/', 'https://vault.azure.net', 'https://storage.azure.com/', 'https://graph.microsoft.com/')
$expected = @((Get-CvEnv 'BAS_CLOUD_EXPECTED_RESOURCES') -split ',' | ForEach-Object { $_.Trim().TrimEnd('/') } | Where-Object { $_ -ne '' })
$issued = @(); $unexpected = @(); $refused = 0
foreach ($res in $resources) {
  $t = Get-CvAzureToken $res
  if ($t.Token -ne '') { $issued += $res.TrimEnd('/'); if ($expected -notcontains $res.TrimEnd('/')) { $unexpected += $res.TrimEnd('/') } }
  elseif ($t.Code -eq 400 -or $t.Code -eq 401 -or $t.Code -eq 403 -or $t.Code -eq 404) { $refused++ }
}
Write-Output ('EXEC T1552.005: managed-identity tokens requested for ' + $resources.Count + ' resources; issued=' + $issued.Count + ', refused=' + $refused + '. Token values were not recorded.')
if ($unexpected.Count -gt 0) { Complete-CvStep @{ Outcome = 'fail'; Reason = ('identity tokens were issued for resources outside the operator-expected list: ' + ($unexpected -join ', ')) } 'CV-A7' }
if ($issued.Count -gt 0) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'tokens were issued only for resources the operator documents as expected, so no control verdict is scored' } 'CV-A7' }
if ($refused -gt 0) { Complete-CvStep @{ Outcome = 'pass'; Reason = 'no managed-identity token was issued for any tested resource; the token endpoint refused the request (no identity attached, or issuance refused)' } 'CV-A7' }
Complete-CvStep @{ Outcome = 'error'; Reason = 'no token request returned a classifiable answer' } 'CV-A7'
