if ((Get-CvAwsToken) -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS IMDS is unreachable from this host, so this is not an EC2 instance' } 'CV-B20' }
if (-not (Test-CvAwsCli)) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS CLI is not installed on this host' } 'CV-B20' }
Set-CvAwsRegion
$r = Invoke-CvAws @('secretsmanager', 'list-secrets', '--max-results', '5')
Write-Output ('EXEC T1555: secret names listed (first page only; get-secret-value was never called); exit=' + $r.Code)
Complete-CvStep (Resolve-CvAws $r 'Secrets Manager access') 'CV-B20'
