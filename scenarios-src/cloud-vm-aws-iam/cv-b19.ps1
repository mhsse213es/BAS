if ((Get-CvAwsToken) -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS IMDS is unreachable from this host, so this is not an EC2 instance' } 'CV-B19' }
if (-not (Test-CvAwsCli)) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS CLI is not installed on this host' } 'CV-B19' }
Set-CvAwsRegion
$r = Invoke-CvAws @('kms', 'list-keys', '--limit', '5')
Write-Output ('EXEC T1580: KMS key identifiers listed (first page); exit=' + $r.Code)
Complete-CvStep (Resolve-CvAws $r 'KMS key inventory discovery') 'CV-B19'
