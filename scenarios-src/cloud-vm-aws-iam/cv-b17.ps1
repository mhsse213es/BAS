if ((Get-CvAwsToken) -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS IMDS is unreachable from this host, so this is not an EC2 instance' } 'CV-B17' }
if (-not (Test-CvAwsCli)) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS CLI is not installed on this host' } 'CV-B17' }
Set-CvAwsRegion
$r = Invoke-CvAws @('s3api', 'list-buckets')
Write-Output ('EXEC T1619: bucket names listed (names only); exit=' + $r.Code)
Complete-CvStep (Resolve-CvAws $r 'S3 bucket discovery') 'CV-B17'
