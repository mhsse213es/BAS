if ((Get-CvAwsToken) -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS IMDS is unreachable from this host, so this is not an EC2 instance' } 'CV-B18' }
if (-not (Test-CvAwsCli)) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS CLI is not installed on this host' } 'CV-B18' }
Set-CvAwsRegion
$r = Invoke-CvAws @('ec2', 'describe-security-groups', '--max-items', '5')
Write-Output ('EXEC T1580: security group inventory (first page); exit=' + $r.Code)
Complete-CvStep (Resolve-CvAws $r 'security group and network inventory discovery') 'CV-B18'
