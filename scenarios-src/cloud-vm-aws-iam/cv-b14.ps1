if ((Get-CvAwsToken) -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS IMDS is unreachable from this host, so this is not an EC2 instance' } 'CV-B14' }
$prof = $null; $code = 0
try { $prof = [string](Invoke-RestMethod -Headers @{ 'X-aws-ec2-metadata-token' = (Get-CvAwsToken) } -Uri 'http://169.254.169.254/latest/meta-data/iam/info' -TimeoutSec 3 -ErrorAction Stop) } catch { try { $code = [int]$_.Exception.Response.StatusCode } catch {} }
if ($code -eq 404) { Complete-CvStep @{ Outcome = 'pass'; Reason = 'no instance profile is attached to this EC2 instance (least-privilege posture)' } 'CV-B14' }
if ($null -eq $prof) { Complete-CvStep @{ Outcome = 'error'; Reason = ('the instance profile could not be read (HTTP ' + $code + ')') } 'CV-B14' }
Write-Output 'EXEC T1552.005: an instance profile is attached. The ARN and credentials were not retrieved or recorded.'
if (Test-CvGate 'BAS_CLOUD_EXPECT_INSTANCE_ROLE') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'an instance role is attached and the operator documents it as expected, so no control verdict is scored' } 'CV-B14' }
Complete-CvStep @{ Outcome = 'fail'; Reason = 'an instance role is attached and its profile is readable from local IMDS by any local process' } 'CV-B14'
