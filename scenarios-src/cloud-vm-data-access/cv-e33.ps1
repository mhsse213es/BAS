$bucket = Get-CvEnv 'BAS_CLOUD_TEST_BUCKET'
$key = Get-CvEnv 'BAS_CLOUD_TEST_OBJECT_KEY'
if ($bucket -eq '' -or $key -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no test bucket or synthetic object key configured (BAS_CLOUD_TEST_BUCKET, BAS_CLOUD_TEST_OBJECT_KEY)' } 'CV-E33' }
if ((Get-CvAwsToken) -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS IMDS is unreachable from this host, so this is not an EC2 instance' } 'CV-E33' }
if (-not (Test-CvAwsCli)) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS CLI is not installed on this host' } 'CV-E33' }
Set-CvAwsRegion
$r = Invoke-CvAws @('s3api', 'head-object', '--bucket', $bucket, '--key', $key)
Write-Output ('EXEC T1530: metadata-only head-object on the synthetic test object; exit=' + $r.Code + '. The object body was never requested.')
Complete-CvStep (Resolve-CvAws $r 'S3 object access') 'CV-E33'
