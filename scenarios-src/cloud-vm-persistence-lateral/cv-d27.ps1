if (-not (Test-CvGate 'BAS_CONFIRM_CLOUD_ROLE_ASSUME')) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'lab gate BAS_CONFIRM_CLOUD_ROLE_ASSUME is not set to true; this step asks the cloud to issue temporary credentials for a test role' } 'CV-D27' }
$arn = Get-CvEnv 'BAS_CLOUD_TEST_ROLE_ARN'
if ($arn -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no test role configured (BAS_CLOUD_TEST_ROLE_ARN)' } 'CV-D27' }
if (-not (Test-CvAwsCli)) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS CLI is not installed on this host' } 'CV-D27' }
Set-CvAwsRegion
$r = Invoke-CvAws @('sts', 'assume-role', '--role-arn', $arn, '--role-session-name', $script:CvTag, '--duration-seconds', '900')
$res = Resolve-CvAws $r 'role assumption of the test role' 'BAS_CLOUD_EXPECT_ROLE_ASSUME'
$r = $null
Write-Output 'EXEC T1098: assume-role attempted for the test role only. Any returned credentials were discarded unrecorded.'
Complete-CvStep $res 'CV-D27'
