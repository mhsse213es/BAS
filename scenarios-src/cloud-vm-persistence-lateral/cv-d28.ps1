if (-not (Test-CvGate 'BAS_CONFIRM_CLOUD_IAM_WRITE')) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'lab gate BAS_CONFIRM_CLOUD_IAM_WRITE is not set to true; this step creates and then deletes an access key on a test user' } 'CV-D28' }
$user = Get-CvEnv 'BAS_CLOUD_TEST_USER'
if ($user -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'no test IAM user configured (BAS_CLOUD_TEST_USER)' } 'CV-D28' }
if (-not (Test-CvAwsCli)) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS CLI is not installed on this host' } 'CV-D28' }
Set-CvAwsRegion
$r = Invoke-CvAws @('iam', 'create-access-key', '--user-name', $user)
if ($r.Code -ne 0) { Complete-CvStep (Resolve-CvAws $r 'access key creation for the test user' 'BAS_CLOUD_EXPECT_KEY_CREATE') 'CV-D28' }
$parsed = Get-CvJson $r.Text
$keyId = ''; if ($parsed) { $keyId = [string]$parsed.AccessKey.AccessKeyId }
$r = $null
if ($keyId -eq '') { Complete-CvStep @{ Outcome = 'fail'; Reason = 'an access key was created for the test user but its id could not be parsed, so cleanup was NOT attempted; list and delete the test user keys manually' } 'CV-D28' }
$del = Invoke-CvAws @('iam', 'delete-access-key', '--user-name', $user, '--access-key-id', $keyId)
$listed = Invoke-CvAws @('iam', 'list-access-keys', '--user-name', $user)
$listOk = ($listed.Code -eq 0)
$still = ($keyId -ne '' -and $listed.Text -match [regex]::Escape($keyId))
Write-Output ('EXEC T1098.001: access key created for the test user and deleted; delete_exit=' + $del.Code + ' still_listed=' + $still + '. The secret was never recorded.')
if ($del.Code -ne 0 -or -not $listOk -or $still) { Complete-CvStep @{ Outcome = 'fail'; Reason = ('an access key was created for the test user, and cleanup was NOT verified; delete the key with id ' + $keyId + ' manually') } 'CV-D28' }
if (Test-CvGate 'BAS_CLOUD_EXPECT_KEY_CREATE') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'access key creation succeeded and is documented as expected; cleanup verified' } 'CV-D28' }
Complete-CvStep @{ Outcome = 'fail'; Reason = 'the workload identity could create an access key for the test user; cleanup verified' } 'CV-D28'
