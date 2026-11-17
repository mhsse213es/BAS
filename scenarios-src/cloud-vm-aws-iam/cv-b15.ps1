if ((Get-CvAwsToken) -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS IMDS is unreachable from this host, so this is not an EC2 instance' } 'CV-B15' }
if (-not (Test-CvAwsCli)) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS CLI is not installed on this host' } 'CV-B15' }
Set-CvAwsRegion
$r = Invoke-CvAws @('sts', 'get-caller-identity')
if ($r.Code -ne 0) { Complete-CvStep (Resolve-CvAws $r 'caller identity discovery') 'CV-B15' }
$acct = ''; try { $acct = [string](($r.Text | ConvertFrom-Json).Account) } catch {}
Write-Output ('EXEC T1087.004: caller identity resolved for account ' + $acct + '. The ARN was not recorded.')
Complete-CvStep @{ Outcome = 'skip'; Reason = 'GetCallerIdentity is permitted to every principal, so it documents identity for the report but scores no control' } 'CV-B15'
