if ((Get-CvAwsToken) -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS IMDS is unreachable from this host, so this is not an EC2 instance' } 'CV-B21' }
if (-not (Test-CvAwsCli)) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS CLI is not installed on this host' } 'CV-B21' }
Set-CvAwsRegion
$role = Get-CvAwsRoleName
if ($role -eq '') { Complete-CvStep @{ Outcome = 'pass'; Reason = 'no instance role is attached, so there is no escalation path from this instance identity' } 'CV-B21' }
$g = Invoke-CvAws @('iam', 'get-role', '--role-name', $role)
if ($g.Code -ne 0) { Complete-CvStep (Resolve-CvAws $g 'reading the instance role') 'CV-B21' }
$arn = ''; try { $arn = [string](($g.Text | ConvertFrom-Json).Role.Arn) } catch {}
$sim = Invoke-CvAws @('iam', 'simulate-principal-policy', '--policy-source-arn', $arn, '--action-names', 'iam:AttachRolePolicy', 'iam:PutRolePolicy', 'iam:CreatePolicyVersion', 'iam:CreateAccessKey', 'iam:PassRole', '--resource-arns', '*')
if ($sim.Code -ne 0) { Complete-CvStep @{ Outcome = 'error'; Reason = 'the policy simulation was refused or failed, so escalation exposure is not measured' } 'CV-B21' }
$parsed = Get-CvJson $sim.Text
if ($null -eq $parsed -or $null -eq $parsed.EvaluationResults) { Complete-CvStep @{ Outcome = 'error'; Reason = 'the policy simulation output could not be parsed, so escalation exposure is not measured' } 'CV-B21' }
$allowed = @($parsed.EvaluationResults | Where-Object { $_.EvalDecision -eq 'allowed' } | ForEach-Object { $_.EvalActionName })
Write-Output ('EXEC T1098: IAM policy simulation only, no change made. Actions reported allowed: ' + $allowed.Count)
if ($allowed.Count -gt 0) { Complete-CvStep @{ Outcome = 'fail'; Reason = ('the instance role policy simulation allows privilege-escalation actions (' + ($allowed -join ', ') + '); no change was made') } 'CV-B21' }
Complete-CvStep @{ Outcome = 'pass'; Reason = 'the instance role policy simulation denies every tested privilege-escalation action' } 'CV-B21'
