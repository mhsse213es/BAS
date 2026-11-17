if ((Get-CvAwsToken) -eq '') { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS IMDS is unreachable from this host, so this is not an EC2 instance' } 'CV-B16' }
if (-not (Test-CvAwsCli)) { Complete-CvStep @{ Outcome = 'skip'; Reason = 'AWS CLI is not installed on this host' } 'CV-B16' }
Set-CvAwsRegion
$role = Get-CvAwsRoleName
if ($role -eq '') { Complete-CvStep @{ Outcome = 'pass'; Reason = 'no instance role is attached, so there are no role policies to enumerate' } 'CV-B16' }
$r = Invoke-CvAws @('iam', 'list-attached-role-policies', '--role-name', $role)
$n = 0; try { $n = @((($r.Text | ConvertFrom-Json).AttachedPolicies)).Count } catch {}
if ($r.Code -eq 0) { Write-Output ('EXEC T1069.003: attached role policies visible; count=' + $n) }
Complete-CvStep (Resolve-CvAws $r 'attached role policy enumeration') 'CV-B16'
