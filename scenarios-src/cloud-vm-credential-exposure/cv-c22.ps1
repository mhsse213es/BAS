$f = Join-Path $env:USERPROFILE '.aws\credentials'
if (-not (Test-Path -LiteralPath $f)) { Complete-CvStep @{ Outcome = 'pass'; Reason = 'no shared AWS credentials file exists under this user profile' } 'CV-C22' }
$txt = Get-Content -LiteralPath $f -Raw
$profiles = ([regex]::Matches($txt, '(?m)^\s*\[')).Count
Write-Output ('EXEC T1552.001: shared credentials file present; profile sections=' + $profiles + '. Key values were not recorded.')
if ($txt -match '(?im)^\s*aws_secret_access_key\s*=') { Complete-CvStep @{ Outcome = 'fail'; Reason = ('a shared AWS credentials file holds a plaintext aws_secret_access_key (' + $profiles + ' profile section(s)); values were not recorded') } 'CV-C22' }
Complete-CvStep @{ Outcome = 'pass'; Reason = 'a shared AWS credentials file exists but holds no plaintext secret access key on this host' } 'CV-C22'
