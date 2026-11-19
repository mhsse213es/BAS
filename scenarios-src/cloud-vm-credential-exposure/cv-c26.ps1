$files = @((Join-Path $env:USERPROFILE '.aws\config'), (Join-Path $env:USERPROFILE '.azure\config'), (Join-Path $env:APPDATA 'gcloud\configurations\config_default'))
$present = @($files | Where-Object { Test-Path -LiteralPath $_ })
if ($present.Count -eq 0) { Complete-CvStep @{ Outcome = 'pass'; Reason = 'no cloud SDK configuration files were found under the user profile' } 'CV-C26' }
$hits = 0
foreach ($p in $present) { $txt = Get-Content -LiteralPath $p -Raw; $hits += ([regex]::Matches($txt, '(?im)^\s*(client_secret|secret_key|password|aws_secret_access_key)\s*=')).Count }
Write-Output ('EXEC T1552.001: cloud SDK configuration files present=' + $present.Count + '; secret-like keys=' + $hits + '. Values were not recorded.')
if ($hits -gt 0) { Complete-CvStep @{ Outcome = 'fail'; Reason = ('cloud SDK configuration holds ' + $hits + ' secret-like key(s) in plaintext') } 'CV-C26' }
Complete-CvStep @{ Outcome = 'pass'; Reason = 'cloud SDK configuration files exist but hold no secret-like keys in plaintext' } 'CV-C26'
