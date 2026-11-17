$dir = Join-Path $env:USERPROFILE '.azure'
$files = @((Join-Path $dir 'accessTokens.json'), (Join-Path $dir 'msal_token_cache.json'))
$present = @($files | Where-Object { Test-Path -LiteralPath $_ })
if ($present.Count -eq 0) { Complete-CvStep @{ Outcome = 'pass'; Reason = 'no Azure CLI token cache exists under this user profile' } 'CV-C23' }
$hits = 0
foreach ($p in $present) { $txt = Get-Content -LiteralPath $p -Raw; $hits += ([regex]::Matches($txt, '(?i)"(access_?token|refresh_?token)"')).Count }
Write-Output ('EXEC T1552.001: Azure CLI token cache files present=' + $present.Count + '; token-bearing entries=' + $hits + '. Token values were not recorded.')
if ($hits -gt 0) { Complete-CvStep @{ Outcome = 'fail'; Reason = ('the Azure CLI token cache holds ' + $hits + ' bearer or refresh token entr(y/ies) at rest on this workload VM') } 'CV-C23' }
Complete-CvStep @{ Outcome = 'pass'; Reason = 'Azure CLI token cache files exist but contain no access or refresh token entries' } 'CV-C23'
