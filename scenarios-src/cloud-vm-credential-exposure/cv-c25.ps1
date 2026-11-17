$roots = @($env:USERPROFILE) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
$hits = @()
foreach ($r in $roots) { $hits += @(Get-ChildItem -LiteralPath $r -Recurse -File -Include 'terraform.tfstate', '*.tfstate', '*.tfstate.backup' -ErrorAction SilentlyContinue | Select-Object -First 20) }
if ($hits.Count -eq 0) { Complete-CvStep @{ Outcome = 'pass'; Reason = 'no Terraform state files were found under the user profile' } 'CV-C25' }
$secret = 0
foreach ($h in $hits) { $txt = Get-Content -LiteralPath $h.FullName -Raw; $secret += ([regex]::Matches($txt, '"(password|secret|access_key|private_key|client_secret)"')).Count }
Write-Output ('EXEC T1552.001: Terraform state files found=' + $hits.Count + '; secret-like attribute names=' + $secret + '. Values were not recorded.')
if ($secret -gt 0) { Complete-CvStep @{ Outcome = 'fail'; Reason = ('Terraform state on this host holds ' + $secret + ' secret-like attribute(s) in plaintext') } 'CV-C25' }
Complete-CvStep @{ Outcome = 'pass'; Reason = 'Terraform state files were found but none holds secret-like attributes in plaintext' } 'CV-C25'
