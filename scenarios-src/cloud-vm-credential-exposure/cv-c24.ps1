$names = @('AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AZURE_CLIENT_SECRET')
$present = @($names | Where-Object { -not [string]::IsNullOrEmpty((Get-CvEnv $_)) })
$gcp = Get-CvEnv 'GOOGLE_APPLICATION_CREDENTIALS'
if ($gcp -ne '' -and (Test-Path -LiteralPath $gcp)) { $present += 'GOOGLE_APPLICATION_CREDENTIALS (file exists)' }
if ($present.Count -gt 0) { Complete-CvStep @{ Outcome = 'fail'; Reason = ('secret-bearing cloud environment variables are set in this process environment (names only): ' + ($present -join ', ')) } 'CV-C24' }
Complete-CvStep @{ Outcome = 'pass'; Reason = 'no cloud credential environment variables are set in the process environment checked' } 'CV-C24'
