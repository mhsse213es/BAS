$names = @('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AZURE_CLIENT_SECRET', 'AZURE_CLIENT_ID', 'GOOGLE_APPLICATION_CREDENTIALS')
$present = @($names | Where-Object { -not [string]::IsNullOrEmpty((Get-CvEnv $_)) })
if ($present.Count -gt 0) { Complete-CvStep @{ Outcome = 'fail'; Reason = ('cloud credential environment variables are set in this process environment (names only): ' + ($present -join ', ')) } 'CV-C24' }
Complete-CvStep @{ Outcome = 'pass'; Reason = 'no cloud credential environment variables are set in the process environment checked' } 'CV-C24'
