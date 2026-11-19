# Offline classifier checks for the cloud VM pack. Runs with no cloud access:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File scenarios-src\cloud-vm-common\lib.Tests.ps1
# Exits 1 when any check fails.
. (Join-Path $PSScriptRoot 'lib.ps1')
$script:fail = 0
function Check([string]$name, $got, $want) {
  if ($got -ne $want) { $script:fail++; Write-Output ('FAIL ' + $name + ': got ' + $got + ' want ' + $want) } else { Write-Output ('ok   ' + $name) }
}
Check 'http 403 -> pass'                    (Resolve-CvHttp @{ Code = 403; Text = '' } 'x').Outcome 'pass'
Check 'http 401 -> pass'                    (Resolve-CvHttp @{ Code = 401; Text = '' } 'x').Outcome 'pass'
Check 'http 200 -> fail'                    (Resolve-CvHttp @{ Code = 200; Body = @{} } 'x').Outcome 'fail'
Check 'http 0 -> error'                     (Resolve-CvHttp @{ Code = 0; Text = '' } 'x').Outcome 'error'
Check 'http 500 -> error'                   (Resolve-CvHttp @{ Code = 500; Text = '' } 'x').Outcome 'error'
Check 'http 404 -> error (not a control)'   (Resolve-CvHttp @{ Code = 404; Text = '' } 'x').Outcome 'error'
$env:BAS_CLOUD_EXPECT_ENUMERATION = 'true'
Check 'expected 200 -> skip'                (Resolve-CvHttp @{ Code = 200; Body = @{} } 'x').Outcome 'skip'
Check 'expected 403 still pass'             (Resolve-CvHttp @{ Code = 403; Text = '' } 'x').Outcome 'pass'
$env:BAS_CLOUD_EXPECT_ENUMERATION = 'TRUE'
Check 'gate is exact-case'                  (Resolve-CvHttp @{ Code = 200; Body = @{} } 'x').Outcome 'fail'
Remove-Item Env:BAS_CLOUD_EXPECT_ENUMERATION -ErrorAction SilentlyContinue
Check 'aws AccessDenied -> pass'            (Resolve-CvAws @{ Code = 254; Text = 'An error occurred (AccessDenied) when calling ListBuckets' } 'x').Outcome 'pass'
Check 'aws unauthorized -> pass'            (Resolve-CvAws @{ Code = 255; Text = 'UnauthorizedOperation: not authorized' } 'x').Outcome 'pass'
Check 'aws no credentials -> skip'          (Resolve-CvAws @{ Code = 255; Text = 'Unable to locate credentials' } 'x').Outcome 'skip'
Check 'aws exit 0 -> fail'                  (Resolve-CvAws @{ Code = 0; Text = '{}' } 'x').Outcome 'fail'
Check 'aws network error -> error'          (Resolve-CvAws @{ Code = 255; Text = 'Could not connect to the endpoint URL' } 'x').Outcome 'error'
Check 'aws role assume unexpected -> fail'(Resolve-CvAws @{ Code = 0; Text = '{}' } 'x' 'BAS_CLOUD_EXPECT_ROLE_ASSUME').Outcome 'fail'
$env:BAS_CLOUD_EXPECT_ROLE_ASSUME = 'true'
Check 'expected role assume -> skip'        (Resolve-CvAws @{ Code = 0; Text = '{}' } 'x' 'BAS_CLOUD_EXPECT_ROLE_ASSUME').Outcome 'skip'
Remove-Item Env:BAS_CLOUD_EXPECT_ROLE_ASSUME -ErrorAction SilentlyContinue
$j = Get-CvJson ('Parameter warning on stderr' + [Environment]::NewLine + '{"AccessKey":{"AccessKeyId":"AKIATEST"}}')
Check 'json after stderr text parses'       ([string]$j.AccessKey.AccessKeyId) 'AKIATEST'
Check 'json garbage -> null'                ($null -eq (Get-CvJson 'not json at all')) $true
Check 'run tag shape'                       ($script:CvTag -match '^bas_cv_[0-9a-f]+$') $true
Write-Output ('classifier-failures=' + $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
