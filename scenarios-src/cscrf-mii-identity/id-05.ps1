# CSCRF-ID-05: a disabled account must not authenticate
if (-not (Test-CgIdentityGate)) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_CONFIRM_IDENTITY_CHANGE not true; no account created [CSCRF-ID-05]' } 'id-05' }
$name = New-CgIdName
$plain = New-CgSynthPassword
New-CgUndoRecord 'id-05' @{ scenario = 'id-05'; accountName = $name }
try {
  New-LocalUser -Name $name -Password (ConvertTo-SecureString $plain -AsPlainText -Force) -AccountNeverExpires -ErrorAction Stop | Out-Null
  Disable-LocalUser -Name $name -ErrorAction Stop
} catch { Complete-CgStep @{ Outcome = 'error'; Reason = "could not create or disable synthetic account: $($_.Exception.Message) [CSCRF-ID-05]" } 'id-05' }
$token = [IntPtr]::Zero
$ok = [BasId.Logon]::LogonUser($name, $env:COMPUTERNAME, $plain, 3, 0, [ref]$token)
if ($ok) { [BasId.Logon]::CloseHandle($token) | Out-Null; Complete-CgStep @{ Outcome = 'fail'; Reason = 'disabled synthetic account authenticated; disabled accounts are accepted [CSCRF-ID-05]' } 'id-05' }
$err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
Complete-CgStep @{ Outcome = 'pass'; Reason = "logon with the disabled synthetic account was refused (Win32 error $err) [CSCRF-ID-05]" } 'id-05'
