# Cobalt Group BFSI - Valid Local Account Logon (acc-01)
$accountName = New-CgAccessAccountName
$undo_data = @{ scenario = 'acc-01'; accountName = $accountName }
try { New-CgUndoRecord 'acc-01' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'acc-01' }

$plain = [Guid]::NewGuid().ToString('N') + 'Aa1!'
try {
  $secure = ConvertTo-SecureString -String $plain -AsPlainText -Force
  New-LocalUser -Name $accountName -Password $secure -AccountNeverExpires -PasswordNeverExpires -ErrorAction Stop | Out-Null
} catch {
  Complete-CgStep @{ Outcome = 'error'; Reason = "Could not create synthetic account: $($_.Exception.Message)" } 'acc-01'
}

Add-Type -Namespace BasAcc -Name Logon -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern bool LogonUser(string user, string domain, string password, int logonType, int logonProvider, out System.IntPtr token);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool CloseHandle(System.IntPtr handle);
'@

$token = [IntPtr]::Zero
$ok = [BasAcc.Logon]::LogonUser($accountName, $env:COMPUTERNAME, $plain, 3, 0, [ref]$token)
if ($ok) { [BasAcc.Logon]::CloseHandle($token) | Out-Null }

if ($ok) {
  $res = @{ Outcome = 'pass'; Reason = 'Synthetic local account logon succeeded with its own credentials' }
} else {
  $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  $res = @{ Outcome = 'fail'; Reason = "Logon with the synthetic account was refused (Win32 error $err)" }
}
Complete-CgStep $res 'acc-01'
