# Cobalt Group BFSI - Password spraying simulation (cred-07)
# Wrong-password attempts can lock out real accounts, so this runs only against a domain the operator
# has named as the lab domain. Anything else is refused before any authentication is attempted.
$labDomain = $env:BAS_LAB_DOMAIN
if (-not $labDomain) {
  Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_LAB_DOMAIN is not set; refusing to spray an unscoped domain' } 'CRED-07'
}
if ($env:USERDNSDOMAIN -ne $labDomain) {
  Complete-CgStep @{ Outcome = 'skip'; Reason = "Current domain does not match BAS_LAB_DOMAIN ($labDomain); refusing to spray" } 'CRED-07'
}

$undo_data = @{ scenario = 'cred-07'; timestamp = (Get-Date -Format 'o'); description = 'Password spraying simulation' }
try { New-CgUndoRecord 'cred-07' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'cred-07' }

$res = try { $users = @('testuser1', 'testuser2'); $pwd = ConvertTo-SecureString 'wrongpassword' -AsPlainText -Force; foreach ($u in $users) { $cred = New-Object System.Management.Automation.PSCredential($u, $pwd); $null = Get-ADUser -Identity $u -Server $labDomain -Credential $cred -ErrorAction Stop } @{ Outcome = 'fail'; Reason = 'Password spray succeeded' } } catch { @{ Outcome = 'pass'; Reason = 'Password spray blocked' } }
Complete-CgStep $res 'CRED-07'
