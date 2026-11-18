# Cobalt Group BFSI - AS-REP roasting simulation (cred-06)
# Queries AD, so it runs only against a domain the operator has named as the lab domain.
$labDomain = $env:BAS_LAB_DOMAIN
if (-not $labDomain) {
  Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_LAB_DOMAIN is not set; refusing to query an unscoped domain' } 'CRED-06'
}
if ($env:USERDNSDOMAIN -ne $labDomain) {
  Complete-CgStep @{ Outcome = 'skip'; Reason = "Current domain does not match BAS_LAB_DOMAIN ($labDomain); refusing to query" } 'CRED-06'
}

$undo_data = @{ scenario = 'cred-06'; timestamp = (Get-Date -Format 'o'); description = 'AS-REP roasting simulation' }
try { New-CgUndoRecord 'cred-06' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'cred-06' }

$res = try { Get-ADUser -Identity 'testuser' -Server $labDomain -Properties UserAccountControl -ErrorAction Stop | Out-Null; @{ Outcome = 'fail'; Reason = 'AS-REP roasting possible' } } catch { @{ Outcome = 'pass'; Reason = 'AS-REP roasting blocked or account not found' } }
Complete-CgStep $res 'CRED-06'
