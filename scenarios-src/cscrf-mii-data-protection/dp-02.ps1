# CSCRF-DP-02: BAS_DP_PATH does not grant write or full control to Everyone or Users (read only). SKIP when unset.
$p = $env:BAS_DP_PATH
if (-not $p) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_DP_PATH not set; no data path checked [CSCRF-DP-02]' } 'dp-02' }
if (-not (Test-Path -LiteralPath $p)) { Complete-CgStep @{ Outcome = 'error'; Reason = "BAS_DP_PATH does not exist: $p [CSCRF-DP-02]" } 'dp-02' }
$acl = Get-Acl -LiteralPath $p -ErrorAction SilentlyContinue
if (-not $acl) { Complete-CgStep @{ Outcome = 'error'; Reason = 'ACL could not be read [CSCRF-DP-02]' } 'dp-02' }
$broad = @($acl.Access | Where-Object { $_.IdentityReference.Value -match '(^|\\)(Everyone|Users|Authenticated Users)$' -and ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) -and $_.AccessControlType -eq 'Allow' })
if ($broad.Count -gt 0) { Complete-CgStep @{ Outcome = 'fail'; Reason = "broad write access on data path ($($broad[0].IdentityReference.Value)) [CSCRF-DP-02]" } 'dp-02' }
Complete-CgStep @{ Outcome = 'pass'; Reason = 'no broad write grant on the data path [CSCRF-DP-02]' } 'dp-02'
