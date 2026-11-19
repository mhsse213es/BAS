# CSCRF-EA-04: PowerShell script block logging is enabled by policy (read only)
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$v = (Get-ItemProperty -Path $k -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
if ($v -eq 1) { Complete-CgStep @{ Outcome = 'pass'; Reason = 'script block logging enabled by policy [CSCRF-EA-04]' } 'ea-04' }
Complete-CgStep @{ Outcome = 'fail'; Reason = 'script block logging is not enabled by policy; PowerShell command content is not recorded [CSCRF-EA-04]' } 'ea-04'
