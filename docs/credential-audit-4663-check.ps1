# Verifies that Security EID 4663 (object access) is produced for a read of an
# audited file, on a lab host. Run from an elevated PowerShell on the LAB VM only.
#
# What it changes, and how it puts things back:
#   - Turns File System auditing on (success) and records the previous setting.
#   - Adds one audit rule to ONE synthetic file it creates under %TEMP%.
# It restores the audit setting and removes the rule and the file at the end, even
# if the check fails. It never touches a browser store or any real credential file.
#
# Output: EID4663_FOUND=True|False and the matching object name, if found.

#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from an elevated PowerShell.'
}

$subcat = 'File System'
$before = (auditpol /get /subcategory:"$subcat" | Out-String)
$wasOff = $before -match 'No Auditing'
$testFile = Join-Path $env:TEMP ("bas_audit_check_{0}.txt" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
$found = $false
$matchName = $null

try {
    Set-Content -Path $testFile -Value '[BAS-SIM] audit verification file, no real data' -Encoding UTF8

    auditpol /set /subcategory:"$subcat" /success:enable | Out-Null

    $acl = Get-Acl -Path $testFile
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        'Everyone', 'ReadData', 'None', 'None', 'Success')
    $acl.AddAuditRule($rule)
    Set-Acl -Path $testFile -AclObject $acl

    $start = Get-Date
    Start-Sleep -Milliseconds 500
    [void][System.IO.File]::ReadAllBytes($testFile)
    Start-Sleep -Seconds 3

    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663; StartTime = $start } -ErrorAction SilentlyContinue
    foreach ($e in $events) {
        $xml = [xml]$e.ToXml()
        $obj = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ObjectName' }).'#text'
        if ($obj -and $obj -like "*$(Split-Path $testFile -Leaf)") {
            $found = $true
            $matchName = $obj
            break
        }
    }
}
finally {
    # Restore: remove the audit rule and the file, then put auditing back as it was.
    if (Test-Path $testFile) {
        try {
            $acl = Get-Acl -Path $testFile
            $acl.Audit | ForEach-Object { [void]$acl.RemoveAuditRule($_) }
            Set-Acl -Path $testFile -AclObject $acl
        } catch { }
        Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
    }
    if ($wasOff) {
        auditpol /set /subcategory:"$subcat" /success:disable | Out-Null
    }
}

Write-Output ("EID4663_FOUND={0}" -f $found)
if ($matchName) { Write-Output ("ObjectName={0}" -f $matchName) }
Write-Output ("AuditRestoredToOff={0}" -f $wasOff)
