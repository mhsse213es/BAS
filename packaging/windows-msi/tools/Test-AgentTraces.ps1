# Read-only audit: lists anything the Audspect Agent leaves (or has) on this computer.
# Run it after an uninstall; "No trace of the Audspect Agent was found" means the computer is clean.
# It changes nothing. Run from an elevated PowerShell for complete results.
[CmdletBinding()] param()

$found = New-Object System.Collections.Generic.List[string]
function Trace([string]$what) { $script:found.Add($what) }

# Services (current and legacy name)
foreach ($n in 'Audspect Agent', 'BASAgent') {
    if (Get-Service -Name $n -ErrorAction SilentlyContinue) { Trace "service: $n" }
}

# Processes
Get-Process -Name bas_agent -ErrorAction SilentlyContinue | ForEach-Object { Trace "process: bas_agent (pid $($_.Id))" }

# Files and folders the agent or its installer creates
$pd = if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' }
$paths = @(
    "$env:ProgramFiles\BASAgent",
    "$env:ProgramFiles\Audspect Agent",
    "$pd\BASAgent",
    "$pd\Audspect\certs",
    "$env:APPDATA\BASAgent",
    "$env:TEMP\BASAgent",
    "$env:WINDIR\Temp\BASAgent",
    "$pd\Microsoft\Windows\Start Menu\Programs\Audspect",
    "$pd\Microsoft\Windows\Start Menu\Programs\BAS Agent.lnk",
    "$pd\Microsoft\Windows\Start Menu\Programs\Audspect Agent.lnk"
)
foreach ($p in $paths) { if (Test-Path -LiteralPath $p) { Trace "path: $p" } }
Get-ChildItem -Path "$pd\Audspect" -Filter 'certs.replaced-*' -ErrorAction SilentlyContinue | ForEach-Object { Trace "path: $($_.FullName)" }
Get-Item -Path "$env:SystemRoot\System32\config\systemprofile\AppData\Roaming\BASAgent" -ErrorAction SilentlyContinue | ForEach-Object { Trace "path: $($_.FullName)" }

# Registry the agent or its installer creates
$keys = @(
    'HKLM:\SOFTWARE\Audspect\Agent',
    'HKLM:\SYSTEM\CurrentControlSet\Services\Audspect Agent',
    'HKLM:\SYSTEM\CurrentControlSet\Services\BASAgent',
    'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Audspect Agent',
    'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\BASAgent'
)
foreach ($k in $keys) { if (Test-Path -LiteralPath $k) { Trace "registry: $k" } }
$run = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
if ($run -and $run.PSObject.Properties['BASAgentTray']) { Trace 'registry: HKLM Run value BASAgentTray' }
foreach ($u in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
    Get-ChildItem $u -ErrorAction SilentlyContinue | ForEach-Object {
        $dn = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName
        if ($dn -like '*Audspect Agent*' -or $dn -eq 'BAS Agent') { Trace "installed program entry: $dn" }
    }
}

# Pending delete-at-restart operations that still name the agent (cleared by the next restart)
$pend = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue).PendingFileRenameOperations
if ($pend) { $pend | Where-Object { $_ -match 'BASAgent|Audspect' } | ForEach-Object { Trace "pending delete at restart: $_" } }

# Windows settings the agent changes while it runs. Informational: a value here is not by itself a trace (an
# administrator may have set it), but the agent's own record of the originals must be gone.
$note = New-Object System.Collections.Generic.List[string]
$wer = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -ErrorAction SilentlyContinue
if ($wer -and $wer.PSObject.Properties['DontShowUI']) { $note.Add("WER DontShowUI = $($wer.DontShowUI)") }
$pca = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags' -ErrorAction SilentlyContinue
if ($pca -and $pca.PSObject.Properties['DisablePCA']) { $note.Add("DisablePCA = $($pca.DisablePCA)") }
$ae = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug' -ErrorAction SilentlyContinue
if ($ae -and $ae.PSObject.Properties['Auto']) { $note.Add("AeDebug Auto = $($ae.Auto)") }
$desk = Get-ItemProperty 'Registry::HKEY_USERS\.DEFAULT\Control Panel\Desktop' -ErrorAction SilentlyContinue
foreach ($n in 'AutoEndTasks', 'HungAppTimeout', 'WaitToKillAppTimeout') {
    if ($desk -and $desk.PSObject.Properties[$n]) { $note.Add("SYSTEM profile $n = $($desk.$n)") }
}

if ($found.Count -eq 0) {
    Write-Host 'No trace of the Audspect Agent was found.' -ForegroundColor Green
} else {
    Write-Host "$($found.Count) trace(s) of the Audspect Agent found:" -ForegroundColor Yellow
    $found | ForEach-Object { Write-Host "  $_" }
}
if ($note.Count -gt 0) {
    Write-Host 'Windows settings currently set (informational; the agent restores these to their originals when it is removed):'
    $note | ForEach-Object { Write-Host "  $_" }
}
exit ([int]($found.Count -gt 0))
