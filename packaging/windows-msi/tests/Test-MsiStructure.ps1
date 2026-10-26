#requires -Version 5.1
<#
  Structural checks on a built Audspect Agent MSI. They read the MSI database only: nothing is
  installed. They catch broken wizard navigation, a secret that is not hidden, and a custom action
  sequence that would run in the wrong place.
  Usage: .\Test-MsiStructure.ps1 -Msi ..\out\AudspectAgent.msi
#>
param([Parameter(Mandatory)][string]$Msi)
$ErrorActionPreference = 'Stop'
$Msi = (Resolve-Path $Msi).Path
$failures = New-Object System.Collections.Generic.List[string]
function Check([bool]$ok, [string]$name) {
    if ($ok) { Write-Host "PASS  $name" } else { Write-Host "FAIL  $name"; $failures.Add($name) }
}

$installer = New-Object -ComObject WindowsInstaller.Installer
$db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($Msi, 0))

function Query([string]$sql) {
    # A missing table means the feature is not authored; the checks below then fail with a clear name.
    try { $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @($sql)) }
    catch { Write-Host "note: query failed ($sql)"; return , @() }
    $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
    $rows = @()
    while ($true) {
        $rec = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
        if ($null -eq $rec) { break }
        $n = $rec.GetType().InvokeMember('FieldCount', 'GetProperty', $null, $rec, $null)
        $row = @()
        for ($i = 1; $i -le $n; $i++) { $row += [string]$rec.GetType().InvokeMember('StringData', 'GetProperty', $null, $rec, $i) }
        $rows += , $row
    }
    $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null
    return , $rows
}

# --- wizard navigation -------------------------------------------------------------------
$dialogs = @((Query 'SELECT `Dialog` FROM `Dialog`') | ForEach-Object { $_[0] })
$events = Query 'SELECT `Dialog_`, `Control_`, `Event`, `Argument`, `Condition` FROM `ControlEvent`'
$bad = @($events | Where-Object { $_[2] -in 'NewDialog', 'SpawnDialog' -and $_[3] -notin $dialogs })
Check ($bad.Count -eq 0) ("every NewDialog/SpawnDialog target exists" + $(if ($bad) { ": " + ($bad | ForEach-Object { "$($_[0]).$($_[1])->$($_[3])" }) -join ', ' }))
foreach ($d in 'ConfigDlg', 'SecretDlg', 'TestConnectionDlg') { Check ($dialogs -contains $d) "dialog $d is present" }

$next = @($events | Where-Object { $_[0] -eq 'ConfigDlg' -and $_[1] -eq 'Next' })
Check (@($next | Where-Object { $_[2] -eq 'DoAction' -and $_[3] -eq 'CheckDeploymentConfig' }).Count -eq 1) 'ConfigDlg Next re-verifies the config before moving on'
Check (@($next | Where-Object { $_[2] -eq 'NewDialog' -and $_[4] -match 'CONFIG_OK = "1"' }).Count -eq 1) 'ConfigDlg Next only advances when the config verified'

$ctl = Query 'SELECT `Dialog_`, `Control`, `Attributes`, `Property` FROM `Control`'
$secretEdit = @($ctl | Where-Object { $_[0] -eq 'SecretDlg' -and $_[3] -eq 'AGENT_SECRET' })
Check ($secretEdit.Count -eq 1) 'the secret has exactly one input control'
Check (($secretEdit.Count -eq 1) -and (([int]$secretEdit[0][2] -band 0x200000) -ne 0)) 'the secret input is a password (masked) control'

$cc = Query 'SELECT `Dialog_`, `Control_`, `Action`, `Condition` FROM `ControlCondition`'
Check (@($cc | Where-Object { $_[0] -eq 'TestConnectionDlg' -and $_[1] -eq 'Next' -and $_[3] -match 'PREFLIGHT_OK' }).Count -ge 1) 'Test connection gates Next on a passed test or SKIPPREFLIGHT'

# --- secret handling ---------------------------------------------------------------------
$props = Query 'SELECT `Property`, `Value` FROM `Property`'
$hidden = @($props | Where-Object { $_[0] -eq 'MsiHiddenProperties' } | ForEach-Object { $_[1] })
Check (($hidden.Count -eq 1) -and ($hidden[0] -match '(^|;)AGENT_SECRET(;|$)')) 'AGENT_SECRET is listed in MsiHiddenProperties'
Check (($hidden.Count -eq 1) -and ($hidden[0] -match '(^|;)RunAgentInstall(;|$)')) 'the deferred action data property is hidden too'
Check (@($props | Where-Object { $_[0] -eq 'AGENT_SECRET' -and $_[1] }).Count -eq 0) 'AGENT_SECRET has no default value in the MSI'
Check (@($props | Where-Object { $_[0] -eq 'ENV_LABEL' -and $_[1] -eq 'Production' }).Count -eq 1) 'ENV_LABEL defaults to Production'
Check (($hidden.Count -eq 1) -and ($hidden[0] -match '(^|;)ENROLLMENT_TOKEN(;|$)')) 'ENROLLMENT_TOKEN is listed in MsiHiddenProperties'
Check (@($props | Where-Object { $_[0] -eq 'ENROLLMENT_TOKEN' -and $_[1] }).Count -eq 0) 'ENROLLMENT_TOKEN has no value baked into the MSI (a token is per host and single use)'
$tokenEdit = @($ctl | Where-Object { $_[0] -eq 'SecretDlg' -and $_[3] -eq 'ENROLLMENT_TOKEN' })
Check (($tokenEdit.Count -eq 1) -and (([int]$tokenEdit[0][2] -band 0x200000) -ne 0)) 'the enrollment token has one masked input control'

# --- custom actions and sequence ----------------------------------------------------------
$seq = Query 'SELECT `Action`, `Condition`, `Sequence` FROM `InstallExecuteSequence`'
Check (@($seq | Where-Object { $_[1] -match 'ENROLLMENT_TOKEN' }).Count -eq 0) 'no sequence condition references the token'
function SeqOf([string]$a) { ($seq | Where-Object { $_[0] -eq $a } | Select-Object -First 1) }
$prepare = SeqOf 'PrepareAgentInstall'; $install = SeqOf 'RunAgentInstall'; $rollback = SeqOf 'RollbackAgentInstall'
$uninstall = SeqOf 'RunAgentUninstall'; $refresh = SeqOf 'RefreshAgentIntegrity'
$installFiles = SeqOf 'InstallFiles'; $removeFiles = SeqOf 'RemoveFiles'; $startSvc = SeqOf 'StartServices'
Check ($null -ne $prepare -and $null -ne $install -and $null -ne $rollback -and $null -ne $uninstall -and $null -ne $refresh) 'all agent custom actions are scheduled'
Check ([int]$rollback[2] -lt [int]$install[2]) 'the rollback action is scheduled before the install action'
Check ([int]$install[2] -gt [int]$installFiles[2] -and [int]$install[2] -lt [int]$startSvc[2]) 'the service is registered after files are installed and before services start'
Check ([int]$uninstall[2] -lt [int]$removeFiles[2]) 'the agent is uninstalled before its files are removed'
Check ($uninstall[1] -match 'UPGRADINGPRODUCTCODE') 'uninstall is skipped during a major upgrade'
Check ($install[1] -match 'AGENT_SERVICE_EXISTS') 'the install action is skipped when a service already exists (upgrade keeps enrollment)'

$ca = Query 'SELECT `Action`, `Type` FROM `CustomAction`'
$deferredInstall = @($ca | Where-Object { $_[0] -eq 'RunAgentInstall' })[0]
Check (([int]$deferredInstall[1] -band 0x400) -ne 0) 'RunAgentInstall is deferred'
Check (([int]$deferredInstall[1] -band 0x800) -ne 0) 'RunAgentInstall runs without impersonation (SYSTEM)'

$bin = Query 'SELECT `Name` FROM `Binary`'
Check (@($bin | Where-Object { $_[0] -eq 'AgentForPreflight' }).Count -eq 1) 'the agent is embedded for the pre-install checks'

$reg = Query 'SELECT `Name`, `Value` FROM `Registry`'
Check (@($reg | Where-Object { $_[0] -eq 'ProductCode' -and $_[1] -eq '[ProductCode]' }).Count -eq 1) 'the product code is recorded so a remote uninstall can remove the MSI registration'

$upg = Query 'SELECT `UpgradeCode`, `Attributes` FROM `Upgrade`'
Check ($upg.Count -ge 1) 'a major-upgrade entry exists'

if ($failures.Count -gt 0) { Write-Host "`n$($failures.Count) check(s) failed"; exit 1 }
Write-Host "`nAll structural checks passed."
