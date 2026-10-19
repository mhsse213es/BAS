# ScriptBlock Visibility Procedure (Application Control, in-process host)

**Purpose.** Establish whether PowerShell ScriptBlock logging (event 4104) records the script text of the custom in-process host used by `inprocess_hosting`. This is the only visibility signal that path has. Until this procedure passes on a host, visibility stays `unknown` for that path. It is never assumed.

**What this does not establish.** It does not establish AMSI coverage, coverage of `powershell.exe`, or coverage of any product's own host. Those are separate measurements. It also does not establish that a blocking control enforces anything. That is the lab sign-off in `appcontrol-mastery-qa-log.md`.

## Prerequisites

- A Windows host where you may change PowerShell logging policy. Use a disposable lab machine or VM, not a production endpoint.
- The helper built from `tools/inprocess-host/build.ps1`, for example `C:\BAS\bas-pshost.exe`.
- A readable operational log: `Microsoft-Windows-PowerShell/Operational`.
- Windows build 17763 or later. Earlier builds report `not_applicable`, as the step gate defines.

## Procedure

### 1. Record the starting state

Run this in an elevated PowerShell session and keep the output with the test record:

```powershell
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
"ScriptBlockLogging policy value: " + ((Get-ItemProperty -Path $key -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging)
"Build: " + [Environment]::OSVersion.Version.Build
```

If the value is not `1`, continue to step 2. If it is `1`, skip step 2.

### 2. Enable ScriptBlock logging (lab host only)

```powershell
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord
```

Record the change. Revert it in step 6.

### 3. Run the benign host test with a unique marker

The marker is a fresh identifier for this run, so it cannot match an earlier record. The helper validates it and accepts only the `BAS-SIM-INPROC-` form.

```powershell
$start  = Get-Date
$marker = 'BAS-SIM-INPROC-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
& 'C:\BAS\bas-pshost.exe' $marker
"exit=" + $LASTEXITCODE
```

Expected output includes `HOST_LANGUAGE_MODE:`, `HOST_ADDTYPE:`, and the marker. The helper runs a benign `Add-Type` probe and does nothing destructive.

### 4. Look for the event

Wait a few seconds for the log to flush, then search for event 4104 recorded since the start time:

```powershell
Start-Sleep -Seconds 5
$hits = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $start } |
  Where-Object { $_.Message -like "*$marker*" }
"matching 4104 events: " + @($hits).Count
$hits | Select-Object -First 1 TimeCreated, Id, RecordId | Format-List
```

### 5. Interpret the result

| Observed | Meaning | Visibility to record |
|---|---|---|
| One or more matching 4104 events | The host script text was recorded. | `visible` |
| No matching event, logging enabled (step 2) and log readable | The host's script text was not recorded. | `not_visible` |
| Log unreadable, or logging not enabled | Nothing can be concluded. | `unknown` |

Do not report `visible` from anything other than a matching event. Do not report `not_visible` unless logging was enabled and the log was readable. The scenario step applies the same rule automatically when logging is enabled by policy.

### 6. Revert and record

Remove the lab setting, then confirm it is gone:

```powershell
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
```

Record the following in `appcontrol-mastery-qa-log.md`: the starting policy value, the build number, the marker, the matching event count, the event's `TimeCreated` and `RecordId`, the visibility result from the table, and any error text.

## Acceptance

The procedure passes when a run with logging enabled produces a matching 4104 event and the step reports `visible`. A run with logging disabled must report `unknown`, not `not_visible`. Both runs must be recorded. A single `visible` result does not establish visibility on other hosts, other builds, or other PowerShell hosts.
