# Caldera allow-list v1: first abilities to validate in the lab

Status: **draft, unverified.** Nothing here is eligible for execution. Each ability stays ineligible until its lab run passes (see `download-stager.md`, lab steps 1 to 6, which apply here too).

Selection source: the Caldera server's ability catalogue, read-only. Of 48 Windows executor entries in the persistence and privilege-escalation tactics, 20 carry a Caldera cleanup command.

## Selection rules

1. Side effects limited to the registry or local user accounts, both fully reversible.
2. The Caldera cleanup command undoes what the ability creates.
3. No reboot, no domain-wide change, no service or DLL replacement, no code downloaded from the internet, no lateral copy to another host.
4. The ability must be restorable to its prior state, not just deleted.

## v1 allow-list (4)

| # | Ability | Technique | Executor | Creates | Cleanup | Notes |
|---|---|---|---|---|---|---|
| 1 | Set Registry Persistence on CFO | T1547.001 | psh | HKLM Run value `Java-Update` (admin) | `reg delete` of that value | Points at a file the command does not create, so harmless on its own. Needs admin. |
| 2 | Emotet Persistence | T1547.001 | cmd | HKCU Run value `blbdigital` | `reg delete` of that value | Points at a DLL the command does not create. |
| 3 | Create a new user in PowerShell | T1136.001 | psh | Local user with no password | `Remove-LocalUser -ErrorAction Ignore` | Creates a real local account. Lab only. |
| 4 | Create a new user in a command prompt | T1136.001 | cmd | Local user with a fixed password from the ability | `net user /del` | Creates a real local account. Lab only. The password is the ability's test value and is not copied here. |

## Excluded from v1, with reason

| Ability | Why it is excluded |
|---|---|
| Install Outlook Home Page Persistence (T1137.004) | `reg add /f` overwrites any existing Outlook home-page value, and the cleanup deletes it. The original value cannot be restored. Revisit only with a pre-state snapshot. |
| Office Application Startup - Outlook as a C2 (T1137) | Changes Office security settings. Needs its own review. |
| Create a new Domain Account / domain admin user (T1136.002) | Domain-wide change. Out of scope for a single lab endpoint. |
| Restart-computer (T1546.011, T1218.011) | Reboots the endpoint. |
| Modify Terminal Services DLL Path / Simulate Patching termsrv.dll (T1505.005) | Changes a system DLL and its ACL. Not reliably reversible. |
| Replace a service binary (T1543.003) | Replaces a running service binary. |
| Install IIS Module (T1505.004) | System-wide web server change. |
| Install MS Exchange Transport Agent (T1505.002) | Mail-system change. |
| Google Chrome extension, UAC bypass, PowerSploit, Akagi, Process Injection | Download or run third-party code. |
| OilRig copy webshell (T1505.003) | Copies a file to another host. |
| Scheduled Task Persistence (T1553.005, T1053.005) | No Caldera cleanup. Tasks are not removed by the ability. |
| Registry Run Keys (T1547.001, cmd) | No Caldera cleanup. |
| Persistent Service 1 / 2 (T1547.009) | No Caldera cleanup. |

## Before any of the four run

- The lab endpoint must be confirmed as a lab (see the message to the owner). It must not be the shared staging host.
- Take an endpoint snapshot, or record the pre-state of the registry keys and local users listed above.
- Run each ability, then its cleanup, then confirm the state matches the pre-state.
