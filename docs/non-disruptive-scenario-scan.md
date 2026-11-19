# Non-Disruptive Execution: scenario scan

Why this exists: after some simulations an endpoint stopped behaving normally (`appwiz.cpl` from Run opened Explorer,
folders would not open). Cause: Atomic Red Team T1548.002 tests (sdclt, Warzone) write
`HKCU\Software\Classes\Folder\shell\open\command` with an empty `DelegateExecute`, which overrides Explorer's handler,
and the agent (running as LocalSystem) looked at SYSTEM's own `HKCU`, not the logged-in user's.

## What the agent now guarantees after every run

| Stage | Mechanism | Where |
|---|---|---|
| Observe | Before the run: registry guard roots, processes, services, tasks, Run keys, Startup folder, hosts file, and the effective handler for common file types are recorded | `agent/reghijack_guard_windows.go`, `snapshot_windows.go`, `health_windows.go` |
| Restore | Registry diffs put back (in the **logged-in user's** hive, `HKEY_USERS\<SID>`); new services stopped, disabled and deleted when safe; new tasks deleted; stray processes the run started stopped; recovery after an agent crash | `userhive_windows.go`, `service_revert_windows.go`, `process_sweep_windows.go` |
| Verify | Windows is asked again how `.cpl`, `.exe`, `Folder`, `Directory`, `ms-settings` ... open, that Explorer is running, and whether a default-action override exists. Anything wrong is reported as `restore incomplete: ...` | `health_windows.go` |
| Report | `restore incomplete:` items show in a red "Not fully restored" block in the PDF/HTML report, change the run's cleanup status (never "Successful"), and appear in the console run view | `reporting/engine.go`, `html.go`, `web/src/features/restore-model.js` |

Service deletion is limited to user-mode services whose program is not under Program Files, WinSxS, drivers, or an
`svchost` group; anything else a run introduces is stopped and disabled only. The process sweep stops only processes
that are new since the run began **and** descend from the agent, or are orphans of a known demo program (calc, notepad,
shells, script hosts). Explorer, the shell, system processes and the agent itself are never touched.

## Static scan of the Windows atomics

`scripts/scenario-scan/` reads the atomics in the `art_atomic_tests` table and lists the persistent changes each could
make. 1,279 Windows tests were scanned; 382 write something persistent.

Registry writes found: **287**. Outside the guard before this work: 214 (of 269 found then). Outside it now: **82**.
The guard now covers Policies (HKLM and HKCU), Lsa, WDigest, Terminal Server, Session Manager, SafeBoot, network
providers, Winlogon (HKCU), Internet Settings, event-log channels, Active Setup, Office security keys, and more.
The guard takes about 0.4 s to record 94 roots on a real machine.

Still outside the guard (82 writes), by area: Explorer and Windows shell settings; Defender and Security Center
settings (also tamper-protected); service entries (`HKLM\System\CurrentControlSet\Services`); per-test marker keys
(`AtomicTest`, `.pwn`, `NetWire`); `HKLM\SAM`, `SECURITY` (not restorable from a user session). Run
`python scripts/scenario-scan/paths.py <scan.json> 6` for the live list.

## Categories the agent does NOT restore (honest gaps)

The scanner flags these; the agent has no restore for them today. Their own cleanup commands are the only defence.

| Category | Tests | Note |
|---|---|---|
| Files dropped outside temp | 60 | Only the temp folders and Startup are swept |
| Process injection / kills | 32 | A process the test **stopped** is not restarted |
| Permissions / ACL changes | 13 | |
| Local accounts | 12 | |
| Defender configuration | 11 | `Set-MpPreference` is not reverted |
| Log or backup destruction | 9 | **Irreversible** (`wevtutil cl`, `vssadmin delete`): flag or block, cannot be restored |
| Firewall rules | 8 | Captured, not verified after revert |
| WMI persistence, boot config, certificates, WinRM, port proxy, environment, time zone, file association | 14 | |

Tests with no cleanup command at all that touch the registry: T1547.014 Test 3 (HKLM Active Setup). T1685 Tests 54-55
(delete Defender keys) and T1218 Test 14 are now inside the guard. T1548.002 Test 23 (WSReset) leaves
`HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2`, which the guard does not cover yet.

## Not verified yet

- Never run as the real LocalSystem service. The tests exercise the logic with the current user; the SYSTEM-to-user
  hive path (`userHiveKey`) is covered by stubbed SIDs only. Needs one live scenario that writes the Folder key.
- The console change (`restore-model.js`) is unit-tested but not viewed in a browser.
- Requires a rebuild, re-signing of `BINARIES.sha256` and agent redeploy before any of this takes effect.
