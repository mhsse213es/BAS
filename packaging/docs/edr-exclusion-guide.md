# BAS Agent — EDR / AV Exclusion Guide

Before running breach-and-attack simulations, the BAS agent process must be
excluded from your EDR/AV **process termination** and **network blocking**
policies. The simulated attack techniques it spawns are intentionally NOT
excluded — your security controls should still detect and alert on those.

> **Why exclude only the agent?**
> The agent is a thin executor: it receives tasks over WebSocket and launches
> child processes to run each technique. If the EDR kills the agent itself,
> the WebSocket connection drops and results are never reported. If it kills a
> child process (the actual simulation), the agent catches that, marks the step
> as **Blocked**, and reports it as a finding — which is exactly the result
> you want.

> **Standalone Windows Defender Antivirus is handled automatically.** Both
> `bas_agent.exe --install` and `--update` call `Add-MpPreference` to add a
> process + path exclusion for the agent's own exe, best-effort (a failure
> here never blocks install). This is what most single-machine/consumer
> Windows endpoints run — a false-positive detection there (commonly
> `Behavior:Win32/Execution.A!ml`, an ML behavioral heuristic on the
> agent's own process) should self-resolve on the next install/update.
> Everything below this point (CrowdStrike, MDE, SentinelOne, etc.) still
> needs to be configured by hand — those are centrally-managed policies the
> agent has no way to reach from the endpoint.

---

## What to exclude

| Item | Value |
|------|-------|
| **Linux binary path** | `/opt/bas/bas-agent` (or wherever your team deployed it) |
| **Windows binary path** | Wherever `bas_agent.exe` was installed — there's no single fixed path; check `(Get-Service BASAgent).BinaryPathName` on the endpoint, or ask whoever deployed it. |
| **Process name** | `bas-agent` / `bas_agent.exe` |
| **Outbound destination** | BAS Orchestrator IP/hostname, port `9000` (TCP) |

Do **not** exclude `cmd.exe`, `powershell.exe`, `bash`, or any technique
binaries — those should remain monitored so the simulation produces real
detection findings.

---

## CrowdStrike Falcon

1. **Falcon Console** → Prevention Policies → select your policy → **Exclusions**
2. Add a **Process Exclusion**:
   - Path: `<install path>\bas_agent.exe` (Windows — see "What to exclude" above)  
     or `/opt/bas/bas-agent` (Linux sensor)
   - Toggle **Prevent** off; leave **Detect** on
3. Repeat for each OS policy that covers the target hosts.

CLI (Falcon API):
```
falconctl exclusions create --type process --value /opt/bas/bas-agent
```

---

## Microsoft Defender for Endpoint (MDE)

**Security portal** → Settings → Endpoints → Indicators → **Add indicator**

- Indicator type: **File** (SHA-256 of `bas-agent` binary)
- Action: **Allow**
- Scope: device group containing your simulation targets

Or via Intune / Group Policy — add the agent path to:
```
Computer Configuration → Policies → Administrative Templates →
  Windows Components → Microsoft Defender Antivirus →
  Exclusions → Process Exclusions
```
Value: `<install path>\bas_agent.exe` (see "What to exclude" above)

---

## SentinelOne

1. **Sentinels** → Exclusions → **New Exclusion**
2. Type: **Path**  
   Value: `/opt/bas/bas-agent` or `<install path>\bas_agent.exe`
3. Operating Mode: **Detect** (not Protect) — keeps alerting on child techniques

---

## Symantec Endpoint Security (SES/SEP)

**Policies** → Exceptions → **Add Exception** → Application Exception  
- Application name: `bas_agent.exe`  
- Action: Exclude from SONAR and intrusion prevention

---

## Trend Micro Apex One / Vision One

**Policies** → Behavior Monitoring → Exception List  
Add the agent binary path under **Trusted Process**.

---

## Generic (any EDR)

If your EDR is not listed above, add an exclusion by:

1. **Binary hash (SHA-256)** — most precise; re-add after each agent upgrade.
2. **Full path** — covers all versions but path must be consistent.
3. **Certificate / publisher** — if Audspect code-signs the binary, whitelist
   the publisher name (contact support@audspect.com for the certificate thumbprint).

---

## Verifying the exclusion works

After adding the exclusion, start the agent and run a known-noisy technique
(e.g., T1059 — Command and Scripting Interpreter). Expected outcome:

- **Agent stays running** throughout the simulation
- EDR fires an alert on the child process / technique
- BAS report shows the step as **Detected** (not **Blocked**)

If the agent is killed mid-run, the BAS report will show steps as **partial**.
Check EDR telemetry for a termination event on `bas-agent` and verify the
exclusion was applied to the correct policy/scope.

---

## Questions

Contact **support@audspect.com** with your EDR platform and version if you
need platform-specific guidance not covered above.
