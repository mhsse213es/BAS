# Audspect BAS — Agent Management Guide

**Platform Version:** v1.7.3

---

## Overview

An Audspect BAS agent is a lightweight Go binary deployed on a target endpoint. Agents are intentionally minimal — they receive fully-formed commands from the orchestrator, execute them, and return raw output. All intelligence (scenario parsing, framework resolution, result interpretation) lives on the server.

---

## Agent Lifecycle States

| State | Meaning | Who Sets It |
|---|---|---|
| **Enrolling** | Agent first connected; awaiting initial heartbeat confirmation | Automatic |
| **Active** | Agent connected and healthy, last heartbeat within 90 seconds | Automatic |
| **Restricted** | Agent can connect and report results, but cannot receive new scenario dispatches | Admin |
| **Quarantined** | Agent fully isolated; no dispatches, no result submission, connection rejected | Admin |
| **Retired** | Agent decommissioned; kept for historical data; no new connections | Admin |
| **Offline** | Automatic status when no heartbeat received for >90 seconds | Automatic |

### State transitions

```
Enrolling → Active (first healthy heartbeat)
Active → Offline (heartbeat timeout)
Offline → Active (agent reconnects and heartbeat succeeds)
Active/Offline → Restricted (admin action)
Active/Offline → Quarantined (admin action)
Active/Offline/Restricted → Retired (admin action)
Quarantined → Active (admin lifts quarantine)
```

### Setting agent state (Admin only)

In the dashboard: **Agents** → click the three-dot menu on an agent row → select state.

Via API:
```
POST /api/agents/{id}/state
Body: { "state": "quarantined", "reason": "Suspicious process detected" }
```

---

## Enrolling Agents

### Download the binary

**Dashboard:** Agents → Download Agent → select OS → download

**Direct URL:**
```
GET /api/agents/download?os=windows&arch=amd64
GET /api/agents/download?os=linux&arch=amd64
GET /api/agents/download?os=darwin&arch=arm64
```

### Install on Windows

Open PowerShell **as Administrator**:
```powershell
.\bas-agent.exe `
  -url http://<server-ip>:9000 `
  -secret <agent-secret> `
  -label "DESKTOP-FINANCE-01" `
  -install
```

The agent installs as `BAS Agent` Windows service (auto-start). Event logs go to Windows Event Log under `BAS Agent`.

**Uninstall:**
```powershell
.\bas-agent.exe -uninstall
```

### Install on Linux

```bash
chmod +x bas-agent

# Install as systemd service
sudo ./bas-agent \
  -url http://<server-ip>:9000 \
  -secret <agent-secret> \
  -label "UBUNTU-WEB-01" \
  -install

sudo systemctl status bas-agent
```

Config is written to `/etc/bas-agent/config` on install. Edit this file to change the server URL or secret after installation:
```ini
url = http://192.168.1.50:9000
secret = your-agent-secret
label = UBUNTU-WEB-01
```

Restart after editing:
```bash
sudo systemctl restart bas-agent
```

### Install on macOS

```bash
chmod +x bas-agent
sudo ./bas-agent \
  -url http://<server-ip>:9000 \
  -secret <agent-secret> \
  -label "MAC-ANALYST-01" \
  -install
```

The agent installs as a launchd service (StartAtLoad=true).

### Verify enrollment

Within 30–60 seconds, the agent appears in the dashboard under **Agents** with state **Active**. The agent table shows:
- Hostname and label
- OS version
- Last heartbeat timestamp
- Current state (Active/Offline/etc.)
- Binary trust status
- Active run count

---

## Agent Detail Drawer

Click **Detail** next to any agent row to open the detail drawer. The drawer has five tabs:

### Overview Tab

Displays:
- Hostname, IP address, OS version, architecture
- Agent binary version and binary trust verification result
- Enrollment timestamp, last heartbeat
- Run statistics: total runs, pass rate, last Prevention Score
- Current state badge

### Scenarios Tab

Shows the last 20 scenario runs for this agent:
- Scenario name, start time, duration
- Prevention Score and verdict breakdown
- Status (Completed, Running, Failed, Partial)

Click any run row to open the run detail (step-by-step output).

### Logs Tab

Real-time log stream from the agent (forwarded via WebSocket). Useful for troubleshooting dispatch failures, connectivity issues, and step execution problems.

### Health Tab

Agent environment diagnostics:
- OS version, free disk, memory
- AV product detection results
- Pending OS patches (if posture check ran)
- Agent process uptime

### Attack Path Tab

Lists the last 10 Attack Path collection jobs for this agent:
- Job ID, status, start time, duration
- Collection stage (Initializing / Probing / Running SharpHound / etc.)
- Progress percentage during active runs
- Node count and edge count for completed runs
- Error message for failed runs

When an AP collection is running, this tab refreshes automatically via WebSocket. You can also trigger a new collection from here or from the dedicated **Attack Path** section.

---

## Binary Trust Verification

On every heartbeat, the agent submits the SHA-256 hash of its own binary. The orchestrator compares this against the `BINARIES.sha256` manifest shipped with the delivery package.

**Verification outcomes:**

| Dashboard indicator | Meaning |
|---|---|
| Green shield icon | Binary hash matches manifest |
| Yellow shield icon | Hash not in manifest (agent binary not recognized) |
| Red shield icon | Hash explicitly marked as revoked in manifest |

A yellow shield indicates the agent binary was not part of the delivery package — this can mean:
- Agent binary was replaced on the endpoint
- Agent is an older version not in the current manifest
- Legitimate upgrade not yet reflected in the manifest

A red shield indicates the binary was explicitly revoked (e.g., a leaked or compromised build). In this case, the orchestrator refuses to dispatch scenarios to the agent.

---

## Mass Deployment

### Windows — Group Policy / SCCM

Deploy `bas-agent.exe` via software distribution. Use a startup script that runs the install command:

```powershell
if (-not (Get-Service "BAS Agent" -ErrorAction SilentlyContinue)) {
    & "\\fileserver\bas\bas-agent.exe" `
      -url http://192.168.1.50:9000 `
      -secret "your-secret" `
      -install
}
```

The agent is idempotent on install — running install a second time on an already-installed agent is safe.

### Linux — Ansible

```yaml
- name: Install Audspect BAS agent
  hosts: linux_endpoints
  become: true
  tasks:
    - name: Copy agent binary
      copy:
        src: bas-agent
        dest: /usr/local/bin/bas-agent
        mode: '0755'

    - name: Install agent service
      command: >
        /usr/local/bin/bas-agent
        -url http://192.168.1.50:9000
        -secret {{ agent_secret }}
        -label {{ inventory_hostname }}
        -install
      args:
        creates: /etc/bas-agent/config

    - name: Ensure agent is running
      systemd:
        name: bas-agent
        state: started
        enabled: true
```

---

## Agent Connectivity Troubleshooting

| Symptom | Check | Fix |
|---|---|---|
| Agent not appearing in dashboard | Server URL reachable from endpoint? | `Test-NetConnection <server-ip> -Port 9000` (Windows) or `nc -zv <server-ip> 9000` (Linux) |
| Agent shows Offline immediately | Agent secret mismatch | Copy secret from **Admin → Connection Config** |
| Agent enrolls then immediately goes Offline | Clock skew >5 minutes between server and endpoint | Sync NTP on both machines |
| Agent runs scenarios but results never arrive | Firewall blocking result POST (same port 9000) | Verify agent → server firewall rule |
| Binary trust shows yellow shield | Outdated agent binary | Download and deploy the new binary from the dashboard |

---

## Retiring and Removing Agents

**Retire** — sets agent to Retired state; historical data preserved; no new connections accepted:
```
POST /api/agents/{id}/state   Body: {"state": "retired"}
```

**Delete** — permanently removes the agent record and all associated run data. This cannot be undone.
```
DELETE /api/agents/{id}
```

Delete is only available in the API. The dashboard uses Retire for non-destructive decommission.

---

*© Audspect — Confidential — Customer Distribution*
