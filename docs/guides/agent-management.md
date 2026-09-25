# Audspect BAS — Agent Management Guide

**Platform Version:** v1.7.5

---

## Overview

An Audspect BAS agent is a lightweight Go binary deployed on a target endpoint. Agents are intentionally minimal — they receive fully-formed commands from the orchestrator, execute them, and return raw output. All intelligence (scenario parsing, framework resolution, result interpretation) lives on the server.

---

## Agent Lifecycle States

`state` is a persisted field on the agent record, set explicitly by an Admin action (or by the agent itself for the uninstall states below). It is separate from the *connectivity* status shown in the dashboard (Active/Offline), which is derived live from heartbeat timing — an agent in state `active` still shows as **Offline** in the UI the moment its heartbeat lapses, without any state change.

| State | Meaning | Who Sets It |
|---|---|---|
| **enrolling** | Agent first connected; awaiting initial heartbeat confirmation | Automatic |
| **active** | Normal operating state | Automatic (on first healthy heartbeat) |
| **restricted** | Agent can connect and report results, but cannot receive new scenario dispatches | Admin |
| **quarantined** | Agent fully isolated; no dispatches accepted | Admin |
| **retired** | Agent decommissioned; historical data preserved; no new connections | Admin |
| **uninstalling** | Remote uninstall in progress; agent has been told to remove itself | Automatic (set by the Uninstall action below) |
| **uninstalled** | Agent confirmed it removed itself, via its own callback | Automatic (agent-reported) |

### Setting agent state (Admin only)

Via API:
```
PUT /api/agents/{agentId}/state
Body: { "state": "quarantined" }
```

---

## Enrolling Agents

### Download the binary

**Dashboard:** Agents → Download Agent → select platform → download

**Direct URL** — `{platform}` is one exact value, not separate os/arch query params:
```
GET /api/agents/download/linux-amd64
GET /api/agents/download/linux-arm64
GET /api/agents/download/linux-amd64-deb
GET /api/agents/download/linux-arm64-deb
GET /api/agents/download/linux-amd64-rpm
GET /api/agents/download/windows-amd64-setup
GET /api/agents/download/windows-amd64
GET /api/agents/download/darwin-amd64
GET /api/agents/download/darwin-arm64
```

### Install on Windows

Open PowerShell **as Administrator**:
```powershell
.\bas-agent.exe `
  -server https://<server-ip>:9443 `
  -secret <agent-secret> `
  -install
```

The agent installs as the `Audspect Agent` Windows service (auto-start; the Windows Service Manager's own `DisplayName` field reads "Audspect - BAS Platform Agent"). The tray icon and status console window separately display "BAS Agent" as a friendly title — that's the tray window's own title, unrelated to the service name below it. The actual service name (for `Get-Service`, `sc.exe`, etc.) is `Audspect Agent`, with a space — quote it in commands: `Get-Service "Audspect Agent"`. An endpoint enrolled before the Audspect rebrand may still show the legacy service name `BASAgent`; it's migrated automatically on the endpoint's next `-update`.

**Uninstall (locally, on the endpoint):**
```powershell
.\bas-agent.exe -uninstall
```
To uninstall remotely instead, from the dashboard, see **Retiring and Removing Agents** below.

### Install on Linux

```bash
chmod +x bas-agent

# Install as systemd service
sudo ./bas-agent \
  -server https://<server-ip>:9443 \
  -secret <agent-secret> \
  -install

sudo systemctl status bas-agent
```

Config is written to `/etc/bas-agent/config` on install (shell-style `KEY=value`, one per line — not INI):
```
BAS_SERVER_URL=https://192.168.1.50:9443
BAS_ENV_LABEL=Production
BAS_AGENT_SECRET=your-agent-secret
```
`BAS_ENV_LABEL` is a free-text environment tag shown next to the agent in the dashboard (e.g. "Production", "Staging") — it is not a per-agent display name; the agent's hostname is used for that.

Edit the config file directly to change any of these values, then restart:
```bash
sudo systemctl restart bas-agent
```

### Install on macOS

```bash
chmod +x bas-agent
sudo ./bas-agent \
  -server https://<server-ip>:9443 \
  -secret <agent-secret> \
  -install
```

Config is written to `/etc/bas-agent/config`, same format as Linux. The agent installs as a launchd service.

### Verify enrollment

Within 30–60 seconds, the agent appears in the dashboard under **Agents** with state **enrolling**, moving to **active** on its first healthy heartbeat. The agent table shows:
- Hostname
- OS version
- Last heartbeat timestamp
- Current state
- Binary trust status
- Active run count

---

## Agent Detail Drawer

Click an agent row to open the detail drawer. The drawer has **six** tabs:

### Overview Tab

Displays hostname, IP, OS version, environment label, current state, binary trust status, and enrollment/heartbeat timestamps.

### Scenarios Tab

Shows recent scenario runs for this agent: name, start time, status, and score. Click any run row to open the run detail.

### Logs Tab

Real-time operational log stream from the agent (auto-refreshes every 15 seconds while this tab is open). Useful for troubleshooting dispatch failures and step execution problems.

### Health Tab

Agent environment diagnostics: OS version, resource usage, and posture-check-derived signals when a posture run has executed on this agent.

### Attack Path Tab

Lists recent Attack Path collection jobs for this agent, with status, stage, and node/edge counts for completed runs.

### Risk Tab

Per-agent risk scoring, derived from posture/patch/config findings and their severity — a separate signal from the BAS Prevention Score, focused on standing exposure rather than simulated-attack outcomes.

---

## Binary Trust Verification

On every heartbeat, the agent submits the SHA-256 hash of its own binary. The orchestrator checks whether that hash is present in the `BINARIES.sha256` manifest shipped with the delivery package.

**This is a two-state check, not a tiered trust system:**

| Dashboard indicator | Meaning |
|---|---|
| ✓ Verified (green) | Binary hash is present in the shipped manifest |
| ⚠ Unverified (yellow) | Binary hash is not present in the manifest |

An Unverified result can mean the agent binary was replaced on the endpoint, or it's simply an older/newer build not covered by the currently-loaded manifest. There is no separate "revoked hash" list or automatic dispatch-blocking based on this flag alone — it is a visibility signal for the operator to investigate, not an enforcement gate.

---

## Mass Deployment

### Windows — Group Policy / SCCM

```powershell
if (-not (Get-Service "Audspect Agent" -ErrorAction SilentlyContinue)) {
    & "\\fileserver\bas\bas-agent.exe" `
      -server https://192.168.1.50:9443 `
      -secret "your-secret" `
      -install
}
```

Install is idempotent — running it a second time on an already-installed agent is safe.

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
        -server https://192.168.1.50:9443
        -secret {{ agent_secret }}
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
| Agent not appearing in dashboard | Server URL reachable from endpoint? | `Test-NetConnection <server-ip> -Port 9443` (Windows) or `nc -zv <server-ip> 9443` (Linux) |
| Agent shows Offline immediately | Agent secret mismatch | Reissue the secret from the dashboard's agent enrollment flow |
| Agent enrolls then immediately goes Offline | Clock skew between server and endpoint | Sync NTP on both machines |
| Agent runs scenarios but results never arrive | Firewall blocking the same port 9443 in both directions | Verify agent ↔ server firewall rules |
| Binary trust shows Unverified | Agent binary predates or postdates the loaded manifest | Confirm the deployed binary matches the current release |

---

## Retiring and Removing Agents

There are three distinct decommission actions, each doing something meaningfully different:

**Stop** — sends the agent a live command to disable its own service so it never auto-restarts. The agent must currently be connected. Requires a reason (audited):
```
POST /api/agents/{agentId}/stop
Body: { "reason": "Suspicious activity — isolating pending investigation" }
```

**Remove (Retire)** — sets the agent's state to `retired` server-side. No action on the endpoint itself; historical run data is preserved; the agent no longer accepts new dispatches. Requires a reason (audited):
```
POST /api/agents/{agentId}/remove
Body: { "reason": "Endpoint decommissioned" }
```

**Uninstall** — the fully verified remote-uninstall flow: the orchestrator tells the agent to remove itself (state moves to `uninstalling`), and the agent confirms completion via its own callback (state moves to `uninstalled`):
```
POST /api/agents/{agentId}/uninstall
```

All three are Admin-only actions, available from the dashboard's agent row menu.

---

*© Audspect — Confidential — Customer Distribution*
