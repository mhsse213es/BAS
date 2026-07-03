# Audspect BAS — Quick Start Guide

**Platform Version:** v1.7.3  
**Time to first simulation:** ~30 minutes

---

## Prerequisites

- Ubuntu 20.04 LTS or later (22.04/24.04 recommended)
- Docker 24.0+, Docker Compose v2.20+
- 4 GB RAM minimum, 40 GB disk
- At least one Windows or Linux endpoint to test on
- Delivery ZIP from Audspect

---

## Step 1 — Deploy the Server (10 minutes)

**Transfer the delivery ZIP to the server and extract it:**

```bash
scp audspect-bas-v1.7.3.zip admin@<server-ip>:/opt/
ssh admin@<server-ip>
cd /opt && unzip audspect-bas-v1.7.3.zip && cd audspect-bas-v1.7.3
```

**Run the setup wizard:**

```bash
sudo ./setup.sh --web
```

Open `http://<server-ip>:9001/setup` in a browser to complete initial configuration. The wizard asks for:

| Field | Description |
|---|---|
| Server URL | The public URL agents will connect to, e.g., `http://192.168.1.50:9000` |
| Admin email | Initial admin username (an email address) |
| Admin password | Initial password (you will be forced to change it on first login) |
| Agent secret | Random passphrase — copy it; you'll need it when enrolling agents |
| JWT secret | Auto-generated if left blank |

Click **Deploy**. The wizard starts Docker Compose and waits for the orchestrator to become healthy (typically under 60 seconds).

When the wizard shows **Deployment successful**, open the dashboard at `http://<server-ip>:9000` and complete the first-login password change.

---

## Step 2 — Enroll an Agent (5 minutes)

### Download the agent binary

Log in to the dashboard. Navigate to **Agents** → **Download Agent** → select the OS matching your test endpoint → download.

### Deploy and enroll (Windows example)

Transfer `bas-agent.exe` to the target machine. Open a terminal **as Administrator**:

```powershell
# Replace <server-url> and <secret> with values from Admin → Connection Config
.\bas-agent.exe -url http://192.168.1.50:9000 -secret <agent-secret> -install
```

The agent installs as a Windows service and enrolls automatically. Refresh the dashboard — the agent appears in the **Agents** list within 30 seconds.

### Deploy and enroll (Linux example)

```bash
chmod +x bas-agent
sudo ./bas-agent -url http://192.168.1.50:9000 -secret <agent-secret> -install
sudo systemctl status bas-agent
```

---

## Step 3 — Run Your First Simulation (5 minutes)

1. In the dashboard, go to **Scenarios**
2. Find **"Safe Simulation"** (the safest built-in scenario — read-only OS queries, no modification)
3. Click **Run** → select your enrolled agent → click **Confirm**
4. Navigate to **Live Runs** — watch steps execute in real time

When the run completes, click the run row to open the results drawer. You will see:

- Step-by-step PASS/FAIL/ERROR/SKIPPED verdicts
- Prevention Score and Exposure Score
- Remediation guidance for any failures

---

## Step 4 — Review Results and First Finding

If any steps produced **FAIL**, a Finding has been automatically created. Navigate to **Findings** to view it.

Click a finding to see:
- The technique that failed (MITRE ATT&CK ID)
- The severity and tactic
- Step-by-step output from the run
- Recommended remediation

After fixing the control, click **Re-validate** to dispatch a targeted single-technique run directly to that agent.

---

## What's Next

| Task | Where to go |
|---|---|
| Run a full endpoint assessment | Scenarios → ART Full Windows |
| Schedule a recurring campaign | Campaigns → New Campaign |
| Run attack path collection | Attack Path → Run Collection |
| Invite another analyst | Settings → Users → Add User |
| Download an audit pack | Agents → [agent] → Reports → Audit Pack |
| Configure MISP / OpenCTI | Settings → Integrations |

---

## Useful Links

- [Full Installation Guide](installation.md) — TLS, systemd, offline, sizing
- [Agent Management Guide](agent-management.md) — lifecycle, quarantine, retire
- [Scenarios Guide](scenarios.md) — library reference, custom builder
- [Troubleshooting Guide](troubleshooting.md) — common deployment issues

---

*© Audspect — Confidential — Customer Distribution*
