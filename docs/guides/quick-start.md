# Audspect BAS — Quick Start Guide

**Platform Version:** v1.7.5  
**Time to first simulation:** ~30 minutes

---

## Prerequisites

- Ubuntu 20.04/22.04/24.04 LTS, or Rocky Linux / RHEL 9
- Docker Engine with the daemon running, Docker Compose v2.8.0+ (the installer checks both and can install them with your confirmation)
- 3.8 GB RAM and 2 CPU cores minimum, 10 GB free disk (the installer's checks)
- At least one Windows or Linux endpoint to test on
- Delivery ZIP from Audspect (`bas-install-<version>.zip`)

---

## Step 1 — Deploy the Server (10 minutes)

**Transfer the delivery ZIP to the server and extract it:**

```bash
scp bas-install-<version>.zip admin@<server-ip>:/opt/
ssh admin@<server-ip>
cd /opt && sudo unzip bas-install-<version>.zip && cd bas-install-<version>
```

**Prepare a config file and run the installer:**

```bash
cp setup.conf.template setup.conf
nano setup.conf   # fill in DB_PASSWORD, ADMIN_EMAIL, ADMIN_PASSWORD, LIC_PATH at minimum
sudo bash install.sh --install --config setup.conf --yes
```

| `setup.conf` field | Description |
|---|---|
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | Initial admin login. The installer creates this account without a forced password change. Change the password from the dashboard after first login. |
| `DB_PASSWORD` | Postgres password |
| `LIC_PATH` | Path to the customer license file |
| `BAS_PORT` | Listening port (defaults to `9443` if omitted) |
| `BAS_DASHBOARD_PORT` | Dashboard port (defaults to `9543` if omitted) |

This one command loads the Docker images, writes secrets, creates and starts the systemd service, waits for the health check, and creates the admin user — typically well under a couple of minutes.

When it reports success, open the dashboard at the URL the installer prints (`https://<server-ip>:9543` by default) and complete the first-login password change.

---

## Step 2 — Enroll an Agent (5 minutes)

### Download the agent installer

Log in to the dashboard. Navigate to **Agents** → **Download Installer** → select the OS matching your test endpoint → download.

### Deploy and enroll (Windows)

Run the downloaded `BASAgent-Setup-<version>.exe` on the target machine as Administrator and follow its prompts for the server URL and agent secret (found under **Agents → Connection Config** in the dashboard). It installs the agent as a Windows service and enrolls automatically.

For a manual/scripted install instead of the GUI installer, use the standalone agent binary directly:
```powershell
# Replace <server-url> and <secret> with values from Settings -> Connection Config
.\bas-agent-windows-amd64.exe -server https://192.168.1.50:9443 -secret <agent-secret> -install
```

Refresh the dashboard — the agent appears in the **Agents** list within 30 seconds.

### Deploy and enroll (Linux example)

```bash
chmod +x bas-agent-linux-amd64
sudo ./bas-agent-linux-amd64 -server https://192.168.1.50:9443 -secret <agent-secret> -install
sudo systemctl status bas-agent
```

---

## Step 3 — Run Your First Simulation (5 minutes)

1. In the dashboard, go to **Scenarios**
2. Find **"Safe Security Simulation (Read-Only)"** (the safest built-in scenario — read-only OS queries, no modification)
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
| Run a full endpoint assessment | Scenarios → Atomic Red Team - Full Windows Sweep |
| Create a Campaign (multi-agent, or target an Agent Group / all agents) | Campaigns → New Campaign |
| Set up a recurring assessment | Scheduled Assessments → New Schedule |
| Run attack path collection | Attack Path → Run Collection |
| Invite another analyst | Settings → Users & roles |
| Organize endpoints into groups | Agents → Group tree panel |
| Download an audit pack | Agents → [agent] → Reports → Audit Pack |
| Configure MISP / OpenCTI / OTX | Settings → Threat Intel Connector — enter URL/API key, Test Connection, Save (no restart needed) |
| Check fleet-wide posture at a glance | Dashboard (Executive Dashboard KPI row) |

---

## Useful Links

- [Full Installation Guide](installation.md) — TLS, systemd, offline, sizing
- [Agent Management Guide](agent-management.md) — lifecycle, quarantine, retire
- [Scenarios Guide](scenarios.md) — library reference, custom builder
- [Troubleshooting Guide](troubleshooting.md) — common deployment issues

---

*© Audspect — Confidential — Customer Distribution*
