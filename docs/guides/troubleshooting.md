# Audspect BAS — Troubleshooting Guide

**Platform Version:** v1.7.3

---

## Diagnostic Quick Reference

```bash
# Platform health
curl http://localhost:9000/health

# Container status
docker compose ps

# Orchestrator logs (last 100 lines)
docker compose logs orchestrator --tail=100

# PostgreSQL connectivity
docker compose exec postgres psql -U bas -d bas -c "SELECT COUNT(*) FROM users;"

# Agent count in database
docker compose exec postgres psql -U bas -d bas -c "SELECT state, COUNT(*) FROM agents GROUP BY state;"
```

---

## Section 1 — Installation and Startup

### 1.1 Orchestrator container exits immediately on startup

**Symptom:** `docker compose ps` shows orchestrator in `Exit 1` state seconds after start.

**Check logs:**
```bash
docker compose logs orchestrator 2>&1 | tail -30
```

**Common causes:**

| Log message | Cause | Fix |
|---|---|---|
| `database_url required` | `DATABASE_URL` not set in `.env` | Set `DATABASE_URL` in `.env` |
| `jwt_secret required` | `JWT_SECRET` not set | Set `JWT_SECRET` (min 32 chars) |
| `dial tcp: connection refused` | PostgreSQL not up yet | Wait 10s, `docker compose restart orchestrator` |
| `failed to load license` | `BAS_LICENSE_PATH` points to non-existent file | Verify file path and container volume mount |
| `CRYPTO SELF-TEST FAILED` | Binary corruption or environment issue | Re-pull/re-load the orchestrator image |

---

### 1.2 Setup wizard never shows "Deployment successful"

**Symptom:** Web wizard at port 9001 hangs on "Deploying…" indefinitely.

**Checks:**
1. `docker compose logs orchestrator | tail -20` — look for startup errors (see 1.1)
2. `curl localhost:9000/health` — if timeout, orchestrator not bound to port 9000
3. `docker ps | grep orchestrator` — check container is running

If `docker ps` shows the container running but `/health` times out: check that `HTTP_PORT=9000` is correct in `.env` and the port is not already in use (`ss -tlnp | grep 9000`).

---

### 1.3 Admin password is unknown after fresh install

**Symptom:** Can't log in after first install; `BAS_ADMIN_PASSWORD` was not set.

**Fix:** The auto-generated password is printed once to the orchestrator log:
```bash
docker compose logs orchestrator | grep -i "admin password\|initial password"
```

If not found: reset via direct database update:
```bash
# Generate a PBKDF2 hash for the new password using the orchestrator's built-in tool
docker compose exec orchestrator /bas-server set-password admin@company.com "NewPassword1!"
```

---

## Section 2 — Agent Connectivity

### 2.1 Agent not appearing in the dashboard

**Symptom:** Agent installed, service running, but not in the Agents list.

**Checks:**

1. **Verify agent service is running:**
   - Windows: `Get-Service "BAS Agent"`
   - Linux: `sudo systemctl status bas-agent`

2. **Verify server URL in agent config:**
   - Windows: `Get-Content "C:\ProgramData\BAS Agent\config"`
   - Linux: `cat /etc/bas-agent/config`
   - The URL must be reachable from the endpoint (not `localhost`)

3. **Test TCP connectivity from endpoint:**
   - Windows: `Test-NetConnection <server-ip> -Port 9000`
   - Linux: `nc -zv <server-ip> 9000`

4. **Check agent logs:**
   - Windows: Event Viewer → Windows Logs → Application → Source: "BAS Agent"
   - Linux: `journalctl -u bas-agent -n 50`

**Common error messages:**

| Agent log | Cause | Fix |
|---|---|---|
| `connection refused` | Wrong IP or port | Correct `url` in agent config |
| `401 Unauthorized` | Wrong agent secret | Copy secret from Admin → Connection Config |
| `dial tcp: i/o timeout` | Firewall blocking | Open port 9000 on server firewall |
| `certificate verify failed` | Self-signed cert, agent doesn't trust CA | Install CA cert on endpoint or use HTTP for agents |

---

### 2.2 Agent shows Active then immediately goes Offline

**Symptom:** Agent appears in dashboard briefly, then state changes to Offline.

**Cause:** Heartbeat is reaching the server once but subsequent heartbeats fail.

**Checks:**
1. Clock skew: If the server and endpoint clocks differ by >5 minutes, JWT validation can fail intermittently. Sync NTP on both machines.
2. Intermittent network connectivity: Monitor `ping <server-ip>` from endpoint during Offline period.
3. Agent crash: Check event log/journalctl for crash entries.

---

### 2.3 Agent shows 401 on heartbeat

**Symptom:** Agent log shows `401 Unauthorized` on every heartbeat attempt.

**Cause:** `AGENT_SECRET` mismatch between server and agent.

**Fix:**
1. Dashboard: Admin → Connection Config → copy the current agent secret
2. Update agent config with the correct secret
3. Restart agent service

---

### 2.4 Binary trust shows yellow shield on all agents

**Symptom:** Every agent shows a yellow binary trust warning.

**Cause:** `BINARIES.sha256` manifest was not updated in the current deployment, or points to a different agent binary version.

**Checks:**
1. Confirm the agent binary matches the platform version: agent reports its version on heartbeat
2. `GET /api/config` → check what manifest the server is using

This is expected if agents are running a version not included in the current manifest. Update agents to the version included in the delivery package to clear the warning.

---

## Section 3 — Scenario Execution

### 3.1 Run stuck at "Running" indefinitely

**Symptom:** Live run shows step executing for >5 minutes without completing.

**Cause options:**
- Agent went offline mid-run
- Step timeout exceeded (ART atomics default to 60-second step timeout)
- Agent service crashed

**Behavior:** The staleness monitor marks a run as `Partial` if no result is received for 90 seconds after the last reported step. Check the run status in the Runs list.

**Fix:** If the agent is offline, wait for it to reconnect (run resumes from the last successful step on reconnect). If the agent is online but the run is stuck, cancel via `DELETE /api/scenarios/runs/{runId}`.

---

### 3.2 Run immediately shows "Failed" with no steps

**Symptom:** Run starts, immediately fails, no step output visible.

**Causes:**

| Situation | Fix |
|---|---|
| Agent went offline between dispatch and execution | Verify agent is Active; retry |
| Scenario signature verification failure | Re-sign the scenario or use a built-in scenario |
| Invalid scenario YAML | Check scenario YAML syntax; use the validator in the dashboard |
| Agent doesn't support the scenario OS | Verify OS compatibility in the scenario metadata |

---

### 3.3 ART scenario steps show ERROR (not FAIL)

**Symptom:** ART atomic steps show ERROR verdict instead of FAIL for expected failures.

**Meaning:** ERROR means the BAS platform could not execute the step, not that the control blocked it. ERROR is excluded from scoring.

**Common causes:**
- Missing ART prerequisite (e.g., a required tool not present on the endpoint)
- Atomic test requires network connectivity the endpoint doesn't have
- PowerShell execution policy blocking the step (run `Set-ExecutionPolicy Bypass -Scope Process` on the endpoint, or configure per-scope)

**Note:** ERROR on a FAIL-expected step is not a cause for concern about control effectiveness. It means the test couldn't run, not that the attacker was blocked.

---

### 3.4 Scenario rejected as unsigned

**Symptom:** Scenario appears with red "Signature Invalid" badge; cannot be run.

**Cause:** Scenario YAML was modified after signing, or the signature file is missing.

**Fix:**
- If using a built-in scenario that was unintentionally modified: restore from the delivery ZIP
- If using a custom scenario: re-sign via the scenario upload process (dashboard signing occurs automatically on upload)
- For externally placed YAML: run the signing step from `windows-build.ps1` or use the standalone signing tool

---

### 3.5 PowerShell execution blocked — all steps ERROR on Windows

**Symptom:** All Windows ART steps return ERROR; agent log shows PowerShell-related access denial.

**Fix:**
The agent runs with the service account's PowerShell execution policy. For BAS simulation, the agent needs to execute downloaded scripts:

```powershell
# Set policy for the service account (run as that account, or via Group Policy)
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine
```

Alternatively, deploy the agent as a user with an appropriate policy applied.

---

## Section 4 — Reports and PDF

### 4.1 PDF report is blank

**Symptom:** Downloading a PDF report produces a valid PDF with blank pages.

**Cause:** The Chromium sidecar is not running or is crashing.

**Fix:**
```bash
docker compose ps | grep chromium
docker compose logs chromium --tail=30
```

If the container is not running:
```bash
docker compose up -d chromium
```

If Chromium is running but PDFs are still blank: check that the Chromium container has at least 512 MB memory. Increase memory limit in `docker-compose.yml`:
```yaml
services:
  chromium:
    mem_limit: 1g
```

---

### 4.2 PDF report uses old design (pre-v1.7.3 style)

**Symptom:** PDF looks like the old report format; plain text tables without the new design.

**Cause:** Old orchestrator image still running; not upgraded to v1.7.3.

**Fix:** Verify orchestrator version:
```bash
curl -s http://localhost:9000/health | python3 -m json.tool
```

If version is not `1.7.3`, follow the [Upgrade Guide](upgrade-guide.md).

---

### 4.3 Audit pack ZIP download fails with 500 error

**Symptom:** Downloading the audit pack returns HTTP 500.

**Check logs:**
```bash
docker compose logs orchestrator | grep "audit-pack\|auditpack" | tail -20
```

**Common causes:**
- Chromium not running (PDF generation fails, making audit pack fail)
- Agent has no completed runs (nothing to pack)
- Database connectivity issue during ZIP assembly

---

## Section 5 — Attack Path Validation

### 5.1 AP job stays Queued

**Symptom:** Attack Path job created but status stays `queued` for more than 60 seconds.

**Cause:** Agent is offline at job creation time.

**Behavior:** This is expected. Jobs auto-dispatch when the agent reconnects. The `queued` status will advance to `dispatched` within 30 seconds of the agent's next heartbeat.

If the agent is showing as Active but the job stays queued:
- Check the agent's WebSocket connection: restart agent service
- Check orchestrator logs for dispatch errors: `docker compose logs orchestrator | grep "attackpath\|ap job"`

---

### 5.2 AP job shows delivery_failed

**Symptom:** Job status transitions to `delivery_failed`.

**Cause:** The orchestrator dispatched the job but the agent did not send an ACK within 30 seconds.

**Fix:** The job can be retried: `POST /api/attackpath/jobs/{jobId}/retry`. If retries consistently fail, check agent connectivity.

---

### 5.3 AP job completes but graph shows 0 nodes

**Symptom:** Job completed successfully but the graph shows "No data."

**Cause:** No targets were reachable from the agent, or the target list was empty/invalid.

**Check:**
1. Verify target IPs are correct and reachable from the agent endpoint
2. Check the job's `metrics` field: `GET /api/attackpath/jobs/{jobId}` → `metrics.nodeCount`
3. Confirm the agent can reach port 445/5985 on at least one target host

---

## Section 6 — Findings and Remediation

### 6.1 Re-validate shows wrong technique ID

**Symptom:** The Re-validate run dispatches a different technique than the finding.

**Cause:** This was a known bug in v1.6.x where the `_runSelection` state was not properly scoped to the finding. Fixed in v1.7.3 (commits `22314a0` + `4f9e39d`).

**Fix:** Upgrade to v1.7.3.

---

### 6.2 Findings not created after failed run

**Symptom:** A run completed with FAIL verdicts, but no findings appear in the Findings section.

**Cause:** Finding creation runs asynchronously post-run. Allow 10–30 seconds after run completion.

If still no findings after 60 seconds:
- Check the run status is `Completed` (not `Partial` or `Failed`)
- Check orchestrator logs for finding insertion errors: `docker compose logs orchestrator | grep "finding\|upsert"`

---

### 6.3 All findings show "Created" status, never "Open"

**Symptom:** Findings remain in Created state; status not progressing.

**Behavior:** This is correct. `Created` is the initial state. An analyst must manually move findings to `Open` to assign ownership. Findings do not auto-progress from Created to Open.

---

## Section 7 — WebSocket and Dashboard

### 7.1 Dashboard live run output never appears

**Symptom:** Run starts, status shows Running, but no step output appears in the live view.

**Cause:** WebSocket connection not established between browser and orchestrator.

**Checks:**
1. Browser DevTools → Network → WS — look for a WebSocket connection to `/ws`
2. If connection is shown but no messages: check for proxy stripping `Upgrade` header

**For nginx reverse proxy:** Ensure these headers are forwarded:
```nginx
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
```

---

### 7.2 Session expires and dashboard shows blank

**Symptom:** After some time, the dashboard becomes blank or shows 401 errors.

**Cause:** JWT expired (24-hour TTL). Refresh the page to re-authenticate.

**Longer TTL:** The JWT TTL is hardcoded to 24 hours and cannot be configured in v1.7.3.

---

### 7.3 Multiple users see each other's live run output

**Symptom:** An analyst sees run output for a run they did not start.

**Behavior:** Live run output is broadcast to all connected WebSocket sessions. This is by design — the platform supports a security operations team view where all analysts can monitor active runs.

To restrict this, only share access with users who should see all run activity.

---

## Section 8 — Database

### 8.1 Disk filling up

**Symptom:** Orchestrator returns 500 errors; PostgreSQL logs show disk full.

**Immediate fix:**
1. Stop non-essential containers: `docker compose stop chromium caldera`
2. Delete old PDF blobs from the database (with care):
```sql
-- Preview what would be deleted (runs older than 90 days)
SELECT COUNT(*), pg_size_pretty(SUM(pg_column_size(pdf_data)))
FROM run_reports
WHERE created_at < NOW() - INTERVAL '90 days';

-- Delete (run after reviewing the preview)
DELETE FROM run_reports
WHERE created_at < NOW() - INTERVAL '90 days'
AND format = 'pdf';
```

**Long-term:** Schedule regular backups and prune old data. Resize the volume.

---

### 8.2 Migration fails on upgrade

**Symptom:** After upgrade, orchestrator logs show `migration failed` and the service exits.

**Immediate action:**
```bash
docker compose logs orchestrator | grep -i "migration\|migrate"
```

Do not run the old orchestrator — this may result in partial state.

**Recovery:**
1. Restore from pre-upgrade backup (see [Backup and Restore Guide](backup-restore.md))
2. Contact Audspect support with the full migration error message

---

## Section 9 — Integrations

### 9.1 Caldera scenarios show "Caldera unavailable"

**Symptom:** Caldera-backed scenarios fail to start with "Caldera unavailable" error.

**Checks:**
```bash
docker compose ps caldera
curl http://localhost:8888/api/v2/health    # from orchestrator server
```

If Caldera is running: verify `CALDERA_URL` and `CALDERA_API_KEY` in `.env`.

---

### 9.2 Threat intel sync shows 0 new indicators

**Symptom:** Manual sync of MISP or OpenCTI returns immediately with 0 indicators.

**Checks:**
1. Verify connector URL reachable from orchestrator: `docker compose exec orchestrator wget -q -O - <MISP_URL>/health`
2. Check sector and region filters — they may be filtering out all events
3. MISP: verify the API key has `read` permission on the feed
4. OpenCTI: verify the API key has `read` on the Indicators and Reports entities

---

### 9.3 Email reports not received (exercise engine)

**Symptom:** Exercise completion emails configured but not received.

**SMTP test:**
```bash
docker compose exec orchestrator /bas-server smtp-test --to test@company.com
```

If this fails: check `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` in `.env`. Many SMTP servers require explicit auth even for internal servers.

---

*© Audspect — Confidential — Customer Distribution*
