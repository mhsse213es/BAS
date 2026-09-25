# Audspect BAS — Troubleshooting Guide

**Platform Version:** v1.7.5

---

## Diagnostic Quick Reference

```bash
# Platform health
curl http://localhost:9443/health

# Container status
docker compose ps

# Orchestrator logs (last 100 lines)
docker compose logs orchestrator --tail=100

# PostgreSQL connectivity
docker compose exec postgres psql -U bas_user -d bas_platform -c "SELECT COUNT(*) FROM users;"

# Agent count in database
docker compose exec postgres psql -U bas_user -d bas_platform -c "SELECT state, COUNT(*) FROM agents GROUP BY state;"
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

### 1.2 `install.sh --install` hangs or reports failure before completing

**Symptom:** `sudo bash install.sh --install --config setup.conf` doesn't reach "Installation Complete."

There is no separate web-based setup wizard to troubleshoot — `install.sh` does the whole install in one run (image load → bundle files → systemd unit → start stack → health-check wait → admin user creation). If it's stuck or fails partway:

**Checks:**
1. Which numbered step (`1/10`–`10/10`) did it stop at? The step label tells you which phase failed.
2. `docker logs audspect-orchestrator --tail=30` — look for startup errors (see 1.1)
3. `curl http://localhost:9443/health` — if this times out, the orchestrator isn't bound to the configured port yet, or isn't up
4. `docker ps | grep audspect-orchestrator` — confirm the container is actually running

If the container is running but `/health` times out: confirm `BAS_PORT` in `setup.conf` matches what you're checking, and that the port isn't already in use (`ss -tlnp | grep 9443`).

---

### 1.3 Can't log in after fresh install

**Symptom:** The admin credentials from `setup.conf` don't work.

Unlike an older `.env`-based flow, the admin account is **not** auto-generated — `install.sh` creates it directly from `ADMIN_EMAIL`/`ADMIN_PASSWORD` in your `setup.conf` (via one internal POST to `/api/auth/setup`, step 10/10 of the install), so there's no printed-to-logs password to search for. If login fails:

1. Double-check `setup.conf`'s `ADMIN_EMAIL`/`ADMIN_PASSWORD` were actually what you typed (typos, especially in `ADMIN_PASSWORD`, are the most common cause)
2. Confirm step 10/10 actually ran and succeeded — check the install output/log for a `_create_admin`-related error; if the health check never passed, admin creation is skipped entirely
3. If you have another working admin account, use **Settings → Users → Reset Password** to fix the locked-out account instead of fighting with the original credentials
4. If this is the *only* admin account and it's genuinely lost with no way to recreate it from `setup.conf`, that requires either a direct database update using the same PBKDF2-HMAC-SHA256 scheme the platform uses (non-trivial to do safely by hand) or contacting Audspect support — don't attempt an ad-hoc SQL password reset without matching the exact hash format (`$pbkdf2-sha256$<iterations>$<salt>$<dk>`), a mismatched format just locks the account out differently.

---

## Section 2 — Agent Connectivity

### 2.1 Agent not appearing in the dashboard

**Symptom:** Agent installed, service running, but not in the Agents list.

**Checks:**

1. **Verify agent service is running:**
   - Windows: `Get-Service "Audspect Agent"` (the service *name* has a space; a pre-rebrand endpoint may still be registered under the legacy name `BASAgent` until its next `--update`, which auto-migrates it)
   - Linux: `sudo systemctl status bas-agent`

2. **Verify server URL in agent config:**
   - Windows: config is stored in the registry, not a file — `Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Audspect Agent\Parameters"` and check `BAS_SERVER_URL`
   - Linux: `cat /etc/bas-agent/config`
   - The URL must be reachable from the endpoint (not `localhost`)

3. **Test TCP connectivity from endpoint:**
   - Windows: `Test-NetConnection <server-ip> -Port 9443`
   - Linux: `nc -zv <server-ip> 9443`

4. **Check agent logs:**
   - Windows: `C:\ProgramData\BASAgent\logs` (this data directory still uses the pre-rebrand name — only the *service* name changed) — or Event Viewer → Windows Logs → Application → Source: "Audspect Agent"
   - Linux: `journalctl -u bas-agent -n 50`

**Common error messages:**

| Agent log | Cause | Fix |
|---|---|---|
| `connection refused` | Wrong IP or port | Correct the server URL (Windows: registry `BAS_SERVER_URL`; Linux: `/etc/bas-agent/config`) |
| `401 Unauthorized` | Wrong agent secret | Copy secret from Settings → Connection Config |
| `dial tcp: i/o timeout` | Firewall blocking | Open the configured port (default 9443) on server firewall |
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
2. Confirm the orchestrator's `BINARIES.sha256`/`.sig` were actually refreshed for the current release — a `windows-build.ps1` run with `-SkipBuild` doesn't re-extract or re-sign the manifest, only a full build does (see [Build Guide](../internal/build-guide.md))

This is expected if agents are running a version not included in the current manifest. Update agents to the version included in the delivery package to clear the warning.

---

### 2.5 Proxy authentication failures

**Symptom:** An agent behind a corporate forward proxy never connects — logs show repeated `WS connect failed` retries with no other obvious cause (server URL correct, port reachable, no certificate error). This is expected if the proxy requires authentication: see [Installation Guide → 7.2 Agent Outbound Proxy Authentication](installation.md#72-agent-outbound-proxy-authentication) for how to configure it. The messages below tell you exactly what's missing.

**Checks:** same log locations as [2.1](#21-agent-not-appearing-in-the-dashboard) above.

| Agent log contains | Meaning | Fix |
|---|---|---|
| `SSPI unavailable on this platform` | Proxy offered NTLM, but this agent isn't on Windows (NTLM is Windows-only) | Configure `BAS_PROXY_USER`/`BAS_PROXY_PASSWORD` for Basic auth instead, if the proxy also offers it — otherwise this proxy cannot be used from a non-Windows agent |
| `no Basic credentials configured (set BAS_PROXY_USER/BAS_PROXY_PASSWORD)` | Proxy offered Basic, no credentials are set | Set `BAS_PROXY_USER`/`BAS_PROXY_PASSWORD` — see Installation Guide 7.2 for the exact mechanism per platform |
| `no supported mechanism was offered` | Proxy requires auth but offered neither NTLM nor Basic | This proxy uses a mechanism the agent doesn't support (e.g. Kerberos/Negotiate) — not currently supported; contact the network team about enabling Basic or NTLM for this agent's traffic |
| `proxy rejected the configured credentials` | A username/password (or, on Windows, the machine's own NTLM identity) was actually sent and the proxy rejected it — this is a **confirmed** rejection, not a missing-config case | Verify `BAS_PROXY_USER`/`BAS_PROXY_PASSWORD` are correct. On Windows with NTLM: check whether the proxy's access rule is scoped to named user accounts only — the agent authenticates as its machine account (`DOMAIN\COMPUTERNAME$`), see the caveat in Installation Guide 7.2. **Retries on this specific error back off far slower than usual (up to 30 minutes) specifically to avoid repeatedly hammering a wrong credential against an AD-integrated proxy and tripping its account lockout policy** — if you just fixed the credential, restart the agent service rather than waiting for the next retry |

---

## Section 3 — Scenario Execution

### 3.1 Run stuck at "Running" indefinitely

**Symptom:** Live run shows step executing for >5 minutes without completing.

**Cause options:**
- Agent went offline mid-run
- Step timeout exceeded (ART atomics default to 60-second step timeout)
- Agent service crashed

**Behavior:** The staleness monitor marks a run as `Partial` if no result is received for 90 seconds after the last reported step. Check the run status in the Runs list.

**Fix:** If the agent is offline, wait for it to reconnect (run resumes from the last successful step on reconnect). If the agent is online but the run is stuck, cancel via `POST /api/scenarios/runs/{runId}/cancel`.

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

**This only affects builtin scenarios** — RSA-4096 signature verification applies exclusively to `.yaml` files loaded from disk at startup. Custom scenarios created/edited via the dashboard are never signed at all and can't hit this error; they're trusted via authenticated dashboard access instead (see [Scenario SDK](../internal/scenario-sdk.md) → Signing).

**Fix:**
- If a built-in scenario was unintentionally modified on disk: restore the original `.yaml`+`.yaml.sig` pair from the delivery ZIP
- For a new hand-authored file placed directly in `SCENARIOS_DIR` (bypassing the dashboard): it must be signed on the build host with `orchestrator/scripts/signer.go sign private_key.pem <file>.yaml` before it will load

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
docker compose ps | grep chrome
docker compose logs chrome --tail=30
```

If the container is not running:
```bash
docker compose up -d chrome
```

If Chromium is running but PDFs are still blank: check that the container has at least 512 MB memory. Increase memory limit in `docker-compose.yml`:
```yaml
services:
  chrome:
    mem_limit: 1g
```

If the sidecar is unreachable, the orchestrator degrades to a built-in fallback PDF renderer (`fpdf`, lower fidelity) rather than failing the download outright — a blank-page PDF is more likely a hung/unhealthy Chromium container than a total failure. Check the orchestrator log for `chrome sidecar not configured` or `HTML→PDF via chrome unavailable` — if present, `CHROME_WS_URL` isn't reaching a healthy sidecar.

---

### 4.2 PDF report uses the older report design

**Symptom:** PDF looks like an older report format; plain text tables without the current design.

**Cause:** An old orchestrator image is still running.

**Fix:** Verify orchestrator version:
```bash
curl -s http://localhost:9443/health | python3 -m json.tool
```

If the reported version is older than expected, follow the [Upgrade Guide](upgrade-guide.md).

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

**Longer TTL:** The JWT TTL is hardcoded to 24 hours and is not configurable.

---

### 7.3 Multiple users see each other's live run output

**Symptom:** An analyst sees run output for a run they did not start.

**Behavior:** Live run output is broadcast to all connected WebSocket sessions. This is by design — the platform supports a security operations team view where all analysts can monitor active runs.

To restrict this, only share access with users who should see all run activity.

---

## Section 8 — Database

### 8.1 Disk filling up

**Symptom:** Orchestrator returns 500 errors; PostgreSQL logs show disk full.

Reports render on-demand from HTML at request time — there's no growing PDF/HTML blob table to prune. The table most likely to grow large is `scenario_runs.results` (a JSONB column holding step-level output).

**Immediate fix:**
1. Stop non-essential containers: `docker compose stop chrome caldera`
2. Archive old run results (with care — see [Performance Tuning Guide](../internal/performance-tuning.md) → Run History Retention for the full procedure and its caveats):
```sql
-- Preview what would be archived (runs older than 1 year)
SELECT COUNT(*) FROM scenario_runs
WHERE completed_at < NOW() - INTERVAL '1 year' AND results != '[]';

-- Archive (clears only the raw results payload, not scores/status)
UPDATE scenario_runs SET results = '[]'
WHERE completed_at < NOW() - INTERVAL '1 year' AND results != '[]';
VACUUM ANALYZE scenario_runs;
```

**Long-term:** Schedule regular backups and prune old data (see [Backup and Restore Guide](backup-restore.md)). Resize the volume.

---

### 8.2 Orchestrator fails to start after upgrade with a database-related error

**Symptom:** After running `install.sh --upgrade`, the orchestrator container restarts in a loop with a database connection or authentication error.

**Most likely cause:** `POSTGRES_PASSWORD` mismatch between a freshly-generated `.env` and the still-persisted Postgres volume's actual password — this is exactly the scenario `install.sh --upgrade` is designed to prevent by preserving existing secrets, so this should only happen if `.env` was hand-edited or restored from the wrong source outside of `install.sh`.

**Immediate action:**
```bash
docker logs audspect-orchestrator --tail=50
docker logs audspect-postgres --tail=50
```

**Recovery:**
```bash
sudo bash install.sh --rollback
```
This restores the previous working `docker-compose.yml`/`.env` from the automatic pre-upgrade backup. If that doesn't resolve it, restore from a pre-upgrade database backup instead — see [Backup and Restore Guide](backup-restore.md) — and contact Audspect support with the full error message.

There are no numbered schema migrations that can "fail" in the traditional sense — schema application is a single idempotent pass (`CREATE TABLE IF NOT EXISTS` / `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`) that runs on every startup; a startup failure here is virtually always a connectivity/credential problem, not a migration ordering problem.

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

### 9.2 Threat intel sync shows 0 new indicators / connectors show no data in Threat Prioritization

**Symptom:** MISP/OpenCTI/OTX are configured, but sync returns 0 actors, or Threat Prioritization stays empty.

MISP, OpenCTI, and OTX are configured entirely from **Settings → Threat Intel Connector** now — enter the URL/API key, click **Test Connection** (a real one-off connectivity check that reports back an actor count), then **Save**. There's no `.env` editing and no restart involved; a save takes effect immediately.

**Checks, in order:**
1. Did **Test Connection** report a non-zero actor count *before* saving? If it reported 0, the credentials/URL are the problem, not the platform — check with the connector's own admin console that the feed actually has data.
2. Was the connector actually **saved with Enabled checked** — Test Connection alone never persists anything or triggers a sync.
3. Check the connector status card on the same Settings page for `lastSyncStatus`/`lastError` — every save triggers an immediate sync, so this should update within seconds of saving.
4. Sector/region filters may be filtering out everything — try broadening them.
5. MISP: verify the API key has `read` permission on the feed. OpenCTI: verify `read` on the Indicators and Reports entities.
6. If Threat Prioritization specifically is empty despite a successful sync with actors found: it reads from `threat_actor_profiles`, populated only after actors are actually returned by a sync — confirm the connector status card shows a recent successful sync, not just a saved config.

The orchestrator image is distroless (no shell), so `docker exec`-ing a `wget`/`curl` check into the container doesn't work — test connectivity from Test Connection in the UI instead, or from another host on the same network as the orchestrator.

---

### 9.3 Email reports not received (exercise engine)

**Symptom:** Exercise completion emails configured but not received.

There is no built-in SMTP test CLI command. Check `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` in `.env` are all set correctly, and check the orchestrator logs around the time an exercise completed for an SMTP send error:
```bash
docker logs audspect-orchestrator | grep -i smtp
```
Many SMTP servers require explicit auth even for internal servers — verify credentials directly against the mail server if the orchestrator log shows an auth failure.

---

*© Audspect — Confidential — Customer Distribution*
