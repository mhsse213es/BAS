# Audspect BAS — Upgrade Guide

**Platform Version:** v1.7.3

---

## Overview

Audspect BAS upgrades are delivered as a new versioned delivery ZIP. The upgrade process replaces the Docker images and restarts services. Database migrations run automatically on orchestrator startup.

**Upgrade path supported:**
- v1.6.x → v1.7.3 (supported, data preserved)
- v1.7.x → v1.7.3 (supported, data preserved)
- Versions below v1.6.0: contact Audspect support before upgrading

---

## Before You Upgrade

- [ ] Take a full database backup (see step 1 below)
- [ ] Note the current version: `docker inspect audspect-orchestrator:latest | grep -i version`
- [ ] Read the [Release Notes](release-notes.md) for v1.7.3 — specifically the **Breaking Changes** and **Migration Notes** sections
- [ ] Confirm you have the new delivery ZIP: `audspect-bas-v1.7.3.zip`
- [ ] Schedule during a low-activity window — the orchestrator is offline for approximately 2–3 minutes during image swap
- [ ] Agents will reconnect automatically after the orchestrator restarts

---

## Step 1 — Back Up the Database

```bash
# Run from the current deployment directory
BACKUP_FILE="/opt/backups/bas-pre-upgrade-$(date +%Y%m%d-%H%M%S).sql"
mkdir -p /opt/backups
docker compose exec postgres pg_dump -U bas bas > "$BACKUP_FILE"
gzip "$BACKUP_FILE"
echo "Backup saved: ${BACKUP_FILE}.gz"
```

Verify the backup is non-empty:
```bash
ls -lh "${BACKUP_FILE}.gz"
```

---

## Step 2 — Extract the New Package

```bash
cd /opt
sudo unzip audspect-bas-v1.7.3.zip
cd audspect-bas-v1.7.3
```

---

## Step 3 — Copy Your Existing Configuration

Your current `.env` file contains all secrets and configuration. Copy it to the new directory:

```bash
cp /opt/audspect-bas-<previous-version>/.env /opt/audspect-bas-v1.7.3/.env
```

Review the new `config.template.env` for any new variables introduced in v1.7.3. Add new required variables to your `.env` if needed. Release notes list all new environment variables.

---

## Step 4 — Load the New Docker Images

```bash
cd /opt/audspect-bas-v1.7.3/images
for f in *.tar; do sudo docker load < "$f"; echo "Loaded $f"; done
```

---

## Step 5 — Stop the Current Deployment

```bash
cd /opt/audspect-bas-<previous-version>
docker compose down
```

Agents will begin accumulating heartbeat retries while the server is offline. They will reconnect automatically when the new orchestrator starts.

---

## Step 6 — Start the New Deployment

```bash
cd /opt/audspect-bas-v1.7.3
docker compose up -d
```

The orchestrator:
1. Runs database migrations automatically
2. Seeds any new built-in scenario content
3. Starts serving on port 9000

Wait for the health check to pass:
```bash
until curl -sf http://localhost:9000/health > /dev/null; do
  echo "Waiting for orchestrator..."
  sleep 5
done
echo "Orchestrator healthy"
```

---

## Step 7 — Verify the Upgrade

```bash
# Check version
curl -s http://localhost:9000/health | python3 -m json.tool

# Check logs for errors
docker compose logs orchestrator --tail=50

# Check agents reconnecting
# (watch the Agents page in the dashboard — agents should return to Active within 60s)
```

Expected health response:
```json
{"status": "ok", "db": "ok", "version": "1.7.3"}
```

---

## Step 8 — Update systemd (if configured)

If you installed the systemd service pointing to the old directory, update it:

```bash
sudo sed -i 's|audspect-bas-v1\.[0-9.]*|audspect-bas-v1.7.3|g' \
  /etc/systemd/system/audspect.service
sudo systemctl daemon-reload
sudo systemctl enable audspect
```

---

## Step 9 — Update Agent Binaries (if required)

Check the release notes for whether the agent binary has changed. If a new agent binary is included in the delivery ZIP:

1. Download the new binary from the dashboard: **Agents → Download Agent**
2. Deploy to each endpoint using your standard deployment method
3. The old agent continues to function but may lack new collection capabilities

Agent binary trust verification will flag outdated binaries in the dashboard if the `BINARIES.sha256` manifest has changed.

---

## Post-Upgrade Cleanup

After confirming the new deployment is healthy, clean up old images to reclaim disk space:

```bash
docker image prune -f
```

Keep the old deployment directory for at least 48 hours in case rollback is needed. You can remove it after the window:

```bash
rm -rf /opt/audspect-bas-<previous-version>
```

---

## Rollback Procedure

If the upgrade causes critical issues:

```bash
# Stop new deployment
cd /opt/audspect-bas-v1.7.3
docker compose down

# Restore previous version
cd /opt/audspect-bas-<previous-version>
docker compose up -d
```

If schema migrations introduced structural changes that the old binary cannot read, restore from the pre-upgrade database backup:

```bash
# Stop orchestrator before restore
docker compose down

# Restore database (destructive — all data after the backup is lost)
docker compose up -d postgres
gunzip < /opt/backups/bas-pre-upgrade-<timestamp>.sql.gz | \
  docker compose exec -T postgres psql -U bas -d bas

# Restart on previous version
cd /opt/audspect-bas-<previous-version>
docker compose up -d
```

---

## Upgrading Agents

| Scenario | Action Required |
|---|---|
| Agent version matches server version | No action needed |
| Older agent, no new agent capabilities needed | Agents continue working; no upgrade required |
| New agent binary released | Download from dashboard, deploy via your standard method |
| `BINARIES.sha256` manifest updated | Dashboard shows binary trust warning on outdated agents |

---

*© Audspect — Confidential — Customer Distribution*
