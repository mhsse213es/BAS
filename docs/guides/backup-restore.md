# Audspect BAS — Backup and Restore Guide

**Platform Version:** v1.7.5

---

## Two Layers of Backup

`install.sh --upgrade` already takes an automatic, timestamped backup of `docker-compose.yml`/`.env`/version marker before every upgrade (under `<DATA_DIR>/backups/`), and `install.sh --rollback` restores it in one command — see the [Upgrade Guide](upgrade-guide.md). **That covers configuration, not database contents.** This guide covers the database backup, which is a separate, deliberate step you own on a schedule — it is not automatic.

## What Needs to Be Backed Up

| Data | Location | Priority |
|---|---|---|
| PostgreSQL database | Docker volume `audspect-postgres-data` | Critical |
| Environment config | `<DATA_DIR>/.env` (default `/opt/audspect/.env`) — also auto-backed-up by every `install.sh --upgrade` | Critical |
| License file | `<DATA_DIR>/bas.lic` | Critical |
| Custom scenarios | Created via the dashboard, stored in the database — covered by the database backup, not a separate file backup | High |
| Generated reports | Rendered on-demand from HTML at request time — nothing to back up | N/A |

**What does NOT need a separate backup:**
- Docker images (re-load from delivery ZIP)
- Built-in scenario YAML (bundled in image)
- ATT&CK STIX data, KEV catalog (bundled in image)

---

## Database Backup

### Manual backup

```bash
# One-line backup — creates a timestamped SQL dump
BACKUP_DIR="/opt/backups"
BACKUP_FILE="${BACKUP_DIR}/bas-$(date +%Y%m%d-%H%M%S).sql.gz"
mkdir -p "$BACKUP_DIR"
docker compose exec postgres pg_dump -U bas_user bas_platform | gzip > "$BACKUP_FILE"
echo "Backup: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"
```

### Scheduled backup with cron

```bash
sudo crontab -e
```

Add (runs at 02:00 daily, keeps 30 days of backups):
```cron
0 2 * * * cd /opt/audspect && docker compose exec -T postgres pg_dump -U bas_user bas_platform | gzip > /opt/backups/bas-$(date +\%Y\%m\%d).sql.gz
0 3 * * * find /opt/backups -name "bas-*.sql.gz" -mtime +30 -delete
```

### Backup verification

Always verify backups can be read:
```bash
# List tables in backup without restoring
zcat /opt/backups/bas-YYYYMMDD.sql.gz | grep "^CREATE TABLE" | head -20
```

---

## Configuration Backup

```bash
cp /opt/audspect/.env /opt/backups/bas-env-$(date +%Y%m%d).bak
cp /opt/audspect/bas.lic /opt/backups/bas-license.lic
```

Store configuration backups in an encrypted location (vault, encrypted USB, or secrets manager). The `.env` file contains JWT and agent secrets — treat it as a credential. Note that `install.sh --upgrade` already does this automatically for every upgrade (under `<DATA_DIR>/backups/`) — this manual step is for backing up on a schedule independent of upgrades, or before non-upgrade maintenance.

---

## Restore Procedure

### 1. Stop the orchestrator

```bash
cd /opt/audspect
docker compose stop orchestrator
```

Leave PostgreSQL running for the restore.

### 2. Drop and recreate the database

```bash
docker compose exec postgres psql -U bas_user -c "DROP DATABASE IF EXISTS bas_platform;"
docker compose exec postgres psql -U bas_user -c "CREATE DATABASE bas_platform OWNER bas_user;"
```

### 3. Restore from backup

```bash
zcat /opt/backups/bas-YYYYMMDD.sql.gz | \
  docker compose exec -T postgres psql -U bas_user -d bas_platform
```

### 4. Restart the orchestrator

```bash
docker compose up -d orchestrator
```

The orchestrator applies its full idempotent schema on every startup (`CREATE TABLE IF NOT EXISTS` / `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, not numbered migrations). If the backup was taken from an older version, this brings the schema forward safely — schema changes are additive, never destructive.

### 5. Verify restore

```bash
# Check table counts
docker compose exec postgres psql -U bas_user -d bas_platform \
  -c "SELECT schemaname, tablename, n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC LIMIT 10;"

# Check dashboard loads
curl -sf http://localhost:9443/health
```

---

## Disaster Recovery Scenarios

### Scenario A — Server OS failure, database intact (volume survived)

1. Provision a new Ubuntu (or Rocky/RHEL) server
2. Transfer the delivery ZIP, extract, run `install.sh --install --config setup.conf` with the **same `DATA_DIR`** and (if you have it) the original `setup.conf` — see the [Upgrade Guide](upgrade-guide.md)'s note on why `install.sh` should always be used instead of hand-copying `.env`, even in a DR scenario
3. As long as the `audspect-postgres-data` volume survived on this host, Postgres picks it up automatically — no manual mount/restore step needed

If the Docker volume is readable but on a different machine:
```bash
# On old/backup machine: export volume
docker run --rm -v audspect-postgres-data:/data -v /opt/backups:/backup \
  alpine tar czf /backup/audspect-postgres-data_$(date +%Y%m%d).tar.gz -C /data .

# On new machine: import volume
docker volume create audspect-postgres-data
docker run --rm -v audspect-postgres-data:/data -v /opt/backups:/backup \
  alpine tar xzf /backup/audspect-postgres-data_YYYYMMDD.tar.gz -C /data
```

Import the volume onto the new machine **before** running `install.sh --install` (so Postgres finds existing data on its first start instead of initializing empty), then run `install.sh --install --config setup.conf`.

### Scenario B — Full server loss, using SQL dump backup

1. Provision a new server, transfer the delivery ZIP, extract
2. Run `install.sh --install --config setup.conf --yes` — this creates a fresh, empty database
3. Stop the orchestrator so it isn't writing during restore: `sudo systemctl stop audspect 2>/dev/null || (cd /opt/audspect && docker compose stop orchestrator)`
4. Follow the [Restore Procedure](#restore-procedure) above to load the SQL dump over the fresh schema
5. Restart: `sudo systemctl start audspect 2>/dev/null || (cd /opt/audspect && docker compose up -d)`

### Scenario C — Accidental data deletion (partial loss)

If specific records were deleted (agents, runs, findings) and you need to recover them without a full restore, use a temporary recovery instance:

```bash
# Start a recovery postgres on a different port
docker run -d --name bas-recovery \
  -e POSTGRES_USER=bas_user -e POSTGRES_PASSWORD=recovery-temp -e POSTGRES_DB=bas_platform \
  -p 5433:5432 postgres:16

# Restore backup into recovery instance
zcat /opt/backups/bas-YYYYMMDD.sql.gz | \
  docker exec -i bas-recovery psql -U bas_user -d bas_platform

# Extract specific rows and insert into production
docker exec bas-recovery psql -U bas_user -d bas_platform \
  -c "COPY (SELECT * FROM findings WHERE id IN (...)) TO STDOUT" | \
  docker compose exec -T postgres psql -U bas_user -d bas_platform -c "COPY findings FROM STDIN"
```

---

## Backup Checklist

Run this checklist before any upgrade or maintenance window:

```bash
# Backup database
docker compose exec -T postgres pg_dump -U bas_user bas_platform | \
  gzip > /opt/backups/bas-pre-maint-$(date +%Y%m%d-%H%M%S).sql.gz

# Backup config
cp /opt/audspect/.env /opt/backups/

# Verify backup
ls -lh /opt/backups/bas-pre-maint-*.sql.gz | tail -1

echo "Backup complete. Proceed with maintenance."
```

---

*© Audspect — Confidential — Customer Distribution*
