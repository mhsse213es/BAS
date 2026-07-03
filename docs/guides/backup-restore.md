# Audspect BAS — Backup and Restore Guide

**Platform Version:** v1.7.3

---

## What Needs to Be Backed Up

| Data | Location | Priority |
|---|---|---|
| PostgreSQL database | Docker volume `bas_pgdata` | Critical |
| Environment config | `/opt/audspect-bas-*/. env` | Critical |
| License file | Wherever `BAS_LICENSE_PATH` points | Critical |
| Custom scenarios | Wherever `SCENARIOS_DIR` points | High |
| ART payload binaries | `BAS_PAYLOAD_DIR` (if operator-supplied) | High |
| Generated reports | Stored in PostgreSQL (HTML/PDF are regenerated on demand) | Included in DB backup |

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
docker compose exec postgres pg_dump -U bas bas | gzip > "$BACKUP_FILE"
echo "Backup: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"
```

### Scheduled backup with cron

```bash
sudo crontab -e
```

Add (runs at 02:00 daily, keeps 30 days of backups):
```cron
0 2 * * * cd /opt/audspect-bas-v1.7.3 && docker compose exec -T postgres pg_dump -U bas bas | gzip > /opt/backups/bas-$(date +\%Y\%m\%d).sql.gz
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
cp /opt/audspect-bas-v1.7.3/.env /opt/backups/bas-env-$(date +%Y%m%d).bak
cp "$BAS_LICENSE_PATH" /opt/backups/bas-license.lic
```

Store configuration backups in an encrypted location (vault, encrypted USB, or secrets manager). The `.env` file contains JWT and agent secrets — treat it as a credential.

---

## Restore Procedure

### 1. Stop the orchestrator

```bash
cd /opt/audspect-bas-v1.7.3
docker compose stop orchestrator
```

Leave PostgreSQL running for the restore.

### 2. Drop and recreate the database

```bash
docker compose exec postgres psql -U bas -c "DROP DATABASE IF EXISTS bas;"
docker compose exec postgres psql -U bas -c "CREATE DATABASE bas OWNER bas;"
```

### 3. Restore from backup

```bash
zcat /opt/backups/bas-YYYYMMDD.sql.gz | \
  docker compose exec -T postgres psql -U bas -d bas
```

### 4. Restart the orchestrator

```bash
docker compose up -d orchestrator
```

The orchestrator runs schema migrations on startup. If the backup was taken from a previous version, the migrations will bring the schema forward.

### 5. Verify restore

```bash
# Check table counts
docker compose exec postgres psql -U bas -d bas \
  -c "SELECT schemaname, tablename, n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC LIMIT 10;"

# Check dashboard loads
curl -sf http://localhost:9000/health
```

---

## Disaster Recovery Scenarios

### Scenario A — Server OS failure, database intact (volume survived)

1. Provision a new Ubuntu server
2. Install Docker and Docker Compose
3. Transfer delivery ZIP and extract
4. Restore `.env` and license file from backup
5. Import Docker images from delivery ZIP
6. Mount or copy the `bas_pgdata` volume to the new server

If the Docker volume is readable but on a different machine:
```bash
# On old/backup machine: export volume
docker run --rm -v bas_pgdata:/data -v /opt/backups:/backup \
  alpine tar czf /backup/bas_pgdata_$(date +%Y%m%d).tar.gz -C /data .

# On new machine: import volume
docker volume create bas_pgdata
docker run --rm -v bas_pgdata:/data -v /opt/backups:/backup \
  alpine tar xzf /backup/bas_pgdata_YYYYMMDD.tar.gz -C /data
```

Then start the deployment on the new server.

### Scenario B — Full server loss, using SQL dump backup

1. Provision a new Ubuntu server
2. Install Docker and Docker Compose
3. Transfer delivery ZIP and extract
4. Restore `.env` and license file from backup
5. Import Docker images
6. Start PostgreSQL only: `docker compose up -d postgres`
7. Follow the [Restore Procedure](#restore-procedure) above
8. Start all services: `docker compose up -d`

### Scenario C — Accidental data deletion (partial loss)

If specific records were deleted (agents, runs, findings) and you need to recover them without a full restore, use a temporary recovery instance:

```bash
# Start a recovery postgres on a different port
docker run -d --name bas-recovery \
  -e POSTGRES_USER=bas -e POSTGRES_PASSWORD=bas -e POSTGRES_DB=bas \
  -p 5433:5432 postgres:16

# Restore backup into recovery instance
zcat /opt/backups/bas-YYYYMMDD.sql.gz | \
  docker exec -i bas-recovery psql -U bas -d bas

# Extract specific rows and insert into production
docker exec bas-recovery psql -U bas -d bas \
  -c "COPY (SELECT * FROM findings WHERE id IN (...)) TO STDOUT" | \
  docker compose exec -T postgres psql -U bas -d bas -c "COPY findings FROM STDIN"
```

---

## Backup Checklist

Run this checklist before any upgrade or maintenance window:

```bash
# Backup database
docker compose exec -T postgres pg_dump -U bas bas | \
  gzip > /opt/backups/bas-pre-maint-$(date +%Y%m%d-%H%M%S).sql.gz

# Backup config
cp /opt/audspect-bas-v1.7.3/.env /opt/backups/

# Verify backup
ls -lh /opt/backups/bas-pre-maint-*.sql.gz | tail -1

echo "Backup complete. Proceed with maintenance."
```

---

*© Audspect — Confidential — Customer Distribution*
