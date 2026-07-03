# Audspect BAS — Disaster Recovery Guide

**Classification:** Internal — Audspect Engineering / Confidential  
**Platform Version:** v1.7.3

---

## Recovery Time and Point Objectives

| Objective | Target |
|---|---|
| **RTO** (Recovery Time Objective) | < 2 hours for full platform restoration |
| **RPO** (Recovery Point Objective) | < 24 hours with daily backup; < 1 hour with hourly backup |

---

## Disaster Scenarios and Procedures

### Scenario 1: Orchestrator container crash (no data loss)

**Symptoms:** Dashboard unreachable; `docker compose ps` shows orchestrator in Exit state.

**Impact:** Agents queue heartbeats locally; no runs dispatch; no result submission.

**Recovery:**
```bash
docker compose logs orchestrator --tail=30   # Diagnose cause
docker compose restart orchestrator          # Attempt restart
docker compose up -d orchestrator            # If restart fails
```

Expected recovery time: **<5 minutes**. Agents reconnect automatically.

---

### Scenario 2: PostgreSQL container crash (no data loss — volume intact)

**Symptoms:** Orchestrator logs show database connection errors; `/health` returns `{"db":"unavailable"}`.

**Impact:** No data loss. All data in Docker volume `bas_pgdata`.

**Recovery:**
```bash
docker compose restart postgres
# Wait for postgres to start
docker compose restart orchestrator   # Reconnect orchestrator
curl http://localhost:9000/health     # Verify
```

Expected recovery time: **<5 minutes**.

---

### Scenario 3: Full server failure (OS/hardware failure, Docker volumes intact)

**Symptoms:** Server completely unreachable.

**If volumes survived (same hardware with OS reinstall):**

1. Reinstall Ubuntu and Docker
2. Transfer delivery ZIP and extract
3. Import Docker images
4. Restore `.env` from backup
5. Start Compose — PostgreSQL will use the existing volume

```bash
sudo unzip audspect-bas-v1.7.3.zip && cd audspect-bas-v1.7.3
for f in images/*.tar; do docker load < "$f"; done
cp /backup/.env .env                # Restore config
docker compose up -d
curl http://localhost:9000/health
```

Expected recovery time: **30–60 minutes**.

---

### Scenario 4: Full server failure with volume loss (bare metal failure)

**Symptoms:** Server physically dead; storage unrecoverable.

**Recovery from SQL backup:**

1. Provision new Ubuntu server
2. Install Docker + Compose
3. Transfer delivery ZIP and extract
4. Import Docker images
5. Copy `.env` from off-site backup
6. Start PostgreSQL only, restore database from backup

```bash
# Step 1-4 same as Scenario 3

# Start only postgres
docker compose up -d postgres

# Wait for postgres to be ready
until docker compose exec postgres pg_isready -U bas > /dev/null 2>&1; do
  sleep 2; done

# Restore from backup
zcat /backup/bas-YYYYMMDD.sql.gz | \
  docker compose exec -T postgres psql -U bas -d bas

# Start remaining services
docker compose up -d
curl http://localhost:9000/health
```

Expected recovery time: **1–2 hours** (including data restore).

---

### Scenario 5: Accidental data deletion

**Affected data:** Scenario runs, findings, agents, users — accidentally deleted via API or direct SQL.

**Recovery options:**

**Option A: Full restore (loses all data after backup):**
1. Stop orchestrator
2. Drop and recreate database
3. Restore from backup
4. Restart orchestrator

**Option B: Surgical recovery (preserve recent data):**
1. Spin up a temporary recovery PostgreSQL instance on port 5433
2. Restore backup into recovery instance
3. Export only the deleted rows using `COPY ... TO STDOUT`
4. Insert into production

```bash
# Spin up recovery instance
docker run -d --name bas-recovery -p 5433:5432 \
  -e POSTGRES_USER=bas -e POSTGRES_PASSWORD=basdev -e POSTGRES_DB=bas \
  postgres:16

# Wait for it
sleep 10

# Restore backup into recovery instance
zcat /backup/bas-YYYYMMDD.sql.gz | \
  docker exec -i bas-recovery psql -U bas -d bas

# Extract deleted finding rows
docker exec bas-recovery psql -U bas -d bas \
  -c "\COPY (SELECT * FROM findings WHERE id IN ('find-abc','find-xyz')) TO '/tmp/findings.csv' CSV HEADER"

# (Transfer CSV from recovery container, insert into production via COPY FROM STDIN)

# Cleanup
docker stop bas-recovery && docker rm bas-recovery
```

---

### Scenario 6: Signing key lost

**Symptoms:** Build pipeline fails: GPG key not found; cannot sign scenarios.

**Impact:** Cannot release new signed scenarios or rebuild agent trust manifests. Existing signed scenarios continue to work.

**Recovery:**

If backup exists:
```powershell
gpg --import audspect-signing-key-private.asc
```

If no backup: the key is unrecoverable. Generate a new key, update `signing_key.go`, rebuild the orchestrator, re-sign all scenarios. This requires a platform release. See [Signing Infrastructure](signing-infrastructure.md).

**Prevention:** Always maintain off-site backup of the private key. See [Signing Infrastructure](signing-infrastructure.md) → Backing Up the Signing Key.

---

### Scenario 7: License file lost

**Symptoms:** Platform starts with warning about missing license; new scenario dispatches blocked.

**Recovery:** Contact Audspect support with the Customer ID. License files can be re-issued. The Customer ID is in the license file header — if you have a backup, extract it:

```bash
head -5 audspect.lic
```

If no backup of the license: contact support with your organization name and original purchase details.

---

## Recovery Priority Matrix

| Component | Priority | RTO |
|---|---|---|
| PostgreSQL container restart | P1 (immediate) | 5 min |
| Orchestrator container restart | P1 (immediate) | 5 min |
| Full server restore (volume intact) | P2 | 60 min |
| Full restore from SQL backup | P2 | 2 hours |
| Signing key recovery from backup | P3 | 30 min |
| New signing key generation + release | P3 | 1–2 days |
| License re-issue | P3 | 4–24 hours (support ticket) |

---

## Runbook Contact List

| Situation | Contact |
|---|---|
| License re-issue needed | support@audspect.com |
| Database corruption suspected | engineering@audspect.com |
| Signing key compromise | security@audspect.com (treat as incident) |
| Physical hardware failure | customer's IT operations team |

---

*© Audspect Engineering — Internal / Confidential*
