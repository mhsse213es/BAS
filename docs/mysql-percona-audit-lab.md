# Lab MySQL on Percona Server 8.0 with the audit log plugin

Purpose: give the DB-04 MySQL checks a maintained audit plugin. The harness reads the audit
file from the host. The agent never touches the file. No sidecar, no extra database.

## Verified status (2026-11-20, lab host `audspecterver`)

- Image: `percona/percona-server@sha256:a4ba7d1afd325f40bc6d65b6455fb4f15388638dfa39e3b85f9755755fd9ec2d`
  (Percona Server 8.0.46-37). Pinned by digest, not by tag.
- Plugin `audit_log` ACTIVE. Settings: handler FILE, format JSON, policy ALL, strategy SYNCHRONOUS,
  file `/var/log/mysql-audit/audit.log` (host: `~/dbsim-lab-run/audit/audit.log`).
- Verified: a marker-tagged query appears in the audit file (marker count 1).
- Data volume `dbsim-lab_mysql-data` was recreated for this image (see "What went wrong").

## Decisions this runbook follows

- Plugin: the Percona Audit Log plugin (`audit_log.so`), documented for the 8.0 line. Percona marks
  it deprecated in newer lines and recommends the Audit Log Filter component there. Revisit on upgrade.
- Output: JSON in a host-mounted directory. The harness reads it. The agent does not.
- Strategy SYNCHRONOUS, so an event is on disk before the query returns.

## Steps (as run)

Run from `~/dbsim-lab-run/lab/dbsim`. Keep `docker-compose.noaudit.yml` as the rollback point.

### 1. Phase one: start without audit settings so the data directory is created

In the `mysql:` service of `docker-compose.yml`:
- `image: percona/percona-server@sha256:a4ba7d1afd325f40bc6d65b6455fb4f15388638dfa39e3b85f9755755fd9ec2d`
- add to `environment:` `MYSQL_ONETIME_PASSWORD: ""` (the entrypoint runs `set -u` and aborts if unset)
- add the host mount `/home/zain/dbsim-lab-run/audit:/var/log/mysql-audit` to `volumes:`
- no `command:` block yet

Create the audit directory: `mkdir -p ~/dbsim-lab-run/audit`

Volume ownership, before first start (the image runs as UID 1001):
```bash
docker volume create dbsim-lab_mysql-data
docker run --rm -v dbsim-lab_mysql-data:/d alpine chown 1001:1001 /d
docker compose up -d mysql
sleep 90
docker ps --filter name=dbsim-lab-mysql-1 --format '{{.Names}} {{.Status}}'   # expect (healthy)
```

### 2. Phase two: enable the audit plugin

Add to the `mysql:` service, before `hostname:`:
```yaml
    command:
      - --plugin-load-add=audit_log.so
      - --audit_log_handler=FILE
      - --audit_log_format=JSON
      - --audit_log_policy=ALL
      - --audit_log_strategy=SYNCHRONOUS
      - --audit_log_file=/var/log/mysql-audit/audit.log
```
Then `docker compose config --quiet && docker compose up -d mysql` and wait for `(healthy)`.

### 3. Verify the settings on the running image

```bash
docker exec dbsim-lab-mysql-1 sh -c 'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "SHOW VARIABLES LIKE '"'"'audit_log%'"'"'; SHOW PLUGINS LIKE '"'"'audit_log'"'"';"' 2>/dev/null
```

### 4. Verify a marker-tagged query reaches the audit file

The `mysql` client strips `/* */` comments unless `--comments` is given, so the flag is required:
```bash
docker exec dbsim-lab-mysql-1 sh -c 'mysql --comments -uroot -p"$MYSQL_ROOT_PASSWORD" -e "SELECT /* dbsim:audit-verify-002 */ 1;"' >/dev/null 2>&1
grep -c "dbsim:audit-verify-002" ~/dbsim-lab-run/audit/audit.log    # expect 1 or more
```

## Rollback

```bash
cd ~/dbsim-lab-run/lab/dbsim
cp docker-compose.noaudit.yml docker-compose.yml   # audit settings removed, data kept
docker compose up -d mysql
```
Community image rollback: `docker-compose.yml.bak-community` restores `dbsim-lab/mysql-general-log:8.0.40`.
The data volume is not deleted by either rollback.

## What went wrong (for the next person)

- Adding the `audit_log_*` options at first initialization fails: `unknown variable 'audit_log_handler=FILE'`
  while the data directory is created. Start without them, then add them (step 2).
- The Percona image runs as UID 1001. The community volume was UID 999, and a fresh volume is root-owned.
  Both cases give "data directory is unusable" or "binlog.index Permission denied" until chowned.
- The community data volume could not be upgraded in place: `ALTER TABLE general_log` failed during the
  8.0.40 to 8.0.46 upgrade. The volume was recreated; lab MySQL data is synthetic and reseeded.
- Without `MYSQL_ONETIME_PASSWORD: ""` the entrypoint aborts after seeding and the container restarts forever.
- The `mysql` client strips comments; use `--comments` for marker checks.

## Credentials

Do not put MySQL passwords in this file, in the compose file, or in chat. The commands above read the
root password from the container's own environment. Verify the lab MySQL login separately before running
any MySQL DB-04 test.
