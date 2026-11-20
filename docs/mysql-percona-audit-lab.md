# Lab MySQL on Percona Server 8.0 with the audit log plugin

Purpose: give the DB-04 MySQL checks a maintained audit plugin. The harness reads the audit
file from the host. The agent never touches the file. No sidecar, no extra database.

## Decisions this runbook follows

- Image: Percona Server 8.0, pinned to one exact tag (see step 1). Not `latest`, not `8.0`.
- Plugin: the Percona Audit Log plugin (`audit_log.so`), the one documented for the 8.0 line.
  Percona notes the plugin is deprecated in newer lines and recommends the Audit Log Filter
  component there. Revisit when this image is upgraded.
- Output: JSON, written to a host-mounted directory. The harness reads that directory.
- Strategy: SYNCHRONOUS, so an event is on disk before the query returns. The verification
  step below relies on this.

## 1. Pick and pin the image

Choose one exact 8.0 patch tag from https://hub.docker.com/r/percona/percona-server/tags
and record it here: `percona/percona-server:<PINNED_TAG>`.

## 2. Compose changes (on staging, in the lab directory)

Replace the community image for the mysql service and add the plugin settings and the host
mount. Keep the existing data volume unchanged.

```yaml
  mysql:
    image: percona/percona-server:<PINNED_TAG>
    command:
      - --plugin-load-add=audit_log.so
      - --audit_log_handler=FILE
      - --audit_log_format=JSON
      - --audit_log_policy=ALL
      - --audit_log_strategy=SYNCHRONOUS
      - --audit_log_file=/var/log/mysql-audit/audit.log
    volumes:
      - <existing data volume>:/var/lib/mysql
      - /home/zain/dbsim-lab-run/audit:/var/log/mysql-audit
```

Create the host directory first, owned so the database can write and the harness can read:

```bash
mkdir -p /home/zain/dbsim-lab-run/audit
```

## 3. Start and validate the settings against the running image

```bash
docker compose up -d mysql
docker exec dbsim-lab-mysql-1 mysql -uroot -e "SHOW VARIABLES LIKE 'audit_log%'; SHOW PLUGINS LIKE 'audit_log';"
```

Expected: `audit_log_handler=FILE`, `audit_log_format=JSON`, `audit_log_policy=ALL`,
`audit_log_strategy=SYNCHRONOUS`, `audit_log_file=/var/log/mysql-audit/audit.log`, and the
plugin status `ACTIVE`. If a variable name differs on the image, use the name the image
reports and tell me, so the runbook can be corrected.

## 4. Verify a marker-tagged query reaches the audit file

```bash
docker exec dbsim-lab-mysql-1 mysql -uroot -e "SELECT /* dbsim:audit-verify-001 */ 1;"
grep -c "dbsim:audit-verify-001" /home/zain/dbsim-lab-run/audit/audit.log
```

Expected: the count is at least 1. Check the file is readable from the host without sudo:
`ls -l /home/zain/dbsim-lab-run/audit/`. If it isn't readable, adjust permissions on that
host directory only.

## 5. Rollback

```bash
# restore the community image and remove the audit settings and mount
docker compose up -d mysql     # after editing the compose file back to the original image
```

The original image is `dbsim-lab/mysql-general-log:8.0.40`. The data volume is not touched by
either direction, so rollback does not lose lab data.

## Credentials

Do not put MySQL passwords in this file, in the compose file, or in chat. Verify the lab
MySQL login separately before running any MySQL DB-04 test.

## Status

Not yet applied on staging. The steps above are unverified until run on the lab.
