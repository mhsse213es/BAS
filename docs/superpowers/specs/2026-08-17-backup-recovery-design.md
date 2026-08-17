# Backup & Recovery — Design Spec

**Date:** 2026-08-17
**Status:** Approved for planning

## Goal

Give Audspect a real disaster-recovery story: if the console gets stuck, corrupted,
or misconfigured, an operator can recover all prior scan/run/report data from a
backup instead of losing it. The backup must cover both Postgres (the actual
source of truth for scans, runs, findings, reports, IOCs, threat intel, users)
and the on-disk `DATA_DIR` state the console depends on to function
(`.env` secrets, license, TLS certs, scenario definitions, `docker-compose.yml`).

## Non-goals

- No support for `art-payloads/`, `sharphound/`, or `intel-bundles/` in v1 — these
  are optional, client-supplied binaries/bundles that are either re-droppable or
  already tracked by the client outside Audspect. Can be added to the archive's
  file list later with zero architecture change.
- No object-storage (S3-compatible) remote target in v1 — only a filesystem/rsync
  path. The remote push is written as a single shell function so a new target
  type is a new branch inside it, not a redesign.
- No automatic/console-triggered restore execution. Restore is always a
  host-side, human-confirmed action (see Restore Flow below).
- No cross-version schema-migration tooling — restore assumes the archive's BAS
  version is compatible with (usually: equal to or one behind) the version being
  restored onto. Manifest records the version so `install.sh --restore` can refuse
  a clearly incompatible combination.

## Architecture

The orchestrator container never touches `pg_dump`, `DATA_DIR`, or `docker`
directly — its trust boundary stays exactly what it is today (Postgres access
only). Backups are requested through Postgres — a channel that already crosses
the console↔host boundary safely — and executed by a host-side systemd timer.

```
                    AUDSPECT CONSOLE (orchestrator container)
                              │  INSERT/SELECT backup_jobs
                              ▼
                          PostgreSQL  ◄────────────┐
                              ▲                    │ pg_dump
                              │ poll every 60s      │
                    Host: audspect-backup-worker.timer
                              │
                ┌─────────────┴──────────────┐
                ▼                             ▼
          pg_dump (docker exec)        tar: .env, bas.lic, certs/,
                                        scenarios/, docker-compose.yml
                │                             │
                └──────────────┬──────────────┘
                               ▼
                      manifest.json + encrypt (openssl aes-256-cbc,
                      key at DATA_DIR/.backup_key, root:root 0600)
                               ▼
                      sha256 + write to DATA_DIR/backups/
                               │
                 ┌─────────────┴─────────────┐
                 ▼ (always)                   ▼ (if REMOTE_BACKUP_ENABLED)
           local archive                push to REMOTE_BACKUP_PATH
                 │                             │
                 └─────────────┬───────────────┘
                               ▼
                update backup_jobs row: protected / local_success /
                remote_failed / failed
```

A second, daily systemd timer (`audspect-backup-schedule.timer`) exists purely
to *decide* a scheduled backup should happen — it inserts one `requested` row
and exits. The worker timer is the only thing that ever *executes* a backup,
so manual (console), scheduled (cron/timer), and CLI-triggered backups all run
through one code path.

## Components

### 1. `backup_jobs` table (Postgres)

Created idempotently at orchestrator startup, same pattern as other tables in
`orchestrator/internal/db/postgres.go` (`CREATE TABLE IF NOT EXISTS`).

```sql
CREATE TABLE IF NOT EXISTS backup_jobs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type         TEXT NOT NULL CHECK (job_type IN ('backup', 'restore_marker')),
    trigger          TEXT NOT NULL CHECK (trigger IN ('console', 'scheduled', 'cli', 'pre_restore')),
    requested_by     TEXT,                    -- user id, null for scheduled/cli
    requested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at       TIMESTAMPTZ,
    finished_at      TIMESTAMPTZ,
    status           TEXT NOT NULL DEFAULT 'requested'
                       CHECK (status IN ('requested','running','protected',
                                          'local_success','remote_failed','failed')),
    archive_filename TEXT,
    archive_size_bytes BIGINT,
    sha256           TEXT,
    local_path       TEXT,
    remote_path      TEXT,
    error_message    TEXT,
    restore_of_id    UUID REFERENCES backup_jobs(id),  -- set only for restore_marker rows
    manifest         JSONB
);
CREATE INDEX IF NOT EXISTS idx_backup_jobs_status ON backup_jobs(status);
CREATE INDEX IF NOT EXISTS idx_backup_jobs_requested_at ON backup_jobs(requested_at DESC);
```

`restore_marker` rows are pure audit trail — a record that an admin flagged a
backup for restore intent from the console. Nothing ever acts on them
automatically.

Note: this row's `manifest` JSONB column is a queryable *summary* (BAS
version, Postgres version, archive contents list) written back by the worker
after a successful backup — separate from the `manifest.json` file the engine
writes *inside* the encrypted archive itself. The console reads the DB copy;
`install.sh --restore` reads the archive copy, since the console's copy isn't
trustworthy input for a destructive host operation.

### 2. Host backup engine (`packaging/compose/install.sh`)

New modes, added alongside the existing `mode_check` / `mode_install` /
`mode_upgrade` / `mode_rollback` / `mode_status` / `mode_uninstall`:

- **`mode_backup`** (`install.sh --backup [--trigger=cli]`) — runs the engine
  synchronously once: pg_dump → tar config → manifest → encrypt → hash → write
  local → optional remote push → prune per retention → done. Used directly by
  a human, and internally by the worker below.
- **`mode_backup_request`** (`install.sh --backup-request --trigger=scheduled`)
  — inserts one `requested` row into `backup_jobs` via
  `docker exec audspect-postgres psql` and exits. Called by the daily timer.
- **`mode_backup_worker`** (`install.sh --backup-worker`) — one poll pass:
  `SELECT ... WHERE status='requested' ORDER BY requested_at LIMIT 1 FOR UPDATE SKIP LOCKED`;
  if a row exists, mark `running`, call the same engine as `mode_backup`, write
  the result back into that row. Called every 60s by the worker timer.
- **`mode_restore`** (`install.sh --restore <archive-id-or-filename>`) —
  described under Restore Flow.

Shared engine internals (private functions, not exposed as their own modes):

- `_run_pg_dump()` — `docker exec audspect-postgres pg_dump -U ${POSTGRES_USER} -Fc ${POSTGRES_DB}` → `postgres/audspect.dump`. Custom format (`-Fc`), so restore uses `pg_restore` against a fresh/empty database rather than replaying a live data directory — safe across minor Postgres point releases within the same major version.
- `_package_config()` — tars `.env`, `bas.lic`, `certs/`, `scenarios/`, `docker-compose.yml` from `DATA_DIR` into `config.tar`.
- `_write_manifest()` — `manifest.json`: BAS version, Postgres version, archive contents list, retention policy snapshot, trigger, timestamp.
- `_encrypt_archive()` — `openssl enc -aes-256-cbc -pbkdf2 -salt -in archive.tar -out archive.tar.enc -pass file:${DATA_DIR}/.backup_key`.
- `_push_remote_backup()` — branches on `REMOTE_BACKUP_TYPE` (`rsync` | `mount`); `mount` just `cp`s into an already-mounted `REMOTE_BACKUP_PATH` (NFS/SMB mounted by the host, out of scope for this script), `rsync` shells out to `rsync` against a remote path/host. New target types (SFTP, S3) are new branches here only.
- `_prune_backups()` — tiered retention: keep every local archive within `BACKUP_RETENTION_DAILY` days, thin to one-per-week for the next `BACKUP_RETENTION_WEEKLY` weeks, one-per-month for `BACKUP_RETENTION_MONTHLY` months, delete anything older. Same policy shape applied to the remote path using `REMOTE_BACKUP_RETENTION` (a flat day count — remote storage is usually cheaper/simpler to reason about as one number).

### 3. Encryption key

Generated once at install time (`mode_install`), alongside the existing
auto-generated `JWT_SECRET`/`POSTGRES_PASSWORD`:

```bash
openssl rand -base64 48 > "${DATA_DIR}/.backup_key"
chmod 600 "${DATA_DIR}/.backup_key"
chown root:root "${DATA_DIR}/.backup_key"
```

Never read by, transmitted to, or stored in the orchestrator app or Postgres.
Losing this file means existing backup archives become unrecoverable — `install.sh --status`
gets a line reminding the operator this file (and the DB password) are the two
secrets that must be preserved outside the host for the backups to be worth anything.

### 4. Config (`setup.conf` / `DATA_DIR/.env`)

```
BACKUP_RETENTION_DAILY=7
BACKUP_RETENTION_WEEKLY=4
BACKUP_RETENTION_MONTHLY=3
BACKUP_SCHEDULE_TIME=02:00        # OnCalendar for the daily schedule timer

REMOTE_BACKUP_ENABLED=false
REMOTE_BACKUP_TYPE=                # rsync | mount
REMOTE_BACKUP_PATH=
REMOTE_BACKUP_RETENTION=30
```

All configurable at install/upgrade time via `setup.conf`, never hardcoded and
never exposed as editable fields in the console (matches the user's explicit
"configurable at the ops layer, not the application" requirement).

### 5. systemd units

Two new units, written by `install.sh` the same way `_write_systemd_unit`
already writes the main `audspect.service`:

- `audspect-backup-worker.service` (oneshot, `ExecStart=install.sh --backup-worker`) + `audspect-backup-worker.timer` (`OnUnitActiveSec=60s`)
- `audspect-backup-schedule.service` (oneshot, `ExecStart=install.sh --backup-request --trigger=scheduled`) + `audspect-backup-schedule.timer` (`OnCalendar=*-*-* ${BACKUP_SCHEDULE_TIME}:00`)

### 6. Backend API (Go)

New `orchestrator/internal/api/backup_handlers.go`, new permission
`auth.CanManageBackups` (RoleAdmin only, same tier as `CanUpdateConnectorConfig`).

- `POST /api/backups` — inserts a `backup_jobs` row (`job_type='backup', trigger='console', requested_by=<user id>`). Returns the job id. Does not touch the filesystem, `pg_dump`, or Docker — a plain `INSERT` through the existing DB pool.
- `GET /api/backups` — lists recent `backup_jobs` (`job_type='backup'`) rows, most recent first, for the console table.
- `GET /api/backups/{id}` — single job, for polling status after "Backup Now."
- `POST /api/backups/{id}/restore-marker` — RoleAdmin only. Inserts a `restore_marker` row referencing the backup. Returns the exact CLI command (`sudo bash install.sh --restore <archive_filename>`) for the console to display. Performs no restore action.

Routes wired in `routes.go` under the existing permission-tier pattern (mirrors
the `/api/vex/sweeps` block).

### 7. Frontend

New Settings sub-section, following the exact existing pattern
(`showSettingsSection('users')` etc. in `wwwroot/index.html`):

```html
<a class="sset" data-set="backup" onclick="showSettingsSection('backup')">Backup &amp; Recovery</a>
```

Renders:
- **Status card** — last successful backup: timestamp, size, type (manual/scheduled), Local ✓/✗, Remote ✓/✗, an overall pill (`Protected` / `Local only` / `Remote failed` / `Failed`). "Backup Now" button → `POST /api/backups`, then polls `GET /api/backups/{id}` every few seconds until a terminal status, updating the pill live.
- **Available backups table** — recent `backup_jobs`, same columns as the mockup the user specified (date, Local, Remote, Status).
- **Restore panel** — per-backup "Prepare Restore" action → `POST /api/backups/{id}/restore-marker`, then displays the returned CLI command in a copy-able code block with explicit copy: *"Restore must be performed by an administrator with host access. This console cannot and will not run it for you."* No button anywhere in the console executes a restore.

## Restore Flow (host-only)

`sudo bash install.sh --restore <archive-id-or-filename>`, interactive, requires
typing the literal word `RESTORE` to proceed (mirrors this codebase's existing
destructive-op confirmation pattern):

1. Verify archive integrity (sha256) and read `manifest.json`; refuse if the
   BAS/Postgres version recorded is incompatible with what's currently installed.
2. Run `mode_backup` once more first, tagged `trigger='pre_restore'` — snapshot
   current state before touching anything, so a bad restore is itself
   recoverable.
3. Stop services (`docker compose stop orchestrator caldera chrome` — Postgres
   stays up for `pg_restore`).
4. Decrypt archive, `pg_restore --clean --if-exists` into `bas_platform`,
   restore `config.tar` contents into `DATA_DIR`.
5. Start Postgres-dependent health check, then bring the rest of the stack
   back up.
6. Run the existing `/health` check (same endpoint `docker-compose.yml`'s
   healthcheck already polls).
7. Report pass/fail with a clear summary; on failure, tell the operator the
   `pre_restore` snapshot exists and how to re-restore it.

## Security considerations

- Archive contains `.env` (DB password, JWT secret, agent secret), TLS private
  key, and scan/report data — encryption at rest is mandatory, not optional,
  which is why `_encrypt_archive()` is unconditional in the engine, not a config flag.
- `.backup_key` and `.env` live at 0600/root:root, matching existing file
  permission conventions already used for `certs/bas.key` in `install.sh`.
- The orchestrator's permission set gains exactly one new admin-only
  capability (`CanManageBackups`) and zero new filesystem/process access —
  the container's trust boundary is unchanged.
- Restore requires simultaneous host root access *and* the typed confirmation
  word — a compromised web session alone can never trigger a restore.

## Testing strategy

- Go: unit tests for the `backup_jobs` INSERT/SELECT handlers (mirrors the
  session's existing `campaign_crud_test.go`/`variant_handlers_test.go`
  `authedRequest`/`callAuthed` pattern) — request creates a `requested` row
  with the right `trigger`/`requested_by`; list/get return expected shape;
  RBAC matrix (`rbac_matrix_test.go`) gets entries for all 4 new routes.
- Bash: the engine functions (`_run_pg_dump`, `_package_config`,
  `_encrypt_archive`, `_prune_backups`) are each independently testable against
  a throwaway `DATA_DIR` + a disposable Postgres container — no need for the
  full stack per test.
- End-to-end (manual, documented in the plan, not automated in CI): run
  `--install` on a scratch VM, generate some scan data, `--backup`, wipe the
  VM, `--install` fresh, `--restore`, confirm the scan data is back.

## Open items deferred past v1

- Remote target types beyond `rsync`/mounted filesystem (SFTP, S3-compatible).
- `art-payloads/`/`sharphound/`/`intel-bundles/` inclusion in the archive.
- Any UI editing of retention/remote config (stays ops-layer only for now).
