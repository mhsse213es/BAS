# Release notes — Versioned database migrations (H1)

## What changes for operators

- **Upgrade with `install.sh --upgrade` — it is now mandatory.** The
  orchestrator no longer creates or alters database tables when it starts.
  Restarting a container on a new image does not upgrade the database; the
  orchestrator will refuse to start and tell you to run
  `sudo bash install.sh --upgrade --config setup.conf`.
- **First upgrade to this release adopts your existing database.** `--upgrade`
  runs `orchestrator migrate up` once. It brings the existing schema to the
  release baseline, compares it object by object, and records it as
  version-managed. If anything does not match, it stops **without changing
  the database** and lists the objects; the previous release can be restored
  with the printed `--rollback` command. Tables or columns that exist in your
  database but not in the baseline are kept and listed in the output (and in
  the `h1_adoption_report` table).
- **Every upgrade takes an encrypted database snapshot** before migrating:
  `<DATA_DIR>/backups/upgrade-<time>-<from>-to-<to>/db.dump.enc`, encrypted
  with `<DATA_DIR>/.backup_key`. `--upgrade` checks for free space for about
  two copies of the database first. Keep `.backup_key` safe.
- **`install.sh --rollback` restores that upgrade's snapshot** together with
  the previous configuration and version (`--upgrade-id <dir>` selects a
  specific upgrade). **Database changes made after the upgrade began are
  lost**; the command shows the time and asks you to type the version being
  restored. It never uses a scheduled backup and refuses a snapshot whose
  checksum does not match.
- **New: `install.sh --rotate-db-app-password`** generates a new password for
  the orchestrator's database account (`bas_app`), applies and verifies it,
  and restarts the orchestrator. The password is no longer re-applied on every
  start-up; if `.env` and the database disagree, `migrate` stops with this
  command as the fix.
- **If the orchestrator refuses to start** with a schema message:
  - "older than this release" / "no migration record" → run `install.sh --upgrade`;
  - "newer than this release" → run the matching release, or `install.sh --rollback`;
  - "dirty" (a migration failed part-way) → `install.sh --rollback`.
- The orchestrator container no longer receives the database owner
  credentials (`DATABASE_ADMIN_URL`); only the one-off migrate step does.

## Notes

- A seeded payload family that was deleted on a pre-H1 install reappears once
  at the first H1 upgrade (pre-H1 releases re-inserted it on every start, so
  such deletions were never permanent). Delete it again after upgrading; from
  this release on, deletions are permanent.
- `setup.sh` / the air-gap `import.sh` path is not covered by this change; use
  `install.sh`.
