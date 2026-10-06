# Database migrations (H1)

The schema is changed only by `orchestrator migrate up`, which `install.sh`
runs on `--install` and `--upgrade`. The server never runs DDL: at start-up it
checks that the database is at this release's schema and reference-data
versions (`migrate.CheckRuntime`) and refuses to start otherwise.

Design: `docs/superpowers/specs/2026-10-06-h1-versioned-migrations-design.md`.

## Rules

1. **Every schema change is a new numbered migration**:
   `NNNNNN_short_name.up.sql` + `NNNNNN_short_name.down.sql`, the next number,
   no gaps (`migrate.CheckSet` and the tests enforce it).
2. **Shipped migrations are immutable.** Never edit, rename or delete one.
   A mistake is fixed by a new, corrective migration.
3. **Append every new file to `MANIFEST.sha256`** in the same commit
   (`sha256` of the LF-normalised file, two spaces, file name).
   `TestManifest_PinsEveryMigration` fails on a changed or missing file.
4. **Down migrations** ship where rolling back is technically safe. They are
   for development and tests; production rollback is the encrypted pre-upgrade
   snapshot restored by `install.sh --rollback`.
5. **Destructive changes** (drop or rename a column/table, tighten a type or
   constraint) use an explicit forward-compatible sequence across releases:
   add the new shape, migrate data, switch code, remove the old shape later.
6. **One-time data repairs** are numbered data migrations here, not code that
   runs at start-up.
7. **Reference data** (default tenant, SLA defaults, built-in payload families)
   lives in `../seed/` as numbered files `NNNN_name.sql`, each applied exactly
   once and recorded in `reference_data_version`. New or corrected reference
   data is a **new seed file** (never an edit), appended to
   `../seed/MANIFEST.sha256`. Seed statements must be idempotent and must
   never overwrite operator-controlled state (`ON CONFLICT DO NOTHING`, no
   `UPDATE` of rows operators can edit).
8. **Customer data is never seeded or overwritten.**
9. **No DDL outside migrations.** `scripts/h1-check-no-runtime-ddl.py` (CI)
   fails on `CREATE/ALTER/DROP TABLE|INDEX|…`, `GRANT`, `REVOKE`, `TRUNCATE` in
   Go string literals outside `internal/db/{legacy,migrate}`, tests and the
   test harness. A hit belongs in a migration; never allowlist it.
10. Migration and seed sets are release artifacts embedded in the signed
    orchestrator binary; they are never downloaded or replaced at runtime.

## Frozen legacy chain

`internal/db/legacy` is the pre-H1 boot-time schema code, frozen
(`FROZEN.sha256`, `TestLegacyChainIsFrozen`). It runs only when `migrate`
adopts a pre-H1 install. `TestBaselineEqualsLegacyChain` proves `000001`
builds the same schema. Delete `legacy` (its own change) once every customer
has upgraded through an H1 release.

## Testing a migration

`go test ./internal/db/migrate/ ./internal/db/migrations/ -p 1` (Docker). The
test harness (`internal/testutil`) builds every test database with
`migrate.Up`, so the whole suite runs on the migrated schema.
