# H1 — Versioned schema migrations, explicit migrate step, no boot-time DDL

**Status:** approved design (2026-10-06). Implementation starts after G1d's final whole-branch review (shared `main`); it may interleave with G1e (disjoint files).
**Finding:** `GroupH.txt` H1 (Medium) — boot-time idempotent DDL, no versioned migrations.

## 1. Goal and contract

The database schema becomes versioned, auditable and changed only by an explicit deploy step. The running orchestrator never changes the schema, seeds data or administers roles at boot; it connects only as `bas_app` and refuses to start on a schema mismatch with an actionable message.

Behaviour contract: the baseline reproduces today's schema exactly. No schema clean-up, renames or drops ride along with H1.

## 2. Current state (verified 2026-10-06)

| What | Where | Count / note |
|---|---|---|
| Boot-time DDL | `internal/db/postgres.go` `EnsureSchema` (112 KB) + `EnsureContentSchema`, `EnsureIOCSchema`, `EnsureIOCEnrichmentSchema`, `EnsureAgentGroupSchema`, `EnsureAgentUninstallSchema`, `EnsureExerciseSchema` | 68 `CREATE TABLE`, 148 `ADD COLUMN IF NOT EXISTS`, 91 `CREATE INDEX` in postgres.go alone |
| Hand-rolled conditional migrations | e.g. `postgres.go:1222` `DO $$ … RENAME COLUMN tenant_id TO azure_tenant_id` | |
| Data writes at boot | seed upserts (`payload_families … ON CONFLICT DO UPDATE`), default tenant, one-time dedupe `DELETE FROM variant_findings …` (`postgres.go:625`) | ~47 statements |
| Role administration at boot | `EnsureAppRole` (`internal/db/app_role.go`): create `bas_app`, sync password every boot, grants + default privileges | |
| Startup | `cmd/server/main.go:241-290`: `adminPool` (`DATABASE_ADMIN_URL`, bas_user) runs the 7 Ensure* + EnsureAppRole, closes, then `DATABASE_URL` (bas_app) | `os.Args[1]` = config path or `--healthcheck` |
| Version tracking | none (no `schema_migrations`, no migration library) | |
| Deploy | `packaging/compose/install.sh` `--install/--upgrade/--rollback`; `--upgrade` backs up only compose/.env/VERSION — **not the database**; `--rollback` restores images/config over a schema the newer release already mutated | Postgres `16-alpine`; existing encrypted dump helpers `_run_pg_dump` (`pg_dump -Fc`) + `openssl enc -aes-256-cbc -pbkdf2` with `.backup_key` |
| Image | distroless static, `ENTRYPOINT ["/orchestrator"]`; garble-built, cosign-signed | |
| Tests | 9 test files call `EnsureSchema` directly | |

## 3. Decisions

| Decision | Choice |
|---|---|
| Rollback | **Snapshot + restore** is the official production rollback. `--upgrade` takes an encrypted DB dump tied to that upgrade; `--rollback` restores images/config **and** that exact snapshot. Binaries are never rolled back without their snapshot. Operator is warned that changes made after the upgrade began are lost. Down migrations exist for development/testing only. |
| Seed / reference data | Separate deterministic, idempotent seed step inside `migrate up`, versioned separately (`reference_data_version`) from `schema_migrations`. Never overwrites customer-controlled state. One-time repairs → numbered data migrations. Customer/runtime data never seeded. Threat content keeps its own pipeline. |
| Roles | `migrate up` (bas_user, one-shot) owns `bas_app` provisioning and grants. The runtime orchestrator holds only the `bas_app` DSN. Password set only on role creation or explicit rotation — never as a side effect of `migrate up`. |
| Engine | golang-migrate (pinned, vendored; only the `pgx/v5` database driver and `iofs` source linked); migrations and seed embedded via `embed.FS` in the signed binary — immutable release artifacts, never downloaded or replaced at runtime. |
| Baseline and adoption | Approach A: baseline captured mechanically from a database built by today's chain; today's chain frozen in `internal/db/legacy` and used only to bring pre-H1 installs to the baseline; adoption validated by an order-insensitive catalog fingerprint. Rejected: hand-assembled baseline (error-prone, `DO $$` blocks); wrapping the Ensure* chain as "migration 1" (not versioning). |

## 4. Architecture

### 4.1 Command surface

The orchestrator binary gains subcommands, dispatched in `main.go` before the existing `os.Args[1]` config-path handling (`--healthcheck` unchanged):

- `orchestrator migrate up` — classify, adopt or migrate, seed, provision/verify `bas_app` (§4.3).
- `orchestrator migrate status` — schema version, dirty flag, reference-data version, pending count; exit 0 when current, non-zero otherwise.
- `orchestrator migrate rotate-app-password` — sets `bas_app`'s password to the configured `BAS_APP_DB_PASSWORD`, then verifies login.

All three need `DATABASE_ADMIN_URL` (bas_user). `install.sh` runs them as `docker compose run --rm orchestrator migrate …`.

### 4.2 Packages

- `internal/db/migrations/` — `000001_baseline.{up,down}.sql`, then `00000N_<name>.{up,down}.sql`; `embed.FS`; `README.md` with the development rules (§7).
- `internal/db/seed/` — `*.sql` (e.g. `system_defaults.sql`, `tenants.sql`, `payload_families.sql`) applied in lexical order, plus `SEED_VERSION` (integer); `embed.FS`.
- `internal/db/legacy/` — today's seven `Ensure*Schema` functions moved verbatim and frozen; called only by adoption. `EnsureAppRole` is not moved (its logic is re-homed in `migrate`, §4.3).
- `internal/db/schemacheck/` — `Fingerprint(ctx, conn, schema) (Fingerprint, error)` over the catalog: tables; columns (name, type, nullability, default, identity/generated); constraints (type, columns, definition); indexes (definition); sequences; functions; triggers; extensions. Column order is not part of the fingerprint. `Diff(want, got) (missing, different, extra []Object)`.
- `internal/db/migrate/` — orchestration: classification, golang-migrate wrapper, adoption, seed, role, status, and `CheckRuntime(ctx, pool) error` used by the server at startup.

### 4.3 `migrate up`

Runs as bas_user under a Postgres advisory lock (one constant key) so concurrent runs cannot interleave. Classification:

| State | Detection | Action |
|---|---|---|
| Fresh | no Audspect tables, no `schema_migrations` | apply 000001…N |
| Pre-H1 | Audspect tables present (sentinel set: `tenants`, `agents`, `scenario_runs`), no `schema_migrations` | adoption, then 2…N |
| Managed | `schema_migrations` present, `dirty = false` | apply pending, or nothing |
| Dirty | `dirty = true` | refuse; name the version; point to the upgrade snapshot and `install.sh --rollback`; never auto-repair |
| Newer | version > highest embedded migration | refuse: "database is at V, this release knows N — run the matching release or `install.sh --rollback`" |
| Unrecognised | non-Audspect tables present, sentinel set absent | refuse |

**Adoption:**
1. Run the frozen `legacy` chain once (brings any older release to the baseline, including its conditional rename and one-time dedupe).
2. Fingerprint `public` and compare with the baseline fingerprint, obtained by applying 000001 into a temporary schema inside a transaction that is always rolled back. Missing or different objects → fail closed: no `schema_migrations` written, every difference printed. Extra objects (leftovers from older releases) → printed and recorded in `h1_adoption_report(object, kind, detail, recorded_at)`, not blocking; removing them is a later numbered migration.
3. Create `schema_migrations` with version 1, `dirty = false`; continue with 2…N.
Steps 1–3 run in one transaction. If the legacy chain contains a statement Postgres cannot run in a transaction (e.g. `CREATE INDEX CONCURRENTLY`), adoption runs non-transactionally and recovery relies on the upgrade snapshot; the implementation verifies which applies and records it.

**Seed:** one transaction applies every `seed/*.sql`, then upserts `reference_data_version(version, applied_at)` to `SEED_VERSION`. Each statement is keyed on natural keys and idempotent. Rows in tables an operator can edit through the API are inserted with `ON CONFLICT DO NOTHING`; only rows that are pure reference data (not operator-editable) may use `DO UPDATE`. Each current boot-time data statement is classified during implementation by checking the API's write paths for its table; the classification is recorded in the seed file header.

**Role:** create `bas_app` (`LOGIN NOSUPERUSER NOBYPASSRLS`) only when absent, with `BAS_APP_DB_PASSWORD`; (re)apply `GRANT CONNECT`, `USAGE ON SCHEMA public`, `SELECT, INSERT, UPDATE, DELETE ON ALL TABLES`, sequence privileges and `ALTER DEFAULT PRIVILEGES` exactly as `EnsureAppRole` does today; then open a connection as `bas_app` with the configured password. Login failure → stop: "bas_app password does not match BAS_APP_DB_PASSWORD — run `install.sh --rotate-db-app-password`". The password is never changed by `migrate up` for an existing role.

**Output:** one summary line (`schema 1→3, reference data 2→3, bas_app ok`) plus the adoption report when one was produced; non-zero exit on any refusal.

### 4.4 Runtime

The server connects only with `DATABASE_URL` (bas_app) and calls `migrate.CheckRuntime`: reads `schema_migrations` and `reference_data_version`; any of missing / dirty / lower / higher than the binary's embedded versions → `log.Fatalf` with the state and the action (`run install.sh --upgrade`, or `install.sh --rollback` for a newer database). No DDL, DML or role statements at startup. `config` keeps `DatabaseAdminURL` only for the migrate subcommands. The `orchestrator` compose service no longer receives `DATABASE_ADMIN_URL` or `POSTGRES_PASSWORD`.

### 4.5 Baseline capture (development time, once)

`tools/h1-capture-baseline` (in `orchestrator/`): starts `postgres:16-alpine` in Docker, runs the `legacy` chain, `pg_dump --schema-only --no-owner --no-privileges`, normalizes (drops `SET`/`SELECT pg_catalog.set_config` lines and comments; removes role and grant statements, which `migrate` owns; removes seed rows, which `seed/` owns), writes `000001_baseline.up.sql`. `000001_baseline.down.sql` drops every object (development/test only). A test proves fingerprint(empty + 000001) = fingerprint(empty + legacy chain); it runs in CI until `legacy` is deleted.

## 5. Install, upgrade, rollback

**Upgrade record:** `${DATA_DIR}/backups/upgrade-<ts>-<from>-to-<to>/` holds compose, `.env`, `VERSION`, `db.dump.enc` (existing `pg_dump -Fc` + `openssl enc` helpers with `.backup_key`) and `UPGRADE.json` (`from`, `to`, schema version before/after, reference-data version before/after, dump SHA-256, timestamps, `state`: `started` → `migrated` → `healthy` | `failed` | `rolled-back`). The `upgrade-` prefix separates these from scheduled backups.

**`--upgrade`:** (1) validate: install healthy, disk space for the dump, bundle signatures (existing checks); (2) stop the orchestrator (Postgres stays up); (3) encrypted dump, verified with `pg_restore --list` and its hash; (4) load images and bundle files; (5) `docker compose run --rm -e DATABASE_ADMIN_URL=… orchestrator migrate up` — on failure mark `failed`, leave the orchestrator stopped, print the rollback command; (6) start the new version; (7) health check → `healthy`, else `failed` with the same guidance. No automatic rollback.

**`--rollback`:** selects the newest `upgrade-*` record (or `--upgrade-id <dir>`); never a scheduled backup. Shows from/to versions and: "Database changes made after this upgrade began (<timestamp>) will be lost." Requires typing the from-version (or `--yes`). Then: stop orchestrator; verify dump hash; restore previous images/config; drop and recreate the database as bas_user; decrypt and `pg_restore`; start the previous version; health check; mark `rolled-back`.

**`--install`:** Postgres up → `migrate up` (schema, seed, `bas_app` created with the password generated into `.env`) → orchestrator up.

**`--rotate-db-app-password`:** generate a password, write `.env`, run `migrate rotate-app-password`, restart the orchestrator.

**Airgap:** `import.sh` keeps loading/verifying images; the operator then runs `install.sh --upgrade`, so the same transaction applies. The open airgap cosign finding is not part of H1.

## 6. Testing

Go tests against testcontainers Postgres 16 (race tests via the Docker recipe); install.sh tests in a container.

| ID | Test |
|---|---|
| H1-T1 | Empty DB → `migrate up` → fingerprint = baseline; seed applied; `bas_app` logs in with DML-only privileges |
| H1-T2 | `migrate up` ×3 → second and third: nothing pending, fingerprint and per-table row counts unchanged |
| H1-T3 | Adoption: legacy-built DB with representative rows in every table → `migrate up` → per-table row counts and checksums unchanged, version 1 marked, later migrations applied. Variants: an older-release schema (legacy chain from an earlier tagged commit); extra leftover objects (reported, not blocking) |
| H1-T3b | Adoption fails closed on a missing column: refused, all differences listed, no `schema_migrations` |
| H1-T4 | Migrations apply in order; versions recorded; gaps or duplicate numbers in the embedded set rejected (unit test) |
| H1-T5 | A failing test migration leaves `dirty`; next `migrate up` and server startup both refuse |
| H1-T6 | up/down/up for non-destructive test migrations; baseline down/up on an empty DB |
| H1-T7 | Startup: current → starts as bas_app with zero DDL/DML/role statements at boot (statement log on the test role); pending → refuses with the version message; newer → refuses |
| H1-T8 | Role: created when absent; wrong configured password → `migrate up` stops with the rotation message, password unchanged; `rotate-app-password` works and the old password stops working |
| H1-T9 | Seed idempotent; an operator-edited row in an editable table survives `migrate up` |
| H1-T10 | install.sh: upgrade writes `UPGRADE.json` with a verified dump; rollback restores the exact pre-upgrade row set; rollback refuses a scheduled backup |

The 9 test files that call `EnsureSchema` switch to a `testdb.Migrated(t)` helper running the real `migrate up`.

## 7. Guardrails and development rules

- **Immutability (CI):** committed manifest of SHA-256 per shipped migration and seed file; CI fails if a listed file changes or disappears; new files are appended.
- **Legacy freeze (CI):** hash of `internal/db/legacy/` pinned; any change fails.
- **No runtime DDL (CI):** check fails on `CREATE`/`ALTER`/`DROP`/`GRANT`/`REVOKE` SQL in Go source outside `internal/db/{legacy,migrate}` and tests.
- **Baseline equivalence (CI):** §4.5 test, until `legacy` is deleted.
- **Rules** (`internal/db/migrations/README.md`): every schema change is a new numbered migration, immutable once shipped; mistakes are fixed by a corrective migration. A down migration ships where rollback is technically safe; destructive changes use an explicit forward-compatible strategy; production rollback is the snapshot. One-time data repairs are numbered data migrations; reference data lives in `seed/` with `SEED_VERSION` bumped; customer data is never seeded or overwritten. Migration and seed sets are release artifacts embedded in the signed binary.

## 8. Rollout

- Code after G1d's final review; may interleave with G1e.
- Release notes: this release adopts the schema; `install.sh --upgrade` is mandatory (restarting the container no longer upgrades the schema); rollback restores the pre-upgrade snapshot.
- `legacy` stays until every customer has passed through one H1 release; deleting it is its own change.

## 9. Out of scope

RLS activation (Runtime Role Separation Phase 2); the airgap cosign finding; schema clean-up, renames or drops; the threat-content pipeline; multi-database or non-compose deployments.

## 10. Carried constraints

Work on `main`; commit and push after every commit; stage by name; new dependency pinned, vendored and gated by the existing govulncheck/gosec checks; garble build must still pass (migrations are SQL in `embed.FS`, no reflection); client production changes go through `install.sh`/`uninstall.sh`, never raw `docker compose`.
