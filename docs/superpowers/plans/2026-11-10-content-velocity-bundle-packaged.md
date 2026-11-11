# Content-Velocity: bundle_packaged Measurement Implementation Plan

> **For agentic workers:** Execute task by task with TDD. Spec: `docs/superpowers/specs/2026-11-10-content-velocity-commitment-design.md` (sections 2, 6 and 9).

**Goal:** Measure stage 4 (packaging) of the content-velocity clock by recording a `bundle_packaged` ledger event for every registry content version that ships in a signed bundle.

**Architecture:** Option 1, decided by the owner. `packaging/build.sh` runs `verify-all` and then writes a manifest of shipped scenario files with their SHA-256. A separate ingest command, run where the database is, maps each SHA-256 to a `content_versions.artifact_sha256` row and records one `bundle_packaged` event per matched version. The build host never connects to the database. Unmatched hashes are counted, never treated as errors.

**Tech Stack:** Go (`orchestrator/internal/tcv`), PostgreSQL, bash (`packaging/build.sh`).

## Global Constraints

- The ledger is append-only and write-once (`idempotency_key` + `ON CONFLICT DO NOTHING`). Corrections are new rows.
- `EventTime` must never be zero (existing invariant in `RecordPipelineEvent`).
- Recording is log-and-continue. A ledger failure must never fail the build or the ingest run.
- Phase-2C TCV (`AggregateMetrics`) stays byte-for-byte untouched.
- The ledger CHECK migration is idempotent and must run before `EnsureAppRole` (its REVOKE targets this table).

## Interfaces (shared across tasks)

- Event type constant: `tcv.EventBundlePackaged EventType = "bundle_packaged"`
- Manifest (JSON written by `build.sh`):
  ```json
  {"schema":1,"bundle_id":"<string>","packaged_at":"<RFC3339>","entries":[{"path":"<relative scenario path>","sha256":"<64 hex>"}]}
  ```
- Pure mapping: `tcv.BundlePackagedEvents(m BundleManifest, versionBySHA map[string]string) (events []Event, unmatched []string)`
  - `versionBySHA` maps sha256 to `content_version_id`.
  - Each matched entry yields one Event with `ContentVersionID` set, `EventTime` = `packaged_at`, `SourceTable` = `"bundle_manifest"`, `SourcePK` = `bundle_id + "/" + sha256`, and `Payload` = `{"bundle_id","path","sha256"}`.
  - A duplicate sha256 in the manifest yields one event (first path wins) so two identical files do not double-count.

## Tasks

### Task 1: Event taxonomy and CHECK migration

**Files:** Modify `orchestrator/internal/tcv/ledger.go`, `orchestrator/internal/db/tcf_pipeline_events_schema.go`. Test: `orchestrator/internal/db/tcf_pipeline_events_schema_test.go`.

- [ ] Write a failing test asserting the schema statements include `'bundle_packaged'` in the event_type CHECK and that a migration statement drops and re-adds the CHECK idempotently (wrapped in a `DO $$ ... $$` block that looks up the constraint by name).
- [ ] Run it; expect FAIL.
- [ ] Add `EventBundlePackaged` to `ledger.go`. Add `'bundle_packaged'` to the CREATE TABLE CHECK, and append the idempotent migration statement to `tcfPipelineEventsTables`.
- [ ] Run the test; expect PASS.

### Task 2: Manifest type and pure mapping

**Files:** Create `orchestrator/internal/tcv/bundle_manifest.go`. Test: `orchestrator/internal/tcv/bundle_manifest_test.go`.

- [ ] Write failing tests: (a) one event per matched entry with the fields above; (b) unmatched sha256 values are returned in `unmatched`, not dropped silently; (c) duplicate sha256 yields one event; (d) a manifest with a zero `packaged_at` or an unknown `schema` returns an error.
- [ ] Run them; expect FAIL (undefined symbols).
- [ ] Implement `BundleManifest`, `BundlePackagedEvents`, and schema validation.
- [ ] Run them; expect PASS.

### Task 3: Ingest against the database

**Files:** Create `orchestrator/internal/tcv/bundle_ingest.go`. Test: `orchestrator/internal/tcv/bundle_ingest_test.go` (fake `Querier`, no database).

- [ ] Write failing test: given a manifest and a fake that returns two of three hashes from `content_versions`, ingest records exactly two events and reports one unmatched hash.
- [ ] Implement `IngestBundleManifest(ctx, q Querier, m BundleManifest) (recorded, unmatched int, err error)`: one `SELECT content_version_id, artifact_sha256 FROM content_versions WHERE artifact_sha256 = ANY($1)`, then `RecordPipelineEvent` per matched event.
- [ ] Run the test; expect PASS.

### Task 4: build.sh writes the manifest

**Files:** Modify `packaging/build.sh` (after the `verify-all` gate at line ~197). Create `packaging/bundle-manifest.sh` as a helper plus a test `packaging/bundle-manifest.test.sh`.

- [ ] Write a failing shell test: given a fixture scenarios dir, the helper writes valid JSON with one entry per file and correct sha256 values.
- [ ] Implement the helper using `sha256sum`. Call it from `build.sh` after the gate, writing `${BUILD_DIR}/bundle-manifest.json`. Set `bundle_id` from the existing bundle version and `packaged_at` from `date -u +%Y-%m-%dT%H:%M:%SZ`.
- [ ] Run the test; expect PASS.

### Task 5: Ingest command

**Files:** Create `orchestrator/cmd/tcv-ingest/main.go` (+ test). Flags: `-manifest <path>`, database URL from the existing `DATABASE_URL` environment variable (no new config mechanism).

- [ ] Write a failing test for argument handling and a missing-manifest error.
- [ ] Implement: read manifest, open pool, call `IngestBundleManifest`, print `recorded=N unmatched=M`. Exit 0 on success, including when `unmatched > 0`.
- [ ] Run the test; expect PASS.

### Task 6: Verification

- [ ] `go build ./...` and `go test ./internal/tcv/ ./internal/db/ ./cmd/tcv-ingest/ -count=1`.
- [ ] `packaging/bundle-manifest.test.sh`.
- [ ] Confirm `EnsureTCFPipelineEventsSchema` runs the migration twice without error (against a real Postgres when available; otherwise record that it was not run).

## Out of scope (tracked separately)

- Intake (`advisory_received`) and exclusion-reason events: the threat_observed event already marks CERT-In intake; exclusion reasons are a separate task.
- Delivery measurement: Audspect records it only when the customer or transfer process confirms it.
