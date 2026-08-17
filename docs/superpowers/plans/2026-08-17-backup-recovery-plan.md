# Backup & Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Audspect a real disaster-recovery path — an admin can request a backup from the console, and a host-side worker (never the orchestrator container) performs it, covering both Postgres and the `DATA_DIR` config/secrets the console depends on.

**Architecture:** The console writes/reads a `backup_jobs` row in Postgres (a channel it already has); a host-side systemd timer polls that table, runs `pg_dump` + packages `DATA_DIR` config, encrypts, writes locally and optionally pushes to a remote target, then writes the result back. Restore is host-only and requires a typed confirmation — the console can only display available backups and the CLI command to run.

**Tech Stack:** Go (`orchestrator/internal/db`, `internal/auth`, `internal/api`), vanilla JS (`orchestrator/wwwroot/index.html`), Bash (`packaging/compose/install.sh`), Postgres, systemd, openssl.

**Spec:** `docs/superpowers/specs/2026-08-17-backup-recovery-design.md`

## Global Constraints

- The orchestrator container gets exactly one new capability: reading/writing the `backup_jobs` table through its existing DB pool. It never gains `pg_dump`, `DATA_DIR`, or `docker` access.
- Backups auto-execute on request (host worker). Restores never auto-execute — always a human running `install.sh --restore <id>` on the host, typing the literal word `RESTORE`.
- Encryption of the archive is unconditional (`openssl enc -aes-256-cbc -pbkdf2`), keyed by `${DATA_DIR}/.backup_key` (root:root, 0600), generated once at install time, never read by the app or stored in the DB.
- Retention (`BACKUP_RETENTION_DAILY/WEEKLY/MONTHLY`, `REMOTE_BACKUP_*`) is configured only via `setup.conf` / `DATA_DIR/.env` — never exposed as editable fields in the console.
- A backup is only reported `protected` if both local write and (when enabled) remote push succeeded; `local_success` if remote failed or is disabled; never silently collapse those into one status.

---

### Task 1: `backup_jobs` table + `CanManageBackups` permission

**Files:**
- Modify: `orchestrator/internal/db/postgres.go:1493` (insert before the closing `}` of the `stmts` slice in `EnsureSchema`)
- Modify: `orchestrator/internal/auth/permissions.go:205-206` (const block), `:258-259` (RoleAdmin map), `:338` (Permissions() slice)
- Modify: `orchestrator/internal/auth/permissions_test.go` (append `TestCanManageBackups_AdminOnly` at EOF; update `TestHasPermission_MatrixIsComplete`'s `tested` map at line 108; update `TestPermissions_Ordering`'s `want` slice at line 157)

**Interfaces:**
- Produces: `auth.CanManageBackups` (`Permission = "backups:manage"`), granted to `RoleAdmin` only. Table `backup_jobs` with columns exactly as in the spec's schema section. Both consumed by Task 2 onward.

- [ ] **Step 1: Write the failing permission test**

Append to `orchestrator/internal/auth/permissions_test.go` (end of file, after `TestCanExecuteRemediation_AnalystAndAdmin`):

```go
func TestCanManageBackups_AdminOnly(t *testing.T) {
	if !HasPermission(RoleAdmin, CanManageBackups) {
		t.Error("expected RoleAdmin to hold CanManageBackups")
	}
	if HasPermission(RoleAnalyst, CanManageBackups) {
		t.Error("expected RoleAnalyst NOT to hold CanManageBackups")
	}
	if HasPermission(RoleViewer, CanManageBackups) {
		t.Error("expected RoleViewer NOT to hold CanManageBackups")
	}
}
```

- [ ] **Step 2: Run it to confirm it fails to compile (CanManageBackups undefined)**

Run: `cd orchestrator && go test ./internal/auth/... -run TestCanManageBackups_AdminOnly -v`
Expected: FAIL — `undefined: CanManageBackups`

- [ ] **Step 3: Add the permission constant and wire it into RoleAdmin**

In `orchestrator/internal/auth/permissions.go`, change line 204-206 from:

```go
	CanExecuteRemediation Permission = "remediation:execute"
	CanApproveRemediation Permission = "remediation:approve"
)
```

to:

```go
	CanExecuteRemediation Permission = "remediation:execute"
	CanApproveRemediation Permission = "remediation:approve"

	// Backup & Recovery — Admin-only. The console never performs the backup
	// itself (see docs/superpowers/specs/2026-08-17-backup-recovery-design.md);
	// this permission gates only the ability to request one and to flag a
	// backup for restore intent (an audit marker, not an execution trigger).
	CanManageBackups Permission = "backups:manage"
)
```

Change line 258 from:

```go
		CanExecuteRemediation: true, CanApproveRemediation: true,
	},
```

to:

```go
		CanExecuteRemediation: true, CanApproveRemediation: true,
		CanManageBackups: true,
	},
```

Change line 338 from:

```go
		CanExecuteRemediation, CanApproveRemediation,
	} {
```

to:

```go
		CanExecuteRemediation, CanApproveRemediation,
		CanManageBackups,
	} {
```

- [ ] **Step 4: Run the new test to confirm it passes**

Run: `cd orchestrator && go test ./internal/auth/... -run TestCanManageBackups_AdminOnly -v`
Expected: PASS

- [ ] **Step 5: Fix the two guard tests this wiring necessarily breaks**

`TestHasPermission_MatrixIsComplete` and `TestPermissions_Ordering` assert the *complete* set/order of admin permissions — adding one anywhere breaks both until updated. This is expected, not a new bug to investigate.

In `orchestrator/internal/auth/permissions_test.go`, change line 108 from:

```go
		CanExecuteRemediation: true, CanApproveRemediation: true,
	}
```

to:

```go
		CanExecuteRemediation: true, CanApproveRemediation: true,
		CanManageBackups: true,
	}
```

Change line 157 from:

```go
		CanExecuteRemediation, CanApproveRemediation,
	}
```

to:

```go
		CanExecuteRemediation, CanApproveRemediation,
		CanManageBackups,
	}
```

- [ ] **Step 6: Run the full auth package test suite**

Run: `cd orchestrator && go test ./internal/auth/... -v`
Expected: PASS, all tests including `TestHasPermission_MatrixIsComplete`, `TestPermissions_Ordering`, `TestCanManageBackups_AdminOnly`.

- [ ] **Step 7: Add the `backup_jobs` table to the schema**

In `orchestrator/internal/db/postgres.go`, change lines 1489-1493 from:

```go
		`ALTER TABLE openaev_config ADD COLUMN IF NOT EXISTS last_sync_errored int NOT NULL DEFAULT 0`,
	}
```

to:

```go
		`ALTER TABLE openaev_config ADD COLUMN IF NOT EXISTS last_sync_errored int NOT NULL DEFAULT 0`,

		// Backup & Recovery: console requests, host-side systemd timer
		// executes. See docs/superpowers/specs/2026-08-17-backup-recovery-design.md.
		// The 'manifest' column is a queryable summary the worker writes back
		// after success -- separate from the manifest.json file inside the
		// archive itself, which is what --restore actually trusts.
		`CREATE TABLE IF NOT EXISTS backup_jobs (
			id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			job_type           TEXT NOT NULL CHECK (job_type IN ('backup', 'restore_marker')),
			trigger            TEXT NOT NULL CHECK (trigger IN ('console', 'scheduled', 'cli', 'pre_restore')),
			requested_by       TEXT,
			requested_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
			started_at         TIMESTAMPTZ,
			finished_at        TIMESTAMPTZ,
			status             TEXT NOT NULL DEFAULT 'requested'
			                     CHECK (status IN ('requested','running','protected',
			                                        'local_success','remote_failed','failed')),
			archive_filename   TEXT,
			archive_size_bytes BIGINT,
			sha256             TEXT,
			local_path         TEXT,
			remote_path        TEXT,
			error_message      TEXT,
			restore_of_id      UUID REFERENCES backup_jobs(id),
			manifest           JSONB
		)`,
		`CREATE INDEX IF NOT EXISTS idx_backup_jobs_status ON backup_jobs(status)`,
		`CREATE INDEX IF NOT EXISTS idx_backup_jobs_requested_at ON backup_jobs(requested_at DESC)`,
	}
```

- [ ] **Step 8: Verify the schema statement is syntactically valid**

Run: `cd orchestrator && gofmt -l internal/db/postgres.go internal/auth/permissions.go internal/auth/permissions_test.go`
Expected: no output (already formatted). If any file is listed, run `gofmt -w` on it and re-check.

Run: `cd orchestrator && go vet ./internal/db/... ./internal/auth/...`
Expected: no output.

This table's real creation is exercised by every `sharedDB`-backed test in Task 2 (they all run `EnsureSchema` once via `TestMain`) — no standalone schema test needed here.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/auth/permissions.go orchestrator/internal/auth/permissions_test.go
git commit -m "$(cat <<'EOF'
feat(backup): add backup_jobs table and CanManageBackups permission

Foundation for the Backup & Recovery feature -- the console requests
backups by writing to this table, a host-side worker executes them.
Admin-only permission, mirroring CanUpdateConnectorConfig's tier.

See docs/superpowers/specs/2026-08-17-backup-recovery-design.md
EOF
)"
git push
```

---

### Task 2: Backup job API — create, list, get

**Files:**
- Create: `orchestrator/internal/api/backup_handlers.go`
- Create: `orchestrator/internal/api/backup_handlers_test.go`

**Interfaces:**
- Consumes: `auth.CanManageBackups` (Task 1), `auth.ClaimsFrom(ctx)` returning `(*auth.Claims, bool)` with `.UserID` (existing, `internal/auth/middleware.go`), `h.db *pgxpool.Pool` (existing `Handler` field), `jsonOK(w, v)` / `jsonError(w, msg, code)` (existing, `internal/api/variant_handlers.go:701`, `internal/api/handlers.go:3054`).
- Produces: `func (h *Handler) CreateBackupJob(w http.ResponseWriter, r *http.Request)`, `func (h *Handler) ListBackupJobs(w http.ResponseWriter, r *http.Request)`, `func (h *Handler) GetBackupJob(w http.ResponseWriter, r *http.Request)` — all consumed by Task 4's route wiring. JSON shape (`backupJobJSON` struct) consumed by Task 5's frontend.

- [ ] **Step 1: Write the failing test for job creation**

Create `orchestrator/internal/api/backup_handlers_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func authedAdminReq(method, path string, body []byte) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	claims := &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}
	return req.WithContext(auth.ContextWithClaims(req.Context(), claims))
}

func TestCreateBackupJob_InsertsRequestedRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalPostureScenario(t, "bkp-create-sc")
		h := New(pool, ws.NewHub(), engine, "")
		rec := httptest.NewRecorder()
		h.CreateBackupJob(rec, authedAdminReq(http.MethodPost, "/api/backups", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var id string
		var jobType, trigger, status, requestedBy string
		if err := pool.QueryRow(context.Background(),
			`SELECT id, job_type, trigger, status, requested_by FROM backup_jobs ORDER BY requested_at DESC LIMIT 1`,
		).Scan(&id, &jobType, &trigger, &status, &requestedBy); err != nil {
			t.Fatalf("query inserted row: %v", err)
		}
		if jobType != "backup" || trigger != "console" || status != "requested" || requestedBy != "admin-1" {
			t.Errorf("row = (%s, %s, %s, %s), want (backup, console, requested, admin-1)", jobType, trigger, status, requestedBy)
		}
	})
}

func TestListBackupJobs_ReturnsRequestedFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalPostureScenario(t, "bkp-list-sc")
		h := New(pool, ws.NewHub(), engine, "")
		h.CreateBackupJob(httptest.NewRecorder(), authedAdminReq(http.MethodPost, "/api/backups", nil))
		rec := httptest.NewRecorder()
		h.ListBackupJobs(rec, authedAdminReq(http.MethodGet, "/api/backups", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		if !bytes.Contains(rec.Body.Bytes(), []byte(`"status":"requested"`)) {
			t.Errorf("body missing requested job: %s", rec.Body.String())
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestCreateBackupJob_InsertsRequestedRow|TestListBackupJobs_ReturnsRequestedFirst' -v`
Expected: FAIL — `h.CreateBackupJob undefined`, `h.ListBackupJobs undefined`

- [ ] **Step 3: Implement the handlers**

Create `orchestrator/internal/api/backup_handlers.go`:

```go
package api

import (
	"net/http"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/go-chi/chi/v5"
)

// backupJobJSON is the wire shape for a backup_jobs row. Pointer fields are
// null until the worker fills them in -- a freshly requested job has none of
// archiveFilename/archiveSizeBytes/sha256/localPath/remotePath/errorMessage.
type backupJobJSON struct {
	ID               string     `json:"id"`
	JobType          string     `json:"jobType"`
	Trigger          string     `json:"trigger"`
	RequestedBy      *string    `json:"requestedBy,omitempty"`
	RequestedAt      time.Time  `json:"requestedAt"`
	StartedAt        *time.Time `json:"startedAt,omitempty"`
	FinishedAt       *time.Time `json:"finishedAt,omitempty"`
	Status           string     `json:"status"`
	ArchiveFilename  *string    `json:"archiveFilename,omitempty"`
	ArchiveSizeBytes *int64     `json:"archiveSizeBytes,omitempty"`
	SHA256           *string    `json:"sha256,omitempty"`
	LocalPath        *string    `json:"localPath,omitempty"`
	RemotePath       *string    `json:"remotePath,omitempty"`
	ErrorMessage     *string    `json:"errorMessage,omitempty"`
	RestoreOfID      *string    `json:"restoreOfId,omitempty"`
}

const backupJobSelectCols = `id, job_type, trigger, requested_by, requested_at, started_at,
	finished_at, status, archive_filename, archive_size_bytes, sha256,
	local_path, remote_path, error_message, restore_of_id`

func scanBackupJob(row interface {
	Scan(dest ...any) error
}) (backupJobJSON, error) {
	var j backupJobJSON
	err := row.Scan(&j.ID, &j.JobType, &j.Trigger, &j.RequestedBy, &j.RequestedAt, &j.StartedAt,
		&j.FinishedAt, &j.Status, &j.ArchiveFilename, &j.ArchiveSizeBytes, &j.SHA256,
		&j.LocalPath, &j.RemotePath, &j.ErrorMessage, &j.RestoreOfID)
	return j, err
}

// POST /api/backups — the console requests a backup; it never performs one.
// A host-side systemd timer (audspect-backup-worker.timer) polls for
// status='requested' rows and executes them. See
// docs/superpowers/specs/2026-08-17-backup-recovery-design.md.
func (h *Handler) CreateBackupJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var requestedBy *string
	if claims, ok := auth.ClaimsFrom(ctx); ok && claims != nil {
		requestedBy = &claims.UserID
	}
	row := h.db.QueryRow(ctx,
		`INSERT INTO backup_jobs (job_type, trigger, requested_by)
		 VALUES ('backup', 'console', $1)
		 RETURNING `+backupJobSelectCols,
		requestedBy,
	)
	job, err := scanBackupJob(row)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, job)
}

// GET /api/backups — most recent backup jobs, newest first, for the Settings
// "Available backups" table. Excludes restore_marker rows (see GetBackupJob
// for looking one up directly, and the restore-marker handler for creating
// them).
func (h *Handler) ListBackupJobs(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT `+backupJobSelectCols+`
		 FROM backup_jobs WHERE job_type = 'backup'
		 ORDER BY requested_at DESC LIMIT 50`,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := make([]backupJobJSON, 0, 16)
	for rows.Next() {
		job, err := scanBackupJob(rows)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out = append(out, job)
	}
	jsonOK(w, out)
}

// GET /api/backups/{id} — single job, for polling status after "Backup Now."
func (h *Handler) GetBackupJob(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row := h.db.QueryRow(r.Context(),
		`SELECT `+backupJobSelectCols+` FROM backup_jobs WHERE id = $1`, id,
	)
	job, err := scanBackupJob(row)
	if err != nil {
		jsonError(w, "backup job not found", http.StatusNotFound)
		return
	}
	jsonOK(w, job)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestCreateBackupJob_InsertsRequestedRow|TestListBackupJobs_ReturnsRequestedFirst' -v`
Expected: PASS

- [ ] **Step 5: gofmt and vet**

Run: `cd orchestrator && gofmt -l internal/api/backup_handlers.go internal/api/backup_handlers_test.go`
Expected: no output (if listed, `gofmt -w` then re-check).

Run: `cd orchestrator && go vet ./internal/api/...`
Expected: no output.

- [ ] **Step 6: Run the full internal/api suite in the background**

Run (background, this suite takes 8-15 minutes):
```bash
cd orchestrator && go test ./internal/api/... -timeout 25m > "$SCRATCHPAD/backup_task2_test.log" 2>&1
```
Wait for the completion notification, then **read the actual log file** at `$SCRATCHPAD/backup_task2_test.log` in full (never trust a piped/truncated capture).
Expected: `ok` for `internal/api`, zero FAIL/panic lines.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/backup_handlers.go orchestrator/internal/api/backup_handlers_test.go
git commit -m "$(cat <<'EOF'
feat(backup): add create/list/get backup job API

Console-side of the request queue -- these handlers only INSERT/SELECT
backup_jobs rows through the existing DB pool, never touch pg_dump or
DATA_DIR. Execution happens host-side (see Task 3+ of the plan).
EOF
)"
git push
```

---

### Task 3: Restore-marker endpoint

**Files:**
- Modify: `orchestrator/internal/api/backup_handlers.go` (append)
- Modify: `orchestrator/internal/api/backup_handlers_test.go` (append)

**Interfaces:**
- Consumes: `scanBackupJob`, `backupJobSelectCols`, `backupJobJSON` (Task 2).
- Produces: `func (h *Handler) CreateRestoreMarker(w http.ResponseWriter, r *http.Request)`, consumed by Task 4's routing and Task 5's frontend Restore panel. Response shape `{"markerId": string, "restoreCommand": string}`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/api/backup_handlers_test.go`:

```go
func TestCreateRestoreMarker_UnfinishedBackupRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalPostureScenario(t, "bkp-marker-unfinished-sc")
		h := New(pool, ws.NewHub(), engine, "")
		var id string
		if err := pool.QueryRow(context.Background(),
			`INSERT INTO backup_jobs (job_type, trigger) VALUES ('backup', 'cli') RETURNING id`,
		).Scan(&id); err != nil {
			t.Fatalf("seed backup job: %v", err)
		}
		rec := httptest.NewRecorder()
		req := authedAdminReq(http.MethodPost, "/api/backups/"+id+"/restore-marker", nil)
		req = withChiURLParam(req, "id", id)
		h.CreateRestoreMarker(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409 (backup not finished), body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateRestoreMarker_FinishedBackupReturnsCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalPostureScenario(t, "bkp-marker-finished-sc")
		h := New(pool, ws.NewHub(), engine, "")
		var id string
		if err := pool.QueryRow(context.Background(),
			`INSERT INTO backup_jobs (job_type, trigger, status, archive_filename)
			 VALUES ('backup', 'cli', 'protected', 'audspect-backup-20260817-020000.tar.enc')
			 RETURNING id`,
		).Scan(&id); err != nil {
			t.Fatalf("seed backup job: %v", err)
		}
		rec := httptest.NewRecorder()
		req := authedAdminReq(http.MethodPost, "/api/backups/"+id+"/restore-marker", nil)
		req = withChiURLParam(req, "id", id)
		h.CreateRestoreMarker(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		if !bytes.Contains(rec.Body.Bytes(), []byte("install.sh --restore audspect-backup-20260817-020000.tar.enc")) {
			t.Errorf("body missing expected restore command: %s", rec.Body.String())
		}
		var jobType, restoreOf string
		if err := pool.QueryRow(context.Background(),
			`SELECT job_type, restore_of_id FROM backup_jobs WHERE job_type = 'restore_marker'`,
		).Scan(&jobType, &restoreOf); err != nil {
			t.Fatalf("query marker row: %v", err)
		}
		if restoreOf != id {
			t.Errorf("restore_of_id = %s, want %s", restoreOf, id)
		}
	})
}
```

`withChiURLParam` doesn't exist yet in this file. Check `orchestrator/internal/api/variant_handlers_test.go` and `campaign_crud_test.go` for how existing tests set chi URL params on a bare `httptest.NewRequest` (search for `chi.NewRouteContext` or `chi.RouteCtxKey`); if a shared helper already exists elsewhere in package `api`, reuse it by name instead of redefining it. If none exists, add this to `backup_handlers_test.go`:

```go
func withChiURLParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}
```

adding `"github.com/go-chi/chi/v5"` to the import block if not already present from a prior step.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestCreateRestoreMarker -v`
Expected: FAIL — `h.CreateRestoreMarker undefined`

- [ ] **Step 3: Implement the handler**

Append to `orchestrator/internal/api/backup_handlers.go`:

```go
// POST /api/backups/{id}/restore-marker — records that an admin flagged a
// backup for restore intent. This is pure audit trail: nothing executes
// automatically from this row. The actual restore is always
// `sudo bash install.sh --restore <archive_filename>`, run by a human with
// host access, typing the literal confirmation word RESTORE. See
// docs/superpowers/specs/2026-08-17-backup-recovery-design.md's Restore Flow.
func (h *Handler) CreateRestoreMarker(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()

	var status string
	var archiveFilename *string
	if err := h.db.QueryRow(ctx,
		`SELECT status, archive_filename FROM backup_jobs WHERE id = $1 AND job_type = 'backup'`, id,
	).Scan(&status, &archiveFilename); err != nil {
		jsonError(w, "backup job not found", http.StatusNotFound)
		return
	}
	if archiveFilename == nil || (status != "protected" && status != "local_success") {
		jsonError(w, "backup has not completed successfully -- cannot restore from it", http.StatusConflict)
		return
	}

	var requestedBy *string
	if claims, ok := auth.ClaimsFrom(ctx); ok && claims != nil {
		requestedBy = &claims.UserID
	}
	var markerID string
	if err := h.db.QueryRow(ctx,
		`INSERT INTO backup_jobs (job_type, trigger, requested_by, restore_of_id, status)
		 VALUES ('restore_marker', 'console', $1, $2, 'requested')
		 RETURNING id`,
		requestedBy, id,
	).Scan(&markerID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonOK(w, map[string]string{
		"markerId":       markerID,
		"restoreCommand": "sudo bash install.sh --restore " + *archiveFilename,
	})
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestCreateRestoreMarker -v`
Expected: PASS

- [ ] **Step 5: gofmt, vet, full suite**

Run: `cd orchestrator && gofmt -l internal/api/backup_handlers.go internal/api/backup_handlers_test.go && go vet ./internal/api/...`
Expected: no output from either.

Run full suite in background as in Task 2 Step 6, log to `$SCRATCHPAD/backup_task3_test.log`, read the full log after notification.
Expected: `ok` for `internal/api`, zero FAIL/panic.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/backup_handlers.go orchestrator/internal/api/backup_handlers_test.go
git commit -m "$(cat <<'EOF'
feat(backup): add restore-marker endpoint

Console can flag a backup for restore intent (audit trail only) and
gets back the exact host command to run -- restore itself always
requires a human with root on the host, never the console.
EOF
)"
git push
```

---

### Task 4: Route wiring + RBAC matrix

**Files:**
- Modify: `orchestrator/internal/api/routes.go:356` (insert after the `/api/em/sweeps/{id}/cancel` line)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go:214` (insert after the `/api/em/sweeps/{id}/cancel` entry)

**Interfaces:**
- Consumes: `h.CreateBackupJob`, `h.ListBackupJobs`, `h.GetBackupJob`, `h.CreateRestoreMarker` (Tasks 2-3), `auth.CanManageBackups` (Task 1).

- [ ] **Step 1: Write the failing RBAC matrix entries**

In `orchestrator/internal/api/rbac_matrix_test.go`, change line 214 from:

```go
	{http.MethodPost, "/api/em/sweeps/{id}/cancel", tierPermission, auth.CanCancelScenarioRun},
```

to:

```go
	{http.MethodPost, "/api/em/sweeps/{id}/cancel", tierPermission, auth.CanCancelScenarioRun},

	// Backup & Recovery -- console requests/reads only, admin-only tier.
	{http.MethodPost, "/api/backups", tierPermission, auth.CanManageBackups},
	{http.MethodGet, "/api/backups", tierPermission, auth.CanManageBackups},
	{http.MethodGet, "/api/backups/{id}", tierPermission, auth.CanManageBackups},
	{http.MethodPost, "/api/backups/{id}/restore-marker", tierPermission, auth.CanManageBackups},
```

- [ ] **Step 2: Run to verify it fails (routes not yet mounted)**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix_NoDrift -v`
Expected: FAIL — matrix lists a route not present in the live router.

- [ ] **Step 3: Wire the routes**

In `orchestrator/internal/api/routes.go`, change lines 350-356 from:

```go
		// Endpoint Mastery Full Sweep — server-owned sequential orchestration
		r.With(auth.RequirePermission(auth.CanRunScenario)).Post("/api/em/sweeps", h.CreateEMSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/em/sweeps/active", h.GetActiveEMSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/em/sweeps/{id}", h.GetEMSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/em/sweeps/{id}/runs", h.GetEMSweepRuns)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/em/sweeps", h.ListEMSweeps)
		r.With(auth.RequirePermission(auth.CanCancelScenarioRun)).Post("/api/em/sweeps/{id}/cancel", h.CancelEMSweep)
```

to:

```go
		// Endpoint Mastery Full Sweep — server-owned sequential orchestration
		r.With(auth.RequirePermission(auth.CanRunScenario)).Post("/api/em/sweeps", h.CreateEMSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/em/sweeps/active", h.GetActiveEMSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/em/sweeps/{id}", h.GetEMSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/em/sweeps/{id}/runs", h.GetEMSweepRuns)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/em/sweeps", h.ListEMSweeps)
		r.With(auth.RequirePermission(auth.CanCancelScenarioRun)).Post("/api/em/sweeps/{id}/cancel", h.CancelEMSweep)

		// Backup & Recovery — console requests, host worker executes.
		// See docs/superpowers/specs/2026-08-17-backup-recovery-design.md.
		r.With(auth.RequirePermission(auth.CanManageBackups)).Post("/api/backups", h.CreateBackupJob)
		r.With(auth.RequirePermission(auth.CanManageBackups)).Get("/api/backups", h.ListBackupJobs)
		r.With(auth.RequirePermission(auth.CanManageBackups)).Get("/api/backups/{id}", h.GetBackupJob)
		r.With(auth.RequirePermission(auth.CanManageBackups)).Post("/api/backups/{id}/restore-marker", h.CreateRestoreMarker)
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix_NoDrift -v`
Expected: PASS

- [ ] **Step 5: Full suite, gofmt, vet**

Run: `cd orchestrator && gofmt -l internal/api/routes.go internal/api/rbac_matrix_test.go && go vet ./internal/api/...`
Expected: no output.

Run full suite in background, log to `$SCRATCHPAD/backup_task4_test.log`, read the full log after notification.
Expected: `ok` for `internal/api`, zero FAIL/panic.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "$(cat <<'EOF'
feat(backup): mount /api/backups routes, admin-only

Completes the console-side API surface for Backup & Recovery.
EOF
)"
git push
```

---

### Task 5: Frontend — Settings → Backup & Recovery

**Files:**
- Modify: `orchestrator/wwwroot/index.html:1957-1964` (Settings sub-nav)
- Modify: `orchestrator/wwwroot/index.html:2338-2348` (append new section after `set-license`)
- Modify: `orchestrator/wwwroot/index.html:7186-7199` (`showSettingsSection`)
- Modify: `orchestrator/wwwroot/index.html` (append new JS functions near `loadLicenseInfo`/`_licRow`, ~line 16663)

**Interfaces:**
- Consumes: `GET /api/backups`, `POST /api/backups`, `GET /api/backups/{id}`, `POST /api/backups/{id}/restore-marker` (Tasks 2-4). Existing helpers: `apicall(path, opts)` (`:7226`), `x()` HTML-escape helper (used throughout, e.g. `:16643`), CSS classes `conn-cfg-card`/`conn-cfg-row`/`conn-cfg-label`/`conn-cfg-val`/`sbadge`/`btn btn-outline btn-sm`/`sec-hdr` (existing, used by the License/Audit sections).

- [ ] **Step 1: Add the nav entry**

In `orchestrator/wwwroot/index.html`, change line 1964 from:

```html
            <a class="sset" data-set="license" onclick="showSettingsSection('license')">License</a>
```

to:

```html
            <a class="sset" data-set="license" onclick="showSettingsSection('license')">License</a>
            <a class="sset" data-set="backup" onclick="showSettingsSection('backup')">Backup &amp; Recovery</a>
```

- [ ] **Step 2: Add the section markup**

Change lines 2338-2348 from:

```html
          <div id="set-license" class="set-section" style="display:none">
            <div class="sec-hdr">
              <h2>License</h2>
              <button class="btn btn-outline btn-sm" onclick="loadLicenseInfo()">&#x21bb; Refresh</button>
            </div>
            <div id="license-card-wrap">
              <div class="empty" style="padding:2rem">Loading…</div>
            </div>
          </div>

          </div>
        </div>
      </div>
```

to:

```html
          <div id="set-license" class="set-section" style="display:none">
            <div class="sec-hdr">
              <h2>License</h2>
              <button class="btn btn-outline btn-sm" onclick="loadLicenseInfo()">&#x21bb; Refresh</button>
            </div>
            <div id="license-card-wrap">
              <div class="empty" style="padding:2rem">Loading…</div>
            </div>
          </div>

          <div id="set-backup" class="set-section" style="display:none">
            <div class="sec-hdr">
              <h2>Backup &amp; Recovery</h2>
              <div style="display:flex;gap:0.5rem">
                <button class="btn btn-outline btn-sm" onclick="loadBackups()">&#x21bb; Refresh</button>
                <button class="btn btn-primary btn-sm" id="backup-now-btn" onclick="backupNow()">Backup Now</button>
              </div>
            </div>
            <div style="font-size:0.8rem;color:var(--muted);margin-bottom:1rem">
              Backups are requested here but performed by a host-side service outside this console —
              the app never touches the database dump or server files directly. Restore is host-only
              by design and cannot be triggered from this page.
            </div>
            <div id="backup-status-card-wrap" style="margin-bottom:1.25rem">
              <div class="empty" style="padding:2rem">Loading…</div>
            </div>
            <div class="conn-cfg-card">
              <div style="font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:0.6rem">Available backups</div>
              <table style="width:100%;border-collapse:collapse;font-size:0.8rem">
                <thead>
                  <tr style="text-align:left;color:var(--muted);border-bottom:1px solid var(--border)">
                    <th style="padding:0.4rem 0.5rem">Date</th>
                    <th style="padding:0.4rem 0.5rem">Trigger</th>
                    <th style="padding:0.4rem 0.5rem">Local</th>
                    <th style="padding:0.4rem 0.5rem">Remote</th>
                    <th style="padding:0.4rem 0.5rem">Status</th>
                    <th style="padding:0.4rem 0.5rem">Restore</th>
                  </tr>
                </thead>
                <tbody id="backup-jobs-body">
                  <tr><td colspan="6" style="text-align:center;color:var(--muted);padding:1.5rem">Loading…</td></tr>
                </tbody>
              </table>
            </div>
            <div id="restore-command-wrap"></div>
          </div>

          </div>
        </div>
      </div>
```

- [ ] **Step 3: Wire `showSettingsSection`**

Change line 7187-7199 from:

```javascript
  ['users', 'engine', 'intel', 'art', 'audit', 'theme', 'dashprefs', 'license'].forEach(function(s) {
    var el = document.getElementById('set-' + s);
    if (el) el.style.display = s === name ? '' : 'none';
    var nav = document.querySelector('[data-set="' + s + '"]');
    if (nav) nav.classList.toggle('active', s === name);
  });
  if (name === 'users') loadUsers();
  else if (name === 'engine') loadCalderaStatus();
  else if (name === 'intel') { loadConnectorStatus(); loadThreatIntelConfig('misp'); loadThreatIntelConfig('opencti'); loadThreatIntelConfig('otx'); loadTAXIIConnectors(); loadOpenAEVConfig(); }
  else if (name === 'art') loadARTContentStatus();
  else if (name === 'audit') loadAuditLogs();
  else if (name === 'license') loadLicenseInfo();
  else if (name === 'dashprefs') syncDashPrefCards();
```

to:

```javascript
  ['users', 'engine', 'intel', 'art', 'audit', 'theme', 'dashprefs', 'license', 'backup'].forEach(function(s) {
    var el = document.getElementById('set-' + s);
    if (el) el.style.display = s === name ? '' : 'none';
    var nav = document.querySelector('[data-set="' + s + '"]');
    if (nav) nav.classList.toggle('active', s === name);
  });
  if (name === 'users') loadUsers();
  else if (name === 'engine') loadCalderaStatus();
  else if (name === 'intel') { loadConnectorStatus(); loadThreatIntelConfig('misp'); loadThreatIntelConfig('opencti'); loadThreatIntelConfig('otx'); loadTAXIIConnectors(); loadOpenAEVConfig(); }
  else if (name === 'art') loadARTContentStatus();
  else if (name === 'audit') loadAuditLogs();
  else if (name === 'license') loadLicenseInfo();
  else if (name === 'dashprefs') syncDashPrefCards();
  else if (name === 'backup') loadBackups();
```

- [ ] **Step 4: Add the JS module**

Insert after `_licRow` (after line 16670, right before `function auditPage(dir) {`):

```javascript
var BACKUP_STATUS_LABEL = {
  requested: 'Requested', running: 'Running…', protected: 'Protected',
  local_success: 'Local only', remote_failed: 'Remote failed', failed: 'Failed'
};
var BACKUP_STATUS_COLOR = {
  requested: 'var(--muted)', running: 'var(--accent)', protected: 'var(--success)',
  local_success: 'var(--warning)', remote_failed: 'var(--danger)', failed: 'var(--danger)'
};
var BACKUP_POLL_TIMER = null;

function loadBackups() {
  var wrap = document.getElementById('backup-status-card-wrap');
  var tbody = document.getElementById('backup-jobs-body');
  apicall('/api/backups').then(function(jobs) {
    if (jobs.error) {
      if (wrap) wrap.innerHTML = '<div class="empty" style="padding:2rem;color:var(--danger)">' + x(jobs.error) + '</div>';
      return;
    }
    renderBackupStatusCard(jobs[0] || null);
    renderBackupJobsTable(jobs);
  }).catch(function(e) {
    if (wrap) wrap.innerHTML = '<div class="empty" style="padding:2rem;color:var(--danger)">' + x(e.message) + '</div>';
  });
}

function renderBackupStatusCard(job) {
  var wrap = document.getElementById('backup-status-card-wrap');
  if (!wrap) return;
  if (!job) {
    wrap.innerHTML = '<div class="conn-cfg-card"><div class="empty" style="padding:1rem 0">No backups yet. Click "Backup Now" to create one.</div></div>';
    return;
  }
  var color = BACKUP_STATUS_COLOR[job.status] || 'var(--muted)';
  var label = BACKUP_STATUS_LABEL[job.status] || job.status;
  var size = job.archiveSizeBytes ? (job.archiveSizeBytes / 1048576).toFixed(1) + ' MB' : '—';
  wrap.innerHTML =
    '<div class="conn-cfg-card">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.6rem">' +
        '<div style="font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--muted)">Most recent backup</div>' +
        '<span class="sbadge" style="background:' + color + '22;color:' + color + ';border:1px solid ' + color + '44;font-size:0.7rem;font-weight:700">' + x(label) + '</span>' +
      '</div>' +
      '<div class="conn-cfg-row"><span class="conn-cfg-label">Requested</span><span class="conn-cfg-val">' + x(new Date(job.requestedAt).toLocaleString()) + '</span></div>' +
      '<div class="conn-cfg-row"><span class="conn-cfg-label">Trigger</span><span class="conn-cfg-val">' + x(job.trigger) + '</span></div>' +
      '<div class="conn-cfg-row"><span class="conn-cfg-label">Size</span><span class="conn-cfg-val">' + size + '</span></div>' +
      '<div class="conn-cfg-row"><span class="conn-cfg-label">Local</span><span class="conn-cfg-val">' + (job.localPath ? '✓' : '—') + '</span></div>' +
      '<div class="conn-cfg-row"><span class="conn-cfg-label">Remote</span><span class="conn-cfg-val">' + (job.remotePath ? '✓' : (job.status === 'local_success' ? '✗' : '—')) + '</span></div>' +
      (job.errorMessage ? '<div class="conn-cfg-row"><span class="conn-cfg-label">Error</span><span class="conn-cfg-val" style="color:var(--danger)">' + x(job.errorMessage) + '</span></div>' : '') +
    '</div>';
}

function renderBackupJobsTable(jobs) {
  var tbody = document.getElementById('backup-jobs-body');
  if (!tbody) return;
  if (!jobs.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:1.5rem">No backups yet.</td></tr>';
    return;
  }
  tbody.innerHTML = jobs.map(function(j) {
    var color = BACKUP_STATUS_COLOR[j.status] || 'var(--muted)';
    var label = BACKUP_STATUS_LABEL[j.status] || j.status;
    var canRestore = (j.status === 'protected' || j.status === 'local_success');
    return '<tr style="border-bottom:1px solid var(--border)">' +
      '<td style="padding:0.4rem 0.5rem">' + x(new Date(j.requestedAt).toLocaleString()) + '</td>' +
      '<td style="padding:0.4rem 0.5rem">' + x(j.trigger) + '</td>' +
      '<td style="padding:0.4rem 0.5rem">' + (j.localPath ? '✓' : '—') + '</td>' +
      '<td style="padding:0.4rem 0.5rem">' + (j.remotePath ? '✓' : '—') + '</td>' +
      '<td style="padding:0.4rem 0.5rem"><span class="sbadge" style="background:' + color + '22;color:' + color + ';border:1px solid ' + color + '44;font-size:0.7rem">' + x(label) + '</span></td>' +
      '<td style="padding:0.4rem 0.5rem">' +
        (canRestore ? '<button class="btn btn-outline btn-sm" onclick="prepareRestore(\'' + j.id + '\')">Prepare Restore</button>' : '—') +
      '</td>' +
    '</tr>';
  }).join('');
}

function backupNow() {
  var btn = document.getElementById('backup-now-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Requesting…'; }
  apicall('/api/backups', { method: 'POST' }).then(function(job) {
    if (job.error) { alert('Backup request failed: ' + job.error); if (btn) { btn.disabled = false; btn.textContent = 'Backup Now'; } return; }
    loadBackups();
    pollBackupJob(job.id, btn);
  }).catch(function(e) {
    alert('Backup request failed: ' + e.message);
    if (btn) { btn.disabled = false; btn.textContent = 'Backup Now'; }
  });
}

function pollBackupJob(id, btn) {
  if (BACKUP_POLL_TIMER) clearInterval(BACKUP_POLL_TIMER);
  BACKUP_POLL_TIMER = setInterval(function() {
    apicall('/api/backups/' + id).then(function(job) {
      if (job.error) { clearInterval(BACKUP_POLL_TIMER); return; }
      renderBackupStatusCard(job);
      if (job.status !== 'requested' && job.status !== 'running') {
        clearInterval(BACKUP_POLL_TIMER);
        loadBackups();
        if (btn) { btn.disabled = false; btn.textContent = 'Backup Now'; }
      }
    }).catch(function() { clearInterval(BACKUP_POLL_TIMER); });
  }, 4000);
}

function prepareRestore(id) {
  apicall('/api/backups/' + id + '/restore-marker', { method: 'POST' }).then(function(res) {
    var wrap = document.getElementById('restore-command-wrap');
    if (!wrap) return;
    if (res.error) { wrap.innerHTML = '<div class="empty" style="padding:1rem;color:var(--danger)">' + x(res.error) + '</div>'; return; }
    wrap.innerHTML =
      '<div class="conn-cfg-card" style="margin-top:1rem;border-color:var(--warning)">' +
        '<div style="font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--warning);margin-bottom:0.5rem">Restore must be run on the host</div>' +
        '<div style="font-size:0.8rem;color:var(--muted);margin-bottom:0.6rem">This console cannot and will not run this for you. An administrator with root access to the server must run the command below and type <b>RESTORE</b> to confirm.</div>' +
        '<code style="display:block;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);padding:0.6rem;font-size:0.8rem;word-break:break-all">' + x(res.restoreCommand) + '</code>' +
      '</div>';
  }).catch(function(e) { alert('Failed to prepare restore: ' + e.message); });
}
```

- [ ] **Step 5: Syntax-check the extracted script**

Extract all `<script>` blocks from `orchestrator/wwwroot/index.html` into one file and run `node --check` on it, per this session's established convention:

```bash
node -e "
const fs = require('fs');
const html = fs.readFileSync('orchestrator/wwwroot/index.html', 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
fs.writeFileSync('C:/Users/ADMINI~1/AppData/Local/Temp/claude/backup_ui_check.js', scripts.join('\n\n'));
"
node --check "C:/Users/ADMINI~1/AppData/Local/Temp/claude/backup_ui_check.js"
```

Expected: no output from `node --check` (syntax OK). Use the session's scratchpad path in place of the literal path above.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "$(cat <<'EOF'
feat(backup): add Settings > Backup & Recovery UI

Status card, available-backups table, and a restore panel that only
ever displays the host command -- no button in the console executes
a restore, matching the spec's host-only restore requirement.
EOF
)"
git push
```

---

### Task 6: install.sh — config vars + `.backup_key` generation

**Files:**
- Modify: `packaging/compose/install.sh:108-166` (config variable declarations + `load_config`)
- Modify: `packaging/compose/install.sh:462` area (`mode_install`) — key generation
- Modify: `packaging/compose/install.sh:865-891` (`_write_env`)

**Interfaces:**
- Produces: `${DATA_DIR}/.backup_key` (0600, root:root), and `.env` vars `BACKUP_RETENTION_DAILY`, `BACKUP_RETENTION_WEEKLY`, `BACKUP_RETENTION_MONTHLY`, `BACKUP_SCHEDULE_TIME`, `REMOTE_BACKUP_ENABLED`, `REMOTE_BACKUP_TYPE`, `REMOTE_BACKUP_PATH`, `REMOTE_BACKUP_RETENTION` — consumed by Task 7's engine functions and Task 8's timers.

- [ ] **Step 1: Add config variable declarations and parsing**

In `packaging/compose/install.sh`, change lines 116-120 from:

```bash
ADMIN_PASSWORD=""
LOG_RETENTION_DAYS=""
JWT_SECRET=""
AGENT_SECRET=""
LIC_PATH=""
```

to:

```bash
ADMIN_PASSWORD=""
LOG_RETENTION_DAYS=""
JWT_SECRET=""
AGENT_SECRET=""
LIC_PATH=""
BACKUP_RETENTION_DAILY=""
BACKUP_RETENTION_WEEKLY=""
BACKUP_RETENTION_MONTHLY=""
BACKUP_SCHEDULE_TIME=""
REMOTE_BACKUP_ENABLED=""
REMOTE_BACKUP_TYPE=""
REMOTE_BACKUP_PATH=""
REMOTE_BACKUP_RETENTION=""
```

Change lines 148-150 from:

```bash
      JWT_SECRET)           JWT_SECRET="$val"           ;;
      AGENT_SECRET)         AGENT_SECRET="$val"         ;;
      LIC_PATH)             LIC_PATH="$val"             ;;
```

to:

```bash
      JWT_SECRET)              JWT_SECRET="$val"              ;;
      AGENT_SECRET)            AGENT_SECRET="$val"            ;;
      LIC_PATH)                LIC_PATH="$val"                ;;
      BACKUP_RETENTION_DAILY)   BACKUP_RETENTION_DAILY="$val"   ;;
      BACKUP_RETENTION_WEEKLY)  BACKUP_RETENTION_WEEKLY="$val"  ;;
      BACKUP_RETENTION_MONTHLY) BACKUP_RETENTION_MONTHLY="$val" ;;
      BACKUP_SCHEDULE_TIME)     BACKUP_SCHEDULE_TIME="$val"     ;;
      REMOTE_BACKUP_ENABLED)    REMOTE_BACKUP_ENABLED="$val"    ;;
      REMOTE_BACKUP_TYPE)       REMOTE_BACKUP_TYPE="$val"       ;;
      REMOTE_BACKUP_PATH)       REMOTE_BACKUP_PATH="$val"       ;;
      REMOTE_BACKUP_RETENTION)  REMOTE_BACKUP_RETENTION="$val"  ;;
```

Change line 158 (`[[ -z "$LOG_RETENTION_DAYS" ]] && LOG_RETENTION_DAYS="90"`) to append these defaults right after it:

```bash
  [[ -z "$LOG_RETENTION_DAYS" ]] && LOG_RETENTION_DAYS="90"
  [[ -z "$BACKUP_RETENTION_DAILY"   ]] && BACKUP_RETENTION_DAILY="7"
  [[ -z "$BACKUP_RETENTION_WEEKLY"  ]] && BACKUP_RETENTION_WEEKLY="4"
  [[ -z "$BACKUP_RETENTION_MONTHLY" ]] && BACKUP_RETENTION_MONTHLY="3"
  [[ -z "$BACKUP_SCHEDULE_TIME"     ]] && BACKUP_SCHEDULE_TIME="02:00"
  [[ -z "$REMOTE_BACKUP_ENABLED"    ]] && REMOTE_BACKUP_ENABLED="false"
  [[ -z "$REMOTE_BACKUP_RETENTION"  ]] && REMOTE_BACKUP_RETENTION="30"
```

- [ ] **Step 2: Verify syntax**

Run: `bash -n packaging/compose/install.sh`
Expected: no output (script parses).

- [ ] **Step 3: Add `.backup_key` generation to `mode_install`**

`mode_install` creates `${DATA_DIR}` subdirectories at line 520 (`mkdir -p "${DATA_DIR}"/{data/postgres,logs,backups,scenarios,wwwroot,art-payloads,sharphound}` — note `backups/` already exists in this list from the original install, convenient). Find the line that generates `JWT_SECRET`/`AGENT_SECRET` if not supplied (search `mode_install` for `openssl rand` — likely just before `_write_env` is called) and add `.backup_key` generation immediately after it:

```bash
  # Backup archive encryption key -- generated once, never touches the app
  # container or the database. Losing this file makes existing backups
  # unrecoverable; --status reminds the operator to preserve it.
  if [[ ! -f "${DATA_DIR}/.backup_key" ]]; then
    openssl rand -base64 48 > "${DATA_DIR}/.backup_key"
    chmod 600 "${DATA_DIR}/.backup_key"
    chown root:root "${DATA_DIR}/.backup_key"
  fi
```

Place this call right before the existing `_write_env` call in `mode_install` (the function already writes `.env` last, after all secrets exist — mirror that ordering).

- [ ] **Step 4: Add the new vars to `_write_env`**

Change `packaging/compose/install.sh` lines 886-889 from:

```bash
DATA_DIR=${DATA_DIR}
LOG_RETENTION_DAYS=${LOG_RETENTION_DAYS}
SHARPHOUND_DIR=${DATA_DIR}/sharphound
EOF
```

to:

```bash
DATA_DIR=${DATA_DIR}
LOG_RETENTION_DAYS=${LOG_RETENTION_DAYS}
SHARPHOUND_DIR=${DATA_DIR}/sharphound
BACKUP_RETENTION_DAILY=${BACKUP_RETENTION_DAILY}
BACKUP_RETENTION_WEEKLY=${BACKUP_RETENTION_WEEKLY}
BACKUP_RETENTION_MONTHLY=${BACKUP_RETENTION_MONTHLY}
BACKUP_SCHEDULE_TIME=${BACKUP_SCHEDULE_TIME}
REMOTE_BACKUP_ENABLED=${REMOTE_BACKUP_ENABLED}
REMOTE_BACKUP_TYPE=${REMOTE_BACKUP_TYPE:-}
REMOTE_BACKUP_PATH=${REMOTE_BACKUP_PATH:-}
REMOTE_BACKUP_RETENTION=${REMOTE_BACKUP_RETENTION}
EOF
```

- [ ] **Step 5: Verify syntax again**

Run: `bash -n packaging/compose/install.sh`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add packaging/compose/install.sh
git commit -m "$(cat <<'EOF'
feat(backup): add backup config vars and .backup_key generation

Retention/remote-target settings are ops-layer only (setup.conf),
never exposed as editable console fields. The encryption key is
generated once at install time and never touches the app or DB.
EOF
)"
git push
```

---

### Task 7: install.sh — core backup engine (`mode_backup`)

**Files:**
- Modify: `packaging/compose/install.sh` (add helper functions near `_write_env`/`_wait_healthy`, add `mode_backup`, wire `--backup` flag)

**Interfaces:**
- Consumes: `DATA_DIR`, `POSTGRES_USER`/`POSTGRES_DB` (hardcoded as `bas_user`/`bas_platform` per `_write_env`, matching `docker-compose.yml`), `.backup_key`, `BACKUP_RETENTION_*`/`REMOTE_BACKUP_*` (Task 6).
- Produces: `mode_backup()`, and helpers `_run_pg_dump()`, `_package_config()`, `_write_backup_manifest()`, `_encrypt_backup_archive()`, `_push_remote_backup()`, `_prune_backups()` — consumed by Task 8's worker mode.

- [ ] **Step 1: Add the engine functions**

Insert after `_write_env()` (after line 891, before `_wait_healthy()`):

```bash
# ── Backup & Recovery engine ──────────────────────────────────────────────────
# Shared by `--backup` (run directly) and `--backup-worker` (polls
# backup_jobs for a 'requested' row and calls this same code). See
# docs/superpowers/specs/2026-08-17-backup-recovery-design.md.

_run_pg_dump() {
  local out_file="$1"
  docker exec audspect-postgres pg_dump -U bas_user -Fc bas_platform > "$out_file"
}

_package_config() {
  local out_file="$1"
  tar -cf "$out_file" -C "${DATA_DIR}" \
    --ignore-failed-read \
    .env bas.lic certs scenarios docker-compose.yml 2>/dev/null || true
}

_write_backup_manifest() {
  local out_file="$1" pg_version
  pg_version=$(docker exec audspect-postgres psql -U bas_user -d bas_platform -tAc "SHOW server_version" 2>/dev/null | tr -d '[:space:]')
  cat > "$out_file" << EOF
{
  "basVersion": "${BAS_VERSION}",
  "postgresVersion": "${pg_version}",
  "createdAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "contents": ["postgres/audspect.dump", "config/.env", "config/bas.lic", "config/certs", "config/scenarios", "config/docker-compose.yml"],
  "retention": {
    "dailyDays": ${BACKUP_RETENTION_DAILY},
    "weeklyWeeks": ${BACKUP_RETENTION_WEEKLY},
    "monthlyMonths": ${BACKUP_RETENTION_MONTHLY}
  }
}
EOF
}

_encrypt_backup_archive() {
  local in_file="$1" out_file="$2"
  openssl enc -aes-256-cbc -pbkdf2 -salt -in "$in_file" -out "$out_file" -pass "file:${DATA_DIR}/.backup_key"
}

# _push_remote_backup copies the finished local archive to REMOTE_BACKUP_PATH.
# REMOTE_BACKUP_TYPE=mount assumes the operator already mounted the remote
# filesystem (NFS/SMB) at that path -- this function only copies into it.
# REMOTE_BACKUP_TYPE=rsync treats REMOTE_BACKUP_PATH as an rsync destination
# (local path or user@host:/path). Returns non-zero on failure; callers must
# not report "protected" unless this returns 0.
_push_remote_backup() {
  local archive="$1"
  [[ "$REMOTE_BACKUP_ENABLED" == "true" ]] || return 1
  [[ -n "$REMOTE_BACKUP_PATH" ]] || return 1
  case "$REMOTE_BACKUP_TYPE" in
    mount) cp "$archive" "${REMOTE_BACKUP_PATH}/" ;;
    rsync) rsync -a "$archive" "${REMOTE_BACKUP_PATH}/" ;;
    *) return 1 ;;
  esac
}

# _prune_backups keeps every archive within BACKUP_RETENTION_DAILY days,
# thins to one-per-week for BACKUP_RETENTION_WEEKLY weeks after that, one-
# per-month for BACKUP_RETENTION_MONTHLY months after that, deletes the rest.
_prune_backups() {
  local dir="${DATA_DIR}/backups"
  local daily_cutoff weekly_cutoff monthly_cutoff
  daily_cutoff=$(date -d "-${BACKUP_RETENTION_DAILY} days" +%s 2>/dev/null || date -v-"${BACKUP_RETENTION_DAILY}"d +%s)
  weekly_cutoff=$(date -d "-$((BACKUP_RETENTION_WEEKLY * 7)) days" +%s 2>/dev/null || date -v-"$((BACKUP_RETENTION_WEEKLY * 7))"d +%s)
  monthly_cutoff=$(date -d "-$((BACKUP_RETENTION_MONTHLY * 30)) days" +%s 2>/dev/null || date -v-"$((BACKUP_RETENTION_MONTHLY * 30))"d +%s)

  local seen_weeks="" seen_months=""
  for f in $(ls -1t "${dir}"/audspect-backup-*.tar.enc 2>/dev/null); do
    local mtime week_key month_key
    mtime=$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f")
    [[ "$mtime" -ge "$daily_cutoff" ]] && continue
    week_key=$(date -d "@$mtime" +%G-%V 2>/dev/null || date -r "$mtime" +%G-%V)
    month_key=$(date -d "@$mtime" +%Y-%m 2>/dev/null || date -r "$mtime" +%Y-%m)
    if [[ "$mtime" -ge "$weekly_cutoff" ]]; then
      if [[ "$seen_weeks" == *"|${week_key}|"* ]]; then rm -f "$f"; else seen_weeks="${seen_weeks}|${week_key}|"; fi
    elif [[ "$mtime" -ge "$monthly_cutoff" ]]; then
      if [[ "$seen_months" == *"|${month_key}|"* ]]; then rm -f "$f"; else seen_months="${seen_months}|${month_key}|"; fi
    else
      rm -f "$f"
    fi
  done
}

# _run_backup_engine performs one full backup and prints the result as
# "STATUS|filename|size_bytes|sha256|local_path|remote_path|error" so both
# mode_backup (human-readable) and mode_backup_worker (writes to
# backup_jobs) can consume the same run.
_run_backup_engine() {
  local ts archive_dir work_dir tar_path enc_path status="protected" error=""
  ts=$(date -u +%Y%m%d-%H%M%S)
  archive_dir="${DATA_DIR}/backups"
  work_dir=$(mktemp -d)
  mkdir -p "${work_dir}/postgres" "${work_dir}/config"

  if ! _run_pg_dump "${work_dir}/postgres/audspect.dump"; then
    echo "FAILED|||||pg_dump failed"; rm -rf "$work_dir"; return 1
  fi
  _package_config "${work_dir}/config.tar"
  _write_backup_manifest "${work_dir}/manifest.json"

  tar_path="${work_dir}/audspect-backup-${ts}.tar"
  tar -cf "$tar_path" -C "$work_dir" postgres/audspect.dump config.tar manifest.json

  enc_path="${archive_dir}/audspect-backup-${ts}.tar.enc"
  if ! _encrypt_backup_archive "$tar_path" "$enc_path"; then
    echo "FAILED|||||encryption failed"; rm -rf "$work_dir"; return 1
  fi

  local size sha
  size=$(stat -c %s "$enc_path" 2>/dev/null || stat -f %z "$enc_path")
  sha=$(sha256sum "$enc_path" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$enc_path" | awk '{print $1}')
  echo "$sha" > "${enc_path}.sha256"

  local remote_path=""
  if [[ "$REMOTE_BACKUP_ENABLED" == "true" ]]; then
    if _push_remote_backup "$enc_path"; then
      remote_path="${REMOTE_BACKUP_PATH}/$(basename "$enc_path")"
    else
      status="local_success"
      error="local backup succeeded, remote replication failed"
    fi
  else
    status="local_success"
  fi

  _prune_backups
  rm -rf "$work_dir"
  echo "${status}|$(basename "$enc_path")|${size}|${sha}|${enc_path}|${remote_path}|${error}"
}

mode_backup() {
  [[ -f "${DATA_DIR}/docker-compose.yml" ]] || { err "No installation found at ${DATA_DIR}."; exit 1; }
  step "Running backup..."
  local result
  result=$(_run_backup_engine)
  IFS='|' read -r status filename size sha local_path remote_path error <<< "$result"
  if [[ "$status" == "FAILED" ]]; then
    err "Backup failed: ${error}"
    exit 1
  fi
  log "Backup complete: ${filename} (${size} bytes, status=${status})"
  [[ -n "$error" ]] && info "$error"
}
```

- [ ] **Step 2: Wire the `--backup` flag**

Change line 84 (`--uninstall)    MODE="uninstall" ;;`) to add a sibling case:

```bash
    --uninstall)    MODE="uninstall" ;;
    --backup)       MODE="backup"    ;;
```

Change line 973 (`uninstall) mode_uninstall ;;`) to add a sibling case:

```bash
  uninstall) mode_uninstall ;;
  backup)    mode_backup    ;;
```

- [ ] **Step 3: Verify syntax**

Run: `bash -n packaging/compose/install.sh`
Expected: no output.

- [ ] **Step 4: Manual smoke test (requires a running install)**

If a dev/test install is available: `sudo bash install.sh --backup`, then check `${DATA_DIR}/backups/` for a new `audspect-backup-<timestamp>.tar.enc` and matching `.sha256` file, and confirm `openssl enc -d -aes-256-cbc -pbkdf2 -in <archive> -out /tmp/check.tar -pass file:${DATA_DIR}/.backup_key && tar -tf /tmp/check.tar` lists `postgres/audspect.dump`, `config.tar`, `manifest.json`. This plan does not assume such an install exists in this environment — if unavailable, defer this check to Task 10's end-to-end pass and proceed.

- [ ] **Step 5: Commit**

```bash
git add packaging/compose/install.sh
git commit -m "$(cat <<'EOF'
feat(backup): add mode_backup -- the core pg_dump + config + encrypt engine

sudo bash install.sh --backup now produces an encrypted, timestamped
archive under DATA_DIR/backups, pruned per the configured retention
policy, with an optional remote push. Shared by --backup-worker in
the next commit so console-requested and scheduled backups run
through identical code.
EOF
)"
git push
```

---

### Task 8: install.sh — `mode_backup_request` + `mode_backup_worker` + systemd timers

**Files:**
- Modify: `packaging/compose/install.sh` (add `mode_backup_request`, `mode_backup_worker`, wire flags, add systemd unit writers, wire into `mode_install`)

**Interfaces:**
- Consumes: `_run_backup_engine` (Task 7), `_write_systemd_unit` pattern (existing, line 838).
- Produces: `audspect-backup-worker.service`/`.timer`, `audspect-backup-schedule.service`/`.timer` — installed by `mode_install`, unified execution path for console/scheduled/CLI-triggered backups (spec's core architectural requirement).

- [ ] **Step 1: Add `mode_backup_request` and `mode_backup_worker`**

Insert after `mode_backup()` (Task 7):

```bash
# mode_backup_request inserts one 'requested' row and exits -- it never
# performs a backup itself. Called by audspect-backup-schedule.timer (daily)
# and directly for CLI-triggered scheduling tests.
mode_backup_request() {
  local trigger="${TRIGGER:-cli}"
  docker exec audspect-postgres psql -U bas_user -d bas_platform -tAc \
    "INSERT INTO backup_jobs (job_type, trigger) VALUES ('backup', '${trigger}')" >/dev/null
}

# mode_backup_worker performs exactly one poll-and-execute pass: claim the
# oldest 'requested' backup row (if any), run the same engine as --backup,
# write the result back. Called every 60s by audspect-backup-worker.timer --
# this is what makes console-requested, scheduled, and CLI-requested backups
# all execute through one path.
mode_backup_worker() {
  local id
  id=$(docker exec audspect-postgres psql -U bas_user -d bas_platform -tAc \
    "SELECT id FROM backup_jobs WHERE status = 'requested' AND job_type = 'backup' ORDER BY requested_at LIMIT 1" 2>/dev/null | tr -d '[:space:]')
  [[ -z "$id" ]] && return 0

  local claimed
  claimed=$(docker exec audspect-postgres psql -U bas_user -d bas_platform -tAc \
    "UPDATE backup_jobs SET status = 'running', started_at = now() WHERE id = '${id}' AND status = 'requested' RETURNING id" 2>/dev/null | tr -d '[:space:]')
  [[ -z "$claimed" ]] && return 0  # lost the race to another worker instance

  local result status filename size sha local_path remote_path error
  result=$(_run_backup_engine)
  IFS='|' read -r status filename size sha local_path remote_path error <<< "$result"
  if [[ "$status" == "FAILED" ]]; then status="failed"; fi

  docker exec audspect-postgres psql -U bas_user -d bas_platform -c "
    UPDATE backup_jobs SET
      status = '${status}',
      finished_at = now(),
      archive_filename = NULLIF('${filename}', ''),
      archive_size_bytes = NULLIF('${size}', '')::bigint,
      sha256 = NULLIF('${sha}', ''),
      local_path = NULLIF('${local_path}', ''),
      remote_path = NULLIF('${remote_path}', ''),
      error_message = NULLIF('${error}', '')
    WHERE id = '${claimed}'
  " >/dev/null
}
```

- [ ] **Step 2: Wire the two new flags**

Extend the case block from Task 7 Step 2:

```bash
    --backup)          MODE="backup"          ;;
    --backup-request)  MODE="backup-request"  ;;
    --backup-worker)   MODE="backup-worker"   ;;
```

And the dispatch block:

```bash
  backup)         mode_backup         ;;
  backup-request) mode_backup_request ;;
  backup-worker)  mode_backup_worker  ;;
```

- [ ] **Step 3: Add the systemd unit writer and wire it into `mode_install`**

Following the exact pattern of `_write_systemd_unit()` (line 838), add:

```bash
_write_backup_systemd_units() {
  cat > /etc/systemd/system/audspect-backup-worker.service << EOF
[Unit]
Description=Audspect backup worker (executes requested backup_jobs rows)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
WorkingDirectory=${DATA_DIR}
ExecStart=/usr/bin/env bash ${DATA_DIR}/install.sh --backup-worker
EOF
  chmod 644 /etc/systemd/system/audspect-backup-worker.service

  cat > /etc/systemd/system/audspect-backup-worker.timer << 'EOF'
[Unit]
Description=Poll backup_jobs every 60s

[Timer]
OnUnitActiveSec=60s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF
  chmod 644 /etc/systemd/system/audspect-backup-worker.timer

  cat > /etc/systemd/system/audspect-backup-schedule.service << EOF
[Unit]
Description=Audspect scheduled backup request (inserts one requested row)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
Environment=TRIGGER=scheduled
WorkingDirectory=${DATA_DIR}
ExecStart=/usr/bin/env bash ${DATA_DIR}/install.sh --backup-request
EOF
  chmod 644 /etc/systemd/system/audspect-backup-schedule.service

  cat > /etc/systemd/system/audspect-backup-schedule.timer << EOF
[Unit]
Description=Daily scheduled backup trigger

[Timer]
OnCalendar=*-*-* ${BACKUP_SCHEDULE_TIME}:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
  chmod 644 /etc/systemd/system/audspect-backup-schedule.timer

  systemctl daemon-reload
  systemctl enable --now audspect-backup-worker.timer audspect-backup-schedule.timer
}
```

Note: `install.sh` itself must be present at `${DATA_DIR}/install.sh` for these units' `ExecStart` to work — `mode_install` already copies the compose bundle into `DATA_DIR`; add `cp "${SCRIPT_DIR}/install.sh" "${DATA_DIR}/install.sh"` alongside the existing `cp "${SCRIPT_DIR}/docker-compose.yml" "${DATA_DIR}/docker-compose.yml"` at line 576, and the same in `mode_upgrade` at its equivalent line 638.

In `mode_install`, immediately after the existing `_write_systemd_unit` call (line 580 `_write_systemd_unit`), add:

```bash
  step "8b/10  Installing backup worker + schedule timers"
  _write_backup_systemd_units
```

- [ ] **Step 4: Verify syntax**

Run: `bash -n packaging/compose/install.sh`
Expected: no output.

- [ ] **Step 5: Manual smoke test (requires a running install)**

If available: `sudo bash install.sh --backup-request`, then check `docker exec audspect-postgres psql -U bas_user -d bas_platform -c "SELECT status, trigger FROM backup_jobs ORDER BY requested_at DESC LIMIT 1"` shows a `requested`/`cli` row; wait up to 60s (or run `sudo bash install.sh --backup-worker` directly) and confirm the row transitions to `local_success` or `protected` with `archive_filename` set. Defer to Task 10 if no install is available now.

- [ ] **Step 6: Commit**

```bash
git add packaging/compose/install.sh
git commit -m "$(cat <<'EOF'
feat(backup): add backup_jobs worker + daily scheduler as systemd timers

Unifies console-requested, scheduled, and CLI-triggered backups
through one execution path: --backup-request only decides a backup
should happen, --backup-worker (polled every 60s) is the only thing
that ever performs one.
EOF
)"
git push
```

---

### Task 9: install.sh — `mode_restore`

**Files:**
- Modify: `packaging/compose/install.sh` (add `mode_restore`, wire flag)

**Interfaces:**
- Consumes: `_run_backup_engine` (Task 7, for the mandatory pre-restore snapshot), `.backup_key`, `DATA_DIR` layout.

- [ ] **Step 1: Add `mode_restore`**

Insert after `mode_backup_worker()`:

```bash
# mode_restore is the only place a restore ever actually executes. Requires
# root, an existing archive under DATA_DIR/backups (or an absolute path),
# and the literal word RESTORE typed at the confirmation prompt -- mirrors
# this script's other destructive-op confirmations (see mode_uninstall).
mode_restore() {
  local archive="$1"
  [[ -z "$archive" ]] && { err "Usage: sudo bash install.sh --restore <archive-filename-or-path>"; exit 1; }
  [[ "$archive" != /* ]] && archive="${DATA_DIR}/backups/${archive}"
  [[ -f "$archive" ]] || { err "Archive not found: ${archive}"; exit 1; }

  step "1/8  Verifying archive integrity"
  if [[ -f "${archive}.sha256" ]]; then
    local expected actual
    expected=$(cat "${archive}.sha256")
    actual=$(sha256sum "$archive" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$archive" | awk '{print $1}')
    [[ "$expected" == "$actual" ]] || { err "Checksum mismatch -- archive may be corrupt. Refusing to restore."; exit 1; }
  else
    info "No .sha256 sidecar found for this archive -- skipping integrity check."
  fi

  step "2/8  Decrypting and reading manifest"
  local work_dir tar_path
  work_dir=$(mktemp -d)
  tar_path="${work_dir}/archive.tar"
  openssl enc -d -aes-256-cbc -pbkdf2 -in "$archive" -out "$tar_path" -pass "file:${DATA_DIR}/.backup_key" \
    || { err "Decryption failed -- wrong .backup_key or corrupt archive."; rm -rf "$work_dir"; exit 1; }
  tar -xf "$tar_path" -C "$work_dir"
  [[ -f "${work_dir}/manifest.json" ]] || { err "Archive missing manifest.json -- refusing to restore."; rm -rf "$work_dir"; exit 1; }
  local archive_version
  archive_version=$(grep -o '"basVersion"[^,]*' "${work_dir}/manifest.json" | grep -o '"[^"]*"$' | tr -d '"')
  info "Archive BAS version: ${archive_version:-unknown}. Installed: ${BAS_VERSION}."

  echo
  echo "  This will STOP Audspect, REPLACE the current database and configuration"
  echo "  with the contents of ${archive}, then restart."
  echo
  read -r -p "  Type RESTORE to continue: " confirm
  [[ "$confirm" == "RESTORE" ]] || { info "Aborted -- no changes made."; rm -rf "$work_dir"; exit 0; }

  step "3/8  Taking a pre-restore safety snapshot"
  TRIGGER=pre_restore _run_backup_engine >/dev/null || info "Pre-restore snapshot failed -- continuing anyway (you typed RESTORE)."

  step "4/8  Stopping services"
  (cd "${DATA_DIR}" && docker compose -p "$COMPOSE_PROJECT" stop orchestrator caldera chrome)

  step "5/8  Restoring PostgreSQL"
  docker exec -i audspect-postgres pg_restore -U bas_user -d bas_platform --clean --if-exists < "${work_dir}/postgres/audspect.dump" \
    || { err "pg_restore failed -- database may be in a partial state. The pre-restore snapshot is at ${DATA_DIR}/backups/ if you need to recover from before this attempt."; rm -rf "$work_dir"; exit 1; }

  step "6/8  Restoring configuration"
  tar -xf "${work_dir}/config.tar" -C "${DATA_DIR}"

  step "7/8  Starting services"
  (cd "${DATA_DIR}" && docker compose -p "$COMPOSE_PROJECT" up -d --remove-orphans)
  _wait_healthy

  step "8/8  Health check"
  if curl -fsSk "https://localhost:${BAS_PORT:-9443}/health" >/dev/null 2>&1 || curl -fs "http://localhost:${BAS_PORT:-9443}/health" >/dev/null 2>&1; then
    log "Restore complete and healthy."
  else
    err "Restore finished but health check failed -- inspect 'docker compose logs orchestrator'."
  fi
  rm -rf "$work_dir"
}
```

- [ ] **Step 2: Wire the `--restore` flag**

`--restore` needs its archive argument, unlike the other flags. Add alongside the existing flag-parsing loop (near line 80-90, following the pattern used for `--config <file>` which also consumes a following argument — search for how `CONFIG_FILE` is captured from `--config` and mirror it):

```bash
    --restore)
      MODE="restore"
      shift
      RESTORE_ARCHIVE="${1:-}"
      ;;
```

Declare `RESTORE_ARCHIVE=""` alongside the other top-level variable declarations (Task 6 Step 1's block), and change the dispatch block to:

```bash
  restore) mode_restore "$RESTORE_ARCHIVE" ;;
```

- [ ] **Step 3: Verify syntax**

Run: `bash -n packaging/compose/install.sh`
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add packaging/compose/install.sh
git commit -m "$(cat <<'EOF'
feat(backup): add mode_restore -- host-only, confirmation-gated restore

Verifies archive integrity and manifest, takes a pre-restore safety
snapshot, stops services, pg_restores, restores config, restarts, and
health-checks. Requires typing RESTORE -- never auto-executed by the
worker, matching the spec's explicit backup/restore asymmetry.
EOF
)"
git push
```

---

### Task 10: End-to-end verification

**Files:** none (verification only)

- [ ] **Step 1: Full Go suite, one last time**

Run the complete `internal/api`, `internal/auth`, and `internal/db` suites in background (`-timeout 25m`), log to `$SCRATCHPAD/backup_final_test.log`, read the full log after notification.
Expected: `ok` for all three packages, zero FAIL/panic.

- [ ] **Step 2: Full `bash -n` pass**

Run: `bash -n packaging/compose/install.sh`
Expected: no output.

- [ ] **Step 3: JS syntax check, one last time**

Repeat Task 5 Step 5's extraction + `node --check` against the final state of `index.html`.
Expected: no output.

- [ ] **Step 4: Manual end-to-end walkthrough (requires a scratch VM or dev install — not assumed available in this session)**

Document this as the deferred manual step per the spec's Testing Strategy, to run whenever a scratch install is available:

1. `sudo bash install.sh --install --config setup.conf` on a scratch VM.
2. Log into the console, run a scenario or two so there's real data in Postgres.
3. In Settings → Backup & Recovery, click "Backup Now"; confirm the status card moves from "Requested" → "Running…" → "Protected"/"Local only" within ~60-90s (worker timer interval + engine runtime).
4. `sudo bash install.sh --status` to confirm `audspect-backup-worker.timer` and `audspect-backup-schedule.timer` are both active.
5. In the console, click "Prepare Restore" on that backup; confirm the exact `install.sh --restore <filename>` command is displayed and copyable, and that nothing in the console executed anything.
6. `sudo bash install.sh --uninstall` (or wipe the VM), then `--install` fresh.
7. `sudo bash install.sh --restore <filename copied from step 5>`, type `RESTORE`, confirm it completes and the previously-run scenario's data is back in the console.

Report the outcome of this walkthrough back before considering the feature fully verified — everything through Step 3 above only proves the code is syntactically and unit-correct, not that a real backup/restore round-trip preserves data.

---

## Execution Handoff

This session's established preference is inline execution (not subagent-driven) — tasks are run directly in this session per prior feedback. Confirm before starting: proceed with `superpowers:executing-plans` inline, or switch to subagent-driven for this one?
