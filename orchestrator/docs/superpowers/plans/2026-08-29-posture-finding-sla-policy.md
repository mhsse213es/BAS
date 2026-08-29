# Posture Finding SLA Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every open `posture_findings` row a deadline (via a severity-keyed, admin-editable policy), and detect + notify the moment that deadline is missed.

**Architecture:** Two new tables (`sla_policy`, `finding_slas`) plus a tiny pure-function package (`internal/slapolicy`). The write path hooks into Sub-project A's existing `applyPostureFinding` transition switch to start/resolve an SLA clock synchronously with the finding's own lifecycle transition. A new 5-minute background tick (mirroring the existing `jobsDispatcher.Tick` pattern) scans for clocks past their deadline, flips them to `breached`, and emits a `notifications.Event`.

**Tech Stack:** Go, Postgres (via `pgxpool`), the existing `internal/notifications` service, `exercise.PollScheduler` for the background tick, chi router, testcontainers-backed Go tests (no live dev server or browser needed anywhere in this plan).

**Spec:** `orchestrator/docs/superpowers/specs/2026-08-29-posture-finding-sla-policy-design.md`

## Global Constraints

- Build directly on `main` — no worktree, no branches/PRs (established repo convention).
- Commit after each task with a clear message; push immediately after every commit.
- SLA policy keys exclusively on `severity` — never `category`.
- `sla_policy` edits only affect *future* `finding_slas` rows — an existing row's `deadline_at` is captured once at creation and never recomputed.
- Scope is `posture_findings` only — no BAS-finding SLA, no polymorphic `finding_type`/`finding_id` reference.
- Every task must be verifiable via `go test` against testcontainers Postgres — no `wwwroot`/browser/live-agent dependency anywhere in this plan.

---

### Task 1: Per-check severity data

**Files:**
- Modify: `orchestrator/internal/api/endpointrisk_aggregations.go:106-129`
- Modify: `orchestrator/internal/api/posture_finding_handlers.go:123-131` (the `tr == findings.Created` INSERT)
- Test: `orchestrator/internal/api/posture_finding_handlers_test.go`

**Interfaces:**
- Produces: `postureCheckFindingText[checkID].Severity string` — one of `"Critical"`/`"High"`/`"Medium"`/`"Low"`, populated for all 20 existing keys. Later tasks (4, 5, 6) read/validate against exactly these 4 string values.

**Context:** `posture_findings.severity` currently always ends up `'Medium'` — the column default, never explicitly set on `INSERT`. Since Sub-project B's SLA policy keys on severity, this must be fixed first or the whole feature is inert.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/posture_finding_handlers_test.go` (same file Sub-project A's lifecycle tests live in — reuse its existing `newPostureTestHandler`/`seedPostureCheckRun` helpers exactly as they are):

```go
func TestUpsertPostureFindingsForRun_PersistsPerCheckSeverity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)

		// seedPostureCheckRun (defined earlier in this file, Sub-project A)
		// hardcodes check_id="windows-firewall-enabled" -- its severity per
		// Task 1's table is "High".
		seedPostureCheckRun(t, pool, "sev-run-high", "sev-agent", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "sev-run-high")

		var severity string
		if err := pool.QueryRow(context.Background(),
			`SELECT severity FROM posture_findings WHERE agent_id='sev-agent' AND check_id='windows-firewall-enabled'`,
		).Scan(&severity); err != nil {
			t.Fatalf("query: %v", err)
		}
		if severity != "High" {
			t.Fatalf("severity = %q, want High (was defaulting to Medium before this fix)", severity)
		}
	})
}
```

`seedPostureCheckRun` (confirmed real, `posture_finding_handlers_test.go:36`) seeds the agent itself via its own internal `ON CONFLICT DO NOTHING` insert, so no separate `mustExecAPI` agent-seed call is needed before calling it — it hardcodes `check_id="windows-firewall-enabled"` and only takes `(t, pool, runID, agentID, result, at)`, no check_id parameter.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestUpsertPostureFindingsForRun_PersistsPerCheckSeverity -v`
Expected: FAIL — `severity = "Medium", want High`

- [ ] **Step 3: Add the Severity field and values**

Replace the `postureCheckFindingText` var in `orchestrator/internal/api/endpointrisk_aggregations.go` (lines 106-129) with:

```go
// postureCheckFindingText holds the static per-check_id copy (description,
// expected/observed values, remediation, reference, severity) used to build
// a Finding without inventing anything from raw command output. Keyed by
// check_id; shared across Security Configuration and Identity since a
// check_id is unique across both categories. Severity is assigned by actual
// security impact (direct remote-exploitation/auth-bypass/disabled-defense
// checks rank High/Critical; hardening/hygiene checks rank Medium; pure
// staleness checks with no specific known-exploitable gap rank Low) -- see
// docs/superpowers/specs/2026-08-29-posture-finding-sla-policy-design.md's
// Background section for the full rationale table.
var postureCheckFindingText = map[string]struct {
	Title, Description, Expected, Observed, Remediation, Reference, Severity string
}{
	"windows-firewall-enabled":            {"Windows Firewall disabled", "Windows Firewall must be enabled for the Domain, Private, and Public profiles.", "Enabled", "Disabled", "Enable Windows Firewall for all profiles.", "Microsoft Security Baseline", "High"},
	"windows-defender-realtime":           {"Defender real-time protection disabled", "Windows Defender's real-time protection must be active.", "Enabled", "Disabled", "Enable Windows Defender real-time protection.", "Microsoft Security Baseline", "High"},
	"windows-bitlocker-enabled":           {"BitLocker not enabled", "The system volume should be encrypted with BitLocker.", "On", "Off", "Enable BitLocker on the system volume.", "CIS Microsoft Windows Benchmark", "High"},
	"windows-rdp-nla-required":            {"RDP exposed without NLA", "RDP, if enabled, must require Network Level Authentication.", "Disabled or NLA required", "Enabled without NLA", "Disable RDP or require NLA.", "CIS Microsoft Windows Benchmark", "High"},
	"windows-smbv1-disabled":              {"SMBv1 enabled", "The legacy, vulnerable SMBv1 protocol must be disabled.", "Disabled", "Enabled", "Disable the SMB1Protocol Windows feature.", "Microsoft Security Baseline", "High"},
	"windows-guest-account-disabled":      {"Guest account enabled", "The built-in Guest account must be disabled.", "Disabled", "Enabled", "Disable the local Guest account.", "CIS Microsoft Windows Benchmark", "Medium"},
	"windows-local-admin-count":           {"Excess local administrators", "Local Administrators group membership should be minimal.", "<= 2 members", "> 2 members", "Review and remove unnecessary local administrator accounts.", "CIS Microsoft Windows Benchmark", "High"},
	"windows-password-min-length":         {"Weak minimum password length", "Minimum password length should be at least 12 characters.", ">= 12", "< 12", "Increase the minimum password length to 12+.", "CIS Microsoft Windows Benchmark", "Medium"},
	"windows-password-max-age":            {"Password max age out of policy", "Maximum password age should be 90 days or fewer.", "1-90 days", "Out of range", "Set maximum password age to 90 days or fewer.", "CIS Microsoft Windows Benchmark", "Low"},
	"windows-account-lockout-threshold":   {"Account lockout threshold not configured", "Account lockout threshold should be between 1 and 10 attempts.", "1-10", "Not configured", "Configure an account lockout threshold.", "CIS Microsoft Windows Benchmark", "Medium"},
	"linux-firewall-enabled":              {"UFW firewall not confirmed active", "The UFW firewall should be active.", "active", "inactive", "Enable UFW (ufw enable).", "CIS Ubuntu Benchmark", "High"},
	"linux-apparmor-enabled":              {"AppArmor not enforcing", "AppArmor should be enabled and enforcing.", "enforcing", "not enforcing", "Enable and enforce AppArmor profiles.", "CIS Ubuntu Benchmark", "Medium"},
	"linux-ssh-root-login-disabled":       {"SSH root login permitted", "SSH root login should be disabled.", "PermitRootLogin no", "permitted", "Set PermitRootLogin no in sshd_config.", "CIS Ubuntu Benchmark", "High"},
	"linux-ssh-empty-passwords-forbidden": {"SSH empty passwords permitted", "SSH must not allow empty passwords.", "PermitEmptyPasswords no", "permitted", "Set PermitEmptyPasswords no in sshd_config.", "CIS Ubuntu Benchmark", "Critical"},
	"linux-password-min-length":           {"Weak minimum password length", "Minimum password length should be at least 12 characters.", ">= 12", "< 12", "Set PASS_MIN_LEN 12 in /etc/login.defs.", "CIS Ubuntu Benchmark", "Medium"},
	"linux-password-max-age":              {"Password max age out of policy", "Maximum password age should be 365 days or fewer.", "<= 365", "> 365", "Set PASS_MAX_DAYS 365 in /etc/login.defs.", "CIS Ubuntu Benchmark", "Low"},
	"linux-no-empty-password-accounts":    {"Accounts with empty passwords found", "No account should have an empty password.", "none", "one or more found", "Set a password or lock the affected account(s).", "CIS Ubuntu Benchmark", "Critical"},
	"windows-last-patch-age":              {"Last patch overdue", "The last installed security update should be within 30 days.", "<= 30 days", "> 30 days or unknown", "Install pending Windows Updates.", "SEBI CSCRF", "Medium"},
	"linux-pending-security-updates":      {"Pending security updates", "No pending security updates should be outstanding.", "0 pending", "1 or more pending", "Run apt upgrade to install pending security updates.", "SEBI CSCRF", "Medium"},
	"linux-last-patch-age":                {"Last patch overdue", "The last installed patch should be within 30 days.", "<= 30 days", "> 30 days", "Run apt upgrade regularly to keep patches current.", "SEBI CSCRF", "Medium"},
}
```

(This struct literal has 20 entries — same 20 keys as before, just each gaining a 7th field. Do not add or remove any key.)

- [ ] **Step 4: Set severity on INSERT in `applyPostureFinding`**

In `orchestrator/internal/api/posture_finding_handlers.go`, find the `tr == findings.Created` block (lines 123-131):

```go
	if tr == findings.Created {
		text := postureCheckFindingText[a.checkID]
		_, _ = h.db.Exec(ctx,
			`INSERT INTO posture_findings (agent_id, check_id, category, title, exposure_state, status,
			        occurrence_count, last_run_id, first_seen, last_seen, last_observed_at)
			 VALUES ($1,$2,$3,$4,$5,'open',1,$6,NOW(),NOW(),$7)
			 ON CONFLICT (agent_id, check_id) DO NOTHING`,
			agentID, a.checkID, a.category, text.Title, next.ExposureState, o.RunID, o.ObservedAt)
		return
	}
```

Replace with (adds `severity` column + value, with a defensive fallback if a check_id is somehow absent from the map):

```go
	if tr == findings.Created {
		text := postureCheckFindingText[a.checkID]
		severity := text.Severity
		if severity == "" {
			severity = "Medium"
		}
		_, _ = h.db.Exec(ctx,
			`INSERT INTO posture_findings (agent_id, check_id, category, title, severity, exposure_state, status,
			        occurrence_count, last_run_id, first_seen, last_seen, last_observed_at)
			 VALUES ($1,$2,$3,$4,$5,$6,'open',1,$7,NOW(),NOW(),$8)
			 ON CONFLICT (agent_id, check_id) DO NOTHING`,
			agentID, a.checkID, a.category, text.Title, severity, next.ExposureState, o.RunID, o.ObservedAt)
		return
	}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestUpsertPostureFindingsForRun_PersistsPerCheckSeverity -v`
Expected: PASS

- [ ] **Step 6: Run the full existing posture-finding test suite to confirm no regression**

Run: `cd orchestrator && go test ./internal/api/... -run 'PostureFinding' -v`
Expected: all PASS (Sub-project A's 10 existing tests plus this new one)

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/endpointrisk_aggregations.go orchestrator/internal/api/posture_finding_handlers.go orchestrator/internal/api/posture_finding_handlers_test.go
git commit -m "feat: assign per-check severity to posture findings

posture_findings.severity was always the column default 'Medium' --
never set per-check. Adds a Severity field to postureCheckFindingText
(all 20 checks, ranked by actual security impact) and sets it on
INSERT. Prerequisite for a severity-keyed SLA policy."
git push
```

---

### Task 2: `internal/slapolicy` domain package

**Files:**
- Create: `orchestrator/internal/slapolicy/slapolicy.go`
- Test: `orchestrator/internal/slapolicy/slapolicy_test.go`

**Interfaces:**
- Produces: `slapolicy.Policy{Severity string, DurationHours int}`, `slapolicy.DeadlineFor(policy Policy, startedAt time.Time) time.Time`, `slapolicy.EvaluateSLABreach(deadlineAt, now time.Time) bool`. Tasks 4 and 5 call both functions; Task 6 constructs `Policy` values from `sla_policy` table rows.

No container needed for this task — pure functions, no DB/network dependency.

- [ ] **Step 1: Write the failing tests**

```go
package slapolicy

import (
	"testing"
	"time"
)

func TestDeadlineFor(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got := DeadlineFor(Policy{Severity: "High", DurationHours: 72}, start)
	want := start.Add(72 * time.Hour)
	if !got.Equal(want) {
		t.Fatalf("DeadlineFor = %v, want %v", got, want)
	}
}

func TestEvaluateSLABreach(t *testing.T) {
	deadline := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"before deadline", deadline.Add(-time.Minute), false},
		{"exactly at deadline", deadline, true},
		{"after deadline", deadline.Add(time.Minute), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := EvaluateSLABreach(deadline, c.now); got != c.want {
				t.Errorf("EvaluateSLABreach(%v, %v) = %v, want %v", deadline, c.now, got, c.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/slapolicy/... -v`
Expected: FAIL — package `internal/slapolicy` does not exist / functions undefined

- [ ] **Step 3: Write the implementation**

```go
// Package slapolicy holds the pure logic behind posture-finding SLA
// deadlines: computing a deadline from a policy and a start time, and
// deciding whether a given deadline is breached as of now. No I/O -- the
// API layer resolves the right Policy row and persists the result.
package slapolicy

import "time"

// Policy is one severity's SLA duration -- mirrors one row of the
// sla_policy table.
type Policy struct {
	Severity      string
	DurationHours int
}

// DeadlineFor computes when a clock that started at startedAt expires,
// given the policy in effect for that severity at the moment it started.
func DeadlineFor(policy Policy, startedAt time.Time) time.Time {
	return startedAt.Add(time.Duration(policy.DurationHours) * time.Hour)
}

// EvaluateSLABreach is the single source of truth for "is this clock
// breached" -- a deadline exactly reached counts as breached, not
// exclusively strictly after.
func EvaluateSLABreach(deadlineAt, now time.Time) bool {
	return !now.Before(deadlineAt)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/slapolicy/... -v`
Expected: PASS (both `TestDeadlineFor` and all 3 subtests of `TestEvaluateSLABreach`)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/slapolicy/
git commit -m "feat: add internal/slapolicy pure domain package

DeadlineFor and EvaluateSLABreach -- the entire SLA deadline/breach
domain logic, zero DB/network dependency, mirrors internal/findings'
and internal/driftanalytics' shape."
git push
```

---

### Task 3: Database migration — `sla_policy` and `finding_slas`

**Files:**
- Modify: `orchestrator/internal/db/postgres.go:1654` (append after the existing `idx_posture_findings_status` statement, before the closing `}` of the `stmts` slice)
- Test: `orchestrator/internal/api/sla_migration_test.go` (new)

**Interfaces:**
- Produces: tables `sla_policy` (columns `severity`, `duration_hours`, `updated_at`, `updated_by`) and `finding_slas` (columns `id`, `posture_finding_id`, `severity_at_start`, `started_at`, `deadline_at`, `status`, `breached_at`, `resolved_at`). Tasks 4, 5, 6, 7 all read/write these tables directly by column name.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/api/sla_migration_test.go`:

```go
package api

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSLAPolicySeed_FourDefaultRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		want := map[string]int{"Critical": 24, "High": 72, "Medium": 168, "Low": 720}
		for severity, hours := range want {
			var got int
			if err := pool.QueryRow(context.Background(),
				`SELECT duration_hours FROM sla_policy WHERE severity=$1`, severity,
			).Scan(&got); err != nil {
				t.Fatalf("query %s: %v", severity, err)
			}
			if got != hours {
				t.Errorf("sla_policy[%s].duration_hours = %d, want %d", severity, got, hours)
			}
		}
	})
}

func TestSLAMigration_BackfillsExistingOpenFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('backfill-agent', 'BACKFILL-AGENT')`)
		mustExecAPI(t, pool,
			`INSERT INTO posture_findings (id, agent_id, check_id, category, title, severity, status, first_seen, last_seen, last_observed_at)
			 VALUES ('pf-backfill-1', 'backfill-agent', 'windows-firewall-enabled', 'security-configuration', 'Windows Firewall disabled', 'High', 'open', NOW(), NOW(), NOW())`)

		// Re-running EnsureSchema simulates this migration landing against a
		// fleet that already has open posture_findings rows from before this
		// sub-project shipped.
		if err := db.EnsureSchema(context.Background(), pool); err != nil {
			t.Fatalf("EnsureSchema (2nd run): %v", err)
		}

		var status string
		var startedAt, deadlineAt time.Time
		if err := pool.QueryRow(context.Background(),
			`SELECT status, started_at, deadline_at FROM finding_slas WHERE posture_finding_id='pf-backfill-1'`,
		).Scan(&status, &startedAt, &deadlineAt); err != nil {
			t.Fatalf("expected a backfilled finding_slas row: %v", err)
		}
		if status != "active" {
			t.Errorf("status = %q, want active", status)
		}
		gotHours := deadlineAt.Sub(startedAt).Hours()
		if gotHours < 71.9 || gotHours > 72.1 {
			t.Errorf("deadline - started = %.2fh, want ~72h (High severity policy)", gotHours)
		}

		// Idempotency: a 3rd EnsureSchema run must not create a 2nd row for
		// the same posture_finding_id.
		if err := db.EnsureSchema(context.Background(), pool); err != nil {
			t.Fatalf("EnsureSchema (3rd run): %v", err)
		}
		var n int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM finding_slas WHERE posture_finding_id='pf-backfill-1'`,
		).Scan(&n); err != nil || n != 1 {
			t.Fatalf("finding_slas rows for pf-backfill-1 = %d (err=%v), want exactly 1", n, err)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestSLAPolicySeed|TestSLAMigration' -v`
Expected: FAIL — `sla_policy`/`finding_slas` tables don't exist

- [ ] **Step 3: Add the migration statements**

In `orchestrator/internal/db/postgres.go`, immediately after line 1654 (`` `CREATE INDEX IF NOT EXISTS idx_posture_findings_status ON posture_findings (status)`, ``) and before the closing `}` of the `stmts` slice, insert:

```go
		// ── Posture Finding SLA Policy (Sub-project B of the SLA initiative,
		// see docs/superpowers/specs/2026-08-29-posture-finding-sla-policy-design.md).
		// Scoped to posture_findings only, same as Sub-project A -- no
		// polymorphic finding_type/finding_id reference.
		`CREATE TABLE IF NOT EXISTS sla_policy (
			severity       text PRIMARY KEY,
			duration_hours int  NOT NULL CHECK (duration_hours > 0 AND duration_hours <= 8760),
			updated_at     timestamptz NOT NULL DEFAULT NOW(),
			updated_by     text NOT NULL DEFAULT ''
		)`,
		`INSERT INTO sla_policy (severity, duration_hours) VALUES
			('Critical', 24), ('High', 72), ('Medium', 168), ('Low', 720)
		 ON CONFLICT (severity) DO NOTHING`,
		// finding_slas is one row per open EPISODE of a posture_findings row,
		// not 1:1 with it -- a finding that heals then reopens months later
		// gets a fresh row with a fresh clock; the prior episode's row stays
		// as history. severity_at_start is a snapshot so a later
		// postureCheckFindingText edit never rewrites history, and editing
		// sla_policy only affects episodes started after the edit (an
		// existing deadline_at is never recomputed).
		`CREATE TABLE IF NOT EXISTS finding_slas (
			id                 text PRIMARY KEY DEFAULT gen_random_uuid()::text,
			posture_finding_id text NOT NULL REFERENCES posture_findings(id),
			severity_at_start  text NOT NULL,
			started_at         timestamptz NOT NULL,
			deadline_at        timestamptz NOT NULL,
			status             text NOT NULL DEFAULT 'active',
			breached_at        timestamptz,
			resolved_at        timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_finding_slas_posture_finding ON finding_slas (posture_finding_id)`,
		`CREATE INDEX IF NOT EXISTS idx_finding_slas_active_deadline ON finding_slas (status, deadline_at) WHERE status = 'active'`,
		// Backfill: any posture_findings row that was already 'open' before
		// this migration ran gets an SLA clock starting now (not backdated to
		// its original first_seen -- backdating would let some findings
		// arrive already breached, a migration artifact, not a real SLA
		// miss). The NOT EXISTS guard makes this statement idempotent across
		// repeated EnsureSchema runs.
		`INSERT INTO finding_slas (posture_finding_id, severity_at_start, started_at, deadline_at, status)
		 SELECT pf.id, pf.severity, NOW(), NOW() + (sp.duration_hours || ' hours')::interval, 'active'
		   FROM posture_findings pf
		   JOIN sla_policy sp ON sp.severity = pf.severity
		  WHERE pf.status = 'open'
		    AND NOT EXISTS (SELECT 1 FROM finding_slas fs WHERE fs.posture_finding_id = pf.id)`,
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestSLAPolicySeed|TestSLAMigration' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/api/sla_migration_test.go
git commit -m "feat(db): add sla_policy and finding_slas tables

Severity-keyed, admin-editable policy (seeded with Critical=24h/
High=72h/Medium=7d/Low=30d) and per-open-episode deadline tracking for
posture_findings, plus a backfill for any already-open finding."
git push
```

---

### Task 4: Write-path hook — start/resolve SLA clocks

**Files:**
- Modify: `orchestrator/internal/api/posture_finding_handlers.go` (the `applyPostureFinding` function, and its initial `SELECT`)
- Test: `orchestrator/internal/api/posture_finding_handlers_test.go`

**Interfaces:**
- Consumes: `slapolicy.Policy`, `slapolicy.DeadlineFor` (Task 2); `findings.Created`/`findings.Reopened`/`findings.Healed` (existing, `internal/findings` package).
- Produces: `finding_slas` rows written synchronously with every `posture_findings` lifecycle transition. Task 5's tick reads rows this task writes; Task 7's read endpoints join against them.

**Context:** `applyPostureFinding`'s initial `SELECT` doesn't currently fetch `id` (never needed it before — nothing referenced `posture_findings.id` elsewhere in Sub-project A). This task adds it, since `finding_slas.posture_finding_id` needs it.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/api/posture_finding_handlers_test.go`:

```go
func TestApplyPostureFinding_CreatedStartsSLAClock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)

		// windows-firewall-enabled is the only check_id seedPostureCheckRun
		// seeds (it hardcodes it) -- severity "High" per Task 1's table.
		seedPostureCheckRun(t, pool, "sla-run-1", "sla-a1", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "sla-run-1")

		var pfID, status, severityAtStart string
		if err := pool.QueryRow(context.Background(),
			`SELECT id FROM posture_findings WHERE agent_id='sla-a1' AND check_id='windows-firewall-enabled'`,
		).Scan(&pfID); err != nil {
			t.Fatalf("posture_findings query: %v", err)
		}
		if err := pool.QueryRow(context.Background(),
			`SELECT status, severity_at_start FROM finding_slas WHERE posture_finding_id=$1`, pfID,
		).Scan(&status, &severityAtStart); err != nil {
			t.Fatalf("expected a finding_slas row: %v", err)
		}
		if status != "active" || severityAtStart != "High" {
			t.Errorf("status=%q severityAtStart=%q, want active/High", status, severityAtStart)
		}
	})
}

func TestApplyPostureFinding_HealedResolvesActiveSLA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)

		seedPostureCheckRun(t, pool, "sla-run-2a", "sla-a2", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "sla-run-2a")
		seedPostureCheckRun(t, pool, "sla-run-2b", "sla-a2", "pass", time.Now().Add(time.Hour))
		h.upsertPostureFindingsForRun(context.Background(), "sla-run-2b")

		var pfID string
		pool.QueryRow(context.Background(),
			`SELECT id FROM posture_findings WHERE agent_id='sla-a2' AND check_id='windows-firewall-enabled'`,
		).Scan(&pfID)

		var status string
		var resolvedAt *time.Time
		if err := pool.QueryRow(context.Background(),
			`SELECT status, resolved_at FROM finding_slas WHERE posture_finding_id=$1`, pfID,
		).Scan(&status, &resolvedAt); err != nil {
			t.Fatalf("query: %v", err)
		}
		if status != "resolved" || resolvedAt == nil {
			t.Errorf("status=%q resolvedAt=%v, want resolved/non-nil", status, resolvedAt)
		}
	})
}

func TestApplyPostureFinding_ReopenedStartsNewSLAEpisode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)

		seedPostureCheckRun(t, pool, "sla-run-3a", "sla-a3", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "sla-run-3a")
		seedPostureCheckRun(t, pool, "sla-run-3b", "sla-a3", "pass", time.Now().Add(time.Hour))
		h.upsertPostureFindingsForRun(context.Background(), "sla-run-3b")
		seedPostureCheckRun(t, pool, "sla-run-3c", "sla-a3", "fail", time.Now().Add(2*time.Hour))
		h.upsertPostureFindingsForRun(context.Background(), "sla-run-3c")

		var pfID string
		pool.QueryRow(context.Background(),
			`SELECT id FROM posture_findings WHERE agent_id='sla-a3' AND check_id='windows-firewall-enabled'`,
		).Scan(&pfID)

		var total, activeCount, resolvedCount int
		pool.QueryRow(context.Background(), `SELECT count(*) FROM finding_slas WHERE posture_finding_id=$1`, pfID).Scan(&total)
		pool.QueryRow(context.Background(), `SELECT count(*) FROM finding_slas WHERE posture_finding_id=$1 AND status='active'`, pfID).Scan(&activeCount)
		pool.QueryRow(context.Background(), `SELECT count(*) FROM finding_slas WHERE posture_finding_id=$1 AND status='resolved'`, pfID).Scan(&resolvedCount)
		if total != 2 || activeCount != 1 || resolvedCount != 1 {
			t.Errorf("total=%d active=%d resolved=%d, want 2/1/1 (prior episode resolved, new episode active)", total, activeCount, resolvedCount)
		}
	})
}
```

Verify `seedPostureCheckRun`'s exact parameters against the real helper (read the file) before using it in these tests — Task 1's Step 1 already required doing this once; reuse whatever the confirmed real signature turned out to be.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestApplyPostureFinding_' -v`
Expected: FAIL — no `finding_slas` rows are ever inserted yet

- [ ] **Step 3: Add `id` to the initial state read**

In `orchestrator/internal/api/posture_finding_handlers.go`, find `applyPostureFinding`'s initial `SELECT` (originally lines 105-117):

```go
func (h *Handler) applyPostureFinding(ctx context.Context, agentID string, a *postureFindingAgg, o findings.Observation) {
	var s findings.State
	var resolvedAt *time.Time
	err := h.db.QueryRow(ctx,
		`SELECT status, exposure_state, occurrence_count, reopened_count,
		        COALESCE(last_run_id,''), last_observed_at, resolved_at
		   FROM posture_findings WHERE agent_id=$1 AND check_id=$2`,
		agentID, a.checkID).
		Scan(&s.Status, &s.ExposureState, &s.OccurrenceCount, &s.ReopenedCount, &s.LastRunID, &s.LastObservedAt, &resolvedAt)
	if err == nil {
		s.Exists = true
		s.Resolved = resolvedAt != nil
	}
```

Replace with (adds `id` as the first scanned column, into a new `pfID` variable):

```go
func (h *Handler) applyPostureFinding(ctx context.Context, agentID string, a *postureFindingAgg, o findings.Observation) {
	var s findings.State
	var pfID string
	var resolvedAt *time.Time
	err := h.db.QueryRow(ctx,
		`SELECT id, status, exposure_state, occurrence_count, reopened_count,
		        COALESCE(last_run_id,''), last_observed_at, resolved_at
		   FROM posture_findings WHERE agent_id=$1 AND check_id=$2`,
		agentID, a.checkID).
		Scan(&pfID, &s.Status, &s.ExposureState, &s.OccurrenceCount, &s.ReopenedCount, &s.LastRunID, &s.LastObservedAt, &resolvedAt)
	if err == nil {
		s.Exists = true
		s.Resolved = resolvedAt != nil
	}
```

- [ ] **Step 4: Start an SLA clock on Created, using `RETURNING id`**

Replace the `tr == findings.Created` block (as left by Task 1) with a version that captures the newly-inserted row's `id` via `RETURNING` and starts its SLA clock:

```go
	if tr == findings.Created {
		text := postureCheckFindingText[a.checkID]
		severity := text.Severity
		if severity == "" {
			severity = "Medium"
		}
		var newID string
		err := h.db.QueryRow(ctx,
			`INSERT INTO posture_findings (agent_id, check_id, category, title, severity, exposure_state, status,
			        occurrence_count, last_run_id, first_seen, last_seen, last_observed_at)
			 VALUES ($1,$2,$3,$4,$5,$6,'open',1,$7,NOW(),NOW(),$8)
			 ON CONFLICT (agent_id, check_id) DO NOTHING
			 RETURNING id`,
			agentID, a.checkID, a.category, text.Title, severity, next.ExposureState, o.RunID, o.ObservedAt).
			Scan(&newID)
		if err != nil {
			// ON CONFLICT DO NOTHING with RETURNING returns no row on a
			// conflict (a rare concurrent-insert race for the same
			// agent/check) -- nothing to start a clock for in that case.
			return
		}
		h.startSLAClock(ctx, newID, severity, o.ObservedAt)
		return
	}
```

- [ ] **Step 5: Resolve on Healed, start a new episode on Reopened**

Find the trailing `// recurred | healed | reopened -> update.` block (originally lines 134-155) and its `h.db.Exec(ctx, "UPDATE posture_findings SET ...")` call. Immediately after that `Exec` call (still inside the same `if`/switch context, after the UPDATE has run), add:

```go
	switch tr {
	case findings.Healed:
		h.resolveSLAClock(ctx, pfID)
	case findings.Reopened:
		h.startSLAClock(ctx, pfID, next.ExposureState, o.ObservedAt) // exposure_state isn't severity -- see note below
	}
```

Wait — `next.ExposureState` is the wrong value for severity; `findings.State` has no severity field at all (severity lives only on `posture_findings`, not in the `findings` package's domain-agnostic `State`). Use the finding's own stored severity instead — query it once, since Reopened's severity is the same value that was set at original creation and never changes on this row:

```go
	switch tr {
	case findings.Healed:
		h.resolveSLAClock(ctx, pfID)
	case findings.Reopened:
		var severity string
		h.db.QueryRow(ctx, `SELECT severity FROM posture_findings WHERE id=$1`, pfID).Scan(&severity)
		h.startSLAClock(ctx, pfID, severity, o.ObservedAt)
	}
```

- [ ] **Step 6: Add the two new helper functions**

Add to `orchestrator/internal/api/posture_finding_handlers.go`:

```go
// startSLAClock opens a new finding_slas episode for postureFindingID,
// using the sla_policy row matching severity. Silently no-ops if that
// severity has no policy row (shouldn't happen -- all 4 severities are
// seeded by migration -- but a missing policy must never panic the ingest
// path).
func (h *Handler) startSLAClock(ctx context.Context, postureFindingID, severity string, startedAt time.Time) {
	var durationHours int
	if err := h.db.QueryRow(ctx, `SELECT duration_hours FROM sla_policy WHERE severity=$1`, severity).Scan(&durationHours); err != nil {
		return
	}
	deadlineAt := slapolicy.DeadlineFor(slapolicy.Policy{Severity: severity, DurationHours: durationHours}, startedAt)
	_, _ = h.db.Exec(ctx,
		`INSERT INTO finding_slas (posture_finding_id, severity_at_start, started_at, deadline_at, status)
		 VALUES ($1,$2,$3,$4,'active')`,
		postureFindingID, severity, startedAt, deadlineAt)
}

// resolveSLAClock closes postureFindingID's current non-terminal episode
// (active or already-breached -- a late resolution after a miss is still a
// real resolution, breached_at stays set as history).
func (h *Handler) resolveSLAClock(ctx context.Context, postureFindingID string) {
	_, _ = h.db.Exec(ctx,
		`UPDATE finding_slas SET status='resolved', resolved_at=NOW()
		  WHERE posture_finding_id=$1 AND status IN ('active','breached')`,
		postureFindingID)
}
```

Add `"github.com/audspect/bas/internal/slapolicy"` to this file's import block.

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestApplyPostureFinding_' -v`
Expected: PASS (all 3 new tests)

- [ ] **Step 8: Run the full posture-finding suite to confirm no regression**

Run: `cd orchestrator && go test ./internal/api/... -run 'PostureFinding' -v`
Expected: all PASS (Sub-project A's existing tests + Task 1's + these 3)

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/api/posture_finding_handlers.go orchestrator/internal/api/posture_finding_handlers_test.go
git commit -m "feat: start/resolve SLA clocks synchronously with finding lifecycle

applyPostureFinding now opens a finding_slas episode on Created/
Reopened (via slapolicy.DeadlineFor against the finding's severity)
and resolves the current episode on Healed. One episode per open
period -- a reopened finding gets a fresh clock, the prior episode's
row (breached or not) is untouched."
git push
```

---

### Task 5: Background tick — breach detection and notification

**Files:**
- Create: `orchestrator/internal/api/sla_handlers.go`
- Test: `orchestrator/internal/api/sla_handlers_test.go` (new)
- Modify: `orchestrator/internal/notifications/types.go` (add `EventSLABreached`)
- Modify: `orchestrator/cmd/server/main.go` (register the new scheduler)

**Interfaces:**
- Consumes: `slapolicy.EvaluateSLABreach` (Task 2), `h.notifications *notifications.Service` (existing, nil-guarded), `h.db` (existing).
- Produces: `func (h *Handler) TickSLABreaches(ctx context.Context) error` — **exported**, since `main.go` (package `main`) calls it directly, the same way it already calls `jobsDispatcher.Tick` and `handler.ReapNeverStartedRuns`.

- [ ] **Step 1: Add the new notification event type**

In `orchestrator/internal/notifications/types.go`, add to the `const ( ... )` block (after `EventTargetAssigned`):

```go
	EventSLABreached EventType = "sla_breached"
```

- [ ] **Step 2: Write the failing tests**

Create `orchestrator/internal/api/sla_handlers_test.go`:

```go
package api

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/notifications"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func seedFindingSLA(t *testing.T, pool *pgxpool.Pool, id, agentID, checkID, severity, status string, deadlineAt time.Time, breachedAt *time.Time) {
	t.Helper()
	pfID := "pf-" + id
	mustExecAPI(t, pool,
		`INSERT INTO posture_findings (id, agent_id, check_id, category, title, severity, status, first_seen, last_seen, last_observed_at)
		 VALUES ($1,$2,$3,'security-configuration','Test Finding',$4,'open',NOW(),NOW(),NOW())
		 ON CONFLICT (agent_id, check_id) DO NOTHING`,
		pfID, agentID, checkID, severity)
	mustExecAPI(t, pool,
		`INSERT INTO finding_slas (id, posture_finding_id, severity_at_start, started_at, deadline_at, status, breached_at)
		 VALUES ($1, $2, $3, NOW(), $4, $5, $6)`,
		id, pfID, severity, deadlineAt, status, breachedAt)
}

func TestTickSLABreaches_DeadlineNotReached_NoBreach(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tick-a1', 'TICK-A1')`)
		seedFindingSLA(t, pool, "fs-notdue", "tick-a1", "windows-firewall-enabled", "High", "active", time.Now().Add(time.Hour), nil)

		notifStore := notifications.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithNotifications(notifStore)
		if err := h.TickSLABreaches(context.Background()); err != nil {
			t.Fatalf("TickSLABreaches: %v", err)
		}

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM finding_slas WHERE id='fs-notdue'`).Scan(&status)
		if status != "active" {
			t.Errorf("status = %q, want still active", status)
		}
	})
}

func TestTickSLABreaches_DeadlinePassed_MarksBreachedAndNotifies(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tick-a2', 'TICK-A2')`)
		seedFindingSLA(t, pool, "fs-due", "tick-a2", "linux-ssh-empty-passwords-forbidden", "Critical", "active", time.Now().Add(-time.Hour), nil)

		notifStore := notifications.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithNotifications(notifStore)
		if err := h.TickSLABreaches(context.Background()); err != nil {
			t.Fatalf("TickSLABreaches: %v", err)
		}

		var status string
		var breachedAt *time.Time
		pool.QueryRow(context.Background(), `SELECT status, breached_at FROM finding_slas WHERE id='fs-due'`).Scan(&status, &breachedAt)
		if status != "breached" || breachedAt == nil {
			t.Fatalf("status=%q breachedAt=%v, want breached/non-nil", status, breachedAt)
		}

		events, err := notifStore.List(context.Background(), notifications.ListFilter{Type: string(notifications.EventSLABreached), Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(events) != 1 || events[0].Severity != notifications.SeverityCritical || events[0].AgentID != "tick-a2" {
			t.Fatalf("events = %+v, want exactly one sla_breached/critical event for tick-a2", events)
		}
	})
}

func TestTickSLABreaches_RepeatedTicks_OnlyOneNotification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tick-a3', 'TICK-A3')`)
		seedFindingSLA(t, pool, "fs-repeat", "tick-a3", "windows-firewall-enabled", "High", "active", time.Now().Add(-time.Hour), nil)

		notifStore := notifications.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithNotifications(notifStore)
		h.TickSLABreaches(context.Background())
		h.TickSLABreaches(context.Background())
		h.TickSLABreaches(context.Background())

		events, err := notifStore.List(context.Background(), notifications.ListFilter{Type: string(notifications.EventSLABreached), Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("events = %d, want exactly 1 despite 3 ticks (idempotency)", len(events))
		}
	})
}

func TestTickSLABreaches_MultipleFindingsBreachInSameTick(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tick-a4', 'TICK-A4')`)
		seedFindingSLA(t, pool, "fs-multi1", "tick-a4", "windows-firewall-enabled", "High", "active", time.Now().Add(-time.Hour), nil)
		seedFindingSLA(t, pool, "fs-multi2", "tick-a4", "windows-smbv1-disabled", "High", "active", time.Now().Add(-2*time.Hour), nil)

		notifStore := notifications.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithNotifications(notifStore)
		if err := h.TickSLABreaches(context.Background()); err != nil {
			t.Fatalf("TickSLABreaches: %v", err)
		}

		var breachedCount int
		pool.QueryRow(context.Background(), `SELECT count(*) FROM finding_slas WHERE status='breached'`).Scan(&breachedCount)
		if breachedCount != 2 {
			t.Errorf("breached count = %d, want 2", breachedCount)
		}
		events, _ := notifStore.List(context.Background(), notifications.ListFilter{Type: string(notifications.EventSLABreached), Limit: 10})
		if len(events) != 2 {
			t.Errorf("events = %d, want 2", len(events))
		}
	})
}

func TestTickSLABreaches_ResolvedRowNeverTouched(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tick-a5', 'TICK-A5')`)
		seedFindingSLA(t, pool, "fs-resolved", "tick-a5", "windows-firewall-enabled", "High", "resolved", time.Now().Add(-time.Hour), nil)

		notifStore := notifications.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithNotifications(notifStore)
		if err := h.TickSLABreaches(context.Background()); err != nil {
			t.Fatalf("TickSLABreaches: %v", err)
		}

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM finding_slas WHERE id='fs-resolved'`).Scan(&status)
		if status != "resolved" {
			t.Errorf("status = %q, want still resolved (tick must never touch a non-active row)", status)
		}
		events, _ := notifStore.List(context.Background(), notifications.ListFilter{Type: string(notifications.EventSLABreached), Limit: 10})
		if len(events) != 0 {
			t.Errorf("events = %d, want 0", len(events))
		}
	})
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestTickSLABreaches' -v`
Expected: FAIL — `h.TickSLABreaches` undefined

- [ ] **Step 4: Write the implementation**

Create `orchestrator/internal/api/sla_handlers.go`:

```go
package api

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/notifications"
	"github.com/audspect/bas/internal/slapolicy"
)

// TickSLABreaches scans finding_slas for active episodes whose deadline has
// been reached or passed, flips each to breached, and emits one
// notifications.Event per breach. Driven by a 5-minute exercise.PollScheduler
// registered in cmd/server/main.go, mirroring jobsDispatcher.Tick's pattern.
// Idempotent by construction: the UPDATE's own "AND status='active'" guard
// plus checking RowsAffected means a row can only ever be breached-and-
// notified once, even across concurrent or overlapping ticks.
func (h *Handler) TickSLABreaches(ctx context.Context) error {
	rows, err := h.db.Query(ctx,
		`SELECT fs.id, fs.deadline_at, pf.agent_id, pf.check_id, pf.title, pf.severity
		   FROM finding_slas fs
		   JOIN posture_findings pf ON pf.id = fs.posture_finding_id
		  WHERE fs.status = 'active' AND fs.deadline_at <= NOW()`)
	if err != nil {
		return err
	}
	type candidate struct {
		id, agentID, checkID, title, severity string
		deadlineAt                            time.Time
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if rows.Scan(&c.id, &c.deadlineAt, &c.agentID, &c.checkID, &c.title, &c.severity) != nil {
			continue
		}
		candidates = append(candidates, c)
	}
	rows.Close()

	for _, c := range candidates {
		if !slapolicy.EvaluateSLABreach(c.deadlineAt, time.Now()) {
			continue
		}
		tag, err := h.db.Exec(ctx,
			`UPDATE finding_slas SET status='breached', breached_at=NOW() WHERE id=$1 AND status='active'`, c.id)
		if err != nil || tag.RowsAffected() == 0 {
			continue // already handled (concurrent tick) or write failed -- next tick re-evaluates from the query above
		}
		if h.notifications == nil {
			continue
		}
		h.notifications.Emit(ctx, notifications.Event{
			Type:     notifications.EventSLABreached,
			AgentID:  c.agentID,
			Severity: slaNotifySeverity(c.severity),
			Message:  fmt.Sprintf("SLA breached: %s (%s) on %s", c.title, c.checkID, c.agentID),
			Metadata: map[string]any{
				"findingSlaId": c.id, "checkId": c.checkID, "severity": c.severity, "deadlineAt": c.deadlineAt,
			},
		})
	}
	return nil
}

// slaNotifySeverity maps a posture finding's severity to a notification
// severity -- Critical/High elevate to the notification system's two
// highest tiers since those are the findings whose breach is operationally
// urgent; Medium/Low map to warning/info.
func slaNotifySeverity(severity string) notifications.Severity {
	switch severity {
	case "Critical":
		return notifications.SeverityCritical
	case "High":
		return notifications.SeverityError
	case "Low":
		return notifications.SeverityInfo
	default:
		return notifications.SeverityWarning
	}
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestTickSLABreaches' -v`
Expected: PASS (all 5 tests)

- [ ] **Step 6: Wire the scheduler in main.go**

In `orchestrator/cmd/server/main.go`, immediately after the existing block (originally lines 630-635):

```go
	jobsScheduler.Start(func(ctx context.Context) {
		if err := jobsDispatcher.Tick(ctx); err != nil {
			log.Printf("[jobs] tick: %v", err)
		}
	})
	defer jobsScheduler.Stop()
```

add:

```go
	slaScheduler := exercise.NewPollScheduler(5 * time.Minute)
	slaScheduler.Start(func(ctx context.Context) {
		if err := handler.TickSLABreaches(ctx); err != nil {
			log.Printf("[sla] tick: %v", err)
		}
	})
	defer slaScheduler.Stop()
```

Confirm the local variable holding the `*api.Handler` instance is actually named `handler` at this point in `main.go` (it's used that way at `dispatchWatchdogScheduler`'s `handler.ReapNeverStartedRuns(ctx)` call a few lines above) before finalizing this edit — read the surrounding function to confirm, don't assume.

- [ ] **Step 7: Verify the server still builds**

Run: `cd orchestrator && go build ./...`
Expected: no errors

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/sla_handlers.go orchestrator/internal/api/sla_handlers_test.go orchestrator/internal/notifications/types.go orchestrator/cmd/server/main.go
git commit -m "feat: background tick detects SLA breaches and notifies

TickSLABreaches scans active finding_slas past their deadline, flips
them to breached, and emits one notifications.Event each -- idempotent
via the UPDATE's own status='active' guard. Runs every 5 minutes via a
new exercise.PollScheduler, mirroring jobsDispatcher.Tick."
git push
```

---

### Task 6: Policy API — `GET`/`PATCH /api/sla/policies`

**Files:**
- Modify: `orchestrator/internal/api/sla_handlers.go`
- Test: `orchestrator/internal/api/sla_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Produces: `func (h *Handler) ListSLAPolicies(w http.ResponseWriter, r *http.Request)`, `func (h *Handler) UpdateSLAPolicy(w http.ResponseWriter, r *http.Request)`.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/api/sla_handlers_test.go`:

```go
func TestListSLAPolicies_ReturnsAllFour(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/sla/policies", nil)
		w := httptest.NewRecorder()
		h.ListSLAPolicies(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var got []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got) != 4 {
			t.Fatalf("len = %d, want 4", len(got))
		}
	})
}

func TestUpdateSLAPolicy_HappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		body, _ := json.Marshal(map[string]int{"durationHours": 8})
		req := withURLParam(httptest.NewRequest(http.MethodPatch, "/x", bytes.NewReader(body)), "severity", "Critical")
		w := httptest.NewRecorder()
		h.UpdateSLAPolicy(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var got int
		pool.QueryRow(context.Background(), `SELECT duration_hours FROM sla_policy WHERE severity='Critical'`).Scan(&got)
		if got != 8 {
			t.Errorf("duration_hours = %d, want 8", got)
		}
	})
}

func TestUpdateSLAPolicy_UnknownSeverity_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		body, _ := json.Marshal(map[string]int{"durationHours": 8})
		req := withURLParam(httptest.NewRequest(http.MethodPatch, "/x", bytes.NewReader(body)), "severity", "Nope")
		w := httptest.NewRecorder()
		h.UpdateSLAPolicy(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}

func TestUpdateSLAPolicy_InvalidDuration_400(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		for _, hours := range []int{0, -5, 9000} {
			body, _ := json.Marshal(map[string]int{"durationHours": hours})
			req := withURLParam(httptest.NewRequest(http.MethodPatch, "/x", bytes.NewReader(body)), "severity", "High")
			w := httptest.NewRecorder()
			h.UpdateSLAPolicy(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("durationHours=%d: status = %d, want 400", hours, w.Code)
			}
		}
	})
}
```

Add `"bytes"`, `"encoding/json"`, `"net/http"`, `"net/http/httptest"` to this test file's imports if not already present (check the file's current import block first — `sla_migration_test.go` in the same package already imports several of these, but each `_test.go` file needs its own import block).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestListSLAPolicies|TestUpdateSLAPolicy' -v`
Expected: FAIL — `h.ListSLAPolicies`/`h.UpdateSLAPolicy` undefined

- [ ] **Step 3: Write the implementation**

Add to `orchestrator/internal/api/sla_handlers.go`:

```go
var validSLASeverities = map[string]bool{"Critical": true, "High": true, "Medium": true, "Low": true}

// ListSLAPolicies returns all 4 severity->deadline rows. GET /api/sla/policies
func (h *Handler) ListSLAPolicies(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(), `SELECT severity, duration_hours, updated_at, updated_by FROM sla_policy ORDER BY severity`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var severity, updatedBy string
		var durationHours int
		var updatedAt time.Time
		if rows.Scan(&severity, &durationHours, &updatedAt, &updatedBy) != nil {
			continue
		}
		out = append(out, map[string]any{
			"severity": severity, "durationHours": durationHours,
			"updatedAt": updatedAt, "updatedBy": updatedBy,
		})
	}
	respond(w, out)
}

// UpdateSLAPolicy sets one severity's durationHours. Only affects future
// finding_slas episodes -- an existing row's deadline_at was already
// computed and is never recomputed. PATCH /api/sla/policies/{severity}
func (h *Handler) UpdateSLAPolicy(w http.ResponseWriter, r *http.Request) {
	severity := chi.URLParam(r, "severity")
	if !validSLASeverities[severity] {
		jsonError(w, "unknown severity", http.StatusNotFound)
		return
	}
	var body struct {
		DurationHours int `json:"durationHours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "malformed JSON", http.StatusBadRequest)
		return
	}
	if body.DurationHours < 1 || body.DurationHours > 8760 {
		jsonError(w, "durationHours must be between 1 and 8760", http.StatusBadRequest)
		return
	}
	_, err := h.db.Exec(r.Context(),
		`UPDATE sla_policy SET duration_hours=$1, updated_at=NOW(), updated_by=$2 WHERE severity=$3`,
		body.DurationHours, actorID(r), severity)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"severity": severity, "durationHours": body.DurationHours})
}
```

Add `"encoding/json"`, `"net/http"`, and `"github.com/go-chi/chi/v5"` to `sla_handlers.go`'s import block (`fmt`, `time`, and the two internal packages are already there from Task 5).

- [ ] **Step 4: Register the routes**

In `orchestrator/internal/api/routes.go`, immediately after line 566 (`` r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/posture-findings/{id}", h.GetPostureFinding) ``), add:

```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/sla/policies", h.ListSLAPolicies)
		r.With(auth.RequirePermission(auth.CanApproveRemediation)).Patch("/api/sla/policies/{severity}", h.UpdateSLAPolicy)
```

- [ ] **Step 5: Add the routes to the RBAC matrix**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after line 341 (`` {http.MethodGet, "/api/posture-findings/{id}", tierPermission, auth.CanExecuteRemediation}, ``), add:

```go
	{http.MethodGet, "/api/sla/policies", tierPermission, auth.CanExecuteRemediation},
	{http.MethodPatch, "/api/sla/policies/{severity}", tierPermission, auth.CanApproveRemediation},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestListSLAPolicies|TestUpdateSLAPolicy|TestRBACMatrix' -v`
Expected: PASS (including `TestRBACMatrix_NoDrift` and `TestRBACMatrix_AuthorizationBoundary`, confirming `PATCH /api/sla/policies/{severity}` is actually Admin-only end-to-end through the router)

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/sla_handlers.go orchestrator/internal/api/sla_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat: add SLA policy read/write API

GET /api/sla/policies (Analyst+Admin), PATCH /api/sla/policies/{severity}
(Admin-only, validates severity and 1-8760h bounds). Edits only affect
future finding_slas episodes."
git push
```

---

### Task 7: Extended read endpoints + fleet-wide breach report

**Files:**
- Modify: `orchestrator/internal/api/posture_finding_handlers.go` (`postureFindingCols`, `scanPostureFindings`, `ListAgentPostureFindings`, `GetPostureFinding`)
- Modify: `orchestrator/internal/api/sla_handlers.go` (new `GetSLABreaches`)
- Test: `orchestrator/internal/api/posture_finding_handlers_test.go`, `orchestrator/internal/api/sla_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Produces: `slaStatus`/`slaStartedAt`/`slaDeadlineAt`/`slaBreachedAt` fields on the JSON returned by `ListAgentPostureFindings`/`GetPostureFinding`; `func (h *Handler) GetSLABreaches(w http.ResponseWriter, r *http.Request)`.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/api/posture_finding_handlers_test.go`:

```go
func TestListAgentPostureFindings_IncludesSLAFields(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('sla-read-1', 'SLA-READ-1')`)

		seedPostureCheckRun(t, pool, "sla-read-run", "sla-read-1", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "sla-read-run")

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "sla-read-1")
		w := httptest.NewRecorder()
		h.ListAgentPostureFindings(w, req)

		var got []map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1", len(got))
		}
		if got[0]["slaStatus"] != "active" {
			t.Errorf("slaStatus = %v, want active", got[0]["slaStatus"])
		}
		if got[0]["slaDeadlineAt"] == nil {
			t.Errorf("slaDeadlineAt missing")
		}
	})
}
```

Add to `orchestrator/internal/api/sla_handlers_test.go`:

```go
func TestGetSLABreaches_ReturnsOnlyBreachedOldestFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('breach-a1', 'BREACH-A1')`)
		oldBreach := time.Now().Add(-48 * time.Hour)
		newBreach := time.Now().Add(-12 * time.Hour)
		seedFindingSLA(t, pool, "fs-active", "breach-a1", "windows-firewall-enabled", "High", "active", time.Now().Add(time.Hour), nil)
		seedFindingSLA(t, pool, "fs-b-old", "breach-a1", "windows-smbv1-disabled", "High", "breached", time.Now().Add(-72*time.Hour), &oldBreach)
		seedFindingSLA(t, pool, "fs-b-new", "breach-a1", "windows-rdp-nla-required", "High", "breached", time.Now().Add(-24*time.Hour), &newBreach)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/sla/breaches", nil)
		w := httptest.NewRecorder()
		h.GetSLABreaches(w, req)

		var got []map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		if len(got) != 2 {
			t.Fatalf("len = %d, want 2 (active row excluded)", len(got))
		}
		if got[0]["checkId"] != "windows-smbv1-disabled" {
			t.Errorf("got[0].checkId = %v, want windows-smbv1-disabled (oldest breach first)", got[0]["checkId"])
		}
	})
}
```

`seedFindingSLA` takes `breachedAt *time.Time` as its 8th parameter (Task 5) — pass `nil` for an `active` row, a real pointer for a `breached` row, exactly as shown above.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestListAgentPostureFindings_IncludesSLAFields|TestGetSLABreaches' -v`
Expected: FAIL

- [ ] **Step 3: Extend `postureFindingCols` and `scanPostureFindings`**

In `orchestrator/internal/api/posture_finding_handlers.go`, replace the `postureFindingCols` constant and `scanPostureFindings` function with:

```go
const postureFindingCols = `pf.id, pf.agent_id, pf.check_id, pf.category, pf.title, pf.severity, pf.status,
	pf.occurrence_count, pf.reopened_count, pf.first_seen, pf.last_seen, pf.last_observed_at,
	COALESCE(pf.last_run_id,''), pf.resolved_at, pf.resolved_reason,
	fs.status, fs.started_at, fs.deadline_at, fs.breached_at`

const postureFindingJoin = `FROM posture_findings pf
	LEFT JOIN LATERAL (
		SELECT status, started_at, deadline_at, breached_at
		  FROM finding_slas
		 WHERE posture_finding_id = pf.id
		 ORDER BY started_at DESC LIMIT 1
	) fs ON true`

func scanPostureFindings(rows findingScanner) []map[string]any {
	out := []map[string]any{}
	for rows.Next() {
		var id, agentID, checkID, category, title, severity, status, lastRunID string
		var occ, reopened int
		var firstSeen, lastSeen, lastObserved time.Time
		var resolvedAt *time.Time
		var resolvedReason *string
		var slaStatus *string
		var slaStartedAt, slaDeadlineAt, slaBreachedAt *time.Time
		if rows.Scan(&id, &agentID, &checkID, &category, &title, &severity, &status,
			&occ, &reopened, &firstSeen, &lastSeen, &lastObserved, &lastRunID, &resolvedAt, &resolvedReason,
			&slaStatus, &slaStartedAt, &slaDeadlineAt, &slaBreachedAt) != nil {
			continue
		}
		m := map[string]any{
			"id": id, "agentId": agentID, "checkId": checkID, "category": category,
			"title": title, "severity": severity, "status": status,
			"occurrenceCount": occ, "reopenedCount": reopened,
			"firstSeen": firstSeen, "lastSeen": lastSeen, "lastObservedAt": lastObserved,
			"lastRunId": lastRunID,
		}
		if resolvedAt != nil {
			m["resolvedAt"] = *resolvedAt
		}
		if resolvedReason != nil {
			m["resolvedReason"] = *resolvedReason
		}
		if slaStatus != nil {
			m["slaStatus"] = *slaStatus
		}
		if slaStartedAt != nil {
			m["slaStartedAt"] = *slaStartedAt
		}
		if slaDeadlineAt != nil {
			m["slaDeadlineAt"] = *slaDeadlineAt
		}
		if slaBreachedAt != nil {
			m["slaBreachedAt"] = *slaBreachedAt
		}
		out = append(out, m)
	}
	return out
}
```

- [ ] **Step 4: Update the two query call sites**

Replace `ListAgentPostureFindings`'s query:

```go
	rows, err := h.db.Query(r.Context(),
		`SELECT `+postureFindingCols+` FROM posture_findings
		  WHERE agent_id=$1 AND ($2='' OR status=$2)
		  ORDER BY last_seen DESC`,
		agentID, statusFilter)
```

with:

```go
	rows, err := h.db.Query(r.Context(),
		`SELECT `+postureFindingCols+` `+postureFindingJoin+`
		  WHERE pf.agent_id=$1 AND ($2='' OR pf.status=$2)
		  ORDER BY pf.last_seen DESC`,
		agentID, statusFilter)
```

Replace `GetPostureFinding`'s query:

```go
	rows, err := h.db.Query(r.Context(),
		`SELECT `+postureFindingCols+` FROM posture_findings WHERE id=$1`, chi.URLParam(r, "id"))
```

with:

```go
	rows, err := h.db.Query(r.Context(),
		`SELECT `+postureFindingCols+` `+postureFindingJoin+` WHERE pf.id=$1`, chi.URLParam(r, "id"))
```

- [ ] **Step 5: Add `GetSLABreaches`**

Add to `orchestrator/internal/api/sla_handlers.go`:

```go
// GetSLABreaches returns every currently-breached finding, oldest breach
// first. GET /api/sla/breaches
func (h *Handler) GetSLABreaches(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT pf.agent_id, pf.check_id, pf.title, pf.severity, pf.category, fs.breached_at, fs.deadline_at
		   FROM finding_slas fs
		   JOIN posture_findings pf ON pf.id = fs.posture_finding_id
		  WHERE fs.status = 'breached'
		  ORDER BY fs.breached_at ASC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var agentID, checkID, title, severity, category string
		var breachedAt, deadlineAt time.Time
		if rows.Scan(&agentID, &checkID, &title, &severity, &category, &breachedAt, &deadlineAt) != nil {
			continue
		}
		out = append(out, map[string]any{
			"agentId": agentID, "checkId": checkID, "title": title, "severity": severity,
			"category": category, "breachedAt": breachedAt, "deadlineAt": deadlineAt,
		})
	}
	respond(w, out)
}
```

- [ ] **Step 6: Register the route**

In `orchestrator/internal/api/routes.go`, immediately after the `PATCH /api/sla/policies/{severity}` line added in Task 6, add:

```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/sla/breaches", h.GetSLABreaches)
```

- [ ] **Step 7: Add the route to the RBAC matrix**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after the `PATCH /api/sla/policies/{severity}` row added in Task 6, add:

```go
	{http.MethodGet, "/api/sla/breaches", tierPermission, auth.CanExecuteRemediation},
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestListAgentPostureFindings_IncludesSLAFields|TestGetSLABreaches|TestRBACMatrix' -v`
Expected: PASS

- [ ] **Step 9: Run the full posture/SLA test surface to confirm no regression**

Run: `cd orchestrator && go test ./internal/api/... -run 'PostureFinding|SLA' -v`
Expected: all PASS — every test from Tasks 1, 3, 4, 5, 6, 7

- [ ] **Step 10: Commit**

```bash
git add orchestrator/internal/api/posture_finding_handlers.go orchestrator/internal/api/posture_finding_handlers_test.go orchestrator/internal/api/sla_handlers.go orchestrator/internal/api/sla_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat: surface SLA status on posture-finding reads + fleet breach report

GET /api/agents/{agentId}/posture-findings and GET /api/posture-findings/{id}
now include slaStatus/slaStartedAt/slaDeadlineAt/slaBreachedAt via a
LEFT JOIN LATERAL to each finding's most recent episode. New
GET /api/sla/breaches lists every currently-breached finding fleet-wide,
oldest breach first."
git push
```

---

### Task 8: Full-suite verification

No commit for this task — verification only, mirroring Sub-project A's final task exactly.

- [ ] **Step 1: Run the full `internal/api` package**

Run: `cd orchestrator && go test ./internal/api/... -v`
Expected: zero `FAIL` lines. If the whole-package run times out or hits a resource-contention-shaped failure (the known class documented in `[[project_endpoint_health_remediation]]`'s Sub-project 8/9/11/14 notes — a `panic: test timed out` with a `gorilla/websocket`/`httptest` goroutine dump, unrelated to any file this plan touches), re-run just the failing test name in isolation with `-run '^TestName$'` to confirm it passes clean alone before concluding it's contention and not a real regression. Do not skip this confirmation step — assuming contention without checking is exactly the mistake this note exists to prevent.

- [ ] **Step 2: Run the new/adjacent packages directly**

Run: `cd orchestrator && go test ./internal/slapolicy/... ./internal/findings/... ./internal/endpointrisk/... ./internal/notifications/... -v`
Expected: all PASS

- [ ] **Step 3: Confirm no unrelated diff**

Run: `cd "C:\Users\Administrator\Downloads\Audspect_Cloud" && git status --porcelain orchestrator/internal/findings orchestrator/internal/endpointrisk orchestrator/wwwroot`
Expected: empty output (this plan never touches any of these)

- [ ] **Step 4: Report completion**

Summarize what shipped (all 7 implementation tasks + this verification) and confirm nothing is pending. Since this repo builds directly on `main` with no worktree, `finishing-a-development-branch`'s cleanup step is a no-op here, same as Sub-project A.
