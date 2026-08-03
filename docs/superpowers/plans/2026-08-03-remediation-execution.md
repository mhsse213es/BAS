# Remediation Catalog & Single-Endpoint Execution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the complete lifecycle for one endpoint, one remediation — a new `internal/remediation` package + `remediation_requests` table that lets a Risk & Remediation finding actually be fixed, verified, and (where declared) rolled back, using zero new agent capability.

**Architecture:** A remediation fix/verification/rollback is a synthetic 1-step scenario dispatched through the *existing* `MsgCommandScenario`/`SubmitScenarioResult` pipeline (`scenario.BuildSteps` on an in-memory, never-persisted `scenario.Scenario`) — no new WebSocket message type, no new agent code. `internal/remediation` holds pure types/catalog/state constants; `internal/api` holds the DB-touching orchestration, mirroring the existing `internal/endpointrisk` (pure) vs. `internal/api/endpointrisk_aggregations.go` (orchestration) split.

**Tech Stack:** Go 1.x, PostgreSQL (via `pgxpool`), embedded YAML catalog (`gopkg.in/yaml.v3`), `testcontainers-go` for DB-backed tests, existing `chi` router + `internal/auth` RBAC.

## Global Constraints

- No new agent code — every dispatch reuses the existing `MsgCommandScenario`/`MsgScenarioResult`/`SubmitScenarioResult` pipeline.
- No batch/bulk execution, no Tier 3 (scheduled/maintenance-window) remediation — single endpoint only. That's Sub-project 6.
- `CanApproveRemediation` gates **all** rollbacks, regardless of the original fix's tier.
- The API surface avoids `/api/remediations` — that path is already an existing, unrelated endpoint (`ListRemediations` in `finding_handlers.go`, BAS-finding remediation *text*). This sub-project's single-request endpoints live under `/api/remediation-requests/{requestId}`, matching the `remediation_requests` table name.
- `Finding` fixability enrichment (Task 3) applies only to `postureCheckInput`'s findings (Security Configuration, Identity, Patch Management) — **not** Application Risk. Application Risk findings are keyed by EOL catalog id, a different namespace than `check_id`, and every EOL finding (uninstall old software) is inherently Tier 4 guidance-only territory anyway; wiring it in is explicitly out of scope here.
- Full spec: `docs/superpowers/specs/2026-08-03-remediation-execution-design.md`.

---

### Task 1: Remediation Catalog

**Files:**
- Create: `orchestrator/internal/remediation/catalog.yaml`
- Create: `orchestrator/internal/remediation/catalog.go`
- Test: `orchestrator/internal/remediation/catalog_test.go`

**Interfaces:**
- Produces: `remediation.Tier` (`TierSafeAutomatic=1`, `TierConfirmRequired=2`, `TierManualGuidance=4`), `remediation.CatalogEntry{ID, Title, Description, Category, Tier, CheckID, VerificationCheckID, SupportedOS, RequiresAdmin, RequiresReboot, SupportsRollback, EstimatedTimeSec, Executor, Command, RollbackCommand, ManualSteps}`, `remediation.NewCatalog() (*Catalog, error)`, `(*Catalog).Lookup(checkID string) (CatalogEntry, bool)`, `(*Catalog).ByID(id string) (CatalogEntry, bool)` — consumed by every later task.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/remediation/catalog_test.go
package remediation

import "testing"

func TestNewCatalog_LoadsEmbeddedFile(t *testing.T) {
	c, err := NewCatalog()
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	entry, ok := c.Lookup("windows-firewall-enabled")
	if !ok {
		t.Fatal("expected windows-firewall-enabled to be mapped")
	}
	if entry.ID != "enable_windows_firewall" || entry.Tier != TierSafeAutomatic {
		t.Errorf("entry = %+v, want id=enable_windows_firewall tier=1", entry)
	}
}

func TestCatalogByID_FindsEntry(t *testing.T) {
	c, err := NewCatalog()
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	entry, ok := c.ByID("enable_bitlocker")
	if !ok || entry.Tier != TierManualGuidance {
		t.Errorf("entry = %+v ok=%v, want enable_bitlocker/TierManualGuidance", entry, ok)
	}
	if entry.Command != "" {
		t.Error("expected a Tier 4 entry to have no command")
	}
	if len(entry.ManualSteps) == 0 {
		t.Error("expected a Tier 4 entry to have manual_steps")
	}
}

func TestCatalogLookup_UnknownCheckID_NotOK(t *testing.T) {
	c, err := NewCatalog()
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	_, ok := c.Lookup("no-such-check")
	if ok {
		t.Error("expected ok=false for an unmapped check_id")
	}
}

func TestCatalogTier2Entry_HasCommandAndRollback(t *testing.T) {
	c, err := NewCatalog()
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	entry, ok := c.ByID("disable_windows_smbv1")
	if !ok || entry.Tier != TierConfirmRequired {
		t.Fatalf("entry = %+v ok=%v, want disable_windows_smbv1/TierConfirmRequired", entry, ok)
	}
	if entry.Command == "" || !entry.SupportsRollback || entry.RollbackCommand == "" {
		t.Errorf("entry = %+v, want a command and rollback support", entry)
	}
	if !entry.RequiresReboot {
		t.Error("expected disable_windows_smbv1 to declare requires_reboot=true")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/remediation/... -run TestNewCatalog -v`
Expected: FAIL — `internal/remediation` package doesn't exist yet (no Go files, build error) or `NewCatalog` undefined.

- [ ] **Step 3: Write `catalog.yaml`**

```yaml
remediations:
  - id: enable_windows_firewall
    title: Enable Windows Firewall
    category: security-configuration
    tier: 1
    check_id: windows-firewall-enabled
    verification_check_id: windows-firewall-enabled
    supported_os: [windows]
    requires_admin: true
    requires_reboot: false
    supports_rollback: true
    estimated_time_sec: 30
    executor: local
    command: "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True"
    rollback_command: "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False"
    description: "Enables Windows Firewall for the Domain, Private, and Public profiles."

  - id: disable_windows_smbv1
    title: Disable SMBv1
    category: security-configuration
    tier: 2
    check_id: windows-smbv1-disabled
    verification_check_id: windows-smbv1-disabled
    supported_os: [windows]
    requires_admin: true
    requires_reboot: true
    supports_rollback: true
    estimated_time_sec: 60
    executor: local
    command: "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
    rollback_command: "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
    description: "Disables the legacy, vulnerable SMBv1 protocol. Requires a reboot to fully take effect."

  - id: enable_bitlocker
    title: Enable BitLocker
    category: security-configuration
    tier: 4
    check_id: windows-bitlocker-enabled
    supported_os: [windows]
    supports_rollback: false
    manual_steps:
      - "Back up the recovery key to Azure AD or a secure location first."
      - "Run: Enable-BitLocker -MountPoint C: -RecoveryPasswordProtector"
      - "Confirm encryption status: Get-BitLockerVolume"
    description: "BitLocker requires recovery-key escrow before enabling -- not safe to automate."
```

- [ ] **Step 4: Write `catalog.go`**

```go
package remediation

import (
	"embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed catalog.yaml
var catalogFS embed.FS

// Tier is the remediation execution tier -- how much human gate a
// remediation needs before it runs. Tier 3 (scheduled/maintenance-window)
// is reserved for Sub-project 6 and must never appear in this catalog.
type Tier int

const (
	TierSafeAutomatic   Tier = 1
	TierConfirmRequired Tier = 2
	TierManualGuidance  Tier = 4
)

// CatalogEntry is one remediation definition. Exported so callers
// (internal/api's Finding-enrichment and orchestration code) can read its
// fields directly.
type CatalogEntry struct {
	ID                   string   `yaml:"id"`
	Title                string   `yaml:"title"`
	Description          string   `yaml:"description"`
	Category             string   `yaml:"category"`
	Tier                 Tier     `yaml:"tier"`
	CheckID              string   `yaml:"check_id"`
	VerificationCheckID  string   `yaml:"verification_check_id,omitempty"`
	SupportedOS          []string `yaml:"supported_os"`
	RequiresAdmin        bool     `yaml:"requires_admin,omitempty"`
	RequiresReboot       bool     `yaml:"requires_reboot,omitempty"`
	SupportsRollback     bool     `yaml:"supports_rollback,omitempty"`
	EstimatedTimeSec     int      `yaml:"estimated_time_sec,omitempty"`
	Executor             string   `yaml:"executor,omitempty"`
	Command              string   `yaml:"command,omitempty"`
	RollbackCommand      string   `yaml:"rollback_command,omitempty"`
	ManualSteps          []string `yaml:"manual_steps,omitempty"`
}

type catalogFile struct {
	Remediations []CatalogEntry `yaml:"remediations"`
}

// Catalog is the embedded, hand-curated set of remediation definitions,
// indexed by both id and check_id for O(1) lookup either way.
type Catalog struct {
	byID      map[string]CatalogEntry
	byCheckID map[string]CatalogEntry
}

// NewCatalog loads and validates the embedded catalog.yaml: unique id,
// non-empty check_id/supported_os, and the tier/command/manual_steps
// pairing (Tier 1/2 need a command and no manual_steps; Tier 4 needs
// manual_steps and no command) -- a violation is a load-time error, not a
// runtime surprise.
func NewCatalog() (*Catalog, error) {
	data, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("remediation: read catalog.yaml: %w", err)
	}
	var cf catalogFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("remediation: parse catalog.yaml: %w", err)
	}
	if len(cf.Remediations) == 0 {
		return nil, fmt.Errorf("remediation: no catalog entries loaded")
	}
	byID := make(map[string]CatalogEntry, len(cf.Remediations))
	byCheckID := make(map[string]CatalogEntry, len(cf.Remediations))
	for _, e := range cf.Remediations {
		if e.ID == "" || e.CheckID == "" || len(e.SupportedOS) == 0 {
			return nil, fmt.Errorf("remediation: entry missing id/check_id/supported_os: %+v", e)
		}
		if _, dup := byID[e.ID]; dup {
			return nil, fmt.Errorf("remediation: duplicate catalog id %q", e.ID)
		}
		switch e.Tier {
		case TierSafeAutomatic, TierConfirmRequired:
			if e.Command == "" {
				return nil, fmt.Errorf("remediation: tier 1/2 entry %q missing command", e.ID)
			}
			if len(e.ManualSteps) > 0 {
				return nil, fmt.Errorf("remediation: tier 1/2 entry %q must not have manual_steps", e.ID)
			}
		case TierManualGuidance:
			if e.Command != "" {
				return nil, fmt.Errorf("remediation: tier 4 entry %q must not have a command", e.ID)
			}
			if len(e.ManualSteps) == 0 {
				return nil, fmt.Errorf("remediation: tier 4 entry %q missing manual_steps", e.ID)
			}
		default:
			return nil, fmt.Errorf("remediation: entry %q has unsupported tier %d", e.ID, e.Tier)
		}
		byID[e.ID] = e
		byCheckID[e.CheckID] = e
	}
	return &Catalog{byID: byID, byCheckID: byCheckID}, nil
}

// Lookup finds the remediation catalog entry for a finding's check_id.
func (c *Catalog) Lookup(checkID string) (CatalogEntry, bool) {
	e, ok := c.byCheckID[checkID]
	return e, ok
}

// ByID finds a catalog entry by its own id (used once execution is
// requested with an explicit remediationId).
func (c *Catalog) ByID(id string) (CatalogEntry, bool) {
	e, ok := c.byID[id]
	return e, ok
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/remediation/... -v`
Expected: PASS for all 4 tests.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/remediation/catalog.yaml orchestrator/internal/remediation/catalog.go orchestrator/internal/remediation/catalog_test.go
git commit -m "feat(remediation): add embedded remediation catalog"
git push
```

---

### Task 2: `RemediationRequest` types, state machine, and `remediation_requests` table

**Files:**
- Create: `orchestrator/internal/remediation/types.go`
- Test: `orchestrator/internal/remediation/types_test.go`
- Modify: `orchestrator/internal/db/postgres.go` (append table to the migration list)
- Test: `orchestrator/internal/api/remediation_schema_test.go`

**Interfaces:**
- Consumes: `remediation.Tier` (Task 1).
- Produces: `remediation.RemediationRequest{...}` struct, `remediation.Status*` string constants, `remediation.IsTerminal(status string) bool`, the `remediation_requests` table — consumed by every later task.

- [ ] **Step 1: Write the failing test for `IsTerminal`**

```go
// orchestrator/internal/remediation/types_test.go
package remediation

import "testing"

func TestIsTerminal(t *testing.T) {
	terminal := []string{StatusCompleted, StatusFailed, StatusVerificationFailed, StatusTimedOut, StatusCancelled}
	for _, s := range terminal {
		if !IsTerminal(s) {
			t.Errorf("IsTerminal(%q) = false, want true", s)
		}
	}
	nonTerminal := []string{StatusRequested, StatusDispatched, StatusRunning, StatusVerifying}
	for _, s := range nonTerminal {
		if IsTerminal(s) {
			t.Errorf("IsTerminal(%q) = true, want false", s)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/remediation/... -run TestIsTerminal -v`
Expected: FAIL — `StatusCompleted`/`IsTerminal` undefined (compile error).

- [ ] **Step 3: Write `types.go`**

```go
package remediation

import "time"

const (
	StatusRequested          = "requested"
	StatusDispatched         = "dispatched"
	StatusRunning            = "running"
	StatusVerifying          = "verifying"
	StatusCompleted          = "completed"
	StatusFailed             = "failed"             // the fix command itself failed
	StatusVerificationFailed = "verification_failed" // fix command exited cleanly, but the check still fails
	StatusTimedOut           = "timed_out"
	StatusCancelled          = "cancelled"
)

// IsTerminal reports whether status is a terminal state -- no further
// state-machine transitions happen once a request reaches one of these.
func IsTerminal(status string) bool {
	switch status {
	case StatusCompleted, StatusFailed, StatusVerificationFailed, StatusTimedOut, StatusCancelled:
		return true
	}
	return false
}

// RemediationRequest is the full record of one endpoint's attempt to run
// one remediation -- every field is a column in internal/api's
// remediation_requests table, mirroring how internal/actions.Action maps
// onto action_requests.
type RemediationRequest struct {
	ID                      string
	RemediationID           string
	AgentID                 string
	CheckID                 string
	Tier                    Tier
	Status                  string
	FixRunID                string
	VerifyRunID             string
	Error                   string
	RequestedBy             string
	ApprovedBy              string
	Reason                  string
	RollbackAvailable       bool
	RollbackStatus          string
	RollbackRunID           string
	RollbackVerifyRunID     string
	RequestedAt             time.Time
	DispatchedAt            *time.Time
	ExecutionCompletedAt    *time.Time
	VerificationCompletedAt *time.Time
	CompletedAt             *time.Time
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/remediation/... -v`
Expected: PASS for all tests in the package.

- [ ] **Step 5: Add the `remediation_requests` table to the schema migration**

In `orchestrator/internal/db/postgres.go`, in the `stmts := []string{...}` slice inside `EnsureSchema`, right after the `threat_actor_profiles` table (the last entry before the closing `}`):

```go
		`CREATE TABLE IF NOT EXISTS threat_actor_profiles (
			name       text        PRIMARY KEY,
			aliases    text[]      NOT NULL DEFAULT '{}',
			sectors    text[]      NOT NULL DEFAULT '{}',
			regions    text[]      NOT NULL DEFAULT '{}',
			source     text        NOT NULL DEFAULT '',
			last_seen  timestamptz,
			updated_at timestamptz NOT NULL DEFAULT NOW()
		)`,

		// remediation_requests: full audit trail + state machine for one
		// endpoint's attempt to run one remediation catalog entry. See
		// docs/superpowers/specs/2026-08-03-remediation-execution-design.md.
		`CREATE TABLE IF NOT EXISTS remediation_requests (
			id                          text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			remediation_id              text        NOT NULL,
			agent_id                    text        NOT NULL,
			check_id                    text        NOT NULL,
			tier                        int         NOT NULL,
			status                      text        NOT NULL,
			fix_run_id                  text        NOT NULL DEFAULT '',
			verify_run_id               text        NOT NULL DEFAULT '',
			error                       text        NOT NULL DEFAULT '',
			requested_by                text        NOT NULL DEFAULT '',
			approved_by                 text        NOT NULL DEFAULT '',
			reason                      text        NOT NULL DEFAULT '',
			rollback_available          boolean     NOT NULL DEFAULT false,
			rollback_status             text        NOT NULL DEFAULT '',
			rollback_run_id             text        NOT NULL DEFAULT '',
			rollback_verify_run_id      text        NOT NULL DEFAULT '',
			requested_at                timestamptz NOT NULL DEFAULT NOW(),
			dispatched_at               timestamptz,
			execution_completed_at      timestamptz,
			verification_completed_at   timestamptz,
			completed_at                timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_remediation_requests_agent_id ON remediation_requests (agent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_remediation_requests_fix_run_id ON remediation_requests (fix_run_id) WHERE fix_run_id != ''`,
		`CREATE INDEX IF NOT EXISTS idx_remediation_requests_verify_run_id ON remediation_requests (verify_run_id) WHERE verify_run_id != ''`,
	}
```

- [ ] **Step 6: Write a DB-backed test confirming the table accepts a full row**

```go
// orchestrator/internal/api/remediation_schema_test.go
package api

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRemediationRequestsTable_AcceptsFullRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-rm-a1', 'ER-RM-HOST')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests
				(id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available)
			VALUES ('rr-1', 'enable_windows_firewall', 'er-rm-a1', 'windows-firewall-enabled', 1, 'requested', 'user-1', 'test', true)`)

		var status string
		var tier int
		if err := pool.QueryRow(t.Context(),
			`SELECT status, tier FROM remediation_requests WHERE id = 'rr-1'`,
		).Scan(&status, &tier); err != nil {
			t.Fatalf("query: %v", err)
		}
		if status != "requested" || tier != 1 {
			t.Errorf("status/tier = %s/%d, want requested/1", status, tier)
		}
	})
}
```

- [ ] **Step 7: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestRemediationRequestsTable -v`
Expected: PASS.

- [ ] **Step 8: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/remediation/types.go orchestrator/internal/remediation/types_test.go orchestrator/internal/db/postgres.go orchestrator/internal/api/remediation_schema_test.go
git commit -m "feat(remediation): add RemediationRequest types, state machine, and remediation_requests table"
git push
```

---

### Task 3: `Finding` fixability fields + catalog wiring into `postureCheckInput`

**Files:**
- Modify: `orchestrator/internal/endpointrisk/types.go` (`Finding` struct)
- Modify: `orchestrator/internal/api/endpointrisk_aggregations.go` (`postureCheckInput`)
- Modify: `orchestrator/internal/api/handlers.go` (`Handler` struct + `WithRemediationCatalog`)
- Modify: `orchestrator/cmd/server/main.go` (construct + wire the catalog)
- Test: `orchestrator/internal/api/endpointrisk_aggregations_test.go`

**Interfaces:**
- Consumes: `remediation.NewCatalog()`, `(*remediation.Catalog).Lookup` (Task 1).
- Produces: `Finding.RemediationID/Tier/EstimatedTimeSec/RequiresReboot/RollbackAvailable/CanFix` fields; `(h *Handler) enrichFindingWithRemediation(f *endpointrisk.Finding, checkID string)` — consumed nowhere else in this plan, but this is the field the frontend Execute button will eventually read.

- [ ] **Step 1: Add the fixability fields to `Finding`**

In `orchestrator/internal/endpointrisk/types.go`, in the `Finding` struct, right after `LastPassed`:

```go
	LastPassed       *time.Time `json:"lastPassed,omitempty"`
	// RemediationID/Tier/EstimatedTimeSec/RequiresReboot/RollbackAvailable/CanFix
	// are populated by internal/api's postureCheckInput via a remediation
	// catalog lookup keyed on this Finding's ID (its check_id) -- see
	// Sub-project 4's design spec §3.4. Zero-valued (CanFix=false) for any
	// finding with no catalog entry, including every Application Risk
	// finding (a different ID namespace -- see that sub-project's plan).
	RemediationID     string `json:"remediationId,omitempty"`
	Tier              int    `json:"tier,omitempty"`
	EstimatedTimeSec  int    `json:"estimatedTimeSec,omitempty"`
	RequiresReboot    bool   `json:"requiresReboot,omitempty"`
	RollbackAvailable bool   `json:"rollbackAvailable,omitempty"`
	CanFix            bool   `json:"canFix"`
}
```

- [ ] **Step 2: Write the failing test**

Add to `orchestrator/internal/api/endpointrisk_aggregations_test.go`:

```go
func TestPostureCheckInput_EnrichesFindingWithRemediation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-rem-a1', 'ER-REM-HOST')`)
		now := time.Now().UTC()
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-rem-run', 'windows-security-config', 'Posture Run', 'er-rem-a1', 'completed', $1::jsonb, NOW())`,
			`[{"checkId":"windows-firewall-enabled","result":"fail","executedAt":"`+now.Format(time.RFC3339)+`"}]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		tx, err := endpointrisk.NewTaxonomy()
		if err != nil {
			t.Fatalf("NewTaxonomy: %v", err)
		}
		h.endpointRiskTaxonomy = tx
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h.remediationCatalog = cat

		all := h.aggregateAgentResults(context.Background(), "er-rem-a1")
		got := h.securityConfigInput(context.Background(), "er-rem-a1", now.Add(time.Hour), all)
		if len(got.Findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(got.Findings))
		}
		f := got.Findings[0]
		if !f.CanFix || f.RemediationID != "enable_windows_firewall" || f.Tier != 1 || !f.RollbackAvailable {
			t.Errorf("finding = %+v, want CanFix=true RemediationID=enable_windows_firewall Tier=1 RollbackAvailable=true", f)
		}
	})
}

func TestPostureCheckInput_NoCatalogEntry_NotFixable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-rem-a2', 'ER-REM-HOST-2')`)
		now := time.Now().UTC()
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-rem-run-2', 'windows-security-config', 'Posture Run 2', 'er-rem-a2', 'completed', $1::jsonb, NOW())`,
			`[{"checkId":"windows-defender-realtime","result":"fail","executedAt":"`+now.Format(time.RFC3339)+`"}]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		tx, err := endpointrisk.NewTaxonomy()
		if err != nil {
			t.Fatalf("NewTaxonomy: %v", err)
		}
		h.endpointRiskTaxonomy = tx
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h.remediationCatalog = cat

		all := h.aggregateAgentResults(context.Background(), "er-rem-a2")
		got := h.securityConfigInput(context.Background(), "er-rem-a2", now.Add(time.Hour), all)
		if len(got.Findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(got.Findings))
		}
		if got.Findings[0].CanFix {
			t.Error("expected CanFix=false -- windows-defender-realtime has no catalog entry")
		}
	})
}
```

Add `"github.com/audspect/bas/internal/remediation"` to this test file's import block.

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestPostureCheckInput_Enriches -v`
Expected: FAIL — `h.remediationCatalog` undefined (compile error).

- [ ] **Step 4: Add the `enrichFindingWithRemediation` helper and wire it into `postureCheckInput`**

In `orchestrator/internal/api/endpointrisk_aggregations.go`, add `"github.com/audspect/bas/internal/remediation"` to the import block, then add near `postureCheckInput`:

```go
// enrichFindingWithRemediation attaches fixability fields to f by looking
// up checkID in the remediation catalog. A no-op (f stays zero-valued,
// CanFix=false) when the catalog isn't loaded or has no entry for this
// check -- exactly the same "absent means not yet available" pattern
// every other optional Handler dependency in this file already follows.
func (h *Handler) enrichFindingWithRemediation(f *endpointrisk.Finding, checkID string) {
	if h.remediationCatalog == nil {
		return
	}
	entry, ok := h.remediationCatalog.Lookup(checkID)
	if !ok {
		return
	}
	f.RemediationID = entry.ID
	f.Tier = int(entry.Tier)
	f.EstimatedTimeSec = entry.EstimatedTimeSec
	f.RequiresReboot = entry.RequiresReboot
	f.RollbackAvailable = entry.SupportsRollback
	f.CanFix = entry.Tier != remediation.TierManualGuidance
}
```

Then in `postureCheckInput`, right after the `findings = append(findings, endpointrisk.Finding{...})` call (inside the `for checkID, l := range byCheck` loop's `failed++` branch):

```go
		failed++
		text := postureCheckFindingText[checkID]
		observedAt := l.result.ExecutedAt
		findings = append(findings, endpointrisk.Finding{
			ID: checkID, Title: text.Title, Description: text.Description,
			Severity: "Medium", Risk: text.Description,
			Remediation: text.Remediation, Reference: text.Reference,
			Expected: text.Expected, Observed: text.Observed,
			Passed: false, LastObserved: &observedAt, LastPassed: l.lastPassed,
		})
		h.enrichFindingWithRemediation(&findings[len(findings)-1], checkID)
```

- [ ] **Step 5: Add the `remediationCatalog` field and `WithRemediationCatalog` method**

In `orchestrator/internal/api/handlers.go`, add the field next to `eolCatalog`:

```go
	eolCatalog            *endpointrisk.Catalog  // nil when not loaded
	remediationCatalog    *remediation.Catalog   // nil when not loaded
```

Add `"github.com/audspect/bas/internal/remediation"` to this file's import block. Add a `With` method next to `WithEOLCatalog`:

```go
// WithRemediationCatalog attaches the endpoint remediation catalog.
func (h *Handler) WithRemediationCatalog(c *remediation.Catalog) *Handler {
	h.remediationCatalog = c
	return h
}
```

- [ ] **Step 6: Wire construction in `main.go`**

In `orchestrator/cmd/server/main.go`, right after the Application Risk EOL catalog block:

```go
	// ── Endpoint Remediation Catalog ────────────────────────────────────────
	remediationCatalog, remErr := remediation.NewCatalog()
	if remErr != nil {
		log.Printf("[!] remediation catalog: %v — one-click remediation unavailable", remErr)
	} else {
		log.Printf("[+] Remediation catalog loaded")
	}
```

Add `"github.com/audspect/bas/internal/remediation"` to `main.go`'s import block. Add `.WithRemediationCatalog(remediationCatalog).` to the handler chain right after `.WithEOLCatalog(eolCatalog).`.

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestPostureCheckInput -v`
Expected: PASS for all `TestPostureCheckInput*` tests, including the two new ones.

- [ ] **Step 8: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/endpointrisk/types.go orchestrator/internal/api/endpointrisk_aggregations.go orchestrator/internal/api/endpointrisk_aggregations_test.go orchestrator/internal/api/handlers.go orchestrator/cmd/server/main.go
git commit -m "feat(api): enrich posture-check Findings with remediation fixability fields"
git push
```

---

### Task 4: RBAC permissions

**Files:**
- Modify: `orchestrator/internal/auth/permissions.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Produces: `auth.CanExecuteRemediation`, `auth.CanApproveRemediation` (Permission constants) — consumed by Task 6, 8, 9, 10's route registrations and handlers.

- [ ] **Step 1: Add the two new permission constants**

In `orchestrator/internal/auth/permissions.go`, right after the SCIM block (before the closing `)` of the `const` block):

```go
	// SCIM provisioning — Admin only. Separate from SSO's permissions:
	// different protocol, different admin action (rotate a token vs.
	// configure an IdP issuer).
	CanViewSCIMConfig   Permission = "scim:config:view"
	CanManageSCIMConfig Permission = "scim:config:manage"

	// Endpoint Remediation Execution — CanExecuteRemediation is Analyst+Admin
	// (Tier 1 fixes); CanApproveRemediation is Admin-only, deliberately
	// stricter (Tier 2 fixes and every rollback -- reversing a security
	// control is inherently risk-increasing, mirroring how
	// CanExecuteResponseAction is stricter than every other "run"
	// permission in this file).
	CanExecuteRemediation Permission = "remediation:execute"
	CanApproveRemediation Permission = "remediation:approve"
)
```

- [ ] **Step 2: Add both permissions to `RoleAdmin`**

In the `rolePermissions` map's `RoleAdmin` entry, right after `CanViewSCIMConfig: true, CanManageSCIMConfig: true,`:

```go
		CanViewSCIMConfig: true, CanManageSCIMConfig: true,
		CanExecuteRemediation: true, CanApproveRemediation: true,
	},
```

- [ ] **Step 3: Add `CanExecuteRemediation` to `RoleAnalyst`**

In the `rolePermissions` map's `RoleAnalyst` entry, right after `CanViewResponseActions: true,`:

```go
		CanViewResponseActions: true,
		CanExecuteRemediation:  true,
	},
```

(`CanApproveRemediation` stays Admin-only — deliberately absent from `RoleAnalyst`.)

- [ ] **Step 4: Add both permissions to the `Permissions()` iteration slice**

In `Permissions()`'s `for _, p := range []Permission{...}` slice, right after `CanViewSCIMConfig, CanManageSCIMConfig,`:

```go
		CanViewSCIMConfig, CanManageSCIMConfig,

		CanExecuteRemediation, CanApproveRemediation,
	} {
```

- [ ] **Step 5: Write the failing RBAC test**

Add to `orchestrator/internal/auth/permissions_test.go` (create if it doesn't already cover this):

```go
func TestCanApproveRemediation_AdminOnly(t *testing.T) {
	if !HasPermission(RoleAdmin, CanApproveRemediation) {
		t.Error("expected RoleAdmin to hold CanApproveRemediation")
	}
	if HasPermission(RoleAnalyst, CanApproveRemediation) {
		t.Error("expected RoleAnalyst NOT to hold CanApproveRemediation")
	}
}

func TestCanExecuteRemediation_AnalystAndAdmin(t *testing.T) {
	if !HasPermission(RoleAdmin, CanExecuteRemediation) {
		t.Error("expected RoleAdmin to hold CanExecuteRemediation")
	}
	if !HasPermission(RoleAnalyst, CanExecuteRemediation) {
		t.Error("expected RoleAnalyst to hold CanExecuteRemediation")
	}
	if HasPermission(RoleViewer, CanExecuteRemediation) {
		t.Error("expected RoleViewer NOT to hold CanExecuteRemediation")
	}
}
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/auth/... -run "TestCanApproveRemediation|TestCanExecuteRemediation" -v`
Expected: FAIL — `CanApproveRemediation`/`CanExecuteRemediation` undefined (compile error).

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/auth/... -v`
Expected: PASS for all tests in the package, including the two new ones.

- [ ] **Step 8: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/auth/permissions.go orchestrator/internal/auth/permissions_test.go
git commit -m "feat(auth): add CanExecuteRemediation and CanApproveRemediation permissions"
git push
```

(Route-matrix table rows for the new endpoints are added in Task 6, once those routes exist — `rbac_matrix_test.go`'s `TestRBACMatrix_NoDrift` checks the table against the live router, so adding rows before the routes exist would fail that drift check.)

---

### Task 5: Pre-flight OS-match validation

**Files:**
- Create: `orchestrator/internal/remediation/preflight.go`
- Test: `orchestrator/internal/remediation/preflight_test.go`

**Interfaces:**
- Consumes: `remediation.CatalogEntry` (Task 1).
- Produces: `remediation.OSSupported(agentOS string, entry CatalogEntry) bool` — consumed by Task 6's `ExecuteRemediation` handler. (The "already compliant" pre-flight check requires DB-fetched `[]models.SimulationResult` data and is implemented directly in Task 6's handler, not here — this package has no DB access, matching `internal/endpointrisk`'s pure-only design.)

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/remediation/preflight_test.go
package remediation

import "testing"

func TestOSSupported_ExactMatch(t *testing.T) {
	entry := CatalogEntry{SupportedOS: []string{"windows"}}
	if !OSSupported("windows", entry) {
		t.Error("expected windows to match")
	}
}

func TestOSSupported_CaseInsensitive(t *testing.T) {
	entry := CatalogEntry{SupportedOS: []string{"Windows"}}
	if !OSSupported("WINDOWS", entry) {
		t.Error("expected case-insensitive match")
	}
}

func TestOSSupported_Mismatch(t *testing.T) {
	entry := CatalogEntry{SupportedOS: []string{"windows"}}
	if OSSupported("linux", entry) {
		t.Error("expected linux not to match a windows-only entry")
	}
}

func TestOSSupported_EmptyAgentOS(t *testing.T) {
	entry := CatalogEntry{SupportedOS: []string{"windows"}}
	if OSSupported("", entry) {
		t.Error("expected an unknown/empty agent OS not to match")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/remediation/... -run TestOSSupported -v`
Expected: FAIL — `OSSupported` undefined (compile error).

- [ ] **Step 3: Write `preflight.go`**

```go
package remediation

import "strings"

// OSSupported reports whether agentOS (e.g. "windows", "linux", as stored
// on the agents.os_version column) is in entry's supported_os list.
// Case-insensitive; an empty agentOS never matches.
func OSSupported(agentOS string, entry CatalogEntry) bool {
	if agentOS == "" {
		return false
	}
	agentOS = strings.ToLower(agentOS)
	for _, os := range entry.SupportedOS {
		if strings.ToLower(os) == agentOS {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/remediation/... -v`
Expected: PASS for every test in the package.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/remediation/preflight.go orchestrator/internal/remediation/preflight_test.go
git commit -m "feat(remediation): add OS-match pre-flight validation"
git push
```

---

### Task 6: Dispatch helper + `ExecuteRemediation` handler + routes

**Files:**
- Create: `orchestrator/internal/api/remediation_dispatch.go`
- Create: `orchestrator/internal/api/remediation_handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Test: `orchestrator/internal/api/remediation_handlers_test.go`

**Interfaces:**
- Consumes: `scenario.BuildSteps`, `scenario.Scenario`/`scenario.Step`/`scenario.ScenarioCommand`, `h.hub.SendToAgent`, `h.persistStepMeta` (all existing), `remediation.Catalog`/`OSSupported`/`Status*` (Tasks 1, 5), `auth.CanExecuteRemediation`/`CanApproveRemediation` (Task 4).
- Produces: `(h *Handler) dispatchRemediationStep(ctx, agentID, scenarioIDPrefix, remediationID, command, executor string, timeoutSec int) (runID string, sent bool, err error)`, `(h *Handler) findStepByCheckID(checkID string) (scenario.Step, bool)`, `(h *Handler) ExecuteRemediation(w, r)` — consumed by Tasks 7, 8, 9, 10.

- [ ] **Step 1: Write `remediation_dispatch.go`**

```go
package api

import (
	"context"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
)

// findStepByCheckID searches every loaded scenario for a step with the
// given check_id, returning its Command/Executor/TimeoutSec. Used to
// re-run a finding's own posture check as remediation verification,
// without duplicating that check's command inside the remediation
// catalog -- the catalog only ever references check_id by name.
func (h *Handler) findStepByCheckID(checkID string) (scenario.Step, bool) {
	for _, sc := range h.engine.List() {
		for _, st := range sc.Steps {
			if st.CheckID == checkID {
				return st, true
			}
		}
	}
	return scenario.Step{}, false
}

// dispatchRemediationStep builds an ephemeral, never-persisted Scenario
// containing exactly one local/custom step, builds it into agent-ready
// ScenarioSteps via the existing scenario.BuildSteps pipeline, inserts a
// tracking scenario_runs row, and dispatches it to the agent over the
// existing MsgCommandScenario/SubmitScenarioResult pipeline -- the same
// mechanism TriggerScan already uses to dispatch "full-scan", just against
// an in-memory Scenario instead of one loaded from h.engine.
//
// scenarioIDPrefix becomes part of the scenario_runs.id's scenario_id
// value (e.g. "remediation-fix", "remediation-verify",
// "remediation-rollback", "remediation-rollback-verify") for human-
// readable scenario_runs browsing -- Task 7's continuation hook matches on
// the run's own id against remediation_requests' four run-id columns, not
// on this prefix, so it's not load-bearing for correctness.
func (h *Handler) dispatchRemediationStep(ctx context.Context, agentID, scenarioIDPrefix, remediationID, command, executor string, timeoutSec int) (runID string, sent bool, err error) {
	scenarioID := scenarioIDPrefix + ":" + remediationID

	var agentOS string
	h.db.QueryRow(ctx, `SELECT COALESCE(os_version,'windows') FROM agents WHERE agent_id=$1`, agentID).Scan(&agentOS)

	sc := &scenario.Scenario{
		ID:         scenarioID,
		Name:       scenarioIDPrefix,
		LocalCheck: true,
		Steps: []scenario.Step{{
			Name:       scenarioID,
			Framework:  "custom",
			Executor:   executor,
			Command:    command,
			TimeoutSec: timeoutSec,
		}},
	}
	steps, err := scenario.BuildSteps(sc, h.calderaURL, h.calderaKey, h.artStore, agentOS)
	if err != nil {
		return "", false, err
	}

	runID = newID()
	if _, err = h.db.Exec(ctx,
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at)
		 VALUES ($1, $2, $3, $4, 'running', NOW())`,
		runID, sc.ID, agentID, sc.Name,
	); err != nil {
		return "", false, err
	}
	h.persistStepMeta(ctx, runID, steps)

	cmd := scenario.ScenarioCommand{RunID: runID, ScenarioID: sc.ID, Name: sc.Name, Steps: steps}
	sent = h.hub.SendToAgent(agentID, models.WSMessage{Type: models.MsgCommandScenario, AgentID: agentID, Data: cmd})
	if !sent {
		h.db.Exec(context.Background(), `UPDATE scenario_runs SET status='failed', completed_at=NOW() WHERE id=$1`, runID)
	}
	return runID, sent, nil
}

// latestCheckIsPassing reports whether the most recent result for checkID
// in allResults is a PASS -- used as the "already compliant" pre-flight
// check before dispatching a fix.
func latestCheckIsPassing(allResults []models.SimulationResult, checkID string) bool {
	var latest *models.SimulationResult
	for i := range allResults {
		r := &allResults[i]
		if r.CheckID != checkID {
			continue
		}
		if latest == nil || r.ExecutedAt.After(latest.ExecutedAt) {
			latest = r
		}
	}
	return latest != nil && latest.Result == models.ResultPass
}
```

- [ ] **Step 2: Write the failing tests for `ExecuteRemediation`**

```go
// orchestrator/internal/api/remediation_handlers_test.go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestExecuteRemediation_Tier1_DispatchesFix(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-ex-a1', 'ER-EX-HOST', 'windows')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h.remediationCatalog = cat

		body := strings.NewReader(`{"remediationId":"enable_windows_firewall","reason":"test"}`)
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", body), "agentId", "er-ex-a1")
		w := httptest.NewRecorder()
		h.ExecuteRemediation(w, req)

		// No agent is connected in this test, so dispatch fails and the
		// request should end in StatusFailed -- but it must still be
		// INSERTed and pre-flight-validated correctly first.
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			RequestID string `json:"requestId"`
			Status    string `json:"status"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.Status != remediation.StatusFailed {
			t.Errorf("status = %q, want %q (no agent connected)", resp.Status, remediation.StatusFailed)
		}

		var dbStatus, errText string
		pool.QueryRow(context.Background(), `SELECT status, error FROM remediation_requests WHERE id=$1`, resp.RequestID).
			Scan(&dbStatus, &errText)
		if dbStatus != remediation.StatusFailed || errText != "agent not connected" {
			t.Errorf("db status/error = %s/%s, want failed/agent not connected", dbStatus, errText)
		}
	})
}

func TestExecuteRemediation_UnknownRemediationID_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-ex-a2', 'ER-EX-HOST-2', 'windows')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		body := strings.NewReader(`{"remediationId":"no-such-remediation","reason":"test"}`)
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", body), "agentId", "er-ex-a2")
		w := httptest.NewRecorder()
		h.ExecuteRemediation(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}

func TestExecuteRemediation_Tier4_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-ex-a3', 'ER-EX-HOST-3', 'windows')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		body := strings.NewReader(`{"remediationId":"enable_bitlocker","reason":"test"}`)
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", body), "agentId", "er-ex-a3")
		w := httptest.NewRecorder()
		h.ExecuteRemediation(w, req)
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("status = %d, want 422 (Tier 4 is manual guidance only)", w.Code)
		}
	})
}

func TestExecuteRemediation_AlreadyCompliant_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-ex-a4', 'ER-EX-HOST-4', 'windows')`)
		now := time.Now().UTC()
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-ex-run-4', 'windows-security-config', 'Posture Run', 'er-ex-a4', 'completed', $1::jsonb, NOW())`,
			`[{"checkId":"windows-firewall-enabled","result":"pass","executedAt":"`+now.Format(time.RFC3339)+`"}]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		body := strings.NewReader(`{"remediationId":"enable_windows_firewall","reason":"test"}`)
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", body), "agentId", "er-ex-a4")
		w := httptest.NewRecorder()
		h.ExecuteRemediation(w, req)
		if w.Code != http.StatusConflict {
			t.Errorf("status = %d, want 409 (already compliant)", w.Code)
		}
	})
}

func TestExecuteRemediation_OSMismatch_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-ex-a5', 'ER-EX-HOST-5', 'linux')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		body := strings.NewReader(`{"remediationId":"enable_windows_firewall","reason":"test"}`)
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", body), "agentId", "er-ex-a5")
		w := httptest.NewRecorder()
		h.ExecuteRemediation(w, req)
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("status = %d, want 422 (Linux agent, Windows-only remediation)", w.Code)
		}
	})
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestExecuteRemediation -v`
Expected: FAIL — `h.ExecuteRemediation` undefined (compile error).

- [ ] **Step 4: Write `remediation_handlers.go`'s `ExecuteRemediation`**

```go
package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/remediation"
)

// POST /api/agents/{agentId}/remediations
func (h *Handler) ExecuteRemediation(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	var req struct {
		RemediationID string `json:"remediationId"`
		Reason        string `json:"reason"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.RemediationID == "" {
		jsonError(w, "remediationId is required", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}
	if h.remediationCatalog == nil {
		jsonError(w, "remediation catalog not loaded", http.StatusServiceUnavailable)
		return
	}
	entry, ok := h.remediationCatalog.ByID(req.RemediationID)
	if !ok {
		jsonError(w, "unknown remediationId", http.StatusNotFound)
		return
	}
	if entry.Tier == remediation.TierManualGuidance {
		jsonError(w, "this remediation is manual guidance only -- no automatic execution", http.StatusUnprocessableEntity)
		return
	}

	claims, _ := auth.ClaimsFrom(r.Context())
	if entry.Tier == remediation.TierConfirmRequired && (claims == nil || !auth.HasPermission(claims.Role, auth.CanApproveRemediation)) {
		jsonError(w, "this remediation requires an Administrator", http.StatusForbidden)
		return
	}

	var agentExists bool
	var agentOS string
	h.db.QueryRow(r.Context(), `SELECT true, COALESCE(os_version,'') FROM agents WHERE agent_id=$1`, agentID).Scan(&agentExists, &agentOS)
	if !agentExists {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}
	if !remediation.OSSupported(agentOS, entry) {
		jsonError(w, "remediation not supported on this endpoint's OS", http.StatusUnprocessableEntity)
		return
	}

	allResults := h.aggregateAgentResults(r.Context(), agentID)
	if latestCheckIsPassing(allResults, entry.CheckID) {
		jsonError(w, "already compliant -- nothing to fix", http.StatusConflict)
		return
	}

	actorID := ""
	if claims != nil {
		actorID = claims.UserID
	}
	approvedBy := ""
	if entry.Tier == remediation.TierConfirmRequired {
		approvedBy = actorID
	}
	requestID := newID()
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, approved_by, reason, rollback_available)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		requestID, entry.ID, agentID, entry.CheckID, int(entry.Tier), remediation.StatusRequested, actorID, approvedBy, req.Reason, entry.SupportsRollback,
	); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	timeoutSec := entry.EstimatedTimeSec * 2
	if timeoutSec == 0 {
		timeoutSec = 60
	}
	runID, sent, err := h.dispatchRemediationStep(r.Context(), agentID, "remediation-fix", entry.ID, entry.Command, entry.Executor, timeoutSec)
	if err != nil {
		h.db.Exec(r.Context(), `UPDATE remediation_requests SET status=$1, error=$2 WHERE id=$3`, remediation.StatusFailed, err.Error(), requestID)
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !sent {
		h.db.Exec(r.Context(), `UPDATE remediation_requests SET status=$1, error='agent not connected' WHERE id=$2`, remediation.StatusFailed, requestID)
		h.auditLog(r, "remediation.execute", requestID, map[string]any{"remediationId": entry.ID, "agentId": agentID}, "failed")
		respond(w, map[string]string{"requestId": requestID, "status": remediation.StatusFailed})
		return
	}
	h.db.Exec(r.Context(),
		`UPDATE remediation_requests SET status=$1, fix_run_id=$2, dispatched_at=NOW() WHERE id=$3`,
		remediation.StatusDispatched, runID, requestID)
	h.auditLog(r, "remediation.execute", requestID, map[string]any{"remediationId": entry.ID, "agentId": agentID, "tier": int(entry.Tier)}, "dispatched")
	respond(w, map[string]string{"requestId": requestID, "status": remediation.StatusDispatched})
}
```

- [ ] **Step 5: Register the route**

In `orchestrator/internal/api/routes.go`, right after the EPP Response Actions block:

```go
		// Endpoint Remediation Execution — execute is Analyst+Admin (Tier 2's
		// stricter Admin-only gate is checked dynamically inside the handler,
		// since it depends on the requested remediation's own tier).
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/agents/{agentId}/remediations", h.ExecuteRemediation)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestExecuteRemediation -v`
Expected: PASS for all 5 tests.

- [ ] **Step 7: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/remediation_dispatch.go orchestrator/internal/api/remediation_handlers.go orchestrator/internal/api/remediation_handlers_test.go orchestrator/internal/api/routes.go
git commit -m "feat(api): add remediation dispatch helper and ExecuteRemediation endpoint"
git push
```

---

### Task 7: `SubmitScenarioResult` continuation hook — fix → verify → completed/failed/verification_failed

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`SubmitScenarioResult`)
- Create: `orchestrator/internal/api/remediation_continuation.go`
- Test: `orchestrator/internal/api/remediation_continuation_test.go`

**Interfaces:**
- Consumes: `h.dispatchRemediationStep`, `h.findStepByCheckID` (Task 6), `remediation.Status*` (Task 2).
- Produces: `(h *Handler) continueRemediationFromResult(r *http.Request, runID string, simResults []models.SimulationResult)` — called from `SubmitScenarioResult`; also lays the groundwork Task 10 extends for rollback.

- [ ] **Step 1: Write the failing integration test**

```go
// orchestrator/internal/api/remediation_continuation_test.go
package api

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// TestSubmitScenarioResult_AdvancesRemediationFromFixToVerifying exercises
// Task 6's dispatch + Task 7's continuation hook together: a fix dispatch
// followed by the agent's (simulated) result submission must move the
// remediation into "verifying" and dispatch a second synthetic scenario.
func TestSubmitScenarioResult_AdvancesRemediationFromFixToVerifying(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-cont-a1', 'ER-CONT-HOST', 'windows')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine("../../../scenarios"), "")
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h.remediationCatalog = cat
		if err := h.engine.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}

		requestID := "rr-cont-1"
		fixRunID := "run-cont-fix-1"
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, fix_run_id, requested_by, reason, rollback_available)
			VALUES ($1, 'enable_windows_firewall', 'er-cont-a1', 'windows-firewall-enabled', 1, 'dispatched', $2, 'user-1', 'test', true)`,
			requestID, fixRunID)
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at)
			VALUES ($1, 'remediation-fix:enable_windows_firewall', 'er-cont-a1', 'remediation-fix', 'running', NOW())`,
			fixRunID)

		passResult := []models.SimulationResult{{ID: "t1", Result: models.ResultPass, ExecutedAt: time.Now().UTC()}}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.continueRemediationFromResult(req, fixRunID, passResult)

		var status, verifyRunID string
		pool.QueryRow(context.Background(), `SELECT status, verify_run_id FROM remediation_requests WHERE id=$1`, requestID).
			Scan(&status, &verifyRunID)
		if status != remediation.StatusVerifying {
			t.Errorf("status = %q, want %q", status, remediation.StatusVerifying)
		}
		if verifyRunID == "" {
			t.Error("expected verify_run_id to be set")
		}
	})
}

func TestSubmitScenarioResult_FixFails_MarksFailed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-cont-a2', 'ER-CONT-HOST-2', 'windows')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		requestID := "rr-cont-2"
		fixRunID := "run-cont-fix-2"
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, fix_run_id, requested_by, reason)
			VALUES ($1, 'enable_windows_firewall', 'er-cont-a2', 'windows-firewall-enabled', 1, 'dispatched', $2, 'user-1', 'test')`,
			requestID, fixRunID)

		failResult := []models.SimulationResult{{ID: "t1", Result: models.ResultFail, ExecutedAt: time.Now().UTC()}}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.continueRemediationFromResult(req, fixRunID, failResult)

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM remediation_requests WHERE id=$1`, requestID).Scan(&status)
		if status != remediation.StatusFailed {
			t.Errorf("status = %q, want %q", status, remediation.StatusFailed)
		}
	})
}

func TestSubmitScenarioResult_VerifyPasses_MarksCompleted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-cont-a3', 'ER-CONT-HOST-3', 'windows')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		requestID := "rr-cont-3"
		verifyRunID := "run-cont-verify-3"
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, verify_run_id, requested_by, reason)
			VALUES ($1, 'enable_windows_firewall', 'er-cont-a3', 'windows-firewall-enabled', 1, 'verifying', $2, 'user-1', 'test')`,
			requestID, verifyRunID)

		passResult := []models.SimulationResult{{ID: "t1", Result: models.ResultPass, ExecutedAt: time.Now().UTC()}}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.continueRemediationFromResult(req, verifyRunID, passResult)

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM remediation_requests WHERE id=$1`, requestID).Scan(&status)
		if status != remediation.StatusCompleted {
			t.Errorf("status = %q, want %q", status, remediation.StatusCompleted)
		}
	})
}

func TestSubmitScenarioResult_VerifyFails_MarksVerificationFailed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-cont-a4', 'ER-CONT-HOST-4', 'windows')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		requestID := "rr-cont-4"
		verifyRunID := "run-cont-verify-4"
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, verify_run_id, requested_by, reason)
			VALUES ($1, 'enable_windows_firewall', 'er-cont-a4', 'windows-firewall-enabled', 1, 'verifying', $2, 'user-1', 'test')`,
			requestID, verifyRunID)

		failResult := []models.SimulationResult{{ID: "t1", Result: models.ResultFail, ExecutedAt: time.Now().UTC()}}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.continueRemediationFromResult(req, verifyRunID, failResult)

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM remediation_requests WHERE id=$1`, requestID).Scan(&status)
		if status != remediation.StatusVerificationFailed {
			t.Errorf("status = %q, want %q", status, remediation.StatusVerificationFailed)
		}
	})
}

func TestSubmitScenarioResult_UnrelatedRunID_NoOp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		// Must not panic or error for a run_id that matches nothing.
		h.continueRemediationFromResult(req, "no-such-run-id", nil)
	})
}
```

Add `"net/http"`, `"net/http/httptest"`, and `"github.com/audspect/bas/internal/models"` to this test file's import block.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestSubmitScenarioResult_Advances -v`
Expected: FAIL — `h.continueRemediationFromResult` undefined (compile error).

- [ ] **Step 3: Write `remediation_continuation.go`**

```go
package api

import (
	"net/http"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/remediation"
)

// continueRemediationFromResult checks whether runID matches an open
// remediation_requests row's fix_run_id/verify_run_id (Task 10 extends
// this for rollback_run_id/rollback_verify_run_id), and if so advances
// that row's state machine. Called synchronously at the end of
// SubmitScenarioResult -- purely additive, a no-op for the vast majority
// of runs with no matching row. Every remediation dispatch (fix, verify)
// is a synthetic 1-step scenario, so simResults has exactly one element on
// success; an empty slice is treated as a failure.
func (h *Handler) continueRemediationFromResult(r *http.Request, runID string, simResults []models.SimulationResult) {
	passed := len(simResults) > 0 && simResults[0].Result == models.ResultPass

	var id string
	if err := h.db.QueryRow(r.Context(),
		`SELECT id FROM remediation_requests WHERE fix_run_id = $1 AND status = 'dispatched'`, runID,
	).Scan(&id); err == nil {
		h.handleRemediationFixResult(r, id, passed)
		return
	}
	if err := h.db.QueryRow(r.Context(),
		`SELECT id FROM remediation_requests WHERE verify_run_id = $1 AND status = 'verifying'`, runID,
	).Scan(&id); err == nil {
		h.handleRemediationVerifyResult(r, id, passed)
	}
}

// handleRemediationFixResult advances a remediation from "dispatched" once
// its fix command's result arrives: on success, dispatches the
// verification check as a second synthetic scenario; on failure, the
// remediation ends here (StatusFailed) -- verification never runs against
// a fix that didn't even execute cleanly.
func (h *Handler) handleRemediationFixResult(r *http.Request, requestID string, passed bool) {
	ctx := r.Context()
	var remediationID, agentID, requestedBy string
	if err := h.db.QueryRow(ctx,
		`SELECT remediation_id, agent_id, requested_by FROM remediation_requests WHERE id=$1`, requestID,
	).Scan(&remediationID, &agentID, &requestedBy); err != nil {
		return
	}
	if !passed {
		h.db.Exec(ctx,
			`UPDATE remediation_requests SET status=$1, error='fix command failed', execution_completed_at=NOW() WHERE id=$2`,
			remediation.StatusFailed, requestID)
		h.auditLogAs(r, requestedBy, "remediation.fix_failed", requestID,
			map[string]any{"remediationId": remediationID, "agentId": agentID}, "failed")
		return
	}
	h.db.Exec(ctx, `UPDATE remediation_requests SET execution_completed_at=NOW() WHERE id=$1`, requestID)

	if h.remediationCatalog == nil {
		h.db.Exec(ctx, `UPDATE remediation_requests SET status=$1, error='remediation catalog not loaded' WHERE id=$2`,
			remediation.StatusFailed, requestID)
		return
	}
	entry, ok := h.remediationCatalog.ByID(remediationID)
	if !ok {
		h.db.Exec(ctx, `UPDATE remediation_requests SET status=$1, error='remediation catalog entry no longer exists' WHERE id=$2`,
			remediation.StatusFailed, requestID)
		return
	}
	verificationCheckID := entry.VerificationCheckID
	if verificationCheckID == "" {
		verificationCheckID = entry.CheckID
	}
	step, found := h.findStepByCheckID(verificationCheckID)
	if !found {
		h.db.Exec(ctx, `UPDATE remediation_requests SET status=$1, error='verification check not found in scenario library' WHERE id=$2`,
			remediation.StatusFailed, requestID)
		return
	}
	timeoutSec := step.TimeoutSec
	if timeoutSec == 0 {
		timeoutSec = 30
	}
	verifyRunID, sent, err := h.dispatchRemediationStep(ctx, agentID, "remediation-verify", remediationID, step.Command, step.Executor, timeoutSec)
	if err != nil || !sent {
		h.db.Exec(ctx, `UPDATE remediation_requests SET status=$1, error='could not dispatch verification' WHERE id=$2`,
			remediation.StatusFailed, requestID)
		return
	}
	h.db.Exec(ctx,
		`UPDATE remediation_requests SET status=$1, verify_run_id=$2 WHERE id=$3`,
		remediation.StatusVerifying, verifyRunID, requestID)
}

// handleRemediationVerifyResult resolves a remediation once its
// verification check's result arrives: PASS means the fix actually took
// effect (StatusCompleted); FAIL means the command exited cleanly but the
// endpoint's compliance state didn't change (StatusVerificationFailed) --
// evidence-based, not exit-code-based.
func (h *Handler) handleRemediationVerifyResult(r *http.Request, requestID string, passed bool) {
	ctx := r.Context()
	var remediationID, agentID, requestedBy string
	h.db.QueryRow(ctx, `SELECT remediation_id, agent_id, requested_by FROM remediation_requests WHERE id=$1`, requestID).
		Scan(&remediationID, &agentID, &requestedBy)

	status := remediation.StatusCompleted
	outcome := "completed"
	if !passed {
		status = remediation.StatusVerificationFailed
		outcome = "verification_failed"
	}
	h.db.Exec(ctx,
		`UPDATE remediation_requests SET status=$1, verification_completed_at=NOW(), completed_at=NOW() WHERE id=$2`,
		status, requestID)
	h.auditLogAs(r, requestedBy, "remediation."+status, requestID,
		map[string]any{"remediationId": remediationID, "agentId": agentID}, outcome)
}
```

- [ ] **Step 4: Wire the hook into `SubmitScenarioResult`**

In `orchestrator/internal/api/handlers.go`, inside `SubmitScenarioResult`, find the SIEM auto-correlation block that immediately precedes `w.WriteHeader(http.StatusOK)`:

```go
	{
		runID := raw.RunID
		agentID := raw.AgentID
		sr := simResults
		go func() {
			var agentIP string
			var runStart time.Time
			h.db.QueryRow(context.Background(),
				`SELECT COALESCE(a.ip_address,''), sr.started_at
				   FROM scenario_runs sr
				   LEFT JOIN agents a ON a.agent_id = sr.agent_id
				  WHERE sr.id = $1`, runID,
			).Scan(&agentIP, &runStart)
			runEnd := time.Now()
			h.AutoCorrelateSIEM(runID, agentID, agentIP, runStart, runEnd, sr)
			h.AutoVerifyDetection(runID)
		}()
	}

	w.WriteHeader(http.StatusOK)
}
```

Insert the continuation hook call between that block and `w.WriteHeader`:

```go
	{
		runID := raw.RunID
		agentID := raw.AgentID
		sr := simResults
		go func() {
			var agentIP string
			var runStart time.Time
			h.db.QueryRow(context.Background(),
				`SELECT COALESCE(a.ip_address,''), sr.started_at
				   FROM scenario_runs sr
				   LEFT JOIN agents a ON a.agent_id = sr.agent_id
				  WHERE sr.id = $1`, runID,
			).Scan(&agentIP, &runStart)
			runEnd := time.Now()
			h.AutoCorrelateSIEM(runID, agentID, agentIP, runStart, runEnd, sr)
			h.AutoVerifyDetection(runID)
		}()
	}

	// Remediation lifecycle continuation -- if this run corresponds to an
	// open remediation_requests row, advance its state machine. Purely
	// additive: a no-op for the vast majority of runs with no matching row.
	h.continueRemediationFromResult(r, raw.RunID, simResults)

	w.WriteHeader(http.StatusOK)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestSubmitScenarioResult_ -v`
Expected: PASS for all 5 new tests.

- [ ] **Step 6: Run the full `internal/api` test suite to confirm no regressions in `SubmitScenarioResult`'s existing behavior**

Run: `cd orchestrator && go test ./internal/api/... -v 2>&1 | tail -60`
Expected: PASS, zero failures — the hook must not have broken any pre-existing `SubmitScenarioResult`/scenario-run test.

- [ ] **Step 7: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/remediation_continuation.go orchestrator/internal/api/remediation_continuation_test.go orchestrator/internal/api/handlers.go
git commit -m "feat(api): wire fix-to-verify remediation continuation into SubmitScenarioResult"
git push
```

**Corrections found during execution:**
- `TestSubmitScenarioResult_AdvancesRemediationFromFixToVerifying` originally loaded real scenarios from `../../../scenarios`, which failed builtin RSA-signature verification (unsigned/stale `.sig` files, the same expected behavior noted in Sub-project 2). Fixed by registering an in-memory fixture scenario directly via `scenario.Engine.Save()` (bypasses file/signature loading entirely) instead of `Load()`.
- The same test also needs a real connected agent for `dispatchRemediationStep`'s `SendToAgent` call to succeed during the verify-dispatch — added via the existing `startFakeAgent(t, h.hub, agentID)` test helper (`run_dispatch_helpers_test.go`), matching the pattern `dispatch_run_test.go` already uses.
- The seeded fix `scenario_runs` row must have `status='completed'`, not `'running'` — `scenario_runs` has a unique partial index allowing only one `'running'` row per agent at a time, and in the real flow `SubmitScenarioResult` already transitions the fix's own run to `'completed'`/`'partial'` before the continuation hook runs.
- `handleRemediationFixResult`'s dispatch-failure branch now includes the real underlying error text (`err.Error()` or `"sent=false"`) in `remediation_requests.error` instead of a bare generic string — genuinely more useful for diagnosing a real failure, not just a test artifact.

---

### Task 8: Status polling and history — `GetRemediation` (lazy timeout) + `ListAgentRemediations`

**Files:**
- Create: `orchestrator/internal/api/remediation_query.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`
- Test: `orchestrator/internal/api/remediation_query_test.go`

**Interfaces:**
- Consumes: `remediation.RemediationRequest`, `remediation.Status*`, `remediation.Tier` (Task 2).
- Produces: `(h *Handler) scanRemediationRequest(ctx, id string) (remediation.RemediationRequest, error)`, `(h *Handler) reapTimedOutRemediation(ctx, req *remediation.RemediationRequest)`, `(h *Handler) GetRemediation(w, r)`, `(h *Handler) ListAgentRemediations(w, r)` — consumed by Tasks 9 and 10.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/remediation_query_test.go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetRemediation_ReturnsCurrentStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-q-a1', 'ER-Q-HOST')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-q-1', 'enable_windows_firewall', 'er-q-a1', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "requestId", "rr-q-1")
		w := httptest.NewRecorder()
		h.GetRemediation(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var got remediation.RemediationRequest
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.Status != remediation.StatusCompleted {
			t.Errorf("Status = %q, want %q", got.Status, remediation.StatusCompleted)
		}
	})
}

func TestGetRemediation_NotFound_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "requestId", "no-such-request")
		w := httptest.NewRecorder()
		h.GetRemediation(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}

func TestGetRemediation_LazilyReapsTimedOut(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-q-a2', 'ER-Q-HOST-2')`)
		longAgo := time.Now().UTC().Add(-1 * time.Hour)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, dispatched_at)
			VALUES ('rr-q-2', 'enable_windows_firewall', 'er-q-a2', 'windows-firewall-enabled', 1, 'dispatched', 'user-1', 'test', $1)`,
			longAgo)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "requestId", "rr-q-2")
		w := httptest.NewRecorder()
		h.GetRemediation(w, req)
		var got remediation.RemediationRequest
		json.Unmarshal(w.Body.Bytes(), &got)
		if got.Status != remediation.StatusTimedOut {
			t.Errorf("Status = %q, want %q (dispatched 1h ago, well past the ~120s deadline)", got.Status, remediation.StatusTimedOut)
		}

		var dbStatus string
		pool.QueryRow(req.Context(), `SELECT status FROM remediation_requests WHERE id='rr-q-2'`).Scan(&dbStatus)
		if dbStatus != remediation.StatusTimedOut {
			t.Errorf("db status = %q, want persisted as %q", dbStatus, remediation.StatusTimedOut)
		}
	})
}

func TestGetRemediation_RecentDispatch_NotReaped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-q-a3', 'ER-Q-HOST-3')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, dispatched_at)
			VALUES ('rr-q-3', 'enable_windows_firewall', 'er-q-a3', 'windows-firewall-enabled', 1, 'dispatched', 'user-1', 'test', NOW())`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "requestId", "rr-q-3")
		w := httptest.NewRecorder()
		h.GetRemediation(w, req)
		var got remediation.RemediationRequest
		json.Unmarshal(w.Body.Bytes(), &got)
		if got.Status != remediation.StatusDispatched {
			t.Errorf("Status = %q, want %q (just dispatched, well within deadline)", got.Status, remediation.StatusDispatched)
		}
	})
}

func TestListAgentRemediations_ReturnsHistoryMostRecentFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-q-a4', 'ER-Q-HOST-4')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, requested_at)
			VALUES ('rr-q-4a', 'enable_windows_firewall', 'er-q-a4', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test', NOW() - INTERVAL '1 hour')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, requested_at)
			VALUES ('rr-q-4b', 'disable_windows_smbv1', 'er-q-a4', 'windows-smbv1-disabled', 2, 'requested', 'user-1', 'test', NOW())`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "er-q-a4")
		w := httptest.NewRecorder()
		h.ListAgentRemediations(w, req)
		var body struct {
			Remediations []remediation.RemediationRequest `json:"remediations"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(body.Remediations) != 2 {
			t.Fatalf("got %d remediations, want 2", len(body.Remediations))
		}
		if body.Remediations[0].ID != "rr-q-4b" {
			t.Errorf("first result = %s, want rr-q-4b (most recent)", body.Remediations[0].ID)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestGetRemediation|TestListAgentRemediations" -v`
Expected: FAIL — `h.GetRemediation`/`h.ListAgentRemediations` undefined (compile error).

- [ ] **Step 3: Write `remediation_query.go`**

```go
package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/remediation"
)

// scanRemediationRequest reads one remediation_requests row into a
// remediation.RemediationRequest, the shared read path for GetRemediation,
// CancelRemediation, and RollbackRemediation.
func (h *Handler) scanRemediationRequest(ctx context.Context, id string) (remediation.RemediationRequest, error) {
	var req remediation.RemediationRequest
	var tier int
	err := h.db.QueryRow(ctx,
		`SELECT id, remediation_id, agent_id, check_id, tier, status, fix_run_id, verify_run_id, error,
		        requested_by, approved_by, reason, rollback_available, rollback_status, rollback_run_id,
		        rollback_verify_run_id, requested_at, dispatched_at, execution_completed_at,
		        verification_completed_at, completed_at
		   FROM remediation_requests WHERE id=$1`, id,
	).Scan(&req.ID, &req.RemediationID, &req.AgentID, &req.CheckID, &tier, &req.Status, &req.FixRunID, &req.VerifyRunID,
		&req.Error, &req.RequestedBy, &req.ApprovedBy, &req.Reason, &req.RollbackAvailable, &req.RollbackStatus,
		&req.RollbackRunID, &req.RollbackVerifyRunID, &req.RequestedAt, &req.DispatchedAt, &req.ExecutionCompletedAt,
		&req.VerificationCompletedAt, &req.CompletedAt)
	req.Tier = remediation.Tier(tier)
	return req, err
}

// reapTimedOutRemediation marks req as StatusTimedOut if it's been sitting
// in a non-terminal, dispatched-or-later status past its deadline (catalog
// EstimatedTimeSec x 4, floor 60s) -- checked lazily whenever a
// remediation is read, the same on-read pattern
// internal/api/liveness.go's runIsStale uses for scenario_runs, rather
// than a background sweep.
func (h *Handler) reapTimedOutRemediation(ctx context.Context, req *remediation.RemediationRequest) {
	if req.Status != remediation.StatusDispatched && req.Status != remediation.StatusRunning && req.Status != remediation.StatusVerifying {
		return
	}
	if req.DispatchedAt == nil {
		return
	}
	deadline := 60 * time.Second
	if h.remediationCatalog != nil {
		if entry, ok := h.remediationCatalog.ByID(req.RemediationID); ok && entry.EstimatedTimeSec > 0 {
			d := time.Duration(entry.EstimatedTimeSec*4) * time.Second
			if d > deadline {
				deadline = d
			}
		}
	}
	if time.Since(*req.DispatchedAt) <= deadline {
		return
	}
	h.db.Exec(ctx, `UPDATE remediation_requests SET status=$1 WHERE id=$2 AND status=$3`,
		remediation.StatusTimedOut, req.ID, req.Status)
	req.Status = remediation.StatusTimedOut
}

// GET /api/remediation-requests/{requestId}
func (h *Handler) GetRemediation(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, "requestId")
	req, err := h.scanRemediationRequest(r.Context(), requestID)
	if err != nil {
		jsonError(w, "remediation request not found", http.StatusNotFound)
		return
	}
	h.reapTimedOutRemediation(r.Context(), &req)
	respond(w, req)
}

// GET /api/agents/{agentId}/remediations
func (h *Handler) ListAgentRemediations(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	rows, err := h.db.Query(r.Context(),
		`SELECT id, remediation_id, agent_id, check_id, tier, status, fix_run_id, verify_run_id, error,
		        requested_by, approved_by, reason, rollback_available, rollback_status, rollback_run_id,
		        rollback_verify_run_id, requested_at, dispatched_at, execution_completed_at,
		        verification_completed_at, completed_at
		   FROM remediation_requests WHERE agent_id=$1 ORDER BY requested_at DESC LIMIT 100`, agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []remediation.RemediationRequest{}
	for rows.Next() {
		var req remediation.RemediationRequest
		var tier int
		if err := rows.Scan(&req.ID, &req.RemediationID, &req.AgentID, &req.CheckID, &tier, &req.Status, &req.FixRunID,
			&req.VerifyRunID, &req.Error, &req.RequestedBy, &req.ApprovedBy, &req.Reason, &req.RollbackAvailable,
			&req.RollbackStatus, &req.RollbackRunID, &req.RollbackVerifyRunID, &req.RequestedAt, &req.DispatchedAt,
			&req.ExecutionCompletedAt, &req.VerificationCompletedAt, &req.CompletedAt); err != nil {
			continue
		}
		req.Tier = remediation.Tier(tier)
		out = append(out, req)
	}
	respond(w, map[string]any{"remediations": out})
}
```

- [ ] **Step 4: Register the routes**

In `orchestrator/internal/api/routes.go`, right after the `ExecuteRemediation` route from Task 6:

```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/agents/{agentId}/remediations", h.ExecuteRemediation)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/agents/{agentId}/remediations", h.ListAgentRemediations)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/remediation-requests/{requestId}", h.GetRemediation)
```

- [ ] **Step 5: Add rows to the RBAC route matrix**

In `orchestrator/internal/api/rbac_matrix_test.go`, in `routeMatrix`, right after the response-actions block (`{http.MethodGet, "/api/actions", tierPermission, auth.CanViewResponseActions},`):

```go
	{http.MethodGet, "/api/actions", tierPermission, auth.CanViewResponseActions},
	{http.MethodPost, "/api/agents/{agentId}/remediations", tierPermission, auth.CanExecuteRemediation},
	{http.MethodGet, "/api/agents/{agentId}/remediations", tierPermission, auth.CanExecuteRemediation},
	{http.MethodGet, "/api/remediation-requests/{requestId}", tierPermission, auth.CanExecuteRemediation},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestGetRemediation|TestListAgentRemediations|TestRBACMatrix" -v`
Expected: PASS for all new tests plus `TestRBACMatrix_NoDrift`.

- [ ] **Step 7: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/remediation_query.go orchestrator/internal/api/remediation_query_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(api): add remediation status polling, history, and lazy timeout detection"
git push
```

---

### Task 9: Cancellation

**Files:**
- Create: `orchestrator/internal/api/remediation_cancel.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`
- Test: `orchestrator/internal/api/remediation_cancel_test.go`

**Interfaces:**
- Consumes: `h.scanRemediationRequest` (Task 8), `h.cancelScenarioRun` (existing, `handlers.go:2241`), `remediation.Status*`/`Tier` (Task 2).
- Produces: `(h *Handler) CancelRemediation(w, r)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/remediation_cancel_test.go
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestCancelRemediation_NoRunInFlight_Conflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-cx-a1', 'ER-CX-HOST')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-cx-1', 'enable_windows_firewall', 'er-cx-a1', 'windows-firewall-enabled', 1, 'requested', 'user-1', 'test')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "requestId", "rr-cx-1")
		w := httptest.NewRecorder()
		h.CancelRemediation(w, req)
		if w.Code != http.StatusConflict {
			t.Errorf("status = %d, want 409 (no fix_run_id/verify_run_id yet)", w.Code)
		}
	})
}

func TestCancelRemediation_InFlight_MarksCancelled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-cx-a2', 'ER-CX-HOST-2')`)
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at)
			VALUES ('run-cx-2', 'remediation-fix:enable_windows_firewall', 'er-cx-a2', 'remediation-fix', 'running', NOW())`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, fix_run_id, requested_by, reason)
			VALUES ('rr-cx-2', 'enable_windows_firewall', 'er-cx-a2', 'windows-firewall-enabled', 1, 'dispatched', 'run-cx-2', 'user-1', 'test')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "requestId", "rr-cx-2")
		w := httptest.NewRecorder()
		h.CancelRemediation(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM remediation_requests WHERE id='rr-cx-2'`).Scan(&status)
		if status != remediation.StatusCancelled {
			t.Errorf("status = %q, want %q", status, remediation.StatusCancelled)
		}
	})
}

func TestCancelRemediation_NotFound_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "requestId", "no-such-request")
		w := httptest.NewRecorder()
		h.CancelRemediation(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestCancelRemediation -v`
Expected: FAIL — `h.CancelRemediation` undefined (compile error).

- [ ] **Step 3: Write `remediation_cancel.go`**

```go
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/remediation"
)

// POST /api/remediation-requests/{requestId}/cancel
func (h *Handler) CancelRemediation(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, "requestId")
	req, err := h.scanRemediationRequest(r.Context(), requestID)
	if err != nil {
		jsonError(w, "remediation request not found", http.StatusNotFound)
		return
	}
	if req.Tier == remediation.TierConfirmRequired {
		claims, _ := auth.ClaimsFrom(r.Context())
		if claims == nil || !auth.HasPermission(claims.Role, auth.CanApproveRemediation) {
			jsonError(w, "this remediation requires an Administrator to cancel", http.StatusForbidden)
			return
		}
	}
	runID := req.VerifyRunID
	if runID == "" {
		runID = req.FixRunID
	}
	if runID == "" {
		jsonError(w, "nothing in flight to cancel", http.StatusConflict)
		return
	}
	if _, _, cancelErr := h.cancelScenarioRun(r.Context(), runID); cancelErr != nil && cancelErr != errRunNotRunning {
		jsonError(w, cancelErr.Error(), http.StatusInternalServerError)
		return
	}
	h.db.Exec(r.Context(), `UPDATE remediation_requests SET status=$1 WHERE id=$2`, remediation.StatusCancelled, requestID)
	h.auditLog(r, "remediation.cancel", requestID, map[string]any{"remediationId": req.RemediationID, "agentId": req.AgentID}, "ok")
	respond(w, map[string]string{"requestId": requestID, "status": remediation.StatusCancelled})
}
```

- [ ] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, right after the `ListAgentRemediations`/`GetRemediation` routes from Task 8:

```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/remediation-requests/{requestId}", h.GetRemediation)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/remediation-requests/{requestId}/cancel", h.CancelRemediation)
```

- [ ] **Step 5: Add the row to the RBAC route matrix**

In `orchestrator/internal/api/rbac_matrix_test.go`, right after the `GetRemediation` row added in Task 8:

```go
	{http.MethodGet, "/api/remediation-requests/{requestId}", tierPermission, auth.CanExecuteRemediation},
	{http.MethodPost, "/api/remediation-requests/{requestId}/cancel", tierPermission, auth.CanExecuteRemediation},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestCancelRemediation|TestRBACMatrix" -v`
Expected: PASS for all 3 new tests plus `TestRBACMatrix_NoDrift`.

- [ ] **Step 7: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/remediation_cancel.go orchestrator/internal/api/remediation_cancel_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(api): add remediation cancellation"
git push
```

---

### Task 10: Rollback

**Files:**
- Create: `orchestrator/internal/api/remediation_rollback.go`
- Modify: `orchestrator/internal/api/remediation_continuation.go` (extend `continueRemediationFromResult` for rollback)
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`
- Test: `orchestrator/internal/api/remediation_rollback_test.go`

**Interfaces:**
- Consumes: `h.dispatchRemediationStep`, `h.findStepByCheckID` (Task 6), `h.scanRemediationRequest` (Task 8), `remediation.Status*` (Task 2).
- Produces: `(h *Handler) RollbackRemediation(w, r)`, extends `continueRemediationFromResult` to handle `rollback_run_id`/`rollback_verify_run_id`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/remediation_rollback_test.go
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestRollbackRemediation_NotCompleted_Conflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-rb-a1', 'ER-RB-HOST', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available)
			VALUES ('rr-rb-1', 'enable_windows_firewall', 'er-rb-a1', 'windows-firewall-enabled', 1, 'dispatched', 'user-1', 'test', true)`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "requestId", "rr-rb-1")
		w := httptest.NewRecorder()
		h.RollbackRemediation(w, req)
		if w.Code != http.StatusConflict {
			t.Errorf("status = %d, want 409 (not yet completed)", w.Code)
		}
	})
}

func TestRollbackRemediation_NotAvailable_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-rb-a2', 'ER-RB-HOST-2', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available)
			VALUES ('rr-rb-2', 'enable_windows_firewall', 'er-rb-a2', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test', false)`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "requestId", "rr-rb-2")
		w := httptest.NewRecorder()
		h.RollbackRemediation(w, req)
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("status = %d, want 422 (rollback_available=false)", w.Code)
		}
	})
}

func TestRollbackRemediation_AlreadyRequested_Conflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-rb-a3', 'ER-RB-HOST-3', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available, rollback_status)
			VALUES ('rr-rb-3', 'enable_windows_firewall', 'er-rb-a3', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test', true, 'requested')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "requestId", "rr-rb-3")
		w := httptest.NewRecorder()
		h.RollbackRemediation(w, req)
		if w.Code != http.StatusConflict {
			t.Errorf("status = %d, want 409 (rollback already requested)", w.Code)
		}
	})
}

func TestContinueRemediation_RollbackSucceeds_DispatchesRollbackVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-rb-a4', 'ER-RB-HOST-4', 'windows')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine("../../../scenarios"), "")
		if err := h.engine.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}

		requestID := "rr-rb-4"
		rollbackRunID := "run-rb-4"
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available, rollback_status, rollback_run_id)
			VALUES ($1, 'enable_windows_firewall', 'er-rb-a4', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test', true, 'requested', $2)`,
			requestID, rollbackRunID)

		passResult := []models.SimulationResult{{ID: "t1", Result: models.ResultPass, ExecutedAt: time.Now().UTC()}}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.continueRemediationFromResult(req, rollbackRunID, passResult)

		var rollbackVerifyRunID string
		pool.QueryRow(context.Background(), `SELECT rollback_verify_run_id FROM remediation_requests WHERE id=$1`, requestID).
			Scan(&rollbackVerifyRunID)
		if rollbackVerifyRunID == "" {
			t.Error("expected rollback_verify_run_id to be set after a successful rollback dispatch")
		}
	})
}

func TestContinueRemediation_RollbackVerifyStillPasses_MarksRollbackFailed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-rb-a5', 'ER-RB-HOST-5')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		requestID := "rr-rb-5"
		rollbackVerifyRunID := "run-rbv-5"
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available, rollback_status, rollback_verify_run_id)
			VALUES ($1, 'enable_windows_firewall', 'er-rb-a5', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test', true, 'requested', $2)`,
			requestID, rollbackVerifyRunID)

		// The check STILL PASSES after rollback -- the rollback did NOT take effect.
		stillPassing := []models.SimulationResult{{ID: "t1", Result: models.ResultPass, ExecutedAt: time.Now().UTC()}}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.continueRemediationFromResult(req, rollbackVerifyRunID, stillPassing)

		var rollbackStatus string
		pool.QueryRow(context.Background(), `SELECT rollback_status FROM remediation_requests WHERE id=$1`, requestID).Scan(&rollbackStatus)
		if rollbackStatus != "failed" {
			t.Errorf("rollback_status = %q, want failed (control still active after rollback)", rollbackStatus)
		}
	})
}

func TestContinueRemediation_RollbackVerifyNowFails_MarksRollbackCompleted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-rb-a6', 'ER-RB-HOST-6')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		requestID := "rr-rb-6"
		rollbackVerifyRunID := "run-rbv-6"
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available, rollback_status, rollback_verify_run_id)
			VALUES ($1, 'enable_windows_firewall', 'er-rb-a6', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test', true, 'requested', $2)`,
			requestID, rollbackVerifyRunID)

		// The check now FAILS after rollback -- the rollback worked.
		nowFailing := []models.SimulationResult{{ID: "t1", Result: models.ResultFail, ExecutedAt: time.Now().UTC()}}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.continueRemediationFromResult(req, rollbackVerifyRunID, nowFailing)

		var rollbackStatus string
		pool.QueryRow(context.Background(), `SELECT rollback_status FROM remediation_requests WHERE id=$1`, requestID).Scan(&rollbackStatus)
		if rollbackStatus != "completed" {
			t.Errorf("rollback_status = %q, want completed", rollbackStatus)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestRollbackRemediation|TestContinueRemediation_Rollback" -v`
Expected: FAIL — `h.RollbackRemediation` undefined (compile error).

- [ ] **Step 3: Write `remediation_rollback.go`**

```go
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/remediation"
)

// POST /api/remediation-requests/{requestId}/rollback
// Always requires CanApproveRemediation at the route level (routes.go),
// regardless of the original fix's own tier -- reversing a security
// control is inherently risk-increasing.
func (h *Handler) RollbackRemediation(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, "requestId")
	req, err := h.scanRemediationRequest(r.Context(), requestID)
	if err != nil {
		jsonError(w, "remediation request not found", http.StatusNotFound)
		return
	}
	if req.Status != remediation.StatusCompleted {
		jsonError(w, "can only roll back a completed remediation", http.StatusConflict)
		return
	}
	if !req.RollbackAvailable {
		jsonError(w, "this remediation does not support rollback", http.StatusUnprocessableEntity)
		return
	}
	if req.RollbackStatus != "" {
		jsonError(w, "a rollback has already been requested for this remediation", http.StatusConflict)
		return
	}
	if h.remediationCatalog == nil {
		jsonError(w, "remediation catalog not loaded", http.StatusServiceUnavailable)
		return
	}
	entry, ok := h.remediationCatalog.ByID(req.RemediationID)
	if !ok || entry.RollbackCommand == "" {
		jsonError(w, "rollback command not found in catalog", http.StatusUnprocessableEntity)
		return
	}
	timeoutSec := entry.EstimatedTimeSec * 2
	if timeoutSec == 0 {
		timeoutSec = 60
	}
	runID, sent, dispatchErr := h.dispatchRemediationStep(r.Context(), req.AgentID, "remediation-rollback", entry.ID, entry.RollbackCommand, entry.Executor, timeoutSec)
	if dispatchErr != nil || !sent {
		jsonError(w, "could not dispatch rollback -- agent may be offline", http.StatusServiceUnavailable)
		return
	}
	h.db.Exec(r.Context(),
		`UPDATE remediation_requests SET rollback_status='requested', rollback_run_id=$1 WHERE id=$2`, runID, requestID)
	h.auditLog(r, "remediation.rollback_requested", requestID, map[string]any{"remediationId": entry.ID, "agentId": req.AgentID}, "requested")
	respond(w, map[string]string{"requestId": requestID, "rollbackStatus": "requested"})
}
```

- [ ] **Step 4: Extend `continueRemediationFromResult` for rollback**

In `orchestrator/internal/api/remediation_continuation.go`, replace the body of `continueRemediationFromResult`:

```go
func (h *Handler) continueRemediationFromResult(r *http.Request, runID string, simResults []models.SimulationResult) {
	passed := len(simResults) > 0 && simResults[0].Result == models.ResultPass

	var id string
	if err := h.db.QueryRow(r.Context(),
		`SELECT id FROM remediation_requests WHERE fix_run_id = $1 AND status = 'dispatched'`, runID,
	).Scan(&id); err == nil {
		h.handleRemediationFixResult(r, id, passed)
		return
	}
	if err := h.db.QueryRow(r.Context(),
		`SELECT id FROM remediation_requests WHERE verify_run_id = $1 AND status = 'verifying'`, runID,
	).Scan(&id); err == nil {
		h.handleRemediationVerifyResult(r, id, passed)
		return
	}
	if err := h.db.QueryRow(r.Context(),
		`SELECT id FROM remediation_requests WHERE rollback_run_id = $1 AND rollback_status = 'requested'`, runID,
	).Scan(&id); err == nil {
		h.handleRemediationRollbackResult(r, id, passed)
		return
	}
	if err := h.db.QueryRow(r.Context(),
		`SELECT id FROM remediation_requests WHERE rollback_verify_run_id = $1 AND rollback_status = 'requested'`, runID,
	).Scan(&id); err == nil {
		h.handleRemediationRollbackVerifyResult(r, id, passed)
	}
}
```

Then append the two new handlers to the same file:

```go
// handleRemediationRollbackResult mirrors handleRemediationFixResult for
// the rollback path: on success, re-runs verification to confirm the
// control is actually back in its pre-fix state; on failure, the rollback
// stops here.
func (h *Handler) handleRemediationRollbackResult(r *http.Request, requestID string, passed bool) {
	ctx := r.Context()
	var remediationID, agentID, requestedBy string
	h.db.QueryRow(ctx, `SELECT remediation_id, agent_id, requested_by FROM remediation_requests WHERE id=$1`, requestID).
		Scan(&remediationID, &agentID, &requestedBy)

	if !passed {
		h.db.Exec(ctx, `UPDATE remediation_requests SET rollback_status='failed' WHERE id=$1`, requestID)
		h.auditLogAs(r, requestedBy, "remediation.rollback_failed", requestID,
			map[string]any{"remediationId": remediationID, "agentId": agentID}, "failed")
		return
	}

	if h.remediationCatalog == nil {
		h.db.Exec(ctx, `UPDATE remediation_requests SET rollback_status='failed' WHERE id=$1`, requestID)
		return
	}
	entry, ok := h.remediationCatalog.ByID(remediationID)
	if !ok {
		h.db.Exec(ctx, `UPDATE remediation_requests SET rollback_status='failed' WHERE id=$1`, requestID)
		return
	}
	verificationCheckID := entry.VerificationCheckID
	if verificationCheckID == "" {
		verificationCheckID = entry.CheckID
	}
	step, found := h.findStepByCheckID(verificationCheckID)
	if !found {
		h.db.Exec(ctx, `UPDATE remediation_requests SET rollback_status='failed' WHERE id=$1`, requestID)
		return
	}
	timeoutSec := step.TimeoutSec
	if timeoutSec == 0 {
		timeoutSec = 30
	}
	verifyRunID, sent, err := h.dispatchRemediationStep(ctx, agentID, "remediation-rollback-verify", remediationID, step.Command, step.Executor, timeoutSec)
	if err != nil || !sent {
		h.db.Exec(ctx, `UPDATE remediation_requests SET rollback_status='failed' WHERE id=$1`, requestID)
		return
	}
	h.db.Exec(ctx, `UPDATE remediation_requests SET rollback_verify_run_id=$1 WHERE id=$2`, verifyRunID, requestID)
}

// handleRemediationRollbackVerifyResult: passed==true means the finding's
// check STILL PASSES after the rollback command ran -- the rollback did
// NOT take effect. passed==false means the check now fails again,
// confirming the rollback worked (the control reverted to its pre-fix
// state).
func (h *Handler) handleRemediationRollbackVerifyResult(r *http.Request, requestID string, passed bool) {
	ctx := r.Context()
	var remediationID, agentID, requestedBy string
	h.db.QueryRow(ctx, `SELECT remediation_id, agent_id, requested_by FROM remediation_requests WHERE id=$1`, requestID).
		Scan(&remediationID, &agentID, &requestedBy)

	status := "completed"
	outcome := "ok"
	if passed {
		status = "failed"
		outcome = "rollback ran but the control is still active -- verify manually"
	}
	h.db.Exec(ctx, `UPDATE remediation_requests SET rollback_status=$1 WHERE id=$2`, status, requestID)
	h.auditLogAs(r, requestedBy, "remediation.rollback_"+status, requestID,
		map[string]any{"remediationId": remediationID, "agentId": agentID}, outcome)
}
```

- [ ] **Step 5: Register the route**

In `orchestrator/internal/api/routes.go`, right after the `CancelRemediation` route from Task 9. Note this one requires `CanApproveRemediation` at the router level, not `CanExecuteRemediation` — the only remediation route that's statically Admin-only:

```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/remediation-requests/{requestId}/cancel", h.CancelRemediation)
		r.With(auth.RequirePermission(auth.CanApproveRemediation)).Post("/api/remediation-requests/{requestId}/rollback", h.RollbackRemediation)
```

- [ ] **Step 6: Add the row to the RBAC route matrix**

In `orchestrator/internal/api/rbac_matrix_test.go`, right after the `cancel` row added in Task 9:

```go
	{http.MethodPost, "/api/remediation-requests/{requestId}/cancel", tierPermission, auth.CanExecuteRemediation},
	{http.MethodPost, "/api/remediation-requests/{requestId}/rollback", tierPermission, auth.CanApproveRemediation},
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestRollbackRemediation|TestContinueRemediation_Rollback|TestRBACMatrix" -v`
Expected: PASS for all 6 new tests plus `TestRBACMatrix_NoDrift`.

- [ ] **Step 8: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/api/remediation_rollback.go orchestrator/internal/api/remediation_continuation.go orchestrator/internal/api/remediation_rollback_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(api): add remediation rollback with rollback verification"
git push
```

**Correction found during execution:** `TestContinueRemediation_RollbackSucceeds_DispatchesRollbackVerify` needs `h.remediationCatalog` set (and, per Task 7's corrections, a registered fixture scenario + a live fake agent connection) — the initial version omitted the catalog assignment, so `handleRemediationRollbackResult`'s nil-catalog guard fired and marked `rollback_status=failed` instead of dispatching rollback-verification.

---

### Task 11: Full verification pass

**Files:** none (verification only).

- [ ] **Step 1: Confirm Docker is available for container-backed tests**

```bash
docker info >/dev/null 2>&1 && echo "docker running" || echo "docker not running"
```

- [ ] **Step 2: Full build**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 3: Full test suite for every touched package**

Run: `cd orchestrator && go test ./internal/remediation/... ./internal/api/... ./internal/auth/... ./internal/endpointrisk/... -v 2>&1 | tail -100`
Expected: PASS, zero failures.

- [ ] **Step 4: Confirm the RBAC route matrix has zero drift against the live router**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix_NoDrift -v`
Expected: PASS — every route this plan registered is present in `routeMatrix` with the correct tier, and nothing was missed.

- [ ] **Step 5: Sanity-check the catalog against the real scenario library**

Confirm every catalog entry's `check_id`/`verification_check_id` actually exists in a loaded scenario (a typo here would silently make `findStepByCheckID` fail at remediation time, not at catalog load time):

```bash
cd orchestrator && mkdir -p cmd/checkremcatalog_tmp && cat <<'EOF' > cmd/checkremcatalog_tmp/main.go
package main

import (
	"fmt"

	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
)

func main() {
	eng := scenario.NewEngine("../scenarios")
	if err := eng.Load(); err != nil {
		panic(err)
	}
	checkIDs := map[string]bool{}
	for _, sc := range eng.List() {
		for _, st := range sc.Steps {
			if st.CheckID != "" {
				checkIDs[st.CheckID] = true
			}
		}
	}
	cat, err := remediation.NewCatalog()
	if err != nil {
		panic(err)
	}
	for _, id := range []string{"enable_windows_firewall", "disable_windows_smbv1", "enable_bitlocker"} {
		entry, ok := cat.ByID(id)
		if !ok {
			panic("missing catalog entry " + id)
		}
		if !checkIDs[entry.CheckID] {
			panic(fmt.Sprintf("%s: check_id %q not found in any loaded scenario", id, entry.CheckID))
		}
		verifyID := entry.VerificationCheckID
		if verifyID == "" {
			verifyID = entry.CheckID
		}
		if !checkIDs[verifyID] {
			panic(fmt.Sprintf("%s: verification_check_id %q not found in any loaded scenario", id, verifyID))
		}
		fmt.Printf("%s: OK check_id=%s verification_check_id=%s\n", id, entry.CheckID, verifyID)
	}
	fmt.Println("all catalog entries reference real check_ids")
}
EOF
go run ./cmd/checkremcatalog_tmp
rm -rf cmd/checkremcatalog_tmp
```

Expected: all 3 entries print `OK`, then `all catalog entries reference real check_ids`.

- [ ] **Step 6: No commit needed** (verification-only task).

---

## Self-Review Notes

- **Spec coverage**: §2.1/2.2/2.3 (architecture) → Task 6's `dispatchRemediationStep`/`findStepByCheckID`, Task 2's sibling-package types. §3.1 (catalog) → Task 1. §3.2 (table) → Task 2. §3.3 (state machine) → Task 2. §3.4 (Finding fields) → Task 3. §4 (pre-flight) → Task 5 (OS match, pure) + Task 6 (already-compliant + tier gate, inline in the handler since it needs DB-fetched results). §5 (error handling) → Task 6 (agent-offline), Task 8 (lazy timeout), Task 9 (cancellation). §6 (API surface) → Tasks 6, 8, 9, 10 — with one correction from the spec: single-request endpoints moved from `/api/remediations/{requestId}` to `/api/remediation-requests/{requestId}` to avoid colliding with the pre-existing, unrelated `GET /api/remediations` (BAS finding-remediation text). §6.1 (continuation hook) → Task 7 (fix/verify) + Task 10 (rollback/rollback-verify). §7 (RBAC) → Task 4. §8 (testing) → every task's own tests plus Task 11's full-suite run.
- **Placeholder scan**: none found — every step has real, complete code; no TBD/TODO; the two `internal/remediation`-only pure-function pieces (catalog, pre-flight) are fully implemented, and every DB-touching piece has real SQL.
- **Type consistency checked**: `CatalogEntry`, `RemediationRequest`, `Tier`, `Status*` constants, and every handler/helper function name match verbatim between their defining task and every consuming task (`dispatchRemediationStep`, `findStepByCheckID`, `scanRemediationRequest`, `reapTimedOutRemediation`, `continueRemediationFromResult` and its four `handleRemediation*Result` helpers).
- **No temporary build breaks**: Task order is catalog → types/table → Finding enrichment → RBAC → pre-flight → dispatch+execute → continuation hook → query/cancel/rollback, so every dependency exists before its first consumer; `go build ./...` stays green after every task.
