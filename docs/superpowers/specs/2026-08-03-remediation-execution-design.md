# Remediation Catalog & Single-Endpoint Execution — Design Spec

**Sub-project:** 4 of 6 in the Endpoint Health & Remediation initiative (1: Risk & Remediation view, 2: Security Config & Identity Posture Collection, 3: Patch Management & Application Risk, 4: this doc, 5: BAS-Verified Remediation, 6: Enterprise ops tail — fleet comparison, exceptions, ownership/SLA, maintenance windows, **batch remediation**, MTTR)

## 1. Goal

Sub-projects 2 and 3 gave every finding on the Risk & Remediation view (Security Configuration, Identity, Patch Management, Application Risk) evidence and remediation *text*, but no remediation *execution* — the "Can Audspect Fix" field has been deliberately absent since Sub-project 1's spec. This sub-project builds the complete lifecycle for **one endpoint, one remediation**:

```
Finding (has a check_id)
   ↓
Catalog lookup (embedded YAML, keyed by check_id)
   ↓
Permission check (CanExecuteRemediation / CanApproveRemediation)
   ↓
Pre-flight validation (server-side only, no agent round-trip)
   ↓
Dispatch fix command as a synthetic 1-step scenario
   ↓
Execution result → failed? stop here.
   ↓
Dispatch verification_check_id as a second synthetic 1-step scenario
   ↓
Verification result → PASS? Completed. FAIL? VerificationFailed.
   ↓
Audit log
```

Explicitly **out of scope**, deferred to Sub-project 6: batch/bulk execution across many endpoints, Tier 3 (scheduled/maintenance-window) remediation, retries, progress tracking across a fleet, and any job-queue infrastructure. Sub-project 4 must produce a proven single-endpoint execution pipeline that Sub-project 6 builds on, not orchestration.

## 2. Architecture

### 2.1 Sibling package, not a merge into `internal/actions`

`internal/actions` (EPP isolate/kill/quarantine, Sub-project "EPP Response Actions") is the closest existing analog — `Request`/`Action` structs, a status enum, `RequestedBy`/`Reason` fields, a DB-backed audit table, permission-gated dispatch. But it is architecturally a *connector-action framework*: synchronous (`Execute()` blocks on a vendor HTTP call and returns the final `Action` inline), and its `action_requests.connector_id` column is `NOT NULL` with no concept of an agent.

Remediation is fundamentally different: dispatch to the agent is asynchronous (`ws.Hub.SendToAgent` enqueues a message; the result arrives later as a separate `MsgScenarioResult` submission, exactly like any scenario run), execution can wedge or the agent can go offline mid-run, and there's a distinct verification phase after execution. Forcing this into `internal/actions`/`action_requests` would require migrating a `NOT NULL` column on an already-shipped table and retrofitting an async state machine onto a package whose own code comments say it assumes synchronous, single-shot completion.

**Decision:** a new sibling package `internal/remediation` and a new `remediation_requests` table, deliberately mirroring `internal/actions`' *conventions* (same status vocabulary shape, same `RequestedBy`/`Reason` fields, same audit-log call, same permission-gate-before-dispatch pattern) without sharing implementation, schema, or execution engine.

### 2.2 No new agent capability

The agent never learns about "remediation" as a concept. `internal/api`'s existing ad-hoc dispatch path (used today for the `/api/scan/full/{agentId}` "full-scan" trigger, `handlers.go:895-935`) already supports building a `scenario.ScenarioCommand{RunID, ScenarioID, Name, Steps}` from steps that don't come from a saved YAML scenario, and sending it via `SendToAgent(agentID, WSMessage{Type: MsgCommandScenario, Data: cmd})`. The agent runs it and reports back via the existing `MsgScenarioResult` → `SubmitScenarioResult` path exactly like any other run.

A remediation fix is a **synthetic 1-step scenario** built directly from the catalog entry's `command`/`executor`/`timeout_sec` (using `ScenarioID: "remediation-fix:"+remediationID`). Verification is the same trick a second time, using the catalog entry's `verification_check_id`'s own existing command (`ScenarioID: "remediation-verify:"+remediationID`). No new WebSocket message type, no new agent code.

### 2.3 Finding Resolved falls out for free

Verification re-runs the *same* `check_id` whose latest result already drives whether that finding appears at all (`postureCheckInput`/`applicationRiskInput` in `internal/api/endpointrisk_aggregations.go` always read the most recent result per `check_id`). There is no separate "mark finding resolved" step to build — the next `GetAgentRisk` call naturally reflects the new PASS, because the verification dispatch's result *is* the new latest result for that check.

## 3. Data Model

### 3.1 Remediation Catalog

New embedded YAML, following the `eol_catalog.yaml`/`eol.go` pattern from Sub-project 3 exactly (same `//go:embed`, load-and-validate-on-`NewCatalog()` shape).

`orchestrator/internal/remediation/catalog.yaml`:

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

Tier 1/2 entries require `command` (and `executor`/`estimated_time_sec`); Tier 4 entries require `manual_steps` and must NOT have a `command`. `NewCatalog()` validates: unique `id`, non-empty `check_id`, non-empty `supported_os`, and the tier/command/manual_steps pairing above — a catalog entry that violates the pairing is a load-time error, not a runtime surprise.

`orchestrator/internal/remediation/catalog.go`:

```go
package remediation

import (
	"embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed catalog.yaml
var catalogFS embed.FS

type Tier int

const (
	TierSafeAutomatic   Tier = 1
	TierConfirmRequired Tier = 2
	// Tier 3 (scheduled/maintenance-window) is reserved for Sub-project 6
	// and must never appear in this catalog.
	TierManualGuidance Tier = 4
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

// Catalog is the embedded, hand-curated set of remediation definitions.
type Catalog struct {
	byID      map[string]CatalogEntry
	byCheckID map[string]CatalogEntry
}

// NewCatalog loads and validates the embedded catalog.yaml.
func NewCatalog() (*Catalog, error) { /* load, validate id/check_id uniqueness
	and the tier/command/manual_steps pairing described above, index by both
	id and check_id (a check_id maps to at most one remediation in V1) */ }

// Lookup finds the remediation catalog entry for a finding's check_id.
func (c *Catalog) Lookup(checkID string) (CatalogEntry, bool)

// ByID finds a catalog entry by its own id (used once execution is
// requested with an explicit remediationId).
func (c *Catalog) ByID(id string) (CatalogEntry, bool)
```

### 3.2 `remediation_requests` table

Mirrors `action_requests`' shape (`orchestrator/internal/db/postgres.go`), extended for the async lifecycle. Deliberately references `scenario_runs.id` for the fix/verify dispatches rather than duplicating their output — that's already fully captured there via the existing `SimulationResult`/`RawOutput` machinery.

```sql
CREATE TABLE IF NOT EXISTS remediation_requests (
    id                          text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    remediation_id               text        NOT NULL,               -- catalog id
    agent_id                    text        NOT NULL,
    check_id                    text        NOT NULL,               -- denormalized: which finding this targets
    tier                        int         NOT NULL,
    status                      text        NOT NULL,
    fix_run_id                  text        NOT NULL DEFAULT '',    -- scenario_runs.id for the fix dispatch
    verify_run_id               text        NOT NULL DEFAULT '',    -- scenario_runs.id for the verification dispatch
    error                       text        NOT NULL DEFAULT '',
    requested_by                text        NOT NULL DEFAULT '',
    approved_by                 text        NOT NULL DEFAULT '',    -- Tier 2's confirming actor (holds CanApproveRemediation)
    reason                      text        NOT NULL DEFAULT '',
    rollback_available           boolean     NOT NULL DEFAULT false,
    rollback_status              text        NOT NULL DEFAULT '',    -- '' | requested | completed | failed
    rollback_run_id              text        NOT NULL DEFAULT '',    -- scenario_runs.id for the rollback command dispatch
    rollback_verify_run_id       text        NOT NULL DEFAULT '',    -- scenario_runs.id for the rollback's own verification dispatch
    requested_at                timestamptz NOT NULL DEFAULT NOW(),
    dispatched_at                timestamptz,
    execution_completed_at       timestamptz,
    verification_completed_at    timestamptz,
    completed_at                 timestamptz
);
CREATE INDEX IF NOT EXISTS idx_remediation_requests_agent_id ON remediation_requests (agent_id);
CREATE INDEX IF NOT EXISTS idx_remediation_requests_fix_run_id ON remediation_requests (fix_run_id) WHERE fix_run_id != '';
CREATE INDEX IF NOT EXISTS idx_remediation_requests_verify_run_id ON remediation_requests (verify_run_id) WHERE verify_run_id != '';
```

`approved_by` is set equal to `requested_by` whenever `tier=2` — Tier 2 has no separate two-actor approval workflow (§2.1, §7): the actor who calls `POST /remediations` for a Tier 2 catalog entry must already hold `CanApproveRemediation` themselves, so requesting *is* approving. `approved_by` stays empty for `tier=1`. This column exists for the audit trail's clarity (a reviewer scanning `remediation_requests` can see at a glance which rows required the stricter permission), not to model a distinct approval step.

The equivalent Go record type, `orchestrator/internal/remediation/types.go`:

```go
type RemediationRequest struct {
	ID                       string
	RemediationID            string
	AgentID                  string
	CheckID                  string
	Tier                     Tier
	Status                   string
	FixRunID                 string
	VerifyRunID              string
	Error                    string
	RequestedBy              string
	ApprovedBy               string
	Reason                   string
	RollbackAvailable        bool
	RollbackStatus           string
	RollbackRunID            string
	RollbackVerifyRunID      string
	RequestedAt              time.Time
	DispatchedAt             *time.Time
	ExecutionCompletedAt     *time.Time
	VerificationCompletedAt  *time.Time
	CompletedAt              *time.Time
}
```

### 3.3 State machine

```go
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
```

`requested → dispatched → running → verifying → completed`, with `failed` branching off after the fix result, `verification_failed` branching off after the verify result, `timed_out` detected lazily (§5), and `cancelled` reachable from `requested`/`dispatched`/`running`/`verifying` via the cancel endpoint. `Queued` (from the original brainstorm) is intentionally not modeled — dispatch is immediate in V1; there is no queue.

### 3.4 `Finding` gains fixability fields

`orchestrator/internal/endpointrisk/types.go`'s `Finding` struct gains:

```go
	RemediationID     string `json:"remediationId,omitempty"`
	Tier              int    `json:"tier,omitempty"`
	EstimatedTimeSec  int    `json:"estimatedTimeSec,omitempty"`
	RequiresReboot    bool   `json:"requiresReboot,omitempty"`
	RollbackAvailable bool   `json:"rollbackAvailable,omitempty"`
	CanFix            bool   `json:"canFix"`
```

Populated in `internal/api/endpointrisk_aggregations.go`'s `postureCheckInput` and `applicationRiskInput`, at the exact point each currently builds a `Finding` for a failing check — a catalog lookup by `checkID`/`entry.ID` alongside the existing `postureCheckFindingText` lookup. No new endpoint is needed for the frontend to know whether a finding is fixable; it reads straight off the `Finding` it already has from `GetAgentRisk`.

## 4. Pre-flight validation

Scoped to what's checkable **without an extra agent round-trip** — remediation execution costs at most two dispatches (fix + verify); pre-flight must not add a third.

1. **OS match** — `agent.os_version` (already on the `agents` row) against the catalog entry's `supported_os`. Mismatch → reject with "not supported on this endpoint's OS."
2. **Already compliant** — the finding's `check_id` latest result (same read `postureCheckInput` already does) is checked; if it's already `PASS`, reject with "already compliant, nothing to fix" instead of dispatching a redundant command.
3. **Tier gate** — a Tier 4 entry has no `command`; the execute endpoint rejects it outright with "manual guidance only" before any pre-flight or dispatch logic runs.

`requires_admin` stays informational-only in V1, displayed on the `Finding` but not independently probed — if the account genuinely lacks privilege, that surfaces as a normal `StatusFailed` with the command's own error text. Probe-based pre-flight (service exists, registry path exists, verified elevated context) is explicitly deferred — it would double the agent round-trips for marginal V1 benefit, and can be added to the catalog schema later without breaking existing entries (new optional fields, same pattern as this sub-project's own additions were to `Finding`).

## 5. Error handling

- **Agent offline at dispatch** — `SendToAgent` returns `sent=false` (the same signal every other dispatch site already checks) → immediate `StatusFailed`, `error="agent not connected"`. No waiting.
- **Agent goes dark mid-run, or the command wedges** — detected **lazily**, the same pattern `internal/api/liveness.go`'s `runIsStale` already uses for `scenario_runs` (checked when something reads the run's status, not via a background ticker): when `GET /api/remediations/{requestId}` is polled, if the request is in `dispatched`/`running`/`verifying` and its underlying `fix_run_id`/`verify_run_id` scenario_run's agent heartbeat is older than `models.AgentOfflineAfter`, **or** `dispatched_at`/`execution_completed_at` is older than `catalog_entry.EstimatedTimeSec × 4` (floor 60s) — a per-remediation deadline, not the global 2-hour `staleRunGuard`, since a hung 30-second firewall toggle shouldn't wait 2 hours — mark `StatusTimedOut`.
- **Cancellation** — `POST /api/remediations/{requestId}/cancel` requires the same permission as the remediation's own tier (Tier 1: `CanExecuteRemediation`, Tier 2: `CanApproveRemediation`), and reuses the existing `MsgCommandCancel`/`{"runId": ...}` primitive (`handlers.go:2251`) against whichever of `fix_run_id`/`verify_run_id` is currently outstanding.

## 6. API surface

```
POST /api/agents/{agentId}/remediations       body: {remediationId, reason}
  → permission check (Tier 1: CanExecuteRemediation, Tier 2: CanApproveRemediation)
  → pre-flight (§4)
  → INSERT remediation_requests (status=requested), dispatch fix as a synthetic
    1-step scenario, UPDATE status=dispatched, fix_run_id=<new runID>
  → returns immediately: {"requestId": "...", "status": "dispatched"}
    (mirrors the existing {"runId":...,"status":"dispatched"} scan-dispatch shape)

GET  /api/remediations/{requestId}
  → full remediation_requests row as JSON; lazily reaps StatusTimedOut (§5) on read

POST /api/remediations/{requestId}/cancel
  → requires the tier-appropriate permission (§5); reuses MsgCommandCancel

POST /api/remediations/{requestId}/rollback
  → only when status=completed AND rollback_available=true
  → ALWAYS requires CanApproveRemediation, regardless of the original fix's tier
    (reversing a security control is inherently risk-increasing)
  → dispatches rollback_command as a synthetic 1-step scenario (rollback_run_id),
    then re-runs verification_check_id the same way as the original fix
    (rollback_verify_run_id); if the check still passes after rollback,
    rollback_status=failed with an explicit "rollback ran but the control is
    still active -- verify manually" message

GET  /api/agents/{agentId}/remediations
  → this agent's remediation_requests history, most recent first (for the
    per-agent drill-down view's "past remediation attempts" list)
```

### 6.1 The fix→verify continuation hook

`SubmitScenarioResult` (`handlers.go:1839`) is the single existing ingestion point for every scenario run's results, including these synthetic ones. After it persists `simResults`/`status` for a run (existing code, unchanged), it gains one small additive block that checks `raw.RunID` against all four `remediation_requests` run-ID columns in an open (non-terminal) row:

- matches `fix_run_id` → pass: dispatch verification as the second synthetic scenario, `status=verifying`, `verify_run_id=<new runID>`. fail: `status=failed`, `execution_completed_at=NOW()`, `h.auditLog(...)`.
- matches `verify_run_id` → pass: `status=completed`. fail: `status=verification_failed`. Either way set `verification_completed_at`/`completed_at`, `h.auditLog(...)`.
- matches `rollback_run_id` → pass: dispatch `verification_check_id` again as the rollback-verification synthetic scenario, `rollback_verify_run_id=<new runID>`. fail: `rollback_status=failed`, `h.auditLog(...)`.
- matches `rollback_verify_run_id` → check still fails (rollback worked) → `rollback_status=completed`. check still passes → `rollback_status=failed` with the "verify manually" message (§6). Either way `h.auditLog(...)`.

This is a lookup-and-branch addition at the end of an already-large handler, not a rewrite of it.

## 7. RBAC

Two new permissions in `orchestrator/internal/auth/permissions.go`'s `rolePermissions` map, following the file's existing pattern (e.g. `CanReview`'s approve/reject split in the verification pipeline):

- `CanExecuteRemediation` — Analyst + Admin. Gates Tier 1 execution and viewing the catalog/fixability fields (the latter is already visible to anyone who can see the finding; this permission gates the *Execute* action specifically).
- `CanApproveRemediation` — Admin only. Gates Tier 2 execution and **all** rollbacks (§6).

## 8. Testing

- **Catalog**: `catalog_test.go` mirrors `eol_test.go` — loads the embedded file, validates `Lookup`/`ByID`, and a load-time-error test for a malformed tier/command/manual_steps pairing.
- **Pre-flight**: pure-function unit tests for OS-match and already-compliant logic — no DB, no agent.
- **State machine**: unit tests for each status transition function in isolation (fix-succeeds→verifying, fix-fails→failed, verify-passes→completed, verify-fails→verification_failed, lazy-timeout detection).
- **Integration**: DB-backed tests for the full `POST /remediations` → `SubmitScenarioResult` (fix) → `SubmitScenarioResult` (verify) → `GET /remediations/{id}` flow, following the existing test-agent-connection pattern already used in `dispatch_run_test.go`/`submit_scenario_result_test.go` to simulate agent responses.
- **RBAC**: extend the existing `rbac_matrix_test.go` table with `CanExecuteRemediation`/`CanApproveRemediation` rows, matching its current per-role coverage pattern.

## 9. Explicitly deferred (Sub-project 6)

- Batch/bulk execution across many endpoints ("for each endpoint, execute remediation" — the user's own framing; single-endpoint logic here doesn't change).
- Tier 3 (scheduled/maintenance-window remediation) — genuinely new infrastructure (job persistence, retries, concurrency, conflict resolution); zero of it exists today and none of it is needed for Sub-project 4.
- Fleet-wide progress tracking, notifications, and campaign-style remediation runs.
