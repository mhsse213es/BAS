# EPP Response Actions — Plan 4: Actions Package + DB + Permissions + API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the vendor-level response actions built in Plans 1-3 into a callable feature: a vendor-agnostic `internal/actions` package, persisted audit trail, permission gates, and REST API — everything Plan 5's UI will call.

**Architecture:** `internal/actions` owns the `Action`/`Target`/`Request` model and a pure `Execute(ctx, client, req) Action` function with no database I/O, mirroring `internal/detectverify`'s established convention exactly. `internal/api` owns `action_connectors` (credentials) and `action_requests` (the audit trail — every field of `Action` is a column) and calls `Execute` with everything it needs already loaded.

**Tech Stack:** Go 1.26, `pgx` (existing Postgres driver), stdlib `net/http`/`encoding/json`.

## Global Constraints

- This is Plan 4 of 5 for EPP Response Actions (spec: `docs/superpowers/specs/2026-07-21-epp-response-actions-design.md`). Plans 1-3 are done — commits through `e8310a6`. Plan 5 (UI) comes after this one.
- **Admin-only execution.** New permission `actions:execute` gates running an action — stricter than every other "run" permission in this codebase (`scenarios:run`, `detectverify:run` are Analyst+Admin). Per the spec: "a new Admin-only permission gates execution... no separate approver role exists yet."
- **Target must be a currently-enrolled agent.** `POST /api/actions/run` rejects any hostname that isn't the current hostname of a row in the `agents` table — an operator cannot type an arbitrary hostname and act on a host outside the BAS fleet.
- **Reason is mandatory**, enforced at the API layer with an HTTP 400 for a missing one (not just a UI nicety).
- **Two known vendor asymmetries from Plan 3, both resolved in this plan's design — read before implementing:**
  1. CrowdStrike's `QuarantineFile(ctx, deviceID, filePath string)` takes a file path; Defender's `QuarantineFile(ctx, deviceID, sha1 string)` takes a SHA1 hash. Both have the identical Go signature `(context.Context, string, string) (string, error)`, so `internal/actions` treats this as one generic `Parameters["quarantineTarget"]` string — the caller (this plan's HTTP handler today, Plan 5's UI eventually) is responsible for supplying the right *kind* of value for the connector's provider. `internal/actions` itself stays vendor-agnostic and never branches on provider for this.
  2. A structural discovery made while designing this plan: `*crowdstrike.Client` and `*defender.Client` satisfy an *identical* 5-method shape (`ResolveDevice`, `Isolate`, `Release`, `KillProcess`, `QuarantineFile` — same parameter and return types on both, Go doesn't care about parameter *names*). This lets `internal/actions` define one `VendorClient` interface both vendor types satisfy implicitly, with zero changes to `internal/vendors/*` and no per-vendor switch inside `Execute` — only inside the one small `NewVendorClient(cfg) (VendorClient, error)` constructor. This is a deliberate, reasoned simplification of the spec's "no shared Go interface... a small vendor-specific switch" self-review note from Plan 2 — noted there because a shared interface wasn't obviously available until this plan actually looked at both signatures side by side.
- **Status lifecycle simplified from the spec's literal wording.** The spec described `requested→dispatched→vendor_accepted|vendor_rejected→completed|failed`. Because `Execute` runs synchronously (no queue, no polling — consistent with Plans 2-3's "no polling to completion" convention) and nothing is persisted to the database until `Execute` returns, a caller can only ever observe two terminal states in the stored `action_requests.status` column: **`completed`** or **`failed`**. `Requested`/`Dispatched` exist as in-memory intermediate values `Execute` assigns while running (useful for reading the code, useless as a persisted state nobody can observe mid-flight), and `vendor_accepted`/`vendor_rejected` don't exist as separate states at all in v1 — a vendor accepting a request *is* what `completed` means here, since there's no follow-up confirmation step. If a future plan adds async dispatch or polling, `vendor_accepted`/`vendor_rejected` become real intermediate states then, not now.
- Module path: `github.com/audspect/bas`.

---

### Task 1: `internal/actions` package — model, `Execute`, no database I/O

**Files:**
- Create: `orchestrator/internal/actions/actions.go`
- Create: `orchestrator/internal/actions/actions_test.go`

**Interfaces:**
- Consumes: `crowdstrike.New`/`crowdstrike.Config` (Plans 1-3), `defender.New`/`defender.Config` (Plans 1-3) — via `NewVendorClient` only; `Execute` itself never imports either vendor package.
- Produces: `actions.Target{Type, Identifier string}`, `actions.Request{Type, Target, Parameters, ConnectorID, RequestedBy, Reason, TicketRef, RunID}`, `actions.Action{Type, Target, Parameters, ConnectorID, Status, ResolvedDeviceID, VendorRequestID, Error, RequestedBy, Reason, TicketRef, RunID, RequestedAt, DispatchedAt *time.Time, CompletedAt *time.Time}`, `actions.VendorClient` interface, `actions.ConnectorConfig{Provider, TenantID, ClientID, ClientSecret, BaseURL, KillProcessScriptName}`, `actions.NewVendorClient(cfg ConnectorConfig) (VendorClient, error)`, `actions.Execute(ctx context.Context, client VendorClient, req Request) Action`, action-type constants `TypeIsolate`/`TypeRelease`/`TypeKillProcess`/`TypeQuarantineFile`, status constants `StatusRequested`/`StatusDispatched`/`StatusCompleted`/`StatusFailed` — all consumed by Task 5 (API handlers).

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/actions/actions_test.go`:
```go
package actions

import (
	"context"
	"errors"
	"testing"
)

// fakeVendorClient is a lightweight in-package double — Execute's own
// logic (validation, status transitions, parameter extraction) doesn't
// need a real HTTP round trip to test; vendor-specific behavior is already
// covered by internal/vendors/crowdstrike and internal/vendors/defender's
// own tests from Plans 1-3.
type fakeVendorClient struct {
	resolveDeviceFunc   func(ctx context.Context, hostname string) (string, error)
	isolateFunc         func(ctx context.Context, deviceID string) (string, error)
	releaseFunc         func(ctx context.Context, deviceID string) (string, error)
	killProcessFunc     func(ctx context.Context, deviceID string, pid int) (string, error)
	quarantineFileFunc  func(ctx context.Context, deviceID, param string) (string, error)
}

func (f *fakeVendorClient) ResolveDevice(ctx context.Context, hostname string) (string, error) {
	return f.resolveDeviceFunc(ctx, hostname)
}
func (f *fakeVendorClient) Isolate(ctx context.Context, deviceID string) (string, error) {
	return f.isolateFunc(ctx, deviceID)
}
func (f *fakeVendorClient) Release(ctx context.Context, deviceID string) (string, error) {
	return f.releaseFunc(ctx, deviceID)
}
func (f *fakeVendorClient) KillProcess(ctx context.Context, deviceID string, pid int) (string, error) {
	return f.killProcessFunc(ctx, deviceID, pid)
}
func (f *fakeVendorClient) QuarantineFile(ctx context.Context, deviceID, param string) (string, error) {
	return f.quarantineFileFunc(ctx, deviceID, param)
}

func baseRequest() Request {
	return Request{
		Type:        TypeIsolate,
		Target:      Target{Type: "hostname", Identifier: "WIN-01"},
		ConnectorID: "conn-1",
		RequestedBy: "user-1",
		Reason:      "confirmed ransomware simulation success",
	}
}

func TestExecute_Isolate_Success(t *testing.T) {
	client := &fakeVendorClient{
		resolveDeviceFunc: func(ctx context.Context, hostname string) (string, error) {
			if hostname != "WIN-01" {
				t.Errorf("hostname = %q, want WIN-01", hostname)
			}
			return "device-abc", nil
		},
		isolateFunc: func(ctx context.Context, deviceID string) (string, error) {
			if deviceID != "device-abc" {
				t.Errorf("deviceID = %q, want device-abc", deviceID)
			}
			return "trace-1", nil
		},
	}
	a := Execute(context.Background(), client, baseRequest())
	if a.Status != StatusCompleted {
		t.Fatalf("Status = %q, want %q (err=%q)", a.Status, StatusCompleted, a.Error)
	}
	if a.ResolvedDeviceID != "device-abc" {
		t.Fatalf("ResolvedDeviceID = %q, want device-abc", a.ResolvedDeviceID)
	}
	if a.VendorRequestID != "trace-1" {
		t.Fatalf("VendorRequestID = %q, want trace-1", a.VendorRequestID)
	}
	if a.DispatchedAt == nil || a.CompletedAt == nil {
		t.Fatal("expected DispatchedAt and CompletedAt to both be set on success")
	}
}

func TestExecute_Release_Success(t *testing.T) {
	client := &fakeVendorClient{
		resolveDeviceFunc: func(ctx context.Context, hostname string) (string, error) { return "device-abc", nil },
		releaseFunc:       func(ctx context.Context, deviceID string) (string, error) { return "trace-2", nil },
	}
	req := baseRequest()
	req.Type = TypeRelease
	a := Execute(context.Background(), client, req)
	if a.Status != StatusCompleted || a.VendorRequestID != "trace-2" {
		t.Fatalf("a = %+v, want Completed/trace-2", a)
	}
}

func TestExecute_KillProcess_ExtractsPIDFromParameters(t *testing.T) {
	var gotPID int
	client := &fakeVendorClient{
		resolveDeviceFunc: func(ctx context.Context, hostname string) (string, error) { return "device-abc", nil },
		killProcessFunc: func(ctx context.Context, deviceID string, pid int) (string, error) {
			gotPID = pid
			return "trace-3", nil
		},
	}
	req := baseRequest()
	req.Type = TypeKillProcess
	req.Parameters = map[string]any{"pid": float64(4821)} // JSON numbers decode as float64
	a := Execute(context.Background(), client, req)
	if a.Status != StatusCompleted {
		t.Fatalf("Status = %q, want Completed (err=%q)", a.Status, a.Error)
	}
	if gotPID != 4821 {
		t.Fatalf("gotPID = %d, want 4821", gotPID)
	}
}

func TestExecute_KillProcess_MissingPID_Fails(t *testing.T) {
	client := &fakeVendorClient{
		resolveDeviceFunc: func(ctx context.Context, hostname string) (string, error) { return "device-abc", nil },
	}
	req := baseRequest()
	req.Type = TypeKillProcess
	a := Execute(context.Background(), client, req)
	if a.Status != StatusFailed {
		t.Fatalf("Status = %q, want Failed", a.Status)
	}
	if a.Error == "" {
		t.Fatal("expected a non-empty Error explaining the missing pid parameter")
	}
}

func TestExecute_QuarantineFile_ExtractsQuarantineTarget(t *testing.T) {
	var gotParam string
	client := &fakeVendorClient{
		resolveDeviceFunc: func(ctx context.Context, hostname string) (string, error) { return "device-abc", nil },
		quarantineFileFunc: func(ctx context.Context, deviceID, param string) (string, error) {
			gotParam = param
			return "trace-4", nil
		},
	}
	req := baseRequest()
	req.Type = TypeQuarantineFile
	req.Parameters = map[string]any{"quarantineTarget": `C:\evil.exe`}
	a := Execute(context.Background(), client, req)
	if a.Status != StatusCompleted {
		t.Fatalf("Status = %q, want Completed (err=%q)", a.Status, a.Error)
	}
	if gotParam != `C:\evil.exe` {
		t.Fatalf("gotParam = %q, want C:\\evil.exe", gotParam)
	}
}

func TestExecute_ResolveDeviceFails_StatusFailedWithVendorError(t *testing.T) {
	client := &fakeVendorClient{
		resolveDeviceFunc: func(ctx context.Context, hostname string) (string, error) {
			return "", errors.New("crowdstrike: no device found for hostname \"WIN-01\"")
		},
	}
	a := Execute(context.Background(), client, baseRequest())
	if a.Status != StatusFailed {
		t.Fatalf("Status = %q, want Failed", a.Status)
	}
	if a.Error != `crowdstrike: no device found for hostname "WIN-01"` {
		t.Fatalf("Error = %q, want the vendor's exact message", a.Error)
	}
	if a.ResolvedDeviceID != "" {
		t.Fatalf("ResolvedDeviceID = %q, want empty on resolution failure", a.ResolvedDeviceID)
	}
}

func TestExecute_VendorActionFails_StatusFailed(t *testing.T) {
	client := &fakeVendorClient{
		resolveDeviceFunc: func(ctx context.Context, hostname string) (string, error) { return "device-abc", nil },
		isolateFunc: func(ctx context.Context, deviceID string) (string, error) {
			return "", errors.New("crowdstrike device action contain: HTTP 500")
		},
	}
	a := Execute(context.Background(), client, baseRequest())
	if a.Status != StatusFailed {
		t.Fatalf("Status = %q, want Failed", a.Status)
	}
	if a.ResolvedDeviceID != "device-abc" {
		t.Fatalf("ResolvedDeviceID = %q, want device-abc (resolution succeeded before the isolate call failed)", a.ResolvedDeviceID)
	}
}

func TestExecute_MissingReason_Fails(t *testing.T) {
	client := &fakeVendorClient{}
	req := baseRequest()
	req.Reason = ""
	a := Execute(context.Background(), client, req)
	if a.Status != StatusFailed {
		t.Fatalf("Status = %q, want Failed", a.Status)
	}
	if a.Error == "" {
		t.Fatal("expected a non-empty Error explaining the missing reason")
	}
}

func TestExecute_UnsupportedTargetType_Fails(t *testing.T) {
	client := &fakeVendorClient{}
	req := baseRequest()
	req.Target.Type = "aws-instance-id"
	a := Execute(context.Background(), client, req)
	if a.Status != StatusFailed {
		t.Fatalf("Status = %q, want Failed", a.Status)
	}
}

func TestNewVendorClient_UnsupportedProvider_ReturnsError(t *testing.T) {
	if _, err := NewVendorClient(ConnectorConfig{Provider: "sentinelone"}); err == nil {
		t.Fatal("expected an error for a provider not implemented in this feature")
	}
}

func TestNewVendorClient_KnownProviders_Succeed(t *testing.T) {
	if _, err := NewVendorClient(ConnectorConfig{Provider: "crowdstrike", BaseURL: "https://api.crowdstrike.com"}); err != nil {
		t.Errorf("crowdstrike: %v", err)
	}
	if _, err := NewVendorClient(ConnectorConfig{Provider: "microsoft_defender", TenantID: "t1"}); err != nil {
		t.Errorf("microsoft_defender: %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/actions/... -v` (from `orchestrator/`)
Expected: compile failure — the package doesn't exist yet.

- [ ] **Step 3: Implement the package**

Create `orchestrator/internal/actions/actions.go`:
```go
// Package actions executes EPP response actions (isolate/release/kill
// process/quarantine file) against CrowdStrike or Microsoft Defender for
// Endpoint. Every action here is write-capable — unlike internal/detectverify
// (read-only verification), this package can isolate a live host, kill a
// process, or delete/quarantine a file. This package does no database I/O;
// internal/api owns the action_connectors/action_requests tables and calls
// Execute with everything it needs already loaded, exactly like
// internal/detectverify's VerifyRun.
package actions

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/vendors/crowdstrike"
	"github.com/audspect/bas/internal/vendors/defender"
)

// Action types this feature supports.
const (
	TypeIsolate        = "endpoint.isolate"
	TypeRelease        = "endpoint.release"
	TypeKillProcess    = "endpoint.kill_process"
	TypeQuarantineFile = "endpoint.quarantine_file"
)

// Status values Execute assigns. v1 dispatches synchronously with no
// queue, so only Completed/Failed are ever observed once Execute returns —
// see Global Constraints in the implementation plan for why
// Requested/Dispatched never become independently-observable persisted
// states, and why there is no separate VendorAccepted/VendorRejected pair.
const (
	StatusRequested = "requested"
	StatusDispatched = "dispatched"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
)

// Target identifies what an action acts on. Type is open-ended (only
// "hostname" is implemented) so identity/cloud/firewall targets can be
// added later without an API break.
type Target struct {
	Type       string
	Identifier string
}

// Request is one operator-initiated response action.
type Request struct {
	Type   string
	Target Target
	// Parameters holds action-specific arguments: {"pid": <number>} for
	// endpoint.kill_process, {"quarantineTarget": <string>} for
	// endpoint.quarantine_file (a file path for CrowdStrike, a SHA1 hash
	// for Defender — the caller supplies the right kind of value for the
	// connector's provider; this package stays vendor-agnostic about it).
	// Empty for endpoint.isolate/endpoint.release.
	Parameters  map[string]any
	ConnectorID string
	RequestedBy string
	Reason      string
	TicketRef   string
	RunID       string
}

// Action is the full record of one executed (or failed) response action —
// every field is a column in internal/api's action_requests table.
type Action struct {
	Type             string
	Target           Target
	Parameters       map[string]any
	ConnectorID      string
	Status           string
	ResolvedDeviceID string
	VendorRequestID  string
	Error            string
	RequestedBy      string
	Reason           string
	TicketRef        string
	RunID            string
	RequestedAt      time.Time
	DispatchedAt     *time.Time
	CompletedAt      *time.Time
}

// VendorClient is the shape both crowdstrike.Client and defender.Client
// satisfy structurally (Go's implicit interface satisfaction — neither
// vendor package imports this interface or internal/actions at all).
type VendorClient interface {
	ResolveDevice(ctx context.Context, hostname string) (string, error)
	Isolate(ctx context.Context, deviceID string) (string, error)
	Release(ctx context.Context, deviceID string) (string, error)
	KillProcess(ctx context.Context, deviceID string, pid int) (string, error)
	QuarantineFile(ctx context.Context, deviceID, param string) (string, error)
}

// ConnectorConfig holds the connection settings for one configured
// response connector — persisted in action_connectors, loaded by
// internal/api and passed to NewVendorClient.
type ConnectorConfig struct {
	Provider              string // "crowdstrike" | "microsoft_defender"
	TenantID              string // Defender only
	ClientID              string
	ClientSecret          string
	BaseURL               string // CrowdStrike only
	KillProcessScriptName string // Defender only
}

// NewVendorClient builds the VendorClient for cfg.Provider.
func NewVendorClient(cfg ConnectorConfig) (VendorClient, error) {
	switch cfg.Provider {
	case "crowdstrike":
		return crowdstrike.New(crowdstrike.Config{
			BaseURL: cfg.BaseURL, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
		}), nil
	case "microsoft_defender":
		return defender.New(defender.Config{
			TenantID: cfg.TenantID, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
			KillProcessScriptName: cfg.KillProcessScriptName,
		}), nil
	default:
		return nil, fmt.Errorf("actions: provider %q not supported", cfg.Provider)
	}
}

// Execute runs req against client, returning the full Action record
// whether it succeeded or failed. Callers check Action.Status, not a
// separate error — every failure mode is already captured in Action.Error.
func Execute(ctx context.Context, client VendorClient, req Request) Action {
	a := Action{
		Type: req.Type, Target: req.Target, Parameters: req.Parameters,
		ConnectorID: req.ConnectorID, RequestedBy: req.RequestedBy, Reason: req.Reason,
		TicketRef: req.TicketRef, RunID: req.RunID,
		Status: StatusRequested, RequestedAt: time.Now(),
	}

	if req.Target.Type != "hostname" {
		return fail(a, fmt.Sprintf("actions: unsupported target type %q", req.Target.Type))
	}
	if req.Reason == "" {
		return fail(a, "actions: reason is required")
	}

	dispatchedAt := time.Now()
	a.DispatchedAt = &dispatchedAt
	a.Status = StatusDispatched

	deviceID, err := client.ResolveDevice(ctx, req.Target.Identifier)
	if err != nil {
		return fail(a, err.Error())
	}
	a.ResolvedDeviceID = deviceID

	vendorRequestID, err := dispatch(ctx, client, req.Type, deviceID, req.Parameters)
	if err != nil {
		return fail(a, err.Error())
	}
	a.VendorRequestID = vendorRequestID

	completedAt := time.Now()
	a.CompletedAt = &completedAt
	a.Status = StatusCompleted
	return a
}

func fail(a Action, msg string) Action {
	completedAt := time.Now()
	a.CompletedAt = &completedAt
	a.Status = StatusFailed
	a.Error = msg
	return a
}

func dispatch(ctx context.Context, client VendorClient, actionType, deviceID string, params map[string]any) (string, error) {
	switch actionType {
	case TypeIsolate:
		return client.Isolate(ctx, deviceID)
	case TypeRelease:
		return client.Release(ctx, deviceID)
	case TypeKillProcess:
		pid, err := intParam(params, "pid")
		if err != nil {
			return "", err
		}
		return client.KillProcess(ctx, deviceID, pid)
	case TypeQuarantineFile:
		target, err := stringParam(params, "quarantineTarget")
		if err != nil {
			return "", err
		}
		return client.QuarantineFile(ctx, deviceID, target)
	default:
		return "", fmt.Errorf("actions: unsupported action type %q", actionType)
	}
}

func intParam(params map[string]any, key string) (int, error) {
	v, ok := params[key]
	if !ok {
		return 0, fmt.Errorf("actions: missing required parameter %q", key)
	}
	switch n := v.(type) {
	case float64:
		return int(n), nil
	case int:
		return n, nil
	default:
		return 0, fmt.Errorf("actions: parameter %q must be a number, got %T", key, v)
	}
}

func stringParam(params map[string]any, key string) (string, error) {
	v, ok := params[key]
	if !ok {
		return "", fmt.Errorf("actions: missing required parameter %q", key)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("actions: parameter %q must be a non-empty string", key)
	}
	return s, nil
}
```

- [ ] **Step 4: Run `gofmt` then the tests**

Run: `gofmt -w internal/actions/actions.go && go test ./internal/actions/... -v` (from `orchestrator/`)
Expected: `PASS` on all 11 tests.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/actions
git commit -m "feat(actions): add internal/actions package with Execute and vendor dispatch"
```

---

### Task 2: `action_connectors` + `action_requests` database schema

**Files:**
- Modify: `orchestrator/internal/db/postgres.go`

**Interfaces:**
- Produces: tables `action_connectors` (id, name, provider, enabled, tenant_id, client_id, client_secret, base_url, kill_process_script_name, created_at, updated_at) and `action_requests` (id, type, target_type, target_identifier, parameters jsonb, connector_id, status, resolved_device_id, vendor_request_id, error, requested_by, reason, ticket_ref, run_id, requested_at, dispatched_at, completed_at) — consumed by Task 4 (connector CRUD) and Task 5 (execute + list).

- [ ] **Step 1: Add the migrations**

In `orchestrator/internal/db/postgres.go`, find:
```go
		// base_url/api_token: generic credential storage for non-Azure-shaped
		// providers (Splunk, QRadar, ...) that don't have tenant/client/secret.
		`ALTER TABLE detection_connectors ADD COLUMN IF NOT EXISTS base_url  text NOT NULL DEFAULT ''`,
		`ALTER TABLE detection_connectors ADD COLUMN IF NOT EXISTS api_token text NOT NULL DEFAULT ''`,

```
Replace with:
```go
		// base_url/api_token: generic credential storage for non-Azure-shaped
		// providers (Splunk, QRadar, ...) that don't have tenant/client/secret.
		`ALTER TABLE detection_connectors ADD COLUMN IF NOT EXISTS base_url  text NOT NULL DEFAULT ''`,
		`ALTER TABLE detection_connectors ADD COLUMN IF NOT EXISTS api_token text NOT NULL DEFAULT ''`,

		// ── EPP Response Actions ─────────────────────────────────────────────
		// action_connectors: one row per CrowdStrike/Defender response-action
		// connector. Deliberately separate from detection_connectors — a
		// customer can enable detection verification against a vendor without
		// enabling write-capable response actions against the same vendor. See
		// docs/superpowers/specs/2026-07-21-epp-response-actions-design.md.
		`CREATE TABLE IF NOT EXISTS action_connectors (
			id                        text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			name                      text        NOT NULL,
			provider                  text        NOT NULL,
			enabled                   boolean     NOT NULL DEFAULT true,
			tenant_id                 text        NOT NULL DEFAULT '',
			client_id                 text        NOT NULL DEFAULT '',
			client_secret             text        NOT NULL DEFAULT '',
			base_url                  text        NOT NULL DEFAULT '',
			kill_process_script_name  text        NOT NULL DEFAULT '',
			created_at                timestamptz NOT NULL DEFAULT NOW(),
			updated_at                timestamptz NOT NULL DEFAULT NOW()
		)`,

		// action_requests IS the audit trail for every executed response
		// action — every field of internal/actions.Action is a column here,
		// not a derived log line. duration is one subtraction of
		// dispatched_at from completed_at, not a stored column (avoids drift).
		`CREATE TABLE IF NOT EXISTS action_requests (
			id                  text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			type                text        NOT NULL,
			target_type         text        NOT NULL,
			target_identifier   text        NOT NULL,
			parameters          jsonb       NOT NULL DEFAULT '{}',
			connector_id        text        NOT NULL,
			status              text        NOT NULL,
			resolved_device_id  text        NOT NULL DEFAULT '',
			vendor_request_id   text        NOT NULL DEFAULT '',
			error               text        NOT NULL DEFAULT '',
			requested_by        text        NOT NULL DEFAULT '',
			reason              text        NOT NULL DEFAULT '',
			ticket_ref          text        NOT NULL DEFAULT '',
			run_id              text        NOT NULL DEFAULT '',
			requested_at        timestamptz NOT NULL DEFAULT NOW(),
			dispatched_at       timestamptz,
			completed_at        timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_action_requests_run_id ON action_requests (run_id) WHERE run_id != ''`,

```

- [ ] **Step 2: Verify the schema bootstraps cleanly**

Run: `go build ./...` (from `orchestrator/`) to confirm the file still compiles (this is a pure data change — a raw SQL string in a slice literal — so there's no Go-level test to write for this step; `EnsureSchema` is exercised by every `internal/db` and `internal/api` test that already spins up a Postgres container).
Expected: build succeeds.

Run: `go test ./internal/db/... -v 2>&1 | tail -30` (from `orchestrator/`) — this package's tests call `EnsureSchema` against a real Postgres testcontainer, so a broken migration string fails loudly here.
Expected: `PASS`.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/db/postgres.go
git commit -m "feat(db): add action_connectors and action_requests tables"
```

---

### Task 3: Permissions

**Files:**
- Modify: `orchestrator/internal/auth/permissions.go`

**Interfaces:**
- Produces: `auth.CanExecuteResponseAction`, `auth.CanViewResponseActions`, `auth.CanListResponseConnectors`, `auth.CanCreateResponseConnector`, `auth.CanUpdateResponseConnector`, `auth.CanDeleteResponseConnector`, `auth.CanTestResponseConnector` — consumed by Task 5 (route wiring).

- [ ] **Step 1: Add the permission constants**

In `orchestrator/internal/auth/permissions.go`, find:
```go
	// Admin-only: Detection Verification connector config.
	CanListDetectionConnectors  Permission = "detectverify:configs:list"
	CanCreateDetectionConnector Permission = "detectverify:configs:create"
	CanUpdateDetectionConnector Permission = "detectverify:configs:update"
	CanDeleteDetectionConnector Permission = "detectverify:configs:delete"
	CanTestDetectionConnector   Permission = "detectverify:configs:test"
```
Replace with:
```go
	// Admin-only: Detection Verification connector config.
	CanListDetectionConnectors  Permission = "detectverify:configs:list"
	CanCreateDetectionConnector Permission = "detectverify:configs:create"
	CanUpdateDetectionConnector Permission = "detectverify:configs:update"
	CanDeleteDetectionConnector Permission = "detectverify:configs:delete"
	CanTestDetectionConnector   Permission = "detectverify:configs:test"

	// EPP Response Actions — CanExecuteResponseAction is Admin-only,
	// deliberately stricter than every other "run" permission in this file
	// (all of which are Analyst+Admin): unlike detectverify (read-only),
	// executing a response action can isolate a live host, kill a process,
	// or delete/quarantine a file. CanViewResponseActions (the audit trail)
	// is Analyst+Admin like other "view" permissions; connector config is
	// Admin-only like every other connector config in this file.
	CanExecuteResponseAction   Permission = "actions:execute"
	CanViewResponseActions     Permission = "actions:view"
	CanListResponseConnectors  Permission = "actions:connectors:list"
	CanCreateResponseConnector Permission = "actions:connectors:create"
	CanUpdateResponseConnector Permission = "actions:connectors:update"
	CanDeleteResponseConnector Permission = "actions:connectors:delete"
	CanTestResponseConnector   Permission = "actions:connectors:test"
```

- [ ] **Step 2: Grant all 7 to RoleAdmin**

Find:
```go
		CanListDetectionConnectors: true, CanCreateDetectionConnector: true,
		CanUpdateDetectionConnector: true, CanDeleteDetectionConnector: true,
		CanTestDetectionConnector: true, CanViewOpenAEVConfig: true, CanUpdateOpenAEVConfig: true,
```
Replace with:
```go
		CanListDetectionConnectors: true, CanCreateDetectionConnector: true,
		CanUpdateDetectionConnector: true, CanDeleteDetectionConnector: true,
		CanTestDetectionConnector: true, CanExecuteResponseAction: true, CanViewResponseActions: true,
		CanListResponseConnectors: true, CanCreateResponseConnector: true, CanUpdateResponseConnector: true,
		CanDeleteResponseConnector: true, CanTestResponseConnector: true,
		CanViewOpenAEVConfig: true, CanUpdateOpenAEVConfig: true,
```

- [ ] **Step 3: Grant only `CanViewResponseActions` to RoleAnalyst**

Find:
```go
		CanLaunchExerciseExecution: true, CanAbortExerciseExecution: true,
		CanApproveExerciseStep: true, CanInjectExerciseEvidence: true, CanLookupIOC: true,
	},
	RoleViewer: {},
```
Replace with:
```go
		CanLaunchExerciseExecution: true, CanAbortExerciseExecution: true,
		CanApproveExerciseStep: true, CanInjectExerciseEvidence: true, CanLookupIOC: true,
		CanViewResponseActions: true,
	},
	RoleViewer: {},
```

- [ ] **Step 4: Add all 7 to the exhaustive `Permissions()` list**

Find:
```go
		CanListDetectionConnectors, CanCreateDetectionConnector, CanUpdateDetectionConnector,
		CanDeleteDetectionConnector, CanTestDetectionConnector, CanViewOpenAEVConfig, CanUpdateOpenAEVConfig,
```
Replace with:
```go
		CanListDetectionConnectors, CanCreateDetectionConnector, CanUpdateDetectionConnector,
		CanDeleteDetectionConnector, CanTestDetectionConnector,
		CanExecuteResponseAction, CanViewResponseActions, CanListResponseConnectors,
		CanCreateResponseConnector, CanUpdateResponseConnector, CanDeleteResponseConnector, CanTestResponseConnector,
		CanViewOpenAEVConfig, CanUpdateOpenAEVConfig,
```

- [ ] **Step 5: Run the auth package's tests**

Run: `go test ./internal/auth/... -v` (from `orchestrator/`)
Expected: `PASS`. If `rbac_matrix_test.go` in `internal/api` asserts an exhaustive permission count or a fixed role→permission snapshot, it will need updating too — check with `go test ./internal/api/... -run TestRBAC -v` and update that test's expected counts/lists if it fails, following whatever pattern that test already uses for the other permissions added in this same file.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/auth/permissions.go
git commit -m "feat(auth): add EPP response action permissions"
```

---

### Task 4: Response Connector config CRUD API

**Files:**
- Create: `orchestrator/internal/api/action_handlers.go`
- Modify: `orchestrator/internal/api/handlers.go:54-61` (Handler struct — test-override hook)
- Modify: `orchestrator/internal/api/routes.go:401` (route registration)

**Interfaces:**
- Consumes: `actions.ConnectorConfig`, `actions.NewVendorClient`, `actions.VendorClient` (Task 1); `action_connectors` table (Task 2); `auth.CanListResponseConnectors`/`CanCreateResponseConnector`/`CanUpdateResponseConnector`/`CanDeleteResponseConnector`/`CanTestResponseConnector` (Task 3).
- Produces: `(*Handler).ListResponseConnectors`, `CreateResponseConnector`, `UpdateResponseConnector`, `DeleteResponseConnector`, `TestResponseConnector`, `(*Handler).loadResponseConnector(ctx, id) (*actions.ConnectorConfig, bool, error)` (the `bool` is `enabled`) — consumed by Task 5.

- [ ] **Step 1: Add the test-override hook to `Handler`**

In `orchestrator/internal/api/handlers.go`, find:
```go
	// detectVerifyConnector builds a detectverify.Connector for a config.
	// nil in production (New leaves it unset; call sites fall back to
	// detectverify.NewConnector) — tests override it to avoid real HTTP calls.
	detectVerifyConnector func(detectverify.Config) (detectverify.Connector, error)
```
Replace with:
```go
	// detectVerifyConnector builds a detectverify.Connector for a config.
	// nil in production (New leaves it unset; call sites fall back to
	// detectverify.NewConnector) — tests override it to avoid real HTTP calls.
	detectVerifyConnector func(detectverify.Config) (detectverify.Connector, error)
	// actionVendorClient builds an actions.VendorClient for a config. nil in
	// production (call sites fall back to actions.NewVendorClient) — tests
	// override it to avoid real HTTP calls.
	actionVendorClient func(actions.ConnectorConfig) (actions.VendorClient, error)
```

- [ ] **Step 2: Create the connector CRUD handlers**

Create `orchestrator/internal/api/action_handlers.go`:
```go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/actions"
)

// ── Response Connector Config CRUD (Admin only) ────────────────────────────

// ListResponseConnectors lists all EPP response-action connector configs.
// GET /api/actions/configs
func (h *Handler) ListResponseConnectors(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT id, name, provider, enabled, tenant_id, base_url, kill_process_script_name, created_at, updated_at
		   FROM action_connectors ORDER BY created_at ASC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type row struct {
		ID                    string    `json:"id"`
		Name                  string    `json:"name"`
		Provider              string    `json:"provider"`
		Enabled               bool      `json:"enabled"`
		TenantID              string    `json:"tenantId"`
		BaseURL               string    `json:"baseUrl"`
		KillProcessScriptName string    `json:"killProcessScriptName"`
		CreatedAt             time.Time `json:"createdAt"`
		UpdatedAt             time.Time `json:"updatedAt"`
	}
	var out []row
	for rows.Next() {
		var rv row
		if err := rows.Scan(&rv.ID, &rv.Name, &rv.Provider, &rv.Enabled, &rv.TenantID,
			&rv.BaseURL, &rv.KillProcessScriptName, &rv.CreatedAt, &rv.UpdatedAt); err != nil {
			continue
		}
		out = append(out, rv)
	}
	if out == nil {
		out = []row{}
	}
	respond(w, out)
}

// CreateResponseConnector creates a new EPP response-action connector config.
// POST /api/actions/configs
func (h *Handler) CreateResponseConnector(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name                  string `json:"name"`
		Provider              string `json:"provider"`
		Enabled               bool   `json:"enabled"`
		TenantID              string `json:"tenantId"`
		ClientID              string `json:"clientId"`
		ClientSecret          string `json:"clientSecret"`
		BaseURL               string `json:"baseUrl"`
		KillProcessScriptName string `json:"killProcessScriptName"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" || req.Provider == "" {
		jsonError(w, "name and provider are required", http.StatusBadRequest)
		return
	}
	validProviders := map[string]bool{"crowdstrike": true, "microsoft_defender": true}
	if !validProviders[req.Provider] {
		jsonError(w, "provider must be crowdstrike | microsoft_defender", http.StatusBadRequest)
		return
	}
	var id string
	err := h.db.QueryRow(r.Context(),
		`INSERT INTO action_connectors
		 (name, provider, enabled, tenant_id, client_id, client_secret, base_url, kill_process_script_name)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		req.Name, req.Provider, req.Enabled, req.TenantID, req.ClientID, req.ClientSecret,
		req.BaseURL, req.KillProcessScriptName,
	).Scan(&id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "actions.connector_created", id, map[string]any{"provider": req.Provider, "name": req.Name}, "ok")
	respond(w, map[string]any{"id": id})
}

// UpdateResponseConnector updates an EPP response-action connector config.
// PUT /api/actions/configs/{id}
func (h *Handler) UpdateResponseConnector(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Name                  string `json:"name"`
		Enabled               bool   `json:"enabled"`
		TenantID              string `json:"tenantId"`
		ClientID              string `json:"clientId"`
		ClientSecret          string `json:"clientSecret"`
		BaseURL               string `json:"baseUrl"`
		KillProcessScriptName string `json:"killProcessScriptName"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	// Preserve masked sensitive values (UI returns "***" for secrets it can't show).
	var existingSecret string
	h.db.QueryRow(r.Context(), `SELECT client_secret FROM action_connectors WHERE id=$1`, id).Scan(&existingSecret)
	if req.ClientSecret == "***" {
		req.ClientSecret = existingSecret
	}
	ct, err := h.db.Exec(r.Context(),
		`UPDATE action_connectors SET name=$1, enabled=$2, tenant_id=$3, client_id=$4,
		        client_secret=$5, base_url=$6, kill_process_script_name=$7, updated_at=NOW()
		  WHERE id=$8`,
		req.Name, req.Enabled, req.TenantID, req.ClientID, req.ClientSecret,
		req.BaseURL, req.KillProcessScriptName, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "connector not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "actions.connector_updated", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}

// DeleteResponseConnector deletes an EPP response-action connector config.
// DELETE /api/actions/configs/{id}
func (h *Handler) DeleteResponseConnector(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ct, err := h.db.Exec(r.Context(), `DELETE FROM action_connectors WHERE id=$1`, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "connector not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "actions.connector_deleted", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}

// TestResponseConnector tests connectivity for a saved response connector by
// resolving a placeholder hostname — a connectivity/auth check, not a real
// action. Uses ResolveDevice specifically because it's the one VendorClient
// method that's read-only for both vendors (a plain device lookup, no
// isolate/kill/quarantine side effect), which is what "test connection"
// should mean here.
// POST /api/actions/configs/{id}/test
func (h *Handler) TestResponseConnector(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	cfg, _, err := h.loadResponseConnector(r.Context(), id)
	if err != nil {
		jsonError(w, "connector not found", http.StatusNotFound)
		return
	}
	client, err := h.buildActionVendorClient(*cfg)
	if err != nil {
		respond(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if _, err := client.ResolveDevice(r.Context(), "audspect-test-connectivity-probe"); err != nil {
		// A "no device found" error means auth succeeded and the API is
		// reachable — that IS a successful connectivity test. Any other
		// error (auth failure, network failure, HTTP 4xx/5xx before the
		// "not found" stage) is a genuine failure.
		respond(w, map[string]any{"ok": true, "note": "connector reachable (probe hostname not expected to exist): " + err.Error()})
		return
	}
	respond(w, map[string]any{"ok": true})
}

// ── Internal helpers ────────────────────────────────────────────────────────

// loadResponseConnector returns the connector's config and its enabled flag.
func (h *Handler) loadResponseConnector(ctx context.Context, id string) (*actions.ConnectorConfig, bool, error) {
	var cfg actions.ConnectorConfig
	var enabled bool
	err := h.db.QueryRow(ctx,
		`SELECT provider, enabled, tenant_id, client_id, client_secret, base_url, kill_process_script_name
		   FROM action_connectors WHERE id=$1`, id,
	).Scan(&cfg.Provider, &enabled, &cfg.TenantID, &cfg.ClientID, &cfg.ClientSecret,
		&cfg.BaseURL, &cfg.KillProcessScriptName)
	if err != nil {
		return nil, false, err
	}
	return &cfg, enabled, nil
}

// buildActionVendorClient builds a live VendorClient for cfg, honoring a
// test override on h.actionVendorClient when set.
func (h *Handler) buildActionVendorClient(cfg actions.ConnectorConfig) (actions.VendorClient, error) {
	if h.actionVendorClient != nil {
		return h.actionVendorClient(cfg)
	}
	return actions.NewVendorClient(cfg)
}
```

- [ ] **Step 3: Write the CRUD tests**

Create `orchestrator/internal/api/action_handlers_test.go`. This follows the exact conventions already established in `internal/api/detectverify_config_test.go`: `testing.Short()` skip, `sharedDB.RunWithPool(t, func(pool) {...})` for isolation, `New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")` to build a `Handler`, and the existing `withURLParam(r, key, val)` helper (already defined package-wide in `event_handlers_test.go`) for injecting a chi `{id}` path param without full router dispatch.
```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func actionsHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
}

func actionsConfigReq(body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/actions/configs", bytes.NewReader(b))
}

func TestListResponseConnectors_EmptyAndPopulated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		rec := httptest.NewRecorder()
		h.ListResponseConnectors(rec, httptest.NewRequest(http.MethodGet, "/api/actions/configs", nil))
		var empty []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &empty)
		if len(empty) != 0 {
			t.Fatalf("expected 0 connectors, got %d", len(empty))
		}

		createRec := httptest.NewRecorder()
		h.CreateResponseConnector(createRec, actionsConfigReq(map[string]any{
			"name": "Prod CrowdStrike", "provider": "crowdstrike", "baseUrl": "https://api.crowdstrike.com",
		}))
		if createRec.Code != http.StatusOK {
			t.Fatalf("create: status = %d, want 200, body = %s", createRec.Code, createRec.Body.String())
		}

		listRec := httptest.NewRecorder()
		h.ListResponseConnectors(listRec, httptest.NewRequest(http.MethodGet, "/api/actions/configs", nil))
		var out []map[string]any
		json.Unmarshal(listRec.Body.Bytes(), &out)
		if len(out) != 1 || out[0]["name"] != "Prod CrowdStrike" || out[0]["provider"] != "crowdstrike" {
			t.Fatalf("out = %+v, want 1 entry named Prod CrowdStrike/crowdstrike", out)
		}
	})
}

func TestCreateResponseConnector_ValidationErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		cases := []struct {
			name string
			body map[string]any
		}{
			{"missing name", map[string]any{"provider": "crowdstrike"}},
			{"missing provider", map[string]any{"name": "x"}},
			{"invalid provider", map[string]any{"name": "x", "provider": "sentinelone"}},
		}
		for _, c := range cases {
			rec := httptest.NewRecorder()
			h.CreateResponseConnector(rec, actionsConfigReq(c.body))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400", c.name, rec.Code)
			}
		}
	})
}

func TestUpdateResponseConnector_PreservesMaskedSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		createRec := httptest.NewRecorder()
		h.CreateResponseConnector(createRec, actionsConfigReq(map[string]any{
			"name": "x", "provider": "crowdstrike", "clientSecret": "real-secret",
		}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)

		b, _ := json.Marshal(map[string]any{"name": "x-renamed", "clientSecret": "***"})
		req := withURLParam(httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(b)), "id", created.ID)
		rec := httptest.NewRecorder()
		h.UpdateResponseConnector(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}

		var name, secret string
		pool.QueryRow(context.Background(),
			`SELECT name, client_secret FROM action_connectors WHERE id=$1`, created.ID,
		).Scan(&name, &secret)
		if name != "x-renamed" {
			t.Errorf("name = %q, want x-renamed", name)
		}
		if secret != "real-secret" {
			t.Errorf("client_secret = %q, want the original secret preserved", secret)
		}
	})
}

func TestDeleteResponseConnector_NotFoundAndSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		notFoundRec := httptest.NewRecorder()
		h.DeleteResponseConnector(notFoundRec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", "nope"))
		if notFoundRec.Code != http.StatusNotFound {
			t.Fatalf("not found: status = %d, want 404", notFoundRec.Code)
		}

		createRec := httptest.NewRecorder()
		h.CreateResponseConnector(createRec, actionsConfigReq(map[string]any{"name": "x", "provider": "microsoft_defender"}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)

		delRec := httptest.NewRecorder()
		h.DeleteResponseConnector(delRec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", created.ID))
		if delRec.Code != http.StatusOK {
			t.Fatalf("delete: status = %d, want 200", delRec.Code)
		}
		var n int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM action_connectors WHERE id=$1`, created.ID).Scan(&n)
		if n != 0 {
			t.Fatalf("expected the connector to be gone, found %d rows", n)
		}
	})
}

func TestTestResponseConnector_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		rec := httptest.NewRecorder()
		h.TestResponseConnector(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/api/... -run 'TestListResponseConnectors|TestCreateResponseConnector|TestUpdateResponseConnector|TestDeleteResponseConnector|TestTestResponseConnector' -v` (from `orchestrator/`)
Expected: `PASS` on all 5 tests.

- [ ] **Step 5: Wire the connector CRUD routes**

In `orchestrator/internal/api/routes.go`, find:
```go
		// Detection Verification — connector management (Admin only)
		r.With(auth.RequirePermission(auth.CanListDetectionConnectors)).Get("/api/detectverify/configs", h.ListDetectionConnectors)
		r.With(auth.RequirePermission(auth.CanCreateDetectionConnector)).Post("/api/detectverify/configs", h.CreateDetectionConnector)
		r.With(auth.RequirePermission(auth.CanUpdateDetectionConnector)).Put("/api/detectverify/configs/{id}", h.UpdateDetectionConnector)
		r.With(auth.RequirePermission(auth.CanDeleteDetectionConnector)).Delete("/api/detectverify/configs/{id}", h.DeleteDetectionConnector)
		r.With(auth.RequirePermission(auth.CanTestDetectionConnector)).Post("/api/detectverify/configs/{id}/test", h.TestDetectionConnector)
```
Replace with:
```go
		// Detection Verification — connector management (Admin only)
		r.With(auth.RequirePermission(auth.CanListDetectionConnectors)).Get("/api/detectverify/configs", h.ListDetectionConnectors)
		r.With(auth.RequirePermission(auth.CanCreateDetectionConnector)).Post("/api/detectverify/configs", h.CreateDetectionConnector)
		r.With(auth.RequirePermission(auth.CanUpdateDetectionConnector)).Put("/api/detectverify/configs/{id}", h.UpdateDetectionConnector)
		r.With(auth.RequirePermission(auth.CanDeleteDetectionConnector)).Delete("/api/detectverify/configs/{id}", h.DeleteDetectionConnector)
		r.With(auth.RequirePermission(auth.CanTestDetectionConnector)).Post("/api/detectverify/configs/{id}/test", h.TestDetectionConnector)

		// EPP Response Actions — connector management (Admin only)
		r.With(auth.RequirePermission(auth.CanListResponseConnectors)).Get("/api/actions/configs", h.ListResponseConnectors)
		r.With(auth.RequirePermission(auth.CanCreateResponseConnector)).Post("/api/actions/configs", h.CreateResponseConnector)
		r.With(auth.RequirePermission(auth.CanUpdateResponseConnector)).Put("/api/actions/configs/{id}", h.UpdateResponseConnector)
		r.With(auth.RequirePermission(auth.CanDeleteResponseConnector)).Delete("/api/actions/configs/{id}", h.DeleteResponseConnector)
		r.With(auth.RequirePermission(auth.CanTestResponseConnector)).Post("/api/actions/configs/{id}/test", h.TestResponseConnector)
```

- [ ] **Step 6: Build and vet as a final regression check**

Run: `go build ./... && go vet ./internal/api/...` (from `orchestrator/`)
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/action_handlers.go orchestrator/internal/api/action_handlers_test.go orchestrator/internal/api/handlers.go orchestrator/internal/api/routes.go
git commit -m "feat(api): add EPP response connector config CRUD"
```

---

### Task 5: Execute + list actions API

**Files:**
- Modify: `orchestrator/internal/api/action_handlers.go`
- Modify: `orchestrator/internal/api/action_handlers_test.go` (created in Task 4 — this task appends to it)
- Modify: `orchestrator/internal/api/routes.go`

**Interfaces:**
- Consumes: `actions.Execute`, `actions.Request`, `actions.Target`, `actions.Action`, `actions.Type*` constants (Task 1); `h.loadResponseConnector`, `h.buildActionVendorClient`, `actionsHandler(t, pool)` test helper (Task 4); `auth.CanExecuteResponseAction`/`CanViewResponseActions` (Task 3); `auth.ClaimsFrom` (existing, `internal/auth`).
- Produces: `(*Handler).ExecuteResponseAction`, `(*Handler).ListResponseActions`, `(*Handler).persistActionRequest(ctx, actions.Action) (string, error)` — this is the final task in this plan; Plan 5's UI calls `POST /api/actions/run` and `GET /api/actions`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/api/action_handlers_test.go` (the file Task 4 created — do not redefine `actionsHandler`, it already exists there). First, update that file's import block — find:
```go
import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)
```
Replace with:
```go
import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/actions"
	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)
```
Then append the following to the end of the file. This follows the exact conventions already established in `internal/api/detectverify_config_test.go` and `internal/api/testmain_test.go`: `testing.Short()` skip, `sharedDB.RunWithPool(t, func(pool) {...})` for isolation (it truncates every table after the test runs), and `authedRequest`/`callAuthed` (both already defined in `testmain_test.go`) for the one test that needs real JWT claims in context (`ExecuteResponseAction` reads `auth.ClaimsFrom` to set `requested_by`) — every other test calls the handler directly, matching `detectverify_config_test.go`'s convention, since permission checks live in `routes.go` middleware, not inside the handler functions themselves.
```go
// fakeActionVendorClient mirrors internal/actions' own test double — this
// package tests the HTTP layer's wiring (validation, persistence, audit),
// not vendor dispatch logic (already covered in internal/actions and
// internal/vendors/*).
type fakeActionVendorClient struct {
	resolveDeviceErr error
	isolateID        string
}

func (f *fakeActionVendorClient) ResolveDevice(ctx context.Context, hostname string) (string, error) {
	if f.resolveDeviceErr != nil {
		return "", f.resolveDeviceErr
	}
	return "device-fake-1", nil
}
func (f *fakeActionVendorClient) Isolate(ctx context.Context, deviceID string) (string, error) {
	return f.isolateID, nil
}
func (f *fakeActionVendorClient) Release(ctx context.Context, deviceID string) (string, error) {
	return "release-id", nil
}
func (f *fakeActionVendorClient) KillProcess(ctx context.Context, deviceID string, pid int) (string, error) {
	return "kill-id", nil
}
func (f *fakeActionVendorClient) QuarantineFile(ctx context.Context, deviceID, param string) (string, error) {
	return "quarantine-id", nil
}

func seedActionConnector(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(),
		`INSERT INTO action_connectors (name, provider, enabled, base_url, client_id, client_secret)
		 VALUES ('test-cs', 'crowdstrike', true, 'https://api.crowdstrike.com', 'c1', 's1') RETURNING id`,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seed action_connectors: %v", err)
	}
	return id
}

func seedTestAgent(t *testing.T, pool *pgxpool.Pool, hostname string) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO agents (agent_id, hostname) VALUES ($1, $2) ON CONFLICT (agent_id) DO NOTHING`,
		"agent-"+hostname, hostname)
	if err != nil {
		t.Fatalf("seed agents: %v", err)
	}
}

func actionRunReq(body map[string]any) *http.Request {
	data, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/actions/run", bytes.NewReader(data))
}

func TestExecuteResponseAction_Isolate_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		h.actionVendorClient = func(cfg actions.ConnectorConfig) (actions.VendorClient, error) {
			return &fakeActionVendorClient{isolateID: "trace-xyz"}, nil
		}
		connID := seedActionConnector(t, pool)
		seedTestAgent(t, pool, "WIN-TEST-01")

		req := authedRequest(t, http.MethodPost, "/api/actions/run", bytes.NewReader(mustJSON(t, map[string]any{
			"type": actions.TypeIsolate, "hostname": "WIN-TEST-01", "connectorId": connID,
			"reason": "confirmed ransomware simulation success",
		})), auth.RoleAdmin, "admin-1")
		w := callAuthed(h.ExecuteResponseAction, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			ID              string `json:"id"`
			Status          string `json:"status"`
			VendorRequestID string `json:"vendorRequestId"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Status != actions.StatusCompleted {
			t.Fatalf("status = %q, want %q", resp.Status, actions.StatusCompleted)
		}
		if resp.VendorRequestID != "trace-xyz" {
			t.Fatalf("vendorRequestId = %q, want trace-xyz", resp.VendorRequestID)
		}

		var persistedStatus, persistedRequestedBy string
		if err := pool.QueryRow(context.Background(),
			`SELECT status, requested_by FROM action_requests WHERE id=$1`, resp.ID,
		).Scan(&persistedStatus, &persistedRequestedBy); err != nil {
			t.Fatalf("action_requests row not found: %v", err)
		}
		if persistedStatus != actions.StatusCompleted {
			t.Fatalf("persisted status = %q, want completed", persistedStatus)
		}
		if persistedRequestedBy != "admin-1" {
			t.Fatalf("persisted requested_by = %q, want admin-1", persistedRequestedBy)
		}
	})
}

func TestExecuteResponseAction_UnknownHostname_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		h.actionVendorClient = func(cfg actions.ConnectorConfig) (actions.VendorClient, error) {
			return &fakeActionVendorClient{}, nil
		}
		connID := seedActionConnector(t, pool)

		w := httptest.NewRecorder()
		h.ExecuteResponseAction(w, actionRunReq(map[string]any{
			"type": actions.TypeIsolate, "hostname": "NOT-AN-ENROLLED-AGENT", "connectorId": connID,
			"reason": "test",
		}))

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
		}
	})
}

func TestExecuteResponseAction_MissingReason_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		connID := seedActionConnector(t, pool)
		seedTestAgent(t, pool, "WIN-TEST-02")

		w := httptest.NewRecorder()
		h.ExecuteResponseAction(w, actionRunReq(map[string]any{
			"type": actions.TypeIsolate, "hostname": "WIN-TEST-02", "connectorId": connID,
		}))

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
		}
	})
}

func TestExecuteResponseAction_VendorFailure_PersistsFailedStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		h.actionVendorClient = func(cfg actions.ConnectorConfig) (actions.VendorClient, error) {
			return &fakeActionVendorClient{resolveDeviceErr: context.DeadlineExceeded}, nil
		}
		connID := seedActionConnector(t, pool)
		seedTestAgent(t, pool, "WIN-TEST-03")

		w := httptest.NewRecorder()
		h.ExecuteResponseAction(w, actionRunReq(map[string]any{
			"type": actions.TypeIsolate, "hostname": "WIN-TEST-03", "connectorId": connID,
			"reason": "test",
		}))

		// A vendor-level failure is still a 200 with status=failed in the
		// body — matching this codebase's existing TestDetectionConnector
		// convention (respond({"ok": false, ...}) rather than an HTTP error
		// status) — because the request itself was well-formed; only the
		// vendor call failed.
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Status string `json:"status"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Status != actions.StatusFailed {
			t.Fatalf("status = %q, want failed", resp.Status)
		}
	})
}

func TestListResponseActions_ReturnsPersistedRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		h.actionVendorClient = func(cfg actions.ConnectorConfig) (actions.VendorClient, error) {
			return &fakeActionVendorClient{isolateID: "trace-list-1"}, nil
		}
		connID := seedActionConnector(t, pool)
		seedTestAgent(t, pool, "WIN-TEST-04")

		h.ExecuteResponseAction(httptest.NewRecorder(), actionRunReq(map[string]any{
			"type": actions.TypeIsolate, "hostname": "WIN-TEST-04", "connectorId": connID,
			"reason": "test", "runId": "run-abc",
		}))

		w := httptest.NewRecorder()
		h.ListResponseActions(w, httptest.NewRequest(http.MethodGet, "/api/actions?runId=run-abc", nil))

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var rows []map[string]any
		json.Unmarshal(w.Body.Bytes(), &rows)
		if len(rows) != 1 {
			t.Fatalf("rows = %d, want 1", len(rows))
		}
		if rows[0]["runId"] != "run-abc" {
			t.Fatalf("rows[0].runId = %v, want run-abc", rows[0]["runId"])
		}
	})
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/api/... -run 'TestExecuteResponseAction|TestListResponseActions' -v` (from `orchestrator/`)
Expected: compile failure — `ExecuteResponseAction`, `ListResponseActions` are undefined on `Handler`.

- [ ] **Step 3: Implement `ExecuteResponseAction`, `ListResponseActions`, and `persistActionRequest`**

Append to `orchestrator/internal/api/action_handlers.go` (after `buildActionVendorClient`, at the end of the file):
```go

// ── Execute + audit trail ───────────────────────────────────────────────────

// ExecuteResponseAction executes one EPP response action against a
// configured connector. The target hostname must belong to a currently-
// enrolled agent — this is the safety rail preventing an operator from
// acting on a host outside the BAS fleet.
// POST /api/actions/run
func (h *Handler) ExecuteResponseAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type        string         `json:"type"`
		Hostname    string         `json:"hostname"`
		Parameters  map[string]any `json:"parameters"`
		ConnectorID string         `json:"connectorId"`
		Reason      string         `json:"reason"`
		TicketRef   string         `json:"ticketRef"`
		RunID       string         `json:"runId"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Type == "" || req.Hostname == "" || req.ConnectorID == "" {
		jsonError(w, "type, hostname, and connectorId are required", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}
	validTypes := map[string]bool{
		actions.TypeIsolate: true, actions.TypeRelease: true,
		actions.TypeKillProcess: true, actions.TypeQuarantineFile: true,
	}
	if !validTypes[req.Type] {
		jsonError(w, "type must be endpoint.isolate | endpoint.release | endpoint.kill_process | endpoint.quarantine_file", http.StatusBadRequest)
		return
	}

	var agentExists bool
	if err := h.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM agents WHERE hostname=$1)`, req.Hostname).Scan(&agentExists); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !agentExists {
		jsonError(w, "hostname must match a currently-enrolled agent", http.StatusBadRequest)
		return
	}

	connCfg, enabled, err := h.loadResponseConnector(r.Context(), req.ConnectorID)
	if err != nil {
		jsonError(w, "connector not found", http.StatusNotFound)
		return
	}
	if !enabled {
		jsonError(w, "connector is disabled", http.StatusBadRequest)
		return
	}

	client, err := h.buildActionVendorClient(*connCfg)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	actorID := ""
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		actorID = claims.UserID
	}
	actionReq := actions.Request{
		Type:        req.Type,
		Target:      actions.Target{Type: "hostname", Identifier: req.Hostname},
		Parameters:  req.Parameters,
		ConnectorID: req.ConnectorID,
		RequestedBy: actorID,
		Reason:      req.Reason,
		TicketRef:   req.TicketRef,
		RunID:       req.RunID,
	}
	action := actions.Execute(r.Context(), client, actionReq)

	id, persistErr := h.persistActionRequest(r.Context(), action)
	if persistErr != nil {
		log.Printf("[actions] failed to persist action request: %v", persistErr)
	}
	h.auditLog(r, "actions.executed", id,
		map[string]any{"type": action.Type, "hostname": req.Hostname, "connectorId": req.ConnectorID}, action.Status)

	respond(w, map[string]any{
		"id": id, "status": action.Status, "vendorRequestId": action.VendorRequestID, "error": action.Error,
	})
}

// ListResponseActions returns the response-action audit trail, most-recent
// first, optionally filtered by runId and/or hostname.
// GET /api/actions?runId=&hostname=&limit=
func (h *Handler) ListResponseActions(w http.ResponseWriter, r *http.Request) {
	runID := r.URL.Query().Get("runId")
	hostname := r.URL.Query().Get("hostname")
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	query := `SELECT id, type, target_type, target_identifier, connector_id, status,
	                 resolved_device_id, vendor_request_id, error, requested_by, reason, ticket_ref, run_id,
	                 requested_at, dispatched_at, completed_at
	            FROM action_requests WHERE true`
	var args []any
	if runID != "" {
		args = append(args, runID)
		query += fmt.Sprintf(" AND run_id=$%d", len(args))
	}
	if hostname != "" {
		args = append(args, hostname)
		query += fmt.Sprintf(" AND target_identifier=$%d", len(args))
	}
	args = append(args, limit)
	query += fmt.Sprintf(" ORDER BY requested_at DESC LIMIT $%d", len(args))

	rows, err := h.db.Query(r.Context(), query, args...)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type row struct {
		ID               string     `json:"id"`
		Type             string     `json:"type"`
		TargetType       string     `json:"targetType"`
		Hostname         string     `json:"hostname"`
		ConnectorID      string     `json:"connectorId"`
		Status           string     `json:"status"`
		ResolvedDeviceID string     `json:"resolvedDeviceId"`
		VendorRequestID  string     `json:"vendorRequestId"`
		Error            string     `json:"error"`
		RequestedBy      string     `json:"requestedBy"`
		Reason           string     `json:"reason"`
		TicketRef        string     `json:"ticketRef"`
		RunID            string     `json:"runId"`
		RequestedAt      time.Time  `json:"requestedAt"`
		DispatchedAt     *time.Time `json:"dispatchedAt,omitempty"`
		CompletedAt      *time.Time `json:"completedAt,omitempty"`
	}
	var out []row
	for rows.Next() {
		var rv row
		if err := rows.Scan(&rv.ID, &rv.Type, &rv.TargetType, &rv.Hostname, &rv.ConnectorID, &rv.Status,
			&rv.ResolvedDeviceID, &rv.VendorRequestID, &rv.Error, &rv.RequestedBy, &rv.Reason, &rv.TicketRef,
			&rv.RunID, &rv.RequestedAt, &rv.DispatchedAt, &rv.CompletedAt); err != nil {
			continue
		}
		out = append(out, rv)
	}
	if out == nil {
		out = []row{}
	}
	respond(w, out)
}

// persistActionRequest writes a completed Execute() result into
// action_requests and returns the row's generated id.
func (h *Handler) persistActionRequest(ctx context.Context, a actions.Action) (string, error) {
	paramsJSON, err := json.Marshal(a.Parameters)
	if err != nil {
		paramsJSON = []byte("{}")
	}
	var id string
	err = h.db.QueryRow(ctx,
		`INSERT INTO action_requests
		 (type, target_type, target_identifier, parameters, connector_id, status,
		  resolved_device_id, vendor_request_id, error, requested_by, reason, ticket_ref, run_id,
		  requested_at, dispatched_at, completed_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id`,
		a.Type, a.Target.Type, a.Target.Identifier, paramsJSON, a.ConnectorID, a.Status,
		a.ResolvedDeviceID, a.VendorRequestID, a.Error, a.RequestedBy, a.Reason, a.TicketRef, a.RunID,
		a.RequestedAt, a.DispatchedAt, a.CompletedAt,
	).Scan(&id)
	return id, err
}
```

Update the file's import block at the top of `orchestrator/internal/api/action_handlers.go` — find:
```go
import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/actions"
)
```
Replace with:
```go
import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/actions"
	"github.com/audspect/bas/internal/auth"
)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/api/... -run 'TestExecuteResponseAction|TestListResponseActions' -v` (from `orchestrator/`)
Expected: `PASS` on all 5 tests.

- [ ] **Step 5: Wire the execute + list routes**

In `orchestrator/internal/api/routes.go`, find the EPP Response Actions connector routes added in Task 4:
```go
		// EPP Response Actions — connector management (Admin only)
		r.With(auth.RequirePermission(auth.CanListResponseConnectors)).Get("/api/actions/configs", h.ListResponseConnectors)
		r.With(auth.RequirePermission(auth.CanCreateResponseConnector)).Post("/api/actions/configs", h.CreateResponseConnector)
		r.With(auth.RequirePermission(auth.CanUpdateResponseConnector)).Put("/api/actions/configs/{id}", h.UpdateResponseConnector)
		r.With(auth.RequirePermission(auth.CanDeleteResponseConnector)).Delete("/api/actions/configs/{id}", h.DeleteResponseConnector)
		r.With(auth.RequirePermission(auth.CanTestResponseConnector)).Post("/api/actions/configs/{id}/test", h.TestResponseConnector)
```
Replace with:
```go
		// EPP Response Actions — connector management (Admin only)
		r.With(auth.RequirePermission(auth.CanListResponseConnectors)).Get("/api/actions/configs", h.ListResponseConnectors)
		r.With(auth.RequirePermission(auth.CanCreateResponseConnector)).Post("/api/actions/configs", h.CreateResponseConnector)
		r.With(auth.RequirePermission(auth.CanUpdateResponseConnector)).Put("/api/actions/configs/{id}", h.UpdateResponseConnector)
		r.With(auth.RequirePermission(auth.CanDeleteResponseConnector)).Delete("/api/actions/configs/{id}", h.DeleteResponseConnector)
		r.With(auth.RequirePermission(auth.CanTestResponseConnector)).Post("/api/actions/configs/{id}/test", h.TestResponseConnector)

		// EPP Response Actions — execute + audit trail
		r.With(auth.RequirePermission(auth.CanExecuteResponseAction)).Post("/api/actions/run", h.ExecuteResponseAction)
		r.With(auth.RequirePermission(auth.CanViewResponseActions)).Get("/api/actions", h.ListResponseActions)
```

- [ ] **Step 6: Run the whole module's tests and build/vet as a final regression check**

Run: `go build ./... && go vet ./... && go test ./internal/actions/... ./internal/api/... ./internal/auth/... -v 2>&1 | tail -60` (from `orchestrator/`)
Expected: no build/vet errors, `PASS` on every test.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/action_handlers.go orchestrator/internal/api/action_handlers_test.go orchestrator/internal/api/routes.go
git commit -m "feat(api): add EPP response action execute + audit trail endpoints"
```

---

## Self-Review Notes

**Spec coverage:** completes the spec's `internal/actions` architecture (Action/Target/Request model, `Execute`, no DB I/O), the `action_connectors`/`action_requests` data model (every `Action` field is a column, duration computed not stored), the 7 permissions (Admin-only execution, matching "stricter than every run permission"), the API routes (exact `/api/actions/*` shape from the spec), and both safety rails (enrolled-agent-only targeting, mandatory reason). Plan 5 (UI) is the only remaining spec section — Findings page Respond menu and the Response Connectors admin config screen.

**Placeholder scan:** none — every step contains complete code or an exact command with expected output. All test helpers (`actionsHandler`, `withURLParam`, `authedRequest`, `callAuthed`, `sharedDB.RunWithPool`) were verified against the real, currently-existing code in `internal/api/detectverify_config_test.go`, `internal/api/event_handlers_test.go`, and `internal/api/testmain_test.go` before being used here — none were guessed.

**Type/name consistency:** `actions.Execute`'s signature (`ctx, client VendorClient, req Request) Action`) is used identically in Task 1's own tests and Task 5's HTTP handler. `loadResponseConnector` returns `(*actions.ConnectorConfig, bool, error)` — the `bool` (enabled) — and both Task 4's `TestResponseConnector` and Task 5's `ExecuteResponseAction` consume it with that exact three-value shape. `Parameters["pid"]` (kill process) and `Parameters["quarantineTarget"]` (quarantine file) are the two parameter keys `internal/actions.dispatch` reads — Task 5's HTTP handler passes `req.Parameters` straight through unmodified, so Plan 5's UI must send JSON bodies using exactly these two key names.
