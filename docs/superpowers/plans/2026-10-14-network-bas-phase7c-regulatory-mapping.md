# Network BAS Mastery Phase 7C: India/UAE Regulatory and Assurance Mapping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a versioned regulatory-obligation-mapping layer (`internal/regobligation`) that maps India/UAE regulatory obligations to Network BAS capabilities and records immutable, auditable evidence snapshots against them — the final sub-project of Phase 7 and the final phase of the Network BAS Mastery roadmap.

**Architecture:** A brand-new, fully independent package with zero Go import dependency on any Phase 1–6B package or `internal/compliance` (deliberately — see spec §2). Two individually-CRUD'd resources (`Obligation`, `EvidenceSnapshot`) persisted as jsonb-payload tables, following the exact store/handler shape `internal/zoneisolation`/`internal/otsafety` already established. No new composition/scoring engine and no "compliant: yes/no" field anywhere — evidence is a server-validated, immutable reference an operator submits after already running a real check elsewhere; this package never calls into any other capability itself.

**Tech Stack:** Go, chi router, pgx/Postgres (jsonb columns), existing `internal/auth` RBAC, existing `internal/api`/`internal/db` test harness (`sharedDB`/`callAuthed`/`seedUser`/`authedRequest`).

**Spec:** `docs/superpowers/specs/2026-10-14-network-bas-phase7c-regulatory-mapping-design.md`

## Global Constraints

- This package imports nothing from `internal/compliance` or any Phase 1–6B package (`networkpolicy`, `networkpath`, `zoneisolation`, `remoteaccess`, `networktopology`, `networkgraph`, `otsafety`, etc.) — confirmed by this plan's own `go vet`/`go build` gate at the end (spec §2).
- No field anywhere computes or displays a compliance verdict — only raw evidence a human reads and judges themselves (spec §3.3, §7).
- `Obligation` and `EvidenceSnapshot` are each independently CRUD'd resources, never bundled into a batch "import" (spec §3, a deliberate departure from the `otsafety`/`zoneisolation` import pattern).
- Server-assigned fields (`ID`, `SchemaVersion`, `ObligationVersion`, `CapturedAt`, `CapturedBy`, `CreatedBy`) are always set by the handler from server-side state, never trusted from the request body (spec §3.2, Review Focus #3).
- GET routes are `tierAny` (any authenticated role); only POST routes are gated by `CanManageRegulatoryObligations` — this is the REAL established pattern across every prior Phase 7 sub-project (confirmed by re-grepping `rbac_matrix_test.go`/`routes.go` this session), not the spec §4 text, which incorrectly implied GET was also permission-gated. Follow this correction, not the spec's literal wording.
- `internal/db` tests for this phase use `package db_test` (external test package) with the already-existing shared `sharedDB *testutil.TestDB` + `sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {...})` harness declared once in `internal/db/tenant_test.go` — do **not** use `testutil.NewTestDB(t)` directly or declare a new `TestMain`/`sharedDB`.
- `internal/api` tests for this phase use the already-existing shared harness in `internal/api/testmain_test.go`: `sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) { h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret); ... })`, `seedUser(t, pool, username, password, role, active) string`, `authedRequest(t, method, path, body, role, userID) *http.Request`, and **`callAuthed(h.HandlerMethod, req) *httptest.ResponseRecorder`** (routes the request through the real `auth.Middleware` so `auth.ClaimsFrom` resolves inside the handler — calling a handler method directly with a bare `httptest.NewRecorder()` is wrong and will silently leave `auth.ClaimsFrom` unpopulated). `withURLParam(req, key, val) *http.Request` (in `event_handlers_test.go`) sets chi URL params for `{id}`-style routes. Do **not** invent a `newTestHandler(t)` helper — it does not exist.
- Host has ~7.84–8.2GB RAM: never run unscoped `go test ./internal/api/...` or `./internal/db/...`. Always `go build ./...` + scoped tests with `-run`. Check `Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize` before any `internal/api`/`internal/db` test run.
- Git push immediately after every commit. Work happens inline on `main`, no worktree, no feature branch. RED must be watched failing (not assumed) before every GREEN.

## Review Focus

1. A snapshot submitted with `Status: "incomplete"` and a non-empty `IncompleteReason` must never be silently dropped or indistinguishable from a captured one when an obligation's snapshots are listed — a reasonable reader must see it distinctly flagged. **Owned by Task 5** (`TestCreateEvidenceSnapshot_IncompleteStatus_PersistsDistinctly`).
2. A `ControlMappingID` that doesn't match any of the referenced obligation's own declared `ControlMapping.CanonicalID` values must be rejected (400), not silently accepted as a dangling reference. **Owned by Task 5** (`TestCreateEvidenceSnapshot_ControlMappingIDNotFound_Rejected`).
3. `ObligationVersion` and `CapturedAt` on a persisted snapshot must reflect server-assigned values — a test must prove a caller-supplied value for either field in the request body is ignored/overwritten, not merely that the fields end up present. **Owned by Task 5** (`TestCreateEvidenceSnapshot_ServerAssignedFields_OverwriteCallerValues`).
4. The two concrete seed obligations (India/RBI, UAE/UAE-CB) must each be independently creatable, each independently support attaching an evidence snapshot, and listing all obligations must return both without either corrupting or leaking into the other's control-mapping/snapshot data. **Owned by Task 6** (`TestRegulatoryMapping_IndiaAndUAE_EndToEnd`).
5. An `Obligation` with `ObligationType` outside the four declared constants (empty string, or a typo) must be rejected at creation (400). **Owned by Task 4** (`TestCreateRegulatoryObligation_InvalidObligationType_Rejected`).

---

## Task 1: Package types — `internal/regobligation`

**Files:**
- Create: `orchestrator/internal/regobligation/types.go`
- Test: `orchestrator/internal/regobligation/types_test.go`

**Interfaces:**
- Consumes: nothing (first task, pure data types).
- Produces: `ObligationType` + 4 constants (`ObligationMandatory`, `ObligationGuidance`, `ObligationContractual`, `ObligationRecommended`), `MaxControlMappingsPerObligation = 50`, `ControlMapping{CanonicalID, ControlName, CapabilityName, Note string}`, `Obligation{ID, Jurisdiction, Regulator, Sector, EntityType, Title, Description string; ObligationType ObligationType; SourceReference string; EffectiveDate time.Time; Version string; ControlMappings []ControlMapping; CreatedBy string; CreatedAt time.Time}`, `SnapshotStatus` + 2 constants (`SnapshotCaptured`, `SnapshotIncomplete`), `CurrentSnapshotSchemaVersion = "1"`, `EvidenceSnapshot{ID, SchemaVersion, ObligationID, ControlMappingID, ObligationVersion, CapabilityName string; ImportReferences map[string]string; QueryParameters map[string]any; CapturedOutcome, CapturedConfidence, CapturedLimitations string; Status SnapshotStatus; IncompleteReason, CapturedBy string; CapturedAt time.Time; Note string}`. All later tasks import `github.com/audspect/bas/internal/regobligation` and use these exact names.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/regobligation/types_test.go
package regobligation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestObligationTypeConstants_HaveExpectedStringValues(t *testing.T) {
	cases := map[ObligationType]string{
		ObligationMandatory:   "mandatory",
		ObligationGuidance:    "guidance",
		ObligationContractual: "contractual",
		ObligationRecommended: "recommended",
	}
	for constant, want := range cases {
		if string(constant) != want {
			t.Errorf("expected %q, got %q", want, string(constant))
		}
	}
}

func TestSnapshotStatusConstants_HaveExpectedStringValues(t *testing.T) {
	if string(SnapshotCaptured) != "captured" {
		t.Errorf(`expected "captured", got %q`, string(SnapshotCaptured))
	}
	if string(SnapshotIncomplete) != "incomplete" {
		t.Errorf(`expected "incomplete", got %q`, string(SnapshotIncomplete))
	}
}

func TestObligation_JSONRoundTrip_PreservesControlMappings(t *testing.T) {
	ob := Obligation{
		ID: "ob-1", Jurisdiction: "India", Regulator: "RBI", Title: "Test obligation",
		ObligationType: ObligationMandatory, SourceReference: "RBI CSF", Version: "v1",
		EffectiveDate: time.Date(2016, 6, 2, 0, 0, 0, 0, time.UTC),
		ControlMappings: []ControlMapping{
			{CanonicalID: "cm-1", ControlName: "Segmentation", CapabilityName: "zoneisolation.isolation-check"},
		},
	}
	data, err := json.Marshal(ob)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), `"controlMappings"`) {
		t.Errorf("expected controlMappings field in JSON, got %s", data)
	}
	var roundTripped Obligation
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(roundTripped.ControlMappings) != 1 || roundTripped.ControlMappings[0].CapabilityName != "zoneisolation.isolation-check" {
		t.Errorf("control mappings did not round-trip: %+v", roundTripped.ControlMappings)
	}
}

func TestEvidenceSnapshot_JSONRoundTrip_PreservesImportReferences(t *testing.T) {
	es := EvidenceSnapshot{
		ID: "es-1", ObligationID: "ob-1", ControlMappingID: "cm-1", CapabilityName: "zoneisolation.isolation-check",
		ImportReferences: map[string]string{"topologyImportId": "topo-1", "isolationImportId": "iso-1"},
		Status:           SnapshotCaptured, CapturedOutcome: "confirmed-violation", CapturedAt: time.Now().UTC(),
	}
	data, err := json.Marshal(es)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), `"obligationId"`) || !strings.Contains(string(data), `"controlMappingId"`) {
		t.Errorf("expected obligationId and controlMappingId fields in JSON, got %s", data)
	}
	var roundTripped EvidenceSnapshot
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if roundTripped.ImportReferences["topologyImportId"] != "topo-1" {
		t.Errorf("import references did not round-trip: %+v", roundTripped.ImportReferences)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/regobligation/... -v`
Expected: FAIL to compile — `package regobligation is not in std` / `undefined: ObligationType` (the package doesn't exist yet).

- [ ] **Step 3: Write the implementation**

```go
// orchestrator/internal/regobligation/types.go
package regobligation

import "time"

// ObligationType distinguishes mandatory obligations from guidance,
// contractual, and recommended ones -- network.txt §3 requires this
// distinction be enforced, not merely documented.
type ObligationType string

const (
	ObligationMandatory   ObligationType = "mandatory"
	ObligationGuidance    ObligationType = "guidance"
	ObligationContractual ObligationType = "contractual"
	ObligationRecommended ObligationType = "recommended"
)

const MaxControlMappingsPerObligation = 50

// ControlMapping names what Network BAS capability would evidence this
// obligation. CapabilityName is a plain string tag (e.g.
// "zoneisolation.isolation-check") -- never an imported type, since this
// package has zero Go dependency on any Phase 1-6B package.
type ControlMapping struct {
	CanonicalID    string `json:"canonicalId"`
	ControlName    string `json:"controlName"`
	CapabilityName string `json:"capabilityName"`
	Note           string `json:"note,omitempty"`
}

// Obligation is one regulatory requirement -- catalog metadata,
// individually CRUD'd and versioned, never bundled into a batch
// "import" the way otsafety/zoneisolation imports are, since
// obligations evolve independently of each other.
type Obligation struct {
	ID              string           `json:"id,omitempty"`
	Jurisdiction    string           `json:"jurisdiction"`
	Regulator       string           `json:"regulator"`
	Sector          string           `json:"sector,omitempty"`
	EntityType      string           `json:"entityType,omitempty"`
	Title           string           `json:"title"`
	Description     string           `json:"description,omitempty"`
	ObligationType  ObligationType   `json:"obligationType"`
	SourceReference string           `json:"sourceReference"`
	EffectiveDate   time.Time        `json:"effectiveDate"`
	Version         string           `json:"version"`
	ControlMappings []ControlMapping `json:"controlMappings"`
	CreatedBy       string           `json:"createdBy,omitempty"`
	CreatedAt       time.Time        `json:"createdAt,omitempty"`
}

type SnapshotStatus string

const (
	SnapshotCaptured   SnapshotStatus = "captured"
	SnapshotIncomplete SnapshotStatus = "incomplete"
)

const CurrentSnapshotSchemaVersion = "1"

// EvidenceSnapshot is an immutable, point-in-time capture of a Network
// BAS check's output, submitted by an operator who already ran that
// check themselves. It is explicitly NOT a persisted execution run of
// the check itself -- isolation-checks, remote-access-path checks,
// network-path checks, and cloud-path checks are all deliberately
// ephemeral (computed fresh, never persisted) -- this snapshot exists
// so this phase has something durable and auditable to point at,
// without this package calling into any of them itself.
//
// Labeled a captured assessment, never implying the underlying check
// was independently rerun or that the snapshot proves the CURRENT state
// of anything -- only the state at CapturedAt.
type EvidenceSnapshot struct {
	ID                  string            `json:"id,omitempty"`
	SchemaVersion       string            `json:"schemaVersion,omitempty"`
	ObligationID        string            `json:"obligationId"`
	ControlMappingID    string            `json:"controlMappingId"`
	ObligationVersion   string            `json:"obligationVersion,omitempty"`
	CapabilityName      string            `json:"capabilityName"`
	ImportReferences    map[string]string `json:"importReferences,omitempty"`
	QueryParameters     map[string]any    `json:"queryParameters,omitempty"`
	CapturedOutcome     string            `json:"capturedOutcome,omitempty"`
	CapturedConfidence  string            `json:"capturedConfidence,omitempty"`
	CapturedLimitations string            `json:"capturedLimitations,omitempty"`
	Status              SnapshotStatus    `json:"status"`
	IncompleteReason    string            `json:"incompleteReason,omitempty"`
	CapturedBy          string            `json:"capturedBy,omitempty"`
	CapturedAt          time.Time         `json:"capturedAt,omitempty"`
	Note                string            `json:"note,omitempty"`
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/regobligation/... -v`
Expected: PASS — `TestObligationTypeConstants_HaveExpectedStringValues`, `TestSnapshotStatusConstants_HaveExpectedStringValues`, `TestObligation_JSONRoundTrip_PreservesControlMappings`, `TestEvidenceSnapshot_JSONRoundTrip_PreservesImportReferences` all PASS.

- [ ] **Step 5: Commit**

```bash
cd orchestrator && git add internal/regobligation/types.go internal/regobligation/types_test.go
git commit -m "feat(regobligation): add Obligation and EvidenceSnapshot types

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

## Task 2: DB store — regulatory obligations

**Files:**
- Create: `orchestrator/internal/db/regobligation_store.go`
- Test: `orchestrator/internal/db/regobligation_store_test.go`
- Modify: `orchestrator/internal/testutil/testdb.go:201-205` (insert after)
- Modify: `orchestrator/cmd/server/main.go:332-334` (insert after)

**Interfaces:**
- Consumes: `regobligation.Obligation`, `regobligation.ControlMapping`, `regobligation.ObligationType` (Task 1).
- Produces: `EnsureRegulatoryObligationSchema(ctx, pool) error`, `InsertRegulatoryObligation(ctx, pool, ob *regobligation.Obligation) error` (caller pre-sets `ob.ID`), `GetRegulatoryObligation(ctx, pool, id string) (*regobligation.Obligation, error)` (returns an error satisfying `errors.Is(err, pgx.ErrNoRows)` when not found), `ListRegulatoryObligations(ctx, pool, limit int) ([]*regobligation.Obligation, error)` (newest-first). Task 4 and Task 6 call all four.

**Test harness note:** `internal/db` tests for this phase live in `package db_test` (an external test package) and use the already-existing shared `sharedDB *testutil.TestDB` declared once in `internal/db/tenant_test.go`, via `sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {...})` — the exact pattern `internal/db/zoneisolation_store_test.go` already uses. Do not create a new `TestMain`/`sharedDB` and do not use `testutil.NewTestDB(t)` directly.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/db/regobligation_store_test.go
package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/regobligation"
)

func TestInsertAndGetRegulatoryObligation_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ob := &regobligation.Obligation{
			ID: "ob-roundtrip-1", Jurisdiction: "India", Regulator: "RBI", Sector: "Banking",
			EntityType: "Regulated Financial Institution", Title: "Network segmentation for critical payment/banking systems",
			ObligationType: regobligation.ObligationMandatory, SourceReference: "RBI Cyber Security Framework for Banks",
			EffectiveDate: time.Date(2016, 6, 2, 0, 0, 0, 0, time.UTC), Version: "RBI CSF 2016 (as amended)",
			ControlMappings: []regobligation.ControlMapping{
				{CanonicalID: "cm-1", ControlName: "Segmentation", CapabilityName: "zoneisolation.isolation-check"},
			},
			CreatedBy: "user-1",
		}
		if err := db.InsertRegulatoryObligation(context.Background(), pool, ob); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := db.GetRegulatoryObligation(context.Background(), pool, ob.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Jurisdiction != "India" || got.Regulator != "RBI" || got.Title != ob.Title {
			t.Errorf("round-tripped obligation mismatch: %+v", got)
		}
		if len(got.ControlMappings) != 1 || got.ControlMappings[0].CapabilityName != "zoneisolation.isolation-check" {
			t.Errorf("control mappings did not round-trip: %+v", got.ControlMappings)
		}
	})
}

func TestGetRegulatoryObligation_NotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetRegulatoryObligation(context.Background(), pool, "nonexistent-id")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("err = %v, want errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}

func TestListRegulatoryObligations_NewestFirst(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		cm := []regobligation.ControlMapping{{CanonicalID: "cm-1", ControlName: "c", CapabilityName: "x"}}
		older := &regobligation.Obligation{
			ID: "ob-older", Jurisdiction: "India", Regulator: "RBI", Title: "Older",
			ObligationType: regobligation.ObligationMandatory, SourceReference: "ref", Version: "v1",
			EffectiveDate: time.Now().UTC(), ControlMappings: cm,
		}
		if err := db.InsertRegulatoryObligation(context.Background(), pool, older); err != nil {
			t.Fatalf("insert older: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
		newer := &regobligation.Obligation{
			ID: "ob-newer", Jurisdiction: "UAE", Regulator: "UAE Central Bank", Title: "Newer",
			ObligationType: regobligation.ObligationMandatory, SourceReference: "ref", Version: "v1",
			EffectiveDate: time.Now().UTC(), ControlMappings: cm,
		}
		if err := db.InsertRegulatoryObligation(context.Background(), pool, newer); err != nil {
			t.Fatalf("insert newer: %v", err)
		}

		list, err := db.ListRegulatoryObligations(context.Background(), pool, 20)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list) < 2 {
			t.Fatalf("got %d obligations, want at least 2", len(list))
		}
		if list[0].ID != "ob-newer" {
			t.Errorf("list[0].ID = %q, want %q (newest first)", list[0].ID, "ob-newer")
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/db/... -run TestInsertAndGetRegulatoryObligation_RoundTrip -v`
Expected: FAIL to compile — `undefined: db.InsertRegulatoryObligation` (store doesn't exist yet).

- [ ] **Step 3: Write the implementation**

```go
// orchestrator/internal/db/regobligation_store.go
package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/regobligation"
)

// EnsureRegulatoryObligationSchema creates the regulatory_obligations
// table. created_at is DB-assigned (DEFAULT NOW()), never passed by the
// caller -- same omission zoneisolation.InsertZoneIsolationImport makes
// for imported_at.
func EnsureRegulatoryObligationSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS regulatory_obligations (
			id               text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			created_by       text,
			created_at       timestamptz NOT NULL DEFAULT NOW(),
			obligation_data  jsonb       NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("regulatory_obligations: ensure schema: %w", err)
	}
	return nil
}

// regulatoryObligationData is the shape persisted in the
// obligation_data jsonb column -- everything except id/created_by/
// created_at, which live in their own columns.
type regulatoryObligationData struct {
	Jurisdiction    string                         `json:"jurisdiction"`
	Regulator       string                         `json:"regulator"`
	Sector          string                         `json:"sector,omitempty"`
	EntityType      string                         `json:"entityType,omitempty"`
	Title           string                         `json:"title"`
	Description     string                         `json:"description,omitempty"`
	ObligationType  regobligation.ObligationType   `json:"obligationType"`
	SourceReference string                         `json:"sourceReference"`
	EffectiveDate   time.Time                      `json:"effectiveDate"`
	Version         string                         `json:"version"`
	ControlMappings []regobligation.ControlMapping `json:"controlMappings"`
}

// InsertRegulatoryObligation writes a new regulatory_obligations row.
// The caller supplies ob.ID already generated.
func InsertRegulatoryObligation(ctx context.Context, pool *pgxpool.Pool, ob *regobligation.Obligation) error {
	data, err := json.Marshal(regulatoryObligationData{
		Jurisdiction: ob.Jurisdiction, Regulator: ob.Regulator, Sector: ob.Sector, EntityType: ob.EntityType,
		Title: ob.Title, Description: ob.Description, ObligationType: ob.ObligationType,
		SourceReference: ob.SourceReference, EffectiveDate: ob.EffectiveDate, Version: ob.Version,
		ControlMappings: ob.ControlMappings,
	})
	if err != nil {
		return fmt.Errorf("regulatory_obligations: marshal obligation data for %s: %w", ob.ID, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO regulatory_obligations (id, created_by, obligation_data)
		 VALUES ($1,$2,$3)`,
		ob.ID, nullableString(ob.CreatedBy), data)
	if err != nil {
		return fmt.Errorf("regulatory_obligations: insert %s: %w", ob.ID, err)
	}
	return nil
}

func scanRegulatoryObligation(row pgx.Row) (*regobligation.Obligation, error) {
	ob := &regobligation.Obligation{}
	var createdBy *string
	var data []byte
	if err := row.Scan(&ob.ID, &createdBy, &ob.CreatedAt, &data); err != nil {
		return nil, err
	}
	if createdBy != nil {
		ob.CreatedBy = *createdBy
	}
	var rd regulatoryObligationData
	if err := json.Unmarshal(data, &rd); err != nil {
		return nil, fmt.Errorf("regulatory_obligations: unmarshal obligation data for %s: %w", ob.ID, err)
	}
	ob.Jurisdiction, ob.Regulator, ob.Sector, ob.EntityType = rd.Jurisdiction, rd.Regulator, rd.Sector, rd.EntityType
	ob.Title, ob.Description, ob.ObligationType = rd.Title, rd.Description, rd.ObligationType
	ob.SourceReference, ob.EffectiveDate, ob.Version = rd.SourceReference, rd.EffectiveDate, rd.Version
	ob.ControlMappings = rd.ControlMappings
	return ob, nil
}

// GetRegulatoryObligation returns one obligation by id. A missing id
// returns an error satisfying errors.Is(err, pgx.ErrNoRows).
func GetRegulatoryObligation(ctx context.Context, pool *pgxpool.Pool, id string) (*regobligation.Obligation, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, created_by, created_at, obligation_data FROM regulatory_obligations WHERE id = $1`, id)
	ob, err := scanRegulatoryObligation(row)
	if err != nil {
		return nil, fmt.Errorf("regulatory_obligations: get %s: %w", id, err)
	}
	return ob, nil
}

// ListRegulatoryObligations returns up to limit rows, newest first.
func ListRegulatoryObligations(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*regobligation.Obligation, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, created_by, created_at, obligation_data FROM regulatory_obligations ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("regulatory_obligations: list: %w", err)
	}
	defer rows.Close()
	var out []*regobligation.Obligation
	for rows.Next() {
		ob, err := scanRegulatoryObligation(rows)
		if err != nil {
			return nil, fmt.Errorf("regulatory_obligations: list scan: %w", err)
		}
		out = append(out, ob)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("regulatory_obligations: list rows: %w", err)
	}
	return out, nil
}
```

Modify `orchestrator/internal/testutil/testdb.go` — insert immediately after the existing block ending at line 205 (`EnsureZoneIsolationImportSchema`'s closing `}`):

```go
	if err := db.EnsureRegulatoryObligationSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureRegulatoryObligationSchema: %w", err)
	}
```

Modify `orchestrator/cmd/server/main.go` — insert immediately after the existing block ending at line 334 (`EnsureZoneIsolationImportSchema`'s closing `}`), before `log.Println("[+] Schema verified")`:

```go
	if err := db.EnsureRegulatoryObligationSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] regulatory obligation schema: %v", err)
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/db/... -run TestInsertAndGetRegulatoryObligation_RoundTrip\|TestGetRegulatoryObligation_NotFound\|TestListRegulatoryObligations_NewestFirst -v`
Expected: PASS — all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd orchestrator && git add internal/db/regobligation_store.go internal/db/regobligation_store_test.go internal/testutil/testdb.go cmd/server/main.go
git commit -m "feat(db): add regulatory_obligations persistence

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

## Task 3: DB store — evidence snapshots

**Files:**
- Create: `orchestrator/internal/db/regevidence_store.go`
- Test: `orchestrator/internal/db/regevidence_store_test.go`
- Modify: `orchestrator/internal/testutil/testdb.go` (insert after Task 2's addition)
- Modify: `orchestrator/cmd/server/main.go` (insert after Task 2's addition)

**Interfaces:**
- Consumes: `regobligation.EvidenceSnapshot`, `regobligation.SnapshotStatus` (Task 1).
- Produces: `EnsureEvidenceSnapshotSchema(ctx, pool) error`, `InsertEvidenceSnapshot(ctx, pool, es *regobligation.EvidenceSnapshot) error` (caller pre-sets `es.ID`, `es.CapturedAt`), `GetEvidenceSnapshot(ctx, pool, id string) (*regobligation.EvidenceSnapshot, error)`, `ListEvidenceSnapshotsByObligation(ctx, pool, obligationID string) ([]*regobligation.EvidenceSnapshot, error)` (newest-first, no limit param — snapshots are created deliberately by an operator, not automatically, so there's no unbounded-growth risk the other `List*` functions' `limit` param protects against). Task 5 and Task 6 call all four.

**Test harness note:** same `package db_test` + `sharedDB.RunWithPool` pattern as Task 2 — see Task 2's note.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/db/regevidence_store_test.go
package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/regobligation"
)

func TestInsertAndGetEvidenceSnapshot_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		es := &regobligation.EvidenceSnapshot{
			ID: "es-roundtrip-1", SchemaVersion: regobligation.CurrentSnapshotSchemaVersion,
			ObligationID: "ob-1", ControlMappingID: "cm-1", ObligationVersion: "v1",
			CapabilityName:   "zoneisolation.isolation-check",
			ImportReferences: map[string]string{"topologyImportId": "topo-1", "isolationImportId": "iso-1"},
			CapturedOutcome:  "no-violation-found", Status: regobligation.SnapshotCaptured,
			CapturedBy: "user-1", CapturedAt: time.Now().UTC(),
		}
		if err := db.InsertEvidenceSnapshot(context.Background(), pool, es); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := db.GetEvidenceSnapshot(context.Background(), pool, es.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.ObligationID != "ob-1" || got.ControlMappingID != "cm-1" || got.CapturedOutcome != "no-violation-found" {
			t.Errorf("round-tripped snapshot mismatch: %+v", got)
		}
		if got.ImportReferences["topologyImportId"] != "topo-1" {
			t.Errorf("import references did not round-trip: %+v", got.ImportReferences)
		}
	})
}

func TestGetEvidenceSnapshot_NotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetEvidenceSnapshot(context.Background(), pool, "nonexistent-id")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("err = %v, want errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}

func TestListEvidenceSnapshotsByObligation_NewestFirstAndScopedToObligation(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		forOtherObligation := &regobligation.EvidenceSnapshot{
			ID: "es-other", ObligationID: "ob-other", ControlMappingID: "cm-1",
			CapabilityName: "x", CapturedOutcome: "no-violation-found",
			Status: regobligation.SnapshotCaptured, CapturedAt: time.Now().UTC(),
		}
		if err := db.InsertEvidenceSnapshot(context.Background(), pool, forOtherObligation); err != nil {
			t.Fatalf("insert forOtherObligation: %v", err)
		}
		older := &regobligation.EvidenceSnapshot{
			ID: "es-older", ObligationID: "ob-target", ControlMappingID: "cm-1",
			CapabilityName: "x", CapturedOutcome: "no-violation-found",
			Status: regobligation.SnapshotCaptured, CapturedAt: time.Now().UTC(),
		}
		if err := db.InsertEvidenceSnapshot(context.Background(), pool, older); err != nil {
			t.Fatalf("insert older: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
		newer := &regobligation.EvidenceSnapshot{
			ID: "es-newer", ObligationID: "ob-target", ControlMappingID: "cm-1",
			CapabilityName: "x", CapturedOutcome: "confirmed-violation",
			Status: regobligation.SnapshotCaptured, CapturedAt: time.Now().UTC(),
		}
		if err := db.InsertEvidenceSnapshot(context.Background(), pool, newer); err != nil {
			t.Fatalf("insert newer: %v", err)
		}

		list, err := db.ListEvidenceSnapshotsByObligation(context.Background(), pool, "ob-target")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list) != 2 {
			t.Fatalf("got %d snapshots scoped to ob-target, want exactly 2", len(list))
		}
		if list[0].ID != "es-newer" {
			t.Errorf("list[0].ID = %q, want %q (newest first)", list[0].ID, "es-newer")
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/db/... -run TestInsertAndGetEvidenceSnapshot_RoundTrip -v`
Expected: FAIL to compile — `undefined: db.InsertEvidenceSnapshot`.

- [ ] **Step 3: Write the implementation**

```go
// orchestrator/internal/db/regevidence_store.go
package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/regobligation"
)

// EnsureEvidenceSnapshotSchema creates the regulatory_evidence_snapshots
// table and its obligation_id index. Unlike regulatory_obligations'
// created_at, captured_at IS passed explicitly by the caller (never
// DB-defaulted) -- Review Focus #3 requires proving a caller-supplied
// value is server-overwritten, which needs the handler's own
// server-assigned time.Now() to be the value actually persisted and
// visible in the immediate POST response, not a later DB default.
func EnsureEvidenceSnapshotSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS regulatory_evidence_snapshots (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			obligation_id  text        NOT NULL,
			captured_at    timestamptz NOT NULL,
			captured_by    text,
			snapshot_data  jsonb       NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("regulatory_evidence_snapshots: ensure schema: %w", err)
	}
	_, err = pool.Exec(ctx, `
		CREATE INDEX IF NOT EXISTS idx_regulatory_evidence_snapshots_obligation_id
		ON regulatory_evidence_snapshots (obligation_id)`)
	if err != nil {
		return fmt.Errorf("regulatory_evidence_snapshots: ensure index: %w", err)
	}
	return nil
}

// evidenceSnapshotData is the shape persisted in the snapshot_data
// jsonb column -- everything except id/obligation_id/captured_at/
// captured_by, which live in their own columns.
type evidenceSnapshotData struct {
	SchemaVersion       string                       `json:"schemaVersion,omitempty"`
	ControlMappingID    string                       `json:"controlMappingId"`
	ObligationVersion   string                       `json:"obligationVersion,omitempty"`
	CapabilityName      string                       `json:"capabilityName"`
	ImportReferences    map[string]string            `json:"importReferences,omitempty"`
	QueryParameters     map[string]any               `json:"queryParameters,omitempty"`
	CapturedOutcome     string                       `json:"capturedOutcome,omitempty"`
	CapturedConfidence  string                       `json:"capturedConfidence,omitempty"`
	CapturedLimitations string                       `json:"capturedLimitations,omitempty"`
	Status              regobligation.SnapshotStatus `json:"status"`
	IncompleteReason    string                       `json:"incompleteReason,omitempty"`
	Note                string                       `json:"note,omitempty"`
}

// InsertEvidenceSnapshot writes a new regulatory_evidence_snapshots
// row. The caller supplies es.ID and es.CapturedAt already set.
func InsertEvidenceSnapshot(ctx context.Context, pool *pgxpool.Pool, es *regobligation.EvidenceSnapshot) error {
	data, err := json.Marshal(evidenceSnapshotData{
		SchemaVersion: es.SchemaVersion, ControlMappingID: es.ControlMappingID, ObligationVersion: es.ObligationVersion,
		CapabilityName: es.CapabilityName, ImportReferences: es.ImportReferences, QueryParameters: es.QueryParameters,
		CapturedOutcome: es.CapturedOutcome, CapturedConfidence: es.CapturedConfidence, CapturedLimitations: es.CapturedLimitations,
		Status: es.Status, IncompleteReason: es.IncompleteReason, Note: es.Note,
	})
	if err != nil {
		return fmt.Errorf("regulatory_evidence_snapshots: marshal snapshot data for %s: %w", es.ID, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO regulatory_evidence_snapshots (id, obligation_id, captured_at, captured_by, snapshot_data)
		 VALUES ($1,$2,$3,$4,$5)`,
		es.ID, es.ObligationID, es.CapturedAt, nullableString(es.CapturedBy), data)
	if err != nil {
		return fmt.Errorf("regulatory_evidence_snapshots: insert %s: %w", es.ID, err)
	}
	return nil
}

func scanEvidenceSnapshot(row pgx.Row) (*regobligation.EvidenceSnapshot, error) {
	es := &regobligation.EvidenceSnapshot{}
	var capturedBy *string
	var data []byte
	if err := row.Scan(&es.ID, &es.ObligationID, &es.CapturedAt, &capturedBy, &data); err != nil {
		return nil, err
	}
	if capturedBy != nil {
		es.CapturedBy = *capturedBy
	}
	var sd evidenceSnapshotData
	if err := json.Unmarshal(data, &sd); err != nil {
		return nil, fmt.Errorf("regulatory_evidence_snapshots: unmarshal snapshot data for %s: %w", es.ID, err)
	}
	es.SchemaVersion, es.ControlMappingID, es.ObligationVersion = sd.SchemaVersion, sd.ControlMappingID, sd.ObligationVersion
	es.CapabilityName, es.ImportReferences, es.QueryParameters = sd.CapabilityName, sd.ImportReferences, sd.QueryParameters
	es.CapturedOutcome, es.CapturedConfidence, es.CapturedLimitations = sd.CapturedOutcome, sd.CapturedConfidence, sd.CapturedLimitations
	es.Status, es.IncompleteReason, es.Note = sd.Status, sd.IncompleteReason, sd.Note
	return es, nil
}

// GetEvidenceSnapshot returns one snapshot by id. A missing id returns
// an error satisfying errors.Is(err, pgx.ErrNoRows).
func GetEvidenceSnapshot(ctx context.Context, pool *pgxpool.Pool, id string) (*regobligation.EvidenceSnapshot, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, obligation_id, captured_at, captured_by, snapshot_data FROM regulatory_evidence_snapshots WHERE id = $1`, id)
	es, err := scanEvidenceSnapshot(row)
	if err != nil {
		return nil, fmt.Errorf("regulatory_evidence_snapshots: get %s: %w", id, err)
	}
	return es, nil
}

// ListEvidenceSnapshotsByObligation returns every snapshot for one
// obligation, newest first.
func ListEvidenceSnapshotsByObligation(ctx context.Context, pool *pgxpool.Pool, obligationID string) ([]*regobligation.EvidenceSnapshot, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, obligation_id, captured_at, captured_by, snapshot_data
		 FROM regulatory_evidence_snapshots WHERE obligation_id = $1 ORDER BY captured_at DESC`, obligationID)
	if err != nil {
		return nil, fmt.Errorf("regulatory_evidence_snapshots: list by obligation %s: %w", obligationID, err)
	}
	defer rows.Close()
	var out []*regobligation.EvidenceSnapshot
	for rows.Next() {
		es, err := scanEvidenceSnapshot(rows)
		if err != nil {
			return nil, fmt.Errorf("regulatory_evidence_snapshots: list scan: %w", err)
		}
		out = append(out, es)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("regulatory_evidence_snapshots: list rows: %w", err)
	}
	return out, nil
}
```

Modify `orchestrator/internal/testutil/testdb.go` — insert immediately after Task 2's `EnsureRegulatoryObligationSchema` block:

```go
	if err := db.EnsureEvidenceSnapshotSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureEvidenceSnapshotSchema: %w", err)
	}
```

Modify `orchestrator/cmd/server/main.go` — insert immediately after Task 2's `EnsureRegulatoryObligationSchema` block, before `log.Println("[+] Schema verified")`:

```go
	if err := db.EnsureEvidenceSnapshotSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] evidence snapshot schema: %v", err)
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/db/... -run TestInsertAndGetEvidenceSnapshot_RoundTrip\|TestGetEvidenceSnapshot_NotFound\|TestListEvidenceSnapshotsByObligation_NewestFirstAndScopedToObligation -v`
Expected: PASS — all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd orchestrator && git add internal/db/regevidence_store.go internal/db/regevidence_store_test.go internal/testutil/testdb.go cmd/server/main.go
git commit -m "feat(db): add regulatory_evidence_snapshots persistence

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

## Task 4: API — regulatory obligation CRUD

**Files:**
- Create: `orchestrator/internal/api/regobligation_handlers.go`
- Test: `orchestrator/internal/api/regobligation_handlers_test.go`
- Modify: `orchestrator/internal/auth/permissions.go:270-271` (insert after line 270, before the closing `)`)
- Modify: `orchestrator/internal/auth/permissions.go:336` (RoleAdmin map) and `:352` (RoleAnalyst map)
- Modify: `orchestrator/internal/api/routes.go:265-266` (GET routes) and `:449-450` (POST routes)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go:78-79` (tierAny rows) and `:235-236` (tierPermission rows)

**Interfaces:**
- Consumes: `regobligation.Obligation`, `regobligation.ControlMapping`, `regobligation.ObligationType`, `MaxControlMappingsPerObligation` (Task 1); `db.InsertRegulatoryObligation`, `db.GetRegulatoryObligation`, `db.ListRegulatoryObligations` (Task 2).
- Produces: `(h *Handler) CreateRegulatoryObligation`, `(h *Handler) ListRegulatoryObligations`, `(h *Handler) GetRegulatoryObligation` (handler methods), `validateObligation(ob *regobligation.Obligation) error`, `auth.CanManageRegulatoryObligations` permission constant, test helper `createTestObligation(t, h, pool, body) string`. Task 5 reuses `auth.CanManageRegulatoryObligations` for its own routes; Task 5 and Task 6 reuse `createTestObligation`.

**Test harness note:** use the real, already-existing `internal/api` test harness — `sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) { h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret); ... })`, `seedUser`, `authedRequest`, `callAuthed`, `withURLParam` (all in `internal/api/testmain_test.go`/`event_handlers_test.go`, confirmed this session by reading `internal/api/zoneisolation_handlers_test.go` in full). Every handler call in this task's tests MUST go through `callAuthed(h.HandlerMethod, req)`, never a direct `h.HandlerMethod(httptest.NewRecorder(), req)` call — only `callAuthed` routes the request through `auth.Middleware` so `auth.ClaimsFrom(r.Context())` resolves inside the handler.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/regobligation_handlers_test.go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/regobligation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func validObligationBody() map[string]any {
	return map[string]any{
		"jurisdiction":    "India",
		"regulator":       "RBI",
		"sector":          "Banking",
		"entityType":      "Regulated Financial Institution",
		"title":           "Network segmentation for critical payment/banking systems",
		"obligationType":  "mandatory",
		"sourceReference": "RBI Cyber Security Framework for Banks",
		"effectiveDate":   "2016-06-02T00:00:00Z",
		"version":         "RBI CSF 2016 (as amended)",
		"controlMappings": []map[string]any{
			{"canonicalId": "cm-1", "controlName": "Segmentation", "capabilityName": "zoneisolation.isolation-check"},
		},
	}
}

// createTestObligation mirrors createTestTopologyImport's own pattern
// exactly: seeds its own user, builds the request, and runs it through
// callAuthed so auth.ClaimsFrom resolves inside the handler.
func createTestObligation(t *testing.T, h *Handler, pool *pgxpool.Pool, body map[string]any) string {
	t.Helper()
	userID := seedUser(t, pool, "regobligation-op", "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	req := authedRequest(t, http.MethodPost, "/api/regulatory-obligations", bytes.NewReader(b), auth.RoleAnalyst, userID)
	rec := callAuthed(h.CreateRegulatoryObligation, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create obligation: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created regobligation.Obligation
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created obligation: %v", err)
	}
	return created.ID
}

func TestCreateRegulatoryObligation_Valid_Created(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		id := createTestObligation(t, h, pool, validObligationBody())
		if id == "" {
			t.Fatal("expected a non-empty obligation id")
		}

		getReq := authedRequest(t, http.MethodGet, "/api/regulatory-obligations/"+id, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", id)
		rec := callAuthed(h.GetRegulatoryObligation, getReq)
		if rec.Code != http.StatusOK {
			t.Fatalf("get obligation: expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var got regobligation.Obligation
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Jurisdiction != "India" || got.Regulator != "RBI" {
			t.Errorf("round-tripped obligation mismatch: %+v", got)
		}
		if len(got.ControlMappings) != 1 || got.ControlMappings[0].CapabilityName != "zoneisolation.isolation-check" {
			t.Errorf("control mappings mismatch: %+v", got.ControlMappings)
		}
	})
}

func TestCreateRegulatoryObligation_InvalidObligationType_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validObligationBody()
		body["obligationType"] = "not-a-real-type"
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "regobligation-badtype", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/regulatory-obligations", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateRegulatoryObligation, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for an invalid obligationType, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateRegulatoryObligation_MissingControlMappings_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validObligationBody()
		body["controlMappings"] = []map[string]any{}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "regobligation-nocm", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/regulatory-obligations", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateRegulatoryObligation, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for zero control mappings, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateRegulatoryObligation_MissingRequiredFields_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validObligationBody()
		delete(body, "sourceReference")
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "regobligation-missing", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/regulatory-obligations", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateRegulatoryObligation, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for a missing sourceReference, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestListRegulatoryObligations_ReturnsCreated(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		id := createTestObligation(t, h, pool, validObligationBody())

		req := authedRequest(t, http.MethodGet, "/api/regulatory-obligations", nil, auth.RoleViewer, "")
		rec := callAuthed(h.ListRegulatoryObligations, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("list: expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var list []regobligation.Obligation
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
			t.Fatalf("decode: %v", err)
		}
		found := false
		for _, ob := range list {
			if ob.ID == id {
				found = true
			}
		}
		if !found {
			t.Errorf("expected created obligation %s in list, got %+v", id, list)
		}
	})
}

func TestGetRegulatoryObligation_NotFound_Returns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := authedRequest(t, http.MethodGet, "/api/regulatory-obligations/nonexistent", nil, auth.RoleViewer, "")
		req = withURLParam(req, "id", "nonexistent")
		rec := callAuthed(h.GetRegulatoryObligation, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestCreateRegulatoryObligation_Valid_Created -v`
Expected: FAIL to compile — `undefined: Handler.CreateRegulatoryObligation` (handler doesn't exist yet).

- [ ] **Step 3: Write the implementation**

```go
// orchestrator/internal/api/regobligation_handlers.go
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/regobligation"
)

const maxRegulatoryObligationRequestBytes = 1 << 16

// CreateRegulatoryObligation -- POST /api/regulatory-obligations.
func (h *Handler) CreateRegulatoryObligation(w http.ResponseWriter, r *http.Request) {
	var req regobligation.Obligation
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRegulatoryObligationRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateObligation(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var createdBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		createdBy = c.UserID
	}
	req.ID = newID()
	req.CreatedBy = createdBy

	if err := db.InsertRegulatoryObligation(r.Context(), h.db, &req); err != nil {
		h.auditLog(r, "regobligation.create", "", map[string]any{"error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "regobligation.create", req.ID, map[string]any{"jurisdiction": req.Jurisdiction, "regulator": req.Regulator}, "ok")
	respondStatus(w, req, http.StatusCreated)
}

// validateObligation enforces spec §3.1's required-field and
// ObligationType-enum discipline.
func validateObligation(ob *regobligation.Obligation) error {
	if ob.Jurisdiction == "" {
		return fmt.Errorf("jurisdiction is required")
	}
	if ob.Regulator == "" {
		return fmt.Errorf("regulator is required")
	}
	if ob.Title == "" {
		return fmt.Errorf("title is required")
	}
	if ob.SourceReference == "" {
		return fmt.Errorf("sourceReference is required")
	}
	if ob.EffectiveDate.IsZero() {
		return fmt.Errorf("effectiveDate is required")
	}
	if ob.Version == "" {
		return fmt.Errorf("version is required")
	}
	switch ob.ObligationType {
	case regobligation.ObligationMandatory, regobligation.ObligationGuidance, regobligation.ObligationContractual, regobligation.ObligationRecommended:
	default:
		return fmt.Errorf("obligationType must be one of mandatory, guidance, contractual, recommended — got %q", ob.ObligationType)
	}
	if len(ob.ControlMappings) == 0 {
		return fmt.Errorf("at least one controlMapping is required")
	}
	if len(ob.ControlMappings) > regobligation.MaxControlMappingsPerObligation {
		return fmt.Errorf("too many control mappings — got %d, max %d", len(ob.ControlMappings), regobligation.MaxControlMappingsPerObligation)
	}
	for i, cm := range ob.ControlMappings {
		if cm.ControlName == "" || cm.CapabilityName == "" {
			return fmt.Errorf("controlMappings[%d]: controlName and capabilityName are both required", i)
		}
	}
	return nil
}

// ListRegulatoryObligations -- GET /api/regulatory-obligations.
func (h *Handler) ListRegulatoryObligations(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	obligations, err := db.ListRegulatoryObligations(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if obligations == nil {
		obligations = []*regobligation.Obligation{}
	}
	respond(w, obligations)
}

// GetRegulatoryObligation -- GET /api/regulatory-obligations/{id}.
func (h *Handler) GetRegulatoryObligation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ob, err := db.GetRegulatoryObligation(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "regulatory obligation not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, ob)
}
```

Modify `orchestrator/internal/auth/permissions.go` — insert immediately after line 270 (`CanImportZoneIsolationConfig Permission = "zone-isolation:import"`), before the closing `)`:

```go

	// regulatory-obligation:manage gates creating/listing regulatory
	// obligations and their evidence snapshots (Network BAS Phase 7C)
	// -- same placement as CanImportZoneIsolationConfig, for the same
	// reason.
	CanManageRegulatoryObligations Permission = "regulatory-obligation:manage"
```

Modify `orchestrator/internal/auth/permissions.go` — in `RoleAdmin`'s map (the line containing `CanImportZoneIsolationConfig: true,`, around line 336), append `CanManageRegulatoryObligations: true,` on its own line in the same style. In `RoleAnalyst`'s map (the line ending `..., CanImportZoneIsolationConfig: true,`, around line 352), append `CanManageRegulatoryObligations: true,` to the end of that line.

Modify `orchestrator/internal/api/routes.go` — insert immediately after the `/api/zone-isolation-imports/{id}` GET route (line 265):

```go
		r.Get("/api/regulatory-obligations", h.ListRegulatoryObligations)
		r.Get("/api/regulatory-obligations/{id}", h.GetRegulatoryObligation)
```

Modify `orchestrator/internal/api/routes.go` — insert immediately after the `/api/isolation-checks` POST route (line 449):

```go
		r.With(auth.RequirePermission(auth.CanManageRegulatoryObligations)).Post("/api/regulatory-obligations", h.CreateRegulatoryObligation)
```

Modify `orchestrator/internal/api/rbac_matrix_test.go` — insert immediately after the `/api/zone-isolation-imports/{id}` tierAny row (line 78):

```go
	{http.MethodGet, "/api/regulatory-obligations", tierAny, ""},
	{http.MethodGet, "/api/regulatory-obligations/{id}", tierAny, ""},
```

Modify `orchestrator/internal/api/rbac_matrix_test.go` — insert immediately after the `/api/isolation-checks` tierPermission row (line 235):

```go
	{http.MethodPost, "/api/regulatory-obligations", tierPermission, auth.CanManageRegulatoryObligations},
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestCreateRegulatoryObligation_Valid_Created\|TestCreateRegulatoryObligation_InvalidObligationType_Rejected\|TestCreateRegulatoryObligation_MissingControlMappings_Rejected\|TestCreateRegulatoryObligation_MissingRequiredFields_Rejected\|TestListRegulatoryObligations_ReturnsCreated\|TestGetRegulatoryObligation_NotFound_Returns404\|TestRBACMatrix_NoDrift -v`
Expected: PASS — all 7 tests PASS (including the RBAC drift check, confirming the new routes/permission/rows are mutually consistent).

- [ ] **Step 5: Commit**

```bash
cd orchestrator && git add internal/api/regobligation_handlers.go internal/api/regobligation_handlers_test.go internal/auth/permissions.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(api): add regulatory obligation CRUD endpoints

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

## Task 5: API — evidence snapshot CRUD

**Files:**
- Create: `orchestrator/internal/api/regevidence_handlers.go`
- Test: `orchestrator/internal/api/regevidence_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go` (GET + POST routes, immediately after Task 4's additions)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (tierAny + tierPermission rows, immediately after Task 4's additions)

**Interfaces:**
- Consumes: `regobligation.EvidenceSnapshot`, `regobligation.ControlMapping`, `regobligation.SnapshotStatus`, `regobligation.SnapshotCaptured`, `regobligation.SnapshotIncomplete`, `regobligation.CurrentSnapshotSchemaVersion` (Task 1); `db.GetRegulatoryObligation` (Task 2); `db.InsertEvidenceSnapshot`, `db.GetEvidenceSnapshot`, `db.ListEvidenceSnapshotsByObligation` (Task 3); `auth.CanManageRegulatoryObligations`, `createTestObligation(t, h, pool, body) string`, `validObligationBody() map[string]any` (Task 4).
- Produces: `(h *Handler) CreateEvidenceSnapshot`, `(h *Handler) ListEvidenceSnapshots`, `(h *Handler) GetEvidenceSnapshot` (handler methods), test helper `createTestEvidenceSnapshot(t, h, pool, body) (string, int)`. Task 6 calls `CreateEvidenceSnapshot`/`ListEvidenceSnapshots`/`createTestEvidenceSnapshot`.

**Test harness note:** same as Task 4 — `sharedDB.RunWithPool`, `seedUser`, `authedRequest`, `callAuthed`, `withURLParam`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/regevidence_handlers_test.go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/regobligation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// createTestEvidenceSnapshot mirrors createTestObligation's pattern.
// It returns ("", code) when creation failed, so rejection tests can
// assert on the status code without decoding a body that isn't there.
func createTestEvidenceSnapshot(t *testing.T, h *Handler, pool *pgxpool.Pool, body map[string]any) (string, int) {
	t.Helper()
	userID := seedUser(t, pool, "regevidence-op", "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	req := authedRequest(t, http.MethodPost, "/api/regulatory-evidence-snapshots", bytes.NewReader(b), auth.RoleAnalyst, userID)
	rec := callAuthed(h.CreateEvidenceSnapshot, req)
	if rec.Code != http.StatusCreated {
		return "", rec.Code
	}
	var created regobligation.EvidenceSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created snapshot: %v", err)
	}
	return created.ID, rec.Code
}

func TestCreateEvidenceSnapshot_Valid_Created(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		obligationID := createTestObligation(t, h, pool, validObligationBody())

		id, code := createTestEvidenceSnapshot(t, h, pool, map[string]any{
			"obligationId":     obligationID,
			"controlMappingId": "cm-1",
			"capabilityName":   "zoneisolation.isolation-check",
			"status":           "captured",
			"capturedOutcome":  "no-violation-found",
			"importReferences": map[string]string{"topologyImportId": "topo-1", "isolationImportId": "iso-1"},
		})
		if code != http.StatusCreated {
			t.Fatalf("expected 201, got %d", code)
		}
		if id == "" {
			t.Fatal("expected a non-empty snapshot id")
		}
	})
}

func TestCreateEvidenceSnapshot_ControlMappingIDNotFound_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		obligationID := createTestObligation(t, h, pool, validObligationBody())

		_, code := createTestEvidenceSnapshot(t, h, pool, map[string]any{
			"obligationId":     obligationID,
			"controlMappingId": "cm-does-not-exist",
			"capabilityName":   "zoneisolation.isolation-check",
			"status":           "captured",
			"capturedOutcome":  "no-violation-found",
		})
		if code != http.StatusBadRequest {
			t.Fatalf("expected 400 for an unknown controlMappingId, got %d", code)
		}
	})
}

func TestCreateEvidenceSnapshot_ObligationNotFound_Returns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		_, code := createTestEvidenceSnapshot(t, h, pool, map[string]any{
			"obligationId":     "nonexistent-obligation",
			"controlMappingId": "cm-1",
			"capabilityName":   "zoneisolation.isolation-check",
			"status":           "captured",
			"capturedOutcome":  "no-violation-found",
		})
		if code != http.StatusNotFound {
			t.Fatalf("expected 404 for a nonexistent obligation, got %d", code)
		}
	})
}

func TestCreateEvidenceSnapshot_CapabilityNameMismatch_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		obligationID := createTestObligation(t, h, pool, validObligationBody())

		_, code := createTestEvidenceSnapshot(t, h, pool, map[string]any{
			"obligationId":     obligationID,
			"controlMappingId": "cm-1",
			"capabilityName":   "some-other-capability",
			"status":           "captured",
			"capturedOutcome":  "no-violation-found",
		})
		if code != http.StatusBadRequest {
			t.Fatalf("expected 400 for a mismatched capabilityName, got %d", code)
		}
	})
}

func TestCreateEvidenceSnapshot_CapturedStatusWithoutOutcome_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		obligationID := createTestObligation(t, h, pool, validObligationBody())

		_, code := createTestEvidenceSnapshot(t, h, pool, map[string]any{
			"obligationId":     obligationID,
			"controlMappingId": "cm-1",
			"capabilityName":   "zoneisolation.isolation-check",
			"status":           "captured",
		})
		if code != http.StatusBadRequest {
			t.Fatalf("expected 400 when status=captured has no capturedOutcome, got %d", code)
		}
	})
}

// TestCreateEvidenceSnapshot_IncompleteStatus_PersistsDistinctly --
// Review Focus #1: an incomplete snapshot must never be silently
// dropped or indistinguishable from a captured one when listed.
func TestCreateEvidenceSnapshot_IncompleteStatus_PersistsDistinctly(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		obligationID := createTestObligation(t, h, pool, validObligationBody())

		id, code := createTestEvidenceSnapshot(t, h, pool, map[string]any{
			"obligationId":     obligationID,
			"controlMappingId": "cm-1",
			"capabilityName":   "zoneisolation.isolation-check",
			"status":           "incomplete",
			"incompleteReason": "topology import was not yet available at assessment time",
		})
		if code != http.StatusCreated {
			t.Fatalf("expected 201, got %d", code)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/regulatory-evidence-snapshots?obligationId="+obligationID, nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListEvidenceSnapshots, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list: expected 200, got %d: %s", listRec.Code, listRec.Body.String())
		}
		var list []regobligation.EvidenceSnapshot
		if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var found *regobligation.EvidenceSnapshot
		for i := range list {
			if list[i].ID == id {
				found = &list[i]
			}
		}
		if found == nil {
			t.Fatalf("expected snapshot %s in list, got %+v", id, list)
		}
		if found.Status != regobligation.SnapshotIncomplete {
			t.Errorf("expected status %q, got %q", regobligation.SnapshotIncomplete, found.Status)
		}
		if found.IncompleteReason == "" {
			t.Error("expected a non-empty incompleteReason to be preserved")
		}
	})
}

// TestCreateEvidenceSnapshot_ServerAssignedFields_OverwriteCallerValues
// -- Review Focus #3: a caller-supplied obligationVersion/capturedAt
// must be ignored and overwritten by the server, not merely present.
func TestCreateEvidenceSnapshot_ServerAssignedFields_OverwriteCallerValues(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		obligationID := createTestObligation(t, h, pool, validObligationBody())

		data, _ := json.Marshal(map[string]any{
			"obligationId":      obligationID,
			"controlMappingId":  "cm-1",
			"capabilityName":    "zoneisolation.isolation-check",
			"status":            "captured",
			"capturedOutcome":   "no-violation-found",
			"obligationVersion": "a bogus caller-supplied version that should never be trusted",
			"capturedAt":        "1999-01-01T00:00:00Z",
		})
		userID := seedUser(t, pool, "regevidence-spoof-op", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/regulatory-evidence-snapshots", bytes.NewReader(data), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateEvidenceSnapshot, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
		}
		var created regobligation.EvidenceSnapshot
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if created.ObligationVersion == "a bogus caller-supplied version that should never be trusted" {
			t.Error("expected obligationVersion to be server-assigned from the real obligation, not the caller's value")
		}
		if created.ObligationVersion != "RBI CSF 2016 (as amended)" {
			t.Errorf("expected the real obligation's version, got %q", created.ObligationVersion)
		}
		if created.CapturedAt.Year() == 1999 {
			t.Error("expected capturedAt to be server-assigned to the current time, not the caller's 1999 value")
		}
	})
}

func TestListEvidenceSnapshots_MissingObligationID_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := authedRequest(t, http.MethodGet, "/api/regulatory-evidence-snapshots", nil, auth.RoleViewer, "")
		rec := callAuthed(h.ListEvidenceSnapshots, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 when obligationId is missing, got %d", rec.Code)
		}
	})
}

func TestGetEvidenceSnapshot_NotFound_Returns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := authedRequest(t, http.MethodGet, "/api/regulatory-evidence-snapshots/nonexistent", nil, auth.RoleViewer, "")
		req = withURLParam(req, "id", "nonexistent")
		rec := callAuthed(h.GetEvidenceSnapshot, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestCreateEvidenceSnapshot_Valid_Created -v`
Expected: FAIL to compile — `undefined: Handler.CreateEvidenceSnapshot`.

- [ ] **Step 3: Write the implementation**

```go
// orchestrator/internal/api/regevidence_handlers.go
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/regobligation"
)

const maxEvidenceSnapshotRequestBytes = 1 << 16

// CreateEvidenceSnapshot -- POST /api/regulatory-evidence-snapshots.
// Unlike every other Create* handler in this codebase, this one is not
// a simple decode-validate-insert: it looks up the referenced
// Obligation and cross-checks the submitted controlMappingId/
// capabilityName against that obligation's own declared control
// mappings (spec §3.2) before persisting. It calls no other package's
// composition logic -- the caller has already run the real check
// elsewhere and is submitting its output for recording.
func (h *Handler) CreateEvidenceSnapshot(w http.ResponseWriter, r *http.Request) {
	var req regobligation.EvidenceSnapshot
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEvidenceSnapshotRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.ObligationID == "" {
		jsonError(w, "obligationId is required", http.StatusBadRequest)
		return
	}
	obligation, err := db.GetRegulatoryObligation(r.Context(), h.db, req.ObligationID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "regulatory obligation not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var matched *regobligation.ControlMapping
	for i := range obligation.ControlMappings {
		if obligation.ControlMappings[i].CanonicalID == req.ControlMappingID {
			matched = &obligation.ControlMappings[i]
			break
		}
	}
	if matched == nil {
		jsonError(w, "controlMappingId does not match any control mapping on this obligation", http.StatusBadRequest)
		return
	}
	if req.CapabilityName != matched.CapabilityName {
		jsonError(w, "capabilityName does not match the referenced control mapping's capabilityName", http.StatusBadRequest)
		return
	}

	switch req.Status {
	case regobligation.SnapshotCaptured:
		if req.CapturedOutcome == "" {
			jsonError(w, "capturedOutcome is required when status is captured", http.StatusBadRequest)
			return
		}
	case regobligation.SnapshotIncomplete:
		if req.IncompleteReason == "" {
			jsonError(w, "incompleteReason is required when status is incomplete", http.StatusBadRequest)
			return
		}
	default:
		jsonError(w, fmt.Sprintf("status must be %q or %q — got %q", regobligation.SnapshotCaptured, regobligation.SnapshotIncomplete, req.Status), http.StatusBadRequest)
		return
	}

	var capturedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		capturedBy = c.UserID
	}
	// Server-assigned -- proven by TestCreateEvidenceSnapshot_ServerAssignedFields_OverwriteCallerValues
	// to overwrite whatever the caller sent for these three fields.
	req.ID = newID()
	req.SchemaVersion = regobligation.CurrentSnapshotSchemaVersion
	req.ObligationVersion = obligation.Version
	req.CapturedBy = capturedBy
	req.CapturedAt = time.Now().UTC()

	if err := db.InsertEvidenceSnapshot(r.Context(), h.db, &req); err != nil {
		h.auditLog(r, "regevidence.create", "", map[string]any{"error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "regevidence.create", req.ID, map[string]any{"obligationId": req.ObligationID, "status": string(req.Status)}, "ok")
	respondStatus(w, req, http.StatusCreated)
}

// ListEvidenceSnapshots -- GET /api/regulatory-evidence-snapshots?obligationId={id}.
func (h *Handler) ListEvidenceSnapshots(w http.ResponseWriter, r *http.Request) {
	obligationID := r.URL.Query().Get("obligationId")
	if obligationID == "" {
		jsonError(w, "obligationId query parameter is required", http.StatusBadRequest)
		return
	}
	snapshots, err := db.ListEvidenceSnapshotsByObligation(r.Context(), h.db, obligationID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if snapshots == nil {
		snapshots = []*regobligation.EvidenceSnapshot{}
	}
	respond(w, snapshots)
}

// GetEvidenceSnapshot -- GET /api/regulatory-evidence-snapshots/{id}.
func (h *Handler) GetEvidenceSnapshot(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	es, err := db.GetEvidenceSnapshot(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "evidence snapshot not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, es)
}
```

Modify `orchestrator/internal/api/routes.go` — insert immediately after Task 4's two new GET routes:

```go
		r.Get("/api/regulatory-evidence-snapshots", h.ListEvidenceSnapshots)
		r.Get("/api/regulatory-evidence-snapshots/{id}", h.GetEvidenceSnapshot)
```

Modify `orchestrator/internal/api/routes.go` — insert immediately after Task 4's new POST route:

```go
		r.With(auth.RequirePermission(auth.CanManageRegulatoryObligations)).Post("/api/regulatory-evidence-snapshots", h.CreateEvidenceSnapshot)
```

Modify `orchestrator/internal/api/rbac_matrix_test.go` — insert immediately after Task 4's two new tierAny rows:

```go
	{http.MethodGet, "/api/regulatory-evidence-snapshots", tierAny, ""},
	{http.MethodGet, "/api/regulatory-evidence-snapshots/{id}", tierAny, ""},
```

Modify `orchestrator/internal/api/rbac_matrix_test.go` — insert immediately after Task 4's new tierPermission row:

```go
	{http.MethodPost, "/api/regulatory-evidence-snapshots", tierPermission, auth.CanManageRegulatoryObligations},
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestCreateEvidenceSnapshot\|TestListEvidenceSnapshots_MissingObligationID_Rejected\|TestGetEvidenceSnapshot_NotFound_Returns404\|TestRBACMatrix_NoDrift -v`
Expected: PASS — all 9 tests PASS (7 `TestCreateEvidenceSnapshot_*` + 2 others + RBAC drift check).

- [ ] **Step 5: Commit**

```bash
cd orchestrator && git add internal/api/regevidence_handlers.go internal/api/regevidence_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(api): add regulatory evidence snapshot CRUD endpoints

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

## Task 6: End-to-end India/UAE acceptance test

**Files:**
- Create: `orchestrator/internal/api/regobligation_e2e_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1–5, plus existing test fixture helpers confirmed this session by reading their real source: `createTestTopologyImport(t, h, pool, body map[string]any) string` (`networkpath_handlers_test.go:18`, body shape `{"sourceType": "manual", "zones": []map[string]any{{"name": ..., "cidrs": []string{...}}}, "edges": []map[string]any{{"fromZone": ..., "toZone": ...}}}`), `createTestIsolationImport(t, h, pool, pairs []map[string]any) string` (`isolationcheck_handlers_test.go:18`, `pairs` shape `{"canonicalId": ..., "zoneA": ..., "zoneB": ...}`), `createNetworkTopologyImportForRemoteAccessTest(t, h, userID string, zones, edges []map[string]any) string` and `createRemoteAccessImportForPathTest(t, h, userID string, tunnels []map[string]any) string` (`remoteaccesspath_handlers_test.go:17,35`, `tunnels` shape `{"canonicalId": ..., "fromZone": ..., "toZone": ..., "state": "up"}`).
- Produces: nothing consumed by a later task — this is the plan's final acceptance proof (spec §9, Review Focus #4).

This task proves the acceptance criteria genuinely, not merely by assertion: the test builds a REAL topology + isolation import (India) and a REAL topology + remote-access import (UAE), calls the REAL `FindIsolationChecks`/`FindRemoteAccessPaths` handlers (via `callAuthed`, exactly as every existing test for those handlers does) to get genuinely computed results, creates the India/UAE `Obligation` from spec §5's exact JSON, submits an `EvidenceSnapshot` populated from each real result, then reads both back and confirms no cross-obligation leakage.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/api/regobligation_e2e_test.go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/regobligation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// TestRegulatoryMapping_IndiaAndUAE_EndToEnd -- Review Focus #4 and
// spec §9's acceptance criteria: each of the two seed obligations is
// independently creatable, independently supports a real evidence
// snapshot derived from a genuinely computed Network BAS check result,
// and listing all obligations returns both without either leaking into
// the other's control-mapping/snapshot data.
func TestRegulatoryMapping_IndiaAndUAE_EndToEnd(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "regmapping-e2e-op", "pw12345678", string(auth.RoleAnalyst), true)

		// --- India: RBI network-segmentation obligation, evidenced by
		// a real zoneisolation.isolation-check result. A policy import
		// with an explicit allow rule makes the pair policy-permitted
		// but unobserved, so the real classification is deterministic:
		// unconfirmed-exposure. ---
		indiaTopoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "payment-core", "cidrs": []string{"10.10.0.0/24"}},
				{"name": "corporate", "cidrs": []string{"10.20.0.0/24"}},
			},
			"edges": []map[string]any{
				{"fromZone": "payment-core", "toZone": "corporate"},
			},
		})
		indiaIsolationID := createTestIsolationImport(t, h, pool, []map[string]any{
			{"canonicalId": "zp-1", "zoneA": "payment-core", "zoneB": "corporate"},
		})
		policyBody := map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "payment-core", "cidrs": []string{"10.10.0.0/24"}},
				{"name": "corporate", "cidrs": []string{"10.20.0.0/24"}},
			},
			"rules": []map[string]any{
				{"order": 1, "sourceZone": "payment-core", "destZone": "corporate", "protocol": "tcp", "action": "allow"},
			},
			"defaultPolicy": "deny",
		}
		pb, _ := json.Marshal(policyBody)
		pReq := authedRequest(t, http.MethodPost, "/api/network-policy-imports", bytes.NewReader(pb), auth.RoleAnalyst, userID)
		pRec := callAuthed(h.CreateNetworkPolicyImport, pReq)
		if pRec.Code != http.StatusCreated {
			t.Fatalf("create India policy import: status = %d, body = %s", pRec.Code, pRec.Body.String())
		}
		var indiaPolicy struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(pRec.Body.Bytes(), &indiaPolicy); err != nil {
			t.Fatalf("decode India policy import: %v", err)
		}

		isolationReqBody, _ := json.Marshal(map[string]any{
			"topologyImportId":  indiaTopoID,
			"isolationImportId": indiaIsolationID,
			"policyImportId":    indiaPolicy.ID,
			"port":              443,
			"protocol":          "tcp",
		})
		isolationReq := authedRequest(t, http.MethodPost, "/api/isolation-checks", bytes.NewReader(isolationReqBody), auth.RoleAnalyst, userID)
		isolationRec := callAuthed(h.FindIsolationChecks, isolationReq)
		if isolationRec.Code != http.StatusOK {
			t.Fatalf("isolation check: expected 200, got %d: %s", isolationRec.Code, isolationRec.Body.String())
		}
		var isolationResp struct {
			Results []struct {
				Severity string `json:"severity"`
			} `json:"results"`
		}
		if err := json.Unmarshal(isolationRec.Body.Bytes(), &isolationResp); err != nil {
			t.Fatalf("decode isolation check response: %v", err)
		}
		if len(isolationResp.Results) != 1 {
			t.Fatalf("expected exactly 1 isolation check result, got %d", len(isolationResp.Results))
		}
		indiaOutcome := isolationResp.Results[0].Severity
		if indiaOutcome == "" {
			t.Fatal("expected a non-empty severity from the real isolation check")
		}

		indiaObligationID := createTestObligation(t, h, pool, map[string]any{
			"jurisdiction":    "India",
			"regulator":       "RBI",
			"sector":          "Banking",
			"entityType":      "Regulated Financial Institution",
			"title":           "Network segmentation for critical payment/banking systems",
			"obligationType":  "mandatory",
			"sourceReference": "RBI Cyber Security Framework for Banks",
			"effectiveDate":   "2016-06-02T00:00:00Z",
			"version":         "RBI CSF 2016 (as amended)",
			"controlMappings": []map[string]any{
				{"canonicalId": "cm-1", "controlName": "Segmentation between critical payment-processing zones and the general corporate network", "capabilityName": "zoneisolation.isolation-check"},
			},
		})

		indiaSnapshotID, indiaSnapshotCode := createTestEvidenceSnapshot(t, h, pool, map[string]any{
			"obligationId":     indiaObligationID,
			"controlMappingId": "cm-1",
			"capabilityName":   "zoneisolation.isolation-check",
			"status":           "captured",
			"capturedOutcome":  indiaOutcome,
			"importReferences": map[string]string{
				"topologyImportId":  indiaTopoID,
				"isolationImportId": indiaIsolationID,
				"policyImportId":    indiaPolicy.ID,
			},
		})
		if indiaSnapshotCode != http.StatusCreated {
			t.Fatalf("expected 201 creating the India snapshot, got %d", indiaSnapshotCode)
		}

		// --- UAE: UAE Central Bank vendor remote-access obligation,
		// evidenced by a real remoteaccess.path-check result. The
		// tunnel's "state": "up" makes the route genuinely reachable. ---
		uaeTopoID := createNetworkTopologyImportForRemoteAccessTest(t, h, userID,
			[]map[string]any{
				{"name": "vendor-remote", "cidrs": []string{"10.30.0.0/24"}},
				{"name": "clinical-core", "cidrs": []string{"10.40.0.0/24"}},
			},
			[]map[string]any{},
		)
		uaeRemoteID := createRemoteAccessImportForPathTest(t, h, userID,
			[]map[string]any{
				{"canonicalId": "vpn-1", "fromZone": "vendor-remote", "toZone": "clinical-core", "state": "up"},
			},
		)

		remoteAccessReqBody, _ := json.Marshal(map[string]any{
			"topologyImportId":     uaeTopoID,
			"remoteAccessImportId": uaeRemoteID,
			"sourceHost":           "10.30.0.5",
			"destHost":             "10.40.0.5",
			"port":                 443,
			"protocol":             "tcp",
		})
		remoteAccessReq := authedRequest(t, http.MethodPost, "/api/remote-access-paths", bytes.NewReader(remoteAccessReqBody), auth.RoleAnalyst, userID)
		remoteAccessRec := callAuthed(h.FindRemoteAccessPaths, remoteAccessReq)
		if remoteAccessRec.Code != http.StatusOK {
			t.Fatalf("remote access path check: expected 200, got %d: %s", remoteAccessRec.Code, remoteAccessRec.Body.String())
		}
		var remoteAccessResp struct {
			Results []struct {
				State string `json:"state"`
			} `json:"results"`
		}
		if err := json.Unmarshal(remoteAccessRec.Body.Bytes(), &remoteAccessResp); err != nil {
			t.Fatalf("decode remote access path response: %v", err)
		}
		if len(remoteAccessResp.Results) != 1 {
			t.Fatalf("expected exactly 1 remote access path result, got %d", len(remoteAccessResp.Results))
		}
		uaeOutcome := remoteAccessResp.Results[0].State
		if uaeOutcome == "" {
			t.Fatal("expected a non-empty state from the real remote access path check")
		}

		uaeObligationID := createTestObligation(t, h, pool, map[string]any{
			"jurisdiction":    "UAE",
			"regulator":       "UAE Central Bank",
			"sector":          "Banking",
			"entityType":      "Regulated Financial Institution",
			"title":           "Third-party/vendor remote-access control for regulated financial institutions",
			"obligationType":  "mandatory",
			"sourceReference": "UAE Central Bank Information Assurance Standards",
			"effectiveDate":   "2018-01-01T00:00:00Z",
			"version":         "IAS 1.0",
			"controlMappings": []map[string]any{
				{"canonicalId": "cm-1", "controlName": "Vendor VPN/remote-access paths are routed only through approved, monitored channels", "capabilityName": "remoteaccess.path-check"},
			},
		})

		uaeSnapshotID, uaeSnapshotCode := createTestEvidenceSnapshot(t, h, pool, map[string]any{
			"obligationId":     uaeObligationID,
			"controlMappingId": "cm-1",
			"capabilityName":   "remoteaccess.path-check",
			"status":           "captured",
			"capturedOutcome":  uaeOutcome,
			"importReferences": map[string]string{
				"topologyImportId":     uaeTopoID,
				"remoteAccessImportId": uaeRemoteID,
			},
		})
		if uaeSnapshotCode != http.StatusCreated {
			t.Fatalf("expected 201 creating the UAE snapshot, got %d", uaeSnapshotCode)
		}

		// --- Both obligations must appear in the list, with their own
		// snapshots scoped correctly, no leakage. ---
		listReq := authedRequest(t, http.MethodGet, "/api/regulatory-obligations", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListRegulatoryObligations, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list obligations: expected 200, got %d: %s", listRec.Code, listRec.Body.String())
		}
		var obligationList []regobligation.Obligation
		if err := json.Unmarshal(listRec.Body.Bytes(), &obligationList); err != nil {
			t.Fatalf("decode obligation list: %v", err)
		}
		var sawIndia, sawUAE bool
		for _, ob := range obligationList {
			if ob.ID == indiaObligationID {
				sawIndia = true
			}
			if ob.ID == uaeObligationID {
				sawUAE = true
			}
		}
		if !sawIndia || !sawUAE {
			t.Fatalf("expected both India (%s) and UAE (%s) obligations in the list, sawIndia=%v sawUAE=%v",
				indiaObligationID, uaeObligationID, sawIndia, sawUAE)
		}

		indiaSnapshotsReq := authedRequest(t, http.MethodGet, "/api/regulatory-evidence-snapshots?obligationId="+indiaObligationID, nil, auth.RoleViewer, "")
		indiaSnapshotsRec := callAuthed(h.ListEvidenceSnapshots, indiaSnapshotsReq)
		var indiaSnapshots []regobligation.EvidenceSnapshot
		if err := json.Unmarshal(indiaSnapshotsRec.Body.Bytes(), &indiaSnapshots); err != nil {
			t.Fatalf("decode India snapshots: %v", err)
		}
		if len(indiaSnapshots) != 1 || indiaSnapshots[0].ID != indiaSnapshotID {
			t.Fatalf("expected exactly the India snapshot scoped to the India obligation, got %+v", indiaSnapshots)
		}
		if indiaSnapshots[0].CapabilityName != "zoneisolation.isolation-check" {
			t.Errorf("India snapshot capabilityName leaked/mismatched: %q", indiaSnapshots[0].CapabilityName)
		}

		uaeSnapshotsReq := authedRequest(t, http.MethodGet, "/api/regulatory-evidence-snapshots?obligationId="+uaeObligationID, nil, auth.RoleViewer, "")
		uaeSnapshotsRec := callAuthed(h.ListEvidenceSnapshots, uaeSnapshotsReq)
		var uaeSnapshots []regobligation.EvidenceSnapshot
		if err := json.Unmarshal(uaeSnapshotsRec.Body.Bytes(), &uaeSnapshots); err != nil {
			t.Fatalf("decode UAE snapshots: %v", err)
		}
		if len(uaeSnapshots) != 1 || uaeSnapshots[0].ID != uaeSnapshotID {
			t.Fatalf("expected exactly the UAE snapshot scoped to the UAE obligation, got %+v", uaeSnapshots)
		}
		if uaeSnapshots[0].CapabilityName != "remoteaccess.path-check" {
			t.Errorf("UAE snapshot capabilityName leaked/mismatched: %q", uaeSnapshots[0].CapabilityName)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestRegulatoryMapping_IndiaAndUAE_EndToEnd -v`
Expected: FAIL — this test file is new, so its first run exercises the whole chain built by Tasks 1–5. If every prior task's GREEN already passed, this step should mostly just confirm compilation and a clean PASS; treat any failure here as a signal to re-read whichever helper/handler the failure points at (per the Global Constraints' "a plan step that turns out impossible given the real current code is a plan defect to rule on and fix inline during execution" rule) rather than a sign Tasks 1–5 are broken.

- [ ] **Step 3: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestRegulatoryMapping_IndiaAndUAE_EndToEnd -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
cd orchestrator && git add internal/api/regobligation_e2e_test.go
git commit -m "test(api): add India/UAE end-to-end regulatory mapping acceptance test

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

## Final Combined Gate (run once, after all 6 tasks)

```bash
cd orchestrator
go build ./...
go vet ./internal/regobligation/... ./internal/db/... ./internal/api/... ./internal/auth/...
go test ./internal/regobligation/... -v
go test ./internal/db/... -run RegulatoryObligation\|EvidenceSnapshot -v
go test ./internal/api/... -run RegulatoryObligation\|EvidenceSnapshot\|RegulatoryMapping\|RBACMatrix -v
```

Expected: everything builds and vets clean, and every test named above passes. Additionally confirm the zero-import-dependency constraint directly:

```bash
go list -deps ./internal/regobligation/... | grep -E "audspect/bas/internal/(compliance|networkpolicy|networkpath|zoneisolation|remoteaccess|networktopology|networkgraph|otsafety|cloudpath|cloudgraph)"
```

Expected: empty output (no matches) — confirms `internal/regobligation` itself imports none of these, satisfying spec §2's non-negotiable boundary. (The `internal/api`/`internal/db` test files for this phase are expected and allowed to import these packages for test fixtures — only `internal/regobligation` itself must stay clean.)
