# Generic TAXII 2.1 Connector — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a generic, multi-instance TAXII 2.1 connector that ingests STIX `indicator` objects (from FS-ISAC or any other TAXII 2.1 server) into the existing IOC Registry with `Origin=threat-feed`.

**Architecture:** A new, fully self-contained `internal/taxii` package (client, STIX/pattern parser, normalizer, Store, per-connector `Poller`/`Manager`) that writes into the existing `iocregistry` package through one new exported function. Deliberately does **not** touch `internal/connector.Scheduler` — Phase 1 has no `ThreatActor` output, so it runs its own poller built on the same `exercise.PollScheduler` primitive this session already used for `vexsweep`/`emsweep`.

**Tech Stack:** Go, Postgres (pgx/v5), chi router, existing `iocregistry`/`exercise` packages, `net/http`+`httptest` for the TAXII client and its tests, plain JS/HTML in `wwwroot/index.html` for the UI.

**Spec:** `docs/superpowers/specs/2026-08-13-taxii-connector-phase1-design.md`

## Global Constraints

- Auth types supported: `none`, `basic` only. `client_cert`/`client_key` columns exist but no mTLS code path is written (spec: no premature mTLS).
- STIX pattern support: single-comparison patterns only (`ipv4-addr:value`, `ipv6-addr:value`, `domain-name:value`, `url:value`, `file:hashes.'SHA-256'|'MD5'|'SHA-1'`). Composite/boolean patterns are never partially parsed — always routed to "skipped".
- Idempotency key: `(connector_id, stix_id, modified)`. A poll re-seeing an identical triple is a no-op; a bumped `modified` on a known `stix_id` still flows through and hits `iocs`' existing `(type,value)` upsert.
- Secrets (`password`, `client_cert`, `client_key`) are stored **plaintext**, matching `threat_intel_config.api_key`'s existing precedent — no new encryption scheme.
- Default poll interval: 24 hours, matching `internal/connector.Scheduler`'s existing default.
- No changes to `internal/connector`, `internal/threatgraph`, or any Phase 2/3/4 concern (actor/campaign/malware/tool routing, `indicates` relationships) — explicitly out of scope for this plan.
- This session works directly on `main`, no worktrees. Commit + `git push` after every task. TDD every Go component. Run the full relevant package suite (not just new tests) via background Bash before each commit, and always read the real completed log file before treating a run as green.

---

### Task 1: DB migration — `taxii_connector_config` + `taxii_ingested_objects`

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (near the `threat_intel_config` block, currently `:1063-1077`, immediately before `dashboard_snapshots` at `:1079` — re-confirm exact lines with `grep -n "threat_intel_config\|dashboard_snapshots" internal/db/postgres.go` before editing, since prior sessions' edits may have shifted them)

**Interfaces:**
- Produces: the two tables every later task's SQL depends on.

- [ ] **Step 1: Add the migration**

Insert immediately after the `threat_intel_config` block's closing `)` and its trailing comma, before the `dashboard_snapshots` comment:

```go
		// taxii_connector_config: one row per configured TAXII 2.1 server
		// (e.g. FS-ISAC, HC-ISAC) -- unlike threat_intel_config's one-row-
		// per-connector-TYPE singleton, this is genuinely multi-instance: a
		// deployment may run zero, one, or several TAXII sources at once.
		// client_cert/client_key are reserved for a future mTLS phase and
		// unused today. See
		// docs/superpowers/specs/2026-08-13-taxii-connector-phase1-design.md.
		`CREATE TABLE IF NOT EXISTS taxii_connector_config (
			id                text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			name              text        NOT NULL,
			server_url        text        NOT NULL,
			api_root          text        NOT NULL DEFAULT '',
			collection_id     text        NOT NULL DEFAULT '',
			auth_type         text        NOT NULL DEFAULT 'none',
			username          text        NOT NULL DEFAULT '',
			password          text        NOT NULL DEFAULT '',
			client_cert       text        NOT NULL DEFAULT '',
			client_key        text        NOT NULL DEFAULT '',
			enabled           boolean     NOT NULL DEFAULT false,
			last_poll_at      timestamptz,
			last_poll_status  text        NOT NULL DEFAULT 'never',
			last_poll_summary jsonb       NOT NULL DEFAULT '{}',
			last_error        text        NOT NULL DEFAULT '',
			created_at        timestamptz NOT NULL DEFAULT NOW(),
			updated_at        timestamptz NOT NULL DEFAULT NOW()
		)`,

		// taxii_ingested_objects: the idempotency ledger. A poll re-seeing an
		// unchanged (connector_id, stix_id, modified) triple short-circuits
		// before re-parsing; a bumped `modified` on a known stix_id still
		// flows through and hits iocs' existing (type,value) upsert.
		`CREATE TABLE IF NOT EXISTS taxii_ingested_objects (
			connector_id text        NOT NULL REFERENCES taxii_connector_config(id) ON DELETE CASCADE,
			stix_id      text        NOT NULL,
			modified     timestamptz NOT NULL,
			ioc_id       text        NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
			ingested_at  timestamptz NOT NULL DEFAULT NOW(),
			PRIMARY KEY (connector_id, stix_id, modified)
		)`,

```

- [ ] **Step 2: Verify it builds**

Run: `cd orchestrator && go build ./... 2>&1`
Expected: no output.

- [ ] **Step 3: Commit**

```bash
cd orchestrator
git add internal/db/postgres.go
git commit -m "feat(db): add taxii_connector_config + taxii_ingested_objects migration"
git push
```

---

### Task 2: `internal/iocregistry` — `SourceThreatFeed`/`StatusReported` + `RegisterFromThreatFeed` (TDD)

**Files:**
- Modify: `orchestrator/internal/iocregistry/types.go`
- Create: `orchestrator/internal/iocregistry/threatfeed.go`
- Test: `orchestrator/internal/iocregistry/threatfeed_test.go`

**Interfaces:**
- Consumes: `upsertIOCFull(ctx, pool, t Type, value string, source Source, origin Origin, status Status, metadata map[string]any) (string, error)` — the existing shared insert, defined in `internal/iocregistry/extract.go`. Unexported, so `RegisterFromThreatFeed` must live inside the `iocregistry` package itself (not `internal/taxii`) to call it.
- Produces: `iocregistry.SourceThreatFeed`, `iocregistry.StatusReported` (new enum consts), `iocregistry.RegisterFromThreatFeed(ctx context.Context, pool *pgxpool.Pool, t Type, value string, metadata map[string]any) (iocID string, err error)` — Task 6 (Normalizer) calls this directly.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/iocregistry/threatfeed_test.go
package iocregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRegisterFromThreatFeed_WritesSourceOriginStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		id, err := RegisterFromThreatFeed(ctx, pool, TypeIP, "203.0.113.9", map[string]any{"stixId": "indicator--abc"})
		if err != nil {
			t.Fatalf("RegisterFromThreatFeed: %v", err)
		}
		if id == "" {
			t.Fatal("expected a non-empty ioc id")
		}
		var source, origin, status string
		if err := pool.QueryRow(ctx, `SELECT source, origin, status FROM iocs WHERE id = $1`, id).
			Scan(&source, &origin, &status); err != nil {
			t.Fatalf("query iocs row: %v", err)
		}
		if source != string(SourceThreatFeed) {
			t.Errorf("source = %q, want %q", source, SourceThreatFeed)
		}
		if origin != string(OriginThreatFeed) {
			t.Errorf("origin = %q, want %q", origin, OriginThreatFeed)
		}
		if status != string(StatusReported) {
			t.Errorf("status = %q, want %q", status, StatusReported)
		}
	})
}

func TestRegisterFromThreatFeed_RepeatCallBumpsSightingCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		id1, err := RegisterFromThreatFeed(ctx, pool, TypeDomain, "evil.example.com", nil)
		if err != nil {
			t.Fatalf("first RegisterFromThreatFeed: %v", err)
		}
		id2, err := RegisterFromThreatFeed(ctx, pool, TypeDomain, "evil.example.com", nil)
		if err != nil {
			t.Fatalf("second RegisterFromThreatFeed: %v", err)
		}
		if id1 != id2 {
			t.Fatalf("expected same ioc id on repeat, got %q then %q", id1, id2)
		}
		var count int
		if err := pool.QueryRow(ctx, `SELECT sighting_count FROM iocs WHERE id = $1`, id1).Scan(&count); err != nil {
			t.Fatalf("query sighting_count: %v", err)
		}
		if count != 2 {
			t.Errorf("sighting_count = %d, want 2", count)
		}
	})
}
```

Note: this test file needs a `sharedDB` variable and `TestMain` — check whether `internal/iocregistry` already has one (e.g. in `extract_test.go` or `otx_test.go`) before adding a second `TestMain` (Go allows only one per package):

Run: `grep -rn "func TestMain" internal/iocregistry/*.go`

If one already exists, do not add another — just use the existing `sharedDB` variable it defines.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/iocregistry/... -run "TestRegisterFromThreatFeed" -v 2>&1`
Expected: compile failure (`RegisterFromThreatFeed`/`SourceThreatFeed`/`StatusReported` undefined).

- [ ] **Step 3: Add the enum values**

In `orchestrator/internal/iocregistry/types.go`, extend the `Source` const block (currently `:30-35`):

```go
const (
	SourceDetectionAlert Source = "detection_alert"
	SourceScenario       Source = "scenario"
	SourceVariant        Source = "variant"
	SourceManual         Source = "manual"
	// SourceThreatFeed marks an indicator ingested from an external threat
	// intelligence feed (e.g. a TAXII/STIX ISAC feed) -- automated, not
	// human-entered like SourceManual, and not observed during our own
	// execution like SourceDetectionAlert/SourceScenario/SourceVariant.
	SourceThreatFeed Source = "threat_feed"
)
```

And extend the `Status` const block (currently `:56-66`), immediately after `StatusArchived`:

```go
	StatusArchived  Status = "archived"
	// StatusReported marks an indicator that is intel-asserted (reported by
	// an external threat feed) but has not gone through any stage of OUR
	// OWN execution lifecycle (Draft..Archived above all describe stages of
	// a scenario/run pipeline a TAXII-ingested indicator never entered).
	StatusReported Status = "reported"
)
```

- [ ] **Step 4: Implement `RegisterFromThreatFeed`**

```go
// orchestrator/internal/iocregistry/threatfeed.go
package iocregistry

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RegisterFromThreatFeed writes one TAXII-sourced indicator into the
// registry as Source=threat_feed, Origin=threat-feed, Status=reported.
// metadata typically carries {"stixId":..., "connectorName":...} for
// traceability. Returns the iocs.id so the caller (internal/taxii) can
// record it in its own idempotency ledger. Thin wrapper over the same
// upsertIOCFull every other producer (ExtractFromDetectionAlert,
// RegisterGenerated, ImportManual) already calls.
func RegisterFromThreatFeed(ctx context.Context, pool *pgxpool.Pool, t Type, value string, metadata map[string]any) (string, error) {
	return upsertIOCFull(ctx, pool, t, value, SourceThreatFeed, OriginThreatFeed, StatusReported, metadata)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/iocregistry/... -run "TestRegisterFromThreatFeed" -v 2>&1`
Expected: both tests PASS.

- [ ] **Step 6: Run the full `internal/iocregistry` suite**

Run in background: `cd orchestrator && go test ./internal/iocregistry/... -v > <scratchpad>/taxii-task2-iocregistry-test.log 2>&1`
Wait for completion, then read the real log file (not a piped view). Expected: `ok github.com/audspect/bas/internal/iocregistry <N>s`.

- [ ] **Step 7: Commit**

```bash
cd orchestrator
git add internal/iocregistry/types.go internal/iocregistry/threatfeed.go internal/iocregistry/threatfeed_test.go
git commit -m "feat(iocregistry): add SourceThreatFeed/StatusReported + RegisterFromThreatFeed"
git push
```

---

### Task 3: `internal/taxii` — package skeleton + `Store` (TDD)

**Files:**
- Create: `orchestrator/internal/taxii/types.go`
- Create: `orchestrator/internal/taxii/store.go`
- Create: `orchestrator/internal/taxii/store_test.go` (also hosts this package's `TestMain` boilerplate)

**Interfaces:**
- Consumes: `taxii_connector_config`/`taxii_ingested_objects` tables (Task 1).
- Produces: `taxii.ConnectorConfig`, `taxii.PollSummary`, `taxii.Store` with `Create`/`Get`/`List`/`ListEnabled`/`Update`/`Delete`/`RecordPollResult`/`HasIngested`/`RecordIngested` — every later task depends on these exact names/signatures.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/taxii/store_test.go
package taxii

import (
	"context"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func TestCreate_PersistsAndGetRoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		created, err := store.Create(ctx, ConnectorConfig{
			Name: "FS-ISAC Test", ServerURL: "https://taxii.example.org", AuthType: "basic",
			Username: "user1", Password: "secret1", Enabled: true,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if created.ID == "" {
			t.Fatal("Create() returned empty ID")
		}
		if created.LastPollStatus != "never" {
			t.Errorf("LastPollStatus = %q, want \"never\"", created.LastPollStatus)
		}

		got, err := store.Get(ctx, created.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Name != "FS-ISAC Test" || got.ServerURL != "https://taxii.example.org" || got.Password != "secret1" {
			t.Errorf("Get() = %+v, fields don't round-trip", got)
		}
	})
}

func TestGet_NotFound_ReturnsErrNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := NewStore(pool).Get(context.Background(), "does-not-exist")
		if err != ErrNotFound {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})
}

func TestListEnabled_OnlyReturnsEnabledRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		if _, err := store.Create(ctx, ConnectorConfig{Name: "Enabled One", ServerURL: "https://a.example", Enabled: true}); err != nil {
			t.Fatalf("create enabled: %v", err)
		}
		if _, err := store.Create(ctx, ConnectorConfig{Name: "Disabled One", ServerURL: "https://b.example", Enabled: false}); err != nil {
			t.Fatalf("create disabled: %v", err)
		}
		got, err := store.ListEnabled(ctx)
		if err != nil {
			t.Fatalf("ListEnabled: %v", err)
		}
		for _, c := range got {
			if c.Name == "Disabled One" {
				t.Fatal("ListEnabled returned a disabled row")
			}
		}
		found := false
		for _, c := range got {
			if c.Name == "Enabled One" {
				found = true
			}
		}
		if !found {
			t.Fatal("ListEnabled did not return the enabled row")
		}
	})
}

func TestUpdate_KeepsSecretWhenFlagSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		created, err := store.Create(ctx, ConnectorConfig{Name: "Orig", ServerURL: "https://a.example", Password: "orig-secret", Enabled: false})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		updated, err := store.Update(ctx, created.ID, ConnectorConfig{
			Name: "Renamed", ServerURL: "https://a.example", Password: "", Enabled: true,
		}, true, true, true) // keepPassword/keepClientCert/keepClientKey
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		if updated.Name != "Renamed" || !updated.Enabled {
			t.Errorf("Update() = %+v, plain fields not applied", updated)
		}
		if updated.Password != "orig-secret" {
			t.Errorf("Password = %q, want kept value %q", updated.Password, "orig-secret")
		}
	})
}

func TestDelete_RemovesRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		created, err := store.Create(ctx, ConnectorConfig{Name: "ToDelete", ServerURL: "https://a.example"})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := store.Delete(ctx, created.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := store.Get(ctx, created.ID); err != ErrNotFound {
			t.Fatalf("Get after Delete: err = %v, want ErrNotFound", err)
		}
	})
}

func TestRecordPollResult_UpdatesStatusAndSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		created, err := store.Create(ctx, ConnectorConfig{Name: "PollTest", ServerURL: "https://a.example"})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := store.RecordPollResult(ctx, created.ID, "ok", PollSummary{Processed: 3, Skipped: 1, Malformed: 0}, ""); err != nil {
			t.Fatalf("RecordPollResult: %v", err)
		}
		got, err := store.Get(ctx, created.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.LastPollStatus != "ok" || got.LastPollSummary.Processed != 3 || got.LastPollAt == nil {
			t.Errorf("Get() after RecordPollResult = %+v", got)
		}
	})
}

func TestIngestedObjects_HasThenRecordThenHasAgain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		cfg, err := store.Create(ctx, ConnectorConfig{Name: "IdemTest", ServerURL: "https://a.example"})
		if err != nil {
			t.Fatalf("create config: %v", err)
		}
		var iocID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO iocs (type, value, source, origin, status) VALUES ('ip','203.0.113.9','threat_feed','threat-feed','reported') RETURNING id`,
		).Scan(&iocID); err != nil {
			t.Fatalf("seed ioc: %v", err)
		}
		modified := time.Now().UTC().Truncate(time.Second)

		has, err := store.HasIngested(ctx, cfg.ID, "indicator--abc", modified)
		if err != nil {
			t.Fatalf("HasIngested (before): %v", err)
		}
		if has {
			t.Fatal("HasIngested returned true before any RecordIngested call")
		}

		if err := store.RecordIngested(ctx, cfg.ID, "indicator--abc", modified, iocID); err != nil {
			t.Fatalf("RecordIngested: %v", err)
		}

		has, err = store.HasIngested(ctx, cfg.ID, "indicator--abc", modified)
		if err != nil {
			t.Fatalf("HasIngested (after): %v", err)
		}
		if !has {
			t.Fatal("HasIngested returned false after RecordIngested")
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/taxii/... -v 2>&1`
Expected: compile failure (package `taxii` doesn't exist yet).

- [ ] **Step 3: Write `types.go`**

```go
// orchestrator/internal/taxii/types.go
package taxii

import "time"

// ConnectorConfig is one configured TAXII 2.1 server (e.g. FS-ISAC). Unlike
// threat_intel_config's one-row-per-connector-TYPE singleton, this is
// genuinely multi-instance.
type ConnectorConfig struct {
	ID              string
	Name            string
	ServerURL       string
	APIRoot         string // resolved from Discover() on first sync if left blank
	CollectionID    string
	AuthType        string // "none" | "basic"
	Username        string
	Password        string // plaintext at rest, matching threat_intel_config.api_key's precedent
	ClientCert      string // reserved, unused Phase 1
	ClientKey       string // reserved, unused Phase 1
	Enabled         bool
	LastPollAt      *time.Time
	LastPollStatus  string // "never" | "ok" | "error"
	LastPollSummary PollSummary
	LastError       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// PollSummary is one sync cycle's outcome counts.
type PollSummary struct {
	Processed int `json:"processed"` // indicator SDOs successfully written/updated
	Skipped   int `json:"skipped"`   // recognized-but-unsupported (composite pattern, non-indicator SDO type)
	Malformed int `json:"malformed"` // failed to parse as valid STIX
}
```

- [ ] **Step 4: Write `store.go`**

```go
// orchestrator/internal/taxii/store.go
package taxii

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned by Get/Update when the row doesn't exist.
var ErrNotFound = errors.New("taxii connector config not found")

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

const configCols = `id, name, server_url, api_root, collection_id, auth_type, username, password,
	client_cert, client_key, enabled, last_poll_at, last_poll_status, last_poll_summary, last_error,
	created_at, updated_at`

func scanConfig(row interface {
	Scan(dest ...any) error
}) (ConnectorConfig, error) {
	var c ConnectorConfig
	var summaryJSON []byte
	err := row.Scan(&c.ID, &c.Name, &c.ServerURL, &c.APIRoot, &c.CollectionID, &c.AuthType, &c.Username,
		&c.Password, &c.ClientCert, &c.ClientKey, &c.Enabled, &c.LastPollAt, &c.LastPollStatus, &summaryJSON,
		&c.LastError, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return ConnectorConfig{}, err
	}
	_ = json.Unmarshal(summaryJSON, &c.LastPollSummary)
	return c, nil
}

func (s *Store) Create(ctx context.Context, c ConnectorConfig) (ConnectorConfig, error) {
	if c.AuthType == "" {
		c.AuthType = "none"
	}
	row := s.pool.QueryRow(ctx,
		`INSERT INTO taxii_connector_config (name, server_url, api_root, collection_id, auth_type, username, password, client_cert, client_key, enabled)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 RETURNING `+configCols,
		c.Name, c.ServerURL, c.APIRoot, c.CollectionID, c.AuthType, c.Username, c.Password, c.ClientCert, c.ClientKey, c.Enabled)
	return scanConfig(row)
}

func (s *Store) Get(ctx context.Context, id string) (ConnectorConfig, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+configCols+` FROM taxii_connector_config WHERE id = $1`, id)
	c, err := scanConfig(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConnectorConfig{}, ErrNotFound
	}
	return c, err
}

func (s *Store) List(ctx context.Context) ([]ConnectorConfig, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+configCols+` FROM taxii_connector_config ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConnectorConfig
	for rows.Next() {
		c, err := scanConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) ListEnabled(ctx context.Context) ([]ConnectorConfig, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+configCols+` FROM taxii_connector_config WHERE enabled = true ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConnectorConfig
	for rows.Next() {
		c, err := scanConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Update applies every plain field from c, keeping the stored secret value
// for any of password/clientCert/clientKey whose keep* flag is true --
// matching PutThreatIntelConfig's "empty submitted value keeps current"
// convention at the store layer instead of the handler layer, since TAXII
// has three independent secrets instead of MISP/OTX's one.
func (s *Store) Update(ctx context.Context, id string, c ConnectorConfig, keepPassword, keepClientCert, keepClientKey bool) (ConnectorConfig, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE taxii_connector_config SET
		   name = $2, server_url = $3, api_root = $4, collection_id = $5, auth_type = $6, username = $7,
		   password = CASE WHEN $8 THEN password ELSE $9 END,
		   client_cert = CASE WHEN $10 THEN client_cert ELSE $11 END,
		   client_key = CASE WHEN $12 THEN client_key ELSE $13 END,
		   enabled = $14, updated_at = NOW()
		 WHERE id = $1
		 RETURNING `+configCols,
		id, c.Name, c.ServerURL, c.APIRoot, c.CollectionID, c.AuthType, c.Username,
		keepPassword, c.Password, keepClientCert, c.ClientCert, keepClientKey, c.ClientKey, c.Enabled)
	updated, err := scanConfig(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConnectorConfig{}, ErrNotFound
	}
	return updated, err
}

func (s *Store) Delete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM taxii_connector_config WHERE id = $1`, id)
	return err
}

func (s *Store) RecordPollResult(ctx context.Context, id, status string, summary PollSummary, errMsg string) error {
	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE taxii_connector_config SET last_poll_at = NOW(), last_poll_status = $2, last_poll_summary = $3, last_error = $4 WHERE id = $1`,
		id, status, summaryJSON, errMsg)
	return err
}

func (s *Store) HasIngested(ctx context.Context, connectorID, stixID string, modified time.Time) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM taxii_ingested_objects WHERE connector_id = $1 AND stix_id = $2 AND modified = $3)`,
		connectorID, stixID, modified,
	).Scan(&exists)
	return exists, err
}

func (s *Store) RecordIngested(ctx context.Context, connectorID, stixID string, modified time.Time, iocID string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO taxii_ingested_objects (connector_id, stix_id, modified, ioc_id) VALUES ($1,$2,$3,$4)
		 ON CONFLICT (connector_id, stix_id, modified) DO NOTHING`,
		connectorID, stixID, modified, iocID)
	return err
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/taxii/... -v 2>&1`
Expected: all 7 tests PASS.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/taxii/types.go internal/taxii/store.go internal/taxii/store_test.go
git commit -m "feat(taxii): add ConnectorConfig type + Store (Postgres CRUD)"
git push
```

---

### Task 4: `internal/taxii` — TAXII 2.1 HTTP client (TDD)

**Files:**
- Create: `orchestrator/internal/taxii/client.go`
- Test: `orchestrator/internal/taxii/client_test.go`

**Interfaces:**
- Consumes: `ConnectorConfig` (Task 3).
- Produces: `taxii.Client`, `taxii.NewClient(cfg ConnectorConfig) *Client`, `(*Client).Discover(ctx) (Discovery, error)`, `(*Client).ListCollections(ctx, apiRoot string) ([]Collection, error)`, `(*Client).PollObjects(ctx, apiRoot, collectionID string, addedAfter *time.Time, next string) (ObjectsPage, error)`, `taxii.ErrAuthFailed` — Task 7 (Poller) calls `Discover`/`PollObjects` directly.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/taxii/client_test.go
package taxii

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockTAXIIServer is a spec-compliant TAXII 2.1 test double, not a fake
// FS-ISAC -- fixtures represent realistic ISAC content, but the server
// itself only implements the generic TAXII 2.1 surface (discovery, API
// root, collections, paginated objects). See spec's Testing section.
func mockTAXIIServer(t *testing.T, requireBasicAuth bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/taxii2/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
		json.NewEncoder(w).Encode(map[string]any{
			"title": "Mock TAXII Server", "default": r.Host + "/api1", "api_roots": []string{r.Host + "/api1"},
		})
	})
	mux.HandleFunc("/api1/collections/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
		json.NewEncoder(w).Encode(map[string]any{
			"collections": []map[string]any{{"id": "col-1", "title": "Indicators"}},
		})
	})
	mux.HandleFunc("/api1/collections/col-1/objects/", func(w http.ResponseWriter, r *http.Request) {
		if requireBasicAuth {
			u, p, ok := r.BasicAuth()
			if !ok || u != "user1" || p != "secret1" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
		if r.URL.Query().Get("next") == "page2" {
			json.NewEncoder(w).Encode(map[string]any{
				"more": false, "next": "",
				"objects": []map[string]any{{"id": "indicator--2", "type": "indicator", "modified": "2026-01-02T00:00:00Z", "pattern": "[domain-name:value = 'evil2.example.com']", "pattern_type": "stix"}},
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"more": true, "next": "page2",
			"objects": []map[string]any{{"id": "indicator--1", "type": "indicator", "modified": "2026-01-01T00:00:00Z", "pattern": "[ipv4-addr:value = '203.0.113.9']", "pattern_type": "stix"}},
		})
	})
	return httptest.NewServer(mux)
}

func TestDiscover_ReturnsDefaultAPIRoot(t *testing.T) {
	srv := mockTAXIIServer(t, false)
	defer srv.Close()
	c := NewClient(ConnectorConfig{ServerURL: srv.URL, AuthType: "none"})
	d, err := c.Discover(t.Context())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if d.DefaultAPIRoot == "" {
		t.Fatal("expected a non-empty DefaultAPIRoot")
	}
}

func TestListCollections_ReturnsCollections(t *testing.T) {
	srv := mockTAXIIServer(t, false)
	defer srv.Close()
	c := NewClient(ConnectorConfig{ServerURL: srv.URL, AuthType: "none"})
	cols, err := c.ListCollections(t.Context(), srv.URL+"/api1")
	if err != nil {
		t.Fatalf("ListCollections: %v", err)
	}
	if len(cols) != 1 || cols[0].ID != "col-1" {
		t.Fatalf("ListCollections() = %+v", cols)
	}
}

func TestPollObjects_PaginatesAcrossTwoPages(t *testing.T) {
	srv := mockTAXIIServer(t, false)
	defer srv.Close()
	c := NewClient(ConnectorConfig{ServerURL: srv.URL, AuthType: "none"})
	page1, err := c.PollObjects(t.Context(), srv.URL+"/api1", "col-1", nil, "")
	if err != nil {
		t.Fatalf("PollObjects page1: %v", err)
	}
	if len(page1.Objects) != 1 || !page1.More || page1.Next != "page2" {
		t.Fatalf("page1 = %+v", page1)
	}
	page2, err := c.PollObjects(t.Context(), srv.URL+"/api1", "col-1", nil, page1.Next)
	if err != nil {
		t.Fatalf("PollObjects page2: %v", err)
	}
	if len(page2.Objects) != 1 || page2.More {
		t.Fatalf("page2 = %+v", page2)
	}
}

func TestPollObjects_BasicAuthSucceeds(t *testing.T) {
	srv := mockTAXIIServer(t, true)
	defer srv.Close()
	c := NewClient(ConnectorConfig{ServerURL: srv.URL, AuthType: "basic", Username: "user1", Password: "secret1"})
	page, err := c.PollObjects(t.Context(), srv.URL+"/api1", "col-1", nil, "")
	if err != nil {
		t.Fatalf("PollObjects with correct basic auth: %v", err)
	}
	if len(page.Objects) != 1 {
		t.Fatalf("page = %+v", page)
	}
}

func TestPollObjects_AuthFailureReturnsErrAuthFailed(t *testing.T) {
	srv := mockTAXIIServer(t, true)
	defer srv.Close()
	c := NewClient(ConnectorConfig{ServerURL: srv.URL, AuthType: "basic", Username: "wrong", Password: "wrong"})
	_, err := c.PollObjects(t.Context(), srv.URL+"/api1", "col-1", nil, "")
	var authErr *ErrAuthFailed
	if err == nil {
		t.Fatal("expected an error for bad credentials")
	}
	if ae, ok := err.(*ErrAuthFailed); !ok {
		t.Fatalf("err = %T (%v), want *ErrAuthFailed", err, err)
	} else {
		authErr = ae
	}
	if authErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want 401", authErr.StatusCode)
	}
}

func TestPollObjects_HTTPErrorSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()
	c := NewClient(ConnectorConfig{ServerURL: srv.URL, AuthType: "none"})
	_, err := c.PollObjects(t.Context(), srv.URL+"/api1", "col-1", nil, "")
	if err == nil {
		t.Fatal("expected an error for HTTP 500")
	}
}

func TestPollObjects_AddedAfterSentAsQueryParam(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
		json.NewEncoder(w).Encode(map[string]any{"more": false, "next": "", "objects": []map[string]any{}})
	}))
	defer srv.Close()
	c := NewClient(ConnectorConfig{ServerURL: srv.URL, AuthType: "none"})
	when := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := c.PollObjects(t.Context(), srv.URL+"/api1", "col-1", &when, ""); err != nil {
		t.Fatalf("PollObjects: %v", err)
	}
	if gotQuery == "" {
		t.Fatal("expected added_after to be sent as a query param")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/taxii/... -run "TestDiscover|TestListCollections|TestPollObjects" -v 2>&1`
Expected: compile failure (`NewClient`/`Client`/etc. undefined).

- [ ] **Step 3: Write `client.go`**

```go
// orchestrator/internal/taxii/client.go
package taxii

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const mediaType = "application/taxii+json;version=2.1"

// Client speaks the TAXII 2.1 Collections API (discovery -> API root ->
// collections -> paginated objects). Skips TLS verification for self-signed
// certs, matching MISPClient's existing precedent for on-prem/air-gapped
// deployments.
type Client struct {
	cfg        ConnectorConfig
	httpClient *http.Client
}

func NewClient(cfg ConnectorConfig) *Client {
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
	}
}

type Discovery struct {
	Title          string   `json:"title"`
	DefaultAPIRoot string   `json:"default"`
	APIRoots       []string `json:"api_roots"`
}

type Collection struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type collectionsResponse struct {
	Collections []Collection `json:"collections"`
}

// ObjectsPage is one page of a TAXII 2.1 "objects" envelope response:
// {"more": bool, "next": "opaque-cursor", "objects": [...]}.
type ObjectsPage struct {
	Objects []json.RawMessage
	More    bool
	Next    string
}

type objectsEnvelope struct {
	More    bool              `json:"more"`
	Next    string            `json:"next"`
	Objects []json.RawMessage `json:"objects"`
}

// ErrAuthFailed is returned for HTTP 401/403 responses.
type ErrAuthFailed struct{ StatusCode int }

func (e *ErrAuthFailed) Error() string {
	return fmt.Sprintf("taxii auth failed (HTTP %d)", e.StatusCode)
}

func (c *Client) do(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", mediaType)
	if c.cfg.AuthType == "basic" {
		auth := base64.StdEncoding.EncodeToString([]byte(c.cfg.Username + ":" + c.cfg.Password))
		req.Header.Set("Authorization", "Basic "+auth)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		resp.Body.Close()
		return nil, &ErrAuthFailed{StatusCode: resp.StatusCode}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("taxii server returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	return resp, nil
}

// Discover fetches the server's discovery document (GET {server_url}/taxii2/).
func (c *Client) Discover(ctx context.Context) (Discovery, error) {
	resp, err := c.do(ctx, strings.TrimRight(c.cfg.ServerURL, "/")+"/taxii2/")
	if err != nil {
		return Discovery{}, err
	}
	defer resp.Body.Close()
	var d Discovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return Discovery{}, fmt.Errorf("decode discovery response: %w", err)
	}
	return d, nil
}

// ListCollections fetches the collections available under an API root.
func (c *Client) ListCollections(ctx context.Context, apiRoot string) ([]Collection, error) {
	resp, err := c.do(ctx, strings.TrimRight(apiRoot, "/")+"/collections/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var cr collectionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, fmt.Errorf("decode collections response: %w", err)
	}
	return cr.Collections, nil
}

// PollObjects fetches one page of a collection's objects. addedAfter
// (nil-able) does incremental polling; next carries the previous page's
// pagination cursor ("" for the first page).
func (c *Client) PollObjects(ctx context.Context, apiRoot, collectionID string, addedAfter *time.Time, next string) (ObjectsPage, error) {
	u := strings.TrimRight(apiRoot, "/") + "/collections/" + collectionID + "/objects/"
	var params []string
	if addedAfter != nil {
		params = append(params, "added_after="+addedAfter.UTC().Format(time.RFC3339))
	}
	if next != "" {
		params = append(params, "next="+next)
	}
	if len(params) > 0 {
		u += "?" + strings.Join(params, "&")
	}
	resp, err := c.do(ctx, u)
	if err != nil {
		return ObjectsPage{}, err
	}
	defer resp.Body.Close()
	var env objectsEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return ObjectsPage{}, fmt.Errorf("decode objects response: %w", err)
	}
	return ObjectsPage{Objects: env.Objects, More: env.More, Next: env.Next}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/taxii/... -run "TestDiscover|TestListCollections|TestPollObjects" -v 2>&1`
Expected: all 7 tests PASS. (`go.mod` floor is Go 1.26, so `t.Context()` is safe to use as-is.)

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/taxii/client.go internal/taxii/client_test.go
git commit -m "feat(taxii): add TAXII 2.1 HTTP client (discovery, collections, paginated polling)"
git push
```

---

### Task 5: `internal/taxii` — STIX object + pattern parser (TDD)

**Files:**
- Create: `orchestrator/internal/taxii/stix.go`
- Test: `orchestrator/internal/taxii/stix_test.go`

**Interfaces:**
- Consumes: `iocregistry.Type` consts (`TypeIP`, `TypeDomain`, `TypeURL`, `TypeFileHash`).
- Produces: `taxii.ParseObject(raw json.RawMessage) (stixEnvelope, error)` (unexported return type — Task 6 lives in the same package so this is fine), `taxii.ParsePattern(pattern string) (t iocregistry.Type, value string, ok bool)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/taxii/stix_test.go
package taxii

import (
	"encoding/json"
	"testing"

	"github.com/audspect/bas/internal/iocregistry"
)

func TestParseObject_ValidIndicator(t *testing.T) {
	raw := json.RawMessage(`{"id":"indicator--abc","type":"indicator","modified":"2026-01-01T00:00:00Z","pattern":"[ipv4-addr:value = '203.0.113.9']","pattern_type":"stix"}`)
	env, err := ParseObject(raw)
	if err != nil {
		t.Fatalf("ParseObject: %v", err)
	}
	if env.ID != "indicator--abc" || env.Type != "indicator" {
		t.Errorf("ParseObject() = %+v", env)
	}
}

func TestParseObject_MalformedJSON(t *testing.T) {
	_, err := ParseObject(json.RawMessage(`{not valid json`))
	if err == nil {
		t.Fatal("expected an error for malformed JSON")
	}
}

func TestParseObject_MissingIDOrType(t *testing.T) {
	_, err := ParseObject(json.RawMessage(`{"modified":"2026-01-01T00:00:00Z"}`))
	if err == nil {
		t.Fatal("expected an error for a STIX object missing id/type")
	}
}

func TestParsePattern_RecognizedForms(t *testing.T) {
	cases := []struct {
		pattern   string
		wantType  iocregistry.Type
		wantValue string
	}{
		{"[ipv4-addr:value = '203.0.113.9']", iocregistry.TypeIP, "203.0.113.9"},
		{"[ipv6-addr:value = '2001:db8::1']", iocregistry.TypeIP, "2001:db8::1"},
		{"[domain-name:value = 'evil.example.com']", iocregistry.TypeDomain, "evil.example.com"},
		{"[url:value = 'http://evil.example.com/payload']", iocregistry.TypeURL, "http://evil.example.com/payload"},
		{"[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']", iocregistry.TypeFileHash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"[file:hashes.'MD5' = '5d41402abc4b2a76b9719d911017c592']", iocregistry.TypeFileHash, "5d41402abc4b2a76b9719d911017c592"},
	}
	for _, tc := range cases {
		gotType, gotValue, ok := ParsePattern(tc.pattern)
		if !ok {
			t.Errorf("ParsePattern(%q) ok = false, want true", tc.pattern)
			continue
		}
		if gotType != tc.wantType || gotValue != tc.wantValue {
			t.Errorf("ParsePattern(%q) = (%q, %q), want (%q, %q)", tc.pattern, gotType, gotValue, tc.wantType, tc.wantValue)
		}
	}
}

func TestParsePattern_CompositePatternRejected(t *testing.T) {
	_, _, ok := ParsePattern("[ipv4-addr:value = '203.0.113.9' AND domain-name:value = 'evil.example.com']")
	if ok {
		t.Error("expected ok=false for a composite/boolean pattern")
	}
}

func TestParsePattern_UnrecognizedObservableRejected(t *testing.T) {
	_, _, ok := ParsePattern("[windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\\\Software\\\\Evil']")
	if ok {
		t.Error("expected ok=false for an unrecognized observable type")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/taxii/... -run "TestParseObject|TestParsePattern" -v 2>&1`
Expected: compile failure (`ParseObject`/`ParsePattern` undefined).

- [ ] **Step 3: Write `stix.go`**

```go
// orchestrator/internal/taxii/stix.go
package taxii

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/audspect/bas/internal/iocregistry"
)

// stixEnvelope is a minimal, deliberately partial STIX 2.1 SDO shape --
// enough to route and parse an `indicator`, without a full STIX type
// hierarchy Phase 1 doesn't need (YAGNI: Phase 2/3 add more fields/types
// when they route threat-actor/campaign/malware/tool SDOs).
type stixEnvelope struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Modified    string `json:"modified"`
	Pattern     string `json:"pattern"`
	PatternType string `json:"pattern_type"`
}

// ParseObject unmarshals one raw SDO into its typed envelope. Returns an
// error only for invalid JSON or a missing id/type -- an unrecognized
// `type` or `pattern_type` value is a valid parse result the caller
// (Task 6's Normalizer) routes as "skipped", never a parse error.
func ParseObject(raw json.RawMessage) (stixEnvelope, error) {
	var env stixEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return stixEnvelope{}, fmt.Errorf("unmarshal STIX object: %w", err)
	}
	if env.ID == "" || env.Type == "" {
		return stixEnvelope{}, fmt.Errorf("STIX object missing id/type")
	}
	return env, nil
}

// simplePatternRE matches exactly one bracketed single-comparison STIX
// pattern, e.g. "[ipv4-addr:value = '203.0.113.9']". Composite/boolean
// patterns (AND/OR, multiple bracket groups) never match this regex and
// so are never partially parsed.
var simplePatternRE = regexp.MustCompile(`^\[([a-zA-Z0-9\-]+):([a-zA-Z0-9_.'"-]+)\s*=\s*'([^']*)'\]$`)

// ParsePattern extracts (Type, value) from a single-comparison STIX
// pattern. ok=false for composite/boolean patterns or unrecognized
// observable paths -- the caller treats that as "skipped", never a
// partial match. Covers exactly the observable/property combinations
// named in the Phase 1 spec: ipv4-addr/ipv6-addr:value, domain-name:value,
// url:value, file:hashes.'SHA-256'|'MD5'|'SHA-1'.
func ParsePattern(pattern string) (t iocregistry.Type, value string, ok bool) {
	m := simplePatternRE.FindStringSubmatch(pattern)
	if m == nil {
		return "", "", false
	}
	object, path, val := m[1], m[2], m[3]
	switch {
	case object == "ipv4-addr" && path == "value":
		return iocregistry.TypeIP, val, true
	case object == "ipv6-addr" && path == "value":
		return iocregistry.TypeIP, val, true
	case object == "domain-name" && path == "value":
		return iocregistry.TypeDomain, val, true
	case object == "url" && path == "value":
		return iocregistry.TypeURL, val, true
	case object == "file" && (path == "hashes.'SHA-256'" || path == "hashes.'MD5'" || path == "hashes.'SHA-1'"):
		return iocregistry.TypeFileHash, val, true
	default:
		return "", "", false
	}
}
```

Note: the regex's `path` capture group excludes the single quotes around `SHA-256`/`MD5`/`SHA-1` from being swallowed by the value group, because `'` is included in the path character class `[a-zA-Z0-9_.'"-]+`. Verify this with the `file:hashes.'SHA-256'` test case specifically — if the regex greedily captures wrong, adjust the character class rather than special-casing the file-hash form separately.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/taxii/... -run "TestParseObject|TestParsePattern" -v 2>&1`
Expected: all 8 tests PASS. If `TestParsePattern_RecognizedForms`'s file-hash cases fail due to the regex capturing the path group incorrectly, debug with a standalone `go run` snippet printing `simplePatternRE.FindStringSubmatch(...)` for that exact input before adjusting the regex — don't guess-and-retry blindly.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/taxii/stix.go internal/taxii/stix_test.go
git commit -m "feat(taxii): add STIX object + single-comparison pattern parser"
git push
```

---

### Task 6: `internal/taxii` — Normalizer (TDD)

**Files:**
- Create: `orchestrator/internal/taxii/normalize.go`
- Test: `orchestrator/internal/taxii/normalize_test.go`

**Interfaces:**
- Consumes: `ParseObject`/`ParsePattern` (Task 5), `Store.HasIngested`/`RecordIngested` (Task 3), `iocregistry.RegisterFromThreatFeed` (Task 2).
- Produces: `taxii.Normalizer`, `taxii.NewNormalizer(pool *pgxpool.Pool, store *Store) *Normalizer`, `(*Normalizer).Ingest(ctx, connectorID, connectorName string, objects []json.RawMessage) (PollSummary, error)` — Task 7 (Poller) calls `Ingest` once per polled page.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/taxii/normalize_test.go
package taxii

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIngest_ProcessesValidIndicator(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		cfg, err := store.Create(ctx, ConnectorConfig{Name: "IngestTest", ServerURL: "https://a.example"})
		if err != nil {
			t.Fatalf("create config: %v", err)
		}
		n := NewNormalizer(pool, store)
		objects := []json.RawMessage{
			json.RawMessage(`{"id":"indicator--1","type":"indicator","modified":"2026-01-01T00:00:00Z","pattern":"[ipv4-addr:value = '203.0.113.9']","pattern_type":"stix"}`),
		}
		sum, err := n.Ingest(ctx, cfg.ID, cfg.Name, objects)
		if err != nil {
			t.Fatalf("Ingest: %v", err)
		}
		if sum.Processed != 1 || sum.Skipped != 0 || sum.Malformed != 0 {
			t.Fatalf("Ingest() summary = %+v", sum)
		}
		var count int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM iocs WHERE type='ip' AND value='203.0.113.9'`).Scan(&count); err != nil {
			t.Fatalf("query iocs: %v", err)
		}
		if count != 1 {
			t.Fatalf("expected exactly 1 ioc row, got %d", count)
		}
	})
}

func TestIngest_SkipsNonIndicatorAndCompositePattern(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		cfg, err := store.Create(ctx, ConnectorConfig{Name: "SkipTest", ServerURL: "https://a.example"})
		if err != nil {
			t.Fatalf("create config: %v", err)
		}
		n := NewNormalizer(pool, store)
		objects := []json.RawMessage{
			json.RawMessage(`{"id":"malware--1","type":"malware","modified":"2026-01-01T00:00:00Z"}`),
			json.RawMessage(`{"id":"indicator--2","type":"indicator","modified":"2026-01-01T00:00:00Z","pattern":"[ipv4-addr:value = '1.2.3.4' AND domain-name:value = 'x.example']","pattern_type":"stix"}`),
		}
		sum, err := n.Ingest(ctx, cfg.ID, cfg.Name, objects)
		if err != nil {
			t.Fatalf("Ingest: %v", err)
		}
		if sum.Skipped != 2 || sum.Processed != 0 {
			t.Fatalf("Ingest() summary = %+v, want Skipped=2 Processed=0", sum)
		}
	})
}

func TestIngest_MalformedJSONCounted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		cfg, err := store.Create(ctx, ConnectorConfig{Name: "MalformedTest", ServerURL: "https://a.example"})
		if err != nil {
			t.Fatalf("create config: %v", err)
		}
		n := NewNormalizer(pool, store)
		objects := []json.RawMessage{json.RawMessage(`{not valid`)}
		sum, err := n.Ingest(ctx, cfg.ID, cfg.Name, objects)
		if err != nil {
			t.Fatalf("Ingest: %v", err)
		}
		if sum.Malformed != 1 {
			t.Fatalf("Ingest() summary = %+v, want Malformed=1", sum)
		}
	})
}

func TestIngest_IdempotentOnRepeatedIdenticalObject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		cfg, err := store.Create(ctx, ConnectorConfig{Name: "IdemIngestTest", ServerURL: "https://a.example"})
		if err != nil {
			t.Fatalf("create config: %v", err)
		}
		n := NewNormalizer(pool, store)
		objects := []json.RawMessage{
			json.RawMessage(`{"id":"indicator--dup","type":"indicator","modified":"2026-01-01T00:00:00Z","pattern":"[domain-name:value = 'dup.example.com']","pattern_type":"stix"}`),
		}
		sum1, err := n.Ingest(ctx, cfg.ID, cfg.Name, objects)
		if err != nil {
			t.Fatalf("first Ingest: %v", err)
		}
		if sum1.Processed != 1 {
			t.Fatalf("first Ingest() = %+v, want Processed=1", sum1)
		}
		sum2, err := n.Ingest(ctx, cfg.ID, cfg.Name, objects)
		if err != nil {
			t.Fatalf("second Ingest: %v", err)
		}
		if sum2.Processed != 0 || sum2.Skipped != 0 || sum2.Malformed != 0 {
			t.Fatalf("second Ingest() = %+v, want all zero (already ingested)", sum2)
		}
		var count int
		if err := pool.QueryRow(ctx, `SELECT sighting_count FROM iocs WHERE type='domain' AND value='dup.example.com'`).Scan(&count); err != nil {
			t.Fatalf("query sighting_count: %v", err)
		}
		if count != 1 {
			t.Fatalf("sighting_count = %d, want 1 (second call was a true no-op, not a re-upsert)", count)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/taxii/... -run "TestIngest" -v 2>&1`
Expected: compile failure (`Normalizer`/`NewNormalizer` undefined).

- [ ] **Step 3: Write `normalize.go`**

```go
// orchestrator/internal/taxii/normalize.go
package taxii

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/iocregistry"
)

// Normalizer routes each polled STIX object by type. Phase 1 only wires the
// `indicator` branch through to iocregistry -- Phase 2/3 add branches here
// for threat-actor/intrusion-set/campaign/malware/tool without touching
// this shape.
type Normalizer struct {
	pool  *pgxpool.Pool
	store *Store
}

func NewNormalizer(pool *pgxpool.Pool, store *Store) *Normalizer {
	return &Normalizer{pool: pool, store: store}
}

// Ingest processes one page of raw objects for the given connector. Never
// returns an error for per-object problems (malformed/unsupported) -- those
// are counted in the returned PollSummary, never propagated. Only a hard
// infrastructure failure (DB unreachable) returns a non-nil error.
func (n *Normalizer) Ingest(ctx context.Context, connectorID, connectorName string, objects []json.RawMessage) (PollSummary, error) {
	var sum PollSummary
	for _, raw := range objects {
		env, err := ParseObject(raw)
		if err != nil {
			sum.Malformed++
			continue
		}
		if env.Type != "indicator" || env.PatternType != "stix" {
			sum.Skipped++
			continue
		}
		modified, err := time.Parse(time.RFC3339Nano, env.Modified)
		if err != nil {
			sum.Malformed++
			continue
		}
		already, err := n.store.HasIngested(ctx, connectorID, env.ID, modified)
		if err != nil {
			return sum, err
		}
		if already {
			continue // already-seen exact version -- not processed, not skipped, not malformed
		}
		iocType, value, ok := ParsePattern(env.Pattern)
		if !ok {
			sum.Skipped++
			continue
		}
		iocID, err := iocregistry.RegisterFromThreatFeed(ctx, n.pool, iocType, value, map[string]any{
			"stixId": env.ID, "connectorName": connectorName,
		})
		if err != nil {
			log.Printf("[taxii] register indicator failed for connector %s: %v", connectorID, err)
			sum.Malformed++
			continue
		}
		if err := n.store.RecordIngested(ctx, connectorID, env.ID, modified, iocID); err != nil {
			log.Printf("[taxii] record ingested failed for connector %s: %v", connectorID, err)
		}
		sum.Processed++
	}
	return sum, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/taxii/... -run "TestIngest" -v 2>&1`
Expected: all 4 tests PASS.

- [ ] **Step 5: Run the full `internal/taxii` suite so far**

Run in background: `cd orchestrator && go test ./internal/taxii/... -v > <scratchpad>/taxii-task6-suite-test.log 2>&1`
Wait for completion, read the real log file. Expected: `ok github.com/audspect/bas/internal/taxii <N>s`.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/taxii/normalize.go internal/taxii/normalize_test.go
git commit -m "feat(taxii): add Normalizer (indicator routing + idempotent ingestion)"
git push
```

---

### Task 7: `internal/taxii` — Poller + Manager (TDD)

**Files:**
- Create: `orchestrator/internal/taxii/poller.go`
- Create: `orchestrator/internal/taxii/manager.go`
- Test: `orchestrator/internal/taxii/poller_test.go`
- Test: `orchestrator/internal/taxii/manager_test.go`

**Interfaces:**
- Consumes: `Client` (Task 4), `Normalizer` (Task 6), `Store` (Task 3), `exercise.NewPollScheduler(interval time.Duration) *exercise.PollScheduler` with `.Start(func(ctx context.Context))`/`.Stop()` (existing, `internal/exercise/scheduler.go`).
- Produces: `taxii.Poller`, `taxii.NewPoller(cfg ConnectorConfig, store *Store, normalizer *Normalizer) *Poller`, `(*Poller).Sync(ctx) error`; `taxii.Manager`, `taxii.NewManager(pool *pgxpool.Pool, store *Store) *Manager`, `(*Manager).Start(ctx) error`, `(*Manager).Reconcile(ctx) error`, `(*Manager).TriggerSync(ctx, connectorID string) error`, `(*Manager).Stop()` — Task 8 (HTTP handlers) calls `Reconcile`/`TriggerSync`; Task 9 (main.go) calls `Start`/`Stop`.

- [ ] **Step 1: Write the failing Poller test**

```go
// orchestrator/internal/taxii/poller_test.go
package taxii

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPollerSync_DiscoversPollsNormalizesAndRecordsResult(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mux := http.NewServeMux()
		mux.HandleFunc("/taxii2/", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"default": "http://" + r.Host + "/api1", "api_roots": []string{"http://" + r.Host + "/api1"}})
		})
		mux.HandleFunc("/api1/collections/col-1/objects/", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"more": false, "next": "",
				"objects": []map[string]any{{"id": "indicator--poller-1", "type": "indicator", "modified": "2026-01-01T00:00:00Z", "pattern": "[ipv4-addr:value = '198.51.100.5']", "pattern_type": "stix"}},
			})
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		ctx := context.Background()
		store := NewStore(pool)
		cfg, err := store.Create(ctx, ConnectorConfig{Name: "PollerTest", ServerURL: srv.URL, CollectionID: "col-1", Enabled: true})
		if err != nil {
			t.Fatalf("create config: %v", err)
		}
		normalizer := NewNormalizer(pool, store)
		poller := NewPoller(cfg, store, normalizer)

		if err := poller.Sync(ctx); err != nil {
			t.Fatalf("Sync: %v", err)
		}

		got, err := store.Get(ctx, cfg.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.LastPollStatus != "ok" || got.LastPollSummary.Processed != 1 || got.LastPollAt == nil {
			t.Fatalf("Get() after Sync = %+v", got)
		}
		var count int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM iocs WHERE type='ip' AND value='198.51.100.5'`).Scan(&count); err != nil {
			t.Fatalf("query iocs: %v", err)
		}
		if count != 1 {
			t.Fatalf("expected 1 ioc row, got %d", count)
		}
	})
}

func TestPollerSync_RecordsErrorOnUnreachableServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		cfg, err := store.Create(ctx, ConnectorConfig{Name: "UnreachableTest", ServerURL: "http://127.0.0.1:1", CollectionID: "col-1", Enabled: true})
		if err != nil {
			t.Fatalf("create config: %v", err)
		}
		poller := NewPoller(cfg, store, NewNormalizer(pool, store))
		if err := poller.Sync(ctx); err == nil {
			t.Fatal("expected an error for an unreachable server")
		}
		got, err := store.Get(ctx, cfg.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.LastPollStatus != "error" || got.LastError == "" {
			t.Fatalf("Get() after failed Sync = %+v", got)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/taxii/... -run "TestPollerSync" -v 2>&1`
Expected: compile failure (`NewPoller`/`Poller` undefined).

- [ ] **Step 3: Write `poller.go`**

```go
// orchestrator/internal/taxii/poller.go
package taxii

import (
	"context"
)

// Poller runs one full discover-if-needed + paginated-poll + normalize
// cycle for a single ConnectorConfig. Unlike vexsweep/emsweep's Dispatcher
// (which advances a long-running dispatched task one step per tick across
// many ticks), a TAXII sync is a single self-contained round trip -- there
// is no external in-flight task to babysit across ticks, so Sync does
// everything in one call.
type Poller struct {
	cfg        ConnectorConfig
	client     *Client
	store      *Store
	normalizer *Normalizer
}

func NewPoller(cfg ConnectorConfig, store *Store, normalizer *Normalizer) *Poller {
	return &Poller{cfg: cfg, client: NewClient(cfg), store: store, normalizer: normalizer}
}

// Sync discovers the API root (if not already configured), polls every
// page of the configured collection since the last successful poll, feeds
// each page to the Normalizer, and records the aggregate result on the
// config row.
func (p *Poller) Sync(ctx context.Context) error {
	apiRoot := p.cfg.APIRoot
	if apiRoot == "" {
		disc, err := p.client.Discover(ctx)
		if err != nil {
			p.store.RecordPollResult(ctx, p.cfg.ID, "error", PollSummary{}, err.Error())
			return err
		}
		apiRoot = disc.DefaultAPIRoot
	}

	var total PollSummary
	next := ""
	for {
		page, err := p.client.PollObjects(ctx, apiRoot, p.cfg.CollectionID, p.cfg.LastPollAt, next)
		if err != nil {
			p.store.RecordPollResult(ctx, p.cfg.ID, "error", total, err.Error())
			return err
		}
		sum, err := p.normalizer.Ingest(ctx, p.cfg.ID, p.cfg.Name, page.Objects)
		if err != nil {
			p.store.RecordPollResult(ctx, p.cfg.ID, "error", total, err.Error())
			return err
		}
		total.Processed += sum.Processed
		total.Skipped += sum.Skipped
		total.Malformed += sum.Malformed
		if !page.More || page.Next == "" {
			break
		}
		next = page.Next
	}
	return p.store.RecordPollResult(ctx, p.cfg.ID, "ok", total, "")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/taxii/... -run "TestPollerSync" -v 2>&1`
Expected: both tests PASS.

- [ ] **Step 5: Write the failing Manager test**

```go
// orchestrator/internal/taxii/manager_test.go
package taxii

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestManagerStart_LaunchesOneSchedulerPerEnabledConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		if _, err := store.Create(ctx, ConnectorConfig{Name: "MgrEnabled", ServerURL: "http://127.0.0.1:1", Enabled: true}); err != nil {
			t.Fatalf("create enabled: %v", err)
		}
		if _, err := store.Create(ctx, ConnectorConfig{Name: "MgrDisabled", ServerURL: "http://127.0.0.1:1", Enabled: false}); err != nil {
			t.Fatalf("create disabled: %v", err)
		}
		m := NewManager(pool, store)
		if err := m.Start(ctx); err != nil {
			t.Fatalf("Start: %v", err)
		}
		defer m.Stop()
		m.mu.Lock()
		n := len(m.schedulers)
		m.mu.Unlock()
		if n != 1 {
			t.Fatalf("running scheduler count = %d, want 1 (only the enabled config)", n)
		}
	})
}

func TestManagerReconcile_StopsRemovedAndStartsNewlyEnabled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		m := NewManager(pool, store)
		if err := m.Start(ctx); err != nil {
			t.Fatalf("Start: %v", err)
		}
		defer m.Stop()
		m.mu.Lock()
		n0 := len(m.schedulers)
		m.mu.Unlock()
		if n0 != 0 {
			t.Fatalf("expected 0 schedulers with no configs yet, got %d", n0)
		}

		cfg, err := store.Create(ctx, ConnectorConfig{Name: "NewlyEnabled", ServerURL: "http://127.0.0.1:1", Enabled: true})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := m.Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		m.mu.Lock()
		n1 := len(m.schedulers)
		m.mu.Unlock()
		if n1 != 1 {
			t.Fatalf("expected 1 scheduler after Reconcile with a new enabled config, got %d", n1)
		}

		if err := store.Delete(ctx, cfg.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if err := m.Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile after delete: %v", err)
		}
		m.mu.Lock()
		n2 := len(m.schedulers)
		m.mu.Unlock()
		if n2 != 0 {
			t.Fatalf("expected 0 schedulers after deleting the only config, got %d", n2)
		}
	})
}

func TestManagerTriggerSync_RunsOneSyncForOneConnector(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		cfg, err := store.Create(ctx, ConnectorConfig{Name: "TriggerTest", ServerURL: "http://127.0.0.1:1", Enabled: false})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		m := NewManager(pool, store)
		_ = m.TriggerSync(ctx, cfg.ID) // expected to error (unreachable server) -- we're only checking it recorded a result, not that it succeeded
		got, err := store.Get(ctx, cfg.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.LastPollAt == nil {
			t.Fatal("TriggerSync did not record a poll attempt")
		}
	})
	_ = time.Second // keep time imported if unused elsewhere in this file after edits
}
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/taxii/... -run "TestManager" -v 2>&1`
Expected: compile failure (`NewManager`/`Manager` undefined).

- [ ] **Step 7: Write `manager.go`**

```go
// orchestrator/internal/taxii/manager.go
package taxii

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/exercise"
)

const defaultPollInterval = 24 * time.Hour

// Manager owns one Poller + one exercise.PollScheduler per currently-enabled
// ConnectorConfig row. Deliberately separate from internal/connector.Scheduler
// (see spec's Sync wiring section) -- TAXII configs are independently
// enabled/disabled/deleted at runtime, which a single shared Source-list
// scheduler doesn't model.
type Manager struct {
	pool       *pgxpool.Pool
	store      *Store
	normalizer *Normalizer

	mu         sync.Mutex
	schedulers map[string]*exercise.PollScheduler // connector id -> its scheduler
}

func NewManager(pool *pgxpool.Pool, store *Store) *Manager {
	return &Manager{
		pool: pool, store: store, normalizer: NewNormalizer(pool, store),
		schedulers: map[string]*exercise.PollScheduler{},
	}
}

// Start launches one scheduler per currently-enabled config row. Each
// scheduler fires an immediate Sync in a goroutine on start (matching
// connector.Scheduler.Start's "run immediately on startup" precedent) --
// exercise.PollScheduler.Start itself only fires after a full interval
// elapses, which would otherwise mean a 24h wait before a freshly-enabled
// connector's first sync.
func (m *Manager) Start(ctx context.Context) error {
	cfgs, err := m.store.ListEnabled(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, cfg := range cfgs {
		m.startLocked(cfg)
	}
	return nil
}

func (m *Manager) startLocked(cfg ConnectorConfig) {
	poller := NewPoller(cfg, m.store, m.normalizer)
	sched := exercise.NewPollScheduler(defaultPollInterval)
	sched.Start(func(ctx context.Context) {
		if err := poller.Sync(ctx); err != nil {
			log.Printf("[taxii] sync failed for connector %s (%s): %v", cfg.ID, cfg.Name, err)
		}
	})
	m.schedulers[cfg.ID] = sched
	go func() {
		if err := poller.Sync(context.Background()); err != nil {
			log.Printf("[taxii] initial sync failed for connector %s (%s): %v", cfg.ID, cfg.Name, err)
		}
	}()
}

// Reconcile fully restarts the running scheduler set to match current DB
// state -- called after every config create/update/delete/enable-toggle.
// A full stop-and-restart (rather than a diff-and-patch) is deliberately
// simple: it's the only way to guarantee an edited server_url/credentials
// change takes effect immediately rather than waiting inside a stale
// closure until the next natural restart, and this only runs on rare admin
// actions, not a hot path.
func (m *Manager) Reconcile(ctx context.Context) error {
	cfgs, err := m.store.ListEnabled(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, sched := range m.schedulers {
		sched.Stop()
		delete(m.schedulers, id)
	}
	for _, cfg := range cfgs {
		m.startLocked(cfg)
	}
	return nil
}

// TriggerSync runs one immediate Sync for a single connector, outside its
// regular interval -- used by the manual "Sync Now" API. Works even for a
// disabled connector (an admin validating before enabling).
func (m *Manager) TriggerSync(ctx context.Context, connectorID string) error {
	cfg, err := m.store.Get(ctx, connectorID)
	if err != nil {
		return err
	}
	poller := NewPoller(cfg, m.store, m.normalizer)
	return poller.Sync(ctx)
}

// Stop shuts down every running scheduler.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sched := range m.schedulers {
		sched.Stop()
	}
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/taxii/... -run "TestManager" -v 2>&1`
Expected: all 3 tests PASS. (`TestManagerStart_LaunchesOneSchedulerPerEnabledConfig` and `TestManagerReconcile_...` read `m.schedulers`/`m.mu` directly since they're in the same package -- this is intentional, white-box testing of internal state, matching this session's own `emsweep`/`vexsweep` dispatcher test conventions.)

- [ ] **Step 9: Run the full `internal/taxii` suite**

Run in background: `cd orchestrator && go test ./internal/taxii/... -v > <scratchpad>/taxii-task7-suite-test.log 2>&1`
Wait for completion, read the real log file. Expected: `ok github.com/audspect/bas/internal/taxii <N>s`, every test from Tasks 3-7 present and passing.

- [ ] **Step 10: Commit**

```bash
cd orchestrator
git add internal/taxii/poller.go internal/taxii/poller_test.go internal/taxii/manager.go internal/taxii/manager_test.go
git commit -m "feat(taxii): add Poller (single-cycle sync) + Manager (per-connector scheduling)"
git push
```

---

### Task 8: `internal/api` — HTTP handlers + routes + RBAC (TDD)

**Files:**
- Create: `orchestrator/internal/api/taxii_handlers.go`
- Create: `orchestrator/internal/api/taxii_handlers_test.go`
- Modify: `orchestrator/internal/api/handlers.go` (add `h.taxiiStore`/`h.taxiiManager` fields + `WithTAXII`, mirroring `WithEMSweep`'s exact shape at `:413-421`)
- Modify: `orchestrator/internal/api/routes.go` (add 7 routes near the existing threat-intel block, currently `:452-456`)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (add 7 rows near the existing threat-intel block, currently `:241-243`)

**Interfaces:**
- Consumes: `taxii.Store`/`taxii.Manager` (Tasks 3, 7), `taxii.Client`/`taxii.NewClient`/`taxii.Discovery` (Task 4), `auth.CanViewConnectorStatus`/`auth.CanUpdateConnectorConfig` (existing, reused as-is per spec's Decisions section).
- Produces: `h.CreateTAXIIConnector`, `h.ListTAXIIConnectors`, `h.GetTAXIIConnector`, `h.UpdateTAXIIConnector`, `h.DeleteTAXIIConnector`, `h.TestTAXIIConnector`, `h.SyncTAXIIConnector` — Task 10 (frontend) calls all 7.

**Deviation from the spec's literal route list:** the spec listed `POST /api/taxii/connectors/{id}/test`. During planning this is corrected to `POST /api/taxii/connectors/test` (no `{id}`, full config fields in the body) — matching `TestThreatIntelConfig`'s existing precedent of validating connectivity *before* a row is ever saved (the natural "Add Connector" UX: fill the form, click Test, then Save). An ID-scoped test-after-save endpoint would be less useful and inconsistent with the one sibling pattern this codebase already has for exactly this purpose.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/taxii_handlers_test.go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/taxii"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testTAXIIHandler(pool *pgxpool.Pool) *Handler {
	store := taxii.NewStore(pool)
	manager := taxii.NewManager(pool, store)
	return New(pool, ws.NewHub(), nil, testJWTSecret).WithTAXII(store, manager)
}

func TestCreateTAXIIConnector_PersistsAndReturnsWithoutSecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := testTAXIIHandler(pool)
		uid := seedUser(t, pool, "taxii-create-user", "pw-Password1!", "admin", true)
		body, _ := json.Marshal(map[string]any{
			"name": "FS-ISAC Test", "serverUrl": "https://taxii.example.org", "authType": "basic",
			"username": "user1", "password": "secret1", "enabled": true,
		})
		req := authedRequest(t, http.MethodPost, "/api/taxii/connectors", bytes.NewReader(body), auth.RoleAdmin, uid)
		rec := callAuthed(h.CreateTAXIIConnector, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out["name"] != "FS-ISAC Test" {
			t.Fatalf("response name = %v", out["name"])
		}
		if _, present := out["password"]; present {
			t.Fatal("response must never include the raw password field")
		}
		if out["hasPassword"] != true {
			t.Fatalf("hasPassword = %v, want true", out["hasPassword"])
		}
	})
}

func TestListTAXIIConnectors_ReturnsCreatedRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := testTAXIIHandler(pool)
		uid := seedUser(t, pool, "taxii-list-user", "pw-Password1!", "admin", true)
		body, _ := json.Marshal(map[string]any{"name": "ListMe", "serverUrl": "https://a.example"})
		createReq := authedRequest(t, http.MethodPost, "/api/taxii/connectors", bytes.NewReader(body), auth.RoleAdmin, uid)
		if rec := callAuthed(h.CreateTAXIIConnector, createReq); rec.Code != http.StatusCreated {
			t.Fatalf("create: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		listReq := authedRequest(t, http.MethodGet, "/api/taxii/connectors", nil, auth.RoleAdmin, uid)
		listRec := callAuthed(h.ListTAXIIConnectors, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", listRec.Code, listRec.Body.String())
		}
		var out []map[string]any
		json.Unmarshal(listRec.Body.Bytes(), &out)
		found := false
		for _, c := range out {
			if c["name"] == "ListMe" {
				found = true
			}
		}
		if !found {
			t.Fatalf("ListTAXIIConnectors did not include the created row: %+v", out)
		}
	})
}

func TestUpdateTAXIIConnector_EmptyPasswordKeepsStoredValue(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := testTAXIIHandler(pool)
		uid := seedUser(t, pool, "taxii-update-user", "pw-Password1!", "admin", true)
		createBody, _ := json.Marshal(map[string]any{"name": "Orig", "serverUrl": "https://a.example", "password": "orig-secret"})
		createReq := authedRequest(t, http.MethodPost, "/api/taxii/connectors", bytes.NewReader(createBody), auth.RoleAdmin, uid)
		createRec := callAuthed(h.CreateTAXIIConnector, createReq)
		var created map[string]any
		json.Unmarshal(createRec.Body.Bytes(), &created)
		id, _ := created["id"].(string)
		if id == "" {
			t.Fatalf("no id in create response: %s", createRec.Body.String())
		}

		updateBody, _ := json.Marshal(map[string]any{"name": "Renamed", "serverUrl": "https://a.example", "password": "", "enabled": true})
		updateReq := withURLParam(authedRequest(t, http.MethodPut, "/api/taxii/connectors/"+id, bytes.NewReader(updateBody), auth.RoleAdmin, uid), "id", id)
		updateRec := callAuthed(h.UpdateTAXIIConnector, updateReq)
		if updateRec.Code != http.StatusOK {
			t.Fatalf("update status = %d, body = %s", updateRec.Code, updateRec.Body.String())
		}

		var pw string
		if err := pool.QueryRow(context.Background(), `SELECT password FROM taxii_connector_config WHERE id = $1`, id).Scan(&pw); err != nil {
			t.Fatalf("query password: %v", err)
		}
		if pw != "orig-secret" {
			t.Fatalf("password = %q, want kept value %q", pw, "orig-secret")
		}
	})
}

func TestDeleteTAXIIConnector_RemovesRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := testTAXIIHandler(pool)
		uid := seedUser(t, pool, "taxii-delete-user", "pw-Password1!", "admin", true)
		createBody, _ := json.Marshal(map[string]any{"name": "ToDelete", "serverUrl": "https://a.example"})
		createReq := authedRequest(t, http.MethodPost, "/api/taxii/connectors", bytes.NewReader(createBody), auth.RoleAdmin, uid)
		createRec := callAuthed(h.CreateTAXIIConnector, createReq)
		var created map[string]any
		json.Unmarshal(createRec.Body.Bytes(), &created)
		id, _ := created["id"].(string)

		delReq := withURLParam(authedRequest(t, http.MethodDelete, "/api/taxii/connectors/"+id, nil, auth.RoleAdmin, uid), "id", id)
		delRec := callAuthed(h.DeleteTAXIIConnector, delReq)
		if delRec.Code != http.StatusOK {
			t.Fatalf("delete status = %d, body = %s", delRec.Code, delRec.Body.String())
		}

		getReq := withURLParam(authedRequest(t, http.MethodGet, "/api/taxii/connectors/"+id, nil, auth.RoleAdmin, uid), "id", id)
		getRec := callAuthed(h.GetTAXIIConnector, getReq)
		if getRec.Code != http.StatusNotFound {
			t.Fatalf("get after delete: status = %d, want 404", getRec.Code)
		}
	})
}

func TestTestTAXIIConnector_ReportsFailureForUnreachableServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := testTAXIIHandler(pool)
		uid := seedUser(t, pool, "taxii-test-user", "pw-Password1!", "admin", true)
		body, _ := json.Marshal(map[string]any{"serverUrl": "http://127.0.0.1:1", "authType": "none"})
		req := authedRequest(t, http.MethodPost, "/api/taxii/connectors/test", bytes.NewReader(body), auth.RoleAdmin, uid)
		rec := callAuthed(h.TestTAXIIConnector, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (test result reported in body, not HTTP status)", rec.Code)
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out["ok"] != false {
			t.Fatalf("ok = %v, want false for an unreachable server", out["ok"])
		}
	})
}

func TestSyncTAXIIConnector_TriggersOneSync(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := testTAXIIHandler(pool)
		uid := seedUser(t, pool, "taxii-sync-user", "pw-Password1!", "admin", true)
		createBody, _ := json.Marshal(map[string]any{"name": "SyncTest", "serverUrl": "http://127.0.0.1:1"})
		createReq := authedRequest(t, http.MethodPost, "/api/taxii/connectors", bytes.NewReader(createBody), auth.RoleAdmin, uid)
		createRec := callAuthed(h.CreateTAXIIConnector, createReq)
		var created map[string]any
		json.Unmarshal(createRec.Body.Bytes(), &created)
		id, _ := created["id"].(string)

		syncReq := withURLParam(authedRequest(t, http.MethodPost, "/api/taxii/connectors/"+id+"/sync", nil, auth.RoleAdmin, uid), "id", id)
		syncRec := callAuthed(h.SyncTAXIIConnector, syncReq)
		if syncRec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", syncRec.Code, syncRec.Body.String())
		}
	})
}
```

This test file needs `"context"` imported for `context.Background()` in `TestUpdateTAXIIConnector_EmptyPasswordKeepsStoredValue` — add it to the import block.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestCreateTAXIIConnector|TestListTAXIIConnectors|TestUpdateTAXIIConnector|TestDeleteTAXIIConnector|TestTestTAXIIConnector|TestSyncTAXIIConnector" -v 2>&1`
Expected: compile failure (`h.CreateTAXIIConnector`/`WithTAXII` etc. undefined).

- [ ] **Step 3: Add `h.taxiiStore`/`h.taxiiManager` + `WithTAXII` to `handlers.go`**

Add the two fields immediately after the existing `emSweep *emsweep.Store` field (confirm exact current line with `grep -n "emSweep \*emsweep.Store" internal/api/handlers.go`):

```go
	taxiiStore   *taxii.Store   // nil when not loaded — generic TAXII 2.1 connector config CRUD
	taxiiManager *taxii.Manager // nil when not loaded — per-connector pollers
```

Add `"github.com/audspect/bas/internal/taxii"` to the import block.

Add `WithTAXII` immediately after the existing `WithEMSweep` method (confirm exact current line with `grep -n "func (h \*Handler) WithEMSweep" internal/api/handlers.go`):

```go
// WithTAXII attaches the generic TAXII 2.1 connector store and its
// per-connector poller manager.
func (h *Handler) WithTAXII(store *taxii.Store, manager *taxii.Manager) *Handler {
	h.taxiiStore = store
	h.taxiiManager = manager
	return h
}
```

- [ ] **Step 4: Write `taxii_handlers.go`**

```go
// orchestrator/internal/api/taxii_handlers.go
package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/taxii"
)

func taxiiConfigToJSON(c taxii.ConnectorConfig) map[string]any {
	return map[string]any{
		"id": c.ID, "name": c.Name, "serverUrl": c.ServerURL, "apiRoot": c.APIRoot,
		"collectionId": c.CollectionID, "authType": c.AuthType, "username": c.Username,
		"hasPassword": c.Password != "", "hasClientCert": c.ClientCert != "", "hasClientKey": c.ClientKey != "",
		"enabled": c.Enabled, "lastPollAt": c.LastPollAt, "lastPollStatus": c.LastPollStatus,
		"lastPollSummary": c.LastPollSummary, "lastError": c.LastError,
		"createdAt": c.CreatedAt, "updatedAt": c.UpdatedAt,
	}
}

type taxiiConnectorBody struct {
	Name         string `json:"name"`
	ServerURL    string `json:"serverUrl"`
	APIRoot      string `json:"apiRoot"`
	CollectionID string `json:"collectionId"`
	AuthType     string `json:"authType"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	ClientCert   string `json:"clientCert"`
	ClientKey    string `json:"clientKey"`
	Enabled      bool   `json:"enabled"`
}

// GET /api/taxii/connectors
func (h *Handler) ListTAXIIConnectors(w http.ResponseWriter, r *http.Request) {
	if h.taxiiStore == nil {
		jsonOK(w, []map[string]any{})
		return
	}
	cfgs, err := h.taxiiStore.List(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(cfgs))
	for _, c := range cfgs {
		out = append(out, taxiiConfigToJSON(c))
	}
	jsonOK(w, out)
}

// GET /api/taxii/connectors/{id}
func (h *Handler) GetTAXIIConnector(w http.ResponseWriter, r *http.Request) {
	if h.taxiiStore == nil {
		jsonError(w, "TAXII connector store not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	c, err := h.taxiiStore.Get(r.Context(), id)
	if err != nil {
		jsonError(w, "connector not found", http.StatusNotFound)
		return
	}
	jsonOK(w, taxiiConfigToJSON(c))
}

// POST /api/taxii/connectors
func (h *Handler) CreateTAXIIConnector(w http.ResponseWriter, r *http.Request) {
	if h.taxiiStore == nil {
		jsonError(w, "TAXII connector store not loaded", http.StatusServiceUnavailable)
		return
	}
	var body taxiiConnectorBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if body.Name == "" || body.ServerURL == "" {
		jsonError(w, "name and serverUrl are required", http.StatusBadRequest)
		return
	}
	created, err := h.taxiiStore.Create(r.Context(), taxii.ConnectorConfig{
		Name: body.Name, ServerURL: body.ServerURL, APIRoot: body.APIRoot, CollectionID: body.CollectionID,
		AuthType: body.AuthType, Username: body.Username, Password: body.Password,
		ClientCert: body.ClientCert, ClientKey: body.ClientKey, Enabled: body.Enabled,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if h.taxiiManager != nil {
		if err := h.taxiiManager.Reconcile(r.Context()); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	h.auditLog(r, "taxii.connector.create", created.ID, map[string]any{"name": created.Name, "enabled": created.Enabled}, "ok")
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, taxiiConfigToJSON(created))
}

// PUT /api/taxii/connectors/{id}
func (h *Handler) UpdateTAXIIConnector(w http.ResponseWriter, r *http.Request) {
	if h.taxiiStore == nil {
		jsonError(w, "TAXII connector store not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	var body taxiiConnectorBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	updated, err := h.taxiiStore.Update(r.Context(), id, taxii.ConnectorConfig{
		Name: body.Name, ServerURL: body.ServerURL, APIRoot: body.APIRoot, CollectionID: body.CollectionID,
		AuthType: body.AuthType, Username: body.Username, Password: body.Password,
		ClientCert: body.ClientCert, ClientKey: body.ClientKey, Enabled: body.Enabled,
	}, body.Password == "", body.ClientCert == "", body.ClientKey == "")
	if err != nil {
		if err == taxii.ErrNotFound {
			jsonError(w, "connector not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if h.taxiiManager != nil {
		if err := h.taxiiManager.Reconcile(r.Context()); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	h.auditLog(r, "taxii.connector.update", id, map[string]any{"name": updated.Name, "enabled": updated.Enabled}, "ok")
	jsonOK(w, taxiiConfigToJSON(updated))
}

// DELETE /api/taxii/connectors/{id}
func (h *Handler) DeleteTAXIIConnector(w http.ResponseWriter, r *http.Request) {
	if h.taxiiStore == nil {
		jsonError(w, "TAXII connector store not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	if err := h.taxiiStore.Delete(r.Context(), id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if h.taxiiManager != nil {
		if err := h.taxiiManager.Reconcile(r.Context()); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	h.auditLog(r, "taxii.connector.delete", id, nil, "ok")
	jsonOK(w, map[string]string{"id": id, "status": "deleted"})
}

// POST /api/taxii/connectors/test — validates connectivity/credentials
// BEFORE a row is saved, mirroring TestThreatIntelConfig's existing
// precedent. Takes the full form body, not a saved connector id.
func (h *Handler) TestTAXIIConnector(w http.ResponseWriter, r *http.Request) {
	var body taxiiConnectorBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if body.ServerURL == "" {
		jsonError(w, "serverUrl is required", http.StatusBadRequest)
		return
	}
	client := taxii.NewClient(taxii.ConnectorConfig{
		ServerURL: body.ServerURL, AuthType: body.AuthType, Username: body.Username, Password: body.Password,
	})
	disc, err := client.Discover(r.Context())
	if err != nil {
		jsonOK(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	apiRoot := body.APIRoot
	if apiRoot == "" {
		apiRoot = disc.DefaultAPIRoot
	}
	collections, err := client.ListCollections(r.Context(), apiRoot)
	if err != nil {
		jsonOK(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	jsonOK(w, map[string]any{"ok": true, "collectionCount": len(collections)})
}

// POST /api/taxii/connectors/{id}/sync — manual trigger for one connector.
func (h *Handler) SyncTAXIIConnector(w http.ResponseWriter, r *http.Request) {
	if h.taxiiManager == nil {
		jsonError(w, "TAXII connector manager not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	if err := h.taxiiManager.TriggerSync(r.Context(), id); err != nil {
		jsonOK(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	h.auditLog(r, "taxii.connector.sync", id, nil, "ok")
	jsonOK(w, map[string]any{"ok": true})
}
```

- [ ] **Step 5: Add routes**

In `orchestrator/internal/api/routes.go`, immediately after the existing `TestThreatIntelConfig` route (currently `:456`):

```go
		r.With(auth.RequirePermission(auth.CanViewConnectorStatus)).Get("/api/taxii/connectors", h.ListTAXIIConnectors)
		r.With(auth.RequirePermission(auth.CanViewConnectorStatus)).Get("/api/taxii/connectors/{id}", h.GetTAXIIConnector)
		r.With(auth.RequirePermission(auth.CanUpdateConnectorConfig)).Post("/api/taxii/connectors", h.CreateTAXIIConnector)
		r.With(auth.RequirePermission(auth.CanUpdateConnectorConfig)).Put("/api/taxii/connectors/{id}", h.UpdateTAXIIConnector)
		r.With(auth.RequirePermission(auth.CanUpdateConnectorConfig)).Delete("/api/taxii/connectors/{id}", h.DeleteTAXIIConnector)
		r.With(auth.RequirePermission(auth.CanUpdateConnectorConfig)).Post("/api/taxii/connectors/test", h.TestTAXIIConnector)
		r.With(auth.RequirePermission(auth.CanUpdateConnectorConfig)).Post("/api/taxii/connectors/{id}/sync", h.SyncTAXIIConnector)
```

- [ ] **Step 6: Add RBAC matrix entries**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after the existing `/api/threat-intel/{connector}/config/test` row (currently `:243`):

```go
	{http.MethodGet, "/api/taxii/connectors", tierPermission, auth.CanViewConnectorStatus},
	{http.MethodGet, "/api/taxii/connectors/{id}", tierPermission, auth.CanViewConnectorStatus},
	{http.MethodPost, "/api/taxii/connectors", tierPermission, auth.CanUpdateConnectorConfig},
	{http.MethodPut, "/api/taxii/connectors/{id}", tierPermission, auth.CanUpdateConnectorConfig},
	{http.MethodDelete, "/api/taxii/connectors/{id}", tierPermission, auth.CanUpdateConnectorConfig},
	{http.MethodPost, "/api/taxii/connectors/test", tierPermission, auth.CanUpdateConnectorConfig},
	{http.MethodPost, "/api/taxii/connectors/{id}/sync", tierPermission, auth.CanUpdateConnectorConfig},
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... 2>&1` (fix any unused-import errors first), then:
`cd orchestrator && go test ./internal/api/... -run "TestCreateTAXIIConnector|TestListTAXIIConnectors|TestUpdateTAXIIConnector|TestDeleteTAXIIConnector|TestTestTAXIIConnector|TestSyncTAXIIConnector" -v 2>&1`
Expected: all 6 tests PASS.

- [ ] **Step 8: RBAC drift check**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix_NoDrift -v 2>&1`
Expected: PASS.

- [ ] **Step 9: Run the full `internal/api` suite (background, real log check)**

```bash
cd orchestrator && go test ./internal/api/... -timeout 20m > <scratchpad>/taxii-task8-full-api-test.log 2>&1
```
Run with `run_in_background: true`. Wait for the real completion notification, then read the actual log file (`tail -n 30`). Confirm it ends with `ok github.com/audspect/bas/internal/api <N>s`.

- [ ] **Step 10: Commit**

```bash
cd orchestrator
git add internal/api/taxii_handlers.go internal/api/taxii_handlers_test.go internal/api/handlers.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(api): add TAXII connector CRUD + test + manual-sync HTTP handlers"
git push
```

---

### Task 9: `cmd/server/main.go` wiring

**Files:**
- Modify: `orchestrator/cmd/server/main.go`

**Interfaces:**
- Consumes: `taxii.NewStore`, `taxii.NewManager` (Task 3, Task 7), `h.WithTAXII` (Task 8).
- Produces: a running TAXII manager in the live server process.

- [ ] **Step 1: Locate the exact insertion point**

Run: `grep -n "vexSweepStore\|WithVexSweep\|vexSweepScheduler.Start\|emSweepStore\|WithEMSweep" orchestrator/cmd/server/main.go`

Confirm the current line numbers for the `emSweepStore`/`WithEMSweep`/`emSweepScheduler.Start` block added in this session's earlier EM Sweep work — insert immediately after it, following the identical pattern.

- [ ] **Step 2: Add TAXII store/manager construction**

Immediately after the `emSweepDispatcher := emsweep.NewDispatcher(...)` block:

```go
	// Generic TAXII 2.1 connector -- deliberately its own Manager, not
	// wired into the connector.Scheduler above (Phase 1 has no ThreatActor
	// output; see docs/superpowers/specs/2026-08-13-taxii-connector-phase1-design.md).
	taxiiStore := taxii.NewStore(pool)
	taxiiManager := taxii.NewManager(pool, taxiiStore)
```

Add `"github.com/audspect/bas/internal/taxii"` to the import block, alphabetized (after `"github.com/audspect/bas/internal/threatpriority"`, before `"github.com/audspect/bas/internal/ticketing"` -- confirm exact neighbors with the current import list since this session's earlier `emsweep` insertion already shifted lines once).

- [ ] **Step 3: Add `.WithTAXII(...)` to the handler chain**

Immediately after the `.WithEMSweep(emSweepStore, emSweepDispatcher).` line:

```go
		WithTAXII(taxiiStore, taxiiManager).
```

- [ ] **Step 4: Start and stop the manager**

Immediately after the existing `emSweepScheduler.Start(...)` / `defer emSweepScheduler.Stop()` pair:

```go
	if err := taxiiManager.Start(context.Background()); err != nil {
		log.Printf("[taxii] manager start: %v", err)
	}
	defer taxiiManager.Stop()
```

- [ ] **Step 5: Verify it builds**

Run: `cd orchestrator && go build ./... 2>&1`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add cmd/server/main.go
git commit -m "feat(server): wire up TAXII connector store/manager"
git push
```

---

### Task 10: Frontend — TAXII Connectors list + add/edit modal

**Files:**
- Modify: `orchestrator/wwwroot/index.html`
  - Add: a new "TAXII Connectors" card inside the existing Settings > Threat Intel section (`#set-intel`, currently around `:2019-2060` — placed as a new `conn-cfg-card`-style block or its own sub-section immediately after the existing MISP/OpenCTI cards, since this is a connector-config area like they are, not an operational data view like Scheduled Assessments)
  - Add: JS functions `loadTAXIIConnectors()`, `renderTAXIIConnectorsList()`, `openTAXIIConnectorModal(id)` (id optional -- null for Add, a real id for Edit), `closeTAXIIConnectorModal()`, `testTAXIIConnectorForm()`, `saveTAXIIConnectorForm()`, `deleteTAXIIConnector(id)`, `syncTAXIIConnectorNow(id)`

**Interfaces:**
- Consumes: `GET/POST/PUT/DELETE /api/taxii/connectors[...]`, `POST /api/taxii/connectors/test`, `POST /api/taxii/connectors/{id}/sync` (Task 8). Reuses the existing `apicall`, `showToast`, `x()` escaping helpers already used throughout this file.

- [ ] **Step 1: Confirm the exact insertion point**

Run: `grep -n 'id="set-intel"\|ti-opencti-config-panel' orchestrator/wwwroot/index.html`
Find the closing `</div>` of the OpenCTI `conn-cfg-card` (the block starting at the confirmed `cs-opencti-card` div) to insert the new card immediately after it, inside the same `set-intel` section, before that section's own closing tag.

- [ ] **Step 2: Add the list card + modal markup**

```html
        <!-- TAXII 2.1 Connectors (generic -- FS-ISAC, HC-ISAC, Auto-ISAC, any TAXII 2.1 server) -->
        <div class="sec-hdr" style="margin-top:1.25rem">
          <h2>TAXII Connectors</h2>
          <div style="display:flex;gap:0.5rem">
            <button class="btn btn-outline btn-sm" onclick="loadTAXIIConnectors()">Refresh</button>
            <button class="btn btn-primary btn-sm" onclick="openTAXIIConnectorModal(null)">+ Add Connector</button>
          </div>
        </div>
        <div class="tbl-wrap">
          <table>
            <thead><tr>
              <th>Name</th><th>Server URL</th><th>Enabled</th><th>Last Poll</th><th>Last Result</th><th></th>
            </tr></thead>
            <tbody id="taxii-connectors-body">
              <tr><td colspan="6" class="empty">Loading…</td></tr>
            </tbody>
          </table>
        </div>
        </div>
```

Note the trailing extra `</div>` closes the `set-intel` section — verify against the actual current closing tag structure at the insertion point rather than assuming; if `set-intel`'s own close is already present further down, drop this last line and let it close naturally.

Add the modal near the other Settings-area modals (e.g. after the existing `#respond-overlay` block, confirm with `grep -n 'id="respond-overlay"' orchestrator/wwwroot/index.html` for a nearby existing overlay to place this next to). The markup below was corrected during plan self-review after verifying the real, established `.overlay`/`.modal` convention against `#respond-overlay` (`:4053-4090`) directly — this codebase's modals have no `.modal-hdr`/`.modal-body`/`.modal-close` wrapper classes (those don't exist), just a plain `<h3>` inside `.modal`, `.modal-lbl` labels, and a `.modal-actions` button row; opening/closing toggles the `open` class (`.overlay.open { display:flex }`, confirmed at `:653`), not inline `style.display`:

```html
<!-- TAXII Connector Add/Edit -->
<div id="taxii-connector-overlay" class="overlay">
  <div class="modal" style="width:480px">
    <h3 id="taxii-connector-modal-title">Add TAXII Connector</h3>

    <label class="modal-lbl">Name</label>
    <input id="taxii-conn-name" type="text" placeholder="e.g. FS-ISAC Production"
           style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">

    <label class="modal-lbl" style="margin-top:0.6rem">Server URL</label>
    <input id="taxii-conn-server-url" type="text" placeholder="https://taxii.example.org"
           style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">

    <label class="modal-lbl" style="margin-top:0.6rem">API Root <span class="tiny muted">(optional — auto-discovered if blank)</span></label>
    <input id="taxii-conn-api-root" type="text"
           style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">

    <label class="modal-lbl" style="margin-top:0.6rem">Collection ID</label>
    <input id="taxii-conn-collection-id" type="text"
           style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">

    <label class="modal-lbl" style="margin-top:0.6rem">Auth Type</label>
    <select id="taxii-conn-auth-type" onchange="taxiiToggleAuthFields()"
            style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem">
      <option value="none">None</option>
      <option value="basic">Basic (username/password)</option>
    </select>

    <div id="taxii-conn-basic-fields" style="display:none">
      <label class="modal-lbl" style="margin-top:0.6rem">Username</label>
      <input id="taxii-conn-username" type="text"
             style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">
      <label class="modal-lbl" style="margin-top:0.6rem">Password</label>
      <input id="taxii-conn-password" type="password" placeholder="Leave blank to keep current"
             style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">
    </div>

    <label style="display:flex;align-items:center;gap:0.4rem;margin-top:0.6rem">
      <input type="checkbox" id="taxii-conn-enabled"> Enabled
    </label>

    <div id="taxii-conn-test-result" class="tiny muted" style="margin-top:0.5rem"></div>

    <div class="modal-actions">
      <button class="btn btn-outline btn-sm" onclick="testTAXIIConnectorForm()">Test Connection</button>
      <span style="flex:1"></span>
      <button class="btn btn-outline btn-sm" onclick="closeTAXIIConnectorModal()">Cancel</button>
      <button class="btn btn-primary btn-sm" id="taxii-conn-save-btn" onclick="saveTAXIIConnectorForm()">Save</button>
    </div>
  </div>
</div>
```

- [ ] **Step 3: Write the JS**

```js
// ── TAXII Connectors (generic TAXII 2.1 -- FS-ISAC/HC-ISAC/Auto-ISAC/any) ──
var TAXII_CONNECTORS = [];
var TAXII_EDITING_ID = null;

function loadTAXIIConnectors() {
  var tbody = document.getElementById('taxii-connectors-body');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" class="empty">Loading…</td></tr>';
  apicall('/api/taxii/connectors').then(function(rows) {
    TAXII_CONNECTORS = rows || [];
    renderTAXIIConnectorsList();
  }).catch(function(e) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">Failed to load: ' + x(e.message || 'unknown error') + '</td></tr>';
  });
}

function renderTAXIIConnectorsList() {
  var tbody = document.getElementById('taxii-connectors-body');
  if (!TAXII_CONNECTORS.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">No TAXII connectors configured yet.</td></tr>';
    return;
  }
  tbody.innerHTML = TAXII_CONNECTORS.map(function(c) {
    var lastPoll = c.lastPollAt ? ago(c.lastPollAt) : 'Never';
    var resultColor = c.lastPollStatus === 'ok' ? 'var(--success)' : (c.lastPollStatus === 'error' ? 'var(--danger)' : 'var(--muted)');
    var summary = c.lastPollSummary || {};
    var resultText = c.lastPollStatus === 'ok'
      ? (summary.processed || 0) + ' processed, ' + (summary.skipped || 0) + ' skipped, ' + (summary.malformed || 0) + ' malformed'
      : (c.lastPollStatus === 'error' ? x(c.lastError || 'error') : '—');
    return '<tr>' +
      '<td>' + x(c.name) + '</td>' +
      '<td class="tiny muted">' + x(c.serverUrl) + '</td>' +
      '<td>' + (c.enabled ? '<span class="badge" style="color:var(--success);border-color:var(--success)">Enabled</span>' : '<span class="badge" style="color:var(--muted);border-color:var(--muted)">Disabled</span>') + '</td>' +
      '<td class="tiny muted">' + x(lastPoll) + '</td>' +
      '<td class="tiny" style="color:' + resultColor + '">' + resultText + '</td>' +
      '<td>' +
        '<button class="btn btn-outline btn-sm" onclick="openTAXIIConnectorModal(\'' + x(c.id) + '\')">Edit</button> ' +
        '<button class="btn btn-outline btn-sm" onclick="syncTAXIIConnectorNow(\'' + x(c.id) + '\')">Sync Now</button> ' +
        '<button class="btn btn-outline btn-sm" onclick="deleteTAXIIConnector(\'' + x(c.id) + '\')">Delete</button>' +
      '</td>' +
    '</tr>';
  }).join('');
}

function taxiiToggleAuthFields() {
  var authType = document.getElementById('taxii-conn-auth-type').value;
  document.getElementById('taxii-conn-basic-fields').style.display = authType === 'basic' ? '' : 'none';
}

function openTAXIIConnectorModal(id) {
  TAXII_EDITING_ID = id;
  document.getElementById('taxii-conn-test-result').textContent = '';
  if (!id) {
    document.getElementById('taxii-connector-modal-title').textContent = 'Add TAXII Connector';
    document.getElementById('taxii-conn-save-btn').textContent = 'Save';
    document.getElementById('taxii-conn-name').value = '';
    document.getElementById('taxii-conn-server-url').value = '';
    document.getElementById('taxii-conn-api-root').value = '';
    document.getElementById('taxii-conn-collection-id').value = '';
    document.getElementById('taxii-conn-auth-type').value = 'none';
    document.getElementById('taxii-conn-username').value = '';
    document.getElementById('taxii-conn-password').value = '';
    document.getElementById('taxii-conn-enabled').checked = false;
    taxiiToggleAuthFields();
    document.getElementById('taxii-connector-overlay').classList.add('open');
    return;
  }
  var c = TAXII_CONNECTORS.find(function(row) { return row.id === id; });
  if (!c) { showToast('Connector not found', 'err'); return; }
  document.getElementById('taxii-connector-modal-title').textContent = 'Edit TAXII Connector';
  document.getElementById('taxii-conn-save-btn').textContent = 'Save Changes';
  document.getElementById('taxii-conn-name').value = c.name || '';
  document.getElementById('taxii-conn-server-url').value = c.serverUrl || '';
  document.getElementById('taxii-conn-api-root').value = c.apiRoot || '';
  document.getElementById('taxii-conn-collection-id').value = c.collectionId || '';
  document.getElementById('taxii-conn-auth-type').value = c.authType || 'none';
  document.getElementById('taxii-conn-username').value = c.username || '';
  document.getElementById('taxii-conn-password').value = ''; // never round-tripped -- blank means "keep current"
  document.getElementById('taxii-conn-enabled').checked = !!c.enabled;
  taxiiToggleAuthFields();
  document.getElementById('taxii-connector-overlay').classList.add('open');
}

function closeTAXIIConnectorModal() {
  document.getElementById('taxii-connector-overlay').classList.remove('open');
  TAXII_EDITING_ID = null;
}

function taxiiFormPayload() {
  return {
    name: document.getElementById('taxii-conn-name').value,
    serverUrl: document.getElementById('taxii-conn-server-url').value,
    apiRoot: document.getElementById('taxii-conn-api-root').value,
    collectionId: document.getElementById('taxii-conn-collection-id').value,
    authType: document.getElementById('taxii-conn-auth-type').value,
    username: document.getElementById('taxii-conn-username').value,
    password: document.getElementById('taxii-conn-password').value,
    enabled: document.getElementById('taxii-conn-enabled').checked
  };
}

function testTAXIIConnectorForm() {
  var resultEl = document.getElementById('taxii-conn-test-result');
  resultEl.textContent = 'Testing…';
  resultEl.style.color = 'var(--muted)';
  apicall('/api/taxii/connectors/test', { method: 'POST', body: JSON.stringify(taxiiFormPayload()) })
    .then(function(res) {
      resultEl.textContent = res.ok ? ('OK — ' + res.collectionCount + ' collection(s) visible') : ('Failed: ' + res.error);
      resultEl.style.color = res.ok ? 'var(--success)' : 'var(--danger)';
    })
    .catch(function(e) {
      resultEl.textContent = 'Failed: ' + (e.message || 'error');
      resultEl.style.color = 'var(--danger)';
    });
}

function saveTAXIIConnectorForm() {
  var payload = taxiiFormPayload();
  if (!payload.name || !payload.serverUrl) { showToast('Name and Server URL are required', 'err'); return; }
  var isEdit = !!TAXII_EDITING_ID;
  var url = isEdit ? '/api/taxii/connectors/' + encodeURIComponent(TAXII_EDITING_ID) : '/api/taxii/connectors';
  apicall(url, { method: isEdit ? 'PUT' : 'POST', body: JSON.stringify(payload) })
    .then(function() {
      showToast('TAXII connector saved', 'ok');
      closeTAXIIConnectorModal();
      loadTAXIIConnectors();
    })
    .catch(function(e) { showToast('Save failed: ' + (e.message || 'error'), 'err'); });
}

function deleteTAXIIConnector(id) {
  if (!confirm('Delete this TAXII connector? This stops its polling immediately and cannot be undone.')) return;
  apicall('/api/taxii/connectors/' + encodeURIComponent(id), { method: 'DELETE' })
    .then(function() { showToast('Connector deleted', 'ok'); loadTAXIIConnectors(); })
    .catch(function(e) { showToast('Delete failed: ' + (e.message || 'error'), 'err'); });
}

function syncTAXIIConnectorNow(id) {
  apicall('/api/taxii/connectors/' + encodeURIComponent(id) + '/sync', { method: 'POST' })
    .then(function(res) {
      showToast(res.ok ? 'Sync completed' : ('Sync failed: ' + (res.error || 'unknown error')), res.ok ? 'ok' : 'err');
      loadTAXIIConnectors();
    })
    .catch(function(e) { showToast('Sync failed: ' + (e.message || 'error'), 'err'); });
}
```

- [ ] **Step 4: Wire `loadTAXIIConnectors()` into the Settings > Threat Intel section's existing load path**

Find where `loadConnectorStatus()`/`loadThreatIntelConfig('misp')` are already called when the Threat Intel settings section opens (`grep -n "loadConnectorStatus()" orchestrator/wwwroot/index.html`) and add `loadTAXIIConnectors();` alongside them, in the same function/place.

- [ ] **Step 5: Verify JS syntax**

```powershell
node "<scratchpad>\extract_scripts.js"; node --check "<scratchpad>\extracted.js"
```
Expected: no output (clean syntax).

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add wwwroot/index.html
git commit -m "feat(ui): add TAXII Connectors list + add/edit modal to Settings > Threat Intel"
git push
```

---

### Task 11: Frontend — IOC Registry source filter dropdown addition

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (the `ioc-filter-source` `<select>`, currently `:3170-3176` — `ioc-filter-origin` already has `threat-feed`, confirmed present at `:3185`, no change needed there)

**Interfaces:**
- Consumes: nothing new — `loadIOCRegistry()` (existing) already builds `source=` from whatever is selected.

- [ ] **Step 1: Add the new option**

```html
          <select id="ioc-filter-source" onchange="loadIOCRegistry()" style="padding:0.35rem 0.6rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.78rem">
            <option value="">All sources</option>
            <option value="detection_alert">Detection alert</option>
            <option value="scenario">Scenario</option>
            <option value="variant">Variant</option>
            <option value="manual">Manual</option>
            <option value="threat_feed">Threat feed</option>
          </select>
```

- [ ] **Step 2: Verify JS syntax**

Not strictly needed for a pure HTML `<option>` addition, but run it anyway for consistency with this session's convention:
```powershell
node "<scratchpad>\extract_scripts.js"; node --check "<scratchpad>\extracted.js"
```

- [ ] **Step 3: Commit**

```bash
cd orchestrator
git add wwwroot/index.html
git commit -m "feat(ui): add threat-feed option to IOC Registry source filter"
git push
```

---

### Task 12: Final verification + manual QA list

**Files:** none new — this task only runs verification across everything Tasks 1-11 touched.

- [ ] **Step 1: Full backend build**

Run: `cd orchestrator && go build ./... 2>&1`
Expected: no output.

- [ ] **Step 2: Full `internal/taxii` suite**

Run: `cd orchestrator && go test ./internal/taxii/... -v 2>&1`
Expected: every test PASS.

- [ ] **Step 3: Full `internal/iocregistry` suite**

Run: `cd orchestrator && go test ./internal/iocregistry/... -v 2>&1`
Expected: every test PASS.

- [ ] **Step 4: Full `internal/api` suite (background, real log check)**

```bash
cd orchestrator && go test ./internal/api/... -timeout 20m > <scratchpad>/taxii-final-test.log 2>&1
```
Run with `run_in_background: true`. Wait for the real completion notification, then read the actual file (`tail -n 15`). Confirm it ends with `ok github.com/audspect/bas/internal/api <N>s`.

- [ ] **Step 5: Full JS syntax check**

```powershell
node "<scratchpad>\extract_scripts.js"; node --check "<scratchpad>\extracted.js"
```
Expected: no output.

- [ ] **Step 6: RBAC drift check (redundant safety net)**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix_NoDrift -v 2>&1`
Expected: PASS.

- [ ] **Step 7: Report manual QA items to the user**

This plan cannot verify these without a live TAXII server (real or reference) and a deployed server. Tell the user explicitly these need manual verification once deployed:

- Point the connector at a real or reference TAXII 2.1 server (not just the unit-test mock) and confirm discovery → collection listing → first sync populates the IOC Registry with `Origin=threat-feed` entries end-to-end.
- Confirm the "Test Connection" button in the Add/Edit modal correctly reports failure for a wrong password/unreachable server before anything is saved.
- Confirm editing an existing connector's `server_url`/credentials and saving actually takes effect on the next sync (exercises `Manager.Reconcile`'s full-restart behavior).
- Confirm deleting a connector stops its polling (no further `last_poll_at` updates after deletion).
- Confirm repeated polling of an unchanged feed does not create duplicate `iocs` rows or inflate `sighting_count` beyond real re-sightings (idempotency in a real long-running deployment, not just the unit tests' single-process scenario).
- **FS-ISAC specifically** (deferred per the spec's Testing section): once real FS-ISAC TAXII membership credentials are available, validate authentication, discovery, real collection/object structure, rate limits, and pagination behavior against the actual server — nothing in this plan's automated suite depends on that access existing yet.

Also remind the user this needs an orchestrator rebuild + redeploy to take effect.

- [ ] **Step 8: Final commit if anything is outstanding**

If Steps 1-6 required any fixes not yet committed, commit and push them now. If everything was already green and committed task-by-task, this step is a no-op — confirm `git status` is clean and `git log` shows the full sequence of commits from Tasks 1-11 pushed to `main`.
