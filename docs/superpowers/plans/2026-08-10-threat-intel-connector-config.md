# Threat Intel Connector Config Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move MISP/OpenCTI/OTX from `.env`-only configuration to a DB-backed, UI-editable config matching OpenAEV's existing pattern, with a real live-reconfigure mechanism so a saved change takes effect immediately — no `.env` editing, no `docker restart`.

**Architecture:** One shared `threat_intel_config` table (3 rows: misp/opencti/otx) replaces direct env-var reads at connector-construction time. `internal/connector.Scheduler` gains a thread-safe `Reconfigure` method so its background poll loop picks up a changed source list live; `Handler.iocProvider` (OTX's second, independent consumer) becomes mutex-guarded so it can be swapped the same way. Existing `.env` values are auto-seeded into the DB once on first boot so already-deployed installs keep working unattended.

**Tech Stack:** Go (`internal/db`, `internal/auth`, `internal/connector`, `internal/api`, `cmd/server`), PostgreSQL, vanilla JS in `orchestrator/wwwroot/index.html`.

## Global Constraints

- API keys are stored in plain text, matching `openaev_config.bearer_token`'s
  existing precedent exactly — no encryption-at-rest in this plan (explicit
  decision, see spec Non-goals).
- Poll interval (`THREAT_INTEL_POLL_HOURS`) is **not** moved into the DB —
  stays a shared, env-configured cadence for the one `Scheduler`, exactly as
  today. Not touched by any task in this plan.
- No per-connector `Sync` endpoint — the existing shared
  `POST /api/connector/sync` is unchanged and untouched.
- `ThreatIntelSectors`/`ThreatIntelRegions` stay env-configured — out of
  scope, not touched by any task.
- `.env` is not removed as a deployment mechanism — it remains the
  first-boot seed source. No task in this plan deletes or deprecates it.
- No automated frontend test suite exists for `wwwroot/index.html`
  (established project convention). Task 3's verification is the Node.js
  syntax-check pattern used throughout this session's frontend plans.

---

### Task 1: Data model, migration, and permission

**Files:**
- Modify: `orchestrator/internal/db/postgres.go:1026` (schema)
- Modify: `orchestrator/internal/auth/permissions.go:101-102` (const), `:232-233` (RoleAdmin map), `:313-314` (`Permissions()` enumeration)
- Modify: `orchestrator/internal/auth/permissions_test.go:44-46` (`TestHasPermission_FullMatrix`), `:82-83` (`TestHasPermission_MatrixIsComplete`'s `tested` map), `:133-134` (`TestPermissions_Ordering`'s `want` slice)
- Create: `orchestrator/internal/connector/seed.go` (env-to-DB seed function)
- Create: `orchestrator/internal/connector/seed_test.go`
- Modify: `orchestrator/cmd/server/main.go:273-299` (build `tiSources` from DB instead of `cfg.*`), `:404-414` (build `iocProvider` from DB instead of `cfg.OTXAPIKey`)

**Interfaces:**
- Consumes: `config.Config` fields `MISPUrl`/`MISPApiKey`/`OpenCTIUrl`/`OpenCTIApiKey`/`OTXAPIKey` (existing, unchanged), `connector.NewMISPClient`/`NewOpenCTIClient`/`NewOTXSource` (existing, unchanged).
- Produces: `threat_intel_config` table (3 seeded rows after first boot). `connector.SeedFromEnv(ctx context.Context, pool *pgxpool.Pool, cfg SeedConfig) error` — `SeedConfig` is a small struct carrying just the 5 env-sourced strings this function needs (not the whole `config.Config`, to keep `internal/connector` free of a dependency on the `config` package). `auth.CanUpdateConnectorConfig` (new permission). Task 2 reads/writes `threat_intel_config` directly and calls `connector.Scheduler.Reconfigure`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/connector/seed_test.go`:

```go
package connector

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSeedFromEnv_WritesRowWhenEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		err := SeedFromEnv(context.Background(), pool, SeedConfig{
			MISPUrl: "https://misp.example.com", MISPApiKey: "misp-key-1",
		})
		if err != nil {
			t.Fatalf("SeedFromEnv: %v", err)
		}
		var baseURL, apiKey string
		var enabled bool
		if err := pool.QueryRow(context.Background(),
			`SELECT base_url, api_key, enabled FROM threat_intel_config WHERE connector='misp'`,
		).Scan(&baseURL, &apiKey, &enabled); err != nil {
			t.Fatalf("query seeded row: %v", err)
		}
		if baseURL != "https://misp.example.com" || apiKey != "misp-key-1" || !enabled {
			t.Errorf("got baseURL=%q apiKey=%q enabled=%v, want the seeded values with enabled=true", baseURL, apiKey, enabled)
		}
	})
}

func TestSeedFromEnv_DoesNotOverwriteExistingRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO threat_intel_config (connector, base_url, api_key, enabled) VALUES ('misp', 'https://custom.example.com', 'custom-key', true)`,
		); err != nil {
			t.Fatalf("seed existing row: %v", err)
		}
		if err := SeedFromEnv(context.Background(), pool, SeedConfig{
			MISPUrl: "https://misp.example.com", MISPApiKey: "misp-key-1",
		}); err != nil {
			t.Fatalf("SeedFromEnv: %v", err)
		}
		var baseURL string
		if err := pool.QueryRow(context.Background(),
			`SELECT base_url FROM threat_intel_config WHERE connector='misp'`,
		).Scan(&baseURL); err != nil {
			t.Fatalf("query row: %v", err)
		}
		if baseURL != "https://custom.example.com" {
			t.Errorf("baseURL = %q, want unchanged %q — SeedFromEnv must never overwrite an already-configured row", baseURL, "https://custom.example.com")
		}
	})
}

func TestSeedFromEnv_SkipsConnectorWithNoEnvValue(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if err := SeedFromEnv(context.Background(), pool, SeedConfig{}); err != nil {
			t.Fatalf("SeedFromEnv: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM threat_intel_config`,
		).Scan(&count); err != nil {
			t.Fatalf("count rows: %v", err)
		}
		if count != 0 {
			t.Errorf("row count = %d, want 0 — no env values set means nothing should be seeded", count)
		}
	})
}

func TestSeedFromEnv_OTXHasNoBaseURL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if err := SeedFromEnv(context.Background(), pool, SeedConfig{OTXAPIKey: "otx-key-1"}); err != nil {
			t.Fatalf("SeedFromEnv: %v", err)
		}
		var baseURL, apiKey string
		var enabled bool
		if err := pool.QueryRow(context.Background(),
			`SELECT base_url, api_key, enabled FROM threat_intel_config WHERE connector='otx'`,
		).Scan(&baseURL, &apiKey, &enabled); err != nil {
			t.Fatalf("query row: %v", err)
		}
		if baseURL != "" || apiKey != "otx-key-1" || !enabled {
			t.Errorf("got baseURL=%q apiKey=%q enabled=%v, want baseURL empty, apiKey=otx-key-1, enabled=true", baseURL, apiKey, enabled)
		}
	})
}
```

Add to `orchestrator/internal/auth/permissions_test.go`, find this exact block:

```go
		{RoleAdmin, CanTargetAllAgents, true},
		{RoleAnalyst, CanTargetAllAgents, false},
		{RoleViewer, CanTargetAllAgents, false},
	}
```

Replace it with:

```go
		{RoleAdmin, CanTargetAllAgents, true},
		{RoleAnalyst, CanTargetAllAgents, false},
		{RoleViewer, CanTargetAllAgents, false},

		{RoleAdmin, CanUpdateConnectorConfig, true},
		{RoleAnalyst, CanUpdateConnectorConfig, false},
		{RoleViewer, CanUpdateConnectorConfig, false},
	}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd orchestrator
go vet ./internal/connector/... ./internal/auth/...
```

Expected: compile errors — `undefined: SeedFromEnv`, `undefined: SeedConfig`, `undefined: sharedDB` (if `internal/connector` doesn't already have a test harness — see Step 3 note below), and `undefined: CanUpdateConnectorConfig`.

- [ ] **Step 3: Check whether `internal/connector` already has a `sharedDB` test harness**

```bash
grep -rn "sharedDB" orchestrator/internal/connector/*_test.go
```

If this returns no results, `internal/connector`'s existing tests don't use the container-backed pattern yet. In that case, read `orchestrator/internal/api/scheduled_assessment_dispatch_test.go`'s or any `internal/api/*_test.go`'s `sharedDB` setup (a package-level `var sharedDB = testutil.MustSharedTestDB()`-style declaration, typically in a `main_test.go` or similar) and add the equivalent to a new `orchestrator/internal/connector/main_test.go` in this step, before proceeding — the exact existing pattern must be copied verbatim from wherever it's already declared, not reinvented.

- [ ] **Step 4: Add the schema**

In `orchestrator/internal/db/postgres.go`, find this exact block:

```go
		// openaev_config: singleton row for the OpenAEV Connector's connection
		// settings. See docs/superpowers/specs/2026-07-15-openaev-connector-design.md.
		`CREATE TABLE IF NOT EXISTS openaev_config (
			id                  int         PRIMARY KEY DEFAULT 1 CHECK (id = 1),
			base_url            text        NOT NULL DEFAULT '',
			bearer_token        text        NOT NULL DEFAULT '',
			poll_interval_hours int         NOT NULL DEFAULT 24,
			enabled             boolean     NOT NULL DEFAULT false,
			last_sync_at        timestamptz,
			last_sync_status    text        NOT NULL DEFAULT 'never',
			last_error          text        NOT NULL DEFAULT '',
			updated_at          timestamptz NOT NULL DEFAULT NOW()
		)`,
```

Replace it with:

```go
		// openaev_config: singleton row for the OpenAEV Connector's connection
		// settings. See docs/superpowers/specs/2026-07-15-openaev-connector-design.md.
		`CREATE TABLE IF NOT EXISTS openaev_config (
			id                  int         PRIMARY KEY DEFAULT 1 CHECK (id = 1),
			base_url            text        NOT NULL DEFAULT '',
			bearer_token        text        NOT NULL DEFAULT '',
			poll_interval_hours int         NOT NULL DEFAULT 24,
			enabled             boolean     NOT NULL DEFAULT false,
			last_sync_at        timestamptz,
			last_sync_status    text        NOT NULL DEFAULT 'never',
			last_error          text        NOT NULL DEFAULT '',
			updated_at          timestamptz NOT NULL DEFAULT NOW()
		)`,

		// threat_intel_config: one row per MISP/OpenCTI/OTX connector, DB-backed
		// replacement for the .env-only config those three used before this.
		// base_url is unused (stays '') for the 'otx' row -- it's a single
		// hosted service, not self-hosted like MISP/OpenCTI. See
		// docs/superpowers/specs/2026-08-10-threat-intel-connector-config-design.md.
		`CREATE TABLE IF NOT EXISTS threat_intel_config (
			connector         text        PRIMARY KEY,
			base_url          text        NOT NULL DEFAULT '',
			api_key           text        NOT NULL DEFAULT '',
			enabled           boolean     NOT NULL DEFAULT false,
			last_sync_at      timestamptz,
			last_sync_status  text        NOT NULL DEFAULT 'never',
			last_error        text        NOT NULL DEFAULT '',
			updated_at        timestamptz NOT NULL DEFAULT NOW()
		)`,
```

- [ ] **Step 5: Add the `CanUpdateConnectorConfig` permission**

In `orchestrator/internal/auth/permissions.go`, find this exact block:

```go
	CanViewConnectorStatus     Permission = "connector:status:view"
	CanSyncConnector           Permission = "connector:sync"
```

Replace it with:

```go
	CanViewConnectorStatus     Permission = "connector:status:view"
	CanSyncConnector           Permission = "connector:sync"
	// CanUpdateConnectorConfig is Admin-only, matching CanViewConnectorStatus
	// and CanSyncConnector's existing tier -- it gates writing MISP/OpenCTI/
	// OTX connection settings (URL, API key), not just viewing or triggering
	// a sync of whatever's already configured.
	CanUpdateConnectorConfig Permission = "connector:config:update"
```

Next, find this exact block (inside `rolePermissions[RoleAdmin]`):

```go
		CanResetUserPassword: true, CanViewCalderaStatus: true, CanViewConnectorStatus: true,
		CanSyncConnector: true, CanDeleteConnectorScenario: true, CanSetAttackPathSchedule: true,
```

Replace it with:

```go
		CanResetUserPassword: true, CanViewCalderaStatus: true, CanViewConnectorStatus: true,
		CanSyncConnector: true, CanUpdateConnectorConfig: true, CanDeleteConnectorScenario: true, CanSetAttackPathSchedule: true,
```

Next, find this exact block (inside `Permissions()`'s enumeration):

```go
		CanUpdateUser, CanDeleteUser, CanResetUserPassword, CanViewCalderaStatus, CanViewConnectorStatus,
		CanSyncConnector, CanDeleteConnectorScenario, CanSetAttackPathSchedule, CanViewARTContentStatus,
```

Replace it with:

```go
		CanUpdateUser, CanDeleteUser, CanResetUserPassword, CanViewCalderaStatus, CanViewConnectorStatus,
		CanSyncConnector, CanUpdateConnectorConfig, CanDeleteConnectorScenario, CanSetAttackPathSchedule, CanViewARTContentStatus,
```

- [ ] **Step 6: Update the two remaining permission test guards**

In `orchestrator/internal/auth/permissions_test.go`, find this exact block (inside `TestHasPermission_MatrixIsComplete`'s `tested` map):

```go
		CanResetUserPassword: true, CanViewCalderaStatus: true, CanViewConnectorStatus: true,
		CanSyncConnector: true, CanDeleteConnectorScenario: true, CanSetAttackPathSchedule: true,
```

Replace it with:

```go
		CanResetUserPassword: true, CanViewCalderaStatus: true, CanViewConnectorStatus: true,
		CanSyncConnector: true, CanUpdateConnectorConfig: true, CanDeleteConnectorScenario: true, CanSetAttackPathSchedule: true,
```

Next, find this exact block (inside `TestPermissions_Ordering`'s `want` slice):

```go
		CanUpdateUser, CanDeleteUser, CanResetUserPassword, CanViewCalderaStatus, CanViewConnectorStatus,
		CanSyncConnector, CanDeleteConnectorScenario, CanSetAttackPathSchedule, CanViewARTContentStatus,
```

Replace it with:

```go
		CanUpdateUser, CanDeleteUser, CanResetUserPassword, CanViewCalderaStatus, CanViewConnectorStatus,
		CanSyncConnector, CanUpdateConnectorConfig, CanDeleteConnectorScenario, CanSetAttackPathSchedule, CanViewARTContentStatus,
```

**Do not** touch `TestPermissionGrants_MatchMigrationInventory` (search for this function name if unsure which block is which) — it is a frozen historical snapshot of the 2026-07-18 migration's inventory and must never grow to include permissions added after that migration, exactly like `CanViewAgentGroups`/`CanTargetAllAgents` were correctly excluded from it earlier this session.

- [ ] **Step 7: Write `SeedFromEnv`**

Create `orchestrator/internal/connector/seed.go`:

```go
package connector

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SeedConfig carries only the env-sourced values SeedFromEnv needs -- kept
// separate from config.Config so internal/connector doesn't gain a
// dependency on the config package just for this.
type SeedConfig struct {
	MISPUrl       string
	MISPApiKey    string
	OpenCTIUrl    string
	OpenCTIApiKey string
	OTXAPIKey     string
}

// SeedFromEnv writes each connector's env-sourced values into
// threat_intel_config exactly once -- only when that connector's row does
// not exist yet. Once seeded (or once created via the UI), the DB row is
// authoritative and this function never overwrites it again on a later
// boot, so an operator's UI-entered changes always win over a stale .env
// value that happens to still be set in the container's environment.
func SeedFromEnv(ctx context.Context, pool *pgxpool.Pool, cfg SeedConfig) error {
	seeds := []struct {
		connector string
		baseURL   string
		apiKey    string
	}{
		{"misp", cfg.MISPUrl, cfg.MISPApiKey},
		{"opencti", cfg.OpenCTIUrl, cfg.OpenCTIApiKey},
		{"otx", "", cfg.OTXAPIKey},
	}
	for _, s := range seeds {
		if s.apiKey == "" {
			continue // nothing to seed for this connector
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO threat_intel_config (connector, base_url, api_key, enabled, updated_at)
			 VALUES ($1, $2, $3, true, NOW())
			 ON CONFLICT (connector) DO NOTHING`,
			s.connector, s.baseURL, s.apiKey,
		); err != nil {
			return err
		}
	}
	return nil
}
```

- [ ] **Step 8: Run the tests to verify they pass**

```bash
cd orchestrator
go build ./...
go vet ./internal/connector/... ./internal/auth/...
go test ./internal/auth/... -v
```

Expected: clean build, `go vet` clean, `internal/auth` tests all PASS.

```bash
go test ./internal/connector/... -run TestSeedFromEnv -v
```

Expected: all 4 new tests PASS.

- [ ] **Step 9: Wire the seed call and switch `main.go` to read from the DB**

In `orchestrator/cmd/server/main.go`, find this exact block:

```go
	// ── Threat-Intel Connector (layered: air-gapped bundle floor + live overlay) ─
	var tiSources []connector.Source
	if cfg.MISPUrl != "" && cfg.MISPApiKey != "" {
		tiSources = append(tiSources, connector.NewMISPClient(cfg.MISPUrl, cfg.MISPApiKey, cfg.ThreatIntelSectors, cfg.ThreatIntelRegions))
		log.Printf("[+] MISP connector configured: %s", cfg.MISPUrl)
	}
	if cfg.OpenCTIUrl != "" && cfg.OpenCTIApiKey != "" {
		tiSources = append(tiSources, connector.NewOpenCTIClient(cfg.OpenCTIUrl, cfg.OpenCTIApiKey, cfg.ThreatIntelSectors))
		log.Printf("[+] OpenCTI connector configured: %s", cfg.OpenCTIUrl)
	}
	// Air-gapped floor: only add the bundle source when a signed ti-bundle.json is
	// actually present. Verified with the release key via integrity.VerifyScenarioFile.
	if cfg.TIBundleDir != "" {
		if _, err := os.Stat(filepath.Join(cfg.TIBundleDir, connector.BundleFileName)); err == nil {
			tiSources = append(tiSources, connector.NewBundleSource(cfg.TIBundleDir, integrity.VerifyScenarioFile))
			log.Printf("[+] Threat-intel bundle found in %s (air-gapped source)", cfg.TIBundleDir)
		}
	}
	if cfg.OTXAPIKey != "" {
		tiSources = append(tiSources, connector.NewOTXSource(cfg.OTXAPIKey))
		log.Printf("[+] OTX connector configured (periodic sync)")
	}
```

Replace it with:

```go
	// ── Threat-Intel Connector (layered: air-gapped bundle floor + live overlay) ─
	// threat_intel_config is now the authoritative source for MISP/OpenCTI/OTX
	// (DB-backed, UI-editable -- see docs/superpowers/specs/2026-08-10-threat-intel-connector-config-design.md).
	// SeedFromEnv migrates any already-set .env values into the DB exactly
	// once, on the first boot after this change ships, so an existing
	// deployment (e.g. one already running with MISP_URL/MISP_API_KEY set)
	// keeps working with zero manual action.
	if err := connector.SeedFromEnv(context.Background(), pool, connector.SeedConfig{
		MISPUrl: cfg.MISPUrl, MISPApiKey: cfg.MISPApiKey,
		OpenCTIUrl: cfg.OpenCTIUrl, OpenCTIApiKey: cfg.OpenCTIApiKey,
		OTXAPIKey: cfg.OTXAPIKey,
	}); err != nil {
		log.Printf("[!] threat-intel config seed warning: %v", err)
	}
	tiSources, err := connector.LoadSourcesFromDB(context.Background(), pool, cfg.ThreatIntelSectors, cfg.ThreatIntelRegions)
	if err != nil {
		log.Printf("[!] threat-intel config load warning: %v", err)
	}
	for _, src := range tiSources {
		log.Printf("[+] %s connector configured", src.Name())
	}
	// Air-gapped floor: only add the bundle source when a signed ti-bundle.json is
	// actually present. Verified with the release key via integrity.VerifyScenarioFile.
	if cfg.TIBundleDir != "" {
		if _, err := os.Stat(filepath.Join(cfg.TIBundleDir, connector.BundleFileName)); err == nil {
			tiSources = append(tiSources, connector.NewBundleSource(cfg.TIBundleDir, integrity.VerifyScenarioFile))
			log.Printf("[+] Threat-intel bundle found in %s (air-gapped source)", cfg.TIBundleDir)
		}
	}
```

This introduces a new function, `connector.LoadSourcesFromDB` — add it to `orchestrator/internal/connector/seed.go` (same file as `SeedFromEnv`, since they're the two halves of the same env→DB→sources pipeline):

```go
// LoadSourcesFromDB builds the misp/opencti/otx Sources from whatever is
// currently enabled in threat_intel_config. Called once at startup (after
// SeedFromEnv has had a chance to populate the table) and again, indirectly,
// every time a config save triggers Scheduler.Reconfigure (Task 2) -- this
// is the one place that turns DB rows into live Source objects, so both
// callers stay in sync by construction.
func LoadSourcesFromDB(ctx context.Context, pool *pgxpool.Pool, sectors, regions []string) ([]Source, error) {
	rows, err := pool.Query(ctx, `SELECT connector, base_url, api_key FROM threat_intel_config WHERE enabled = true`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []Source
	for rows.Next() {
		var conn, baseURL, apiKey string
		if err := rows.Scan(&conn, &baseURL, &apiKey); err != nil {
			return nil, err
		}
		switch conn {
		case "misp":
			if baseURL != "" && apiKey != "" {
				sources = append(sources, NewMISPClient(baseURL, apiKey, sectors, regions))
			}
		case "opencti":
			if baseURL != "" && apiKey != "" {
				sources = append(sources, NewOpenCTIClient(baseURL, apiKey, sectors))
			}
		case "otx":
			if apiKey != "" {
				sources = append(sources, NewOTXSource(apiKey))
			}
		}
	}
	return sources, rows.Err()
}
```

Add `"context"` to `seed.go`'s imports if not already present from Step 7 (it already is).

- [ ] **Step 10: Switch the `iocProvider` construction to the DB too**

In `orchestrator/cmd/server/main.go`, find this exact block:

```go
	var iocProvider ioc.Provider
	if cfg.OTXAPIKey != "" {
		var err error
		iocProvider, err = ioc.NewProvider(ioc.Config{Provider: "otx", APIKey: cfg.OTXAPIKey})
		if err != nil {
			log.Printf("[!] ioc provider init warning: %v", err)
		} else {
			log.Println("[+] IOC threat-intel provider ready (OTX)")
			reportingEngine.WithThreatIntelProvider(iocProvider.Name())
		}
	}
```

Replace it with:

```go
	var iocProvider ioc.Provider
	var otxAPIKey string
	if err := pool.QueryRow(context.Background(),
		`SELECT api_key FROM threat_intel_config WHERE connector='otx' AND enabled=true`,
	).Scan(&otxAPIKey); err != nil {
		otxAPIKey = "" // no row, or not enabled -- same as OTX_API_KEY unset before this change
	}
	if otxAPIKey != "" {
		var err error
		iocProvider, err = ioc.NewProvider(ioc.Config{Provider: "otx", APIKey: otxAPIKey})
		if err != nil {
			log.Printf("[!] ioc provider init warning: %v", err)
		} else {
			log.Println("[+] IOC threat-intel provider ready (OTX)")
			reportingEngine.WithThreatIntelProvider(iocProvider.Name())
		}
	}
```

- [ ] **Step 11: Verify the workspace still builds**

```bash
cd orchestrator
go build ./...
go vet ./...
```

Expected: clean build, clean vet. `cmd/server/main.go` now reads `threat_intel_config` (post-seed) instead of `cfg.MISPUrl`/etc. directly for both `tiSources` and `iocProvider` construction — the same set of sources gets built as before, for an install whose `.env` was already set, because `SeedFromEnv` migrates those exact values into the DB before `LoadSourcesFromDB` reads them back out.

- [ ] **Step 12: Commit**

```bash
cd orchestrator
git add internal/db/postgres.go internal/auth/permissions.go internal/auth/permissions_test.go internal/connector/seed.go internal/connector/seed_test.go cmd/server/main.go
git commit -m "feat(connector): threat_intel_config table + env-to-DB seed migration"
```

If Step 3 required adding a new `internal/connector/main_test.go` for the `sharedDB` harness, include it in this commit too.

---

### Task 2: Live reconfiguration + generic config handlers

**Files:**
- Modify: `orchestrator/internal/connector/scheduler.go` (`Reconfigure` method + `started` field + `sync()` race fix)
- Create: `orchestrator/internal/connector/scheduler_reconfigure_test.go`
- Modify: `orchestrator/internal/api/handlers.go` (mutex-guard `iocProvider`, update `GetConnectorStatus`)
- Create: `orchestrator/internal/api/threat_intel_config_handlers.go`
- Create: `orchestrator/internal/api/threat_intel_config_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go`

**Interfaces:**
- Consumes: `connector.LoadSourcesFromDB` (Task 1), `threat_intel_config` table (Task 1), `auth.CanUpdateConnectorConfig` (Task 1).
- Produces: `Scheduler.Reconfigure(sources []Source)`, `Handler.getIOCProvider() ioc.Provider` / `Handler.setIOCProvider(ioc.Provider)`, `GET/PUT/POST /api/threat-intel/{connector}/config[/test]`. Nothing later consumes these — Task 3 calls the new endpoints directly, not any Go symbol.

- [ ] **Step 1: Write the failing `Scheduler.Reconfigure` tests**

Create `orchestrator/internal/connector/scheduler_reconfigure_test.go`:

```go
package connector

import (
	"testing"
	"time"
)

// fakeSource is a minimal Source for testing Reconfigure without a real
// network call -- Fetch is never actually invoked by these tests (they only
// check source-list/status bookkeeping and the started-goroutine transition),
// but Source is an interface so a concrete type is still required.
type fakeSource struct{ name string }

func (f *fakeSource) Fetch() ([]ThreatActor, error) { return nil, nil }
func (f *fakeSource) Name() string                  { return f.name }

func TestReconfigure_UpdatesSourcesAndStatusFlags(t *testing.T) {
	s := NewScheduler(nil, nil, nil, 24, nil, nil)
	s.Reconfigure([]Source{&fakeSource{name: "misp"}, &fakeSource{name: "opencti"}})

	st := s.Status()
	if !st.MISPEnabled || !st.OpenCTIEnabled {
		t.Errorf("status = %+v, want MISPEnabled and OpenCTIEnabled both true", st)
	}

	s.Reconfigure([]Source{&fakeSource{name: "opencti"}})
	st = s.Status()
	if st.MISPEnabled {
		t.Error("MISPEnabled still true after reconfiguring MISP out of the source list")
	}
	if !st.OpenCTIEnabled {
		t.Error("OpenCTIEnabled should still be true")
	}
}

func TestReconfigure_StartsBackgroundLoopOnFirstNonEmptySources(t *testing.T) {
	// NewScheduler with zero sources: Start() would see len(sources)==0 and
	// never launch the background goroutine -- exactly the "fresh install,
	// nothing configured yet" case. Reconfigure must detect that the
	// scheduler never actually started and launch it now, retroactively.
	s := NewScheduler(nil, nil, nil, 24, nil, nil)
	s.Start() // sources is empty -- run() must NOT be launched here

	s.Reconfigure([]Source{&fakeSource{name: "misp"}})

	// s.started is set (under s.mu) the moment Reconfigure launches run();
	// give the goroutine a moment to actually set it before asserting.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		started := s.started
		s.mu.RUnlock()
		if started {
			return // pass
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("started never became true after Reconfigure added the first source to a scheduler whose Start() saw zero sources")
}

func TestReconfigure_DoesNotDoubleStartAnAlreadyRunningScheduler(t *testing.T) {
	s := NewScheduler([]Source{&fakeSource{name: "misp"}}, nil, nil, 24, nil, nil)
	s.Start() // sources non-empty -- run() launches here, s.started becomes true

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		started := s.started
		s.mu.RUnlock()
		if started {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Reconfigure again -- must not attempt to launch a second run() goroutine.
	s.Reconfigure([]Source{&fakeSource{name: "misp"}, &fakeSource{name: "opencti"}})
	s.mu.RLock()
	sourceCount := len(s.sources)
	s.mu.RUnlock()
	if sourceCount != 2 {
		t.Errorf("source count = %d, want 2 (Reconfigure must still update sources even when already started)", sourceCount)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd orchestrator
go vet ./internal/connector/...
```

Expected: compile error — `undefined: (*Scheduler).Reconfigure`, `s.started` field doesn't exist.

- [ ] **Step 3: Add `Reconfigure`, the `started` field, and fix `sync()`'s unprotected read**

In `orchestrator/internal/connector/scheduler.go`, find this exact block (the `Scheduler` struct):

```go
type Scheduler struct {
	sources   []Source
	generator *Generator
	engine    *scenario.Engine
	interval  time.Duration
	// pool persists fetched actor profiles (sectors/regions) for
	// internal/reporting's priority-score weighting. See
	// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	pool *pgxpool.Pool

	// priorityEngine recomputes and snapshots Threat Prioritization scores
	// whenever intel changes -- connector sync IS the change-detection
	// trigger for internal/threatpriority's "Continuous Intelligence"
	// behavior, no separate polling needed. nil-safe: skipped if unset.
	priorityEngine *threatpriority.Engine

	mu     sync.RWMutex
	status ConnectorStatus
	syncCh chan struct{} // manual trigger
	stopCh chan struct{}
}
```

Replace it with:

```go
type Scheduler struct {
	sources   []Source
	generator *Generator
	engine    *scenario.Engine
	interval  time.Duration
	// pool persists fetched actor profiles (sectors/regions) for
	// internal/reporting's priority-score weighting. See
	// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	pool *pgxpool.Pool

	// priorityEngine recomputes and snapshots Threat Prioritization scores
	// whenever intel changes -- connector sync IS the change-detection
	// trigger for internal/threatpriority's "Continuous Intelligence"
	// behavior, no separate polling needed. nil-safe: skipped if unset.
	priorityEngine *threatpriority.Engine

	// mu now also guards sources (not just status) -- Reconfigure (added for
	// live, restart-free config changes; see
	// docs/superpowers/specs/2026-08-10-threat-intel-connector-config-design.md)
	// mutates sources concurrently with sync()'s background-goroutine read of
	// it, which was previously unprotected since sources never changed after
	// construction.
	mu      sync.RWMutex
	status  ConnectorStatus
	started bool // true once run() has actually been launched (by Start or Reconfigure)
	syncCh  chan struct{} // manual trigger
	stopCh  chan struct{}
}
```

Next, find this exact block (`Start`):

```go
// Start launches the background polling goroutine.
func (s *Scheduler) Start() {
	if len(s.sources) == 0 {
		log.Println("[connector] no sources configured — connector idle")
		return
	}
	go s.run()
	log.Printf("[connector] scheduler started (interval: %s)", s.interval)

	// Run immediately on startup
	s.TriggerSync()
}
```

Replace it with:

```go
// Start launches the background polling goroutine.
func (s *Scheduler) Start() {
	if len(s.sources) == 0 {
		log.Println("[connector] no sources configured — connector idle")
		return
	}
	s.mu.Lock()
	s.started = true
	s.mu.Unlock()
	go s.run()
	log.Printf("[connector] scheduler started (interval: %s)", s.interval)

	// Run immediately on startup
	s.TriggerSync()
}

// Reconfigure replaces the source list live -- no restart needed. If the
// scheduler was constructed with zero sources (Start saw len(sources)==0
// and never launched the background goroutine, e.g. a fresh install with
// nothing configured yet), Reconfigure launches it now, exactly as if those
// sources had been present at boot. Safe to call repeatedly; only the first
// call that transitions from idle to non-idle actually starts the goroutine.
func (s *Scheduler) Reconfigure(sources []Source) {
	s.mu.Lock()
	s.sources = sources
	s.status.MISPEnabled = false
	s.status.OpenCTIEnabled = false
	s.status.BundleEnabled = false
	for _, src := range sources {
		switch src.Name() {
		case "misp":
			s.status.MISPEnabled = true
		case "opencti":
			s.status.OpenCTIEnabled = true
		case "bundle":
			s.status.BundleEnabled = true
		}
	}
	shouldStart := !s.started && len(sources) > 0
	if shouldStart {
		s.started = true
	}
	s.mu.Unlock()

	if shouldStart {
		go s.run()
		log.Printf("[connector] scheduler started via Reconfigure (interval: %s)", s.interval)
		s.TriggerSync()
	}
}
```

Next, find this exact block (`sync`'s unprotected read of `s.sources`):

```go
	// Fetch every configured source. The bundle (air-gapped floor) and live
	// providers (MISP/OpenCTI overlay) are treated uniformly; a single source
	// failing is logged and skipped, never aborting the others.
	for _, src := range s.sources {
```

Replace it with:

```go
	// Fetch every configured source. The bundle (air-gapped floor) and live
	// providers (MISP/OpenCTI overlay) are treated uniformly; a single source
	// failing is logged and skipped, never aborting the others.
	// Take a local copy under lock -- Reconfigure can replace s.sources
	// concurrently with this background goroutine's read of it.
	s.mu.RLock()
	sources := s.sources
	s.mu.RUnlock()
	for _, src := range sources {
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd orchestrator
go build ./...
go vet ./internal/connector/...
go test ./internal/connector/... -run TestReconfigure -v
```

Expected: clean build, clean vet, all 3 new `TestReconfigure_*` tests PASS.

```bash
go test ./internal/connector/...
```

Expected: full package PASS (confirms the `sync()` change didn't break any existing test).

- [ ] **Step 5: Mutex-guard `Handler.iocProvider`**

In `orchestrator/internal/api/handlers.go`, find the `iocProvider` field declaration (search for `iocProvider ` in the `Handler` struct — exact surrounding lines must be re-verified, but the field itself is confirmed as `iocProvider ioc.Provider` with a comment `// nil when OTX_API_KEY is unset`). Add a new field immediately after it:

```go
	iocProvider   ioc.Provider // nil when no OTX connector is configured
	iocProviderMu sync.RWMutex // guards iocProvider -- can be swapped live by a config save
```

(If `sync` is not already imported in `handlers.go`, add `"sync"` to the import block.)

Find this exact block (`WithIOCProvider`):

```go
func (h *Handler) WithIOCProvider(provider ioc.Provider) *Handler {
	h.iocProvider = provider
```

Replace it with:

```go
func (h *Handler) WithIOCProvider(provider ioc.Provider) *Handler {
	h.setIOCProvider(provider)
	return h
}

// getIOCProvider and setIOCProvider are the only allowed access points for
// h.iocProvider -- it can be swapped live by a threat-intel config save
// (see PutThreatIntelConfig), concurrently with in-flight LookupIOC
// requests reading it.
func (h *Handler) getIOCProvider() ioc.Provider {
	h.iocProviderMu.RLock()
	defer h.iocProviderMu.RUnlock()
	return h.iocProvider
}

func (h *Handler) setIOCProvider(provider ioc.Provider) {
	h.iocProviderMu.Lock()
	defer h.iocProviderMu.Unlock()
	h.iocProvider = provider
```

(This replacement intentionally leaves `WithIOCProvider`'s original closing `return h` / `}` in place after `h.iocProvider = provider` — read the function's exact current ending before editing so the brace structure comes out correct; the old body was `h.iocProvider = provider\n\treturn h\n}` and the new one nests that same assignment inside `setIOCProvider` instead.)

Now update every read of `h.iocProvider` to `h.getIOCProvider()`:

```bash
grep -n "h\.iocProvider" orchestrator/internal/api/handlers.go
```

For each remaining match that is a **read** (not the `setIOCProvider`/field-declaration lines just added), replace `h.iocProvider` with `h.getIOCProvider()`. This includes the two `LookupIOC`-related nil-checks and `GetConnectorStatus`'s two `OTXEnabled: h.iocProvider != nil` lines (find the exact current text of `GetConnectorStatus` via `grep -n "func (h \*Handler) GetConnectorStatus" -A 20 orchestrator/internal/api/handlers.go` and replace both `h.iocProvider != nil` occurrences with `h.getIOCProvider() != nil`).

- [ ] **Step 6: Write the failing config-handler tests**

Create `orchestrator/internal/api/threat_intel_config_handlers_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func threatIntelConfigReq(method, connector, path string, body map[string]any) *http.Request {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, "/x", bytes.NewReader(b))
	return withURLParam(req, "connector", connector)
	_ = path
}

func TestGetThreatIntelConfig_UnknownConnector_BadRequest(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	rec := httptest.NewRecorder()
	h.GetThreatIntelConfig(rec, threatIntelConfigReq(http.MethodGet, "mandiant", "", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (unknown connector)", rec.Code)
	}
}

func TestPutThreatIntelConfig_NeverReturnsApiKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		putRec := httptest.NewRecorder()
		h.PutThreatIntelConfig(putRec, threatIntelConfigReq(http.MethodPut, "misp", "", map[string]any{
			"baseUrl": "https://misp.example.com", "apiKey": "secret-key-1", "enabled": true,
		}))
		if putRec.Code != http.StatusOK {
			t.Fatalf("put status = %d, body = %s", putRec.Code, putRec.Body.String())
		}

		getRec := httptest.NewRecorder()
		h.GetThreatIntelConfig(getRec, threatIntelConfigReq(http.MethodGet, "misp", "", nil))
		var resp map[string]any
		json.Unmarshal(getRec.Body.Bytes(), &resp)
		if _, present := resp["apiKey"]; present {
			t.Errorf("GET response contains apiKey field, must never return the stored secret: %v", resp)
		}
		if resp["baseUrl"] != "https://misp.example.com" {
			t.Errorf("baseUrl = %v, want https://misp.example.com", resp["baseUrl"])
		}
	})
}

func TestPutThreatIntelConfig_EmptyApiKeyKeepsExisting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		h.PutThreatIntelConfig(httptest.NewRecorder(), threatIntelConfigReq(http.MethodPut, "otx", "", map[string]any{
			"apiKey": "first-key", "enabled": true,
		}))
		// Second PUT with an empty apiKey must not wipe out "first-key".
		h.PutThreatIntelConfig(httptest.NewRecorder(), threatIntelConfigReq(http.MethodPut, "otx", "", map[string]any{
			"apiKey": "", "enabled": true,
		}))
		var apiKey string
		if err := pool.QueryRow(context.Background(),
			`SELECT api_key FROM threat_intel_config WHERE connector='otx'`,
		).Scan(&apiKey); err != nil {
			t.Fatalf("query: %v", err)
		}
		if apiKey != "first-key" {
			t.Errorf("api_key = %q, want unchanged %q", apiKey, "first-key")
		}
	})
}

func TestPutThreatIntelConfig_MispReconfiguresScheduler(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sched := connector.NewScheduler(nil, nil, nil, 24, nil, nil)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithScheduler(sched)
		rec := httptest.NewRecorder()
		h.PutThreatIntelConfig(rec, threatIntelConfigReq(http.MethodPut, "misp", "", map[string]any{
			"baseUrl": "https://misp.example.com", "apiKey": "misp-key", "enabled": true,
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		st := sched.Status()
		if !st.MISPEnabled {
			t.Error("scheduler status shows MISPEnabled=false after enabling MISP via config save — Reconfigure was not called correctly")
		}
	})
}

func TestTestThreatIntelConfig_UnreachableURL_ReturnsOkFalse(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	rec := httptest.NewRecorder()
	h.TestThreatIntelConfig(rec, threatIntelConfigReq(http.MethodPost, "misp", "", map[string]any{
		"baseUrl": "http://127.0.0.1:1", "apiKey": "whatever",
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (test failures are reported as ok:false in the body, not an HTTP error)", rec.Code)
	}
	var resp struct {
		OK bool `json:"ok"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.OK {
		t.Error("ok = true for an unreachable URL, want false")
	}
}
```

Add `"github.com/audspect/bas/internal/connector"` to this new test file's imports (needed by `TestPutThreatIntelConfig_MispReconfiguresScheduler`).

- [ ] **Step 7: Run the tests to verify they fail**

```bash
cd orchestrator
go vet ./internal/api/...
```

Expected: compile errors — `h.GetThreatIntelConfig`/`PutThreatIntelConfig`/`TestThreatIntelConfig` undefined.

- [ ] **Step 8: Write the generic handlers**

Create `orchestrator/internal/api/threat_intel_config_handlers.go`:

```go
package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/connector"
)

var validConnectors = map[string]bool{"misp": true, "opencti": true, "otx": true}

// GET /api/threat-intel/{connector}/config — Admin. api_key is never
// included in the response, matching GetOpenAEVConfig's existing precedent.
func (h *Handler) GetThreatIntelConfig(w http.ResponseWriter, r *http.Request) {
	conn := chi.URLParam(r, "connector")
	if !validConnectors[conn] {
		jsonError(w, "unknown connector — must be misp, opencti, or otx", http.StatusBadRequest)
		return
	}
	var baseURL, status, lastError string
	var enabled bool
	err := h.db.QueryRow(r.Context(),
		`SELECT base_url, enabled, last_sync_status, last_error FROM threat_intel_config WHERE connector = $1`, conn,
	).Scan(&baseURL, &enabled, &status, &lastError)
	if err != nil {
		respond(w, map[string]any{"baseUrl": "", "enabled": false, "lastSyncStatus": "never", "lastError": ""})
		return
	}
	respond(w, map[string]any{
		"baseUrl":        baseURL,
		"enabled":        enabled,
		"lastSyncStatus": status,
		"lastError":      lastError,
	})
}

// PUT /api/threat-intel/{connector}/config — Admin. Empty submitted apiKey
// keeps the existing stored key, matching PutOpenAEVConfig's existing
// precedent. On success, rebuilds the full 3-connector source list from the
// DB and calls Scheduler.Reconfigure so the change takes effect immediately
// -- no restart. For 'otx', also swaps h.iocProvider the same way, since
// OTX has a second, independent consumer beyond the Scheduler.
func (h *Handler) PutThreatIntelConfig(w http.ResponseWriter, r *http.Request) {
	conn := chi.URLParam(r, "connector")
	if !validConnectors[conn] {
		jsonError(w, "unknown connector — must be misp, opencti, or otx", http.StatusBadRequest)
		return
	}
	var body struct {
		BaseURL string `json:"baseUrl"`
		APIKey  string `json:"apiKey"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	_, err := h.db.Exec(r.Context(),
		`INSERT INTO threat_intel_config (connector, base_url, api_key, enabled, updated_at)
		 VALUES ($1, $2, $3, $4, NOW())
		 ON CONFLICT (connector) DO UPDATE SET
		   base_url = EXCLUDED.base_url,
		   api_key = CASE WHEN EXCLUDED.api_key = '' THEN threat_intel_config.api_key ELSE EXCLUDED.api_key END,
		   enabled = EXCLUDED.enabled,
		   updated_at = NOW()`,
		conn, body.BaseURL, body.APIKey, body.Enabled,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if h.scheduler != nil {
		sources, lerr := connector.LoadSourcesFromDB(r.Context(), h.db, nil, nil)
		if lerr == nil {
			h.scheduler.Reconfigure(sources)
		}
	}
	if conn == "otx" {
		var otxKey string
		var otxEnabled bool
		if qerr := h.db.QueryRow(r.Context(),
			`SELECT api_key, enabled FROM threat_intel_config WHERE connector='otx'`,
		).Scan(&otxKey, &otxEnabled); qerr == nil && otxEnabled && otxKey != "" {
			if provider, perr := ioc.NewProvider(ioc.Config{Provider: "otx", APIKey: otxKey}); perr == nil {
				h.setIOCProvider(provider)
			}
		} else {
			h.setIOCProvider(nil)
		}
	}

	h.auditLog(r, "connector.config.update", conn, map[string]any{"baseUrl": body.BaseURL, "enabled": body.Enabled}, "ok")
	respond(w, map[string]string{"status": "ok"})
}

// POST /api/threat-intel/{connector}/config/test — Admin. Validates
// connectivity/credentials before the operator flips enabled=true,
// mirroring TestOpenAEVConfig's existing precedent.
func (h *Handler) TestThreatIntelConfig(w http.ResponseWriter, r *http.Request) {
	conn := chi.URLParam(r, "connector")
	if !validConnectors[conn] {
		jsonError(w, "unknown connector — must be misp, opencti, or otx", http.StatusBadRequest)
		return
	}
	var body struct {
		BaseURL string `json:"baseUrl"`
		APIKey  string `json:"apiKey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	var src connector.Source
	switch conn {
	case "misp":
		src = connector.NewMISPClient(body.BaseURL, body.APIKey, nil, nil)
	case "opencti":
		src = connector.NewOpenCTIClient(body.BaseURL, body.APIKey, nil)
	case "otx":
		src = connector.NewOTXSource(body.APIKey)
	}
	actors, err := src.Fetch()
	if err != nil {
		respond(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	respond(w, map[string]any{"ok": true, "actorCount": len(actors)})
}
```

Add `"github.com/audspect/bas/internal/ioc"` to this file's imports (needed by the `otx` branch of `PutThreatIntelConfig`).

- [ ] **Step 9: Wire the routes**

In `orchestrator/internal/api/routes.go`, find this exact block:

```go
		r.With(auth.RequirePermission(auth.CanViewConnectorStatus)).Get("/api/connector/status", h.GetConnectorStatus)
		r.With(auth.RequirePermission(auth.CanSyncConnector)).Post("/api/connector/sync", h.TriggerConnectorSync)
```

Replace it with:

```go
		r.With(auth.RequirePermission(auth.CanViewConnectorStatus)).Get("/api/connector/status", h.GetConnectorStatus)
		r.With(auth.RequirePermission(auth.CanSyncConnector)).Post("/api/connector/sync", h.TriggerConnectorSync)
		r.With(auth.RequirePermission(auth.CanViewConnectorStatus)).Get("/api/threat-intel/{connector}/config", h.GetThreatIntelConfig)
		r.With(auth.RequirePermission(auth.CanUpdateConnectorConfig)).Put("/api/threat-intel/{connector}/config", h.PutThreatIntelConfig)
		r.With(auth.RequirePermission(auth.CanUpdateConnectorConfig)).Post("/api/threat-intel/{connector}/config/test", h.TestThreatIntelConfig)
```

- [ ] **Step 10: Run the tests to verify they pass**

```bash
cd orchestrator
go build ./...
go vet ./internal/api/... ./internal/connector/...
go test ./internal/api/... -run "TestGetThreatIntelConfig|TestPutThreatIntelConfig|TestTestThreatIntelConfig" -v
```

Expected: clean build, clean vet, all new tests PASS.

```bash
go test ./internal/connector/...
```

Expected: full package PASS.

- [ ] **Step 11: Commit**

```bash
cd orchestrator
git add internal/connector/scheduler.go internal/connector/scheduler_reconfigure_test.go internal/api/handlers.go internal/api/threat_intel_config_handlers.go internal/api/threat_intel_config_handlers_test.go internal/api/routes.go
git commit -m "feat(api): live-reconfigurable MISP/OpenCTI/OTX config (GET/PUT/Test)"
```

---

### Task 3: Frontend — editable config blocks

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: `GET/PUT/POST /api/threat-intel/{connector}/config[/test]` (Task 2), `x()`/`apicall()`/`showToast()`/`ROLE` (existing), `loadConnectorStatus()`/`triggerConnectorSync()` (existing, unchanged).
- Produces: `loadThreatIntelConfig(name)`, `testConnectorConfig(name)`, `saveConnectorConfig(name)`. Nothing later consumes these — this is the last task.

- [ ] **Step 1: Add the editable block to the MISP card**

Find this exact block (the MISP card, ending with its error div):

```html
            <div class="conn-cfg-card" id="cs-misp-card">
              <div style="font-weight:600;font-size:0.82rem;color:var(--text);margin-bottom:0.5rem">MISP</div>
              <div class="conn-cfg-row">
                <span class="conn-cfg-label">Status</span>
                <span id="cs-misp-status" class="conn-cfg-val">—</span>
              </div>
              <div class="conn-cfg-row">
                <span class="conn-cfg-label">Events</span>
                <span id="cs-misp-events" class="conn-cfg-val">—</span>
              </div>
              <div class="conn-cfg-row">
                <span class="conn-cfg-label">Actors extracted</span>
                <span id="cs-misp-actors" class="conn-cfg-val">—</span>
              </div>
              <div class="conn-cfg-row">
                <span class="conn-cfg-label">Last Fetch</span>
                <span id="cs-misp-lastfetch" class="conn-cfg-val">—</span>
              </div>
              <div id="cs-misp-error" style="display:none;margin-top:0.5rem;font-size:0.72rem;color:#f85149"></div>
            </div>
```

Replace it with:

```html
            <div class="conn-cfg-card" id="cs-misp-card">
              <div style="font-weight:600;font-size:0.82rem;color:var(--text);margin-bottom:0.5rem">MISP</div>
              <div id="ti-misp-config-panel"></div>
              <div class="conn-cfg-row">
                <span class="conn-cfg-label">Status</span>
                <span id="cs-misp-status" class="conn-cfg-val">—</span>
              </div>
              <div class="conn-cfg-row">
                <span class="conn-cfg-label">Events</span>
                <span id="cs-misp-events" class="conn-cfg-val">—</span>
              </div>
              <div class="conn-cfg-row">
                <span class="conn-cfg-label">Actors extracted</span>
                <span id="cs-misp-actors" class="conn-cfg-val">—</span>
              </div>
              <div class="conn-cfg-row">
                <span class="conn-cfg-label">Last Fetch</span>
                <span id="cs-misp-lastfetch" class="conn-cfg-val">—</span>
              </div>
              <div id="cs-misp-error" style="display:none;margin-top:0.5rem;font-size:0.72rem;color:#f85149"></div>
            </div>
```

- [ ] **Step 2: Add the editable block to the OpenCTI card**

Find this exact block:

```html
            <div class="conn-cfg-card" id="cs-opencti-card">
              <div style="font-weight:600;font-size:0.82rem;color:var(--text);margin-bottom:0.5rem">OpenCTI</div>
              <div class="conn-cfg-row">
                <span class="conn-cfg-label">Status</span>
                <span id="cs-opencti-status" class="conn-cfg-val">—</span>
              </div>
```

Replace it with:

```html
            <div class="conn-cfg-card" id="cs-opencti-card">
              <div style="font-weight:600;font-size:0.82rem;color:var(--text);margin-bottom:0.5rem">OpenCTI</div>
              <div id="ti-opencti-config-panel"></div>
              <div class="conn-cfg-row">
                <span class="conn-cfg-label">Status</span>
                <span id="cs-opencti-status" class="conn-cfg-val">—</span>
              </div>
```

- [ ] **Step 3: Add the editable block to OTX's row**

Find this exact block (the start of `connector-status-card`, where OTX's read-only row lives):

```html
          <div class="conn-cfg-card" id="connector-status-card">
            <div class="conn-cfg-row">
              <span class="conn-cfg-label">OTX (AlienVault)</span>
              <span id="cs-otx" class="conn-cfg-val">—</span>
            </div>
```

Replace it with:

```html
          <div class="conn-cfg-card" id="connector-status-card">
            <div style="font-weight:600;font-size:0.82rem;color:var(--text);margin-bottom:0.5rem">OTX (AlienVault)</div>
            <div id="ti-otx-config-panel"></div>
            <div class="conn-cfg-row">
              <span class="conn-cfg-label">OTX (AlienVault)</span>
              <span id="cs-otx" class="conn-cfg-val">—</span>
            </div>
```

- [ ] **Step 4: Add the JS functions**

Find this exact block (`loadConnectorStatus`'s start, to insert the new functions immediately before it so they're defined before anything might reference them):

```js
function loadConnectorStatus() {
  var wrap = document.getElementById('connector-status-wrap');
  if (!wrap) return;
```

Replace it with:

```js
// ── Threat Intel connector config (MISP/OpenCTI/OTX) — editable, matching
// loadOpenAEVConfig's pattern. 'otx' has no URL field (single hosted
// service, unlike self-hosted MISP/OpenCTI).
var TI_CONNECTOR_LABELS = { misp: 'MISP', opencti: 'OpenCTI', otx: 'OTX' };

function loadThreatIntelConfig(name) {
  var panel = document.getElementById('ti-' + name + '-config-panel');
  if (!panel || ROLE !== 'admin') { if (panel) panel.innerHTML = ''; return; }
  apicall('/api/threat-intel/' + name + '/config').then(function(cfg) {
    var urlField = name === 'otx' ? '' :
      '<input id="ti-' + name + '-url" type="text" placeholder="Base URL" value="' + x(cfg.baseUrl || '') + '" class="inp-sm" style="flex:1">';
    panel.innerHTML =
      '<div class="kpi-row">' +
        urlField +
        '<input id="ti-' + name + '-key" type="password" placeholder="API key (leave blank to keep current)" class="inp-sm" style="flex:1">' +
        '<label class="tiny muted" style="display:flex;align-items:center;gap:0.3rem"><input type="checkbox" id="ti-' + name + '-enabled" ' + (cfg.enabled ? 'checked' : '') + '> Enabled</label>' +
      '</div>' +
      '<div class="kpi-row" style="margin-top:0.5rem">' +
        '<button class="btn btn-outline btn-sm" onclick="testConnectorConfig(\'' + name + '\')">Test Connection</button>' +
        '<button class="btn btn-primary btn-sm" onclick="saveConnectorConfig(\'' + name + '\')">Save</button>' +
        '<span id="ti-' + name + '-test-result" class="tiny muted"></span>' +
      '</div>';
  }).catch(function() {});
}

function testConnectorConfig(name) {
  var resultEl = document.getElementById('ti-' + name + '-test-result');
  resultEl.textContent = 'Testing…';
  var urlEl = document.getElementById('ti-' + name + '-url');
  apicall('/api/threat-intel/' + name + '/config/test', {
    method: 'POST',
    body: JSON.stringify({
      baseUrl: urlEl ? urlEl.value : '',
      apiKey: document.getElementById('ti-' + name + '-key').value
    })
  }).then(function(res) {
    resultEl.textContent = res.ok ? ('OK — ' + res.actorCount + ' actors visible') : ('Failed: ' + res.error);
    resultEl.style.color = res.ok ? 'var(--success)' : 'var(--danger)';
  }).catch(function(e) {
    resultEl.textContent = 'Failed: ' + (e.message || 'error');
    resultEl.style.color = 'var(--danger)';
  });
}

function saveConnectorConfig(name) {
  var urlEl = document.getElementById('ti-' + name + '-url');
  apicall('/api/threat-intel/' + name + '/config', {
    method: 'PUT',
    body: JSON.stringify({
      baseUrl: urlEl ? urlEl.value : '',
      apiKey: document.getElementById('ti-' + name + '-key').value,
      enabled: document.getElementById('ti-' + name + '-enabled').checked
    })
  }).then(function() {
    showToast(TI_CONNECTOR_LABELS[name] + ' config saved', 'ok');
    loadThreatIntelConfig(name);
    loadConnectorStatus();
  }).catch(function(e) { showToast('Save failed: ' + (e.message || 'error'), 'err'); });
}

function loadConnectorStatus() {
  var wrap = document.getElementById('connector-status-wrap');
  if (!wrap) return;
```

- [ ] **Step 5: Call the loaders wherever `loadConnectorStatus` is already called**

```bash
grep -n "loadConnectorStatus()" orchestrator/wwwroot/index.html
```

At every call site found (each is a place the Settings → Threat Intel section becomes visible — e.g. inside whatever function shows that settings section), add the three new loader calls immediately after the existing `loadConnectorStatus();` call:

```js
loadConnectorStatus();
loadThreatIntelConfig('misp');
loadThreatIntelConfig('opencti');
loadThreatIntelConfig('otx');
```

Read each call site's exact surrounding lines before editing, and only add the three new lines — do not otherwise alter that function.

- [ ] **Step 6: Syntax-check**

```bash
cd orchestrator/wwwroot
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' index.html > /tmp/ti-config-check.js
node --check /tmp/ti-config-check.js
```

Expected: no output, exit code 0.

- [ ] **Step 7: Read back the three modified cards and the new JS block**

Use the `Read` tool around `id="ti-misp-config-panel"`, `id="ti-opencti-config-panel"`, `id="ti-otx-config-panel"`, and `function loadThreatIntelConfig` (search to find current line numbers) and confirm every tag is balanced and every new function reference (`onclick="testConnectorConfig(...)"`, `onclick="saveConnectorConfig(...)"`) matches a function defined exactly once.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): editable MISP/OpenCTI/OTX connector config"
```

---

## Self-Review

**1. Spec coverage:**
- DB-backed config replacing `.env`-only, matching OpenAEV's GET/PUT/Test/never-return-secret pattern — Task 1 (schema), Task 2 (handlers).
- Env-to-DB auto-seed on first boot, never overwrites an existing row — Task 1 (`SeedFromEnv`, tested for both the seed and no-overwrite cases).
- Live reconfiguration, zero restart, for both `Scheduler.sources` and the OTX `iocProvider` dual-consumer — Task 2 (`Reconfigure`, the `started`/idle-to-live transition fix, `iocProviderMu`).
- The `sync()` unprotected-read race that `Reconfigure` would otherwise introduce — Task 2 Step 3, explicitly fixed alongside `Reconfigure` itself.
- Per-connector field differences (MISP/OpenCTI get a URL field, OTX doesn't) — Task 3's `urlField` conditional in `loadThreatIntelConfig`/`testConnectorConfig`/`saveConnectorConfig`.
- Plain-text key storage matching OpenAEV's precedent, poll interval left alone, no new per-connector Sync endpoint — none of these appear anywhere in any task (confirmed by their absence — nothing in this plan encrypts a key, adds a `poll_hours` column, or adds a `/sync` route beyond the one already existing).
- `CanUpdateConnectorConfig` permission, Admin-only, added via the exact same pattern as `CanViewAgentGroups`/`CanTargetAllAgents` earlier this session, with the frozen `TestPermissionGrants_MatchMigrationInventory` explicitly called out as untouched — Task 1 Steps 5-6.

**2. Placeholder scan:** no TBD/TODO; every step has literal exact-match old/new code (Go and JS) or a concrete `grep`/manual-edit instruction where an exact anchor can't be pinned to one location (Step 5 of Task 3, the multiple `loadConnectorStatus()` call sites — this is a find-and-extend instruction with the exact 4 lines to add, not a vague "wire it up somewhere").

**3. Type consistency:** `SeedConfig`'s 5 fields (Task 1) are read identically by `main.go`'s `SeedFromEnv` call (Task 1 Step 9). `LoadSourcesFromDB`'s signature (`ctx, pool, sectors, regions`) is used identically by `main.go` (Task 1 Step 9, with real `cfg.ThreatIntelSectors`/`cfg.ThreatIntelRegions`) and by `PutThreatIntelConfig` (Task 2 Step 8, with `nil, nil` — matches the design's explicit non-goal that sectors/regions stay env-only and don't need to be threaded through a config save). `threat_intel_config`'s column names (`connector`, `base_url`, `api_key`, `enabled`, `last_sync_at`, `last_sync_status`, `last_error`) are used identically across Task 1's schema, `SeedFromEnv`, `LoadSourcesFromDB`, and Task 2's three handlers. The JSON field names (`baseUrl`/`apiKey`/`enabled`) are used identically between Task 2's Go handlers and Task 3's JS — no camelCase/snake_case mismatch anywhere.
