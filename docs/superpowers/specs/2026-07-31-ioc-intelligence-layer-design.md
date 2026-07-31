# IOC Intelligence Layer — Design Spec

**Phase D of the IOC Handling initiative — the last phase** (source vision: `iochandling.txt`,
repo root, §8/15/16/17/19/22). Phase 0+A (registry), Phase B (relationships/analytics), and
Phase C (generation engine) are all **done** and pushed. This phase closes out the roadmap.

## Goal

Add expiration, suppression awareness, and customer-provided IOC import to the registry —
the three pieces of the original "Intelligence Layer" framing (`docs/superpowers/specs/
2026-07-31-ioc-registry-design.md`: *"suppression/allowlist/customer-exception/expiration/
external-feed metadata"*) that are genuinely new, real, and buildable against what the
registry actually contains today. Everything else in `iochandling.txt`'s §16/17/19 ambition
is either already covered by a different, pre-existing system or would be fabricated data
with no real source — both are explicitly scoped out below, with the investigation that led
to each call.

## Investigation: a third pre-existing IOC system changes this phase's shape

- **`internal/db/ioc_enrichment.go`** is a mature, already-shipped external-lookup cache:
  `ioc_enrichment` table, keyed `(indicator_type, indicator_value, provider)`, storing OTX
  pulse count/malware families/adversary names/industries/tags, **with TTL expiration
  already built** (`ttl_expires_at`, `GetIOCEnrichment` compares it, callers skip a re-lookup
  while fresh). This serves `internal/ioc`'s 5 types (`ip`/`domain`/`url`/`hash`/`cve`) — the
  *other* IOC system found during Phase B (`run_iocs`, regex-scanned from stdout/stderr).
- **`internal/intelligence/models.go`'s own doc comment** (written during an earlier phase
  of this session, unrelated to the IOC Handling initiative) states explicitly: *"Actors,
  IOCs, CVEs) already has a home elsewhere (threat_actor_profiles, internal/ioc's
  ioc_enrichment table, the CVE Relationship Store) — see [...] for why this package doesn't
  duplicate those."* A prior, independent phase of this same session already decided
  IOC-specific external enrichment/import belongs in `internal/ioc`/`ioc_enrichment`, not a
  new pipeline. Building a second MISP/OpenCTI-style IOC importer for `iocregistry` here
  would be exactly the duplication that comment warns against.
- **`iocregistry`'s own types (`command_line`, `process`, `filename`, `mutex`,
  `registry_key`, `service`) have no OTX analog anyway** — OTX has no reputation data for a
  mutex name or a raw command line, so cross-connecting the two systems for *enrichment*
  has no real value even where the systems could theoretically talk to each other.
- **No suppression/allowlist/exception mechanism exists anywhere in the codebase**
  (grepped `suppress|allowlist|whitelist` across `internal/` — every match is either this
  investigation's own future work or an unrelated regex-suppression concept in
  `internal/ioc/extract.go`). This is genuinely new, real work.
- **`internal/detect/retention.go`** is the exact reusable pattern for expiration: a
  `Start*(ctx, pool)` function spawning one goroutine, a 24-hour `time.NewTicker`, runs once
  immediately then on each tick, best-effort logged on error. No new scheduling
  infrastructure needed.
- **`internal/auth/permissions.go`**: admin-only actions follow a consistent
  `Can<Verb><Noun> Permission = "domain:action"` pattern (e.g. `CanReindexSearch Permission
  = "search:reindex"`, line 99), granted only under `RoleAdmin` (line 182). Routes gate via
  `r.With(auth.RequirePermission(auth.Can...)).Post(...)`.

## Decisions

1. **Expiration (§8)**: `iocregistry.StartExpiration(ctx, pool, staleAfter time.Duration)`,
   following `retention.go`'s exact shape. Transitions `iocs.status` to `expired` for rows
   whose `last_seen` is older than `staleAfter` and whose `status` isn't already
   `expired`/`archived` (don't re-touch already-terminal rows). First real transition of the
   lifecycle beyond insert-time `observed`/`generated` (Phase 0+A/C only ever write the
   initial status; nothing has transitioned a row since). A 30-day default matches
   `retention.go`'s own precedent for "how long is IOC data still operationally relevant."
2. **Suppression (§22) is a new, separate axis from `Status`** — lifecycle (`observed →
   detected/missed → expired`) and an operator's suppression judgment ("this is a known
   false-positive / environment-specific exception, don't count it") are different
   questions; conflating them into `Status` would make a suppressed-but-still-active IOC
   ambiguous. Two new columns on `iocs`: `suppressed boolean NOT NULL DEFAULT false`,
   `suppression_reason text NOT NULL DEFAULT ''`.
3. **Suppression is admin-only**, matching every other write-side registry-management
   action's precedent in this codebase (ART content reseed, search reindex, connector
   config). New permission `CanManageIOCs Permission = "iocs:manage"`.
4. **`IOCAnalytics.HighestBypassRate` excludes suppressed IOCs** — the literal scenario
   `iochandling.txt` §22 describes ("Otherwise you may incorrectly report a detection gap").
   The other 3 lists (`MostDetected`, `FrequentlyReused`, `LongestSurviving`) are left
   unfiltered — a suppressed IOC being frequently reused or long-surviving is still true and
   not misleading the way counting it as an *undetected bypass* would be.
5. **`GetIOCs` exposes `suppressed`/`suppressionReason`** on every row (not filtered out by
   default) — an operator must be able to see suppression state via the same read path they
   already use, not just infer it from analytics exclusion.
6. **Customer Import (§17, narrowed)**: `POST /api/iocs/import`, admin-only
   (`CanManageIOCs`), accepts a flat JSON list of `{type, value}` pairs, writes each via a
   new `iocregistry.ImportManual` with `Origin = customer` (reserved since Phase 0+A,
   unused until now) and `Status = draft` (the one lifecycle state nothing has produced yet
   either). Explicitly **not** CSV/STIX/OpenIOC parsing, **not** a MISP/OpenCTI connector —
   both would duplicate `internal/ioc`'s existing enrichment/import domain for a set of
   types that system doesn't even cover.
7. **`Origin = threat-feed`, `metadata.confidence`/`severity` stay unpopulated** — no
   producer exists for either; adding fields nothing writes would be dead API surface
   (same reasoning Phase 0+A applied to 12 of 14 IOC types).

## Architecture

### 1. Schema — `internal/db/postgres.go`

```sql
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS suppressed boolean NOT NULL DEFAULT false;
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS suppression_reason text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_iocs_suppressed ON iocs (suppressed) WHERE suppressed = true;
```

Partial index (`WHERE suppressed = true`) — matches this codebase's existing convention for
boolean flags expected to be false for the overwhelming majority of rows (e.g.
`idx_scenario_runs_agent_running`'s own partial-index precedent from Phase 0+A's plan).

### 2. Expiration — `internal/iocregistry/expire.go`

```go
package iocregistry

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultStaleAfter matches internal/detect/retention.go's own precedent for how long
// operational data stays relevant before it's no longer worth surfacing as "current."
const DefaultStaleAfter = 30 * 24 * time.Hour

// StartExpiration prunes stale IOCs once a day, mirroring internal/detect/retention.go's
// exact shape. Best-effort; logs and continues on error.
func StartExpiration(ctx context.Context, pool *pgxpool.Pool, staleAfter time.Duration) {
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		expireStale(ctx, pool, staleAfter)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				expireStale(ctx, pool, staleAfter)
			}
		}
	}()
}

func expireStale(ctx context.Context, pool *pgxpool.Pool, staleAfter time.Duration) {
	// make_interval(secs => ...) avoids any ambiguity from feeding Go's
	// time.Duration string format ("720h0m0s") into Postgres's interval
	// literal parser -- a plain float8 seconds value has one unambiguous
	// interpretation.
	ct, err := pool.Exec(ctx, `
		UPDATE iocs SET status = $1
		WHERE last_seen < NOW() - make_interval(secs => $2)
		  AND status NOT IN ($1, $3)`,
		string(StatusExpired), staleAfter.Seconds(), string(StatusArchived))
	if err != nil {
		log.Printf("[iocregistry] expiration sweep failed: %v", err)
		return
	}
	if n := ct.RowsAffected(); n > 0 {
		log.Printf("[iocregistry] expired %d stale IOC(s)", n)
	}
}
```

Called once from `cmd/server/main.go` alongside `detect.StartRetention`'s own call site,
same pattern: `iocregistry.StartExpiration(ctx, pool, iocregistry.DefaultStaleAfter)`.

### 3. Suppression — `internal/iocregistry/suppress.go`

```go
package iocregistry

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SetSuppressed sets or clears an IOC's suppression state. reason is stored verbatim when
// suppressing; cleared (empty string) when un-suppressing, regardless of what's passed.
func SetSuppressed(ctx context.Context, pool *pgxpool.Pool, iocID string, suppressed bool, reason string) error {
	if !suppressed {
		reason = ""
	}
	_, err := pool.Exec(ctx,
		`UPDATE iocs SET suppressed = $1, suppression_reason = $2 WHERE id = $3`,
		suppressed, reason, iocID)
	return err
}
```

### 4. Handler + route — `internal/api/ioc_suppress_handler.go`

```go
package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/iocregistry"
)

// POST /api/iocs/{id}/suppress — {"suppressed": true, "reason": "known lab tool"}.
// Admin-only (CanManageIOCs).
func (h *Handler) SetIOCSuppressed(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		Suppressed bool   `json:"suppressed"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := iocregistry.SetSuppressed(r.Context(), h.db, id, body.Suppressed, body.Reason); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"id": id, "suppressed": body.Suppressed, "reason": body.Reason})
}
```

Route: `r.With(auth.RequirePermission(auth.CanManageIOCs)).Post("/api/iocs/{id}/suppress",
h.SetIOCSuppressed)`.

### 5. `GetIOCs` exposes suppression state

`ioc_handlers.go`'s `iocRow` gains 2 fields and its `SELECT`/`Scan` gain the 2 columns:

```go
type iocRow struct {
	// ... existing fields unchanged ...
	Suppressed       bool   `json:"suppressed"`
	SuppressionReason string `json:"suppressionReason"`
}
```

### 6. `IOCAnalytics.HighestBypassRate` excludes suppressed rows

`internal/analytics/ioc.go`'s `iocsByVerdict` call for the bypass list gains `AND NOT
i.suppressed` in its `WHERE` clause — the other 3 lists are untouched.

### 7. Consolidate the 3 near-duplicate `iocs` INSERTs, then add import

Two separate `INSERT INTO iocs` statements already exist: `extract.go`'s `upsertIOC`
(implicitly defaults `origin`/`status` to the table's SQL defaults) and `generate.go`'s
`RegisterGenerated` (its own inline INSERT explicitly setting `origin`/`status`). Adding a
third near-identical INSERT for import would be the kind of small duplication worth fixing
while touching this code, not compounding. `extract.go` gains one new, fully-parameterized
function; the other two become thin callers of it — no behavior change for either.

```go
// extract.go -- new function, replaces upsertIOC's body
func upsertIOCFull(ctx context.Context, pool *pgxpool.Pool, t Type, value string, source Source, origin Origin, status Status, metadata map[string]any) (string, error) {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metaJSON, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	var id string
	err = pool.QueryRow(ctx, `
		INSERT INTO iocs (type, value, source, origin, status, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (type, value) DO UPDATE SET
			last_seen = NOW(),
			sighting_count = iocs.sighting_count + 1
		RETURNING id`,
		string(t), value, string(source), string(origin), string(status), metaJSON,
	).Scan(&id)
	return id, err
}

// upsertIOC keeps its exact existing signature/behavior -- Phase 0+A/B/C callers unchanged.
func upsertIOC(ctx context.Context, pool *pgxpool.Pool, t Type, value string, source Source, metadata map[string]any) (string, error) {
	return upsertIOCFull(ctx, pool, t, value, source, OriginBuiltIn, StatusObserved, metadata)
}
```

`generate.go`'s `RegisterGenerated` replaces its own inline `INSERT` with a call to
`upsertIOCFull(ctx, pool, t, value, SourceVariant, OriginGenerated, StatusGenerated, nil)`
— identical resulting SQL, one fewer near-duplicate.

```go
// internal/iocregistry/import.go
package iocregistry

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ImportEntry is one caller-supplied (type, value) pair to register.
type ImportEntry struct {
	Type  Type   `json:"type"`
	Value string `json:"value"`
}

// ImportManual writes each entry as Origin=customer, Status=draft, Source=manual --
// customer-provided IOCs meant to drive future simulations, not observations of anything
// that has happened yet. Best-effort per-entry; returns the count actually written and
// the first error encountered, if any (partial success is reported, not silently lost).
func ImportManual(ctx context.Context, pool *pgxpool.Pool, entries []ImportEntry) (written int, err error) {
	for _, e := range entries {
		if _, ierr := upsertIOCFull(ctx, pool, e.Type, e.Value, SourceManual, OriginCustomer, StatusDraft, nil); ierr != nil {
			if err == nil {
				err = ierr
			}
			continue
		}
		written++
	}
	return written, err
}
```

Handler: `POST /api/iocs/import`, admin-only, body `{"entries":[{"type":"filename",
"value":"..."}]}`, responds `{"written": N}`.

## Non-goals

- **No STIX/JSON/CSV/YAML/OpenIOC/Sigma/YARA/Suricata/Snort/CEF/LEEF export (§16)** — no
  consumer today, and `iochandling.txt`'s own "What a BAS should not become" section warns
  against exactly this scope creep. `GET /api/iocs` (Phase 0+A) already serves any consumer
  that wants the raw data as JSON.
- **No MISP/OpenCTI/vendor-feed/STIX/OpenIOC import (§17, the rest of it)** — that domain
  already belongs to `internal/ioc`/`ioc_enrichment` per the Investigation above; building a
  second importer here would duplicate a decision an earlier phase of this session already
  made deliberately.
- **No confidence/severity/maliciousness scoring (§19)** — nothing computes a real value for
  any of these; `iocs.metadata` JSONB remains the reserved home for them once a real
  producer exists (unchanged from Phase 0+A's original framing).
- **No IOC versioning (§14)** — still out of scope, as it was in Phase B.
- **No frontend.**

## Testing

- The `upsertIOCFull` consolidation is covered by regression: every existing Phase 0+A/B/C
  test in `internal/iocregistry` (`extract_test.go`, `generate_test.go`) must still pass
  unchanged, since `upsertIOC`/`RegisterGenerated`'s external behavior doesn't change.
- `internal/iocregistry/expire_test.go`: an IOC with `last_seen` older than `staleAfter`
  and `status='observed'` transitions to `expired`; one already `archived` is left
  untouched; one with a recent `last_seen` is left untouched.
- `internal/iocregistry/suppress_test.go`: `SetSuppressed(true, "reason")` sets both
  columns; a second call with `suppressed=false` clears `suppression_reason` regardless of
  the `reason` argument passed.
- `internal/iocregistry/import_test.go`: `ImportManual` with 2 valid entries returns
  `written=2`; dedup against an existing `(type,value)` row still counts as written (upsert
  semantics, matching `upsertIOC`'s existing contract).
- `internal/analytics/ioc_test.go` (extend): a suppressed IOC with an `undetected` sighting
  is excluded from `HighestBypassRate` but still appears in `FrequentlyReused`.
- `internal/api/ioc_suppress_handler_test.go`: `POST /api/iocs/{id}/suppress` sets the
  fields and the RBAC matrix gains one entry (`tierPermission`, `CanManageIOCs`).
- `internal/api/ioc_import_handler_test.go`: `POST /api/iocs/import` with 2 entries writes
  2 `iocs` rows with `origin='customer'`, `status='draft'`.
- `internal/api/ioc_handlers_test.go` (extend): `GetIOCs` response includes
  `suppressed`/`suppressionReason` for a seeded suppressed row.
