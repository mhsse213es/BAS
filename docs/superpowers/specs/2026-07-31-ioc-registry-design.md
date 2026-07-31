# IOC Registry — Design Spec

**Phase 0+A of the IOC Handling initiative** (source vision: `iochandling.txt`, repo root). This is
the first of a 4-phase roadmap the user specified:

1. **Canonical model + Registry** (this spec)
2. **Relationships & Analytics** — timeline, search, reuse-across-runs, IOC→Scenario/Variant/
   Detection/Endpoint views. Deferred — reads this phase's data, not detailed here.
3. **Generation Engine** — a new, separate Artifact Generator producing fresh filenames/registry
   keys/mutexes/domains/etc. per execution, decoupled from the Variant Engine (which decides *how*
   something executes; the Generator decides *what identity* it has). Deferred, genuinely new
   engineering, not detailed here.
4. **Intelligence Layer** — suppression/allowlist/customer-exception/expiration/external-feed
   metadata over the registry. Deferred, not detailed here.

`integrations.txt` is fully out of scope — dropped per explicit user instruction, not referenced
below except where a phase overlaps in spirit (Phase 4/D's external-feed metadata is intentionally
much narrower than that document's TIP-scale ambition).

## Goal

Build one canonical IOC entity and a registry table, and populate it by *extracting* IOC-shaped
data that already flows through the system today — no new generation, no new capability, just
making existing data queryable instead of buried inside JSON result blobs. Every later phase
(analytics, generation, intelligence) builds on this without needing its own schema.

## Investigation: what "IOC data" already exists, and a correction to the user's own framing

Read the actual current code before writing anything:

- **`models.SimulationResult`** (`internal/models/schema.go:36-78`) has **no IOC-shaped field of
  its own**. The closest thing is the nested `DetectionAlert` (`schema.go:99-109`):
  `Channel, Provider, EventID, ThreatName, ProcessName, CommandLine, Timestamp, Confidence, MTTDMs`.
  `CommandLine` and `ProcessName` are real IOC values (Command Line is IOC Type #9 in
  `iochandling.txt`'s own taxonomy). `ThreatName` is **not** an IOC value — it's the EDR's
  classification label (e.g. `"Trojan:Win32/Meterpreter"`), metadata *about* a detection, not an
  indicator itself. It does not fit the IOC type taxonomy and must not become a fake IOC type.
- **`internal/variant`** (`types.go`) rotates *delivery method* — `Encoding`
  (plain/base64/gzip_b64/charcode), `ExecContext` (powershell_direct/cmd_powershell/wmi/schedtask),
  `Evasion` (none/sleep_jitter/delay/parent_process_shift/amsi_patch). **It does not rotate artifact
  identity** — no filename, domain, mutex, or registry-key randomization exists anywhere in this
  package. This corrects an earlier over-claim made during brainstorming (that variant rotation
  already covered `iochandling.txt` §5-7) — it doesn't. That gap is real and is exactly what Phase C
  (Generation Engine) will build; Phase 0+A does not touch it.
- **`variant_run_steps`** (`internal/db/postgres.go:511-527`) stores the *recipe* used
  (`encoding, exec_context, evasion, executor, cmd_preview, variant_hash`) — `variant_hash` is a
  dedup fingerprint of the *combination of dimensions chosen*, not a hash of any dropped artifact.
- **Wiring point confirmed**: `SubmitRunDetections` (`internal/api/detection_handlers.go:17-126`)
  is where `DetectionAlert` gets populated per-result (lines 61-87) and then the updated `results`
  slice plus raw detection data get written back via one `UPDATE scenario_runs ... WHERE id=$10`
  (lines 118-124). This is the single natural extraction point for Phase 0+A — no other code path
  produces `DetectionAlert` data. The handler's initial fetch (line 34-35,
  `SELECT results FROM scenario_runs WHERE id = $1`) will need `scenario_id, agent_id` added to
  give extraction its ownership columns — both already exist on `scenario_runs`
  (`internal/db/postgres.go:95-107`), just not currently selected here.
- **Realistic scope of what Phase 0+A can actually populate**: only `command_line` and `process`
  IOC types have a real data source today (from `DetectionAlert.CommandLine`/`ProcessName`). The
  `iocs.type` column is defined with the full 14-value taxonomy from `iochandling.txt` §1
  (forward-compatible for Phase C), but in practice only 2 of those 14 will ever be populated until
  Phase C ships. This is stated plainly rather than implied — a schema that promises hash/IP/domain
  tracking but never populates it would be misleading.
- **No existing table already does this.** Grepped for any prior "artifact"/"ioc" concept —
  none exists. This is genuinely new storage, not a rename of something that already exists.

## Decisions made during brainstorming (user-specified)

1. **Canonical Go type first** (`iochandling.txt`'s own "Phase 0" addition): every future IOC
   producer (Detection Validation, Variant Engine, future Threat Intel imports, Purple Team,
   DLP validation, Attack Path) emits this one struct, never invents its own shape.
2. **`Source` vs `Origin` are two distinct fields**, not duplicates:
   - `Source` = which Audspect subsystem/code-path produced *this row* (`detection_alert`,
     `scenario`, `variant`, `manual`) — mechanical, always knowable at insert time.
   - `Origin` = `iochandling.txt` §15's broader provenance vocabulary (`built-in`, `generated`,
     `openaev`, `misp`, `opencti`, `manual`, `threat-feed`, `customer`) — conceptual, mostly
     `built-in` until Phase 3/4 (Generation, external-feed import) exist. Phase 0+A only ever
     writes `Source = detection_alert | scenario` and `Origin = built-in`; the other values are
     schema headroom for later phases, not populated here.
3. **`EndpointID` → `AgentID`**: the user's proposed struct uses `EndpointID`, matching
   `iochandling.txt`'s generic language. This codebase's actual convention throughout
   (`agents`, `scenario_runs.agent_id`, `variant_runs.agent_id`) is `AgentID` — adapted for
   consistency with every existing table, not a design disagreement.
4. **First-seen/last-seen deduplication**: the same literal IOC value can appear across multiple
   runs (e.g., the same hardcoded ART test command line, run against 50 agents over a month).
   Phase 0+A dedupes on `(type, value)` — updating `last_seen`/incrementing a `sighting_count`
   rather than inserting a duplicate row — since `iochandling.txt` §6/§13 (rotation, IOC families)
   explicitly frame reused/duplicate values as one logical IOC with multiple observations, not
   separate IOCs. The *per-observation* link (which run, which agent) is preserved via a separate
   junction table, not by denormalizing run/agent onto the IOC row itself (a single IOC value
   observed on 50 agents must not need 50 IOC rows).

## Architecture

### 1. Canonical model — `internal/iocregistry/types.go` (new package)

```go
package iocregistry

import "time"

type Type string

const (
	TypeFileHash    Type = "file_hash"
	TypeDomain      Type = "domain"
	TypeURL         Type = "url"
	TypeIP          Type = "ip"
	TypeRegistryKey Type = "registry_key"
	TypeMutex       Type = "mutex"
	TypeService     Type = "service"
	TypeProcess     Type = "process"
	TypeCommandLine Type = "command_line"
	TypeJA3         Type = "ja3"
	TypeUserAgent   Type = "user_agent"
	TypeEmail       Type = "email"
	TypeDNSRecord   Type = "dns_record"
	TypeCertificate Type = "certificate"
)

type Source string

const (
	SourceDetectionAlert Source = "detection_alert"
	SourceScenario       Source = "scenario"
	SourceVariant        Source = "variant" // unused until Phase C
	SourceManual         Source = "manual"  // unused until an operator-entry UI exists
)

type Origin string

const (
	OriginBuiltIn    Origin = "built-in"
	OriginGenerated  Origin = "generated"  // unused until Phase C
	OriginOpenAEV    Origin = "openaev"    // unused until a producer wires it
	OriginMISP       Origin = "misp"       // unused until Phase 4
	OriginOpenCTI    Origin = "opencti"    // unused until Phase 4
	OriginManual     Origin = "manual"
	OriginThreatFeed Origin = "threat-feed" // unused until Phase 4
	OriginCustomer   Origin = "customer"    // unused until Phase 4
)

// Status is the lifecycle state (iochandling.txt §4). Extraction from
// already-completed runs starts most rows at Observed or Detected directly —
// Draft/Generated/Assigned/Executed describe pre-execution stages that, for
// backfilled/extracted data, already happened before this row existed.
type Status string

const (
	StatusDraft     Status = "draft"
	StatusGenerated Status = "generated"
	StatusAssigned  Status = "assigned"
	StatusExecuted  Status = "executed"
	StatusObserved  Status = "observed"
	StatusDetected  Status = "detected"
	StatusMissed    Status = "missed"
	StatusExpired   Status = "expired"
	StatusArchived  Status = "archived"
)

// IOC is the canonical model every producer (Detection Validation, Variant
// Engine, future Threat Intel imports, Purple Team, DLP validation, Attack
// Path) must emit -- never invent a parallel shape.
type IOC struct {
	ID    string
	Type  Type
	Value string

	Source Source // which Audspect subsystem produced this row
	Origin Origin // iochandling.txt §15 provenance vocabulary

	FirstSeen time.Time
	LastSeen  time.Time

	ScenarioID string
	VariantID  string // empty until Phase C
	RunID      string
	AgentID    string

	Status   Status
	Metadata map[string]any // JSONB -- confidence/severity/tags land here in later phases, not new columns
}
```

### 2. Storage — `iocs` + `ioc_sightings` tables

Two tables, not one, per the dedup decision above: `iocs` is one row per distinct `(type, value)`;
`ioc_sightings` is one row per (IOC, run) observation, carrying the run/agent/scenario link.

```sql
CREATE TABLE IF NOT EXISTS iocs (
	id           text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
	type         text        NOT NULL,
	value        text        NOT NULL,
	source       text        NOT NULL,
	origin       text        NOT NULL DEFAULT 'built-in',
	status       text        NOT NULL DEFAULT 'observed',
	first_seen   timestamptz NOT NULL DEFAULT NOW(),
	last_seen    timestamptz NOT NULL DEFAULT NOW(),
	sighting_count int       NOT NULL DEFAULT 1,
	metadata     jsonb       NOT NULL DEFAULT '{}'
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs (type, value);
CREATE INDEX IF NOT EXISTS idx_iocs_status ON iocs (status);

CREATE TABLE IF NOT EXISTS ioc_sightings (
	id           text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
	ioc_id       text        NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
	scenario_id  text        NOT NULL DEFAULT '',
	run_id       text        NOT NULL DEFAULT '',
	agent_id     text        NOT NULL DEFAULT '',
	observed_at  timestamptz NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ioc_sightings_ioc ON ioc_sightings (ioc_id);
CREATE INDEX IF NOT EXISTS idx_ioc_sightings_run ON ioc_sightings (run_id);
CREATE INDEX IF NOT EXISTS idx_ioc_sightings_agent ON ioc_sightings (agent_id);
```

No FK to `scenario_runs`/`agents` on `ioc_sightings` beyond `run_id`/`agent_id` as plain text
columns — matching this codebase's existing convention (`action_requests.target_identifier`,
`variant_run_steps.task_id`) of loose text-column linkage rather than enforced FKs on
high-write-volume junction tables, and avoiding `ON DELETE CASCADE` risk (per the auto-retire
work earlier this session, cascading deletes on operational history is exactly the kind of thing
this codebase has already had to be careful about).

### 3. Extraction — `internal/iocregistry/extract.go`

```go
func ExtractFromDetectionAlert(ctx context.Context, pool *pgxpool.Pool,
	scenarioID, runID, agentID string, res models.SimulationResult) error
```

Called from `SubmitRunDetections` (`detection_handlers.go`), once per result with a non-nil
`DetectionAlert`, right after the existing `UPDATE scenario_runs` write (line ~124) — extraction
failure must never fail the detection-ingestion request itself (best-effort, logged, matching the
`h.auditLog`/background-goroutine tolerance pattern already used elsewhere in this handler file).

For each result with `DetectionAlert != nil`:
- If `CommandLine != ""`: upsert an IOC row (`type=command_line, source=detection_alert`).
- If `ProcessName != ""`: upsert an IOC row (`type=process, source=detection_alert`).
- `ThreatName` is **not** extracted as an IOC — stored instead in the `command_line` row's
  `metadata` JSONB (`{"threatName": "..."}`) since it describes that observation, not a separate
  indicator.

Upsert logic: `INSERT ... ON CONFLICT (type, value) DO UPDATE SET last_seen = NOW(),
sighting_count = iocs.sighting_count + 1`, then always insert a fresh `ioc_sightings` row (a
sighting is never deduped — the same IOC seen on 3 different agents is 3 sightings, 1 IOC).

`detection_handlers.go`'s initial query is extended:
`SELECT scenario_id, agent_id, results FROM scenario_runs WHERE id = $1` (both columns already
exist, just weren't selected here).

### 4. Query API — `GET /api/iocs`

Minimal, matching the "search by type/value/scenario/run/agent" slice of `iochandling.txt` §18
that's directly answerable by this schema — full search (§18's confidence/severity/creator/date
filters) is Phase B, not here. Query params: `type`, `value` (substring), `scenarioId`, `agentId`,
`limit` (default 50, max 200). `tierAny` (Viewer+), matching every other read-only endpoint this
session.

## Non-goals

- **No artifact generation** (filenames/domains/mutexes/registry keys) — that's Phase C, a
  different engine, deliberately decoupled from Variant Engine per the user's own architecture
  ("Scenario → Artifact Generator → Generated IOC Set → Variant Engine → Execution").
- **No suppression/allowlist/expiration logic** — Phase D.
- **No timeline/correlation/relationship views beyond the raw sightings table** — Phase B reads
  this data; this phase only writes it and exposes flat search.
- **No frontend** — backend-only, matching this session's established "foundation phases are
  backend-only" convention (Unified Analytics Layer Sub-projects A/C).
- **No cleanup/artifact-removal tracking** — `iochandling.txt` §9 already has a home
  (`models.SimulationResult.CleanupVerdict`); not duplicated here.
- **No `variant` or `manual` Source producers wired up** — the enum includes them for forward
  compatibility (Phase C wires `variant`; a manual-entry UI, if ever built, wires `manual`), but
  Phase 0+A's only real producer is `SubmitRunDetections`.

## Testing

`internal/iocregistry/extract_test.go`, `TestMain`/`sharedDB` pattern (matching every Postgres-backed
package this session): seed a `SimulationResult` with a populated `DetectionAlert`
(`CommandLine`, `ProcessName`, `ThreatName` all set), call `ExtractFromDetectionAlert`, assert two
`iocs` rows exist (`command_line`, `process`), the `command_line` row's `metadata` contains
`threatName`, and one `ioc_sightings` row exists per IOC pointing at the right `run_id`/`agent_id`.
A second call with the *same* `CommandLine` value (simulating a second run) asserts
`sighting_count` increments to 2 and a second `ioc_sightings` row is added, not a second `iocs`
row (the dedup contract). A result with `DetectionAlert == nil` asserts no rows are written.

`internal/api/ioc_handler_test.go`: `GET /api/iocs` filtered by `type`/`agentId`/`scenarioId`
against seeded rows.
