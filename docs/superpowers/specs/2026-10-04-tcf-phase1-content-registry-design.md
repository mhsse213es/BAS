# Threat Content Factory — Phase 1: Content Registry (Design)

**Status:** Draft for review · **Date:** 2026-10-04
**Initiative:** Threat Content Factory (TCF) — requirements in `threatIntelFactory.txt` (repo root of the main checkout), index in `docs/threat-content-factory/README.md`.

---

## 1. Purpose and positioning

Audspect already ingests threat intelligence (MISP, OpenCTI, OTX, TAXII, ATT&CK), prioritizes it, and executes ART / Caldera / custom content. What it lacks is a **governance layer** between intelligence and executable content: there is no content versioning, no lifecycle, no approval record, and no link from a run to the exact content that ran.

Phase 1 builds that layer. It does **not** build the factory itself (generation, sandbox validation, scheduling, distribution) — those are later phases that will write into this registry.

**Governing principle:**

> The Content Registry is the system of record for executable threat content and its lifecycle. The existing intelligence tables remain the system of record for threat intelligence.

**Competitive honesty note.** Phase 1 makes Audspect architecturally capable of a governed content factory; it does not by itself make Audspect competitive with Picus / SafeBreach / Cymulate / AttackIQ on breadth or velocity. No customer material may claim parity until the factory produces measured numbers. Phase 1's job is to make those numbers *recordable* (see §4.5 `first_seen_at_generation`).

## 2. Decisions locked during brainstorming

| # | Decision |
|---|---|
| D1 | **Topology C.** The vendor factory (Audspect Research) is the authoritative path: generate → validate → approve → RSA-sign → ship. Customer-side generation (`connector/generator.go`) is retained but its output is local, untrusted, and DRAFT until a customer operator approves it. |
| D2 | **Three independent dimensions:** `origin` (VENDOR, LOCAL), `trust_level` (VENDOR_SIGNED, LOCAL_TRUSTED, UNTRUSTED), `lifecycle` (DRAFT, VALIDATING, VALIDATED, APPROVED, PUBLISHED, PUBLISHED_LOCAL, RETIRED, REJECTED). Local content's terminal state is `PUBLISHED_LOCAL`, never `PUBLISHED`. Local content can never hold `VENDOR_SIGNED`. |
| D3 | **Artifact storage = Postgres bytes (approach A).** Disk YAML is the authoring/intake representation; the registry is the authoritative historical representation once a version exists. Version bytes are never updated — changed bytes are a new version. |
| D4 | **ART/Caldera: pin + detect drift, do not archive.** Content versions declare component versions; each run records the resolved command hash per step. Old ART/Caldera catalogs are not retained. |
| D5 | **Database-enforced invariants over triggers.** Composite FKs for identity pairs, CHECK constraints for legal states, UNIQUE for idempotency, column-level privileges for restricted writes. No triggers unless PostgreSQL cannot express an invariant declaratively. Application code owns workflow transitions; the DB prevents invalid states. |
| D6 | **Fail-closed runtime gate** on origin + trust + lifecycle together (§6). `VALIDATED ≠ executable`. |
| D7 | **Dev-build exception** is compile-time only and never mutates stored trust (§6.3). |
| D8 | **Migration:** existing intel scenarios → DRAFT (schedules referencing them break visibly); existing custom scenarios → grandfathered `PUBLISHED_LOCAL` with actor `migration:pre-registry` (§8). |

## 3. Current state (verified in code, 2026-10-04)

- **Scenarios are YAML on disk** (`scenarios/*.yaml`, 69 files, 924 KB total, largest 34 KB), loaded into an in-memory map by `internal/scenario/engine.go`, keyed by YAML `id`. Folder decides `Source`: root = `builtin`, `custom/` = operator-authored via UI, `intel/` = generator output.
- **Only builtin scenarios are signature-verified** (`engine.go:82-90`, `integrity.VerifyScenarioFile`, RSA-4096 PKCS#1 v1.5 over SHA-256, adjacent `.sig`). **Intel and custom scenarios are unsigned and immediately runnable** — intelligence crosses into executable content with no gate. This is the primary hole Phase 1 closes.
- `VerifyScenarioFile` returns `nil` when the compiled-in key is the placeholder (`signingEnabled() == false`, dev builds). `nil` is therefore **not** proof of verification.
- `filepath.WalkDir` visits in lexical order and the map is last-write-wins: a `custom/<id>.yaml` whose `id` equals a builtin's can replace the signed builtin in the map when the builtin's filename sorts before `custom`.
- **The `scenarios` and `scenario_techniques` Postgres tables are dead** — no Go or Python code reads or writes them. They carry `tenant_id`.
- **The intel generator** (`internal/connector/generator.go`) writes `scenarios/intel/intel-<sha12>.yaml` where `sha12 = sha256(lower(actor) | sorted technique IDs)[:12]`, with `art_techniques:` and single-source `intel_source/_source_id/_actor/_confidence`. A changed technique set produces a *new file* and leaves the old one runnable.
- **Provenance tables:** `intelligence_entity_sources` (entity_type ∈ campaign/malware/tool, entity_id, provider, external_id, first_seen, last_sync, confidence), `threat_actor_sources` (per actor × source), `technique_evidence` (OpenCTI per-relationship evidence).
- **Runs:** `scenario_runs(id, scenario_id, agent_id, …, results jsonb, step_meta jsonb, …)`. `scenario_id` carries no version. Six insert sites: `api/handlers.go` (×3), `api/remediation_dispatch.go` (×2), `api/variant_handlers.go` (×1). Roughly 20 `engine.Get(scenarioID)` call sites, some of which interpret results *after* a run against current YAML (e.g. `handlers.go:2645`).
- **Synthetic runs** build in-memory scenarios with no artifact: remediation steps and technique verification (`remediation_dispatch.go`), variants (`scenario_id = "__variant__<tech>"`).
- `step_meta` is `map[TaskID]StepMeta{techniqueId, name, framework, variant fields}` (`scenario/builder.go:62`), persisted by `persistStepMeta`.
- `art_content_meta` is a singleton (`CHECK (id = 1)`) holding the current ART `source_version`.
- **Safety:** steps carry `risk`, `production_safe`, `reversible`, `blast_radius`, `fidelity`, `requires_priv`; `scenario/execclass.go` resolves `(technique_id, action_key)` to `non_destructive | potentially_destructive | destructive`, failing closed to `destructive`.
- **DB roles:** `bas_app` gets a blanket `SELECT, INSERT, UPDATE, DELETE` with narrowing `REVOKE`s after it (precedent: `REVOKE UPDATE, DELETE ON audit_logs`, `db/app_role.go:84`).
- No `CREATE TRIGGER` exists anywhere in the schema.

## 4. Data model

Legend: **[ALTER]** existing table gains columns · **[NEW]** new table · **[REUSE]** referenced, unchanged.
All DDL follows the existing idempotent pattern (`CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`) and carries `tenant_id text NOT NULL DEFAULT 'default'` like every tenant-owned table.

### 4.1 `scenarios` [ALTER] — content identity

One row per stable content ID (the YAML `id`). The table is currently dead, so repurposing it avoids a parallel identity table.

```sql
ALTER TABLE scenarios ADD COLUMN IF NOT EXISTS origin text;              -- backfilled by intake, then NOT NULL
ALTER TABLE scenarios ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT NOW();
ALTER TABLE scenarios ADD COLUMN IF NOT EXISTS generation_key text;      -- NULL for hand-authored content
-- origin CHECK (origin IN ('VENDOR','LOCAL')), NOT NULL
-- UNIQUE (scenario_id, origin)   -- target of the composite FK in 4.2
```

No Go/Python/SQL code has ever written this table (`git log -S "INTO scenarios"` is empty), so it is empty on every deployment. The migration adds `origin` nullable, asserts the table is empty, then sets `NOT NULL` + CHECK + UNIQUE. If rows unexpectedly exist, the migration stops with an explicit error naming the table (fail-closed — it never guesses an origin).

**Origin is fixed per identity.** A content ID is VENDOR or LOCAL forever; a local file can never contribute a version to a vendor ID.

### 4.2 `content_versions` [NEW] — immutable versions

```sql
CREATE TABLE IF NOT EXISTS content_versions (
    id               text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    content_id       text        NOT NULL,
    origin           text        NOT NULL,
    version          int         NOT NULL CHECK (version >= 1),
    artifact_sha256  text        NOT NULL,
    artifact_size    int         NOT NULL,
    artifact_bytes   bytea       NOT NULL,
    signature_bytes  bytea,
    trust_level      text        NOT NULL CHECK (trust_level IN ('VENDOR_SIGNED','LOCAL_TRUSTED','UNTRUSTED')),
    lifecycle        text        NOT NULL CHECK (lifecycle IN ('DRAFT','VALIDATING','VALIDATED','APPROVED',
                                                               'PUBLISHED','PUBLISHED_LOCAL','RETIRED','REJECTED')),
    schema_version   int         NOT NULL,
    technique_ids    text[]      NOT NULL DEFAULT '{}',
    supported_os     text[]      NOT NULL DEFAULT '{}',
    generation       jsonb       NOT NULL DEFAULT '{}',
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT NOW(),
    tenant_id        text        NOT NULL DEFAULT 'default',

    FOREIGN KEY (content_id, origin) REFERENCES scenarios (scenario_id, origin),
    UNIQUE (content_id, version),
    UNIQUE (content_id, artifact_sha256),

    CHECK (artifact_size = octet_length(artifact_bytes)),
    CHECK (trust_level <> 'VENDOR_SIGNED' OR (origin = 'VENDOR' AND signature_bytes IS NOT NULL)),
    CHECK (trust_level <> 'LOCAL_TRUSTED' OR origin = 'LOCAL'),
    CHECK (lifecycle  <> 'PUBLISHED'       OR origin = 'VENDOR'),
    CHECK (lifecycle  <> 'PUBLISHED_LOCAL' OR origin = 'LOCAL')
);
CREATE INDEX IF NOT EXISTS content_versions_techniques ON content_versions USING GIN (technique_ids);
```

- `origin` is denormalized from `scenarios` and pinned there by the composite FK. This lets the origin/trust/lifecycle invariants be **plain CHECK constraints**.
- `UNIQUE (content_id, artifact_sha256)` is intake idempotency: re-hashing identical bytes always resolves to the existing version.
- `artifact_sha256` is lowercase hex SHA-256 of `artifact_bytes`, the same digest the RSA signature covers.
- `technique_ids` is the ATT&CK mapping *as of this version* (replaces the dead `scenario_techniques` for registry purposes). It covers explicit `steps[].technique_id` and `art_techniques`; modes that expand to whole catalogs (`art_all_*`, `caldera_all_windows`, `caldera_adversary_id`) record an empty list plus `generation.dynamic_scope` naming the mode.
- `schema_version` starts at `1` (the current scenario YAML schema).

**Immutability enforced in the DB** (added to `db/app_role.go` after the blanket grant, mirroring the `audit_logs` precedent). PostgreSQL column privileges do not narrow a table-level grant, so the table-level privilege must be revoked first:

```sql
REVOKE UPDATE, DELETE ON content_versions FROM bas_app;
GRANT  UPDATE (lifecycle, trust_level, signature_bytes) ON content_versions TO bas_app;
REVOKE DELETE ON scenarios FROM bas_app;
```

`bas_app` can therefore change only lifecycle, trust, and the signature on a version. Bytes, hash, size, version number, origin, and identity cannot be rewritten at runtime, and nothing can be deleted.

**Why `signature_bytes` is writable.** On the vendor factory a version is created unsigned (DRAFT) and signed only after approval, so the signature must be attachable later. PostgreSQL cannot express "writable only while NULL" with privileges, so this one rule is application-enforced: `signature_bytes` is written only by `contentregistry.AttachVendorSignature`, which (a) requires the current value to be NULL, (b) verifies the signature against the stored `artifact_bytes` with the compiled-in key and requires `verified == true`, and (c) sets `trust_level = VENDOR_SIGNED`, in one transaction. The CHECK `VENDOR_SIGNED ⇒ signature_bytes IS NOT NULL` still holds in the DB. Because the signed digest is the immutable `artifact_sha256`, a forged replacement signature cannot verify, and the gate re-verifies before trusting (see §6.1). This is the only registry invariant that is not DB-declarative; it is called out so it is not mistaken for one.

### 4.3 `content_version_events` [NEW] — lifecycle history and approvals (append-only)

```sql
CREATE TABLE IF NOT EXISTS content_version_events (
    id                  bigserial   PRIMARY KEY,
    content_version_id  text        NOT NULL REFERENCES content_versions(id),
    from_lifecycle      text,                       -- NULL on creation
    to_lifecycle        text        NOT NULL,
    from_trust          text,
    to_trust            text        NOT NULL,
    actor               text        NOT NULL,       -- 'user:<id>' | 'intake' | 'generator:<name>' | 'migration:pre-registry'
    reason              text        NOT NULL DEFAULT '',
    at                  timestamptz NOT NULL DEFAULT NOW(),
    tenant_id           text        NOT NULL DEFAULT 'default',
    CHECK (to_lifecycle NOT IN ('APPROVED','PUBLISHED_LOCAL','REJECTED')
           OR actor LIKE 'user:%' OR actor = 'migration:pre-registry')
);
-- app_role.go: REVOKE UPDATE, DELETE ON content_version_events FROM bas_app;
```

- **An approval record is an event.** Transitions into `APPROVED`, `PUBLISHED_LOCAL`, or `REJECTED` require a human actor. The single non-human exception is `migration:pre-registry`, whose `reason` must state it is historical authorization, not review (§8).
- Every change to `content_versions.lifecycle` / `trust_level` writes the version update and the event in **one transaction**.
- Approval time is the event's `at`. `published_at` for TCV is the `at` of the event entering `PUBLISHED` / `PUBLISHED_LOCAL`.

**Allowed lifecycle transitions** (enforced by one Go state machine, `internal/contentregistry/lifecycle.go`, with named tests):

| From | To | Origin | Actor |
|---|---|---|---|
| (create) | DRAFT | any | intake / generator |
| (create) | PUBLISHED | VENDOR | intake (verified vendor import only) |
| (create) | PUBLISHED_LOCAL | LOCAL | user (UI save) or migration |
| DRAFT | VALIDATING | any | system or user |
| VALIDATING | VALIDATED, DRAFT | any | system |
| VALIDATED | APPROVED | VENDOR | user |
| APPROVED | PUBLISHED | VENDOR | user (vendor factory); requires `trust_level = VENDOR_SIGNED`, i.e. `AttachVendorSignature` succeeded |
| VALIDATED, DRAFT | PUBLISHED_LOCAL | LOCAL | user |
| DRAFT, VALIDATING, VALIDATED, APPROVED | REJECTED | any | user |
| PUBLISHED, PUBLISHED_LOCAL | RETIRED | matching | user |

`REJECTED` and `RETIRED` are terminal. `DRAFT → PUBLISHED_LOCAL` exists so a customer operator can approve generator output without a validation lab, which Phase 1 does not provide. The approval event records that validation was skipped.

**Trust transitions** are tied to lifecycle: LOCAL entering `PUBLISHED_LOCAL` gets `LOCAL_TRUSTED`; LOCAL leaving it (`RETIRED`) keeps `LOCAL_TRUSTED` as historical fact but is no longer executable. `VENDOR_SIGNED` is set only by an explicit successful verification: at creation by intake for an imported signed builtin (§5.1), or by `AttachVendorSignature` on the vendor factory (§4.2). No lifecycle transition grants it, and it is never set on LOCAL content (DB CHECK).

### 4.4 Generation metadata — `content_versions.generation` + `scenarios.generation_key`

```json
{
  "generator": "connector/generator",
  "generator_version": "1",
  "mapping_version": "1",
  "attack_version": "<bundled ATT&CK version>",
  "inputs": [{"entity_type": "actor", "entity_id": "...", "provider": "misp", "external_id": "..."}],
  "component_versions": {"art": "<art_content_meta.source_version>", "caldera": "<if known>"},
  "parameters": {"min_techniques": 2},
  "dynamic_scope": null
}
```

`generation_key = sha256(canonical JSON of {generator, generator_version, mapping_version, sorted inputs, sorted technique IDs, parameters})`. It identifies a *candidate* (see §5.2). It is jsonb rather than columns because each generator records different inputs and nothing queries them field by field. Hand-authored content has `generation = {}` and `generation_key = NULL`.

### 4.5 `content_version_sources` [NEW] — provenance links (reference + point-in-time snapshot)

```sql
CREATE TABLE IF NOT EXISTS content_version_sources (
    content_version_id        text        NOT NULL REFERENCES content_versions(id),
    entity_type               text        NOT NULL CHECK (entity_type IN
                                  ('actor','campaign','malware','tool','technique_evidence')),
    entity_id                 text        NOT NULL,
    provider                  text        NOT NULL,
    external_id               text        NOT NULL DEFAULT '',
    confidence_at_generation  text        NOT NULL DEFAULT '',
    first_seen_at_generation  timestamptz,
    last_sync_at_generation   timestamptz,
    role                      text        NOT NULL CHECK (role IN ('primary','supporting')),
    tenant_id                 text        NOT NULL DEFAULT 'default',
    PRIMARY KEY (content_version_id, entity_type, entity_id, provider)
);
-- app_role.go: REVOKE UPDATE, DELETE ON content_version_sources FROM bas_app;
```

- **[REUSE]** Rows point into `intelligence_entity_sources` (campaign/malware/tool), `threat_actor_sources` (actor), and `technique_evidence`. This is not a second provenance model.
- **No FK on purpose:** source rows are upserted and may be deleted or renamed; content history must outlive them.
- **Snapshot semantics:** the `*_at_generation` columns record what the factory knew when the version was created. They are never refreshed from the live source rows. `first_seen_at_generation` is copied from `intelligence_entity_sources.first_seen`, or for actors from `threat_actor_sources.last_seen` / `threat_actor_activity.first_observed` (whichever is earliest and non-null). It stays NULL when no source supplies one; it is never invented.
- **Threat-to-Content Velocity** (Phase 11) = `published_at − min(first_seen_at_generation)` over a version's primary sources. It is computable retroactively for every version created from Phase 1 onward.

### 4.6 `content_safety_verdicts` [NEW]

```sql
CREATE TABLE IF NOT EXISTS content_safety_verdicts (
    id                  bigserial   PRIMARY KEY,
    content_version_id  text        NOT NULL REFERENCES content_versions(id),
    classifier          text        NOT NULL,      -- 'execclass'
    classifier_version  text        NOT NULL,
    verdict             text        NOT NULL,      -- classifier's native vocabulary
    detail              jsonb       NOT NULL DEFAULT '[]',
    evaluated_at        timestamptz NOT NULL DEFAULT NOW(),
    tenant_id           text        NOT NULL DEFAULT 'default',
    UNIQUE (content_version_id, classifier, classifier_version)
);
```

Phase 1 stores the **existing `execclass` verdict in its native vocabulary**. The version verdict is the worst step class (`destructive > potentially_destructive > non_destructive`). `detail` holds per step `{technique_id, action_key, class, destructive_action, blast_radius}`. Steps that are only known at dispatch (dynamic ART/Caldera modes) are recorded as `{"dynamic": true}` and do not lower the verdict. No mapping to SAFE/CONTROLLED/HIGH-RISK/BLOCKED — that four-level scale belongs to the Phase 5 safety engine, which will add rows with its own `classifier`. Computed at intake.

### 4.7 `content_validations` [NEW]

```sql
CREATE TABLE IF NOT EXISTS content_validations (
    id                  text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    content_version_id  text        NOT NULL REFERENCES content_versions(id),
    level               text        NOT NULL CHECK (level IN
                            ('STRUCTURAL','STATIC','EXECUTION','TELEMETRY','DETECTION')),
    outcome             text        NOT NULL CHECK (outcome IN
                            ('PASS','FAIL','ERROR','DETECTED','PREVENTED','LOGGED','MISSED',
                             'NO_DATA','NOT_APPLICABLE')),
    run_id              text        REFERENCES scenario_runs(id),
    validator           text        NOT NULL,
    validator_version   text        NOT NULL,
    environment         jsonb       NOT NULL DEFAULT '{}',   -- agent_version, os, arch
    detail              jsonb       NOT NULL DEFAULT '{}',
    created_at          timestamptz NOT NULL DEFAULT NOW(),
    tenant_id           text        NOT NULL DEFAULT 'default',
    CHECK (level IN ('STRUCTURAL','STATIC') OR outcome <> 'PASS' OR run_id IS NOT NULL),
    CHECK (level <> 'DETECTION' OR outcome NOT IN ('PASS','FAIL'))
);
```

- **[REUSE]** Execution evidence stays where it lives (`scenario_runs`, `execution_attempts`, `siem_correlations`, `verification_evidence`). A validation row references the run; it does not copy results.
- Detection-level outcomes use the detection vocabulary only (DETECTED/PREVENTED/LOGGED/MISSED/ERROR/NO_DATA/NOT_APPLICABLE).
- **`NO_DATA` and `NOT_APPLICABLE` are excluded from every aggregate's denominator.** An aggregate whose denominator is zero reports `NO_DATA`, never 0% or a default.
- Phase 1 writes **STRUCTURAL** validations at intake (YAML parses, required fields present, technique IDs exist in `techniques`, ID unique, schema version known). Higher levels are written by later phases; the table and API exist now.

### 4.8 `scenario_runs` [ALTER]

```sql
ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS content_version_id text REFERENCES content_versions(id);
ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS execution_kind text NOT NULL DEFAULT 'legacy';
-- CHECK (execution_kind IN ('content','remediation','technique_verification','variant','legacy'))
-- CHECK (execution_kind <> 'content' OR content_version_id IS NOT NULL)
```

- The column default is `legacy`, so every pre-existing row is honestly labelled without a backfill UPDATE, and an insert site that forgets to set a kind lands as `legacy`. That is caught by test A8, not silently treated as content.
- Every insert site sets `execution_kind` explicitly; content runs set `content_version_id` **in the same INSERT**, before dispatch.
- Synthetic runs (`remediation`, `technique_verification`, `variant`) have no registry version but still record command hashes in `step_meta`.

### 4.9 `step_meta` [ALTER Go struct only — jsonb, no migration]

`scenario.StepMeta` gains:

```go
Component        string `json:"component,omitempty"`        // art | caldera | custom
ComponentVersion string `json:"componentVersion,omitempty"` // art_content_meta.source_version, Caldera version if known
CommandSHA256    string `json:"commandSha256,omitempty"`
```

`ComponentVersion` for ART is `art_content_meta.source_version`. The orchestrator has no Caldera library version source today, so Caldera steps record `""` (shown as `unknown`) and rely on `CommandSHA256` alone for drift — the stronger invariant either way. Adding a Caldera version source is out of scope. The `component_versions.caldera` key in §4.4 follows the same rule.

`CommandSHA256 = sha256(canonical JSON {executor, command, cleanup, payloads: [{name, sha256(content)}] sorted by name})` over the fully resolved `ScenarioStep` sent to the agent — exactly what executed. Computed in `BuildStepMeta`.

### 4.10 Left untouched

`scenario_techniques` (dead; not repurposed — ATT&CK mapping lives on `content_versions.technique_ids`), `art_*`, Caldera integration, `integrity` signing code, all intelligence tables.

## 5. Intake and generation

New package `internal/contentregistry` owns all reads and writes of §4.1–4.7. The scenario engine and API call it; nothing else writes registry tables.

### 5.1 Intake: disk → registry (on every engine load / reload)

For each scenario YAML:

1. Read bytes, compute `sha256`, parse (parse failure → not registered, not executable, logged with path).
2. Look up `(content_id, sha256)` in `content_versions`. **Hit → no-op.**
3. Miss → determine origin/trust/lifecycle **from location and proof only, never from YAML fields**:

| Location | Origin | Trust | Lifecycle | Actor |
|---|---|---|---|---|
| builtin, signature **explicitly verified** | VENDOR | VENDOR_SIGNED (+ `signature_bytes`) | PUBLISHED | intake |
| builtin, `.sig` missing or invalid (signing enabled) | — refused, not registered, TAMPER ALERT (unchanged behavior) | | | |
| builtin, dev build (`!signingEnabled()`) | VENDOR | UNTRUSTED | PUBLISHED | intake |
| `intel/` | LOCAL | UNTRUSTED | DRAFT | generator:connector |
| `custom/`, written by the UI save path | LOCAL | LOCAL_TRUSTED | PUBLISHED_LOCAL | user:\<operator\> |
| `custom/`, any other change | LOCAL | UNTRUSTED | DRAFT | intake |

4. If `scenarios(content_id)` exists with the **other** origin → **refuse** (not registered, error log, `audit_logs` entry). The previously registered identity keeps running.
5. Insert identity (if new), version (`version = max + 1`), creation event, STRUCTURAL validation, and safety verdict in **one transaction**.

**Verification API change.** `integrity` gains `VerifyScenarioBytes(content, sig []byte) (verified bool, err error)`. It returns `verified == true` only when an RSA verification actually succeeded; the dev-build path returns `(false, nil)`. Intake assigns `VENDOR_SIGNED` **only** on `verified == true`. `VerifyScenarioFile` keeps its existing contract for its existing callers.

**UI save path.** `Engine.Save` (custom scenarios) calls `contentregistry.RegisterLocalApproved(bytes, operator)` in the same request after writing the file. The version is created as `PUBLISHED_LOCAL` with an approval event `actor = user:<operator>`, `reason = "operator save"`. When intake later sees the same bytes on disk it hits step 2 (no-op). Any byte difference — an out-of-band edit — misses and becomes a new LOCAL/UNTRUSTED/DRAFT version. The previously published local version stays executable (§6). This gives local content the same immutability guarantee as vendor content.

**Engine map.** The in-memory map still serves the parsed *disk* content for authoring/listing views. All execution and historical reads go through the registry (§6, §7).

### 5.2 Generator rewire

`connector/generator.go`:

- Computes `generation_key` (§4.4) instead of using the filename fingerprint as identity.
- Content ID becomes `intel-<sha256(lower(canonical actor name))[:12]>` — derived from the *actor identity only*, not from techniques or `generation_key` — so successive technique-set changes for the same actor become **versions of one content ID** instead of new, separately runnable files.
- Writes the YAML to `scenarios/intel/<content_id>.yaml` (overwriting the working copy is fine — history lives in the registry) and calls `contentregistry.RegisterGenerated(bytes, generation, sources)`, which creates the DRAFT version and its `content_version_sources` snapshot rows in one transaction.
- Same `generation_key` + same bytes → existing version (idempotent). Changed inputs → new DRAFT version; prior versions untouched.
- Removes the generator's "file exists → skip" logic; idempotency is the registry's job.

Legacy `intel-<fingerprint>.yaml` files from before the rewire are registered by migration (§8) under their existing IDs as DRAFT. They are not merged into the new per-actor IDs; an operator can approve or retire them.

## 6. Runtime gate

### 6.1 Contract

> The execution engine MUST resolve a scenario to an immutable content version and MUST refuse execution unless that version has an allowed origin/trust/lifecycle combination. `scenario_runs.content_version_id` MUST be written before execution begins.

`contentregistry.ResolveExecutable(ctx, contentID) (ExecutableVersion, error)` is the **single authoritative execution boundary**. It returns the **highest version number** satisfying:

| origin | trust_level | lifecycle | result |
|---|---|---|---|
| VENDOR | VENDOR_SIGNED | PUBLISHED | **ALLOW** |
| LOCAL | LOCAL_TRUSTED | PUBLISHED_LOCAL | **ALLOW** |
| VENDOR | UNTRUSTED | PUBLISHED | ALLOW **only in dev builds** (§6.3), else DENY |
| anything else | | | **DENY** |

For a `VENDOR_SIGNED` candidate the resolver **re-verifies** `signature_bytes` against `artifact_bytes` with the compiled-in key before allowing it (one RSA verify per run start, milliseconds). A failure denies the run with `signature re-verification failed` and writes an `audit_logs` TAMPER entry — so a DB-level tamper of bytes or signature by a superuser is still caught at execution time.

`ExecutableVersion` carries the version ID and the scenario parsed from **stored `artifact_bytes`** (not disk). A denial returns `ErrNotExecutable{ContentID, Reason}`, where the reason names the newest version and its state (e.g. `no executable version; latest v3 is DRAFT/UNTRUSTED`).

**A newer non-executable version never displaces an older executable one:** v1 PUBLISHED + v2 VALIDATING → v1 runs.

### 6.2 Enforcement points

All content run-creation paths route through one helper, `h.createContentRun(ctx, contentID, agentID, opts) (runID, ExecutableVersion, error)`, which calls `ResolveExecutable`, inserts `scenario_runs` with `execution_kind='content'` and `content_version_id` in a single INSERT, and returns the registry-parsed scenario for `BuildSteps`. The three content INSERTs in `api/handlers.go` (`full-scan` at ~1468, `safe-simulation` at ~1524, `dispatchRun` at ~1844) are replaced by it; every caller that reaches them (manual runs, campaigns, scheduled assessments, EM sweep layers, revalidation) inherits the gate.

Synthetic run sites set their kind explicitly and do not call the resolver: `remediation_dispatch.go` (`remediation`, `technique_verification`) and `variant_handlers.go` (`variant`).

### 6.3 Dev-build exception

- Controlled solely by `integrity.signingEnabled()`, which compares the **compiled-in** `ScenarioPublicKeyPEM` constant against the placeholder. It is not readable from config, env, or DB. The spec requires a test asserting no runtime path can change it.
- Allows exactly one extra combination (VENDOR + UNTRUSTED + PUBLISHED). LOCAL content gets no exception.
- **Never mutates stored data:** the version stays `trust_level = UNTRUSTED`.
- Logs a prominent startup warning: `DEV BUILD: unsigned vendor content is executable; production builds deny it`.

## 7. Historical interpretation

- Every post-run read that today calls `engine.Get(run.scenario_id)` to interpret results (results view, reports, findings, step-name resolution — e.g. `handlers.go:2645`) instead calls `contentregistry.LoadVersion(run.content_version_id)` and parses the stored bytes.
- `execution_kind = 'legacy'` (pre-registry) runs: interpreted against current content **and labelled** `Unversioned — interpreted against current content` in UI and reports.
- If stored bytes fail to parse: the run is shown as `content version unreadable`. It **never** falls back to current YAML.
- **Component drift:** `contentregistry.CheckDrift(runID)` re-resolves each step of the run's version under the current ART/Caldera catalog and compares `CommandSHA256`. Mismatch → `COMPONENT_DRIFT` with `{task_id, historical_component_version, current_component_version}`. Computed on demand, not stored. Steps whose historical record lacks a hash (legacy) report `DRIFT_UNKNOWN`.

## 8. Migration

Runs at orchestrator startup after DDL, idempotently.

1. **DDL** (§4), plus the `app_role.go` REVOKE/GRANT additions.
2. **No UPDATE of existing `scenario_runs`** — the `legacy` default labels them.
3. **First intake pass** (§5.1) with migration overrides:
   - builtin → normal intake (VENDOR_SIGNED/PUBLISHED, or refused if tampered).
   - `custom/*` → LOCAL / LOCAL_TRUSTED / PUBLISHED_LOCAL, event `actor = migration:pre-registry`, `reason = "historical authorization: authored via operator UI before approval tracking existed; not reviewed during migration"`.
   - `intel/*` → LOCAL / UNTRUSTED / DRAFT.
   - The override applies only when no version for that content ID exists yet. On later runs the hash lookup makes it a no-op.
4. **Inventory report**, computed after the pass and stored as an `audit_logs` event the first time it is produced (`action = content_registry.migration_inventory`):
   - intel scenarios moved to DRAFT (IDs),
   - scheduled assessments referencing them (IDs, names),
   - campaigns referencing them,
   - custom scenarios grandfathered (IDs),
   - builtin scenarios refused (IDs, reason).
   Served at `GET /api/content-registry/migration-report` (Admin). The UI shows a dismissible banner while any listed schedule still references a non-executable scenario.

## 9. API (minimum for Phase 1)

All under `/api/content-registry`, RBAC-registered in the existing permission matrix (`TestRBACMatrix_NoDrift` must stay green for the new routes).

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/content/{id}/versions` | Viewer+ | versions with origin/trust/lifecycle, hash, created_by |
| GET | `/versions/{vid}` | Viewer+ | version detail incl. sources, safety verdicts, validations, events |
| GET | `/versions/{vid}/artifact` | Analyst+ | exact stored YAML bytes |
| POST | `/versions/{vid}/transition` | Admin | `{to, reason}` → state machine; actor = caller |
| GET | `/runs/{runId}/drift` | Viewer+ | §7 drift report |
| GET | `/migration-report` | Admin | §8 inventory |

The existing scenario list/detail views show a lifecycle + trust badge and, when the newest version is not executable, `Running v<n>; v<m> awaiting approval`. Manual dispatch of a non-executable scenario returns **409** with the resolver's reason. Review queues, diffs, and a dedicated approval UI are out of scope.

## 10. Failure semantics (all fail-closed)

| Failure | Behavior |
|---|---|
| Registry/DB unavailable at run creation | Deny the run. No fallback to `engine.Get`. |
| Intake failure for one file (I/O, parse, DB) | That file is not registered → not executable; others proceed; logged with path. |
| Builtin signature invalid/missing (signing enabled) | Refused, TAMPER ALERT (unchanged). |
| Cross-origin ID collision | Refused; error log + `audit_logs` entry; existing identity unaffected. |
| Manual run denied by gate | HTTP 409 with reason. |
| Scheduled / campaign / revalidation / EM-sweep run denied | Visible run-level error event + notification. Never a silent skip. |
| Stored version bytes unparseable on historical read | `content version unreadable`; no fallback. |
| Illegal lifecycle transition | Rejected by state machine (HTTP 409); DB CHECKs independently block illegal resulting states. |
| Attempt to rewrite artifact bytes / delete a version as `bas_app` | Rejected by PostgreSQL privileges. |

## 11. Scope

**IN:** content identity; immutable versions; YAML artifact bytes + SHA-256 + signature bytes; provenance link snapshots incl. `first_seen_at_generation`; origin / trust / lifecycle; lifecycle event log incl. approval records; `execclass` safety-verdict storage; validation-result storage (STRUCTURAL written; other levels storable); `scenario_runs → content_version_id` + `execution_kind`; resolved command hashes in `step_meta`; drift check; idempotent generation identity; generator rewire; runtime gate; historical interpretation; migration + inventory; minimum API and badges.

**OUT:** new intelligence ingestion; new threat scoring; new generation engine; sandbox / validation lab; new safety classifier or four-level safety scale; new signing implementation; content distribution / bundle import (incl. the open airgap-signing gap); archiving ART/Caldera catalogs; registry versioning of variant templates; approval review queues and diff UI; deleting versions. **Not yet governed by the registry (named so nobody assumes otherwise):** the exercise engine, OpenAEV-synced scenarios, attack-path jobs.

## 12. Acceptance tests

Named invariant tests against a real Postgres (existing Docker test harness; `go test ./... -p 2`).

| # | Name | Asserts |
|---|---|---|
| A1 | `TestTraceableCandidate` | A MISP/OpenCTI-sourced actor yields a DRAFT version with source snapshot rows (provider, external_id, confidence, `first_seen_at_generation`), `technique_ids`, `generation_key`, artifact hash — and is not executed. |
| A2 | `TestGenerationIdempotent` | Same inputs twice → one version. Changed inputs → v2; v1 byte-identical. |
| A3 | `TestPublishedVersionImmutable` | Changed published YAML → new version; old version byte-identical and still resolvable. Direct `UPDATE … SET artifact_bytes` and `DELETE` as `bas_app` fail. |
| A4 | `TestImpossibleStatesRejectedByDB` | Table-driven over every origin × trust × lifecycle combination: exactly the legal ones insert; the rest fail on CHECK/FK. Includes LOCAL+VENDOR_SIGNED+PUBLISHED. |
| A5 | `TestRuntimeGateMatrix` | Full combination matrix: exactly the two allowed combinations resolve in production mode; the dev exception adds only VENDOR+UNTRUSTED+PUBLISHED. |
| A6 | `TestDevExceptionDoesNotMutateTrust` | In dev mode, stored trust of an executable builtin stays UNTRUSTED. |
| A7 | `TestDraftDoesNotDisplacePublished` | v1 PUBLISHED + v2 VALIDATING → resolves v1. |
| A8 | `TestEveryRunInsertSetsKind` | Enumerates every `INSERT INTO scenario_runs` in `internal/api` (source scan) and asserts each sets `execution_kind` explicitly; DB rejects `execution_kind='content'` with NULL version. |
| A9 | `TestHistoricalReportUsesStoredVersion` | YAML changes after a run; the run's results/report render from the old version's bytes. |
| A10 | `TestComponentDriftDetected` | Changed ART resolution for a step → `COMPONENT_DRIFT` with both versions; unchanged → no drift. |
| A11 | `TestLocalOutOfBandEditBecomesDraft` | Out-of-band edit to a PUBLISHED_LOCAL file → new LOCAL/UNTRUSTED/DRAFT version; prior version still executes. |
| A12 | `TestCrossOriginCollisionRefused` | `custom/<builtin-id>.yaml` refused; signed builtin still resolves and runs. |
| A13 | `TestNoDataExcludedFromDenominator` | Aggregates exclude NO_DATA/NOT_APPLICABLE; all-NO_DATA yields NO_DATA, not 0%. |
| A14 | `TestMigrationIdempotentWithInventory` | Two migration runs → identical registry; inventory counts match fixtures (intel → DRAFT, custom → grandfathered with `migration:pre-registry`, affected schedules listed). |
| A15 | `TestVerifiedTrustRequiresExplicitProof` | `VerifyScenarioBytes` returning `(false, nil)` never yields VENDOR_SIGNED. |
| A16 | `TestSigningEnabledNotRuntimeConfigurable` | `signingEnabled()` depends only on the compiled constant. |
| A17 | `TestApprovalRequiresHumanActor` | Transition into APPROVED / PUBLISHED_LOCAL / REJECTED with a non-user actor is rejected by the DB CHECK and the state machine. |
| A18 | `TestAttachVendorSignature` | Rejects: a non-NULL existing signature, an invalid signature, LOCAL content. Accepts a valid signature and sets VENDOR_SIGNED atomically. APPROVED → PUBLISHED is rejected until it has succeeded. |
| A19 | `TestGateReverifiesVendorSignature` | Tampered `artifact_bytes` or `signature_bytes` (written as superuser) on a VENDOR_SIGNED/PUBLISHED version → run denied with an audit TAMPER entry. |

**Headline acceptance criterion:** Given a threat from MISP/OpenCTI, Audspect creates a fully traceable content candidate without executing it — preserving source provenance, ATT&CK mappings, freshness, confidence, lifecycle state, and version identity — and every subsequent run of any approved version is attributable to that immutable version and the exact resolved commands executed.

## 13. Risks and open follow-ups

- **Scheduled assessments on intel scenarios will fail after upgrade** (accepted, D8). Mitigated by inventory + banner + visible errors.
- **Engine reload and DB coupling:** the engine now needs the DB at load to register content. Startup already requires Postgres; intake errors fail closed per file.
- **`scenarios.name` / `category`** in the repurposed table are populated from YAML at intake for listing; they are display data, not identity.
- **Phase 8 (signing & distribution)** must define how vendor content arrives on customer deployments beyond the image-baked `scenarios/` directory, and must close the open airgap-signing gap before offline bundles carry vendor content.
