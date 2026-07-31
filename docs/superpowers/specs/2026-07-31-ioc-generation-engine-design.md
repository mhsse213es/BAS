# IOC Generation Engine — Design Spec

**Phase C of the IOC Handling initiative** (source vision: `iochandling.txt`, repo root, §5-7).
Phase 0+A and Phase B are both **done** — canonical `IOC` model, `iocs`/`ioc_sightings`
registry, extraction from `DetectionAlert`, technique/verdict correlation, `threatgraph`
IOC node, `internal/analytics/ioc.go` dashboard. This phase is the first that generates
new data rather than reading/extending what already flows through the system — flagged
as "genuinely new engineering" in the Phase 0+A spec, unlike Phase B.

## Goal

Give ART-sourced scenario steps a fresh artifact identity (filename, mutex, registry key,
service name) on every dispatch, instead of the same static value every time — closing
the literal gap `iochandling.txt` §5 describes ("A mature BAS rarely hardcodes IOCs...
Otherwise EDR vendors simply whitelist them").

## Investigation: the actual root cause and injection point

- **`artResolveArgs`** (`internal/scenario/art.go:381-393`) substitutes every `#{argName}`
  token in an ART atomic's command with that argument's **static YAML default**
  (`artInputArg.Default`). This runs exactly once, inside `NewARTStoreFromDB` /
  `ARTStore.Reload` — i.e. at content-load time (server startup or a content reseed), not
  per execution. The resolved `Command` string is cached in `ARTStore.steps` and reused
  identically forever until the next reseed.
- **`ARTStore.GetStepsByPlatform`** (`art.go:170-191`) returns *copies* of the cached
  steps (`for _, st := range all { out = append(out, st) }` — `ScenarioStep` is a plain
  struct, no shared mutable state) — safe to mutate `Command` on the returned slice
  without corrupting the shared cache.
- **`scenario.BuildSteps`** (`internal/scenario/builder.go:68`) is called fresh on every
  scenario dispatch — confirmed via its two call sites in `internal/api/handlers.go`:
  `TriggerScan` (line 862, the `full-scan` special-case endpoint) and **`dispatchRun`**
  (line 1201), the general-purpose path every regular scenario run goes through
  (`internal/api/handlers.go:1033-1206`: agent-state gate, OS-compatibility check,
  concurrency guard, variant-depth/subset selection, *then* `BuildSteps`).
  `dispatchRun` already assigns `runID = newID()` at line 1096, **before** its
  `BuildSteps` call at line 1201 — so `runID`/`agentID`/`sc.ID` (scenario ID) are all
  already in scope at the exact point Phase C needs to hook in.
- **Consequence**: by the time `BuildSteps` returns a step to `dispatchRun`, its
  `#{argName}` tokens are already gone — replaced with ART's static default text. There
  is nothing left to substitute against unless `artResolveArgs` is told to leave specific
  argument names untouched.
- **ART argument names have no fixed vocabulary.** `input_arguments` keys are chosen by
  each atomic test's author (`filename`, `output_file`, `mutex_name`, `key_name`, ... —
  inconsistent across tests). Classifying "this argument represents a mutex" from the name
  alone would require fragile heuristics. **Decision: a small hand-curated
  `(techniqueID, testName, argName) → Type` table**, not automatic classification — same
  "only populate what has a real, unambiguous source" discipline Phase 0+A applied to the
  IOC type taxonomy (2 of 14 types populated, stated plainly).
- **Variant Engine's own pipeline is separate and out of scope for V1.**
  `internal/api/variant_handlers.go`'s dispatch path pulls raw base commands via
  `resolveBaseCommand`/`loadPayloadFamilies`, never touching `ARTStore`/`artResolveArgs`
  at all. Wiring Generation into that second pipeline is real, additional work, not
  attempted here — see Non-goals.
- **A real gap in the Phase 0+A taxonomy**: `iochandling.txt` §1's own IOC type list has
  "File Hash" but no bare "Filename" entry, even though §5/§6 explicitly ask to generate
  *new filenames* (`simulation.exe → simulation1.exe → explorer_update.exe → ...`).
  `iocregistry.Type` inherited this gap verbatim from §1. **Decision: add
  `TypeFilename = "filename"`** to `iocregistry.Type` in this phase — filling a real hole
  in the source taxonomy the doc's own §5/§6 already assumes exists, not inventing a new
  concept.

## Decisions

1. **Scope: non-network artifact types only** — `filename`, `mutex`, `registry_key`,
   `service`. No `domain`/`ip`/`url`/`certificate` (confirmed with the user: these need
   either non-resolving placeholder infrastructure or Audspect-owned lab domains/certs —
   materially bigger scope and safety surface than local, non-network identity values,
   consistent with this codebase's BFSI-safety-conscious posture — evasions gated behind
   `IncludeAdvanced`, `SAFE`/`MODERATE`/`ADVANCED` risk tiers).
2. **`§7` (Randomization) is not re-implemented.** `variant.Generate`'s 4 encodings ×
   evasions already substantially cover behavioral/command-shape randomization. Phase C's
   job is narrower: artifact *identity* only (§5/§6), layered independently on top of
   whatever encoding/evasion Variant Engine already chose (they operate on different axes
   — identity vs. delivery — and don't interact).
3. **New package: `internal/artifactgen`** — owns the curated mapping table and the 4
   generator functions. Mirrors this session's per-concern package convention
   (`iocregistry`, `threatpriority`, `threatgraph`).
4. **`artResolveArgs` gets a skip-list.** For any `(techniqueID, testName, argName)` in
   `artifactgen`'s curated table, `artResolveArgs` leaves `#{argName}` as a literal token
   in the cached `Command` instead of substituting ART's static default. Every
   non-curated argument keeps today's exact behavior — zero risk to the ~thousands of
   atomic tests not in the curated table.
5. **Curator contract**: a curated entry's `argName` must be a *leaf* value (a name,
   not a structural path) whose substitution doesn't change the technique's behavior —
   only its identity. Documented as an explicit constraint curators must follow, not
   enforced in code (same trust level this codebase already gives ART content authors).
6. **Substitution happens once per `dispatchRun` call**, immediately after `BuildSteps`
   returns (`handlers.go:1201`) — giving "new value every execution" for free, since
   `dispatchRun` already runs fresh per dispatch. No change to `ARTStore`'s caching or
   reload semantics.
7. **Registry integration**: each generated value is written into `iocregistry` via a new
   exported function, `Status = generated` on first write — the first real producer of
   that lifecycle state (unused since Phase 0+A defined it). `Origin = generated`,
   `Source = variant` — both placeholders Phase 0+A explicitly reserved for this phase.
   Transitioning `generated → executed → observed/detected/missed` based on the run's
   actual outcome is real, separate work for a later phase (see Non-goals) — V1 only
   writes the initial `generated` row.
8. **New `iocregistry.Type` value**: `TypeFilename = "filename"` (see Investigation above
   — filling a real gap in `iochandling.txt` §1's own taxonomy, not adding an unfounded
   concept).

## Architecture

### 1. Taxonomy fix — `internal/iocregistry/types.go`

Add one constant to the existing `Type` block:

```go
const (
	TypeFileHash    Type = "file_hash"
	TypeFilename    Type = "filename" // added Phase C -- iochandling.txt §5/§6 assume this exists; §1's own list omits it
	TypeDomain      Type = "domain"
	// ... rest unchanged
)
```

### 2. Curated mapping + generators — `internal/artifactgen`

```go
package artifactgen

import "github.com/audspect/bas/internal/iocregistry"

// ArgKey identifies one ART input argument this package knows how to replace with a
// freshly generated value.
type ArgKey struct {
	TechniqueID string
	TestName    string // Atomic Red Team's atomic_tests[].name -- matches art.go's artAtomicTest.Name
	ArgName     string
}

// curated maps a known-safe argument to the IOC type its value represents. Grows over
// time as more atomic tests are reviewed and added -- deliberately small at launch,
// matching Phase 0+A's "only what has a real, unambiguous source" discipline.
var curated = map[ArgKey]iocregistry.Type{
	// Seeded with a first, verifiable batch -- exact entries added once the
	// corresponding atomic tests are reviewed against ART content during Task 2.
}

// Lookup returns the IOC type for a curated argument, or "" if this argument isn't
// curated (the caller leaves ART's static default substitution alone in that case).
func Lookup(techniqueID, testName, argName string) (iocregistry.Type, bool) {
	t, ok := curated[ArgKey{TechniqueID: techniqueID, TestName: testName, ArgName: argName}]
	return t, ok
}

// CuratedFor returns every curated ArgKey/Type pair for a technique, regardless of
// which of its atomic tests they belong to -- the dispatch-time substitution loop
// (handlers.go) tries each and skips any whose #{argName} token isn't present in the
// particular step's command (a technique can have multiple atomic tests; only the
// matching one contains a given token).
func CuratedFor(techniqueID string) map[ArgKey]iocregistry.Type {
	out := map[ArgKey]iocregistry.Type{}
	for k, t := range curated {
		if k.TechniqueID == techniqueID {
			out[k] = t
		}
	}
	return out
}
```

```go
// generate.go
package artifactgen

import (
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"strings"

	"github.com/audspect/bas/internal/iocregistry"
)

// filenameStems are plausible legitimate-sounding base names -- avoids fully random
// garbage (which is itself a signature; iochandling.txt §6's own example rotates
// through names like "explorer_update.exe", "office_sync.exe", not random hex).
var filenameStems = []string{"explorer_update", "office_sync", "svc_healthcheck", "sys_diag", "print_helper"}

var serviceStems = []string{"WinDefend_Helper", "UpdateOrchestrator", "DiagTrackSvc", "NetProfSvc"}

var registryKeyStems = []string{"RunOnceHelper", "AppUpdateCheck", "SysMaintTask", "UserPrefSync"}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func pick(stems []string, seed []byte) string {
	return stems[int(seed[0])%len(stems)]
}

// Generate produces a fresh value for t, preserving origExt (the file extension from
// ART's own default, e.g. ".exe"/".dll"/".txt") when t is TypeFilename -- the generated
// name must still make sense to the technique (a dropper test expecting a .dll needs a
// .dll back, not a random extension).
func Generate(t iocregistry.Type, origDefault string) string {
	seed := make([]byte, 4)
	_, _ = rand.Read(seed)
	suffix := randHex(2)

	switch t {
	case iocregistry.TypeFilename:
		ext := filepath.Ext(origDefault)
		if ext == "" {
			ext = ".exe"
		}
		return pick(filenameStems, seed) + "_" + suffix + ext
	case iocregistry.TypeMutex:
		return `Global\` + pick(filenameStems, seed) + "-" + randHex(8)
	case iocregistry.TypeRegistryKey:
		return pick(registryKeyStems, seed) + "_" + suffix
	case iocregistry.TypeService:
		return pick(serviceStems, seed) + "_" + strings.ToUpper(suffix)
	default:
		return origDefault
	}
}
```

### 3. `artResolveArgs` skip-list — `internal/scenario/art.go`

```go
func artResolveArgs(cmd string, args map[string]artInputArg, techniqueID, testName string) string {
	if cmd == "" {
		return ""
	}
	for name, arg := range args {
		if _, curated := artifactgen.Lookup(techniqueID, testName, name); curated {
			continue // leave #{name} literal -- substituted per-dispatch, not at build time
		}
		def := arg.Default
		if def == "" {
			def = `$env:TEMP\bas-placeholder-` + name
		}
		cmd = strings.ReplaceAll(cmd, "#{"+name+"}", def)
	}
	return cmd
}
```

Both call sites (`art.go:303`, `art.go:330`) gain the two new parameters
(`techniqueID`, `test.Name` — both already in scope at each call site).

### 4. Dispatch-time substitution — `internal/api/handlers.go`

New helper, called right after each `BuildSteps` call in `dispatchRun`
(`handlers.go:1201`):

```go
func (h *Handler) applyGeneratedArtifacts(ctx context.Context, scenarioID, runID, agentID string, steps []scenario.ScenarioStep) []scenario.ScenarioStep {
	for i := range steps {
		for key, iocType := range artifactgen.CuratedFor(steps[i].TechniqueID) {
			token := "#{" + key.ArgName + "}"
			if !strings.Contains(steps[i].Command, token) {
				continue
			}
			value := artifactgen.Generate(iocType, "")
			steps[i].Command = strings.ReplaceAll(steps[i].Command, token, value)
			if err := iocregistry.RegisterGenerated(ctx, h.db, iocType, value, scenarioID, runID, agentID, steps[i].TechniqueID); err != nil {
				log.Printf("[artifactgen] register failed for run %s: %v", runID, err)
			}
		}
	}
	return steps
}
```

`artifactgen.CuratedFor(techniqueID)` is a small addition to `artifactgen` (alongside
`Lookup`) that returns every curated `ArgKey`/`Type` pair for a technique, so this loop
doesn't need to know argument names in advance — it just tries every curated key that
technique has and skips any whose token isn't present in that particular test's command
(a technique can have multiple atomic tests; only the matching one contains the token).

Call site (`handlers.go:1201`):

```go
	steps, err := scenario.BuildSteps(buildSc, h.calderaURL, h.calderaKey, h.artStore, agentOS)
	if err != nil {
		// ... unchanged
	}
	steps = h.applyGeneratedArtifacts(ctx, sc.ID, runID, agentID, steps)
```

Best-effort, same as Phase 0+A/B's extraction: a `RegisterGenerated` failure is logged,
never fails the dispatch — an artifact identity substitution that can't be registered in
the IOC registry should still execute (the registry is observability, not a gate).

### 5. Registry write — `internal/iocregistry/generate.go`

```go
// RegisterGenerated records a freshly generated artifact identity. First real producer
// of Status=generated (unused since Phase 0+A defined the lifecycle). Upsert semantics
// match ExtractFromDetectionAlert's dedup contract, but a *new* generated value is
// expected to be a new (type, value) pair essentially every call (random suffix) -- the
// ON CONFLICT path exists for correctness, not as the common case.
func RegisterGenerated(ctx context.Context, pool *pgxpool.Pool, t Type, value, scenarioID, runID, agentID, techniqueID string) error {
	var id string
	err := pool.QueryRow(ctx, `
		INSERT INTO iocs (type, value, source, origin, status)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (type, value) DO UPDATE SET
			last_seen = NOW(),
			sighting_count = iocs.sighting_count + 1
		RETURNING id`,
		string(t), value, string(SourceVariant), string(OriginGenerated), string(StatusGenerated),
	).Scan(&id)
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO ioc_sightings (ioc_id, scenario_id, run_id, agent_id, technique_id)
		VALUES ($1, $2, $3, $4, $5)`,
		id, scenarioID, runID, agentID, techniqueID)
	return err
}
```

Reuses the existing `iocs`/`ioc_sightings` tables — no new schema beyond the `filename`
type addition (which needs no migration; `iocs.type` is a plain `text` column).

## Non-goals

- **No `domain`/`ip`/`url`/`certificate` generation** — confirmed out of scope for V1;
  candidate for a later phase once network-touching artifact strategy (placeholder vs.
  lab infrastructure) is decided.
- **No Variant Engine pipeline integration** — `variant_handlers.go`'s
  `resolveBaseCommand`/`loadPayloadFamilies` path doesn't go through `ARTStore`/
  `artResolveArgs` at all; wiring Generation into it is separate, real work.
- **No `TriggerScan`/`SafeScan` integration** — both bypass `dispatchRun` entirely
  (they build+dispatch inline). Only the general `dispatchRun` path gets Generation in
  V1.
- **No lifecycle transition beyond `generated`** — `executed`/`observed`/`detected`/
  `missed` transitions for generated IOCs need to correlate against the run's actual
  outcome (was the file actually dropped, did an EDR alert on it) — that reconciliation
  is real, separate work, not attempted here.
- **No IOC Rotation *history/versioning*** (§14) — each dispatch gets one fresh value;
  no "v1 → v2 → v3" chain is tracked. The registry's existing `sighting_count`/
  `last_seen` already capture reuse; a full version chain is unneeded complexity for V1.
- **No automatic classification of ART arguments** — curated table only, grows by
  explicit review, not name-pattern heuristics (see Investigation).
- **No frontend.**

## Testing

- `internal/artifactgen/generate_test.go`: `Generate` for each of the 4 types returns a
  non-empty, correctly-shaped value (filename preserves the given extension; mutex starts
  with `Global\`; two consecutive calls for the same type produce different values —
  proves the random suffix actually varies, not a fixed table lookup).
- `internal/artifactgen/curated_test.go`: `Lookup` returns `(type, true)` for a seeded
  curated entry and `("", false)` for an unknown key; `CuratedFor` returns every entry
  for a technique with 2+ curated args and an empty slice for a technique with none.
- `internal/scenario/art_test.go`: extend existing ART-resolution tests — a curated
  argument's `#{name}` token survives `artResolveArgs` unresolved; a non-curated argument
  resolves exactly as before (regression guard on the skip-list not over-matching).
- `internal/iocregistry/generate_test.go`: `RegisterGenerated` creates an `iocs` row with
  `status='generated'`, `origin='generated'`, `source='variant'`, and one `ioc_sightings`
  row with the given scenario/run/agent/technique IDs.
- `internal/api/dispatch_run_test.go` (extend): seed one curated mapping via a test-only
  override hook (or seed a scenario whose ART step matches an actual curated entry, once
  Task 2 populates the table), dispatch, assert the sent command no longer contains the
  literal `#{argName}` token and a matching `iocs`/`ioc_sightings` row exists with
  `status='generated'`.
