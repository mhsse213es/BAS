# IOC Generation Engine (Phase C) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give ART-sourced scenario steps a fresh artifact identity (filename, mutex, registry key, service name) on every dispatch, instead of the same static value forever, and record each generated value in the IOC registry.

**Architecture:** A new `internal/artifactgen` package owns a curated `(techniqueID, testName, argName) → IOC type` table and the 4 generator functions. `internal/scenario/art.go`'s `artResolveArgs` gets a skip-list so curated arguments' `#{name}` tokens survive to dispatch time instead of being replaced with ART's static default at content-load time. `internal/api/handlers.go`'s `dispatchRun` substitutes fresh values right after `BuildSteps` returns and registers them via a new `iocregistry.RegisterGenerated`.

**Tech Stack:** Go (`internal/artifactgen`, `internal/iocregistry`, `internal/scenario`, `internal/api`), `crypto/rand`, `*pgxpool.Pool`.

## Global Constraints

- Non-network artifact types only: `filename`, `mutex`, `registry_key`, `service`. No `domain`/`ip`/`url`/`certificate` — deferred, confirmed with the user.
- No Variant Engine pipeline integration (`variant_handlers.go`'s `resolveBaseCommand`/`loadPayloadFamilies` path is untouched) — separate future work.
- No `TriggerScan`/`SafeScan` integration — only `dispatchRun`'s path gets Generation in V1.
- No lifecycle transition beyond `Status = generated` — `executed`/`observed`/`detected`/`missed` transitions are separate future work.
- The curated table starts with zero real, ART-content-verified entries — populating it with reviewed real atomic tests is explicit future work, not this plan. Tests use a temporary, clearly-synthetic entry seeded and cleaned up via a small test-support helper (`artifactgen.SeedForTest`), not a claim of verified real ART content.
- Registry writes are best-effort — `RegisterGenerated` failure is logged, never fails dispatch.
- Every task ends with a commit + `git push`.

---

### Task 1: `internal/artifactgen` — curated mapping + generators

**Files:**
- Modify: `orchestrator/internal/iocregistry/types.go` (add `TypeFilename`)
- Create: `orchestrator/internal/artifactgen/types.go`
- Create: `orchestrator/internal/artifactgen/generate.go`
- Test: `orchestrator/internal/artifactgen/types_test.go`
- Test: `orchestrator/internal/artifactgen/generate_test.go`

**Interfaces:**
- Produces: `type artifactgen.ArgKey struct{TechniqueID, TestName, ArgName string}`; `func artifactgen.Lookup(techniqueID, testName, argName string) (iocregistry.Type, bool)`; `func artifactgen.CuratedFor(techniqueID string) map[ArgKey]iocregistry.Type`; `func artifactgen.SeedForTest(key ArgKey, t iocregistry.Type) (cleanup func())` (test-support only, doc-commented as such); `func artifactgen.Generate(t iocregistry.Type, origDefault string) string`. Tasks 3 and 4 both import this package.

- [ ] **Step 1: Write the failing tests for the curated table**

Create `orchestrator/internal/artifactgen/types_test.go`:

```go
package artifactgen

import (
	"testing"

	"github.com/audspect/bas/internal/iocregistry"
)

func TestLookup_UnknownKey_ReturnsFalse(t *testing.T) {
	_, ok := Lookup("T0000", "no such test", "no_such_arg")
	if ok {
		t.Error("Lookup for an unseeded key = true, want false")
	}
}

func TestLookup_SeededKey_ReturnsTypeAndTrue(t *testing.T) {
	key := ArgKey{TechniqueID: "T0000", TestName: "Example Test", ArgName: "output_file"}
	cleanup := SeedForTest(key, iocregistry.TypeFilename)
	defer cleanup()

	got, ok := Lookup("T0000", "Example Test", "output_file")
	if !ok || got != iocregistry.TypeFilename {
		t.Errorf("Lookup = (%v, %v), want (%v, true)", got, ok, iocregistry.TypeFilename)
	}
}

func TestCuratedFor_ReturnsOnlyMatchingTechnique(t *testing.T) {
	keyA := ArgKey{TechniqueID: "T0000", TestName: "Test A", ArgName: "arg_a"}
	keyB := ArgKey{TechniqueID: "T0000", TestName: "Test B", ArgName: "arg_b"}
	keyOther := ArgKey{TechniqueID: "T0001", TestName: "Test C", ArgName: "arg_c"}
	cleanupA := SeedForTest(keyA, iocregistry.TypeFilename)
	defer cleanupA()
	cleanupB := SeedForTest(keyB, iocregistry.TypeMutex)
	defer cleanupB()
	cleanupOther := SeedForTest(keyOther, iocregistry.TypeService)
	defer cleanupOther()

	got := CuratedFor("T0000")
	if len(got) != 2 {
		t.Fatalf("CuratedFor(T0000) = %+v, want 2 entries", got)
	}
	if got[keyA] != iocregistry.TypeFilename || got[keyB] != iocregistry.TypeMutex {
		t.Errorf("CuratedFor(T0000) = %+v, want keyA=filename keyB=mutex", got)
	}
	if _, found := got[keyOther]; found {
		t.Errorf("CuratedFor(T0000) included a T0001 entry: %+v", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/artifactgen/... -v`
Expected: FAIL — build errors (package `artifactgen` doesn't exist yet).

- [ ] **Step 3: Add `TypeFilename` to the IOC taxonomy**

In `orchestrator/internal/iocregistry/types.go`, find:

```go
const (
	TypeFileHash    Type = "file_hash"
	TypeDomain      Type = "domain"
```

Replace with:

```go
const (
	TypeFileHash    Type = "file_hash"
	// TypeFilename fills a real gap in iochandling.txt §1's own taxonomy: §5/§6
	// explicitly ask to generate new filenames, but §1's type list never names
	// "filename" as distinct from "File Hash". Added Phase C.
	TypeFilename    Type = "filename"
	TypeDomain      Type = "domain"
```

- [ ] **Step 4: Implement the curated table**

Create `orchestrator/internal/artifactgen/types.go`:

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

// curated maps a known-safe argument to the IOC type its value represents. Starts
// empty -- populated by reviewing real ART atomic tests, one at a time, in future
// work. Never guess a mapping from the argument name alone (ART authors use
// inconsistent naming across tests); every entry here must be manually verified
// against the real atomic test's YAML and semantics before being added.
var curated = map[ArgKey]iocregistry.Type{}

// Lookup returns the IOC type for a curated argument, or false if this argument isn't
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

// SeedForTest temporarily adds a curated entry for tests in OTHER packages
// (internal/scenario, internal/api) that need to exercise the skip-list/substitution
// mechanism without a real, reviewed ART entry. Call the returned cleanup func (e.g.
// via defer) to remove it. Test-support only -- never called from production code.
func SeedForTest(key ArgKey, t iocregistry.Type) (cleanup func()) {
	curated[key] = t
	return func() { delete(curated, key) }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/artifactgen/... -run "TestLookup|TestCuratedFor" -v`
Expected: build succeeds; all 3 tests PASS.

- [ ] **Step 6: Write the failing tests for the generators**

Create `orchestrator/internal/artifactgen/generate_test.go`:

```go
package artifactgen

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/iocregistry"
)

func TestGenerate_Filename_PreservesExtension(t *testing.T) {
	got := Generate(iocregistry.TypeFilename, `C:\Windows\Temp\payload.dll`)
	if !strings.HasSuffix(got, ".dll") {
		t.Errorf("Generate(filename, ...payload.dll) = %q, want it to end in .dll", got)
	}
}

func TestGenerate_Filename_DefaultsToExeWhenNoExtension(t *testing.T) {
	got := Generate(iocregistry.TypeFilename, "no_extension_here")
	if !strings.HasSuffix(got, ".exe") {
		t.Errorf("Generate(filename, no-ext default) = %q, want it to end in .exe", got)
	}
}

func TestGenerate_Mutex_StartsWithGlobalPrefix(t *testing.T) {
	got := Generate(iocregistry.TypeMutex, "")
	if !strings.HasPrefix(got, `Global\`) {
		t.Errorf(`Generate(mutex, "") = %q, want it to start with Global\`, got)
	}
}

func TestGenerate_RegistryKeyAndService_NonEmpty(t *testing.T) {
	if got := Generate(iocregistry.TypeRegistryKey, ""); got == "" {
		t.Error("Generate(registry_key, \"\") returned empty string")
	}
	if got := Generate(iocregistry.TypeService, ""); got == "" {
		t.Error("Generate(service, \"\") returned empty string")
	}
}

func TestGenerate_TwoCalls_ProduceDifferentValues(t *testing.T) {
	a := Generate(iocregistry.TypeFilename, "x.exe")
	b := Generate(iocregistry.TypeFilename, "x.exe")
	if a == b {
		t.Errorf("two consecutive Generate calls returned the same value %q -- random suffix isn't varying", a)
	}
}

func TestGenerate_UnknownType_ReturnsOrigDefault(t *testing.T) {
	got := Generate(iocregistry.TypeDomain, "unchanged.example")
	if got != "unchanged.example" {
		t.Errorf("Generate(domain, ...) = %q, want the unchanged origDefault (domain is out of scope for Phase C)", got)
	}
}
```

- [ ] **Step 7: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/artifactgen/... -run TestGenerate -v`
Expected: FAIL — build error, `Generate` undefined.

- [ ] **Step 8: Implement the generators**

Create `orchestrator/internal/artifactgen/generate.go`:

```go
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

// Generate produces a fresh value for t, preserving origDefault's file extension when
// t is TypeFilename -- the generated name must still make sense to the technique (a
// dropper test expecting a .dll needs a .dll back, not a random extension). Types
// outside Phase C's scope (domain/ip/url/certificate/...) return origDefault unchanged.
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

- [ ] **Step 9: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/artifactgen/... -v`
Expected: build/vet clean; all 9 tests PASS.

- [ ] **Step 10: Commit**

```bash
git add orchestrator/internal/iocregistry/types.go orchestrator/internal/artifactgen/
git commit -m "feat(artifactgen): add curated ART-argument mapping and artifact generators

New internal/artifactgen package: a curated (techniqueID, testName,
argName) -> IOC type table (starts empty -- populated by reviewing
real ART content in future work, never guessed from argument names)
plus Generate() for the 4 non-network artifact types (filename, mutex,
registry_key, service). Also adds iocregistry.TypeFilename, filling a
real gap in iochandling.txt §1's own taxonomy.

Phase C of the IOC handling initiative, piece 1/4."
git push
```

---

### Task 2: `iocregistry.RegisterGenerated`

**Files:**
- Create: `orchestrator/internal/iocregistry/generate.go`
- Test: `orchestrator/internal/iocregistry/generate_test.go`

**Interfaces:**
- Consumes: `iocs`/`ioc_sightings` tables (Phase 0+A), `SourceVariant`/`OriginGenerated`/`StatusGenerated` constants (`internal/iocregistry/types.go`, already defined in Phase 0+A).
- Produces: `func iocregistry.RegisterGenerated(ctx context.Context, pool *pgxpool.Pool, t Type, value, scenarioID, runID, agentID, techniqueID string) error`. Task 4 calls this directly.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/iocregistry/generate_test.go`:

```go
package iocregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRegisterGenerated_CreatesIOCAndSighting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if err := RegisterGenerated(context.Background(), pool, TypeFilename, "explorer_update_ab12.exe", "sc-1", "run-1", "agent-1", "T1027"); err != nil {
			t.Fatalf("RegisterGenerated: %v", err)
		}

		var source, origin, status string
		if err := pool.QueryRow(context.Background(),
			`SELECT source, origin, status FROM iocs WHERE type = 'filename' AND value = 'explorer_update_ab12.exe'`).
			Scan(&source, &origin, &status); err != nil {
			t.Fatalf("query iocs: %v", err)
		}
		if source != "variant" || origin != "generated" || status != "generated" {
			t.Errorf("source/origin/status = %q/%q/%q, want variant/generated/generated", source, origin, status)
		}

		var sightingScenario, sightingRun, sightingAgent, sightingTechnique string
		if err := pool.QueryRow(context.Background(), `
			SELECT s.scenario_id, s.run_id, s.agent_id, s.technique_id FROM ioc_sightings s
			JOIN iocs i ON i.id = s.ioc_id WHERE i.value = 'explorer_update_ab12.exe'`).
			Scan(&sightingScenario, &sightingRun, &sightingAgent, &sightingTechnique); err != nil {
			t.Fatalf("query sighting: %v", err)
		}
		if sightingScenario != "sc-1" || sightingRun != "run-1" || sightingAgent != "agent-1" || sightingTechnique != "T1027" {
			t.Errorf("sighting = %q/%q/%q/%q, want sc-1/run-1/agent-1/T1027", sightingScenario, sightingRun, sightingAgent, sightingTechnique)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/iocregistry/... -run TestRegisterGenerated -v`
Expected: FAIL — build error, `RegisterGenerated` undefined.

- [ ] **Step 3: Implement `RegisterGenerated`**

Create `orchestrator/internal/iocregistry/generate.go`:

```go
package iocregistry

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

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

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/iocregistry/... -v`
Expected: build/vet clean; every test in the package PASSES, including the new one and every pre-existing Phase 0+A/B test.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/iocregistry/generate.go orchestrator/internal/iocregistry/generate_test.go
git commit -m "feat(ioc): add RegisterGenerated for proactively-generated artifacts

First real producer of Status=generated / Origin=generated /
Source=variant -- all three have sat unused in the registry since
Phase 0+A reserved them.

Phase C of the IOC handling initiative, piece 2/4."
git push
```

---

### Task 3: `artResolveArgs` skip-list

**Files:**
- Modify: `orchestrator/internal/scenario/art.go`
- Test: `orchestrator/internal/scenario/art_test.go` (new file)

**Interfaces:**
- Consumes: `artifactgen.Lookup(techniqueID, testName, argName string) (iocregistry.Type, bool)`, `artifactgen.SeedForTest` (Task 1).
- Produces: nothing new for later tasks — Task 4 doesn't call `artResolveArgs` directly, it operates on `BuildSteps`'s output.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/scenario/art_test.go`:

```go
package scenario

import (
	"testing"

	"github.com/audspect/bas/internal/artifactgen"
	"github.com/audspect/bas/internal/iocregistry"
)

func TestArtResolveArgs_CuratedArgument_LeftAsLiteralToken(t *testing.T) {
	key := artifactgen.ArgKey{TechniqueID: "T0000", TestName: "Example Test", ArgName: "output_file"}
	cleanup := artifactgen.SeedForTest(key, iocregistry.TypeFilename)
	defer cleanup()

	args := map[string]artInputArg{
		"output_file": {Default: `C:\Windows\Temp\payload.exe`},
	}
	got := artResolveArgs(`Copy-Item -Destination "#{output_file}"`, args, "T0000", "Example Test")
	want := `Copy-Item -Destination "#{output_file}"`
	if got != want {
		t.Errorf("artResolveArgs (curated) = %q, want the token left literal: %q", got, want)
	}
}

func TestArtResolveArgs_NonCuratedArgument_ResolvesAsBefore(t *testing.T) {
	args := map[string]artInputArg{
		"hostname": {Default: "DESKTOP-TEST"},
	}
	got := artResolveArgs(`whoami; #{hostname}`, args, "T1082", "Hostname Discovery")
	want := `whoami; DESKTOP-TEST`
	if got != want {
		t.Errorf("artResolveArgs (non-curated) = %q, want %q (unchanged behavior)", got, want)
	}
}

func TestArtResolveArgs_NonCuratedArgument_EmptyDefault_UsesPlaceholder(t *testing.T) {
	args := map[string]artInputArg{
		"tool_path": {Default: ""},
	}
	got := artResolveArgs(`& "#{tool_path}"`, args, "T1082", "Some Test")
	want := `& "$env:TEMP\bas-placeholder-tool_path"`
	if got != want {
		t.Errorf("artResolveArgs (empty default) = %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestArtResolveArgs -v`
Expected: FAIL — build error, `artResolveArgs` called with 4 args, wants 2.

- [ ] **Step 3: Add the skip-list**

In `orchestrator/internal/scenario/art.go`, find:

```go
func artResolveArgs(cmd string, args map[string]artInputArg) string {
	if cmd == "" {
		return ""
	}
	for name, arg := range args {
		def := arg.Default
		if def == "" {
			def = `$env:TEMP\bas-placeholder-` + name
		}
		cmd = strings.ReplaceAll(cmd, "#{"+name+"}", def)
	}
	return cmd
}
```

Replace with:

```go
func artResolveArgs(cmd string, args map[string]artInputArg, techniqueID, testName string) string {
	if cmd == "" {
		return ""
	}
	for name, arg := range args {
		if _, isCurated := artifactgen.Lookup(techniqueID, testName, name); isCurated {
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

Add the import. Find:

```go
import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/audspect/bas/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"
)
```

Replace with:

```go
import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/audspect/bas/internal/artifactgen"
	"github.com/audspect/bas/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"
)
```

- [ ] **Step 4: Update the 4 call sites**

In `orchestrator/internal/scenario/art.go`, find (Windows loop):

```go
		cmd := artResolveArgs(test.Executor.Command, test.InputArguments)
		if cmd == "" {
			continue
		}
		cleanup := artResolveArgs(test.Executor.CleanupCommand, test.InputArguments)
		cmd, required := artResolvePayloads(cmd, executor)
```

Replace with:

```go
		cmd := artResolveArgs(test.Executor.Command, test.InputArguments, techniqueID, test.Name)
		if cmd == "" {
			continue
		}
		cleanup := artResolveArgs(test.Executor.CleanupCommand, test.InputArguments, techniqueID, test.Name)
		cmd, required := artResolvePayloads(cmd, executor)
```

Then find (Unix loop):

```go
		cmd := artResolveArgs(test.Executor.Command, test.InputArguments)
		if cmd == "" {
			continue
		}
		cleanup := artResolveArgs(test.Executor.CleanupCommand, test.InputArguments)
		cmd, required := artResolvePayloadsUnix(cmd)
```

Replace with:

```go
		cmd := artResolveArgs(test.Executor.Command, test.InputArguments, techniqueID, test.Name)
		if cmd == "" {
			continue
		}
		cleanup := artResolveArgs(test.Executor.CleanupCommand, test.InputArguments, techniqueID, test.Name)
		cmd, required := artResolvePayloadsUnix(cmd)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/scenario/... -v`
Expected: build/vet clean; every test in the package PASSES, including the 3 new ones and every pre-existing test (`TestMapARTElevation` and everything else in `content_import_test.go`/`builder_test.go`/etc.).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/scenario/art.go orchestrator/internal/scenario/art_test.go
git commit -m "feat(scenario): skip static-default substitution for curated ART arguments

artResolveArgs now leaves a curated argument's #{name} token literal
in the cached step instead of baking in ART's static YAML default --
Phase C's dispatch-time pass substitutes a fresh value instead. Every
non-curated argument (the overwhelming majority) keeps today's exact
behavior.

Phase C of the IOC handling initiative, piece 3/4."
git push
```

---

### Task 4: Dispatch-time substitution in `dispatchRun`

**Files:**
- Modify: `orchestrator/internal/api/handlers.go`
- Test: `orchestrator/internal/api/dispatch_run_test.go`

**Interfaces:**
- Consumes: `artifactgen.CuratedFor`, `artifactgen.Generate`, `artifactgen.SeedForTest` (Task 1); `iocregistry.RegisterGenerated` (Task 2); `artResolveArgs`'s skip-list behavior via `scenario.BuildSteps` (Task 3).
- Produces: `func (h *Handler) applyGeneratedArtifacts(ctx context.Context, scenarioID, runID, agentID string, steps []scenario.ScenarioStep) []scenario.ScenarioStep`. Terminal task of Phase C — nothing later depends on this.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/dispatch_run_test.go` (append to the end of the file):

```go
func TestApplyGeneratedArtifacts_SubstitutesCuratedTokenAndRegisters(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		key := artifactgen.ArgKey{TechniqueID: "T0000", TestName: "Example Test", ArgName: "output_file"}
		cleanup := artifactgen.SeedForTest(key, iocregistry.TypeFilename)
		defer cleanup()

		h := &Handler{db: pool}
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T0000", Command: `Copy-Item -Destination "#{output_file}"`},
		}

		got := h.applyGeneratedArtifacts(context.Background(), "sc-1", "run-1", "agent-1", steps)

		if strings.Contains(got[0].Command, "#{output_file}") {
			t.Errorf("Command still contains the literal token: %q", got[0].Command)
		}
		if got[0].Command == steps[0].Command {
			t.Error("Command unchanged -- substitution didn't happen")
		}

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM iocs WHERE type = 'filename' AND status = 'generated'`).Scan(&count); err != nil {
			t.Fatalf("count iocs: %v", err)
		}
		if count != 1 {
			t.Errorf("generated iocs count = %d, want 1", count)
		}

		var sightingRun string
		if err := pool.QueryRow(context.Background(), `
			SELECT s.run_id FROM ioc_sightings s JOIN iocs i ON i.id = s.ioc_id
			WHERE i.type = 'filename' AND i.status = 'generated'`).Scan(&sightingRun); err != nil {
			t.Fatalf("query sighting: %v", err)
		}
		if sightingRun != "run-1" {
			t.Errorf("sighting run_id = %q, want run-1", sightingRun)
		}
	})
}

func TestApplyGeneratedArtifacts_NoCuratedMatch_LeavesStepsUnchanged(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T9999-no-curated-entries", Command: "whoami"},
		}
		got := h.applyGeneratedArtifacts(context.Background(), "sc-1", "run-1", "agent-1", steps)
		if got[0].Command != "whoami" {
			t.Errorf("Command = %q, want unchanged \"whoami\"", got[0].Command)
		}
	})
}
```

Add `"github.com/audspect/bas/internal/artifactgen"` and `"github.com/audspect/bas/internal/iocregistry"` to this file's import block if not already present (check first — this file's existing imports are `context`, `encoding/json`, `testing`, `time`, `github.com/audspect/bas/internal/scenario`, `github.com/audspect/bas/internal/ws`, `github.com/jackc/pgx/v5/pgxpool`; also add `"strings"` for the new tests' `strings.Contains`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestApplyGeneratedArtifacts -v`
Expected: FAIL — build error, `h.applyGeneratedArtifacts` undefined.

- [ ] **Step 3: Implement `applyGeneratedArtifacts` and wire it into `dispatchRun`**

In `orchestrator/internal/api/handlers.go`, find:

```go
	// Build concrete commands — all framework logic resolved server-side.
	steps, err := scenario.BuildSteps(buildSc, h.calderaURL, h.calderaKey, h.artStore, agentOS)
	if err != nil {
		_, _ = h.db.Exec(context.Background(),
			`UPDATE scenario_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, runID)
		return "", "", fmt.Errorf("build steps: %w", err)
	}
```

Replace with:

```go
	// Build concrete commands — all framework logic resolved server-side.
	steps, err := scenario.BuildSteps(buildSc, h.calderaURL, h.calderaKey, h.artStore, agentOS)
	if err != nil {
		_, _ = h.db.Exec(context.Background(),
			`UPDATE scenario_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, runID)
		return "", "", fmt.Errorf("build steps: %w", err)
	}
	steps = h.applyGeneratedArtifacts(ctx, sc.ID, runID, agentID, steps)
```

Then add the new method immediately before `dispatchRun`'s own declaration. Find:

```go
func (h *Handler) dispatchRun(ctx context.Context, sc *scenario.Scenario, agentID string, o dispatchOpts) (runID string, skipReason string, err error) {
```

Insert directly above it:

```go
// applyGeneratedArtifacts substitutes a fresh value for every curated artifact-identity
// token still present in steps (artResolveArgs left them literal for exactly this
// purpose) and registers each substitution in the IOC registry. Best-effort -- a
// registration failure is logged, never fails the dispatch; the registry is
// observability, not a gate. See
// docs/superpowers/specs/2026-07-31-ioc-generation-engine-design.md.
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

Add the two new imports to `handlers.go`'s import block, keeping it alphabetically grouped. Find:

```go
	"github.com/audspect/bas/internal/actions"
	"github.com/audspect/bas/internal/analytics"
	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/compliance"
	"github.com/audspect/bas/internal/connector"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/integrity"
	"github.com/audspect/bas/internal/ioc"
	"github.com/audspect/bas/internal/license"
```

Replace with:

```go
	"github.com/audspect/bas/internal/actions"
	"github.com/audspect/bas/internal/analytics"
	"github.com/audspect/bas/internal/artifactgen"
	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/compliance"
	"github.com/audspect/bas/internal/connector"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/integrity"
	"github.com/audspect/bas/internal/ioc"
	"github.com/audspect/bas/internal/iocregistry"
	"github.com/audspect/bas/internal/license"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/api/... -run "TestApplyGeneratedArtifacts|TestDispatchRun" -v`
Expected: build/vet clean; both new tests and every pre-existing `TestDispatchRun*` test PASS (confirms the new call in `dispatchRun` doesn't break any existing dispatch-gate behavior).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/dispatch_run_test.go
git commit -m "feat(api): substitute generated artifact identities at dispatch time

applyGeneratedArtifacts runs right after BuildSteps in dispatchRun --
already called fresh on every dispatch, so this gives \"new value
every execution\" for free. Best-effort registry write, matching
Phase 0+A/B's extraction pattern.

Phase C of the IOC handling initiative, piece 4/4 -- Phase C complete
pending Task 5's full regression."
git push
```

---

### Task 5: Full regression

**Files:** none (verification only)

- [ ] **Step 1: Confirm Docker is running**

Run: `docker info 2>&1 | grep -iE "server|error"`
If down, start Docker Desktop and poll: `timeout 180 bash -c 'until docker info >/dev/null 2>&1; do sleep 5; done' && echo "DOCKER_READY"`

- [ ] **Step 2: Run the full Go test suite**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./... -count=1`
Expected: `go build`/`go vet` clean, every package `ok`. If any package fails only under full-suite load (Docker resource contention across ~40 concurrent testcontainers was seen repeatedly in Phase 0+A/B — `internal/api`, `internal/relationships`), re-run that package standalone: `go test ./internal/<pkg>/... -count=1 -timeout 20m`. A standalone pass confirms it was contention, not a regression from this phase's changes.

- [ ] **Step 3: Report completion**

Executes directly on `main`, no branch/worktree/PR decision needed. Confirm with the user that Phase C (IOC Generation Engine) is complete, that the curated table is intentionally empty pending real ART-content review (a real, honest limitation — no generated artifacts will actually substitute in production until entries are added), and that Phase D (Intelligence Layer) remains as the last part of the roadmap.
