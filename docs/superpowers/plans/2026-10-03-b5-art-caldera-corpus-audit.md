# B5 ART/Caldera Corpus Classification Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every real ART atomic and Caldera ability a genuine `(technique_id, action_key)` classification in B5's execution-class catalog, replacing today's universal fail-closed default for these two sources, via a permanent re-runnable audit tool.

**Architecture:** A new `corpusaudit` package implements pure, synthetic-data-testable logic (action-key derivation with collision handling, destructiveguard-based triage, reviewed-decisions merge, report/catalog generation). A thin `cmd/auditcorpus` binary wires that logic to the real production loaders (`NewARTStoreFromDB`, a newly-exported `FetchRawCalderaAbilities`) against a locally-run `docker compose` stack, writing a generated catalog file and a coverage report. A Go test gates on `unresolved == 0`, skipping cleanly without the live stack.

**Tech Stack:** Go (orchestrator module), `agent/destructiveguard` (reused, not modified), `gopkg.in/yaml.v3` (already a dependency), Docker Compose (local stack, already runnable — `bas-caldera` images already cached locally).

**Spec:** `docs/superpowers/specs/2026-10-03-b5-art-caldera-corpus-audit-design.md`

## Global Constraints

- `ResolveExecutionClass`, `AttachExecutionClassifications`, and the `ExecutionClass` type (`non_destructive`/`potentially_destructive`/`destructive`) are never modified — additive only.
- Hand-authored catalog entries (`executionClassifications` as populated by `execclass.go`) are never overwritten.
- `agent/destructiveguard.Classify` is the only pattern-scan mechanism — no second, independently-maintained vocabulary list.
- The audit tool is permanent and re-runnable (`orchestrator/cmd/auditcorpus`), not a throwaway script.
- Generated catalog entries live in a new file, `execclass_generated.go`, never hand-edited, never merged into `execclass.go` itself.
- `candidate_non_destructive` is an internal generation-time label only — nothing persisted or in `ExecutionClass` ever carries that value.
- This project works directly on `main` with continuous commits and pushes after each task — no worktree, no feature branch (established convention, confirmed across every prior Group D/E plan this session).

## Review Focus

- **Live stack unreachable or still loading mid-run** (Caldera parses its ~2,200-ability library before answering — the compose file's own healthcheck comment notes a generous `start_period` for exactly this): the tool must fail loudly and write nothing — never a partial or stale-fallback `execclass_generated.go`. Pinned in Task 6.
- **A slug coincidentally matches an existing hand-authored `action_key` under the same technique** (e.g. an ART atomic literally named "Enumerate" under a technique that already has a hand-authored `"enumerate"` entry): must skip via the existing-catalog check, never double-classify or diverge from the hand-authored entry. Pinned in Task 3.
- **A Caldera ability with no PowerShell executor** (only `sh`/`bash`): `caldera_store.go`'s own `tryLoad` hardcodes `Executor: "powershell"` on every `ScenarioStep` it builds regardless of which executor `pickExecutorCommand` actually picked (confirmed by reading `caldera_store.go`'s literal and `builder.go:450-469`'s fallback logic) — a pre-existing mislabeling, out of scope to fix in the live dispatch path, but the new `FetchRawCalderaAbilities` wrapper must report the *real* picked executor name so the audit's own reachability/executor data doesn't propagate that bug. Pinned in Task 2.
- **A true unresolvable `action_key` collision** (same slug, same executor, genuinely different real command text under one technique): must land in `unresolved` and the collision report, never silently picked or overwritten. Pinned in Task 1.
- **A reviewed decision going stale** if the upstream corpus's command text for that `(technique_id, action_key)` changes after a human reviewed it: without a check, a stale human decision would be silently re-applied to a command nobody actually reviewed. `ReviewedDecision` carries a `CommandHash` (SHA-256 of the reviewed command text); a merge against a live item whose current command hash doesn't match is treated as `unresolved`, not silently trusted. Pinned in Task 4.

---

### Task 1: Action-key derivation with collision handling

**Files:**
- Create: `orchestrator/internal/scenario/corpusaudit/identity.go`
- Create: `orchestrator/internal/scenario/corpusaudit/identity_test.go`

**Interfaces:**
- Consumes: nothing from other tasks (first task).
- Produces: `type DiscoveredItem struct { Source, TechniqueID, Name, Executor, Command, AbilityID string; Reachable bool }`, `type KeyedItem struct { DiscoveredItem; ActionKey string }`, `type CollisionError struct { TechniqueID, ActionKey string; ItemA, ItemB DiscoveredItem }` (implements `error`), `func Slugify(name string) string`, `func DeriveActionKeys(items []DiscoveredItem) ([]KeyedItem, []CollisionError)` — consumed by Task 2 (building `DiscoveredItem`s) and Task 3 (triaging `KeyedItem`s).

- [ ] **Step 1: Write the failing tests**

```go
package corpusaudit

import "testing"

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"Delete Volume Shadow Copies":       "delete_volume_shadow_copies",
		"  Stop & Disable Windows Defender": "stop_disable_windows_defender",
		"T1003.001---LSASS Dump (OS X)":     "t1003_001_lsass_dump_os_x",
	}
	for in, want := range cases {
		if got := Slugify(in); got != want {
			t.Errorf("Slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDeriveActionKeys_NoCollision(t *testing.T) {
	items := []DiscoveredItem{
		{Source: "art", TechniqueID: "T1490", Name: "Delete Shadow Copies", Executor: "psh", Command: "vssadmin delete shadows /all"},
		{Source: "art", TechniqueID: "T1490", Name: "List Shadow Copies", Executor: "psh", Command: "vssadmin list shadows"},
	}
	keyed, collisions := DeriveActionKeys(items)
	if len(collisions) != 0 {
		t.Fatalf("expected no collisions, got %v", collisions)
	}
	if len(keyed) != 2 {
		t.Fatalf("expected 2 keyed items, got %d", len(keyed))
	}
	if keyed[0].ActionKey == keyed[1].ActionKey {
		t.Errorf("expected distinct action_keys, both got %q", keyed[0].ActionKey)
	}
}

func TestDeriveActionKeys_SameNameDifferentExecutor_Disambiguated(t *testing.T) {
	items := []DiscoveredItem{
		{Source: "caldera", TechniqueID: "T1070", Name: "Clear Logs", Executor: "psh", Command: "wevtutil cl System"},
		{Source: "caldera", TechniqueID: "T1070", Name: "Clear Logs", Executor: "sh", Command: "rm -f /var/log/syslog"},
	}
	keyed, collisions := DeriveActionKeys(items)
	if len(collisions) != 0 {
		t.Fatalf("expected no collisions, got %v", collisions)
	}
	seen := map[string]bool{}
	for _, k := range keyed {
		if seen[k.ActionKey] {
			t.Fatalf("expected disambiguated keys, got duplicate %q", k.ActionKey)
		}
		seen[k.ActionKey] = true
	}
}

func TestDeriveActionKeys_SameNameSameExecutor_SameCommand_Deduped(t *testing.T) {
	items := []DiscoveredItem{
		{Source: "art", TechniqueID: "T1082", Name: "System Info", Executor: "psh", Command: "systeminfo"},
		{Source: "art", TechniqueID: "T1082", Name: "System Info", Executor: "psh", Command: "systeminfo"},
	}
	keyed, collisions := DeriveActionKeys(items)
	if len(collisions) != 0 {
		t.Fatalf("expected no collisions for identical real duplicates, got %v", collisions)
	}
	if len(keyed) != 2 {
		t.Fatalf("expected both items kept (same key), got %d", len(keyed))
	}
	if keyed[0].ActionKey != keyed[1].ActionKey {
		t.Errorf("expected identical commands to share one action_key, got %q and %q", keyed[0].ActionKey, keyed[1].ActionKey)
	}
}

func TestDeriveActionKeys_SameNameSameExecutor_DifferentCommand_Unresolved(t *testing.T) {
	items := []DiscoveredItem{
		{Source: "caldera", TechniqueID: "T1490", Name: "Disable Recovery", Executor: "psh", Command: "bcdedit /set recoveryenabled no"},
		{Source: "caldera", TechniqueID: "T1490", Name: "Disable Recovery", Executor: "psh", Command: "wbadmin delete catalog -quiet"},
	}
	keyed, collisions := DeriveActionKeys(items)
	if len(collisions) != 1 {
		t.Fatalf("expected exactly 1 unresolvable collision, got %d: %v", len(collisions), collisions)
	}
	for _, k := range keyed {
		if k.TechniqueID == "T1490" {
			t.Errorf("colliding items must not appear in the keyed output, found %+v", k)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/scenario/corpusaudit/... -v`
Expected: FAIL — `Slugify`/`DeriveActionKeys`/`DiscoveredItem`/`KeyedItem`/`CollisionError` undefined (package doesn't exist yet).

- [ ] **Step 3: Write the implementation**

```go
package corpusaudit

import (
	"fmt"
	"regexp"
	"strings"
)

// DiscoveredItem is one real ART atomic or Caldera ability pulled from a
// live stack, before action-key derivation or classification.
type DiscoveredItem struct {
	Source      string // "art" | "caldera"
	TechniqueID string
	Name        string
	Executor    string
	Command     string
	AbilityID   string // Caldera only; "" for ART. Provenance only, never used to derive action_key.
	Reachable   bool   // has a real non-empty command AND a technique mapping
}

// KeyedItem is a DiscoveredItem with its derived action_key assigned.
type KeyedItem struct {
	DiscoveredItem
	ActionKey string
}

// CollisionError describes a true, unresolvable action_key collision: two
// DiscoveredItems with the same TechniqueID, slug, and executor but
// genuinely different Command text. Neither item is kept in
// DeriveActionKeys' returned slice when this occurs -- callers must never
// pick one arbitrarily.
type CollisionError struct {
	TechniqueID, ActionKey string
	ItemA, ItemB           DiscoveredItem
}

func (e CollisionError) Error() string {
	return fmt.Sprintf("unresolvable action_key collision: %s/%s between %q and %q",
		e.TechniqueID, e.ActionKey, e.ItemA.Name, e.ItemB.Name)
}

var slugNonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// Slugify derives an action_key-style token from a human-readable name,
// matching the hand-authored catalog's existing snake_case convention.
func Slugify(name string) string {
	s := strings.ToLower(name)
	s = slugNonAlnum.ReplaceAllString(s, "_")
	return strings.Trim(s, "_")
}

// DeriveActionKeys assigns an action_key to every item, grouped by
// TechniqueID. Two items whose Name slugifies the same get an executor
// suffix. If that still collides on genuinely different Command text,
// both items are reported as a CollisionError and omitted from the
// returned slice -- never silently picked or overwritten. Two items that
// collide on slug+executor AND share identical Command text are treated
// as real duplicates of the same atomic/ability and share one action_key.
func DeriveActionKeys(items []DiscoveredItem) ([]KeyedItem, []CollisionError) {
	type idx = int
	byTechSlug := map[string]map[string][]idx{}
	for i, it := range items {
		slug := Slugify(it.Name)
		if byTechSlug[it.TechniqueID] == nil {
			byTechSlug[it.TechniqueID] = map[string][]idx{}
		}
		byTechSlug[it.TechniqueID][slug] = append(byTechSlug[it.TechniqueID][slug], i)
	}

	actionKeys := make([]string, len(items))
	var collisions []CollisionError
	skip := make(map[idx]bool)

	for tech, slugs := range byTechSlug {
		for slug, group := range slugs {
			if len(group) == 1 {
				actionKeys[group[0]] = slug
				continue
			}
			byExecutor := map[string][]idx{}
			for _, i := range group {
				byExecutor[items[i].Executor] = append(byExecutor[items[i].Executor], i)
			}
			for executor, execGroup := range byExecutor {
				key := slug
				if len(byExecutor) > 1 {
					key = slug + "_" + executor
				}
				if len(execGroup) == 1 {
					actionKeys[execGroup[0]] = key
					continue
				}
				firstCmd := items[execGroup[0]].Command
				allSame := true
				for _, i := range execGroup[1:] {
					if items[i].Command != firstCmd {
						allSame = false
						break
					}
				}
				if allSame {
					for _, i := range execGroup {
						actionKeys[i] = key
					}
					continue
				}
				for i := 0; i < len(execGroup); i++ {
					for j := i + 1; j < len(execGroup); j++ {
						if items[execGroup[i]].Command != items[execGroup[j]].Command {
							collisions = append(collisions, CollisionError{
								TechniqueID: tech, ActionKey: key,
								ItemA: items[execGroup[i]], ItemB: items[execGroup[j]],
							})
						}
					}
				}
				for _, i := range execGroup {
					skip[i] = true
				}
			}
		}
	}

	out := make([]KeyedItem, 0, len(items))
	for i, it := range items {
		if skip[i] {
			continue
		}
		out = append(out, KeyedItem{DiscoveredItem: it, ActionKey: actionKeys[i]})
	}
	return out, collisions
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/scenario/corpusaudit/... -v`
Expected: PASS — all 5 tests green.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/scenario/corpusaudit/identity.go orchestrator/internal/scenario/corpusaudit/identity_test.go
git commit -m "feat(corpusaudit): derive per-item action_key with collision handling"
git push
```

---

### Task 2: Real data collection from ART and Caldera

**Files:**
- Modify: `orchestrator/internal/scenario/caldera_store.go` (add exported raw-fetch wrapper)
- Modify: `packaging/compose/docker-compose.yml` (add a profile-gated `auditcorpus` dev service)
- Create: `orchestrator/internal/scenario/caldera_store_rawfetch_test.go`

**Interfaces:**
- Consumes: nothing new from Task 1 (parallel data-sourcing concern).
- Produces: `type RawCalderaAbility struct { AbilityID, Name, TechniqueID, Executor, Command string }`, `func FetchRawCalderaAbilities(calderaURL, apiKey string) ([]RawCalderaAbility, error)` — consumed by Task 6's `cmd/auditcorpus` wiring.

- [ ] **Step 1: Write the failing test**

```go
package scenario

import "testing"

func TestFetchRawCalderaAbilities_ReportsRealPickedExecutor(t *testing.T) {
	// fetchAllCalderaAbilities hits a live Caldera; this test only exercises
	// the executor-selection logic FetchRawCalderaAbilities adds on top of
	// it, using a synthetic ability built directly (no network).
	ab := calderaAbilityFull{
		AbilityID:   "abc-123",
		Name:        "Clear Bash History",
		TechniqueID: "T1070.003",
		Executors: []calderaExecutor{
			{Name: "sh", Command: "cat /dev/null > ~/.bash_history"},
		},
	}
	raw := rawFromCalderaAbility(ab)
	if raw.Executor != "sh" {
		t.Errorf("Executor = %q, want %q (the real picked executor, not hardcoded)", raw.Executor, "sh")
	}
	if raw.Command != "cat /dev/null > ~/.bash_history" {
		t.Errorf("Command = %q, want the sh executor's real command", raw.Command)
	}
	if raw.AbilityID != "abc-123" || raw.TechniqueID != "T1070.003" {
		t.Errorf("provenance fields not carried through: %+v", raw)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestFetchRawCalderaAbilities -v`
Expected: FAIL — `rawFromCalderaAbility`/`RawCalderaAbility` undefined.

- [ ] **Step 3: Write the implementation**

Add to `orchestrator/internal/scenario/caldera_store.go` (near `fetchAllCalderaAbilities`):

```go
// RawCalderaAbility is the unfiltered form of a Caldera ability, exposed
// for audit tooling (orchestrator/cmd/auditcorpus). CalderaStore itself
// only ever exposes the already-filtered, already-indexed subset via
// GetAbilities -- this exists so the audit can see the TRUE discovered
// count (including abilities tryLoad would otherwise silently drop) and
// the real picked executor name, which tryLoad's own ScenarioStep
// construction hardcodes to "powershell" regardless of which executor
// was actually picked.
type RawCalderaAbility struct {
	AbilityID   string
	Name        string
	TechniqueID string
	Executor    string
	Command     string
}

func rawFromCalderaAbility(ab calderaAbilityFull) RawCalderaAbility {
	executor, command := pickExecutor(ab.Executors, "psh")
	return RawCalderaAbility{
		AbilityID:   ab.AbilityID,
		Name:        ab.Name,
		TechniqueID: ab.TechniqueID,
		Executor:    executor,
		Command:     command,
	}
}

// pickExecutor mirrors pickExecutorCommand's own preference order (preferred,
// then psh/powershell, then first available) but also returns which
// executor's name was actually picked -- pickExecutorCommand only ever
// returns the command, which is why tryLoad's own ScenarioStep construction
// has to hardcode "powershell" instead of reporting the truth.
func pickExecutor(executors []calderaExecutor, preferred string) (name, command string) {
	if preferred == "" {
		preferred = "psh"
	}
	for _, e := range executors {
		if e.Name == preferred {
			return e.Name, e.Command
		}
	}
	for _, e := range executors {
		if e.Name == "psh" || e.Name == "powershell" {
			return e.Name, e.Command
		}
	}
	if len(executors) > 0 {
		return executors[0].Name, executors[0].Command
	}
	return "", ""
}

// FetchRawCalderaAbilities fetches every ability from a live Caldera
// instance, unfiltered -- reuses the exact same fetch fetchAllCalderaAbilities
// uses internally, never a parallel API parser.
func FetchRawCalderaAbilities(calderaURL, apiKey string) ([]RawCalderaAbility, error) {
	full, err := fetchAllCalderaAbilities(calderaURL, apiKey)
	if err != nil {
		return nil, err
	}
	out := make([]RawCalderaAbility, len(full))
	for i, ab := range full {
		out[i] = rawFromCalderaAbility(ab)
	}
	return out, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestFetchRawCalderaAbilities -v`
Expected: PASS.

- [ ] **Step 5: Add the profile-gated compose service**

In `packaging/compose/docker-compose.yml`, add a new service (profile-gated so it never runs during a normal `docker compose up` — zero production impact):

```yaml
  auditcorpus:
    build:
      context: ../..
      dockerfile: orchestrator/Dockerfile
      target: builder
    profiles: ["audit"]
    networks:
      - bas-internal
    depends_on:
      postgres:
        condition: service_started
      caldera:
        condition: service_started
    environment:
      DATABASE_URL: "postgres://bas_app:${BAS_APP_DB_PASSWORD}@postgres:5432/${POSTGRES_DB:-bas_platform}?sslmode=prefer"
      CALDERA_URL: "http://caldera:8888"
      CALDERA_API_KEY: ${CALDERA_API_KEY:-BASPlatform2024}
    working_dir: /src
    command: ["go", "run", "./cmd/auditcorpus"]
```

- [ ] **Step 6: Verify the real stack is reachable (real execution, not assumed)**

Run (from `packaging/compose/`, with `BAS_APP_DB_PASSWORD` set as the existing `.env`/deploy convention requires):
```bash
docker compose up -d postgres caldera
docker compose logs caldera --tail 5
```
Expected: `postgres` and `caldera` containers start; Caldera's log shows it finished loading its ability library (the compose file's own comment already documents this takes time on cold boot — wait for the healthcheck to report healthy, e.g. `docker compose ps caldera` showing `healthy`, before proceeding to later tasks). This step has no `cmd/auditcorpus` to run yet (Task 6 builds it) — it only proves the stack itself is reachable, which Task 6 depends on.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/scenario/caldera_store.go orchestrator/internal/scenario/caldera_store_rawfetch_test.go packaging/compose/docker-compose.yml
git commit -m "feat(corpusaudit): export raw Caldera ability fetch + add profile-gated audit compose service"
git push
```

---

### Task 3: Hand-authored precedence + report arithmetic

**Files:**
- Create: `orchestrator/internal/scenario/corpusaudit/report.go`
- Create: `orchestrator/internal/scenario/corpusaudit/report_test.go`

**Interfaces:**
- Consumes: `KeyedItem` (Task 1).
- Produces: `type Status string` with `StatusAlreadyHandAuthored`/`StatusClassified`/`StatusUnresolved`, `type ClassifiedItem struct { KeyedItem; Status Status; Class scenario.ExecutionClass; DestructiveAction, BlastRadius string }`, `func AlreadyCatalogued(techniqueID, actionKey string) bool`, `type SourceCounts struct { Discovered, Reachable, Classified, DestructiveCandidates, ManuallyReviewed, Unresolved int }`, `type CoverageReport struct { ART, Caldera SourceCounts }`, `func BuildReport(items []ClassifiedItem) CoverageReport` — consumed by Task 4 (triage produces `ClassifiedItem`s) and Task 5 (writes the report).

- [ ] **Step 1: Write the failing tests**

```go
package corpusaudit

import "testing"

func TestAlreadyCatalogued_TrueForHandAuthoredEntry(t *testing.T) {
	// "" / "default" is a real hand-authored entry (execclass.go) -- the
	// BitLocker posture check.
	if !AlreadyCatalogued("", "default") {
		t.Error("expected the hand-authored \"\"/\"default\" entry to be recognized as catalogued")
	}
}

func TestAlreadyCatalogued_FalseForUnknownPair(t *testing.T) {
	if AlreadyCatalogued("T9999", "nonsense_action_key") {
		t.Error("expected an unknown pair to NOT be catalogued")
	}
}

func TestBuildReport_CountsBySourceAndStatus(t *testing.T) {
	items := []ClassifiedItem{
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{Source: "art", Reachable: true}}, Status: StatusClassified},
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{Source: "art", Reachable: false}}, Status: StatusUnresolved},
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{Source: "art", Reachable: true}}, Status: StatusAlreadyHandAuthored},
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{Source: "caldera", Reachable: true}}, Status: StatusClassified},
	}
	r := BuildReport(items)

	if r.ART.Discovered != 3 {
		t.Errorf("ART.Discovered = %d, want 3", r.ART.Discovered)
	}
	if r.ART.Reachable != 2 {
		t.Errorf("ART.Reachable = %d, want 2", r.ART.Reachable)
	}
	if r.ART.Classified != 2 { // StatusClassified + StatusAlreadyHandAuthored both count as classified
		t.Errorf("ART.Classified = %d, want 2", r.ART.Classified)
	}
	if r.ART.Unresolved != 1 {
		t.Errorf("ART.Unresolved = %d, want 1", r.ART.Unresolved)
	}
	if r.Caldera.Discovered != 1 || r.Caldera.Classified != 1 {
		t.Errorf("Caldera counts wrong: %+v", r.Caldera)
	}
}

func TestBuildReport_DestructiveCandidatesAndManuallyReviewed(t *testing.T) {
	items := []ClassifiedItem{
		// a human-confirmed destructive item: went through reviewed-decisions merge
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{Source: "art", Reachable: true}}, Status: StatusClassified, Class: scenario.ClassDestructive},
		// an unresolved item: flagged by destructiveguard, no reviewed decision yet
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{Source: "art", Reachable: true}}, Status: StatusUnresolved},
		// a plain non_destructive promotion: not a destructive candidate at all
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{Source: "art", Reachable: true}}, Status: StatusClassified, Class: scenario.ClassNonDestructive},
	}
	r := BuildReport(items)
	if r.ART.DestructiveCandidates != 2 {
		t.Errorf("DestructiveCandidates = %d, want 2 (1 reviewed-destructive + 1 unresolved)", r.ART.DestructiveCandidates)
	}
	if r.ART.ManuallyReviewed != 1 {
		t.Errorf("ManuallyReviewed = %d, want 1", r.ART.ManuallyReviewed)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/scenario/corpusaudit/... -run 'TestAlreadyCatalogued|TestBuildReport' -v`
Expected: FAIL — `AlreadyCatalogued`/`ClassifiedItem`/`BuildReport`/etc. undefined.

- [ ] **Step 3: Write the implementation**

```go
package corpusaudit

import "github.com/audspect/bas/internal/scenario"

// Status is where a KeyedItem landed after triage.
type Status string

const (
	StatusAlreadyHandAuthored Status = "already_hand_authored"
	StatusClassified          Status = "classified"
	StatusUnresolved          Status = "unresolved"
)

// ClassifiedItem is a KeyedItem after triage against the hand-authored
// catalog, destructiveguard, and the reviewed-decisions file (Task 4).
type ClassifiedItem struct {
	KeyedItem
	Status            Status
	Class             scenario.ExecutionClass // meaningful only when Status == StatusClassified
	DestructiveAction string
	BlastRadius       string
}

// AlreadyCatalogued reports whether (techniqueID, actionKey) already
// resolves via the hand-authored catalog. Reuses the exact sentinel check
// orchestrator/cmd/probeclassify already established (comparing
// DestructiveAction against the "unclassified" fail-closed sentinel) --
// never re-derives catalog internals.
func AlreadyCatalogued(techniqueID, actionKey string) bool {
	return scenario.ResolveExecutionClass(techniqueID, actionKey).DestructiveAction != "unclassified"
}

type SourceCounts struct {
	Discovered            int
	Reachable             int
	Classified            int
	DestructiveCandidates int
	ManuallyReviewed      int
	Unresolved            int
}

type CoverageReport struct {
	ART     SourceCounts
	Caldera SourceCounts
}

// BuildReport tallies real counts from the live classification run --
// never hard-coded. DestructiveCandidates counts every item that was ever
// flagged by destructiveguard, whether a human has resolved it yet
// (Status == StatusClassified with a non-NonDestructive Class) or not
// (Status == StatusUnresolved). ManuallyReviewed counts only the former.
func BuildReport(items []ClassifiedItem) CoverageReport {
	var r CoverageReport
	for _, it := range items {
		var c *SourceCounts
		switch it.Source {
		case "art":
			c = &r.ART
		case "caldera":
			c = &r.Caldera
		default:
			continue
		}
		c.Discovered++
		if it.Reachable {
			c.Reachable++
		}
		switch it.Status {
		case StatusClassified, StatusAlreadyHandAuthored:
			c.Classified++
		case StatusUnresolved:
			c.Unresolved++
			c.DestructiveCandidates++
		}
		if it.Status == StatusClassified && it.Class != scenario.ClassNonDestructive {
			c.DestructiveCandidates++
			c.ManuallyReviewed++
		}
	}
	return r
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/scenario/corpusaudit/... -v`
Expected: PASS — all tests in the package (Task 1's and Task 3's) green.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/scenario/corpusaudit/report.go orchestrator/internal/scenario/corpusaudit/report_test.go
git commit -m "feat(corpusaudit): hand-authored precedence check + coverage report arithmetic"
git push
```

---

### Task 4: Reviewed-decisions file + destructiveguard triage

**Files:**
- Create: `orchestrator/internal/scenario/corpusaudit/triage.go`
- Create: `orchestrator/internal/scenario/corpusaudit/triage_test.go`
- Create: `orchestrator/internal/scenario/execclass_reviewed.yaml` (starts empty — a seed file with a doc-comment header, real entries land in Task 8)

**Interfaces:**
- Consumes: `KeyedItem`, `AlreadyCatalogued` (Tasks 1, 3).
- Produces: `type ReviewedDecision struct { TechniqueID, ActionKey string; Class scenario.ExecutionClass; CommandHash, Reviewer, ReviewedAt, Note string }`, `func LoadReviewedDecisions(path string) ([]ReviewedDecision, error)`, `func CommandHash(command string) string`, `func Triage(items []KeyedItem, reviewed []ReviewedDecision) []ClassifiedItem` — consumed by Task 6's wiring.

- [ ] **Step 1: Write the failing tests**

```go
package corpusaudit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestCommandHash_SameCommandSameHash(t *testing.T) {
	if CommandHash("vssadmin delete shadows /all") != CommandHash("vssadmin delete shadows /all") {
		t.Error("expected identical commands to hash identically")
	}
	if CommandHash("vssadmin delete shadows /all") == CommandHash("vssadmin delete shadows /quiet") {
		t.Error("expected different commands to hash differently")
	}
}

func TestLoadReviewedDecisions_MissingFileReturnsEmpty(t *testing.T) {
	decisions, err := LoadReviewedDecisions(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(decisions) != 0 {
		t.Errorf("expected empty, got %d", len(decisions))
	}
}

func TestLoadReviewedDecisions_ParsesRealFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reviewed.yaml")
	content := `- technique_id: T1490
  action_key: vss_delete_akira_style
  class: destructive
  command_hash: ` + CommandHash("Win32_ShadowCopy.Delete()") + `
  reviewer: test-reviewer
  reviewed_at: "2026-10-03"
  note: "WMI-based VSS deletion, same family as the hand-authored vss_delete entry"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	decisions, err := LoadReviewedDecisions(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(decisions))
	}
	d := decisions[0]
	if d.TechniqueID != "T1490" || d.ActionKey != "vss_delete_akira_style" || d.Class != scenario.ClassDestructive {
		t.Errorf("parsed decision wrong: %+v", d)
	}
}

func TestTriage_SkipsAlreadyHandAuthored(t *testing.T) {
	items := []KeyedItem{
		{DiscoveredItem: DiscoveredItem{Source: "art", TechniqueID: "", Command: "irrelevant"}, ActionKey: "default"},
	}
	result := Triage(items, nil)
	if len(result) != 1 || result[0].Status != StatusAlreadyHandAuthored {
		t.Errorf("expected the hand-authored \"\"/\"default\" pair to be skipped as already covered, got %+v", result)
	}
}

func TestTriage_PromotesNonDestructiveWithNoHumanDecisionNeeded(t *testing.T) {
	items := []KeyedItem{
		{DiscoveredItem: DiscoveredItem{Source: "art", TechniqueID: "T1082", Command: "whoami /all"}, ActionKey: "whoami_fresh_unclassified_test"},
	}
	result := Triage(items, nil)
	if len(result) != 1 || result[0].Status != StatusClassified || result[0].Class != scenario.ClassNonDestructive {
		t.Errorf("expected auto-promotion to non_destructive with no reviewed-decisions entry, got %+v", result)
	}
}

func TestTriage_DestructiveWithNoReviewedDecisionIsUnresolved(t *testing.T) {
	items := []KeyedItem{
		{DiscoveredItem: DiscoveredItem{Source: "art", TechniqueID: "T1490", Command: "vssadmin delete shadows /all /quiet"}, ActionKey: "vss_delete_fresh_unclassified_test"},
	}
	result := Triage(items, nil)
	if len(result) != 1 || result[0].Status != StatusUnresolved {
		t.Errorf("expected unresolved with no matching reviewed decision, got %+v", result)
	}
}

func TestTriage_DestructiveWithMatchingReviewedDecisionIsClassified(t *testing.T) {
	cmd := "vssadmin delete shadows /all /quiet"
	items := []KeyedItem{
		{DiscoveredItem: DiscoveredItem{Source: "art", TechniqueID: "T1490", Command: cmd}, ActionKey: "vss_delete_fresh_unclassified_test"},
	}
	reviewed := []ReviewedDecision{
		{TechniqueID: "T1490", ActionKey: "vss_delete_fresh_unclassified_test", Class: scenario.ClassDestructive, CommandHash: CommandHash(cmd), Note: "matches hand-authored vss_delete family"},
	}
	result := Triage(items, reviewed)
	if len(result) != 1 || result[0].Status != StatusClassified || result[0].Class != scenario.ClassDestructive {
		t.Errorf("expected classified destructive from the reviewed decision, got %+v", result)
	}
}

func TestTriage_StaleReviewedDecision_CommandChanged_IsUnresolved(t *testing.T) {
	items := []KeyedItem{
		{DiscoveredItem: DiscoveredItem{Source: "art", TechniqueID: "T1490", Command: "vssadmin delete shadows /all /quiet /new-flag-nobody-reviewed"}, ActionKey: "vss_delete_fresh_unclassified_test"},
	}
	reviewed := []ReviewedDecision{
		// reviewed against the OLD command text -- hash won't match the live item above
		{TechniqueID: "T1490", ActionKey: "vss_delete_fresh_unclassified_test", Class: scenario.ClassDestructive, CommandHash: CommandHash("vssadmin delete shadows /all /quiet")},
	}
	result := Triage(items, reviewed)
	if len(result) != 1 || result[0].Status != StatusUnresolved {
		t.Errorf("expected a stale reviewed decision (command text changed) to be treated as unresolved, not silently trusted, got %+v", result)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/scenario/corpusaudit/... -run 'TestCommandHash|TestLoadReviewedDecisions|TestTriage' -v`
Expected: FAIL — `CommandHash`/`ReviewedDecision`/`LoadReviewedDecisions`/`Triage` undefined.

- [ ] **Step 3: Write the implementation**

```go
package corpusaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"os"

	"github.com/audspect/bas/internal/scenario"
	"gopkg.in/yaml.v3"

	"audspect/agent/destructiveguard"
)

// ReviewedDecision is one human classification decision for a
// (technique_id, action_key) pair that destructiveguard flagged. Loaded
// from the checked-in execclass_reviewed.yaml.
type ReviewedDecision struct {
	TechniqueID string                  `yaml:"technique_id"`
	ActionKey   string                  `yaml:"action_key"`
	Class       scenario.ExecutionClass `yaml:"class"`
	// CommandHash pins this decision to the exact command text it was
	// reviewed against -- if the live corpus's command for this pair
	// changes, the hash won't match and the item goes back to unresolved
	// rather than silently re-applying a decision nobody actually reviewed
	// against the new text.
	CommandHash string `yaml:"command_hash"`
	Reviewer    string `yaml:"reviewer"`
	ReviewedAt  string `yaml:"reviewed_at"`
	Note        string `yaml:"note"`
}

// CommandHash returns a stable fingerprint of a command string, used to
// detect when a reviewed decision's underlying command has drifted.
func CommandHash(command string) string {
	sum := sha256.Sum256([]byte(command))
	return hex.EncodeToString(sum[:])
}

// LoadReviewedDecisions reads the human-reviewed exception queue. A
// missing file is treated as "no decisions yet" (empty, no error) -- the
// first run against a fresh checkout has nothing reviewed yet, which is
// expected, not a failure.
func LoadReviewedDecisions(path string) ([]ReviewedDecision, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []ReviewedDecision
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

type reviewedKey struct{ tech, key string }

// Triage classifies every KeyedItem: skips anything the hand-authored
// catalog already covers (Task 3's AlreadyCatalogued), runs
// destructiveguard.Classify on the rest, and merges in human decisions
// from reviewed for anything flagged destructive. A non-destructive
// destructiveguard verdict promotes an item straight to classified with
// no human decision needed -- destructiveguard remains an independent
// runtime backstop regardless (see the design doc's Promotion rule).
func Triage(items []KeyedItem, reviewed []ReviewedDecision) []ClassifiedItem {
	byKey := make(map[reviewedKey]ReviewedDecision, len(reviewed))
	for _, r := range reviewed {
		byKey[reviewedKey{r.TechniqueID, r.ActionKey}] = r
	}

	out := make([]ClassifiedItem, 0, len(items))
	for _, it := range items {
		if AlreadyCatalogued(it.TechniqueID, it.ActionKey) {
			out = append(out, ClassifiedItem{KeyedItem: it, Status: StatusAlreadyHandAuthored})
			continue
		}
		switch destructiveguard.Classify(it.Command) {
		case destructiveguard.ClassNonDestructive:
			out = append(out, ClassifiedItem{
				KeyedItem: it, Status: StatusClassified,
				Class:             scenario.ClassNonDestructive,
				DestructiveAction: it.ActionKey,
				BlastRadius:       "no destructiveguard pattern match; destructiveguard remains an independent runtime backstop at dispatch time",
			})
		case destructiveguard.ClassDestructive:
			r, ok := byKey[reviewedKey{it.TechniqueID, it.ActionKey}]
			if ok && r.CommandHash == CommandHash(it.Command) {
				out = append(out, ClassifiedItem{
					KeyedItem: it, Status: StatusClassified,
					Class:             r.Class,
					DestructiveAction: it.ActionKey,
					BlastRadius:       r.Note,
				})
			} else {
				out = append(out, ClassifiedItem{KeyedItem: it, Status: StatusUnresolved})
			}
		}
	}
	return out
}
```

Create the seed `orchestrator/internal/scenario/execclass_reviewed.yaml`:

```yaml
# Human-reviewed classification decisions for ART/Caldera items that
# agent/destructiveguard.Classify flags as destructive. Populated for
# real in Task 8 of docs/superpowers/plans/2026-10-03-b5-art-caldera-corpus-audit.md
# -- see that task for the review methodology. Each entry's command_hash
# pins it to the exact command text reviewed; a later corpus change that
# alters the command text makes the entry stale (treated as unresolved
# again, not silently re-applied) until re-reviewed.
#
# - technique_id: T1490
#   action_key: vss_delete_akira_style
#   class: destructive
#   command_hash: <sha256 of the exact reviewed command text>
#   reviewer: <name>
#   reviewed_at: 2026-10-03
#   note: "<why this classification>"
[]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/scenario/corpusaudit/... -v`
Expected: PASS — all tests in the package green.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/scenario/corpusaudit/triage.go orchestrator/internal/scenario/corpusaudit/triage_test.go orchestrator/internal/scenario/execclass_reviewed.yaml
git commit -m "feat(corpusaudit): destructiveguard triage + reviewed-decisions merge with staleness detection"
git push
```

---

### Task 5: Generated-catalog writer + report writer

**Files:**
- Create: `orchestrator/internal/scenario/corpusaudit/generate.go`
- Create: `orchestrator/internal/scenario/corpusaudit/generate_test.go`

**Interfaces:**
- Consumes: `ClassifiedItem`, `CoverageReport` (Tasks 3, 4).
- Produces: `func WriteGeneratedGo(w io.Writer, items []ClassifiedItem) error`, `func WriteReportMarkdown(w io.Writer, r CoverageReport) error` — consumed by Task 6's wiring.

- [ ] **Step 1: Write the failing tests**

```go
package corpusaudit

import (
	"bytes"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestWriteGeneratedGo_ProducesValidGoSyntax(t *testing.T) {
	items := []ClassifiedItem{
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{TechniqueID: "T1082", Command: "whoami"}, ActionKey: "whoami_test"},
			Status: StatusClassified, Class: scenario.ClassNonDestructive, DestructiveAction: "whoami_test", BlastRadius: "read-only identity query"},
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{TechniqueID: "T1490", Command: "vssadmin delete shadows /all"}, ActionKey: "vss_delete_test"},
			Status: StatusClassified, Class: scenario.ClassDestructive, DestructiveAction: "vss_delete_test", BlastRadius: "deletes real shadow copies"},
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{TechniqueID: "T9999", Command: "irrelevant"}, ActionKey: "still_unresolved"},
			Status: StatusUnresolved},
	}
	var buf bytes.Buffer
	if err := WriteGeneratedGo(&buf, items); err != nil {
		t.Fatalf("WriteGeneratedGo: %v", err)
	}
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "execclass_generated.go", buf.String(), 0); err != nil {
		t.Fatalf("generated file is not valid Go: %v\n---\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "package scenario") {
		t.Error("expected package scenario declaration")
	}
	if !strings.Contains(out, "DO NOT EDIT") {
		t.Error("expected a DO NOT EDIT header")
	}
	if !strings.Contains(out, `"T1082"`) || !strings.Contains(out, `"whoami_test"`) {
		t.Error("expected the classified non_destructive entry to appear")
	}
	if !strings.Contains(out, `"T1490"`) || !strings.Contains(out, `"vss_delete_test"`) {
		t.Error("expected the classified destructive entry to appear")
	}
	if strings.Contains(out, "T9999") {
		t.Error("expected an unresolved item to be excluded from the generated catalog entirely")
	}
}

func TestWriteReportMarkdown_FormatsRealCounts(t *testing.T) {
	r := CoverageReport{
		ART:     SourceCounts{Discovered: 500, Reachable: 480, Classified: 470, DestructiveCandidates: 30, ManuallyReviewed: 28, Unresolved: 2},
		Caldera: SourceCounts{Discovered: 2200, Reachable: 2100, Classified: 2080, DestructiveCandidates: 50, ManuallyReviewed: 45, Unresolved: 5},
	}
	var buf bytes.Buffer
	if err := WriteReportMarkdown(&buf, r); err != nil {
		t.Fatalf("WriteReportMarkdown: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"ART:", "discovered: 500", "unresolved: 2", "Caldera:", "discovered: 2200", "unresolved: 5"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/scenario/corpusaudit/... -run 'TestWriteGeneratedGo|TestWriteReportMarkdown' -v`
Expected: FAIL — `WriteGeneratedGo`/`WriteReportMarkdown` undefined.

- [ ] **Step 3: Write the implementation**

```go
package corpusaudit

import (
	"fmt"
	"io"
	"sort"
)

// WriteGeneratedGo writes execclass_generated.go's full source. Only
// StatusClassified items are emitted -- StatusAlreadyHandAuthored items
// are already in execclass.go (emitting them again would be a harmless
// but confusing duplicate map write), and StatusUnresolved items must
// NEVER appear in a committed catalog file.
func WriteGeneratedGo(w io.Writer, items []ClassifiedItem) error {
	type entry struct{ tech, key, class, da, br string }
	var entries []entry
	for _, it := range items {
		if it.Status != StatusClassified {
			continue
		}
		entries = append(entries, entry{it.TechniqueID, it.ActionKey, string(it.Class), it.DestructiveAction, it.BlastRadius})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].tech != entries[j].tech {
			return entries[i].tech < entries[j].tech
		}
		return entries[i].key < entries[j].key
	})

	if _, err := fmt.Fprint(w, "// Code generated by cmd/auditcorpus. DO NOT EDIT.\n"+
		"// Regenerate: go run ./cmd/auditcorpus (needs a local docker compose stack -- see\n"+
		"// packaging/compose/docker-compose.yml's auditcorpus service).\n\n"+
		"package scenario\n\nfunc init() {\n"); err != nil {
		return err
	}
	for _, e := range entries {
		if _, err := fmt.Fprintf(w,
			"\tif executionClassifications[%q] == nil {\n\t\texecutionClassifications[%q] = map[string]*ExecutionClassification{}\n\t}\n"+
				"\texecutionClassifications[%q][%q] = &ExecutionClassification{Class: %q, DestructiveAction: %q, BlastRadius: %q}\n",
			e.tech, e.tech, e.tech, e.key, e.class, e.da, e.br); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, "}\n")
	return err
}

// WriteReportMarkdown writes the coverage report in the exact format the
// design doc specifies, split by source, with real counts from the run
// that produced r -- never hard-coded.
func WriteReportMarkdown(w io.Writer, r CoverageReport) error {
	_, err := fmt.Fprintf(w, "ART:\n"+
		"  discovered: %d\n  reachable: %d\n  classified: %d\n"+
		"  destructive candidates: %d\n  manually reviewed: %d\n  unresolved: %d\n\n"+
		"Caldera:\n"+
		"  discovered: %d\n  reachable: %d\n  classified: %d\n"+
		"  destructive candidates: %d\n  manually reviewed: %d\n  unresolved: %d\n",
		r.ART.Discovered, r.ART.Reachable, r.ART.Classified, r.ART.DestructiveCandidates, r.ART.ManuallyReviewed, r.ART.Unresolved,
		r.Caldera.Discovered, r.Caldera.Reachable, r.Caldera.Classified, r.Caldera.DestructiveCandidates, r.Caldera.ManuallyReviewed, r.Caldera.Unresolved,
	)
	return err
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/scenario/corpusaudit/... -v`
Expected: PASS — all tests in the package green.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/scenario/corpusaudit/generate.go orchestrator/internal/scenario/corpusaudit/generate_test.go
git commit -m "feat(corpusaudit): generated-catalog and coverage-report writers"
git push
```

---

### Task 6: `cmd/auditcorpus` wiring + first real run against the live stack

**Files:**
- Create: `orchestrator/cmd/auditcorpus/main.go`
- Modify: `orchestrator/internal/scenario/execclass_generated.go` (created fresh by running the tool, then committed)
- Modify: `orchestrator/internal/scenario/testdata/execclass_corpus_report.md` (created fresh by running the tool, then committed)

**Interfaces:**
- Consumes: everything from Tasks 1-5 (`DiscoveredItem`, `DeriveActionKeys`, `Triage`, `LoadReviewedDecisions`, `WriteGeneratedGo`, `WriteReportMarkdown`, `scenario.NewARTStoreFromDB`, `scenario.FetchRawCalderaAbilities`).
- Produces: a real, committed `execclass_generated.go` and `execclass_corpus_report.md` reflecting the actual live corpus — consumed by Task 7 (the gate test reads the same live corpus independently) and Task 8 (the real audit reads the report's `unresolved` count to know what to review).

- [ ] **Step 1: Write `main.go`**

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/scenario/corpusaudit"
)

const (
	generatedPath = "internal/scenario/execclass_generated.go"
	reviewedPath  = "internal/scenario/execclass_reviewed.yaml"
	reportPath    = "internal/scenario/testdata/execclass_corpus_report.md"
)

func main() {
	ctx := context.Background()
	dbURL := os.Getenv("DATABASE_URL")
	calderaURL := os.Getenv("CALDERA_URL")
	calderaKey := os.Getenv("CALDERA_API_KEY")
	if dbURL == "" || calderaURL == "" {
		log.Fatal("auditcorpus requires DATABASE_URL and CALDERA_URL -- run via the local compose stack: docker compose --profile audit run --rm auditcorpus")
	}

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("connect to postgres: %v", err)
	}
	defer pool.Close()

	artStore, err := scenario.NewARTStoreFromDB(ctx, pool, nil)
	if err != nil {
		log.Fatalf("load ART atomics: %v", err)
	}

	var items []corpusaudit.DiscoveredItem
	for _, tech := range artStore.ListTechniques() {
		for _, step := range artStore.GetStepsByPlatform(tech, "windows") {
			items = append(items, corpusaudit.DiscoveredItem{
				Source:      "art",
				TechniqueID: step.TechniqueID,
				Name:        step.Name,
				Executor:    step.Executor,
				Command:     step.Command,
				Reachable:   step.Command != "" && step.TechniqueID != "",
			})
		}
	}
	if len(items) == 0 {
		log.Fatal("loaded zero ART atomics from art_atomic_tests -- is the table populated? (the orchestrator's own startup import populates it; confirm the compose stack's orchestrator service has started at least once)")
	}
	artCount := len(items)

	raw, err := scenario.FetchRawCalderaAbilities(calderaURL, calderaKey)
	if err != nil {
		log.Fatalf("fetch Caldera abilities: %v", err)
	}
	if len(raw) == 0 {
		log.Fatal("fetched zero Caldera abilities -- is Caldera still loading its ability library? check `docker compose ps caldera` reports healthy")
	}
	for _, ab := range raw {
		items = append(items, corpusaudit.DiscoveredItem{
			Source:      "caldera",
			TechniqueID: ab.TechniqueID,
			Name:        ab.Name,
			Executor:    ab.Executor,
			Command:     ab.Command,
			AbilityID:   ab.AbilityID,
			Reachable:   ab.Command != "" && ab.TechniqueID != "",
		})
	}

	keyed, collisions := corpusaudit.DeriveActionKeys(items)
	for _, c := range collisions {
		log.Printf("WARNING: %v (both items excluded from the catalog, will surface as unresolved)", c)
	}

	reviewed, err := corpusaudit.LoadReviewedDecisions(reviewedPath)
	if err != nil {
		log.Fatalf("load %s: %v", reviewedPath, err)
	}

	classified := corpusaudit.Triage(keyed, reviewed)

	genFile, err := os.Create(generatedPath)
	if err != nil {
		log.Fatalf("create %s: %v", generatedPath, err)
	}
	defer genFile.Close()
	if err := corpusaudit.WriteGeneratedGo(genFile, classified); err != nil {
		log.Fatalf("write %s: %v", generatedPath, err)
	}

	if err := os.MkdirAll("internal/scenario/testdata", 0o755); err != nil {
		log.Fatalf("mkdir testdata: %v", err)
	}
	reportFile, err := os.Create(reportPath)
	if err != nil {
		log.Fatalf("create %s: %v", reportPath, err)
	}
	defer reportFile.Close()
	report := corpusaudit.BuildReport(classified)
	if err := corpusaudit.WriteReportMarkdown(reportFile, report); err != nil {
		log.Fatalf("write %s: %v", reportPath, err)
	}

	fmt.Printf("ART atomics loaded: %d\nART: %+v\nCaldera: %+v\n", artCount, report.ART, report.Caldera)
}
```

- [ ] **Step 2: Bring up the real local stack**

Run (from the repo root, with the orchestrator having started at least once already so `art_atomic_tests` is populated — the orchestrator's own startup import does this automatically):
```bash
cd packaging/compose
docker compose up -d postgres caldera orchestrator
# wait until `docker compose ps` shows orchestrator and caldera healthy
```
Expected: all three services report healthy. If `orchestrator` fails to start because of an unrelated pre-existing config requirement (e.g. a missing `.env` secret), use the project's own documented local-dev bring-up steps for this compose file before proceeding — this step only requires that `art_atomic_tests` gets populated at least once, not that the orchestrator stays running afterward.

- [ ] **Step 3: Run the tool for real and observe its actual output**

Run:
```bash
docker compose --profile audit run --rm auditcorpus
```
Expected: real, non-fabricated output resembling `ART atomics loaded: <N>`, `ART: {Discovered:<N> Reachable:<N> ...}`, `Caldera: {Discovered:<N> ...}` — with `Unresolved` counts greater than zero for both sources (nothing has been reviewed yet, so every destructiveguard-flagged item is unresolved at this point; that's the correct, expected state before Task 8).

- [ ] **Step 4: Confirm the generated files are real and compile**

Run:
```bash
cd orchestrator && go build ./...
cat internal/scenario/testdata/execclass_corpus_report.md
```
Expected: clean build (the new `execclass_generated.go` is syntactically valid Go, consistent with Task 5's own `go/parser` test), and the report file shows the exact counts the tool printed to stdout in Step 3.

- [ ] **Step 5: Confirm the tool fails loudly and writes nothing when the stack is unreachable**

Save a copy of the real `execclass_generated.go` from Step 3 first (`cp orchestrator/internal/scenario/execclass_generated.go /tmp/execclass_generated.go.good`), then run with a deliberately broken connection:
```bash
docker compose --profile audit run --rm -e DATABASE_URL="postgres://bad:bad@nowhere:5432/nothing" auditcorpus
echo "exit code: $?"
diff /tmp/execclass_generated.go.good orchestrator/internal/scenario/execclass_generated.go
```
Expected: non-zero exit code, a clear connection-failure error on stdout/stderr (`log.Fatalf("connect to postgres: ...")`), and `diff` reports **no difference** — the real, good file from Step 3 is untouched, because `main.go` only calls `os.Create(generatedPath)` after `NewARTStoreFromDB`/`FetchRawCalderaAbilities` have both already succeeded. If `diff` shows any change, this is a real bug (the write ordering must move after both loads succeed, not before) — fix it with `systematic-debugging` before continuing, not by treating a corrupted file as acceptable.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/cmd/auditcorpus/main.go orchestrator/internal/scenario/execclass_generated.go orchestrator/internal/scenario/testdata/execclass_corpus_report.md
git commit -m "feat(corpusaudit): wire cmd/auditcorpus end to end, first real run against the live stack"
git push
```

---

### Task 7: The live-stack gate test

**Files:**
- Create: `orchestrator/internal/scenario/execclass_art_caldera_test.go`

**Interfaces:**
- Consumes: `scenario.NewARTStoreFromDB`, `scenario.FetchRawCalderaAbilities`, everything in `corpusaudit` (Tasks 1-5).
- Produces: `TestExecutionClassifications_ARTCalderaCorpusFullyResolved` — the release gate. No later task consumes this as code; Task 8 consumes its *result* (watches it go from failing to passing).

- [ ] **Step 1: Write the test**

```go
package scenario_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/scenario/corpusaudit"
)

// TestExecutionClassifications_ARTCalderaCorpusFullyResolved is the real
// release gate for the B5 ART/Caldera audit: it re-runs the exact same
// resolution cmd/auditcorpus uses against a live stack and asserts
// unresolved == 0 for both sources. It needs DATABASE_URL and
// CALDERA_URL pointing at a real, populated local compose stack (see
// packaging/compose/docker-compose.yml) -- without them, it skips
// cleanly rather than failing, matching this repo's existing
// testcontainer-suite convention (see internal/api's tests).
func TestExecutionClassifications_ARTCalderaCorpusFullyResolved(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	calderaURL := os.Getenv("CALDERA_URL")
	if dbURL == "" || calderaURL == "" {
		t.Skip("DATABASE_URL/CALDERA_URL not set -- skipping the live-stack ART/Caldera corpus gate (run via the local compose stack to exercise this for real)")
	}
	calderaKey := os.Getenv("CALDERA_API_KEY")

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("connect to postgres: %v", err)
	}
	defer pool.Close()

	artStore, err := scenario.NewARTStoreFromDB(ctx, pool, nil)
	if err != nil {
		t.Fatalf("load ART atomics: %v", err)
	}

	var items []corpusaudit.DiscoveredItem
	for _, tech := range artStore.ListTechniques() {
		for _, step := range artStore.GetStepsByPlatform(tech, "windows") {
			items = append(items, corpusaudit.DiscoveredItem{
				Source: "art", TechniqueID: step.TechniqueID, Name: step.Name,
				Executor: step.Executor, Command: step.Command,
				Reachable: step.Command != "" && step.TechniqueID != "",
			})
		}
	}
	if len(items) == 0 {
		t.Fatal("loaded zero ART atomics -- art_atomic_tests appears empty; this is an environment problem, not a resolved-vs-unresolved question")
	}

	raw, err := scenario.FetchRawCalderaAbilities(calderaURL, calderaKey)
	if err != nil {
		t.Fatalf("fetch Caldera abilities: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("fetched zero Caldera abilities -- Caldera appears unloaded; this is an environment problem, not a resolved-vs-unresolved question")
	}
	for _, ab := range raw {
		items = append(items, corpusaudit.DiscoveredItem{
			Source: "caldera", TechniqueID: ab.TechniqueID, Name: ab.Name,
			Executor: ab.Executor, Command: ab.Command, AbilityID: ab.AbilityID,
			Reachable: ab.Command != "" && ab.TechniqueID != "",
		})
	}

	keyed, collisions := corpusaudit.DeriveActionKeys(items)
	for _, c := range collisions {
		t.Logf("unresolved action_key collision (counts as unresolved below): %v", c)
	}

	reviewed, err := corpusaudit.LoadReviewedDecisions("execclass_reviewed.yaml")
	if err != nil {
		t.Fatalf("load execclass_reviewed.yaml: %v", err)
	}

	classified := corpusaudit.Triage(keyed, reviewed)
	report := corpusaudit.BuildReport(classified)

	if report.ART.Unresolved != 0 {
		t.Errorf("ART corpus has %d unresolved (technique_id, action_key) pairs -- see internal/scenario/testdata/execclass_corpus_report.md "+
			"and docs/superpowers/plans/2026-10-03-b5-art-caldera-corpus-audit.md's Task 8 for the review methodology", report.ART.Unresolved)
	}
	if report.Caldera.Unresolved != 0 {
		t.Errorf("Caldera corpus has %d unresolved (technique_id, action_key) pairs -- see internal/scenario/testdata/execclass_corpus_report.md "+
			"and docs/superpowers/plans/2026-10-03-b5-art-caldera-corpus-audit.md's Task 8 for the review methodology", report.Caldera.Unresolved)
	}
}
```

- [ ] **Step 2: Run the test without the live stack and confirm it skips cleanly**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestExecutionClassifications_ARTCalderaCorpusFullyResolved -v`
Expected: `--- SKIP` with the "DATABASE_URL/CALDERA_URL not set" message (no env vars set in this invocation) — confirms the no-live-stack path is a clean skip, not a false green or a hard failure.

- [ ] **Step 3: Run the test against the real stack and confirm it fails for the right reason (RED)**

Run (with the compose stack from Task 6 still up):
```bash
cd orchestrator
DATABASE_URL="postgres://bas_app:<password>@localhost:<mapped-postgres-port>/bas_platform?sslmode=prefer" \
CALDERA_URL="http://localhost:<mapped-caldera-port>" \
CALDERA_API_KEY="BASPlatform2024" \
go test ./internal/scenario/... -run TestExecutionClassifications_ARTCalderaCorpusFullyResolved -v
```
(Running from the host rather than inside the compose network needs the ports actually mapped — if `caldera`'s compose service only `expose`s 8888 internally, run this test the same way Task 6 ran the tool: `docker compose --profile audit run --rm` with a throwaway test-runner service pointed at `go test` instead of `go run ./cmd/auditcorpus`, reusing the exact same `DATABASE_URL`/`CALDERA_URL` the `auditcorpus` service already uses.)

Expected: **FAIL**, reporting `ART corpus has N unresolved...` and `Caldera corpus has M unresolved...` with `N, M > 0` — this is the correct RED state: real unresolved items exist because nothing has been reviewed yet. This is not a bug to fix in this task; Task 8 is what drives it GREEN.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/scenario/execclass_art_caldera_test.go
git commit -m "test(corpusaudit): add the live-stack ART/Caldera corpus-resolved gate (currently RED, real unresolved items pending Task 8's review)"
git push
```

---

### Task 8: The real security audit — review every flagged item, close the gate

This is the actual classification judgment the rest of the plan exists to support — not mechanical work. Nothing about the specific findings can be known in advance, so this task is a methodology, not a pre-written answer key, mirroring B5 Phase 1's own Task 10 precedent.

**Files:**
- Modify: `orchestrator/internal/scenario/execclass_reviewed.yaml`

**Interfaces:**
- Consumes: the report from Task 6/7 (`report.ART.Unresolved`, `report.Caldera.Unresolved`, and the specific `(technique_id, action_key)` pairs behind them).
- Produces: a `execclass_reviewed.yaml` with zero remaining unresolved pairs — the terminal state the plan's Review Focus and gate test both depend on.

- [ ] **Step 1: Get the exact list of unresolved pairs with their real command text**

Re-run the tool (or a small throwaway debug build of it — your choice, whichever is faster) with verbose logging of every `StatusUnresolved` item's `TechniqueID`, `ActionKey`, `Source`, and full `Command` text. (The simplest way: temporarily add a `log.Printf` in `main.go`'s loop over `classified` for `Status == corpusaudit.StatusUnresolved`, or write a 10-line throwaway script that calls the same `corpusaudit` functions and prints the unresolved slice directly — delete whichever throwaway you use afterward, same discipline as B5 Phase 1's own throwaway re-signing tool.)

- [ ] **Step 2: Read every real command, one at a time**

For each unresolved `(technique_id, action_key, command)`:
- Read the actual command text. Is it genuinely destructive (irreversible real-world effect — deletes backups, disables recovery, kills a security control, destroys data), or is `destructiveguard` right to flag it but the actual effect is self-limiting (matches the existing `potentially_destructive` tier, e.g. a service stop that gets restarted, a BAS-owned decoy artifact)?
- Cross-reference against the hand-authored catalog's existing entries for similar real commands (e.g. `T1490`'s existing `vss_delete` family) to classify consistently with established precedent, not from scratch each time.
- Watch specifically for narration/false positives: does the "command" actually execute, or is it descriptive text that happens to contain a flagged keyword? (Caldera ability descriptions and ART atomic `description` fields are separate from `executor.command` — confirm you're reading the real executed command, not a description field, for every item.)

- [ ] **Step 3: Record each decision**

For each reviewed item, append a real entry to `execclass_reviewed.yaml`:

```yaml
- technique_id: <real technique ID>
  action_key: <the exact action_key from the report>
  class: destructive  # or potentially_destructive, or non_destructive if this is a genuine false positive
  command_hash: <output of corpusaudit.CommandHash(<the exact real command text>)>
  reviewer: <your name>
  reviewed_at: <today's date>
  note: "<why, referencing the hand-authored precedent this matches if any>"
```

If a reviewed item turns out to be a false positive (destructiveguard flagged it but it's genuinely safe), record `class: non_destructive` here rather than trying to "fix" destructiveguard itself — destructiveguard staying maximally cautious at the pattern layer is correct; this audit's reviewed-decisions file is exactly the place a confirmed-safe exception belongs.

- [ ] **Step 4: Re-run the tool and confirm the real counts dropped**

Run: `docker compose --profile audit run --rm auditcorpus` (same as Task 6, Step 3)
Expected: real output showing `Unresolved: 0` for both ART and Caldera. If any remain, return to Step 2 for those specific pairs — do not mark the task done with a nonzero unresolved count.

- [ ] **Step 5: Run the gate test and confirm GREEN**

Run (same invocation as Task 7, Step 3): `go test ./internal/scenario/... -run TestExecutionClassifications_ARTCalderaCorpusFullyResolved -v`
Expected: **PASS**.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/scenario/execclass_reviewed.yaml orchestrator/internal/scenario/execclass_generated.go orchestrator/internal/scenario/testdata/execclass_corpus_report.md
git commit -m "fix(corpusaudit): complete the ART/Caldera manual classification review -- gate is now green"
git push
```
