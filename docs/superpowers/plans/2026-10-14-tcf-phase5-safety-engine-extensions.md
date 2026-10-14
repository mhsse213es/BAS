# TCF Phase 5 — Safety Engine Extensions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refuse a composed candidate whose components' combined ATT&CK tactics match a known elevated-risk combination (e.g. Defense Evasion + Persistence), before any `content_versions` row is created, without touching the existing per-step `safetyVerdict`/`execclass.go` classifier at all.

**Architecture:** One new, small, hardcoded Go catalog of flagged ATT&CK tactic pairs in `internal/contentregistry`, backed by the already-embedded `attackdata.Lookup` tactic lookup (no new tagging, no DB migration). A single new function resolves each composed candidate's components' tactics, checks them against the catalog, and is called from the existing `Compose` function between its current safety-destructive refusal and its call to `createVersion`. A successful (non-refused) composition records a second `content_safety_verdicts` row for auditability.

**Tech Stack:** Go, `internal/contentregistry`, `internal/reporting/attackdata` (already-embedded MITRE ATT&CK enterprise-attack 16.1 dataset), PostgreSQL (existing `content_safety_verdicts` table, no migration).

**Spec:** `docs/superpowers/specs/2026-10-14-tcf-phase5-safety-engine-extensions-design.md`

## Global Constraints

- The target is emergent risk — a safe-in-isolation part's effect removing a safety net another safe-in-isolation part's rating assumed — not "this looks like a realistic attack chain" (spec §2.1). The starter catalog reflects this: Defense Evasion + Persistence, Defense Evasion + Execution only.
- `scenario.ResolveExecutionClass`, `execclass.go`'s catalog, and `analyze.go`'s `safetyVerdict` must be unmodified by this plan's diff (spec acceptance criterion 5) — every non-composed content path's behavior must be provably unaffected.
- An unresolvable `technique_id` (no `attackdata.Lookup` match) refuses the whole composition, fail-closed, even if no catalog pair would otherwise apply (spec §2.2, acceptance criterion 3).
- The tactic-pair catalog is a hardcoded Go value, never a database table or an API-editable resource (spec acceptance criterion 6).
- A successful composition gets exactly one new `content_safety_verdicts` row, `classifier = "combinatorial"`, distinct from and in addition to the existing `execclass` row (spec acceptance criterion 4).
- Refusal happens before `createVersion` is called — no `content_versions` row on refusal, matching every other `Compose` refusal path (spec §2.4, acceptance criterion 1).

## Review Focus

- Composing a Defense-Evasion-tactic component with a Persistence-tactic component (the spec's own motivating example) — must refuse, with zero new `content_versions` rows.
- Composing a Defense-Evasion-tactic component with a Discovery-tactic component (an unflagged pair) — must succeed, proving this isn't an over-broad "attack-shaped content" filter.
- A component whose `technique_id` doesn't resolve via `attackdata.Lookup` — must refuse the whole composition, even when no catalog pair would otherwise fire.
- A successful composition — must produce exactly one `content_safety_verdicts` row with `classifier = "combinatorial"`, separate from the existing `execclass` row `createVersion` already writes.
- `execclass.go` and `analyze.go` must be byte-for-byte unmodified by this plan's diff — verified by the final reviewer reading the diff's file list, not a unit test (there is nothing a Go test could assert about a file nobody touched; the plan simply never names either file as a Modify target in any task).

---

### Task 1: Combinatorial risk catalog and Compose integration

**Files:**
- Create: `orchestrator/internal/contentregistry/combinatorial.go`
- Create: `orchestrator/internal/contentregistry/combinatorial_test.go`
- Modify: `orchestrator/internal/contentregistry/compose.go`
- Modify: `orchestrator/internal/contentregistry/compose_test.go`

**Interfaces:**
- Consumes: `loadedComponent` (already defined in `compose.go` from TCF Phase 4 — fields include `id`, `techniqueID`, `supportedOS`, `kind`, `stepSnapshot`, `framework`, `abilityID`, `actionKey`, `testIndex`); `attackdata.Lookup(id string) *attackdata.Enrichment` where `Enrichment.Tactics []string` (`internal/reporting/attackdata/attackdata.go:65-76,258-270`, already safely imported elsewhere in this package via `intake.go:10`).
- Produces: `combinatorialRisk(components []loadedComponent) ([]string, error)` (returns the resolved, sorted tactic union on success, or a non-nil error — for either an unresolvable technique or a flagged combination — that the caller returns directly) — nothing downstream in this plan consumes it beyond `Compose` itself (last task).

- [ ] **Step 1: Write the failing pure-logic tests**

```go
// orchestrator/internal/contentregistry/combinatorial_test.go
package contentregistry

import "testing"

// T1562 (Impair Defenses) -> defense-evasion; T1547 (Boot or Logon Autostart
// Execution) -> persistence, privilege-escalation. T1087 (Account Discovery)
// -> discovery. All three verified directly against
// internal/reporting/attackdata/attack_enrichment.json before writing this
// test, not guessed.

func TestCombinatorialRisk_FlagsDefenseEvasionPlusPersistence(t *testing.T) {
	components := []loadedComponent{
		{techniqueID: "T1562"},
		{techniqueID: "T1547"},
	}
	_, err := combinatorialRisk(components)
	if err == nil {
		t.Fatal("expected defense-evasion + persistence to be flagged as an elevated-risk combination")
	}
}

func TestCombinatorialRisk_FlagsDefenseEvasionPlusExecution(t *testing.T) {
	components := []loadedComponent{
		{techniqueID: "T1562"},
		{techniqueID: "T1059"},
	}
	_, err := combinatorialRisk(components)
	if err == nil {
		t.Fatal("expected defense-evasion + execution to be flagged as an elevated-risk combination")
	}
}

func TestCombinatorialRisk_AllowsUnflaggedPair(t *testing.T) {
	components := []loadedComponent{
		{techniqueID: "T1562"}, // defense-evasion
		{techniqueID: "T1087"}, // discovery
	}
	tactics, err := combinatorialRisk(components)
	if err != nil {
		t.Fatalf("expected defense-evasion + discovery (not in the catalog) to succeed, got: %v", err)
	}
	if len(tactics) != 2 {
		t.Fatalf("expected 2 resolved tactics, got %v", tactics)
	}
}

func TestCombinatorialRisk_RefusesUnresolvableTechnique(t *testing.T) {
	components := []loadedComponent{
		{techniqueID: "T9999.999"}, // not a real ATT&CK technique -- confirmed absent from attack_enrichment.json
		{techniqueID: "T1059"},
	}
	_, err := combinatorialRisk(components)
	if err == nil {
		t.Fatal("expected an unresolvable technique_id to refuse the whole composition (fail-closed default)")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/contentregistry/... -run TestCombinatorialRisk -v -count=1`
Expected: FAIL — compile error, `combinatorialRisk` undefined.

- [ ] **Step 3: Implement the catalog and the resolution function**

```go
// orchestrator/internal/contentregistry/combinatorial.go
package contentregistry

import (
	"fmt"
	"sort"

	"github.com/audspect/bas/internal/reporting/attackdata"
)

const (
	combinatorialClassifier        = "combinatorial"
	combinatorialClassifierVersion = "1"
)

// tacticPairRisk names one unordered pair of MITRE ATT&CK tactics whose
// combination within a single composed candidate is an elevated real-world
// risk -- not because the combination looks like a realistic attack (that
// is this product's purpose), but because one tactic's presence removes a
// safety net the other tactic's individually-safe step rating assumed
// (spec §2.1).
type tacticPairRisk struct {
	tacticA string
	tacticB string
	reason  string
}

// combinationRiskCatalog is a hardcoded, code-reviewed value -- never a
// database table, never editable at runtime (spec §2.3, acceptance
// criterion 6). Starter set only; see spec §4 for explicitly-deferred
// candidates.
var combinationRiskCatalog = []tacticPairRisk{
	{
		tacticA: "defense-evasion", tacticB: "persistence",
		reason: "disabling defenses then persisting removes the observability this persistence mechanism's reversibility assumed",
	},
	{
		tacticA: "defense-evasion", tacticB: "execution",
		reason: "disabling defenses then executing removes the observability this execution step's reversibility assumed",
	},
}

// combinatorialRisk resolves each component's ATT&CK tactic(s) via
// attackdata.Lookup, unions them, and checks the union against
// combinationRiskCatalog (spec §2.2-§2.3). An unresolvable technique_id
// fails closed: the whole composition is refused, even if no catalog pair
// would otherwise apply (spec acceptance criterion 3). On success, returns
// the sorted resolved tactic union for the caller to record.
func combinatorialRisk(components []loadedComponent) ([]string, error) {
	tacticSet := map[string]bool{}
	for _, c := range components {
		e := attackdata.Lookup(c.techniqueID)
		if e == nil {
			return nil, fmt.Errorf("composition refused: technique %s has no known ATT&CK tactic, cannot be safety-assessed", c.techniqueID)
		}
		for _, t := range e.Tactics {
			tacticSet[t] = true
		}
	}
	for _, rule := range combinationRiskCatalog {
		if tacticSet[rule.tacticA] && tacticSet[rule.tacticB] {
			return nil, fmt.Errorf("composition refused: combining %s and %s tactics is an elevated-risk combination (%s)",
				rule.tacticA, rule.tacticB, rule.reason)
		}
	}
	tactics := make([]string, 0, len(tacticSet))
	for t := range tacticSet {
		tactics = append(tactics, t)
	}
	sort.Strings(tactics)
	return tactics, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/contentregistry/... -run TestCombinatorialRisk -v -count=1`
Expected: PASS, all 4 tests.

- [ ] **Step 5: Write the failing Compose-integration tests**

Append to the existing `orchestrator/internal/contentregistry/compose_test.go` (this file already has `seedComposeThreat` and the `sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {...})` pattern from TCF Phase 4 — reuse both, don't redefine):

```go
func TestCompose_RefusesDefenseEvasionPlusPersistence(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, testutil.DevVerifier())
		ctx := context.Background()
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1562", "disable-defenses", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1547", "persist", "", "", 2, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		threatID := seedComposeThreat(t, pool, "APT-compose-combo-flagged")
		var countBefore int
		pool.QueryRow(ctx, `SELECT count(*) FROM content_versions`).Scan(&countBefore)

		_, _, err = reg.Compose(ctx, []string{c1, c2}, threatID, "admin-test")
		if err == nil {
			t.Fatal("expected Compose to refuse a defense-evasion + persistence combination")
		}
		var countAfter int
		pool.QueryRow(ctx, `SELECT count(*) FROM content_versions`).Scan(&countAfter)
		if countAfter != countBefore {
			t.Fatalf("expected zero new content_versions rows on combinatorial refusal, got %d new", countAfter-countBefore)
		}
	})
}

func TestCompose_AllowsDefenseEvasionPlusDiscovery(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, testutil.DevVerifier())
		ctx := context.Background()
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1562", "disable-defenses", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1087", "discover", "", "", 2, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		threatID := seedComposeThreat(t, pool, "APT-compose-combo-unflagged")

		_, created, err := reg.Compose(ctx, []string{c1, c2}, threatID, "admin-test")
		if err != nil {
			t.Fatalf("expected defense-evasion + discovery to succeed (not a flagged combination), got: %v", err)
		}
		if !created {
			t.Fatal("expected created=true")
		}
	})
}

func TestCompose_RefusesUnresolvableTechniqueInCombinatorialCheck(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, testutil.DevVerifier())
		ctx := context.Background()
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T9999.999", "unresolvable", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1059", "execute", "", "", 2, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		threatID := seedComposeThreat(t, pool, "APT-compose-combo-unresolvable")

		_, _, err = reg.Compose(ctx, []string{c1, c2}, threatID, "admin-test")
		if err == nil {
			t.Fatal("expected an unresolvable technique_id to refuse the whole composition")
		}
	})
}

func TestCompose_RecordsCombinatorialVerdictOnSuccess(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, testutil.DevVerifier())
		ctx := context.Background()
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1562", "disable-defenses", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1087", "discover", "", "", 2, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		threatID := seedComposeThreat(t, pool, "APT-compose-combo-verdict")

		versionID, _, err := reg.Compose(ctx, []string{c1, c2}, threatID, "admin-test")
		if err != nil {
			t.Fatalf("Compose: %v", err)
		}

		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM content_safety_verdicts WHERE content_version_id = $1 AND classifier = 'combinatorial'`,
			versionID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("expected exactly 1 combinatorial verdict row, got %d", count)
		}

		var execclassCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM content_safety_verdicts WHERE content_version_id = $1 AND classifier = 'execclass'`,
			versionID).Scan(&execclassCount); err != nil {
			t.Fatal(err)
		}
		if execclassCount != 1 {
			t.Fatalf("expected the existing execclass verdict row to still be written exactly once, got %d", execclassCount)
		}
	})
}
```

- [ ] **Step 6: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/contentregistry/... -run "TestCompose_RefusesDefenseEvasionPlusPersistence|TestCompose_AllowsDefenseEvasionPlusDiscovery|TestCompose_RefusesUnresolvableTechniqueInCombinatorialCheck|TestCompose_RecordsCombinatorialVerdictOnSuccess" -v -count=1`
Expected: `TestCompose_RefusesDefenseEvasionPlusPersistence` FAILs (no refusal happens yet — Compose currently succeeds for this input), `TestCompose_RefusesUnresolvableTechniqueInCombinatorialCheck` FAILs the same way, `TestCompose_AllowsDefenseEvasionPlusDiscovery` and `TestCompose_RecordsCombinatorialVerdictOnSuccess` FAIL at the verdict-count assertion (0 combinatorial rows exist yet, since nothing writes them).

- [ ] **Step 7: Wire the check into `Compose`**

In `orchestrator/internal/contentregistry/compose.go`, the existing function reads (from the already-committed Phase 4 code):

```go
	if a.safety.verdict == string(scenario.ClassDestructive) {
		return "", false, fmt.Errorf("composition refused: assembled steps classify as destructive")
	}

	versionID, created, err := r.createVersion(ctx, newVersion{
```

Insert the combinatorial check between those two lines:

```go
	if a.safety.verdict == string(scenario.ClassDestructive) {
		return "", false, fmt.Errorf("composition refused: assembled steps classify as destructive")
	}
	tactics, err := combinatorialRisk(components)
	if err != nil {
		return "", false, err
	}

	versionID, created, err := r.createVersion(ctx, newVersion{
```

Then, in the existing `if created { ... }` block that writes `content_version_components` provenance rows, add the verdict write as its first statement (same transaction-less follow-up step Phase 4's provenance writes already use):

```go
	if created {
		detail, _ := json.Marshal(map[string]any{"tactics": tactics})
		if _, err := r.pool.Exec(ctx, `INSERT INTO content_safety_verdicts (content_version_id, classifier, classifier_version, verdict, detail)
			VALUES ($1, $2, $3, 'PASS', $4)`,
			versionID, combinatorialClassifier, combinatorialClassifierVersion, detail); err != nil {
			return "", false, err
		}
		for i, c := range components {
```

(the `for i, c := range components {` line and everything after it in that block is unchanged from the existing Phase 4 code — only the new `detail`/`INSERT` lines are added immediately before it, inside the same `if created {` block).

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/contentregistry/... -run "TestCombinatorialRisk|TestCompose" -v -count=1`
Expected: PASS, all tests — the 4 pure-logic tests, the 4 new Compose-integration tests, and every pre-existing `TestCompose_*` test from Phase 4 (confirming no regression to the already-shipped refusal paths).

- [ ] **Step 9: Run the full contentregistry suite**

Run: `cd orchestrator && go test ./internal/contentregistry/... -count=1`
Expected: PASS (full package, confirming this task's additions coexist cleanly with everything pre-existing).

- [ ] **Step 10: gofmt and commit**

Run: `cd orchestrator && gofmt -l internal/contentregistry/combinatorial.go internal/contentregistry/combinatorial_test.go internal/contentregistry/compose.go internal/contentregistry/compose_test.go`
Expected: empty output.

```bash
git add orchestrator/internal/contentregistry/combinatorial.go orchestrator/internal/contentregistry/combinatorial_test.go orchestrator/internal/contentregistry/compose.go orchestrator/internal/contentregistry/compose_test.go
git commit -m "feat(tcf-phase5): combinatorial safety risk check for composed candidates"
```
