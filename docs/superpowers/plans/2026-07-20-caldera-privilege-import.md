# Caldera Privilege-Tier Import Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the same class of privilege-tier data-loss gap just fixed for ART, this time for Caldera: every ability fetched from Caldera's REST API carries a `privilege` field ("Elevated" or "") that this platform currently parses and discards, so every Caldera-sourced technique reports as "Legacy (unannotated)" in privilege coverage regardless of whether it actually requires elevation.

**Architecture:** Same normalization pattern as the ART fix (`mapARTElevation` → `PrivSpec`): add `Privilege string` to the `calderaAbilityFull` struct that already carries every other field this platform reads from a Caldera ability, add a small `mapCalderaElevation(privilege string) PrivSpec` function next to it, and set `RequiresPriv` in the three `ScenarioStep` literals that build steps from Caldera ability data. Unlike ART, Caldera abilities are fetched live from the Caldera API on every run — there is no DB cache and no stale-content problem to solve, so this fix takes effect immediately on the next fetch. No schema migration, no importer versioning.

**Tech Stack:** Go, `net/http`, `encoding/json` (existing Caldera REST client code in `internal/scenario/builder.go`).

## Global Constraints

- **Framework-agnostic core, unchanged.** Exactly as with ART, `mapCalderaElevation` is the only Caldera-specific code involved in this fix — it converges on the same `scenario.PrivSpec` type `mapARTElevation` already produces. Nothing downstream (`ScenarioStep`, reporting, variant coverage) changes or needs to know Caldera exists.
- **Verified against a real, live Caldera instance** (`ghcr.io/mitre/caldera:latest`, queried directly this session via its actual `/api/v2/abilities` and `/api/v2/abilities/{id}` endpoints) — not assumed from documentation. Confirmed: `privilege` is a top-level field on the ability JSON object (sibling to `ability_id`, `tactic`, `name` — NOT nested inside `executors`), with exactly two observed values: `"Elevated"` and `""` (empty string for no requirement).
- **Only three of the four Caldera code paths are in scope.** `buildCalderaAdversarySteps`, `buildCalderaAbilitiesSteps`, and `buildCalderaAllWindowsSteps` all auto-generate `ScenarioStep`s directly from Caldera ability metadata — these three are the fix's target. The fourth path (`calderaAbility`/`fetchCalderaCommand`/`calderaGet`, reached via `buildCalderaCommand` when a scenario author references a specific `ability_id` inline inside their own hand-written `Step`) is explicitly **not** touched: that path resolves into an author-written `Step`, which already has its own `RequiresPriv PrivSpec` field the author sets directly in YAML — auto-deriving privilege there would silently override an explicit author choice.
- **No DB/schema changes.** Confirmed via grounding: Caldera abilities are never persisted to Postgres by this codebase (unlike ART's `art_atomic_tests`) — every `buildCaldera*` function fetches live from the Caldera API on each call. This fix is pure in-memory mapping.
- Run all `go` commands from `orchestrator/`.

---

### Task 1: Normalization layer — parse and map Caldera's privilege field

**Files:**
- Modify: `orchestrator/internal/scenario/builder.go:372-378` (`calderaAbilityFull` struct)
- Test: `orchestrator/internal/scenario/caldera_fidelity_test.go` (existing file — same package, same conventions as the existing `calderaStepFidelity` tests)

**Interfaces:**
- Consumes: `scenario.PrivSpec` (already exists, `types.go:25-28`).
- Produces: `calderaAbilityFull.Privilege string` (new field, populated by JSON unmarshal from Caldera's `"privilege"` key). `mapCalderaElevation(privilege string) PrivSpec` — consumed by Task 2.

- [ ] **Step 1: Write the failing unit test**

Add to `orchestrator/internal/scenario/caldera_fidelity_test.go` (same package `scenario`, no new imports needed):

```go
func TestMapCalderaElevation(t *testing.T) {
	if got := mapCalderaElevation("Elevated"); got.Effective() != "admin" {
		t.Errorf(`mapCalderaElevation("Elevated") = %q, want admin`, got.Effective())
	}
	if got := mapCalderaElevation(""); got.Effective() != "user" {
		t.Errorf(`mapCalderaElevation("") = %q, want user`, got.Effective())
	}
	// Defensive: any value this platform doesn't recognize is treated as
	// unprivileged rather than silently escalating a step to admin.
	if got := mapCalderaElevation("Unknown"); got.Effective() != "user" {
		t.Errorf(`mapCalderaElevation("Unknown") = %q, want user`, got.Effective())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestMapCalderaElevation -v`
Expected: FAIL — `mapCalderaElevation` doesn't exist yet (compile error).

- [ ] **Step 3: Add the `Privilege` field and the mapping function**

In `orchestrator/internal/scenario/builder.go`, the current struct:

```go
type calderaAbilityFull struct {
	AbilityID   string            `json:"ability_id"`
	Name        string            `json:"name"`
	TechniqueID string            `json:"technique_id"`
	Tactic      string            `json:"tactic"`
	Executors   []calderaExecutor `json:"executors"`
}
```

becomes:

```go
type calderaAbilityFull struct {
	AbilityID   string            `json:"ability_id"`
	Name        string            `json:"name"`
	TechniqueID string            `json:"technique_id"`
	Tactic      string            `json:"tactic"`
	Executors   []calderaExecutor `json:"executors"`
	// Privilege is Caldera's own execution-context field on the ability
	// (not per-executor). Confirmed via a live Caldera instance
	// (ghcr.io/mitre/caldera:latest, /api/v2/abilities): exactly two
	// observed values, "Elevated" and "" (empty = no requirement).
	Privilege string `json:"privilege"`
}

// mapCalderaElevation translates Caldera's raw ability-level privilege
// string into this platform's framework-agnostic privilege tier (PrivSpec).
// This is the Caldera-specific half of the import normalization boundary,
// mirroring mapARTElevation in art.go — nothing downstream of the
// buildCaldera* functions ever sees Caldera's raw "Elevated"/"" strings
// again, only PrivSpec. Any value other than "Elevated" (including unknown
// future values) is treated as unprivileged rather than silently escalating.
func mapCalderaElevation(privilege string) PrivSpec {
	if privilege == "Elevated" {
		return PrivSpec{Minimum: "admin"}
	}
	return PrivSpec{Minimum: "user"}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestMapCalderaElevation -v`
Expected: PASS (all 3 assertions).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/scenario/builder.go orchestrator/internal/scenario/caldera_fidelity_test.go
git commit -m "feat(caldera): parse ability-level privilege field, map to framework-agnostic PrivSpec"
git push
```

---

### Task 2: Wire the mapping into all three step-builder functions

**Files:**
- Modify: `orchestrator/internal/scenario/builder.go` (`buildCalderaAdversarySteps`, `buildCalderaAbilitiesSteps`, `buildCalderaAllWindowsSteps`)
- Test: `orchestrator/internal/scenario/caldera_fidelity_test.go`

**Interfaces:**
- Consumes: `mapCalderaElevation` (Task 1), `calderaAbilityFull.Privilege` (Task 1).
- Produces: all three functions now populate `ScenarioStep.RequiresPriv` (already exists, `types.go:254`, type `string` — same field the ART fix populates).

- [ ] **Step 1: Write the failing integration test**

Add to `orchestrator/internal/scenario/caldera_fidelity_test.go`, mirroring the existing `TestBuildCalderaAllWindowsStepsSetsFidelity` pattern exactly:

```go
func TestBuildCalderaAllWindowsStepsSetsRequiresPriv(t *testing.T) {
	const abilitiesJSON = `[
	  {"ability_id":"a1","name":"safe recon","technique_id":"T1082","tactic":"discovery","privilege":"",
	   "executors":[{"platform":"windows","name":"psh","command":"systeminfo"}]},
	  {"ability_id":"a2","name":"clear logs","technique_id":"T1070.001","tactic":"defense-evasion","privilege":"Elevated",
	   "executors":[{"platform":"windows","name":"psh","command":"Clear-Eventlog Security"}]}
	]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/abilities" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(abilitiesJSON))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	steps, err := buildCalderaAllWindowsSteps(srv.URL, "")
	if err != nil {
		t.Fatalf("buildCalderaAllWindowsSteps: %v", err)
	}
	got := map[string]string{}
	for _, s := range steps {
		got[s.Name] = s.RequiresPriv
	}
	if got["safe recon"] != "user" {
		t.Errorf("safe recon RequiresPriv = %q, want user", got["safe recon"])
	}
	if got["clear logs"] != "admin" {
		t.Errorf("clear logs RequiresPriv = %q, want admin", got["clear logs"])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestBuildCalderaAllWindowsStepsSetsRequiresPriv -v`
Expected: FAIL — both `RequiresPriv` values are `""` (the field isn't populated yet).

- [ ] **Step 3: Populate `RequiresPriv` in `buildCalderaAdversarySteps`**

The current literal in `orchestrator/internal/scenario/builder.go`:

```go
		steps = append(steps, ScenarioStep{
			TaskID:      TaskID(techniqueID, ab.Name),
			TechniqueID: techniqueID,
			Name:        ab.Name,
			Framework:   "caldera",
			Executor:    "powershell",
			Command:     cmd,
			TimeoutSec:  60,
			Fidelity:    calderaStepFidelity(*ab),
		})
	}

	if len(steps) == 0 {
		return nil, fmt.Errorf("adversary %s yielded no executable steps for Windows platform", adversaryID)
```

becomes (only the struct literal inside `buildCalderaAdversarySteps` — identified by the surrounding `adversaryID` error message):

```go
		steps = append(steps, ScenarioStep{
			TaskID:       TaskID(techniqueID, ab.Name),
			TechniqueID:  techniqueID,
			Name:         ab.Name,
			Framework:    "caldera",
			Executor:     "powershell",
			Command:      cmd,
			TimeoutSec:   60,
			Fidelity:     calderaStepFidelity(*ab),
			RequiresPriv: mapCalderaElevation(ab.Privilege).Effective(),
		})
	}

	if len(steps) == 0 {
		return nil, fmt.Errorf("adversary %s yielded no executable steps for Windows platform", adversaryID)
```

- [ ] **Step 4: Populate `RequiresPriv` in `buildCalderaAbilitiesSteps`**

The identical-looking literal inside `buildCalderaAbilitiesSteps` — identified by its surrounding error message referencing `caldera_abilities`:

```go
		steps = append(steps, ScenarioStep{
			TaskID:      TaskID(techniqueID, ab.Name),
			TechniqueID: techniqueID,
			Name:        ab.Name,
			Framework:   "caldera",
			Executor:    "powershell",
			Command:     cmd,
			TimeoutSec:  60,
			Fidelity:    calderaStepFidelity(*ab),
		})
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf(
			"none of the %d ability IDs in caldera_abilities had a Windows executor in your Caldera instance. "+
```

becomes:

```go
		steps = append(steps, ScenarioStep{
			TaskID:       TaskID(techniqueID, ab.Name),
			TechniqueID:  techniqueID,
			Name:         ab.Name,
			Framework:    "caldera",
			Executor:     "powershell",
			Command:      cmd,
			TimeoutSec:   60,
			Fidelity:     calderaStepFidelity(*ab),
			RequiresPriv: mapCalderaElevation(ab.Privilege).Effective(),
		})
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf(
			"none of the %d ability IDs in caldera_abilities had a Windows executor in your Caldera instance. "+
```

- [ ] **Step 5: Populate `RequiresPriv` in `buildCalderaAllWindowsSteps`**

The literal inside `buildCalderaAllWindowsSteps` — identified by its surrounding error message `"caldera returned no abilities with a Windows executor"`:

```go
		steps = append(steps, ScenarioStep{
			TaskID:      TaskID(techniqueID, ab.Name),
			TechniqueID: techniqueID,
			Name:        ab.Name,
			Framework:   "caldera",
			Executor:    "powershell",
			Command:     cmd,
			TimeoutSec:  60,
			Fidelity:    calderaStepFidelity(ab),
		})
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("caldera returned no abilities with a Windows executor")
```

becomes:

```go
		steps = append(steps, ScenarioStep{
			TaskID:       TaskID(techniqueID, ab.Name),
			TechniqueID:  techniqueID,
			Name:         ab.Name,
			Framework:    "caldera",
			Executor:     "powershell",
			Command:      cmd,
			TimeoutSec:   60,
			Fidelity:     calderaStepFidelity(ab),
			RequiresPriv: mapCalderaElevation(ab.Privilege).Effective(),
		})
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("caldera returned no abilities with a Windows executor")
```

(Note the field is `calderaStepFidelity(ab)` without a `*` here — this literal is inside `buildCalderaAllWindowsSteps`, which ranges over `[]calderaAbilityFull` by value, unlike the other two which range over ability IDs and hold a `*calderaAbilityFull` pointer from `fetchCalderaAbilityFull`. Match whichever form is already present at each site — only add the `RequiresPriv` line, don't change the `Fidelity` line's existing pointer/value form.)

- [ ] **Step 6: Run gofmt to fix struct literal column alignment**

Run: `cd orchestrator && gofmt -w internal/scenario/builder.go`
(The struct literals above show manually-aligned columns for readability in this plan; gofmt will re-align them correctly regardless of the exact whitespace typed.)

- [ ] **Step 7: Run the new test to verify it passes**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestBuildCalderaAllWindowsStepsSetsRequiresPriv -v`
Expected: PASS.

- [ ] **Step 8: Run the full existing Caldera test suite to confirm no regression**

Run: `cd orchestrator && go test ./internal/scenario/... -run 'TestCalderaStepFidelity|TestFullSweepTagsPayloadAbilityLabOnly|TestBuildCalderaAllWindowsStepsSetsFidelity|TestBuildCalderaAllWindowsStepsSetsRequiresPriv|TestMapCalderaElevation' -v`
Expected: all 5 tests PASS, including the 3 pre-existing ones (regression check).

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/scenario/builder.go orchestrator/internal/scenario/caldera_fidelity_test.go
git commit -m "feat(caldera): wire privilege mapping into all three ScenarioStep builders"
git push
```

---

### Task 3: Full verification

**Files:** none — verification only.

- [ ] **Step 1: Full build/vet/gofmt**

Run: `cd orchestrator && go build ./... && go vet ./... && gofmt -l internal/scenario/builder.go internal/scenario/caldera_fidelity_test.go`
Expected: build/vet clean; `gofmt -l` prints nothing.

- [ ] **Step 2: Full `internal/scenario` suite**

Run: `cd orchestrator && go test ./internal/scenario/... -v 2>&1 | tail -30`
Expected: all PASS, no failures — this package is unit-tests-only (no testcontainers), so the run is fast (a few seconds).

- [ ] **Step 3: Optional — confirm against the live Caldera instance from today's session**

If the `caldera-verify` container from this session's schema-verification work is still running (`docker ps --filter name=caldera-verify`), this is a chance to confirm the fix against real, non-mocked data with zero additional setup. This step is a manual sanity check, not a committed test — do not add a test that depends on a live Docker container, since CI won't have one; the committed tests from Tasks 1-2 already cover this with `httptest.NewServer` mocks.

Using the real API key discovered earlier this session (`docker exec caldera-verify cat conf/local.yml | grep api_key_red` if it needs re-checking), fetch a known-elevated ability and confirm the platform's mapping would produce `"admin"`:

```bash
curl -s -H "KEY: <the real key>" "http://localhost:8888/api/v2/abilities/fcf71ee3-d1a9-4136-b919-9e5f6da43608" | python -c "
import json, sys
d = json.load(sys.stdin)
print('privilege field:', repr(d['privilege']))
print('expected mapped tier: admin' if d['privilege'] == 'Elevated' else 'expected mapped tier: user')
"
```

Expected: `privilege field: 'Elevated'`, confirming the exact value this fix's `mapCalderaElevation` switches on is still what a real Caldera instance returns.

Clean up the verification container when done (not needed for anything else this session):

```bash
docker rm -f caldera-verify
docker rmi ghcr.io/mitre/caldera:latest
```

- [ ] **Step 4: Report results to the user**

Summarize: test results (all green), confirmation the fix is verified against real Caldera data (not just mocks), and note that — unlike ART — this fix has zero rollout lag: it takes effect on the very next scenario build/dispatch that fetches Caldera abilities, no restart-triggered reimport needed, matching Caldera's live-fetch architecture.
