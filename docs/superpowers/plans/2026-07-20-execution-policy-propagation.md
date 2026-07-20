# Campaign-Wide ExecutionPolicy Propagation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator set an `ExecutionPolicy` (starting with `MaxPrivilege`) from any of five launch surfaces — `RunScenario`, `CreateCampaign`, `RunAdversaryTemplate`, `RunCalderaAdversary`, and the Exercise Engine's `agent_task` steps — and have it enforced by the dispatch-time filtering that already exists in `dispatchRun`, with zero duplication of that filtering logic.

**Architecture:** A new `scenario.ExecutionPolicy{MaxPrivilege string}` type is unwrapped into the already-shipped `dispatchOpts.MaxPrivilege string` field at each of the five call sites. `dispatchRun`, the skip-synthesis helper, and the `SubmitScenarioResult` merge (all built in the prior MaxPrivilege plan) require no changes — they already operate purely on `dispatchOpts.MaxPrivilege`. The Exercise Engine is the one structurally different path: policy must be persisted on the `exercise.Execution` row at creation time (since launch is a separate, bodyless call) and threaded through an extended `AgentDispatchFn` callback signature when the executor later fires an `agent_task` step.

**Tech Stack:** Go, Postgres (`pgx/v5`), the existing `internal/scenario`/`internal/api`/`internal/exercise`/`internal/db` packages.

## Global Constraints

- **Wire shape:** every request body uses a nested `executionPolicy: {maxPrivilege: "..."}` object (camelCase, matching `internal/api`'s existing JSON convention), except the Exercise Engine's `CreateExerciseExecution`, which uses `execution_policy: {maxPrivilege: "..."}` (snake_case, matching `internal/exercise`'s existing wire convention — e.g. `plan_id`, `agent_id`). This is a deliberate per-package match to existing local convention, not an inconsistency.
- **`RunScenario`'s flat `maxPrivilege` field is renamed, not deprecated.** It shipped hours before this plan with zero consumers (no frontend code reads it) — this is a free rename, not a breaking change requiring back-compat handling.
- **No new validation.** An unrecognized `MaxPrivilege` value behaves exactly as today: `scenario.PrivilegeExceeds` treats unknown tiers as rank 0 (lowest), so it never filters anything. This plan does not add tier-value validation anywhere.
- **`ExecutionPolicy` has exactly one field today** (`MaxPrivilege`). It is a deliberate extension point for future constraints, but do not add placeholder fields for constraints that don't exist yet.
- **No changes to reporting, coverage math, or `SubmitScenarioResult`.** Those are separate, already-deferred follow-ups (see `docs/superpowers/specs/2026-07-20-execution-policy-propagation-design.md`, Non-goals).
- Run all `go` commands from `orchestrator/`. Docker Desktop must be running for container-backed tests (`docker info` to check; start manually if needed — see `project_docker_windows` memory).

---

### Task 1: `scenario.ExecutionPolicy` core type

**Files:**
- Modify: `orchestrator/internal/scenario/types.go` (add `ExecutionPolicy` after `PrivilegeExceeds`)
- Modify: `orchestrator/internal/scenario/types_test.go` (existing file — add a test)

**Interfaces:**
- Produces: `scenario.ExecutionPolicy{MaxPrivilege string}` — consumed by every other task in this plan.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/scenario/types_test.go`:

```go
func TestExecutionPolicyJSONRoundTrip(t *testing.T) {
	in := ExecutionPolicy{MaxPrivilege: "user"}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(raw) != `{"maxPrivilege":"user"}` {
		t.Errorf("marshal = %s, want {\"maxPrivilege\":\"user\"}", raw)
	}
	var out ExecutionPolicy
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Errorf("round-trip = %+v, want %+v", out, in)
	}

	empty, _ := json.Marshal(ExecutionPolicy{})
	if string(empty) != `{}` {
		t.Errorf("empty policy marshal = %s, want {} (omitempty)", empty)
	}
}
```

This test needs `encoding/json` imported. Update the import block at the top of the file:

```go
package scenario

import (
	"encoding/json"
	"testing"
)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestExecutionPolicyJSONRoundTrip -v`
Expected: FAIL — `undefined: ExecutionPolicy` (compile error).

- [ ] **Step 3: Add `ExecutionPolicy` to `types.go`**

In `orchestrator/internal/scenario/types.go`, immediately after the closing `}` of `func PrivilegeExceeds(stepTier, maxTier string) bool { ... }`, add:

```go

// ExecutionPolicy carries operator-set execution constraints for a dispatch
// request. Today it has one field; it's the deliberate extension point for
// future constraints (NetworkIsolation, AllowReboot, etc.) without another
// wire-format change.
type ExecutionPolicy struct {
	MaxPrivilege string `json:"maxPrivilege,omitempty"`
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/scenario/... -v`
Expected: PASS, including `TestExecutionPolicyJSONRoundTrip` and every pre-existing test in the package (regression check).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/scenario/types.go orchestrator/internal/scenario/types_test.go
git commit -m "feat(policy): add scenario.ExecutionPolicy core type"
git push
```

---

### Task 2: `RunScenario` — nested `executionPolicy`

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`RunScenario`'s request struct and `dispatchOpts{}` construction)
- Modify: `orchestrator/internal/api/run_scenario_integration_test.go` (existing file — update the two MaxPrivilege tests' request bodies)

**Interfaces:**
- Consumes: `scenario.ExecutionPolicy` (Task 1).
- Produces: nothing new — `dispatchOpts.MaxPrivilege` (already exists) is now populated from `req.ExecutionPolicy.MaxPrivilege` instead of a flat `req.MaxPrivilege`.

- [ ] **Step 1: Update the two existing tests to use the nested shape**

In `orchestrator/internal/api/run_scenario_integration_test.go`, both `TestRunScenarioIntegration_MaxPrivilegeFiltersStep` and `TestRunScenarioIntegration_MaxPrivilegeAllFilteredCompletesImmediately` currently send:

```go
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true, "maxPrivilege": "user",
		}))
```

This exact block appears twice, byte-identical. Replace **both** occurrences with:

```go
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true,
			"executionPolicy": map[string]any{"maxPrivilege": "user"},
		}))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestRunScenarioIntegration_MaxPrivilege' -v`
Expected: FAIL — the request now sends `executionPolicy` but the handler still only reads the old flat `maxPrivilege` field, so nothing gets filtered (both tests' assertions fail the same way they did before the original MaxPrivilege plan's Task 3 shipped).

- [ ] **Step 3: Replace the flat field with the nested one**

In `orchestrator/internal/api/handlers.go`, `RunScenario`'s request struct currently ends with:

```go
		RunLabel     string                `json:"runLabel"`     // optional override for scenario_runs.name
		MaxPrivilege string                `json:"maxPrivilege"` // ""|"user"|"admin"|"system" — execution policy ceiling
	}
```

Replace with:

```go
		RunLabel        string                   `json:"runLabel"`        // optional override for scenario_runs.name
		ExecutionPolicy scenario.ExecutionPolicy `json:"executionPolicy,omitempty"` // operator-set execution constraints (e.g. maxPrivilege)
	}
```

Then find the `dispatchOpts{}` construction:

```go
	runID, skip, err := h.dispatchRun(r.Context(), sc, req.AgentID, dispatchOpts{
		Mode: mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab, Reason: req.Reason,
		Techniques: req.Techniques, Abilities: req.Abilities, Steps: req.Steps, Checks: req.Checks,
		InitiatedBy: initiatedBy, VariantDepth: req.VariantDepth, RunLabel: req.RunLabel,
		MaxPrivilege: req.MaxPrivilege,
	})
```

Change the last field to read from the nested policy:

```go
	runID, skip, err := h.dispatchRun(r.Context(), sc, req.AgentID, dispatchOpts{
		Mode: mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab, Reason: req.Reason,
		Techniques: req.Techniques, Abilities: req.Abilities, Steps: req.Steps, Checks: req.Checks,
		InitiatedBy: initiatedBy, VariantDepth: req.VariantDepth, RunLabel: req.RunLabel,
		MaxPrivilege: req.ExecutionPolicy.MaxPrivilege,
	})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestRunScenarioIntegration_MaxPrivilege' -v`
Expected: both PASS.

- [ ] **Step 5: Run the full existing dispatch/run suite to confirm no regression**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestRunScenarioIntegration|TestClassifyAgentOS' -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/run_scenario_integration_test.go
git commit -m "feat(policy): RunScenario accepts nested executionPolicy instead of flat maxPrivilege"
git push
```

---

### Task 3: `CreateCampaign`

**Files:**
- Modify: `orchestrator/internal/api/campaign_handlers.go` (import, request struct, `dispatchOpts{}` construction, `subset` persistence)
- Modify: `orchestrator/internal/api/campaign_crud_test.go` (existing file — add a test)

**Interfaces:**
- Consumes: `scenario.ExecutionPolicy` (Task 1).
- Produces: nothing new — `dispatchOpts.MaxPrivilege` is populated once and reused for the whole per-agent fan-out.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/campaign_crud_test.go`, after `TestCreateCampaign_FanOutDispatchedAndSkipped`:

```go
func TestCreateCampaign_ExecutionPolicyFiltersStep(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "user-step", TechniqueID: "T1059", Framework: "custom", Command: "echo user",
				RequiresPriv: scenario.PrivSpec{Minimum: "user"}},
			{Name: "admin-step", TechniqueID: "T1548", Framework: "custom", Command: "echo admin",
				RequiresPriv: scenario.PrivSpec{Minimum: "admin"}},
		}
		sc, engine := minimalLiveScenario(t, "cc-execpolicy-sc", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "cc-execpolicy-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.CreateCampaign(rec, createCampaignReq(map[string]any{
			"name": "ExecPolicy Campaign", "scenarioId": sc.ID, "agentIds": []string{agentID},
			"mode": "telemetry", "confirmLive": true,
			"executionPolicy": map[string]any{"maxPrivilege": "user"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(cmd.Steps) != 1 || cmd.Steps[0].Name != "user-step" {
			t.Fatalf("cmd.Steps = %+v, want exactly [user-step] (admin-step must be filtered)", cmd.Steps)
		}

		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		campID, _ := out["campaignId"].(string)
		if campID == "" {
			t.Fatal("campaignId missing from response")
		}

		var skippedJSON, subsetJSON []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT sr.policy_skipped_results, c.subset
			   FROM scenario_runs sr JOIN campaigns c ON c.id = sr.campaign_id
			  WHERE sr.campaign_id=$1 AND sr.agent_id=$2`,
			campID, agentID,
		).Scan(&skippedJSON, &subsetJSON); err != nil {
			t.Fatalf("query policy_skipped_results/subset: %v", err)
		}
		var skipped []models.SimulationResult
		if err := json.Unmarshal(skippedJSON, &skipped); err != nil {
			t.Fatalf("unmarshal policy_skipped_results: %v", err)
		}
		if len(skipped) != 1 || skipped[0].SkipReason != models.SkipReasonPolicyPrivilege {
			t.Fatalf("policy_skipped_results = %+v, want 1 policy-privilege skip", skipped)
		}

		var subset map[string]any
		json.Unmarshal(subsetJSON, &subset)
		ep, _ := subset["executionPolicy"].(map[string]any)
		if ep["maxPrivilege"] != "user" {
			t.Fatalf("campaigns.subset executionPolicy = %+v, want maxPrivilege=user", subset)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestCreateCampaign_ExecutionPolicyFiltersStep -v`
Expected: FAIL — compile error (`req.ExecutionPolicy` / `executionPolicy` unused key is fine at compile time since it's a `map[string]any`, but `cmd.Steps` will contain both steps since nothing is filtered yet, and the `subset` query will find no `executionPolicy` key).

- [ ] **Step 3: Add the import**

In `orchestrator/internal/api/campaign_handlers.go`, the current import block:

```go
import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/campaign"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting"
	"github.com/go-chi/chi/v5"
)
```

becomes:

```go
import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/campaign"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/scenario"
	"github.com/go-chi/chi/v5"
)
```

- [ ] **Step 4: Add the field to the request struct**

The current request struct in `CreateCampaign`:

```go
	var req struct {
		Name        string   `json:"name"`
		ScenarioID  string   `json:"scenarioId"`
		AgentIDs    []string `json:"agentIds"`
		Mode        string   `json:"mode"`
		ConfirmLive bool     `json:"confirmLive"`
		ConfirmLab  bool     `json:"confirmLab"`
		Reason      string   `json:"reason"`
		Techniques  []string `json:"techniques"`
		Abilities   []string `json:"abilities"`
		Steps       []int    `json:"steps"`
		Checks      []string `json:"checks"`
		Notes       string   `json:"notes"`
		Tags        []string `json:"tags"`
	}
```

becomes:

```go
	var req struct {
		Name            string                   `json:"name"`
		ScenarioID      string                   `json:"scenarioId"`
		AgentIDs        []string                 `json:"agentIds"`
		Mode            string                   `json:"mode"`
		ConfirmLive     bool                     `json:"confirmLive"`
		ConfirmLab      bool                     `json:"confirmLab"`
		Reason          string                   `json:"reason"`
		Techniques      []string                 `json:"techniques"`
		Abilities       []string                 `json:"abilities"`
		Steps           []int                    `json:"steps"`
		Checks          []string                 `json:"checks"`
		Notes           string                   `json:"notes"`
		Tags            []string                 `json:"tags"`
		ExecutionPolicy scenario.ExecutionPolicy `json:"executionPolicy,omitempty"`
	}
```

- [ ] **Step 5: Wire it into `dispatchOpts` and into the persisted `subset`**

The current `dispatchOpts{}` construction:

```go
	opts := dispatchOpts{
		Mode: mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab, Reason: req.Reason,
		Techniques: req.Techniques, Abilities: req.Abilities, Steps: req.Steps, Checks: req.Checks,
		CampaignID: id, InitiatedBy: initiatedBy,
	}
```

becomes:

```go
	opts := dispatchOpts{
		Mode: mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab, Reason: req.Reason,
		Techniques: req.Techniques, Abilities: req.Abilities, Steps: req.Steps, Checks: req.Checks,
		CampaignID: id, InitiatedBy: initiatedBy, MaxPrivilege: req.ExecutionPolicy.MaxPrivilege,
	}
```

The current `subset` marshal:

```go
	subset, _ := json.Marshal(map[string]any{
		"techniques": req.Techniques, "abilities": req.Abilities, "steps": req.Steps, "checks": req.Checks,
	})
```

becomes:

```go
	subset, _ := json.Marshal(map[string]any{
		"techniques": req.Techniques, "abilities": req.Abilities, "steps": req.Steps, "checks": req.Checks,
		"executionPolicy": req.ExecutionPolicy,
	})
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestCreateCampaign_ExecutionPolicyFiltersStep -v`
Expected: PASS.

- [ ] **Step 7: Run the full campaign suite to confirm no regression**

Run: `cd orchestrator && go test ./internal/api/... -run TestCreateCampaign -v`
Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/campaign_handlers.go orchestrator/internal/api/campaign_crud_test.go
git commit -m "feat(policy): CreateCampaign accepts and persists executionPolicy"
git push
```

---

### Task 4: `RunAdversaryTemplate`

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`RunAdversaryTemplate`'s request struct and `base := dispatchOpts{...}`)
- Test: `orchestrator/internal/api/adversary_template_test.go` (new file)

**Interfaces:**
- Consumes: `scenario.ExecutionPolicy` (Task 1).
- Produces: nothing new — `base.MaxPrivilege` is populated once and inherited by all three of the handler's dispatch branches (BAS, ART, Caldera-adversary), since each derives its `dispatchOpts` from `base`.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/api/adversary_template_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func runAdversaryTemplateReq(id string, body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return withURLParam(httptest.NewRequest(http.MethodPost, "/api/adversary-templates/"+id+"/run", bytes.NewReader(b)), "id", id)
}

// TestRunAdversaryTemplate_ExecutionPolicyFiltersStep uses the built-in
// "apt29-quick" template, whose BASScenarioID is "apt29-kill-chain" — a
// scenario is registered under that exact ID so the template's BAS branch
// resolves it via h.engine.Get, without needing a real ART store or Caldera.
func TestRunAdversaryTemplate_ExecutionPolicyFiltersStep(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "user-step", TechniqueID: "T1059", Framework: "custom", Command: "echo user",
				RequiresPriv: scenario.PrivSpec{Minimum: "user"}},
			{Name: "admin-step", TechniqueID: "T1548", Framework: "custom", Command: "echo admin",
				RequiresPriv: scenario.PrivSpec{Minimum: "admin"}},
		}
		_, engine := minimalLiveScenario(t, "apt29-kill-chain", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "rat-execpolicy-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunAdversaryTemplate(rec, runAdversaryTemplateReq("apt29-quick", map[string]any{
			"agentId": agentID, "mode": "telemetry", "useBas": true,
			"executionPolicy": map[string]any{"maxPrivilege": "user"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(cmd.Steps) != 1 || cmd.Steps[0].Name != "user-step" {
			t.Fatalf("cmd.Steps = %+v, want exactly [user-step] (admin-step must be filtered)", cmd.Steps)
		}

		var out struct {
			Dispatched []struct {
				Source string `json:"source"`
				RunID  string `json:"runId"`
			} `json:"dispatched"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out.Dispatched) != 1 || out.Dispatched[0].RunID == "" {
			t.Fatalf("out = %+v, want exactly 1 dispatched entry with a runId", out)
		}

		var skippedJSON []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT policy_skipped_results FROM scenario_runs WHERE id=$1`, out.Dispatched[0].RunID,
		).Scan(&skippedJSON); err != nil {
			t.Fatalf("query policy_skipped_results: %v", err)
		}
		var skipped []models.SimulationResult
		if err := json.Unmarshal(skippedJSON, &skipped); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(skipped) != 1 || skipped[0].SkipReason != models.SkipReasonPolicyPrivilege {
			t.Fatalf("policy_skipped_results = %+v, want 1 policy-privilege skip", skipped)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestRunAdversaryTemplate_ExecutionPolicyFiltersStep -v`
Expected: FAIL — `cmd.Steps` has 2 entries, not 1 (nothing is filtered yet).

- [ ] **Step 3: Add the field and wire it into `base`**

The current request struct in `RunAdversaryTemplate`:

```go
	var req struct {
		AgentID            string `json:"agentId"`
		Mode               string `json:"mode"`
		ConfirmLive        bool   `json:"confirmLive"`
		ConfirmLab         bool   `json:"confirmLab"`
		Reason             string `json:"reason"`
		UseBAS             bool   `json:"useBas"`
		UseART             bool   `json:"useArt"`
		CalderaAdversaryID string `json:"calderaAdversaryId"` // frontend resolves name→UUID
	}
```

becomes:

```go
	var req struct {
		AgentID            string                   `json:"agentId"`
		Mode               string                   `json:"mode"`
		ConfirmLive        bool                     `json:"confirmLive"`
		ConfirmLab         bool                     `json:"confirmLab"`
		Reason             string                   `json:"reason"`
		UseBAS             bool                     `json:"useBas"`
		UseART             bool                     `json:"useArt"`
		CalderaAdversaryID string                   `json:"calderaAdversaryId"` // frontend resolves name→UUID
		ExecutionPolicy    scenario.ExecutionPolicy `json:"executionPolicy,omitempty"`
	}
```

The current `base := dispatchOpts{...}`:

```go
	base := dispatchOpts{
		Mode: req.Mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab,
		Reason: req.Reason, InitiatedBy: uid,
	}
```

becomes:

```go
	base := dispatchOpts{
		Mode: req.Mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab,
		Reason: req.Reason, InitiatedBy: uid, MaxPrivilege: req.ExecutionPolicy.MaxPrivilege,
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestRunAdversaryTemplate_ExecutionPolicyFiltersStep -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/adversary_template_test.go
git commit -m "feat(policy): RunAdversaryTemplate accepts executionPolicy, shared by all 3 dispatch branches"
git push
```

---

### Task 5: `RunCalderaAdversary`

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`RunCalderaAdversary`'s request struct and `dispatchOpts{}` construction)
- Test: `orchestrator/internal/api/caldera_adversary_test.go` (new file)

**Interfaces:**
- Consumes: `scenario.ExecutionPolicy` (Task 1).
- Produces: nothing new.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/api/caldera_adversary_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fakeCalderaServer stubs the two Caldera endpoints buildCalderaAdversarySteps
// needs: GET /api/v2/adversaries/{id} (atomic_ordering) and
// GET /api/v2/abilities/{id} (per-ability detail, including privilege).
func fakeCalderaServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/adversaries/adv-1":
			_, _ = w.Write([]byte(`{"adversary_id":"adv-1","name":"Test Adversary","atomic_ordering":["a1","a2"]}`))
		case "/api/v2/abilities/a1":
			_, _ = w.Write([]byte(`{"ability_id":"a1","name":"user-ability","technique_id":"T1059","tactic":"execution","privilege":"",
				"executors":[{"platform":"windows","name":"psh","command":"echo user"}]}`))
		case "/api/v2/abilities/a2":
			_, _ = w.Write([]byte(`{"ability_id":"a2","name":"admin-ability","technique_id":"T1548","tactic":"privilege-escalation","privilege":"Elevated",
				"executors":[{"platform":"windows","name":"psh","command":"echo admin"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runCalderaAdversaryReq(adversaryID string, body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return withURLParam(httptest.NewRequest(http.MethodPost, "/api/caldera/adversaries/"+adversaryID+"/run", bytes.NewReader(b)), "adversaryId", adversaryID)
}

func TestRunCalderaAdversary_ExecutionPolicyFiltersStep(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := fakeCalderaServer(t)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithCaldera(srv.URL, "")
		agentID := "rca-execpolicy-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunCalderaAdversary(rec, runCalderaAdversaryReq("adv-1", map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true,
			"executionPolicy": map[string]any{"maxPrivilege": "user"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(cmd.Steps) != 1 || cmd.Steps[0].Name != "user-ability" {
			t.Fatalf("cmd.Steps = %+v, want exactly [user-ability] (admin-ability must be filtered)", cmd.Steps)
		}

		var out struct {
			RunID string `json:"runId"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.RunID == "" {
			t.Fatal("response missing runId")
		}

		var skippedJSON []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT policy_skipped_results FROM scenario_runs WHERE id=$1`, out.RunID,
		).Scan(&skippedJSON); err != nil {
			t.Fatalf("query policy_skipped_results: %v", err)
		}
		var skipped []models.SimulationResult
		if err := json.Unmarshal(skippedJSON, &skipped); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(skipped) != 1 || skipped[0].SkipReason != models.SkipReasonPolicyPrivilege {
			t.Fatalf("policy_skipped_results = %+v, want 1 policy-privilege skip", skipped)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestRunCalderaAdversary_ExecutionPolicyFiltersStep -v`
Expected: FAIL — `cmd.Steps` has 2 entries, not 1.

- [ ] **Step 3: Add the field and wire it in**

The current request struct in `RunCalderaAdversary`:

```go
	var req struct {
		AgentID     string `json:"agentId"`
		Mode        string `json:"mode"`
		ConfirmLive bool   `json:"confirmLive"`
		ConfirmLab  bool   `json:"confirmLab"`
		Reason      string `json:"reason"`
	}
```

becomes:

```go
	var req struct {
		AgentID         string                   `json:"agentId"`
		Mode            string                   `json:"mode"`
		ConfirmLive     bool                     `json:"confirmLive"`
		ConfirmLab      bool                     `json:"confirmLab"`
		Reason          string                   `json:"reason"`
		ExecutionPolicy scenario.ExecutionPolicy `json:"executionPolicy,omitempty"`
	}
```

The current `dispatchOpts{}` construction:

```go
	runID, skipReason, err := h.dispatchRun(r.Context(), synthSc, req.AgentID, dispatchOpts{
		Mode: mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab,
		Reason: req.Reason, InitiatedBy: initiatedBy,
	})
```

becomes:

```go
	runID, skipReason, err := h.dispatchRun(r.Context(), synthSc, req.AgentID, dispatchOpts{
		Mode: mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab,
		Reason: req.Reason, InitiatedBy: initiatedBy, MaxPrivilege: req.ExecutionPolicy.MaxPrivilege,
	})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestRunCalderaAdversary_ExecutionPolicyFiltersStep -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/caldera_adversary_test.go
git commit -m "feat(policy): RunCalderaAdversary accepts executionPolicy"
git push
```

---

### Task 6: Exercise Engine

**Files:**
- Modify: `orchestrator/internal/exercise/types.go` (import, `Execution` struct, `AgentDispatchFn` signature)
- Modify: `orchestrator/internal/exercise/store.go` (`CreateExecution`, `GetExecution`, `ListExecutions`, `ListRunningExecutions`)
- Modify: `orchestrator/internal/exercise/executor.go` (`handleAgentTask`'s dispatch call)
- Modify: `orchestrator/internal/api/handlers.go` (`WithExercise`'s `SetDispatch` closure)
- Modify: `orchestrator/internal/api/exercise_handlers.go` (import, `CreateExerciseExecution`)
- Modify: `orchestrator/internal/db/exercise_schema.go` (new column)
- Modify: `orchestrator/internal/exercise/handlers_test.go` (fix the one pre-existing test using the old `AgentDispatchFn` signature)
- Test: `orchestrator/internal/exercise/executor_test.go` (existing file — add a test)
- Test: `orchestrator/internal/api/exercise_execution_test.go` (new file)

**Interfaces:**
- Consumes: `scenario.ExecutionPolicy` (Task 1).
- Produces: `exercise.Execution.ExecutionPolicy scenario.ExecutionPolicy`. `exercise.AgentDispatchFn` becomes `func(agentID, scenarioID, techniqueID string, policy scenario.ExecutionPolicy) (runID string, err error)`.

**Why this is one task, not several:** the `AgentDispatchFn` signature change is a single atomic Go type change — every file that references it (`executor.go`'s call site, `handlers.go`'s closure, `handlers_test.go`'s stub) must change together or the package won't compile. There is no way to split this across separately-committable tasks without leaving the build broken in between.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/exercise/executor_test.go` (needs `scenario` added to the existing import block — the current block is `"context"`, `"testing"`, `"time"`, `"github.com/jackc/pgx/v5/pgxpool"`; add `"github.com/audspect/bas/internal/scenario"` to it):

```go
func TestHandleAgentTask_PassesExecutionPolicyThroughDispatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.RegisterBuiltins(nil, nil, nil, nil)
		received := make(chan scenario.ExecutionPolicy, 1)
		e.SetDispatch(func(agentID, scenarioID, techniqueID string, policy scenario.ExecutionPolicy) (string, error) {
			received <- policy
			return "run-1", nil
		})

		ctx := context.Background()
		p := &Plan{Name: "P", Steps: []PlanStep{
			{ID: "at", Type: StepTypeAgentTask, Config: StepConfig{AgentTask: &AgentTaskConfig{AgentID: "agent-1", ScenarioID: "sc-1"}}},
		}}
		if err := store.CreatePlan(ctx, p); err != nil {
			t.Fatalf("CreatePlan: %v", err)
		}
		ex := &Execution{PlanID: p.ID, Name: "R", Status: ExecDraft, ExecutionPolicy: scenario.ExecutionPolicy{MaxPrivilege: "user"}}
		if err := store.CreateExecution(ctx, ex); err != nil {
			t.Fatalf("CreateExecution: %v", err)
		}
		if err := e.LaunchExecution(ctx, ex.ID); err != nil {
			t.Fatalf("LaunchExecution: %v", err)
		}
		got, err := store.GetExecution(ctx, ex.ID)
		if err != nil {
			t.Fatalf("GetExecution: %v", err)
		}
		if got.ExecutionPolicy.MaxPrivilege != "user" {
			t.Fatalf("ExecutionPolicy did not survive persist/reload: got %+v", got.ExecutionPolicy)
		}
		if err := e.advance(ctx, got); err != nil {
			t.Fatalf("advance: %v", err)
		}

		select {
		case policy := <-received:
			if policy.MaxPrivilege != "user" {
				t.Fatalf("dispatch received MaxPrivilege = %q, want user", policy.MaxPrivilege)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for dispatch to be called")
		}
	})
}
```

Create `orchestrator/internal/api/exercise_execution_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func exerciseExecutionReq(body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/exercises/executions", bytes.NewReader(b))
}

// TestExerciseExecution_ExecutionPolicyPropagatesToBASDispatch proves the
// full async path: an operator-set ExecutionPolicy on a CreateExerciseExecution
// request survives persist → launch → the executor's poll loop → the
// AgentDispatchFn callback → dispatchRun's existing MaxPrivilege filter,
// landing exactly where every other launch path lands. The scenario's one
// step is admin-tier and the policy caps at user, so dispatchRun's existing
// all-filtered-completes-immediately behavior fires — no fake WS agent needed.
func TestExerciseExecution_ExecutionPolicyPropagatesToBASDispatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "admin-step", TechniqueID: "T1548", Framework: "custom", Command: "echo admin",
				RequiresPriv: scenario.PrivSpec{Minimum: "admin"}},
		}
		_, engine := minimalLiveScenario(t, "ee-execpolicy-sc", steps...)

		store := exercise.NewStore(pool)
		chain := exercise.NewEvidenceChain(store)
		reg := exercise.NewRegistry()
		exec := exercise.NewExecutor(store, chain, reg, exercise.NewPollScheduler(50*time.Millisecond), nil)
		exec.RegisterBuiltins(nil, nil, nil, nil)
		exec.RegisterBuiltinTriggers()
		h := New(pool, ws.NewHub(), engine, "").WithExercise(store, exec, chain)
		exec.Start()
		t.Cleanup(exec.Stop)

		planRec := httptest.NewRecorder()
		h.CreateExercisePlan(planRec, exercisePlanReq(map[string]any{
			"name": "Admin Only",
			"steps": []exercise.PlanStep{{
				ID: "at", Type: exercise.StepTypeAgentTask,
				Config: exercise.StepConfig{AgentTask: &exercise.AgentTaskConfig{
					AgentID: "ee-execpolicy-agent", ScenarioID: "ee-execpolicy-sc",
				}},
			}},
		}))
		var plan struct {
			ID string `json:"id"`
		}
		json.Unmarshal(planRec.Body.Bytes(), &plan)
		if plan.ID == "" {
			t.Fatalf("plan create failed: %s", planRec.Body.String())
		}

		execRec := httptest.NewRecorder()
		h.CreateExerciseExecution(execRec, exerciseExecutionReq(map[string]any{
			"plan_id": plan.ID, "name": "Run",
			"execution_policy": map[string]any{"maxPrivilege": "user"},
		}))
		var execOut struct {
			ID string `json:"id"`
		}
		json.Unmarshal(execRec.Body.Bytes(), &execOut)
		if execOut.ID == "" {
			t.Fatalf("execution create failed: %s", execRec.Body.String())
		}

		launchRec := httptest.NewRecorder()
		h.LaunchExerciseExecution(launchRec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", execOut.ID))
		if launchRec.Code != http.StatusOK {
			t.Fatalf("launch: status = %d, body = %s", launchRec.Code, launchRec.Body.String())
		}

		// Poll for the agent_task step to complete and yield a bas_run_id —
		// the poll scheduler's tick fires asynchronously.
		deadline := time.Now().Add(3 * time.Second)
		var runID string
		for time.Now().Before(deadline) {
			se, _ := store.GetStepExecByStepID(context.Background(), execOut.ID, "at")
			if se != nil && se.Status == exercise.StepCompleted {
				if v, ok := se.Result["bas_run_id"].(string); ok {
					runID = v
				}
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if runID == "" {
			t.Fatal("timed out waiting for the agent_task step to complete")
		}

		var status string
		var resultsJSON []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT status, results FROM scenario_runs WHERE id=$1`, runID,
		).Scan(&status, &resultsJSON); err != nil {
			t.Fatalf("query scenario_runs: %v", err)
		}
		if status != "completed" {
			t.Fatalf("status = %q, want completed (all steps filtered by policy)", status)
		}
		var results []models.SimulationResult
		json.Unmarshal(resultsJSON, &results)
		if len(results) != 1 || results[0].SkipReason != models.SkipReasonPolicyPrivilege {
			t.Fatalf("results = %+v, want exactly 1 policy-privilege skip", results)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go build ./... 2>&1 | head -30`
Expected: FAIL — compile errors referencing `ExecutionPolicy` undefined on `Execution`, and the 4-arg `SetDispatch` closure not matching `AgentDispatchFn`'s current 3-arg signature. This is the expected RED state — the rest of this task's steps make it compile and pass.

- [ ] **Step 3: Add the schema column**

In `orchestrator/internal/db/exercise_schema.go`, the current lines:

```go
		`CREATE INDEX IF NOT EXISTS idx_ex_exec_plan   ON exercise_executions(plan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ex_exec_status ON exercise_executions(status)`,
		`ALTER TABLE exercise_executions ADD COLUMN IF NOT EXISTS variables_json jsonb NOT NULL DEFAULT '{}'`,
		`ALTER TABLE exercise_executions ADD COLUMN IF NOT EXISTS plan_version   int NOT NULL DEFAULT 1`,
```

become:

```go
		`CREATE INDEX IF NOT EXISTS idx_ex_exec_plan   ON exercise_executions(plan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ex_exec_status ON exercise_executions(status)`,
		`ALTER TABLE exercise_executions ADD COLUMN IF NOT EXISTS variables_json jsonb NOT NULL DEFAULT '{}'`,
		`ALTER TABLE exercise_executions ADD COLUMN IF NOT EXISTS plan_version   int NOT NULL DEFAULT 1`,
		// execution_policy_json carries the operator-set ExecutionPolicy (e.g.
		// MaxPrivilege) from CreateExerciseExecution through to the executor's
		// AgentDispatchFn callback when an agent_task step fires.
		`ALTER TABLE exercise_executions ADD COLUMN IF NOT EXISTS execution_policy_json jsonb NOT NULL DEFAULT '{}'`,
```

- [ ] **Step 4: Add the field and change the callback signature in `types.go`**

The current import in `orchestrator/internal/exercise/types.go`:

```go
package exercise

import "time"
```

becomes:

```go
package exercise

import (
	"time"

	"github.com/audspect/bas/internal/scenario"
)
```

The current `Execution` struct:

```go
type Execution struct {
	ID          string                 `json:"id"`
	PlanID      string                 `json:"plan_id"`
	Name        string                 `json:"name"`
	Status      ExecStatus             `json:"status"`
	InitiatedBy string                 `json:"initiated_by,omitempty"`
	Targets     []Target               `json:"targets,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	// Variables holds the operator-provided values that override plan defaults.
	// The executor resolves ${VarName} against these before dispatching each step.
	Variables   map[string]string `json:"variables,omitempty"`
	PlanVersion int               `json:"plan_version,omitempty"`
	Score       *ExerciseScore    `json:"score,omitempty"`
	StartedAt   *time.Time        `json:"started_at,omitempty"`
	CompletedAt *time.Time        `json:"completed_at,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}
```

becomes:

```go
type Execution struct {
	ID          string                 `json:"id"`
	PlanID      string                 `json:"plan_id"`
	Name        string                 `json:"name"`
	Status      ExecStatus             `json:"status"`
	InitiatedBy string                 `json:"initiated_by,omitempty"`
	Targets     []Target               `json:"targets,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	// Variables holds the operator-provided values that override plan defaults.
	// The executor resolves ${VarName} against these before dispatching each step.
	Variables   map[string]string `json:"variables,omitempty"`
	PlanVersion int               `json:"plan_version,omitempty"`
	Score       *ExerciseScore    `json:"score,omitempty"`
	// ExecutionPolicy is set at creation time (LaunchExerciseExecution takes no
	// body, so it cannot be set at launch) and read back by the executor when
	// an agent_task step fires, threading it through AgentDispatchFn.
	ExecutionPolicy scenario.ExecutionPolicy `json:"execution_policy,omitempty"`
	StartedAt       *time.Time               `json:"started_at,omitempty"`
	CompletedAt     *time.Time               `json:"completed_at,omitempty"`
	CreatedAt       time.Time                `json:"created_at"`
	UpdatedAt       time.Time                `json:"updated_at"`
}
```

The current `AgentDispatchFn`:

```go
// AgentDispatchFn allows the exercise executor to trigger BAS runs without
// importing the api package (avoids circular dependency).
type AgentDispatchFn func(agentID, scenarioID, techniqueID string) (runID string, err error)
```

becomes:

```go
// AgentDispatchFn allows the exercise executor to trigger BAS runs without
// importing the api package (avoids circular dependency).
type AgentDispatchFn func(agentID, scenarioID, techniqueID string, policy scenario.ExecutionPolicy) (runID string, err error)
```

- [ ] **Step 5: Persist and read back `ExecutionPolicy` in `store.go`**

The current `CreateExecution`:

```go
func (s *Store) CreateExecution(ctx context.Context, e *Execution) error {
	targets, _ := json.Marshal(e.Targets)
	meta, _ := json.Marshal(e.Metadata)
	vars, _ := json.Marshal(e.Variables)
	return s.db.QueryRow(ctx,
		`INSERT INTO exercise_executions (plan_id, name, status, initiated_by, targets_json, metadata_json, variables_json, plan_version)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id, created_at, updated_at`,
		e.PlanID, e.Name, e.Status, e.InitiatedBy, targets, meta, vars, max1(e.PlanVersion),
	).Scan(&e.ID, &e.CreatedAt, &e.UpdatedAt)
}
```

becomes:

```go
func (s *Store) CreateExecution(ctx context.Context, e *Execution) error {
	targets, _ := json.Marshal(e.Targets)
	meta, _ := json.Marshal(e.Metadata)
	vars, _ := json.Marshal(e.Variables)
	policy, _ := json.Marshal(e.ExecutionPolicy)
	return s.db.QueryRow(ctx,
		`INSERT INTO exercise_executions (plan_id, name, status, initiated_by, targets_json, metadata_json, variables_json, plan_version, execution_policy_json)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id, created_at, updated_at`,
		e.PlanID, e.Name, e.Status, e.InitiatedBy, targets, meta, vars, max1(e.PlanVersion), policy,
	).Scan(&e.ID, &e.CreatedAt, &e.UpdatedAt)
}
```

The current `GetExecution`:

```go
func (s *Store) GetExecution(ctx context.Context, id string) (*Execution, error) {
	var e Execution
	var targetsRaw, metaRaw, varsRaw, scoreRaw []byte
	err := s.db.QueryRow(ctx,
		`SELECT id, plan_id, name, status, initiated_by, targets_json, metadata_json,
		        variables_json, plan_version, score_json, started_at, completed_at, created_at, updated_at
		 FROM exercise_executions WHERE id=$1`, id,
	).Scan(&e.ID, &e.PlanID, &e.Name, &e.Status, &e.InitiatedBy,
		&targetsRaw, &metaRaw, &varsRaw, &e.PlanVersion, &scoreRaw,
		&e.StartedAt, &e.CompletedAt, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(targetsRaw, &e.Targets)
	_ = json.Unmarshal(metaRaw, &e.Metadata)
	_ = json.Unmarshal(varsRaw, &e.Variables)
	if len(scoreRaw) > 0 {
		var sc ExerciseScore
		if err := json.Unmarshal(scoreRaw, &sc); err == nil {
			e.Score = &sc
		}
	}
	return &e, nil
}
```

becomes:

```go
func (s *Store) GetExecution(ctx context.Context, id string) (*Execution, error) {
	var e Execution
	var targetsRaw, metaRaw, varsRaw, scoreRaw, policyRaw []byte
	err := s.db.QueryRow(ctx,
		`SELECT id, plan_id, name, status, initiated_by, targets_json, metadata_json,
		        variables_json, plan_version, score_json, started_at, completed_at, created_at, updated_at,
		        execution_policy_json
		 FROM exercise_executions WHERE id=$1`, id,
	).Scan(&e.ID, &e.PlanID, &e.Name, &e.Status, &e.InitiatedBy,
		&targetsRaw, &metaRaw, &varsRaw, &e.PlanVersion, &scoreRaw,
		&e.StartedAt, &e.CompletedAt, &e.CreatedAt, &e.UpdatedAt, &policyRaw)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(targetsRaw, &e.Targets)
	_ = json.Unmarshal(metaRaw, &e.Metadata)
	_ = json.Unmarshal(varsRaw, &e.Variables)
	_ = json.Unmarshal(policyRaw, &e.ExecutionPolicy)
	if len(scoreRaw) > 0 {
		var sc ExerciseScore
		if err := json.Unmarshal(scoreRaw, &sc); err == nil {
			e.Score = &sc
		}
	}
	return &e, nil
}
```

The current `ListExecutions`:

```go
func (s *Store) ListExecutions(ctx context.Context, limit int) ([]Execution, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(ctx,
		`SELECT id, plan_id, name, status, initiated_by, targets_json, metadata_json,
		        variables_json, plan_version, score_json, started_at, completed_at, created_at, updated_at
		 FROM exercise_executions ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Execution
	for rows.Next() {
		var e Execution
		var targetsRaw, metaRaw, varsRaw, scoreRaw []byte
		if err := rows.Scan(&e.ID, &e.PlanID, &e.Name, &e.Status, &e.InitiatedBy,
			&targetsRaw, &metaRaw, &varsRaw, &e.PlanVersion, &scoreRaw,
			&e.StartedAt, &e.CompletedAt, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(targetsRaw, &e.Targets)
		_ = json.Unmarshal(metaRaw, &e.Metadata)
		if len(scoreRaw) > 0 {
			var sc ExerciseScore
			if json.Unmarshal(scoreRaw, &sc) == nil {
				e.Score = &sc
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
```

becomes:

```go
func (s *Store) ListExecutions(ctx context.Context, limit int) ([]Execution, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(ctx,
		`SELECT id, plan_id, name, status, initiated_by, targets_json, metadata_json,
		        variables_json, plan_version, score_json, started_at, completed_at, created_at, updated_at,
		        execution_policy_json
		 FROM exercise_executions ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Execution
	for rows.Next() {
		var e Execution
		var targetsRaw, metaRaw, varsRaw, scoreRaw, policyRaw []byte
		if err := rows.Scan(&e.ID, &e.PlanID, &e.Name, &e.Status, &e.InitiatedBy,
			&targetsRaw, &metaRaw, &varsRaw, &e.PlanVersion, &scoreRaw,
			&e.StartedAt, &e.CompletedAt, &e.CreatedAt, &e.UpdatedAt, &policyRaw); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(targetsRaw, &e.Targets)
		_ = json.Unmarshal(metaRaw, &e.Metadata)
		_ = json.Unmarshal(policyRaw, &e.ExecutionPolicy)
		if len(scoreRaw) > 0 {
			var sc ExerciseScore
			if json.Unmarshal(scoreRaw, &sc) == nil {
				e.Score = &sc
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
```

The current `ListRunningExecutions` (this is the one `tick()` actually uses — critical for the end-to-end test):

```go
func (s *Store) ListRunningExecutions(ctx context.Context) ([]Execution, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, plan_id, name, status, initiated_by, targets_json, metadata_json,
		        variables_json, plan_version, score_json, started_at, completed_at, created_at, updated_at
		 FROM exercise_executions WHERE status IN ('running','paused')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Execution
	for rows.Next() {
		var e Execution
		var targetsRaw, metaRaw, varsRaw, scoreRaw []byte
		if err := rows.Scan(&e.ID, &e.PlanID, &e.Name, &e.Status, &e.InitiatedBy,
			&targetsRaw, &metaRaw, &varsRaw, &e.PlanVersion, &scoreRaw,
			&e.StartedAt, &e.CompletedAt, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(targetsRaw, &e.Targets)
		_ = json.Unmarshal(metaRaw, &e.Metadata)
		_ = json.Unmarshal(varsRaw, &e.Variables)
		out = append(out, e)
	}
	return out, rows.Err()
}
```

becomes:

```go
func (s *Store) ListRunningExecutions(ctx context.Context) ([]Execution, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, plan_id, name, status, initiated_by, targets_json, metadata_json,
		        variables_json, plan_version, score_json, started_at, completed_at, created_at, updated_at,
		        execution_policy_json
		 FROM exercise_executions WHERE status IN ('running','paused')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Execution
	for rows.Next() {
		var e Execution
		var targetsRaw, metaRaw, varsRaw, scoreRaw, policyRaw []byte
		if err := rows.Scan(&e.ID, &e.PlanID, &e.Name, &e.Status, &e.InitiatedBy,
			&targetsRaw, &metaRaw, &varsRaw, &e.PlanVersion, &scoreRaw,
			&e.StartedAt, &e.CompletedAt, &e.CreatedAt, &e.UpdatedAt, &policyRaw); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(targetsRaw, &e.Targets)
		_ = json.Unmarshal(metaRaw, &e.Metadata)
		_ = json.Unmarshal(varsRaw, &e.Variables)
		_ = json.Unmarshal(policyRaw, &e.ExecutionPolicy)
		out = append(out, e)
	}
	return out, rows.Err()
}
```

- [ ] **Step 6: Update the dispatch call site in `executor.go`**

The current call in `handleAgentTask`:

```go
		runID, err := e.dispatch(cfg.AgentID, cfg.ScenarioID, cfg.TechniqueID)
```

becomes:

```go
		runID, err := e.dispatch(cfg.AgentID, cfg.ScenarioID, cfg.TechniqueID, ex.ExecutionPolicy)
```

- [ ] **Step 7: Update `WithExercise`'s closure in `internal/api/handlers.go`**

The current closure:

```go
	exec.SetDispatch(func(agentID, scenarioID, techniqueID string) (string, error) {
		var techniques []string
		if techniqueID != "" {
			techniques = []string{techniqueID}
		}
		opts := dispatchOpts{
			Mode:       "posture",
			Techniques: techniques,
		}
		sc, ok := h.engine.Get(scenarioID)
		if !ok {
			return "", fmt.Errorf("exercise dispatch: scenario %q not found", scenarioID)
		}
		runID, skip, err := h.dispatchRun(context.Background(), sc, agentID, opts)
		if err != nil {
			return "", err
		}
		if skip != "" {
			return "", fmt.Errorf("exercise dispatch: agent skipped (%s)", skip)
		}
		return runID, nil
	})
```

becomes:

```go
	exec.SetDispatch(func(agentID, scenarioID, techniqueID string, policy scenario.ExecutionPolicy) (string, error) {
		var techniques []string
		if techniqueID != "" {
			techniques = []string{techniqueID}
		}
		opts := dispatchOpts{
			Mode:         "posture",
			Techniques:   techniques,
			MaxPrivilege: policy.MaxPrivilege,
		}
		sc, ok := h.engine.Get(scenarioID)
		if !ok {
			return "", fmt.Errorf("exercise dispatch: scenario %q not found", scenarioID)
		}
		runID, skip, err := h.dispatchRun(context.Background(), sc, agentID, opts)
		if err != nil {
			return "", err
		}
		if skip != "" {
			return "", fmt.Errorf("exercise dispatch: agent skipped (%s)", skip)
		}
		return runID, nil
	})
```

- [ ] **Step 8: Add the field to `CreateExerciseExecution` in `internal/api/exercise_handlers.go`**

The current import block:

```go
import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/reporting"
)
```

becomes:

```go
import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/scenario"
)
```

The current `CreateExerciseExecution`:

```go
func (h *Handler) CreateExerciseExecution(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PlanID    string            `json:"plan_id"`
		Name      string            `json:"name"`
		Targets   []exercise.Target `json:"targets"`
		Variables map[string]string `json:"variables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.PlanID == "" {
		jsonError(w, "plan_id required", http.StatusBadRequest)
		return
	}
	plan, err := h.exerciseStore.GetPlan(r.Context(), req.PlanID)
	if err != nil {
		jsonError(w, "plan not found", http.StatusNotFound)
		return
	}
	// Validate required variables are supplied before creating the execution.
	if verr := exercise.ValidateVars(plan.Variables, req.Variables); verr != nil {
		jsonError(w, verr.Error(), http.StatusUnprocessableEntity)
		return
	}
	ex := &exercise.Execution{
		PlanID:      req.PlanID,
		Name:        req.Name,
		Status:      exercise.ExecDraft,
		InitiatedBy: actorID(r),
		Targets:     req.Targets,
		Variables:   req.Variables,
		PlanVersion: plan.Version,
	}
	if err := h.exerciseStore.CreateExecution(r.Context(), ex); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "exercise.execution.create", ex.ID, map[string]any{"plan_id": req.PlanID}, "success")
	respond(w, ex)
}
```

becomes:

```go
func (h *Handler) CreateExerciseExecution(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PlanID          string                   `json:"plan_id"`
		Name            string                   `json:"name"`
		Targets         []exercise.Target        `json:"targets"`
		Variables       map[string]string        `json:"variables"`
		ExecutionPolicy scenario.ExecutionPolicy `json:"execution_policy,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.PlanID == "" {
		jsonError(w, "plan_id required", http.StatusBadRequest)
		return
	}
	plan, err := h.exerciseStore.GetPlan(r.Context(), req.PlanID)
	if err != nil {
		jsonError(w, "plan not found", http.StatusNotFound)
		return
	}
	// Validate required variables are supplied before creating the execution.
	if verr := exercise.ValidateVars(plan.Variables, req.Variables); verr != nil {
		jsonError(w, verr.Error(), http.StatusUnprocessableEntity)
		return
	}
	ex := &exercise.Execution{
		PlanID:          req.PlanID,
		Name:            req.Name,
		Status:          exercise.ExecDraft,
		InitiatedBy:     actorID(r),
		Targets:         req.Targets,
		Variables:       req.Variables,
		PlanVersion:     plan.Version,
		ExecutionPolicy: req.ExecutionPolicy,
	}
	if err := h.exerciseStore.CreateExecution(r.Context(), ex); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "exercise.execution.create", ex.ID, map[string]any{"plan_id": req.PlanID}, "success")
	respond(w, ex)
}
```

- [ ] **Step 9: Fix the pre-existing test using the old `AgentDispatchFn` signature**

In `orchestrator/internal/exercise/handlers_test.go`, add `"github.com/audspect/bas/internal/scenario"` to the import block:

```go
import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/jackc/pgx/v5/pgxpool"
)
```

The current line:

```go
		e.SetDispatch(func(agentID, scenarioID, techniqueID string) (string, error) { return "run-1", nil })
```

becomes:

```go
		e.SetDispatch(func(agentID, scenarioID, techniqueID string, policy scenario.ExecutionPolicy) (string, error) { return "run-1", nil })
```

- [ ] **Step 10: Run the new tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./...`
Expected: clean build (confirms every `AgentDispatchFn` call site now agrees on the new signature).

Run: `cd orchestrator && go test ./internal/exercise/... -run TestHandleAgentTask_PassesExecutionPolicyThroughDispatch -v`
Expected: PASS.

Run: `cd orchestrator && go test ./internal/api/... -run TestExerciseExecution_ExecutionPolicyPropagatesToBASDispatch -v`
Expected: PASS.

- [ ] **Step 11: Run the full exercise suites to confirm no regression**

Run: `cd orchestrator && go test ./internal/exercise/... -v`
Expected: all PASS, including `TestRegisterBuiltinTriggersAndSetDispatch` (the fixed pre-existing test) and every other exercise-package test.

Run: `cd orchestrator && go test ./internal/api/... -run 'TestListExercisePlans|TestGetExercisePlan|TestCreateExercisePlan|TestValidateExercisePlan|TestUpdateExercisePlan|TestDeleteExercisePlan' -v`
Expected: all PASS (regression check on the exercise-plan API tests, which share `exerciseHandler`/`exercisePlanReq`).

- [ ] **Step 12: Commit**

```bash
git add orchestrator/internal/exercise/types.go orchestrator/internal/exercise/store.go orchestrator/internal/exercise/executor.go orchestrator/internal/exercise/executor_test.go orchestrator/internal/exercise/handlers_test.go orchestrator/internal/api/handlers.go orchestrator/internal/api/exercise_handlers.go orchestrator/internal/api/exercise_execution_test.go orchestrator/internal/db/exercise_schema.go
git commit -m "feat(policy): Exercise Engine carries ExecutionPolicy from creation through to agent_task dispatch"
git push
```

---

### Task 7: Full verification

**Files:** none created — `gofmt -w` in Step 1 may reformat files touched by Tasks 2–6.

- [ ] **Step 1: Full build/vet/gofmt**

The struct-literal edits in Tasks 2–6 intentionally leave tag alignment rough rather than hand-aligning columns — run `gofmt -w` to normalize it, then confirm clean:

```bash
cd orchestrator
go build ./...
go vet ./...
gofmt -w internal/scenario/types.go internal/scenario/types_test.go internal/api/handlers.go internal/api/campaign_handlers.go internal/api/exercise_handlers.go internal/exercise/types.go internal/exercise/store.go internal/exercise/executor.go internal/exercise/executor_test.go internal/exercise/handlers_test.go internal/db/exercise_schema.go internal/api/run_scenario_integration_test.go internal/api/campaign_crud_test.go internal/api/adversary_template_test.go internal/api/caldera_adversary_test.go internal/api/exercise_execution_test.go
gofmt -l internal/scenario/types.go internal/scenario/types_test.go internal/api/handlers.go internal/api/campaign_handlers.go internal/api/exercise_handlers.go internal/exercise/types.go internal/exercise/store.go internal/exercise/executor.go internal/exercise/executor_test.go internal/exercise/handlers_test.go internal/db/exercise_schema.go internal/api/run_scenario_integration_test.go internal/api/campaign_crud_test.go internal/api/adversary_template_test.go internal/api/caldera_adversary_test.go internal/api/exercise_execution_test.go
```
Expected: build/vet clean; `gofmt -w` reformats struct-tag alignment in place — commit that formatting fix as part of this task's own commit (do not amend earlier commits); the follow-up `gofmt -l` then prints nothing (or only CRLF-line-ending noise on files this Windows checkout hasn't normalized — confirmed cosmetic-only in prior sessions via `git cat-file`, see `project_docker_windows` memory; do not treat that alone as a real formatting failure).

- [ ] **Step 2: Full `internal/scenario`, `internal/exercise`, and `internal/api` suites**

Run:
```bash
cd orchestrator
go test ./internal/scenario/... -v
go test ./internal/exercise/... -v
go test ./internal/api/... 2>&1 | tail -20
```
Expected: `internal/scenario` and `internal/exercise` fully green. `internal/api` ends with `ok` — this package takes several minutes; if anything unrelated fails, re-run that specific test in isolation before treating it as a real regression (this session's prior full-suite-only flakes in unrelated packages were confirmed non-reproducible in isolation).

- [ ] **Step 3: Commit any gofmt reformatting**

If Step 1's `gofmt -w` changed anything (`git status --short orchestrator/internal`), commit it:

```bash
git add -u orchestrator/internal
git commit -m "chore(policy): gofmt struct-tag alignment"
git push
```

If nothing changed, skip this step.

- [ ] **Step 4: Report results to the user**

Summarize: test results, and note explicitly what's still open per the design spec's Non-goals — reporting `SkipReason` breakdown and the eligible-vs-total coverage split (both separate, already-scoped follow-ups), and that `ExecutionPolicy` still has exactly one field (`MaxPrivilege`) — no other constraints exist yet.
