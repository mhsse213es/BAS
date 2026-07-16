# Exercise Platform Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a synced OpenAEV scenario become a runnable, human-in-the-loop exercise with real SMS/Slack/Teams channels.

**Architecture:** Three additive gap-fills over the existing `internal/exercise` engine: (1) a pure `BuildPlan` bridge in `internal/openaev` that converts a scenario `Detail` into an `exercise.Plan`, exposed via one Admin API endpoint; (2) three new global injectors mirroring the existing `SMTPInjector` pattern, wired through a widened `RegisterBuiltins`; (3) an "Exercises" dashboard tab rendering the existing exercise API, plus a "Create Exercise Plan" button on the OpenAEV scenario drawer. No existing engine behavior changes.

**Tech Stack:** Go 1.26 (garble build), pgx/pgxpool, chi router, vanilla-JS SPA (`wwwroot/index.html`), Docker Compose. Tests: standard `testing` + `httptest`.

## Global Constraints

- **Additive only.** Do not alter existing step semantics, scoring, evidence chain, or Module 1 (OpenAEV) parser/normalizer/store.
- **Garble/reflection:** report HTML renders via json-tag maps, not struct reflection. (Not exercised here, but do not introduce raw-struct `html/template` rendering.)
- **Injector config = global, like SMTP:** channel config via env only; secrets never in the DB.
- **Bridge = structure-preserving skeleton:** uses only `DetailInject{Title, TechniqueIDs}`; no new content captured.
- **Validation chain per task:** `gofmt -w <touched .go files>` → `gofmt -l <touched>` (expect empty) → `go build ./...` → `go vet ./...` → `go test` for the touched package(s). Pre-existing CRLF/LF git warnings on `.go`/`.html` files are expected noise, not regressions. Testcontainers-backed `internal/api` tests need Docker Desktop running.
- **Git push after every commit** (Windows host; user pulls on VM).
- **Two wwwroot copies:** `orchestrator/wwwroot/index.html` and `orchestrator/cmd/server/wwwroot/index.html` are hardlinked/byte-identical; after any UI edit verify both match and `git add` both.
- Run all `go`/`gofmt` commands from `orchestrator/` (module root).

---

### Task 1: OpenAEV → Exercise-Plan bridge (`BuildPlan`)

**Files:**
- Create: `orchestrator/internal/openaev/bridge.go`
- Test: `orchestrator/internal/openaev/bridge_test.go`

**Interfaces:**
- Consumes: `openaev.Scenario` (has `.Name`), `openaev.Detail{Description, Injects []DetailInject{Title, TechniqueIDs []string}, Variables []DetailVariable{Key, Description}}`; `exercise.Plan`, `exercise.PlanStep`, `exercise.StepConfig`, `exercise.AgentTaskConfig`, `exercise.VarDef`, `exercise.StepTypeAgentTask`, `exercise.StepTypeApproval`, `exercise.VarTypeString`.
- Produces: `func BuildPlan(s Scenario, d Detail) exercise.Plan`

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/openaev/bridge_test.go`:

```go
package openaev

import (
	"testing"

	"github.com/audspect/bas/internal/exercise"
)

func TestBuildPlan_TechniqueInjectBecomesAgentTask(t *testing.T) {
	plan := BuildPlan(
		Scenario{Name: "Test Scenario"},
		Detail{Description: "desc", Injects: []DetailInject{{Title: "Recon", TechniqueIDs: []string{"T1046"}}}},
	)
	if plan.Name != "Test Scenario" || plan.Description != "desc" {
		t.Fatalf("name/desc not copied: %+v", plan)
	}
	if len(plan.Steps) != 1 {
		t.Fatalf("want 1 step, got %d", len(plan.Steps))
	}
	st := plan.Steps[0]
	if st.Type != exercise.StepTypeAgentTask {
		t.Fatalf("want agent_task, got %s", st.Type)
	}
	if st.Config.AgentTask == nil || st.Config.AgentTask.TechniqueID != "T1046" {
		t.Fatalf("technique not mapped: %+v", st.Config.AgentTask)
	}
	if st.Config.AgentTask.AgentID != "${agent_id}" {
		t.Fatalf("want ${agent_id}, got %q", st.Config.AgentTask.AgentID)
	}
}

func TestBuildPlan_MultiTechniqueMakesLinearChain(t *testing.T) {
	plan := BuildPlan(Scenario{Name: "x"}, Detail{
		Injects: []DetailInject{{Title: "Multi", TechniqueIDs: []string{"T1046", "T1057"}}},
	})
	if len(plan.Steps) != 2 {
		t.Fatalf("want 2 steps, got %d", len(plan.Steps))
	}
	if len(plan.Steps[1].DependsOn) != 1 || plan.Steps[1].DependsOn[0] != plan.Steps[0].ID {
		t.Fatalf("step 2 must depend on step 1: %+v", plan.Steps[1].DependsOn)
	}
	if len(plan.Steps[0].DependsOn) != 0 {
		t.Fatalf("first step must have no deps")
	}
}

func TestBuildPlan_NonTechniqueInjectBecomesApproval(t *testing.T) {
	plan := BuildPlan(Scenario{Name: "x"}, Detail{
		Injects: []DetailInject{{Title: "Send phishing email"}},
	})
	if len(plan.Steps) != 1 || plan.Steps[0].Type != exercise.StepTypeApproval {
		t.Fatalf("want 1 approval step: %+v", plan.Steps)
	}
	if plan.Steps[0].Config.ApprovalPrompt != "Send phishing email" {
		t.Fatalf("prompt not set: %q", plan.Steps[0].Config.ApprovalPrompt)
	}
	if plan.Steps[0].Label != "Send phishing email" {
		t.Fatalf("label not set: %q", plan.Steps[0].Label)
	}
}

func TestBuildPlan_VariablesPassthroughPlusAgentID(t *testing.T) {
	plan := BuildPlan(Scenario{Name: "x"}, Detail{
		Variables: []DetailVariable{{Key: "target_url", Description: "the URL"}},
	})
	byName := map[string]exercise.VarDef{}
	for _, v := range plan.Variables {
		byName[v.Name] = v
	}
	if a, ok := byName["agent_id"]; !ok || !a.Required || a.Type != exercise.VarTypeString {
		t.Fatalf("agent_id var wrong: %+v", a)
	}
	if u, ok := byName["target_url"]; !ok || u.Description != "the URL" {
		t.Fatalf("target_url var missing/wrong: %+v", u)
	}
}

func TestBuildPlan_EmptyScenario(t *testing.T) {
	plan := BuildPlan(Scenario{Name: "empty"}, Detail{})
	if len(plan.Steps) != 0 {
		t.Fatalf("want 0 steps, got %d", len(plan.Steps))
	}
	if len(plan.Variables) != 1 { // just agent_id
		t.Fatalf("want 1 var (agent_id), got %d", len(plan.Variables))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/openaev/ -run TestBuildPlan -v`
Expected: FAIL — `undefined: BuildPlan`.

- [ ] **Step 3: Write the implementation**

Create `orchestrator/internal/openaev/bridge.go`:

```go
package openaev

import (
	"fmt"

	"github.com/audspect/bas/internal/exercise"
)

// BuildPlan converts a synced OpenAEV scenario into an editable exercise.Plan.
//
// It is a pure, lossy, one-directional transform (see the 2026-07-16 design spec):
//   - technique-bearing injects  → one agent_task step per TechniqueID, with the
//     target left as the ${agent_id} plan variable (resolved at launch);
//   - non-technique injects       → an approval placeholder step preserving the
//     inject's Title and its ordinal position (nothing is silently dropped);
//   - steps form a linear DAG in inject order (step N depends on step N-1).
func BuildPlan(s Scenario, d Detail) exercise.Plan {
	plan := exercise.Plan{
		Name:        s.Name,
		Description: d.Description,
	}

	// agent_id is bound at launch and referenced by every agent_task step.
	plan.Variables = append(plan.Variables, exercise.VarDef{
		Name:        "agent_id",
		Type:        exercise.VarTypeString,
		Description: "Target agent for attack (agent_task) steps",
		Required:    true,
	})
	for _, v := range d.Variables {
		plan.Variables = append(plan.Variables, exercise.VarDef{
			Name:        v.Key,
			Type:        exercise.VarTypeString,
			Description: v.Description,
		})
	}

	var prevID string
	stepNum := 0
	addStep := func(st exercise.PlanStep) {
		stepNum++
		st.ID = fmt.Sprintf("step-%d", stepNum)
		if prevID != "" {
			st.DependsOn = []string{prevID}
		}
		prevID = st.ID
		plan.Steps = append(plan.Steps, st)
	}

	for _, inj := range d.Injects {
		if len(inj.TechniqueIDs) == 0 {
			addStep(exercise.PlanStep{
				Type:   exercise.StepTypeApproval,
				Label:  inj.Title,
				Config: exercise.StepConfig{ApprovalPrompt: inj.Title},
			})
			continue
		}
		for _, tid := range inj.TechniqueIDs {
			addStep(exercise.PlanStep{
				Type:  exercise.StepTypeAgentTask,
				Label: inj.Title + " — " + tid,
				Config: exercise.StepConfig{
					AgentTask: &exercise.AgentTaskConfig{
						AgentID:     "${agent_id}",
						TechniqueID: tid,
					},
				},
			})
		}
	}

	return plan
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/openaev/ -run TestBuildPlan -v`
Expected: PASS (all 5).

- [ ] **Step 5: Validate + commit**

```bash
cd orchestrator
gofmt -w internal/openaev/bridge.go internal/openaev/bridge_test.go
gofmt -l internal/openaev/bridge.go internal/openaev/bridge_test.go   # expect empty
go build ./... && go vet ./internal/openaev/
git add internal/openaev/bridge.go internal/openaev/bridge_test.go
git commit -m "feat(openaev): BuildPlan bridge — scenario Detail to exercise.Plan skeleton"
git push
```

---

### Task 2: Bridge API endpoint (`POST /api/openaev/scenarios/{id}/create-plan`)

**Files:**
- Modify: `orchestrator/internal/api/openaev_handlers.go` (add handler at end of file)
- Modify: `orchestrator/internal/api/routes.go:361` (Admin group — add route after the `/api/openaev/import` line)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go:104` (add Admin-only row after the openaev scenario rows / in the `tierAdminOnly` block)

**Interfaces:**
- Consumes: `openaev.NewSQLStore(h.db)`, `store.Get(ctx, id) (Scenario, Detail, bool, error)`, `openaev.BuildPlan` (Task 1), `h.exerciseStore.CreatePlan(ctx, *exercise.Plan) error`, `h.auditLog`, `chi.URLParam`, `respond`, `jsonError`.
- Produces: `func (h *Handler) CreateExercisePlanFromOpenAEV(w http.ResponseWriter, r *http.Request)` returning `{"plan_id": "<id>"}`.

Note: `openaev_handlers.go` already imports `openaev` and `chi`, and the `api` package already has `h.exerciseStore`. No new imports are needed — the returned `exercise.Plan` value is used via `&plan` without naming the `exercise` package in this file.

- [ ] **Step 1: Write the failing RBAC row**

In `orchestrator/internal/api/rbac_matrix_test.go`, add this line inside the `tierAdminOnly` block (e.g. right after line 361's counterpart `{http.MethodPost, "/api/openaev/import", tierAdminOnly, ""},` — search for that row):

```go
	{http.MethodPost, "/api/openaev/scenarios/{id}/create-plan", tierAdminOnly, ""},
```

- [ ] **Step 2: Run RBAC test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/ -run TestRBACMatrix -v`
Expected: FAIL — the matrix asserts every listed route is registered; the new route is not wired yet (unregistered-route / mismatch failure).

- [ ] **Step 3: Add the handler**

Append to `orchestrator/internal/api/openaev_handlers.go`:

```go
// POST /api/openaev/scenarios/{id}/create-plan — Admin.
// Builds an editable exercise plan from a synced OpenAEV scenario
// (structure-preserving skeleton — see openaev.BuildPlan).
func (h *Handler) CreateExercisePlanFromOpenAEV(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	store := openaev.NewSQLStore(h.db)
	sc, detail, found, err := store.Get(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		jsonError(w, "scenario not found", http.StatusNotFound)
		return
	}
	plan := openaev.BuildPlan(sc, detail)
	if err := h.exerciseStore.CreatePlan(r.Context(), &plan); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "openaev.create_plan", plan.ID, map[string]any{"scenario_id": id, "name": plan.Name}, "success")
	respond(w, map[string]string{"plan_id": plan.ID})
}
```

- [ ] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, in the Admin group, immediately after the line:

```go
			r.Post("/api/openaev/import", h.ImportOpenAEVBundle)
```

add:

```go
			r.Post("/api/openaev/scenarios/{id}/create-plan", h.CreateExercisePlanFromOpenAEV)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/ -run TestRBACMatrix -v`
Expected: PASS. (Requires Docker Desktop for the api package's testcontainer setup.)

- [ ] **Step 6: Validate + commit**

```bash
cd orchestrator
gofmt -w internal/api/openaev_handlers.go internal/api/routes.go internal/api/rbac_matrix_test.go
gofmt -l internal/api/openaev_handlers.go internal/api/routes.go internal/api/rbac_matrix_test.go   # expect empty
go build ./... && go vet ./internal/api/
git add internal/api/openaev_handlers.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(api): create-plan-from-OpenAEV endpoint (Admin)"
git push
```

---

### Task 3: SMS / Slack / Teams injectors

**Files:**
- Create: `orchestrator/internal/exercise/injectors.go`
- Test: `orchestrator/internal/exercise/injectors_test.go`

**Interfaces:**
- Produces:
  - `type SMSGatewayConfig struct { URL, AuthToken, From string }`
  - `func NewSMSInjector(cfg SMSGatewayConfig) *SMSInjector`; `func (*SMSInjector) Send(ctx, to []string, body string) (map[string]any, error)`
  - `func NewSlackInjector(webhookURL string) *SlackInjector`; `func (*SlackInjector) Send(ctx, text string) (map[string]any, error)`
  - `func NewTeamsInjector(webhookURL string) *TeamsInjector`; `func (*TeamsInjector) Send(ctx, text string) (map[string]any, error)`
- Note: config struct named `SMSGatewayConfig` to avoid colliding with the existing step-level `SMSConfig{To, Body}`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/exercise/injectors_test.go`:

```go
package exercise

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSMSInjector_PostsPerRecipient(t *testing.T) {
	var got []map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]string
		_ = json.Unmarshal(b, &m)
		got = append(got, m)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	inj := NewSMSInjector(SMSGatewayConfig{URL: srv.URL, From: "BAS"})
	res, err := inj.Send(context.Background(), []string{"+15550001", "+15550002"}, "hello")
	if err != nil {
		t.Fatal(err)
	}
	if res["sent"] != 2 {
		t.Fatalf("want 2 sent, got %v", res["sent"])
	}
	if len(got) != 2 || got[0]["body"] != "hello" || got[0]["from"] != "BAS" {
		t.Fatalf("payload wrong: %+v", got)
	}
}

func TestSMSInjector_Unconfigured(t *testing.T) {
	inj := NewSMSInjector(SMSGatewayConfig{})
	if _, err := inj.Send(context.Background(), []string{"x"}, "y"); err == nil {
		t.Fatal("want error when URL empty")
	}
}

func TestSlackInjector_PostsText(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	inj := NewSlackInjector(srv.URL)
	if _, err := inj.Send(context.Background(), "alert!"); err != nil {
		t.Fatal(err)
	}
	if body["text"] != "alert!" {
		t.Fatalf("want text=alert!, got %v", body["text"])
	}
}

func TestTeamsInjector_Unconfigured(t *testing.T) {
	inj := NewTeamsInjector("")
	if _, err := inj.Send(context.Background(), "x"); err == nil {
		t.Fatal("want error when webhook empty")
	}
}

func TestSlackInjector_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	inj := NewSlackInjector(srv.URL)
	if _, err := inj.Send(context.Background(), "x"); err == nil {
		t.Fatal("want error on HTTP 500")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/exercise/ -run 'Injector' -v`
Expected: FAIL — `undefined: NewSMSInjector` etc.

- [ ] **Step 3: Write the implementation**

Create `orchestrator/internal/exercise/injectors.go`:

```go
package exercise

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// injectorHTTPClient is shared by the HTTP-based injectors (SMS/Slack/Teams).
var injectorHTTPClient = &http.Client{Timeout: 15 * time.Second}

// ── SMS ─────────────────────────────────────────────────────────────────────

// SMSGatewayConfig configures the generic (Twilio-compatible) HTTP SMS gateway.
// Named to avoid colliding with the step-level SMSConfig{To, Body}.
type SMSGatewayConfig struct {
	URL       string `json:"url"`
	AuthToken string `json:"auth_token,omitempty"`
	From      string `json:"from,omitempty"`
}

type SMSInjector struct{ cfg SMSGatewayConfig }

func NewSMSInjector(cfg SMSGatewayConfig) *SMSInjector { return &SMSInjector{cfg: cfg} }

// Send POSTs one JSON request per recipient: {"to","from","body"}.
func (i *SMSInjector) Send(ctx context.Context, to []string, body string) (map[string]any, error) {
	if i.cfg.URL == "" {
		return nil, fmt.Errorf("SMS gateway not configured")
	}
	sent, failed := 0, 0
	var errs []string
	for _, num := range to {
		payload, _ := json.Marshal(map[string]string{"to": num, "from": i.cfg.From, "body": body})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, i.cfg.URL, bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		if i.cfg.AuthToken != "" {
			req.Header.Set("Authorization", "Bearer "+i.cfg.AuthToken)
		}
		resp, err := injectorHTTPClient.Do(req)
		if err != nil {
			failed++
			errs = append(errs, num+": "+err.Error())
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			failed++
			errs = append(errs, fmt.Sprintf("%s: HTTP %d", num, resp.StatusCode))
			continue
		}
		sent++
	}
	res := map[string]any{"channel": "sms", "sent": sent, "failed": failed}
	if len(errs) > 0 {
		res["errors"] = errs
	}
	return res, nil
}

// ── Slack / Teams (incoming webhook) ──────────────────────────────────────────

type SlackInjector struct{ webhookURL string }

func NewSlackInjector(webhookURL string) *SlackInjector { return &SlackInjector{webhookURL: webhookURL} }

func (i *SlackInjector) Send(ctx context.Context, text string) (map[string]any, error) {
	return postWebhookJSON(ctx, "slack", i.webhookURL, map[string]any{"text": text})
}

type TeamsInjector struct{ webhookURL string }

func NewTeamsInjector(webhookURL string) *TeamsInjector { return &TeamsInjector{webhookURL: webhookURL} }

func (i *TeamsInjector) Send(ctx context.Context, text string) (map[string]any, error) {
	// Teams incoming webhooks accept a simple {"text": ...} payload.
	return postWebhookJSON(ctx, "teams", i.webhookURL, map[string]any{"text": text})
}

func postWebhookJSON(ctx context.Context, channel, url string, payload map[string]any) (map[string]any, error) {
	if url == "" {
		return nil, fmt.Errorf("%s webhook not configured", channel)
	}
	raw, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := injectorHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s webhook returned HTTP %d", channel, resp.StatusCode)
	}
	return map[string]any{"channel": channel, "sent": 1}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/exercise/ -run 'Injector' -v`
Expected: PASS (all 5).

- [ ] **Step 5: Validate + commit**

```bash
cd orchestrator
gofmt -w internal/exercise/injectors.go internal/exercise/injectors_test.go
gofmt -l internal/exercise/injectors.go internal/exercise/injectors_test.go   # expect empty
go build ./... && go vet ./internal/exercise/
git add internal/exercise/injectors.go internal/exercise/injectors_test.go
git commit -m "feat(exercise): real SMS + Slack + Teams injectors (global, SMTP-style)"
git push
```

---

### Task 4: Wire injectors into the engine (step types, handlers, config, compose)

**Files:**
- Modify: `orchestrator/internal/exercise/types.go` (2 step types + 2 step configs)
- Modify: `orchestrator/internal/exercise/executor.go:63` (`RegisterBuiltins` signature + handlers)
- Test: `orchestrator/internal/exercise/executor_wiring_test.go` (new)
- Modify: `orchestrator/config/config.go:39` (struct fields) + `:132` (env reads)
- Modify: `orchestrator/cmd/server/main.go:250-265` (construct injectors; updated `RegisterBuiltins` call)
- Modify: `packaging/compose/docker-compose.yml` (env passthrough in the orchestrator `environment:` block)

**Interfaces:**
- Consumes: `SMSInjector`, `SlackInjector`, `TeamsInjector` (Task 3); existing `SMTPInjector`.
- Produces: `StepTypeSlack`, `StepTypeTeams`; `StepConfig.Slack *SlackStepConfig`, `StepConfig.Teams *TeamsStepConfig`; widened `func (e *Executor) RegisterBuiltins(smtp *SMTPInjector, sms *SMSInjector, slack *SlackInjector, teams *TeamsInjector)`.

- [ ] **Step 1: Add step types + step configs**

In `orchestrator/internal/exercise/types.go`, in the `const (...)` block that defines `StepTypeNotify` (right after the `StepTypeNotify StepType = "notify"` line), add:

```go
	StepTypeSlack StepType = "slack"
	StepTypeTeams StepType = "teams"
```

In the same file, add the `Slack`/`Teams` fields to `StepConfig` (right after the `// notify` block's `NotifyMsg` field):

```go
	// slack
	Slack *SlackStepConfig `json:"slack,omitempty"`
	// teams
	Teams *TeamsStepConfig `json:"teams,omitempty"`
```

And add the two step-config types near `SMSConfig` (after the `SMSConfig` struct):

```go
type SlackStepConfig struct {
	Text string `json:"text"`
}

type TeamsStepConfig struct {
	Text string `json:"text"`
}
```

- [ ] **Step 2: Write the failing wiring test**

Create `orchestrator/internal/exercise/executor_wiring_test.go`:

```go
package exercise

import "testing"

func TestRegisterBuiltins_RegistersAllChannels(t *testing.T) {
	e := &Executor{registry: NewRegistry()}
	e.RegisterBuiltins(nil, nil, nil, nil)
	for _, st := range []StepType{
		StepTypeSendEmail, StepTypeSendSMS, StepTypeSlack, StepTypeTeams,
		StepTypeAgentTask, StepTypeApproval,
	} {
		if !e.registry.Has(st) {
			t.Fatalf("no handler registered for %s", st)
		}
	}
}
```

- [ ] **Step 3: Run the wiring test to verify it fails**

Run: `cd orchestrator && go test ./internal/exercise/ -run TestRegisterBuiltins -v`
Expected: FAIL — compile error: `RegisterBuiltins` currently takes one arg / `StepTypeSlack` undefined until Step 1 applied. (After Step 1, the failure is the arity mismatch on `RegisterBuiltins`.)

- [ ] **Step 4: Convert SMS handler to a factory + add Slack/Teams handlers**

In `orchestrator/internal/exercise/executor.go`, replace the stub method:

```go
func (e *Executor) handleSendSMS(_ context.Context, ex *Execution, ps *PlanStep, _ *StepExecution) error {
	log.Printf("[exercise] SMS step %s/%s — no gateway configured (stub)", ex.ID, ps.ID)
	return e.store.SetStepStatus(context.Background(), ex.ID, ps.ID, StepCompleted, "")
}
```

with real factory handlers (mirroring `handleSendEmail`):

```go
func (e *Executor) handleSendSMS(sms *SMSInjector) func(context.Context, *Execution, *PlanStep, *StepExecution) error {
	return func(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
		if sms == nil {
			return e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, "SMS gateway not configured")
		}
		cfg := ps.Config.SMS
		if cfg == nil {
			return e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, "missing sms config")
		}
		go func() {
			bctx := context.Background()
			result, err := sms.Send(bctx, cfg.To, cfg.Body)
			if err != nil {
				_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepFailed, err.Error())
				return
			}
			_ = e.store.SetStepResult(bctx, ex.ID, ps.ID, result)
			_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepCompleted, "")
			_, _ = e.evidence.Append(bctx, ex.ID, se.ID, "sms_sent", "system", "sms_injector", result)
			_ = e.store.RecordEvent(bctx, ex.ID, ps.ID, "step_completed", "system", result)
		}()
		return nil
	}
}

func (e *Executor) handleSlack(slack *SlackInjector) func(context.Context, *Execution, *PlanStep, *StepExecution) error {
	return func(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
		if slack == nil {
			return e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, "Slack not configured")
		}
		cfg := ps.Config.Slack
		if cfg == nil {
			return e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, "missing slack config")
		}
		go func() {
			bctx := context.Background()
			result, err := slack.Send(bctx, cfg.Text)
			if err != nil {
				_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepFailed, err.Error())
				return
			}
			_ = e.store.SetStepResult(bctx, ex.ID, ps.ID, result)
			_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepCompleted, "")
			_, _ = e.evidence.Append(bctx, ex.ID, se.ID, "slack_sent", "system", "slack_injector", result)
			_ = e.store.RecordEvent(bctx, ex.ID, ps.ID, "step_completed", "system", result)
		}()
		return nil
	}
}

func (e *Executor) handleTeams(teams *TeamsInjector) func(context.Context, *Execution, *PlanStep, *StepExecution) error {
	return func(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
		if teams == nil {
			return e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, "Teams not configured")
		}
		cfg := ps.Config.Teams
		if cfg == nil {
			return e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, "missing teams config")
		}
		go func() {
			bctx := context.Background()
			result, err := teams.Send(bctx, cfg.Text)
			if err != nil {
				_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepFailed, err.Error())
				return
			}
			_ = e.store.SetStepResult(bctx, ex.ID, ps.ID, result)
			_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepCompleted, "")
			_, _ = e.evidence.Append(bctx, ex.ID, se.ID, "teams_sent", "system", "teams_injector", result)
			_ = e.store.RecordEvent(bctx, ex.ID, ps.ID, "step_completed", "system", result)
		}()
		return nil
	}
}
```

Then update `RegisterBuiltins` (currently at line 63):

```go
func (e *Executor) RegisterBuiltins(smtp *SMTPInjector, sms *SMSInjector, slack *SlackInjector, teams *TeamsInjector) {
	e.registry.Register(StepTypeSendEmail, StepHandlerFunc(e.handleSendEmail(smtp)))
	e.registry.Register(StepTypeSendSMS, StepHandlerFunc(e.handleSendSMS(sms)))
	e.registry.Register(StepTypeAgentTask, StepHandlerFunc(e.handleAgentTask))
	e.registry.Register(StepTypeWait, StepHandlerFunc(e.handleWait))
	e.registry.Register(StepTypeApproval, StepHandlerFunc(e.handleApproval))
	e.registry.Register(StepTypeWebhook, StepHandlerFunc(e.handleWebhook))
	e.registry.Register(StepTypeNotify, StepHandlerFunc(e.handleNotify))
	e.registry.Register(StepTypeSlack, StepHandlerFunc(e.handleSlack(slack)))
	e.registry.Register(StepTypeTeams, StepHandlerFunc(e.handleTeams(teams)))
	e.registry.Register(StepTypeWaitForAgent, StepHandlerFunc(e.handleWaitForAgent))
	e.registry.Register(StepTypeWaitForDetection, StepHandlerFunc(e.handleWaitForDetection))
	e.registry.Register(StepTypeWaitForWebhook, StepHandlerFunc(e.handleWaitForWebhook))
}
```

Note: if `log` becomes unused in `executor.go` after removing the stub, remove the `"log"` import; if other code in the file still uses `log`, leave it. Run `go build` to confirm.

- [ ] **Step 5: Run the wiring test to verify it passes**

Run: `cd orchestrator && go test ./internal/exercise/ -run TestRegisterBuiltins -v`
Expected: PASS.

- [ ] **Step 6: Add config fields + env reads**

In `orchestrator/config/config.go`, after the `PublicBaseURL` struct field (line 39), add:

```go
	SMSGatewayURL   string `json:"sms_gateway_url,omitempty"`
	SMSGatewayToken string `json:"sms_gateway_token,omitempty"`
	SMSGatewayFrom  string `json:"sms_gateway_from,omitempty"`
	SlackWebhookURL string `json:"slack_webhook_url,omitempty"`
	TeamsWebhookURL string `json:"teams_webhook_url,omitempty"`
```

In the same file, after the `PUBLIC_BASE_URL` env block (line 132), add:

```go
	if v := os.Getenv("SMS_GATEWAY_URL"); v != "" {
		cfg.SMSGatewayURL = v
	}
	if v := os.Getenv("SMS_GATEWAY_TOKEN"); v != "" {
		cfg.SMSGatewayToken = v
	}
	if v := os.Getenv("SMS_GATEWAY_FROM"); v != "" {
		cfg.SMSGatewayFrom = v
	}
	if v := os.Getenv("SLACK_WEBHOOK_URL"); v != "" {
		cfg.SlackWebhookURL = v
	}
	if v := os.Getenv("TEAMS_WEBHOOK_URL"); v != "" {
		cfg.TeamsWebhookURL = v
	}
```

- [ ] **Step 7: Construct injectors + update RegisterBuiltins call in main.go**

In `orchestrator/cmd/server/main.go`, after the `smtpInj` construction block (ends line 261) and before `exRegistry := ...`, add:

```go
	var smsInj *exercise.SMSInjector
	if cfg.SMSGatewayURL != "" {
		smsInj = exercise.NewSMSInjector(exercise.SMSGatewayConfig{
			URL:       cfg.SMSGatewayURL,
			AuthToken: cfg.SMSGatewayToken,
			From:      cfg.SMSGatewayFrom,
		})
	}
	var slackInj *exercise.SlackInjector
	if cfg.SlackWebhookURL != "" {
		slackInj = exercise.NewSlackInjector(cfg.SlackWebhookURL)
	}
	var teamsInj *exercise.TeamsInjector
	if cfg.TeamsWebhookURL != "" {
		teamsInj = exercise.NewTeamsInjector(cfg.TeamsWebhookURL)
	}
```

Then change the existing call (line 265):

```go
	exExecutor.RegisterBuiltins(smtpInj)
```

to:

```go
	exExecutor.RegisterBuiltins(smtpInj, smsInj, slackInj, teamsInj)
```

- [ ] **Step 8: Add compose env passthrough**

In `packaging/compose/docker-compose.yml`, in the orchestrator service `environment:` block (near the SMTP/threat-intel vars, e.g. after `THREAT_INTEL_POLL_HOURS`), add:

```yaml
      # ── Exercise comm injectors (optional — leave blank to disable) ──
      SMS_GATEWAY_URL:   ${SMS_GATEWAY_URL:-}
      SMS_GATEWAY_TOKEN: ${SMS_GATEWAY_TOKEN:-}
      SMS_GATEWAY_FROM:  ${SMS_GATEWAY_FROM:-}
      SLACK_WEBHOOK_URL: ${SLACK_WEBHOOK_URL:-}
      TEAMS_WEBHOOK_URL: ${TEAMS_WEBHOOK_URL:-}
```

- [ ] **Step 9: Full validate + commit**

```bash
cd orchestrator
gofmt -w internal/exercise/types.go internal/exercise/executor.go internal/exercise/executor_wiring_test.go config/config.go cmd/server/main.go
gofmt -l internal/exercise/types.go internal/exercise/executor.go internal/exercise/executor_wiring_test.go config/config.go cmd/server/main.go   # expect empty
go build ./...
go vet ./internal/exercise/ ./config/ ./cmd/server/
go test ./internal/exercise/
git add internal/exercise/types.go internal/exercise/executor.go internal/exercise/executor_wiring_test.go config/config.go cmd/server/main.go ../packaging/compose/docker-compose.yml
git commit -m "feat(exercise): wire SMS/Slack/Teams injectors into engine + config + compose"
git push
```

---

### Task 5: Exercises dashboard UI tab

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (nav item, tab content, drawer, JS; + OpenAEV drawer button)
- Sync + Modify: `orchestrator/cmd/server/wwwroot/index.html` (hardlink mirror — verify byte-identical, `git add` both)

**Interfaces:**
- Consumes (existing endpoints): `GET /api/exercises/plans`, `GET /api/exercises/plans/{id}`, `GET /api/exercises/executions`, `GET /api/exercises/executions/{id}` (`{execution, steps}`), `POST /api/exercises/executions` (`{plan_id, name, targets, variables}`), `POST /api/exercises/executions/{id}/launch`, `POST /api/exercises/executions/{id}/abort`, `POST /api/exercises/executions/{id}/steps/{stepId}/approve`, and the Task-2 `POST /api/openaev/scenarios/{id}/create-plan`.
- SPA helpers: `apicall(path[,opts])`, `x(s)`, `showToast(msg,kind)`, `ROLE`, drawer `classList.add/remove('open')`.

Note: there is no independent automated test for SPA HTML in this repo; verification is structural (balanced markup, no duplicate IDs, every referenced function defined exactly once) plus a manual spot-check. Follow the existing OpenAEV tab (`loadOpenAEVTab`, `openaev-detail-overlay`) as the concrete template.

- [ ] **Step 1: Add the nav item**

In `orchestrator/wwwroot/index.html`, immediately after the OpenAEV nav item (the `</div>` closing the `data-tab="openaev"` block, line ~1247), add:

```html
        <div class="nav-item" data-tab="exercises" onclick="showTab('exercises')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M2 8h3l2-5 2 10 2-5h3"/>
          </svg>
          Exercises
        </div>
```

- [ ] **Step 2: Register the tab in activateTab, TAB_TITLES, showTab**

In the `activateTab` array (line ~3688), add `'exercises'` to the list (e.g. after `'openaev'`):

```javascript
  ['dashboard','agents','scenarios','runs','campaigns','coverage','findings','remediation','reports','verification','compliance','settings','variants','em','attackpath','exposure','integrations','openaev','exercises'].forEach(function(t) {
```

In `TAB_TITLES` (line ~3560), add before the closing brace:

```javascript
, exercises:'Exercises'
```

In `showTab` (line ~3711, after the `openaev` dispatch), add:

```javascript
  if (name === 'exercises') loadExercisesTab();
```

- [ ] **Step 3: Add the tab content container**

After the `tab-openaev` content div closes (the `</div>` at line ~2838), add:

```html
      <div id="tab-exercises" style="display:none">
        <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
          <div class="card-title">Exercise Plans</div>
          <div class="tbl-wrap" style="margin-top:0.5rem">
            <table>
              <thead><tr><th>Name</th><th>Steps</th><th>Created</th><th></th></tr></thead>
              <tbody id="ex-plans-body"></tbody>
            </table>
          </div>
          <div id="ex-plans-empty" class="empty" style="display:none">No exercise plans yet. Create one from an OpenAEV scenario.</div>
        </div>
        <div class="card" style="padding:1rem 1.2rem">
          <div class="card-title">Executions</div>
          <div class="tbl-wrap" style="margin-top:0.5rem">
            <table>
              <thead><tr><th>Name</th><th>Status</th><th>Started</th></tr></thead>
              <tbody id="ex-execs-body"></tbody>
            </table>
          </div>
          <div id="ex-execs-empty" class="empty" style="display:none">No executions yet.</div>
        </div>
      </div>
```

- [ ] **Step 4: Add the execution detail drawer**

After the OpenAEV drawer closes (the `</div>` at line ~3462), add:

```html
<div id="exercise-detail-overlay" class="drawer-overlay" onclick="if(event.target===this)closeExerciseDetail()">
  <div class="drawer" style="width:640px;max-width:96vw">
    <div class="drawer-header">
      <h3 id="exercise-detail-title">Execution</h3>
      <button class="drawer-close" onclick="closeExerciseDetail()">&#10005;</button>
    </div>
    <div class="drawer-body" style="overflow-y:auto" id="exercise-detail-body"></div>
  </div>
</div>
```

- [ ] **Step 5: Add the JS functions**

Immediately after `closeOpenAEVDetail()` (line ~4268), add:

```javascript
function loadExercisesTab() {
  apicall('/api/exercises/plans').then(function(plans) {
    var body = document.getElementById('ex-plans-body');
    var empty = document.getElementById('ex-plans-empty');
    if (!plans || !plans.length) { body.innerHTML = ''; empty.style.display = 'block'; return; }
    empty.style.display = 'none';
    body.innerHTML = plans.map(function(p) {
      return '<tr>' +
        '<td>' + x(p.name) + '</td>' +
        '<td>' + (p.steps ? p.steps.length : 0) + '</td>' +
        '<td class="tiny muted">' + x(p.created_at || '') + '</td>' +
        '<td><button class="btn btn-primary btn-sm" onclick="launchExercisePrompt(\'' + x(p.id) + '\')">Launch</button></td>' +
        '</tr>';
    }).join('');
  }).catch(function() {});

  apicall('/api/exercises/executions').then(function(execs) {
    var body = document.getElementById('ex-execs-body');
    var empty = document.getElementById('ex-execs-empty');
    if (!execs || !execs.length) { body.innerHTML = ''; empty.style.display = 'block'; return; }
    empty.style.display = 'none';
    body.innerHTML = execs.map(function(e) {
      return '<tr style="cursor:pointer" onclick="openExerciseDetail(\'' + x(e.id) + '\')">' +
        '<td>' + x(e.name || e.plan_id) + '</td>' +
        '<td><span class="badge">' + x(e.status) + '</span></td>' +
        '<td class="tiny muted">' + x(e.started_at || e.created_at || '') + '</td>' +
        '</tr>';
    }).join('');
  }).catch(function() {});
}

function launchExercisePrompt(planId) {
  apicall('/api/exercises/plans/' + encodeURIComponent(planId)).then(function(p) {
    var vars = p.variables || [];
    var values = {};
    for (var i = 0; i < vars.length; i++) {
      var v = vars[i];
      var ans = prompt('Value for "' + v.name + '"' + (v.description ? ' (' + v.description + ')' : '') + ':', v.default || '');
      if (ans === null) return;
      values[v.name] = ans;
    }
    apicall('/api/exercises/executions', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plan_id: planId, name: p.name, targets: [], variables: values })
    }).then(function(ex) {
      return apicall('/api/exercises/executions/' + encodeURIComponent(ex.id) + '/launch', { method: 'POST' });
    }).then(function() {
      showToast('Exercise launched', 'ok');
      loadExercisesTab();
    }).catch(function(e) { showToast('Launch failed: ' + (e.message || 'error'), 'err'); });
  }).catch(function() {});
}

function openExerciseDetail(id) {
  apicall('/api/exercises/executions/' + encodeURIComponent(id)).then(function(d) {
    var ex = d.execution || {}, steps = d.steps || [];
    document.getElementById('exercise-detail-title').textContent = ex.name || ex.plan_id || 'Execution';
    var sc = ex.score;
    var scoreHtml = sc ?
      ('<div class="kpi-row" style="margin-bottom:0.75rem">' +
        '<span class="badge">Overall ' + (sc.overall != null ? sc.overall.toFixed(0) : '—') + '</span>' +
        '<span class="badge">Click rate ' + ((sc.human && sc.human.click_rate != null) ? (sc.human.click_rate * 100).toFixed(0) + '%' : '—') + '</span>' +
        '<span class="badge">EDR ' + ((sc.technical && sc.technical.edr_detected) ? 'detected' : '—') + '</span>' +
        '<span class="badge">SLA ' + ((sc.management && sc.management.sla_met) ? 'met' : '—') + '</span>' +
        '</div>') :
      '<div class="tiny muted" style="margin-bottom:0.75rem">Not yet scored</div>';
    var stepsHtml = steps.map(function(s) {
      var canApprove = s.status === 'waiting' && s.step_type === 'approval';
      return '<div class="kpi-row" style="justify-content:space-between">' +
        '<span>' + x(s.step_id) + ' <span class="tiny muted">' + x(s.step_type) + '</span></span>' +
        '<span><span class="badge">' + x(s.status) + '</span>' +
        (canApprove ? ' <button class="btn btn-outline btn-sm" onclick="approveExStep(\'' + x(id) + '\',\'' + x(s.step_id) + '\')">Approve</button>' : '') +
        '</span></div>';
    }).join('');
    var actions = (ex.status === 'running' || ex.status === 'paused') ?
      '<button class="btn btn-outline btn-sm" onclick="abortExecution(\'' + x(id) + '\')">Abort</button>' : '';
    document.getElementById('exercise-detail-body').innerHTML = scoreHtml + stepsHtml + '<div style="margin-top:0.75rem">' + actions + '</div>';
    document.getElementById('exercise-detail-overlay').classList.add('open');
  }).catch(function() {});
}

function closeExerciseDetail() {
  document.getElementById('exercise-detail-overlay').classList.remove('open');
}

function approveExStep(id, stepId) {
  apicall('/api/exercises/executions/' + encodeURIComponent(id) + '/steps/' + encodeURIComponent(stepId) + '/approve', { method: 'POST' })
    .then(function() { showToast('Step approved', 'ok'); openExerciseDetail(id); })
    .catch(function(e) { showToast('Approve failed: ' + (e.message || 'error'), 'err'); });
}

function abortExecution(id) {
  apicall('/api/exercises/executions/' + encodeURIComponent(id) + '/abort', { method: 'POST' })
    .then(function() { showToast('Execution aborted', 'ok'); openExerciseDetail(id); loadExercisesTab(); })
    .catch(function(e) { showToast('Abort failed: ' + (e.message || 'error'), 'err'); });
}

function createPlanFromOpenAEV(id) {
  apicall('/api/openaev/scenarios/' + encodeURIComponent(id) + '/create-plan', { method: 'POST' })
    .then(function() { showToast('Exercise plan created', 'ok'); closeOpenAEVDetail(); showTab('exercises'); })
    .catch(function(e) { showToast('Create failed: ' + (e.message || 'error'), 'err'); });
}
```

- [ ] **Step 6: Add the "Create Exercise Plan" button to the OpenAEV drawer**

In `openOpenAEVDetail(id)` (line ~4254), after the line that sets `body.innerHTML = ...` (line ~4261) and before the `.classList.add('open')` line, add:

```javascript
    if (ROLE === 'admin') {
      body.innerHTML += '<div style="margin-top:1rem"><button class="btn btn-primary btn-sm" onclick="createPlanFromOpenAEV(\'' + x(id) + '\')">Create Exercise Plan</button></div>';
    }
```

- [ ] **Step 7: Sync the hardlink mirror + structural checks**

```bash
cd orchestrator
# Verify the two wwwroot copies are byte-identical; if not, copy the edited one over.
diff <(sha256sum < wwwroot/index.html) <(sha256sum < cmd/server/wwwroot/index.html) \
  || cp wwwroot/index.html cmd/server/wwwroot/index.html
# Structural sanity: each new id/function should appear the expected number of times.
grep -c 'id="tab-exercises"' wwwroot/index.html          # expect 1
grep -c 'function loadExercisesTab' wwwroot/index.html    # expect 1
grep -c "data-tab=\"exercises\"" wwwroot/index.html       # expect 1
```

Expected: the two files hash-match after the optional copy; each grep prints `1`.

- [ ] **Step 8: Manual spot-check (if a browser is available)**

Load the dashboard as admin → the "Exercises" nav item appears and selects → open an OpenAEV scenario → "Create Exercise Plan" → toast + lands on Exercises tab with the new plan listed → Launch prompts for `agent_id` → the execution appears and its drawer opens. If no browser is available, note this as deferred (as with the OpenAEV tab last session).

- [ ] **Step 9: Commit (both wwwroot paths)**

```bash
cd orchestrator
git add wwwroot/index.html cmd/server/wwwroot/index.html
git commit -m "feat(ui): Exercises tab + Create-Exercise-Plan action on OpenAEV drawer"
git push
```

---

## Self-Review

**Spec coverage:**
- Deliverable 1 (bridge + endpoint) → Tasks 1–2. ✓ (skeleton mapping, `${agent_id}` var, approval placeholders, linear DAG, create-plan endpoint, Admin RBAC).
- Deliverable 2 (UI tab) → Task 5. ✓ (plans/executions lists, launch flow, execution drawer with 3-tier score + steps + approve/abort, OpenAEV entry-point button).
- Deliverable 3 (injectors) → Tasks 3–4. ✓ (SMS real + Slack + Teams; global config like SMTP; new step types/configs; widened `RegisterBuiltins`; env + compose passthrough).
- Testing section → each Go task is TDD; UI verified structurally. ✓
- Out-of-scope items (no Module-1 changes, no extra channels, one-way sync, no per-step override) respected. ✓

**Placeholder scan:** No TBD/TODO; every code step shows complete code; every referenced symbol (`BuildPlan`, `SMSInjector`, `handleSlack`, `StepTypeSlack`, `SlackStepConfig`, config fields, endpoints) is defined in a task or verified to already exist. ✓

**Type consistency:** `BuildPlan(Scenario, Detail) exercise.Plan` used identically in Tasks 1 & 2. `RegisterBuiltins(smtp, sms, slack, teams)` defined in Task 4 Step 4 and called in Task 4 Step 7 with the matching four injector vars. Injector constructors/`Send` signatures from Task 3 match their calls in Task 4 handlers. Step-config field `ps.Config.SMS` (existing), `ps.Config.Slack`/`ps.Config.Teams` (Task 4 Step 1) match handler usage. JSON tags used in the UI (`plan_id`, `step_id`, `step_type`, `status`, `score.overall`, `score.human.click_rate`, etc.) match `types.go`. ✓
