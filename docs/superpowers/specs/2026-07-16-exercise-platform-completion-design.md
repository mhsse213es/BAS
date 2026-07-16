# Exercise Platform Completion — Design Spec

**Date:** 2026-07-16
**Status:** Approved (brainstorming) — pending spec review
**Depends on:** OpenAEV Connector (Module 1, done `233902f`), existing Exercise Engine (`internal/exercise`)

## Goal

Close the three real gaps between the OpenAEV content connector and the existing
Exercise Engine so a synced OpenAEV scenario can become a runnable, human-in-the-loop
exercise with real communication channels:

1. **OpenAEV → Exercise-Plan bridge** — turn a synced scenario into an editable `exercise.Plan`.
2. **Exercise Engine UI tab** — list/launch/observe plans and executions from the dashboard.
3. **Real SMS + Slack + Teams injectors** — replace the SMS stub and add two chat channels.

## Guiding Principle

**Additive only.** No change to the ~4,300-line exercise engine's existing behavior,
scoring, or evidence chain. Every deliverable extends the engine at an existing seam
(new step types, new injectors, one new bridge function, one new UI tab). This is a
completion effort, not a rebuild.

## Locked Decisions (from brainstorming)

- **Bridge fidelity: structure-preserving skeleton.** Uses only the data Module 1
  captured (`DetailInject` = `Title` + `TechniqueIDs`). No Module 1 schema/parser changes.
- **Injector config model: global injectors, like SMTP.** Each channel configured once
  via env; plan steps carry only recipient + message. No per-step channel override (YAGNI).

---

## Deliverable 1 — OpenAEV → Exercise-Plan Bridge

### Data mapping

Input: `openaev.Scenario` (summary) + `openaev.Detail`
(`Description`, `Objectives[]`, `Injects[]{Title, TechniqueIDs[]}`, `Variables[]{Key, Description}`).

Output: `exercise.Plan`.

Mapping rules:

| OpenAEV element | Exercise Plan output |
|---|---|
| Scenario name | `Plan.Name` |
| Detail description | `Plan.Description` |
| Inject with ≥1 TechniqueID | one `agent_task` step **per TechniqueID**, `Label = "<inject title> — <Txxxx>"`, `Config.AgentTask = {AgentID: "${agent_id}", TechniqueID: "<Txxxx>"}` |
| Inject with 0 TechniqueIDs | one `approval` step, `Config.ApprovalPrompt = inject.Title` |
| Inject ordering | **linear DAG**: step *N* `DependsOn = [step N-1 ID]` (first step has no deps) |
| Each `DetailVariable` | one `Plan.Variables` entry (`VarDef{Name: Key, Description, Type: VarTypeString}`) |
| — | plus a `VarDef{Name: "agent_id", Type: VarTypeString, Required: true}` bound at launch, referenced by every agent_task |

> `VarDef` also carries `Type VarType`, `Default`, `Required`, `SecretEnv`. All bridge-emitted
> vars are `VarTypeString`; only `agent_id` is `Required`.

Rationale for `approval` on non-technique injects: OpenAEV injects whose type/content
Module 1 did not capture (email, sms, manual, etc.) still occupy a position in the
scenario. Emitting an `approval` step preserves the inject's title and its ordinal
position so the operator consciously handles or edits it — nothing is silently dropped.

Step IDs are generated deterministically per plan build (e.g. `step-1`, `step-2`, …) so
`DependsOn` links are stable within the produced plan.

### Convention followed (verified against current code)

- `dispatchStep` (`executor.go:236`) resolves `${VarName}` in step config via
  `NewResolver(plan.Variables, ex.Variables, …)` before dispatch.
- `handleAgentTask` (`executor.go:287`) reads `cfg.AgentID` directly.

Therefore emitting `AgentID: "${agent_id}"` as a plan variable, bound at execution
launch, is the idiomatic way to leave the target unresolved at build time.

### Component

- **New file `orchestrator/internal/openaev/bridge.go`**
  - `func BuildPlan(s Scenario, d Detail) exercise.Plan`
  - `internal/openaev` imports `internal/exercise` (no import cycle — `exercise` does not import `openaev`).
  - Pure function: no DB, no I/O. Fully unit-testable.

### API endpoint

- **`POST /api/openaev/scenarios/{id}/create-plan`** (Admin-only)
  - Loads the synced scenario via the OpenAEV store (`Get(ctx, id)` → `Scenario`, `Detail`).
  - Calls `BuildPlan`, persists via `exStore.CreatePlan(ctx, &plan)`.
  - Returns `201 {"plan_id": "<id>"}`.
  - Wiring: the OpenAEV API handler gains a reference to the exercise `*Store`
    (constructor updated in `cmd/server/main.go`).
  - RBAC: added to the Admin group; asserted in `rbac_matrix_test.go`.

---

## Deliverable 2 — Exercise Engine UI Tab

### New nav tab "Exercises"

Follows SP4 Exposure Explorer conventions exactly:
- Added to the hardcoded `activateTab()` JS array, `TAB_TITLES`, and `showTab`.
- Drawer pattern: `exercise-detail-overlay.drawer-overlay > .drawer > .drawer-header/.drawer-body`.
- Both hardlinked wwwroot paths (`orchestrator/wwwroot/index.html` and
  `orchestrator/cmd/server/wwwroot/index.html`) edited and `git add`ed.

### Renders against existing endpoints (no new list endpoints)

- **Plans list** — `GET /api/exercises/plans`: name, step count, "Launch" button.
- **Executions list** — `GET /api/exercises/executions`: status badge, started time,
  row → opens execution drawer.
- **Execution drawer** — step-by-step statuses, the 3-tier `ExerciseScore`
  (Human / Technical / Management), evidence chain, and abort/approve actions
  (existing endpoints). Refreshed on the existing dashboard poll cadence.
- **Launch flow** — launching a plan prompts for the `agent_id` (and any other plan
  variables) and target list, then `POST` to the existing launch endpoint.

### Entry point from OpenAEV (ties Module 1 → Module 2)

- The existing **OpenAEV scenario drawer** (`openaev-detail-overlay`) gains a
  **"Create Exercise Plan"** button (Admin-gated, `ROLE === 'admin'`).
- On click → `POST /api/openaev/scenarios/{id}/create-plan` → success toast →
  deep-link/switch to the Exercises tab with the new plan visible.

---

## Deliverable 3 — Real SMS + Slack + Teams Injectors

Global injectors, mirroring the existing `SMTPInjector` pattern
(`NewSMTPInjector(cfg, store)` → passed to `RegisterBuiltins`).

### New file `orchestrator/internal/exercise/injectors.go`

- **`SMSInjector`** + **`SMSGatewayConfig{URL, AuthToken, From}`** — generic
  Twilio-compatible HTTP POST gateway. Replaces the `handleSendSMS` stub
  (`executor.go:282`). Consumes the existing `SMSConfig{To, Body}` step config.
  (Config struct named `SMSGatewayConfig` to avoid colliding with the existing
  step-level `SMSConfig`.)
- **`SlackInjector`** + **`SlackConfig{WebhookURL}`** (injector config) — POSTs
  `{"text": ...}` JSON to one Slack incoming-webhook URL.
- **`TeamsInjector`** + **`TeamsConfig{WebhookURL}`** (injector config) — POSTs
  MessageCard JSON to one Teams incoming-webhook URL.

Each injector's `Send()` returns `StepFailed` cleanly (never panics) when its channel
is unconfigured — identical posture to `SMTPInjector` with an empty host.

### New step types + step configs (`types.go`)

- `StepTypeSlack StepType = "slack"`, `StepTypeTeams StepType = "teams"`.
- `StepConfig` gains `Slack *SlackStepConfig` and `Teams *TeamsStepConfig`, each
  `{Text string}` (recipient is the channel bound to the webhook, per the global model).

  > Naming note: to keep step-config vs injector-config distinct, the **step** configs
  > are `SlackStepConfig`/`TeamsStepConfig`; the **injector** configs are
  > `SlackConfig`/`TeamsConfig`. (SMS reuses the existing step `SMSConfig{To, Body}`.)

### Executor wiring (`executor.go`)

- `RegisterBuiltins` signature: `(smtp *SMTPInjector, sms *SMSInjector, slack *SlackInjector, teams *TeamsInjector)`.
- Register real `handleSendSMS` (rewritten), `handleSlack`, `handleTeams` — each mirrors
  `handleSendEmail`: goroutine → `SetStepResult` → `SetStepStatus(Completed)` →
  `evidence.Append(...,"<channel>_sent",...)` → `RecordEvent`.

### Config source (`cmd/server/main.go` + central config)

Env vars on the central config struct (mirroring `cfg.SMTPHost` etc.), passed through
in `packaging/compose/docker-compose.yml`:

- `SMS_GATEWAY_URL`, `SMS_GATEWAY_TOKEN`, `SMS_GATEWAY_FROM`
- `SLACK_WEBHOOK_URL`
- `TEAMS_WEBHOOK_URL`

Injectors constructed only when their key config is set (nil otherwise); secrets never
persisted to the DB.

---

## Testing

- **Bridge** (`bridge_test.go`, table-driven): technique inject → agent_task;
  multi-technique inject → N steps; non-technique inject → approval; variable
  passthrough incl. injected `agent_id`; linear DAG `DependsOn` correctness; empty
  scenario → empty-but-valid plan.
- **Injectors** (`injectors_test.go`): `httptest.Server` asserting each channel POSTs
  the correct URL/payload/auth; unconfigured injector → `StepFailed`; handler
  registration present after `RegisterBuiltins`.
- **API** (`openaev_handlers` tests + `rbac_matrix_test.go`): create-plan happy path
  (scenario → persisted plan), 404 for unknown scenario, RBAC (Admin-only).
- **Validation chain** (standing rule): `gofmt -w <touched files>` → `gofmt -l` →
  `go build ./...` → `go vet ./...` → `go test` for `internal/openaev`,
  `internal/exercise`, `internal/api`. Testcontainers requires Docker Desktop running.

## Explicitly Out of Scope

- No changes to existing step semantics, scoring, or the evidence chain.
- No new content captured from OpenAEV bundles (Module 1 normalizer untouched).
- No M365 / Exchange / WhatsApp / voice / Google Chat channels.
- No bidirectional or live-linked sync — OpenAEV → Plan is one-way and one-shot; an
  edited plan has no ongoing tie back to its OpenAEV source.
- No per-step channel/webhook override.

## File Manifest

**New:**
- `orchestrator/internal/openaev/bridge.go`
- `orchestrator/internal/openaev/bridge_test.go`
- `orchestrator/internal/exercise/injectors.go`
- `orchestrator/internal/exercise/injectors_test.go`

**Modified:**
- `orchestrator/internal/exercise/types.go` (2 step types, 2 step configs)
- `orchestrator/internal/exercise/executor.go` (`RegisterBuiltins` sig; real SMS/Slack/Teams handlers)
- `orchestrator/internal/api/openaev_handlers.go` (create-plan handler; exStore reference)
- `orchestrator/internal/api/routes.go` (route registration)
- `orchestrator/internal/api/rbac_matrix_test.go` (create-plan RBAC row)
- `orchestrator/cmd/server/main.go` (construct SMS/Slack/Teams injectors; updated `RegisterBuiltins` call; wire exStore into OpenAEV handler)
- central config struct (SMS/Slack/Teams env fields)
- `packaging/compose/docker-compose.yml` (env passthrough)
- `orchestrator/wwwroot/index.html` + `orchestrator/cmd/server/wwwroot/index.html` (Exercises tab + OpenAEV "Create Exercise Plan" button)
