# Load / Performance / Scale Testing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Answer, with real numbers, how big an agent fleet one Audspect orchestrator instance supports while users simultaneously work the API/dashboard, and characterize behavior beyond that point.

**Architecture:** Extract a clean, execution-free `agent/protocol` package from the entangled `agent/agent.go` (behavior-preserving, gated by the existing agent test suite), wire it into a repo-root `go.work` so a new `orchestrator/cmd/loadgen` binary can simulate real agents' full wire lifecycle without duplicating the protocol. k6 covers the HTTP/API plane independently. A combined runbook runs both against the staging server through a staged fleet-size ramp, scraping the orchestrator's own `/metrics` for server-side impact.

**Tech Stack:** Go 1.26 (both `agent` and `orchestrator` modules, already aligned), `github.com/gorilla/websocket v1.5.3` (already a dependency of both modules), Go workspaces (`go.work`), k6.

**Spec:** `orchestrator/docs/superpowers/specs/2026-08-31-load-perf-scale-testing-design.md`

## Global Constraints

- Target environment is the dedicated test/staging server only — never client PROD.
- `agent/protocol` contains zero OS/technique-execution logic. If a piece would require changing execution behavior to move, it stays in `agent.go`.
- No protocol/transport sub-split inside `agent/protocol` — this extraction establishes a clean boundary, not a full agent-architecture rewrite.
- Both modules pin `go 1.26.0`; `go.work` must not become an implicit production dependency (never referenced by any Dockerfile or release build step).
- CI (`.github/workflows/test.yml`) runs everything with `working-directory: orchestrator` and today never touches the `agent` module at all — verify this stays true (existing steps keep building only `orchestrator`'s own package set) after `go.work` lands.
- 5,000 simulated agents is the primary capacity milestone (must meet the SLOs in Task 6); 10,000 is stretch/characterization only, no strict SLO.
- k6 workload mix: 60% dashboard/read, 20% run/result queries, 10% findings/posture, 10% report generation — a concrete starting point, refine once `http_requests_total{route}` has real staging traffic.
- Never duplicate the agent wire protocol by hand in `loadgen` — it must consume `agent/protocol`'s actual types and network-calling functions, not a hand-rolled equivalent.

---

## File Structure

- **Create** `agent/protocol/messages.go` — every wire-format struct type, moved verbatim from `agent/types.go` (which is deleted once its content is fully migrated).
- **Create** `agent/protocol/enroll.go` — `Enroll()`, the shared network call for `POST /api/agents/enroll`.
- **Create** `agent/protocol/heartbeat.go` — `SendHeartbeat()`, the shared network call for `POST /api/heartbeat`.
- **Create** `agent/protocol/websocket.go` — `DialAgentWS()` (connect + ping/pong keepalive) and `ReadMessage()` (decode one `WSMessage` off an open connection), plus the `wsPongWait`/`wsWriteWait` timing constants.
- **Create** `agent/protocol/result.go` — `SubmitResult()` (shared network call for `POST /api/scenarios/result`) and `SignBody()` (moved from `agent/integrity.go`).
- **Delete** `agent/types.go` — content fully migrated to `agent/protocol`.
- **Modify** `agent/agent.go`, `agent/spool.go`, `agent/simulate.go`, `agent/detect_other.go`, `agent/detect_windows.go`, `agent/attackpath.go`, `agent/attackpath_posix.go`, `agent/attackpath_windows.go`, `agent/events.go`, `agent/executor.go`, `agent/executor_posix.go`, `agent/executor_windows.go`, `agent/pool_posix.go`, `agent/pool_windows.go`, `agent/usertoken_posix.go`, `agent/usertoken_windows.go` — qualify every reference to a moved type with `protocol.`, add the import.
- **Modify** `agent/integrity.go` — remove `SignBody` (moved to `agent/protocol/result.go`), keep `SelfHash` (OS-dependent, loadgen doesn't need it).
- **Modify** `agent/main.go` — remove `wsPongWait`/`wsWriteWait` (moved to `agent/protocol/websocket.go`); `wsReconnectDelay` stays (agent-specific retry pacing, distinct from loadgen's own configurable `--disconnect-rate`).
- **Create** `go.work` (repo root).
- **Create** `orchestrator/cmd/loadgen/main.go` — CLI flag parsing, fleet orchestration (spawns N simulated agents at the configured ramp rate).
- **Create** `orchestrator/cmd/loadgen/agent.go` — one simulated agent's state machine, built on `agent/protocol`.
- **Create** `orchestrator/cmd/loadgen/metrics.go` — the metrics collector (latencies, counts, active-agent gauge) and its CSV/stdout reporter.
- **Create** `orchestrator/cmd/loadgen/agent_test.go` — state-machine unit tests against a mock HTTP/WS server.
- **Create** `orchestrator/loadtest/k6/api-mix.js` — the k6 script exercising the dashboard/API workload mix.
- **Create** `orchestrator/loadtest/runbook.sh` — the combined-test runner (starts loadgen + k6 together, scrapes `/metrics` throughout, writes per-stage output files).
- **Create** `docs/load-testing-capacity-report.md` — the final written capacity report (populated by the last task, after real runs against staging).

---

### Task 1: Extract `agent/protocol` and verify the real agent is unchanged

**Files:**
- Create: `agent/protocol/messages.go`, `agent/protocol/enroll.go`, `agent/protocol/heartbeat.go`, `agent/protocol/websocket.go`, `agent/protocol/result.go`
- Delete: `agent/types.go`
- Modify: `agent/agent.go`, `agent/spool.go`, `agent/simulate.go`, `agent/detect_other.go`, `agent/detect_windows.go`, `agent/attackpath.go`, `agent/attackpath_posix.go`, `agent/attackpath_windows.go`, `agent/events.go`, `agent/executor.go`, `agent/executor_posix.go`, `agent/executor_windows.go`, `agent/pool_posix.go`, `agent/pool_windows.go`, `agent/usertoken_posix.go`, `agent/usertoken_windows.go`, `agent/integrity.go`, `agent/main.go`

**Interfaces:**
- Produces: package `audspect/agent/protocol` exporting `EnrollRequest`, `EnrollResponse`, `PolicyConf`, `PostureCheckMeta`, `Heartbeat`, `HeartbeatResponse`, `HeartbeatJobProgress`, `WSMessage`, `ScenarioCommand`, `ScenarioStep`, `LivePolicy`, `Payload`, `ExecResult`, `RawRunResult`, `SimCheckResult`, `AlertRecord`, `RunDetections`, `SchemaVersion` (const, renamed from unexported `schemaVersion`), `ProtocolVersion` (const, renamed from unexported `protocolVersion`); functions `func Enroll(ctx context.Context, client *http.Client, serverURL, agentSecret string, req EnrollRequest) (EnrollResponse, error)`, `func SendHeartbeat(ctx context.Context, client *http.Client, serverURL, agentSecret string, hb Heartbeat) (HeartbeatResponse, error)`, `func DialAgentWS(serverURL, agentID, agentSecret string) (*websocket.Conn, error)`, `func ReadMessage(conn *websocket.Conn) (WSMessage, error)`, `func SubmitResult(ctx context.Context, client *http.Client, serverURL, agentSecret string, payload RawRunResult) error`, `func SignBody(body []byte, secret string) string`.
- Consumed by: Task 2 (wire-contract tests), Task 4 (`loadgen`'s state machine).

This is the largest task in the plan. Work through the steps in order — each one keeps the build in a compilable state before moving to the next, so a mistake surfaces immediately rather than at the end.

- [ ] **Step 1: Read the current `agent/types.go` in full and copy it as the seed for the new package**

`agent/types.go` (272 lines) is already execution-free — it's the exact content to move, split into the 5 files below by topic. Read it once more immediately before this step to confirm nothing has changed since grounding.

- [ ] **Step 2: Create `agent/protocol/messages.go`**

```go
package protocol

import (
	"encoding/json"
	"time"
)

// SchemaVersion is bumped whenever the wire protocol changes in a breaking way.
const SchemaVersion = 1

// ProtocolVersion advertises the agent's run-protocol capabilities to the server.
// 2 = emits run-event stream (Phase B-1).
const ProtocolVersion = 2

// Execution stage constants — must match server-side APStage* constants.
const (
	APStageInitializing        = "initializing"
	APStageProbing             = "probing"
	APStageEnumeratingAdmins   = "enumerating_admins"
	APStageEnumeratingSessions = "enumerating_sessions"
	APStageRunningSharpHound   = "running_sharphound"
	APStageBuildingGraph       = "building_graph"
	APStageUploading           = "uploading"
)

// PolicyConf carries server-side policy down to the agent on enroll + heartbeat.
type PolicyConf struct {
	LogLevel          string   `json:"logLevel"`
	AllowedScenarios  []string `json:"allowedScenarios"`
	ExecutionWindow   string   `json:"executionWindow"`
	MaxConcurrentRuns int      `json:"maxConcurrentRuns"`
	HeartbeatInterval int      `json:"heartbeatIntervalS"`
}

// LivePolicy mirrors the server-side guardrails the agent must honour for live runs.
type LivePolicy struct {
	BlockOnDomainController bool     `json:"blockOnDomainController,omitempty"`
	RequireDCReachable      bool     `json:"requireDcReachable,omitempty"`
	MaxSprayAttempts        int      `json:"maxSprayAttempts,omitempty"`
	SprayAccountAllowlist   []string `json:"sprayAccountAllowlist,omitempty"`
	ExecutionWindow         string   `json:"executionWindow,omitempty"`
}

type WSMessage struct {
	Type    string          `json:"type"`
	AgentID string          `json:"agentId,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type ScenarioCommand struct {
	RunID      string         `json:"runId"`
	ScenarioID string         `json:"scenarioId"`
	Name       string         `json:"name"`
	Steps      []ScenarioStep `json:"steps"`
	Mode       string         `json:"mode,omitempty"`
	Policy     *LivePolicy    `json:"policy,omitempty"`
	Workers    int            `json:"workers,omitempty"`
	PreventScreenTimeout bool  `json:"preventScreenTimeout,omitempty"`
	SweepID    string `json:"sweepId,omitempty"`
	SweepName  string `json:"sweepName,omitempty"`
	SweepLabel string `json:"sweepLabel,omitempty"`
	SweepFinal bool   `json:"sweepFinal,omitempty"`
}

// ScenarioStep's Resource/Timeout fields reference internal scheduling types
// (audspect/agent/sched) that stay agent-side. To avoid agent/protocol
// depending on agent-only internals, both fields are carried as opaque
// json.RawMessage here -- the real agent decodes them into its own
// sched.ResourceProfile/sched.TimeoutProfile after receiving a
// ScenarioCommand; loadgen has no reason to decode them at all (it never
// schedules real execution).
type ScenarioStep struct {
	TaskID      string          `json:"taskId"`
	TechniqueID string          `json:"techniqueId"`
	Name        string          `json:"name"`
	Executor    string          `json:"executor"`
	Command     string          `json:"command"`
	TimeoutSec  int             `json:"timeoutSec"`
	Payloads    []Payload       `json:"payloads,omitempty"`
	Cleanup     string          `json:"cleanup,omitempty"`
	PayloadDir  string          `json:"-"`
	Resource    json.RawMessage `json:"resource,omitempty"`
	Timeout     json.RawMessage `json:"timeout,omitempty"`
	Env         map[string]string `json:"-"`
	RequiresPriv string         `json:"requiresPriv,omitempty"`
}

type Payload struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type ExecResult struct {
	TaskID          string    `json:"taskId"`
	PID             int       `json:"pid,omitempty"`
	StartedAt       time.Time `json:"startedAt,omitempty"`
	ExitCode        int       `json:"exitCode"`
	Stdout          string    `json:"stdout"`
	Stderr          string    `json:"stderr"`
	DurationMs      int64     `json:"durationMs"`
	ExecutedAt      time.Time `json:"executedAt"`
	Events          []string  `json:"events,omitempty"`
	Blocked         bool      `json:"blocked,omitempty"`
	BlockedReason   string    `json:"blockedReason,omitempty"`
	TimedOut        bool      `json:"timedOut,omitempty"`
	CleanupVerdict  string    `json:"cleanupVerdict,omitempty"`
	CleanupResidual []string  `json:"cleanupResidual,omitempty"`
	RequestedPriv   string    `json:"requestedPriv,omitempty"`
	ExecutedAs      string    `json:"executedAs,omitempty"`
}

// SimCheckResult carries the pre-interpreted result of a single built-in
// local check.
type SimCheckResult struct {
	ID            string    `json:"id"`
	TechniqueID   string    `json:"techniqueId"`
	TechniqueName string    `json:"techniqueName"`
	Tactic        string    `json:"tactic"`
	Result        string    `json:"result"`
	Severity      string    `json:"severity"`
	ThreatImpact  string    `json:"threatImpact"`
	Details       string    `json:"details"`
	Remediation   string    `json:"remediation"`
	Framework     string    `json:"framework"`
	DurationMs    int64     `json:"durationMs"`
	ExecutedAt    time.Time `json:"executedAt"`
}

type RawRunResult struct {
	RunID      string           `json:"runId"`
	ScenarioID string           `json:"scenarioId"`
	AgentID    string           `json:"agentId"`
	Results    []ExecResult     `json:"results"`
	Checks     []SimCheckResult `json:"checks,omitempty"`
	Partial    bool             `json:"partial,omitempty"`
	Reverted   []string         `json:"reverted,omitempty"`
}

// AlertRecord is one raw defensive event collected from the endpoint.
type AlertRecord struct {
	Channel     string    `json:"channel"`
	Provider    string    `json:"provider"`
	EventID     int       `json:"eventId"`
	Level       string    `json:"level"`
	Timestamp   time.Time `json:"timestamp"`
	ThreatName  string    `json:"threatName,omitempty"`
	ProcessName string    `json:"processName,omitempty"`
	ProcessPath string    `json:"processPath,omitempty"`
	CommandLine string    `json:"commandLine,omitempty"`
	User        string    `json:"user,omitempty"`
	Message     string    `json:"message,omitempty"`
}

// RunDetections is the agent's post-result detection submission for one run.
type RunDetections struct {
	RunID      string        `json:"runId"`
	AgentID    string        `json:"agentId"`
	Alerts     []AlertRecord `json:"alerts"`
	WindowFrom time.Time     `json:"windowFrom"`
	WindowTo   time.Time     `json:"windowTo"`
	Truncated  bool          `json:"truncated"`
}
```

**Design note on `ScenarioStep.Resource`/`.Timeout`:** the original fields are `*sched.ResourceProfile`/`*sched.TimeoutProfile`, types defined in `audspect/agent/sched` — an execution-scheduling package that stays agent-side (loadgen never schedules real steps, so it has no use for these). Rather than pull `sched` into `agent/protocol` (which would violate "zero execution logic" — `sched` is scheduling machinery), both fields become `json.RawMessage` in the shared type: the wire bytes still round-trip losslessly (needed so `agent.go` can decode them into the real `sched` types after receiving a `ScenarioCommand`, and so nothing is silently dropped if the orchestrator ever inspects them), but `agent/protocol` itself never depends on `sched`. `agent.go`'s `runScenario` gains two lines decoding these two fields back into `*sched.ResourceProfile`/`*sched.TimeoutProfile` right after receiving the command (Step 6 below) — everywhere else in `agent.go` already reads `step.Resource`/`step.Timeout` as the decoded pointer types, so this keeps every downstream reference unchanged.

- [ ] **Step 3: Create `agent/protocol/enroll.go`**

```go
package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// EnrollRequest is sent by the agent on first contact with the server.
type EnrollRequest struct {
	AgentID      string `json:"agentId"`
	Hostname     string `json:"hostname"`
	IPAddress    string `json:"ipAddress"`
	OSVersion    string `json:"osVersion"`
	Username     string `json:"username"`
	EnvLabel     string `json:"envLabel"`
	BinaryHash   string `json:"binaryHash,omitempty"`
	AgentVersion string `json:"agentVersion,omitempty"`

	PostureCatalog map[string][]PostureCheckMeta `json:"postureCatalog,omitempty"`
}

// PostureCheckMeta is one selectable posture check (no result — catalog only).
type PostureCheckMeta struct {
	ID          string `json:"id"`
	Phase       string `json:"phase"`
	TechniqueID string `json:"techniqueId"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
}

// EnrollResponse is returned by POST /api/agents/enroll.
type EnrollResponse struct {
	AgentID string     `json:"agentId"`
	State   string     `json:"state"`
	Policy  PolicyConf `json:"policy"`
	Trusted bool       `json:"trusted"`
}

// Enroll performs the pre-operation handshake against POST /api/agents/enroll.
// Shared by the real agent and loadgen -- this is the single network-calling
// implementation of enrollment; do not reimplement this call elsewhere.
func Enroll(ctx context.Context, client *http.Client, serverURL, agentSecret string, req EnrollRequest) (EnrollResponse, error) {
	var resp EnrollResponse
	data, err := json.Marshal(req)
	if err != nil {
		return resp, fmt.Errorf("marshal enroll request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/agents/enroll", bytes.NewReader(data))
	if err != nil {
		return resp, fmt.Errorf("new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if agentSecret != "" {
		httpReq.Header.Set("X-Agent-Token", agentSecret)
	}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return resp, fmt.Errorf("POST /api/agents/enroll: %w", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode >= 300 {
		return resp, fmt.Errorf("server %d on /api/agents/enroll", httpResp.StatusCode)
	}
	_ = json.NewDecoder(httpResp.Body).Decode(&resp) // non-fatal: old servers may return 200 with no body
	return resp, nil
}
```

- [ ] **Step 4: Create `agent/protocol/heartbeat.go`**

```go
package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type Heartbeat struct {
	AgentID       string `json:"agentId"`
	Hostname      string `json:"hostname"`
	IPAddress     string `json:"ipAddress"`
	OSVersion     string `json:"osVersion"`
	Username      string `json:"username"`
	Status        string `json:"status"`
	EnvLabel      string `json:"envLabel"`
	BinaryHash    string `json:"binaryHash,omitempty"`
	AgentVersion  string `json:"agentVersion,omitempty"`
	SchemaVersion int    `json:"schemaVersion,omitempty"`

	ProtocolVersion int  `json:"protocolVersion,omitempty"`
	EmitsEvents     bool `json:"emitsEvents,omitempty"`

	SecurityProducts []string `json:"securityProducts,omitempty"`

	CurrentJobID string               `json:"currentJobId,omitempty"`
	JobProgress  HeartbeatJobProgress `json:"jobProgress,omitempty"`
}

// HeartbeatJobProgress carries per-job collection progress in a heartbeat.
type HeartbeatJobProgress struct {
	Stage            string `json:"stage"`
	TargetsCompleted int    `json:"targetsCompleted"`
	TargetsTotal     int    `json:"targetsTotal"`
	ProgressPercent  int    `json:"progressPercent"`
}

// HeartbeatResponse is returned by every POST /api/heartbeat.
type HeartbeatResponse struct {
	State  string     `json:"state"`
	Policy PolicyConf `json:"policy"`
}

// SendHeartbeat performs one heartbeat POST /api/heartbeat. Shared by the
// real agent and loadgen -- the single network-calling implementation.
func SendHeartbeat(ctx context.Context, client *http.Client, serverURL, agentSecret string, hb Heartbeat) (HeartbeatResponse, error) {
	var resp HeartbeatResponse
	data, err := json.Marshal(hb)
	if err != nil {
		return resp, fmt.Errorf("marshal heartbeat: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/heartbeat", bytes.NewReader(data))
	if err != nil {
		return resp, fmt.Errorf("new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if agentSecret != "" {
		httpReq.Header.Set("X-Agent-Token", agentSecret)
	}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return resp, fmt.Errorf("POST /api/heartbeat: %w", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode >= 300 {
		return resp, fmt.Errorf("server %d on /api/heartbeat", httpResp.StatusCode)
	}
	_ = json.NewDecoder(httpResp.Body).Decode(&resp)
	return resp, nil
}
```

- [ ] **Step 5: Create `agent/protocol/websocket.go`**

```go
package protocol

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// wsPongWait is how long the connection may go without a server ping
	// before it's considered dead. Both the real agent and loadgen must
	// agree on this -- it's a protocol-level keepalive contract, not a
	// per-caller tuning knob.
	wsPongWait = 60 * time.Second
	// wsWriteWait bounds how long writing a pong control frame may take.
	wsWriteWait = 10 * time.Second
)

// DialAgentWS connects to /ws/agent and arms the ping/pong keepalive
// handshake. Shared by the real agent and loadgen -- the single
// network-calling implementation of the WS connect step. Reconnect timing
// is the caller's concern (the real agent and loadgen each retry
// differently), so this makes exactly one connection attempt and returns.
func DialAgentWS(serverURL, agentID, agentSecret string) (*websocket.Conn, error) {
	rawURL := strings.Replace(serverURL, "http://", "ws://", 1)
	rawURL = strings.Replace(rawURL, "https://", "wss://", 1)

	u, err := url.Parse(rawURL + "/ws/agent")
	if err != nil {
		return nil, fmt.Errorf("invalid WS URL: %w", err)
	}
	q := u.Query()
	q.Set("agentId", agentID)
	if agentSecret != "" {
		q.Set("agentSecret", agentSecret)
	}
	u.RawQuery = q.Encode()

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("WS dial: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(wsPongWait))
	conn.SetPingHandler(func(appData string) error {
		conn.SetReadDeadline(time.Now().Add(wsPongWait))
		err := conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(wsWriteWait))
		if err == websocket.ErrCloseSent {
			return nil
		}
		return err
	})
	return conn, nil
}

// ReadMessage reads and decodes one WSMessage off conn, extending the read
// deadline on every inbound frame (any frame is proof of life). Shared by
// the real agent and loadgen.
func ReadMessage(conn *websocket.Conn) (WSMessage, error) {
	var msg WSMessage
	_, data, err := conn.ReadMessage()
	if err != nil {
		return msg, err
	}
	conn.SetReadDeadline(time.Now().Add(wsPongWait))
	if err := json.Unmarshal(data, &msg); err != nil {
		return msg, fmt.Errorf("decode WSMessage: %w", err)
	}
	return msg, nil
}
```

- [ ] **Step 6: Create `agent/protocol/result.go`**

```go
package protocol

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
)

// SignBody returns the hex-encoded HMAC-SHA256 of body keyed with secret.
// Used to sign result payloads so the orchestrator can detect tampered
// results. Moved from agent/integrity.go -- SelfHash (binary self-hashing)
// stayed there since it's OS-dependent and loadgen has no use for it.
func SignBody(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// SubmitResult performs one POST /api/scenarios/result, signing the body
// when agentSecret is set (X-Result-MAC), exactly as the real agent's
// postJSONDecode already special-cases this one path. Shared by the real
// agent and loadgen -- the single network-calling implementation. The real
// agent's own submitRunResult/spool durability logic wraps this; loadgen
// calls it directly since it has no durable-delivery requirement (a lost
// fake result is just a data point, not a real assessment).
func SubmitResult(ctx context.Context, client *http.Client, serverURL, agentSecret string, payload RawRunResult) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/scenarios/result", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if agentSecret != "" {
		req.Header.Set("X-Agent-Token", agentSecret)
		req.Header.Set("X-Result-MAC", SignBody(data, agentSecret))
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST /api/scenarios/result: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server %d on /api/scenarios/result", resp.StatusCode)
	}
	return nil
}
```

- [ ] **Step 7: Delete `agent/types.go`**

Its entire content is now in `agent/protocol`.

- [ ] **Step 8: Update `agent/agent.go`**

Add the import:
```go
	"audspect/agent/protocol"
```

Replace every bare reference to a moved type with its `protocol.`-qualified name: `Heartbeat`→`protocol.Heartbeat`, `HeartbeatResponse`→`protocol.HeartbeatResponse`, `HeartbeatJobProgress`→`protocol.HeartbeatJobProgress`, `EnrollRequest`→`protocol.EnrollRequest`, `EnrollResponse`→`protocol.EnrollResponse`, `WSMessage`→`protocol.WSMessage`, `ScenarioCommand`→`protocol.ScenarioCommand`, `RawRunResult`→`protocol.RawRunResult`, `SimCheckResult`→`protocol.SimCheckResult`, `RunDetections`→`protocol.RunDetections`, `ExecResult`→`protocol.ExecResult` (in `runScenario`/`submitResults`/`runLocalScan` signatures and literals).

Rewrite `enrollWithServer` to call the shared function instead of `postJSONDecode` directly:
```go
func (a *Agent) enrollWithServer() {
	req := protocol.EnrollRequest{
		AgentID:        a.id.AgentID,
		Hostname:       a.id.Hostname,
		IPAddress:      a.id.IPAddress,
		OSVersion:      a.id.OSVersion,
		Username:       a.id.Username,
		EnvLabel:       a.cfg.EnvLabel,
		BinaryHash:     a.binaryHash,
		AgentVersion:   version,
		PostureCatalog: BuildPostureCatalog(),
	}
	resp, err := protocol.Enroll(context.Background(), a.client, a.cfg.ServerURL, a.cfg.AgentSecret, req)
	if err != nil {
		log.Printf("[!] enrollment failed: %v — continuing; will retry on reconnect", err)
		return
	}
	a.mu.Lock()
	a.state = resp.State
	a.mu.Unlock()
	log.Printf("[+] enrolled — state=%s trusted=%v", resp.State, resp.Trusted)
	a.logger.Op("info", "lifecycle", fmt.Sprintf("enrolled — state=%s trusted=%v version=%s",
		resp.State, resp.Trusted, version))
	if resp.State == "quarantined" {
		log.Printf("[!] AGENT IS QUARANTINED — scenario execution blocked; contact your BAS administrator")
		a.logger.Op("error", "lifecycle", "agent quarantined — contact administrator to resolve before running scenarios")
	}
}
```

Rewrite `sendHeartbeat` to call the shared function, preserving every existing side effect (outage timestamp, spool kick, latency metric, state-transition logging) exactly as before:
```go
func (a *Agent) sendHeartbeat(status string) {
	a.mu.Lock()
	products := a.secProducts
	jobID := a.currentJobID
	jobStage := a.currentJobStage
	jobCompleted := a.currentJobCompleted
	jobTotal := a.currentJobTotal
	jobPercent := a.currentJobPercent
	a.mu.Unlock()
	hb := protocol.Heartbeat{
		AgentID:       a.id.AgentID,
		Hostname:      a.id.Hostname,
		IPAddress:     a.id.IPAddress,
		OSVersion:     a.id.OSVersion,
		Username:      a.id.Username,
		Status:        status,
		EnvLabel:      a.cfg.EnvLabel,
		BinaryHash:    a.binaryHash,
		AgentVersion:  version,
		SchemaVersion: protocol.SchemaVersion,

		ProtocolVersion:  protocol.ProtocolVersion,
		EmitsEvents:      true,
		SecurityProducts: products,
	}
	if jobID != "" {
		hb.CurrentJobID = jobID
		hb.JobProgress = protocol.HeartbeatJobProgress{
			Stage:            jobStage,
			TargetsCompleted: jobCompleted,
			TargetsTotal:     jobTotal,
			ProgressPercent:  jobPercent,
		}
	}
	t0 := time.Now()
	resp, err := protocol.SendHeartbeat(context.Background(), a.client, a.cfg.ServerURL, a.cfg.AgentSecret, hb)
	if err != nil {
		log.Printf("[!] heartbeat: %v", err)
		a.logger.Op("warn", "connectivity", fmt.Sprintf("heartbeat failed: %v", err))
		a.mu.Lock()
		if a.disconnectedSince.IsZero() {
			a.disconnectedSince = time.Now()
		}
		a.mu.Unlock()
		a.localSt.SetConnected(false)
		return
	}
	a.mu.Lock()
	a.disconnectedSince = time.Time{}
	a.watchdogTripped = false
	a.mu.Unlock()
	a.localSt.SetConnected(true)
	a.kickSpool()
	latencyMs := float64(time.Since(t0).Milliseconds())
	a.logger.Metric("heartbeat_latency_ms", latencyMs, "ms")

	if resp.State != "" {
		a.mu.Lock()
		prev := a.state
		a.state = resp.State
		a.mu.Unlock()
		if resp.State == "quarantined" && prev != "quarantined" {
			log.Printf("[!] SERVER HAS QUARANTINED THIS AGENT — scenario execution blocked; contact administrator")
			a.logger.Op("error", "lifecycle", "server quarantined this agent — contact administrator")
		}
	}
	log.Printf("[~] heartbeat: %s (state=%s latency=%.0fms)", status, resp.State, latencyMs)
}
```

Rewrite `connectWS`'s dial + read loop to use `protocol.DialAgentWS`/`protocol.ReadMessage`, keeping every existing `switch msg.Type` case and its dispatch behavior completely unchanged:
```go
func (a *Agent) connectWS() {
	for {
		conn, err := protocol.DialAgentWS(a.cfg.ServerURL, a.id.AgentID, a.cfg.AgentSecret)
		if err != nil {
			log.Printf("[!] WS connect failed: %v — retry in 5s", err)
			time.Sleep(wsReconnectDelay)
			continue
		}
		log.Printf("[+] WS connected: %s", a.cfg.ServerURL)
		a.logger.Op("info", "connectivity", fmt.Sprintf("WebSocket connected to %s", a.cfg.ServerURL))
		go a.logger.Flush()

		for {
			msg, err := protocol.ReadMessage(conn)
			if err != nil {
				log.Printf("[!] WS read: %v — reconnecting", err)
				a.logger.Op("warn", "connectivity", fmt.Sprintf("WebSocket disconnected: %v", err))
				conn.Close()
				break
			}

			switch msg.Type {
			case "command_scenario":
				var cmd protocol.ScenarioCommand
				if err := json.Unmarshal(msg.Data, &cmd); err != nil {
					log.Printf("[!] WS: bad scenario command: %v", err)
					continue
				}
				ctx, cancel := context.WithCancel(context.Background())
				a.scenarioMu.Lock()
				if a.cancelScenario != nil {
					a.cancelScenario()
				}
				a.cancelScenario = cancel
				a.scenarioMu.Unlock()
				a.runWG.Add(1)
				go func() { defer a.runWG.Done(); a.runScenario(ctx, cmd) }()

			case "command_simulate":
				var sim struct {
					ScenarioID string   `json:"scenarioId"`
					RunID      string   `json:"runId"`
					Checks     []string `json:"checks"`
				}
				if err := json.Unmarshal(msg.Data, &sim); err != nil || sim.ScenarioID == "" {
					log.Printf("[!] WS: bad command_simulate payload: %v", err)
					continue
				}
				ctx, cancel := context.WithCancel(context.Background())
				a.scenarioMu.Lock()
				if a.cancelScenario != nil {
					a.cancelScenario()
				}
				a.cancelScenario = cancel
				a.scenarioMu.Unlock()
				a.runWG.Add(1)
				go func() { defer a.runWG.Done(); a.runLocalScan(ctx, sim.ScenarioID, sim.RunID, sim.Checks) }()

			case "command_attackpath_collect":
				var apc AttackPathCollectCommand
				if err := json.Unmarshal(msg.Data, &apc); err != nil {
					log.Printf("[!] WS: bad attackpath collect payload: %v", err)
					continue
				}
				a.runWG.Add(1)
				go func() { defer a.runWG.Done(); a.runAttackPathCollect(apc) }()

			case "command_cancel":
				if a.cancelCurrentScenario() {
					log.Printf("[*] scenario cancelled by operator")
					a.logger.Op("warn", "lifecycle", "scenario stopped by operator request")
				} else {
					log.Printf("[~] command_cancel received but no scenario is running")
				}

			case "command_pause":
				if a.pauseCurrentScenario() {
					log.Printf("[*] scenario paused by operator")
					a.logger.Op("info", "lifecycle", "scenario paused by operator request")
				} else {
					log.Printf("[~] command_pause received but no scenario is running")
				}

			case "command_resume":
				if a.resumeCurrentScenario() {
					log.Printf("[*] scenario resumed by operator")
					a.logger.Op("info", "lifecycle", "scenario resumed by operator request")
				} else {
					log.Printf("[~] command_resume received but no scenario is running")
				}

			case "command_stop_agent":
				var body struct {
					Reason string `json:"reason"`
				}
				if err := json.Unmarshal(msg.Data, &body); err != nil {
					log.Printf("[!] WS: bad stop command: %v", err)
					continue
				}
				go a.stopSelf(body.Reason)

			case "command_uninstall_agent":
				var body struct {
					Reason string `json:"reason"`
				}
				if err := json.Unmarshal(msg.Data, &body); err != nil {
					log.Printf("[!] WS: bad uninstall command: %v", err)
					continue
				}
				go a.uninstallSelf(body.Reason)

			default:
				log.Printf("[~] WS: unhandled message type %q", msg.Type)
			}
		}

		time.Sleep(wsReconnectDelay)
	}
}
```

(The `msg` variable's declaration moves from `var msg WSMessage; json.Unmarshal(data, &msg)` to being returned directly by `protocol.ReadMessage` — the surrounding `switch` body is otherwise byte-for-byte identical to the pre-refactor version.)

In `runScenario`, immediately after the existing local-state guard (right after the `if st == "quarantined" ...` block, before the function uses `cmd.Steps` for anything else), decode each step's opaque `Resource`/`Timeout` fields back into the real scheduling types so every downstream reference (`step.Resource`, `step.Timeout`) keeps working exactly as before:
```go
	for i := range cmd.Steps {
		if len(cmd.Steps[i].Resource) > 0 {
			var rp sched.ResourceProfile
			if err := json.Unmarshal(cmd.Steps[i].Resource, &rp); err == nil {
				cmd.Steps[i].ResourceDecoded = &rp
			}
		}
		if len(cmd.Steps[i].Timeout) > 0 {
			var tp sched.TimeoutProfile
			if err := json.Unmarshal(cmd.Steps[i].Timeout, &tp); err == nil {
				cmd.Steps[i].TimeoutDecoded = &tp
			}
		}
	}
```

This requires adding two agent-local (not wire) fields to how `runScenario` accesses them: since `protocol.ScenarioStep.Resource`/`.Timeout` are now `json.RawMessage`, every place `agent.go`/`executor_*.go`/`pool_*.go`/`usertoken_*.go` currently reads `step.Resource`/`step.Timeout` as a typed pointer needs the decoded value instead. Add a small agent-local wrapper immediately after the decode loop above:
```go
	type decodedStep struct {
		protocol.ScenarioStep
		ResourceDecoded *sched.ResourceProfile
		TimeoutDecoded  *sched.TimeoutProfile
	}
```
and change `runScenario`'s `step := cmd.Steps[i]` (in the per-job loop) to build a `decodedStep` combining the wire step with its decoded fields, then pass `step.ResourceDecoded`/`step.TimeoutDecoded` wherever `step.Resource`/`step.Timeout` was read before. **Ground this exact wiring against the current per-job loop body (`for i := range cmd.Steps { step := cmd.Steps[i] ...}`, previously read in full during this plan's grounding) before writing the final diff** — the goal is that every one of `executeSeconds(step)`, `graceSeconds(step)`, `execStep(...)`, `pool.Run(...)`, `pooledCandidate(step)`, `runCleanup(step)`, `applyExecutionContext(...)`, `buildCmd(...)`, `buildUserEnv(...)`, `buildPosixUserEnv(...)`, `agentContextFor(step)` (all found referencing `ScenarioStep` in Step 9 below) keep receiving the same decoded `*sched.ResourceProfile`/`*sched.TimeoutProfile` shape they always have — only the two fields' *origin* (decoded from `json.RawMessage` instead of unmarshaled directly) changed, not their type at the call sites that matter.

- [ ] **Step 9: Update the 12 execution files with mechanical `protocol.` qualifiers**

Each of these files only needs an added import (`"audspect/agent/protocol"`) and the listed bare identifiers qualified — no logic changes:

| File | Identifiers to qualify |
|---|---|
| `agent/attackpath.go` | `Payload` (line 32: `SharpHoundPayload *Payload`) |
| `agent/attackpath_posix.go` | `Payload` (line 20: `func runSharpHound(_ *Payload, ...)`) |
| `agent/attackpath_windows.go` | `Payload` (lines 89, 99) |
| `agent/events.go` | `ExecResult` (line 24: `func eventForResult(r ExecResult) ...`) |
| `agent/executor.go` | `Payload`, `ScenarioStep`, `ExecResult` (lines 32, 55, 71, 82, 89, 173, 269) |
| `agent/executor_posix.go` | `ScenarioStep` (lines 14, 25, 59) |
| `agent/executor_windows.go` | `ScenarioStep` (lines 37, 125, 157) — plus decode `step.Resource`/`step.Timeout` the same way as Step 8's `decodedStep`, since `buildCmd`/`applyExecutionContext`/`runCleanup` are exactly the functions that read them |
| `agent/pool_posix.go` | `ScenarioStep`, `ExecResult` (lines 16, 20, 21) |
| `agent/pool_windows.go` | `ScenarioStep`, `ExecResult` (lines 174, 187, 193, 197, 199, 211, 271, 274, 306) |
| `agent/spool.go` | `RawRunResult` (lines 43, 67) |
| `agent/usertoken_posix.go` | `ScenarioStep` (line 121) |
| `agent/usertoken_windows.go` | `ScenarioStep` (lines 170, 196, 260) |

Also qualify `agent/simulate.go`'s `PostureCheckMeta` (lines 135, 136, 139, 152, 153) and `agent/detect_other.go`/`agent/detect_windows.go`'s `AlertRecord`.

- [ ] **Step 10: Update `agent/integrity.go`**

Remove the `SignBody` function (moved to `agent/protocol/result.go`); keep `SelfHash` and its imports (`crypto/sha256`, `encoding/hex`, `fmt`, `io`, `os` stay — `crypto/hmac` is removed since only `SignBody` used it).

- [ ] **Step 11: Update `agent/main.go`**

Remove the `wsPongWait`/`wsWriteWait` const declarations (moved to `agent/protocol/websocket.go`). Leave `wsReconnectDelay = 5 * time.Second` in place.

- [ ] **Step 12: Build the `agent` module**

Run: `cd agent && go build ./...`
Expected: success, no errors. Fix any remaining unqualified references the table above missed — the compiler will name the exact file and line.

- [ ] **Step 13: Run the full existing `agent` test suite**

Run: `cd agent && go test ./...`
Expected: PASS, identical results to before this task started (same test names, same pass count). This is the behavioral-preservation gate — if anything here fails or changes, Task 1 is not done regardless of how clean the new package looks.

- [ ] **Step 14: Commit**

```bash
git add agent/protocol agent/types.go agent/agent.go agent/spool.go agent/simulate.go agent/detect_other.go agent/detect_windows.go agent/attackpath.go agent/attackpath_posix.go agent/attackpath_windows.go agent/events.go agent/executor.go agent/executor_posix.go agent/executor_windows.go agent/pool_posix.go agent/pool_windows.go agent/usertoken_posix.go agent/usertoken_windows.go agent/integrity.go agent/main.go
git commit -m "refactor: extract agent/protocol -- execution-free wire protocol package"
git push
```

---

### Task 2: Protocol wire-contract tests

**Files:**
- Create: `agent/protocol/messages_test.go`, `agent/protocol/enroll_test.go`, `agent/protocol/heartbeat_test.go`, `agent/protocol/websocket_test.go`, `agent/protocol/result_test.go`

**Interfaces:**
- Consumes: everything Task 1 exported from `agent/protocol`.

- [ ] **Step 1: Write enrollment wire-contract tests**

```go
// agent/protocol/enroll_test.go
package protocol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnroll_SendsExpectedRequestShape(t *testing.T) {
	var gotBody EnrollRequest
	var gotHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Agent-Token")
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(EnrollResponse{AgentID: "a1", State: "active", Trusted: true})
	}))
	defer server.Close()

	req := EnrollRequest{AgentID: "a1", Hostname: "H", EnvLabel: "prod"}
	resp, err := Enroll(context.Background(), server.Client(), server.URL, "secret123", req)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if gotBody.AgentID != "a1" || gotBody.Hostname != "H" || gotBody.EnvLabel != "prod" {
		t.Errorf("server received %+v, want AgentID=a1 Hostname=H EnvLabel=prod", gotBody)
	}
	if gotHeader != "secret123" {
		t.Errorf("X-Agent-Token = %q, want secret123", gotHeader)
	}
	if resp.State != "active" || !resp.Trusted {
		t.Errorf("resp = %+v, want State=active Trusted=true", resp)
	}
}

func TestEnroll_ServerErrorReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := Enroll(context.Background(), server.Client(), server.URL, "", EnrollRequest{})
	if err == nil {
		t.Fatal("Enroll: want error on server 500, got nil")
	}
}

func TestEnroll_MalformedResponseBodyDoesNotError(t *testing.T) {
	// Old server versions return 200 with no body -- must not fail the call.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := Enroll(context.Background(), server.Client(), server.URL, "", EnrollRequest{})
	if err != nil {
		t.Fatalf("Enroll with empty 200 body: %v, want nil", err)
	}
}
```

- [ ] **Step 2: Write heartbeat wire-contract tests**

```go
// agent/protocol/heartbeat_test.go
package protocol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSendHeartbeat_RoundTripsJobProgress(t *testing.T) {
	var gotBody Heartbeat
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(HeartbeatResponse{State: "active"})
	}))
	defer server.Close()

	hb := Heartbeat{
		AgentID: "a1", Status: "scanning",
		CurrentJobID: "job1",
		JobProgress:  HeartbeatJobProgress{Stage: APStageProbing, TargetsCompleted: 3, TargetsTotal: 10, ProgressPercent: 30},
	}
	resp, err := SendHeartbeat(context.Background(), server.Client(), server.URL, "", hb)
	if err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	if gotBody.JobProgress.Stage != APStageProbing || gotBody.JobProgress.TargetsCompleted != 3 {
		t.Errorf("server received JobProgress = %+v, want Stage=%s TargetsCompleted=3", gotBody.JobProgress, APStageProbing)
	}
	if resp.State != "active" {
		t.Errorf("resp.State = %q, want active", resp.State)
	}
}

func TestSendHeartbeat_ConnectionRefusedReturnsError(t *testing.T) {
	_, err := SendHeartbeat(context.Background(), http.DefaultClient, "http://127.0.0.1:1", "", Heartbeat{})
	if err == nil {
		t.Fatal("SendHeartbeat: want error against an unreachable host, got nil")
	}
}
```

- [ ] **Step 3: Write WS wire-contract tests**

```go
// agent/protocol/websocket_test.go
package protocol

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestDialAgentWS_ConnectsAndReadsMessage(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("agentId") != "a1" {
			t.Errorf("agentId query param = %q, want a1", r.URL.Query().Get("agentId"))
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.WriteJSON(WSMessage{Type: "command_cancel"})
	}))
	defer server.Close()
	httpURL := strings.Replace(server.URL, "http://", "http://", 1)

	conn, err := DialAgentWS(httpURL, "a1", "")
	if err != nil {
		t.Fatalf("DialAgentWS: %v", err)
	}
	defer conn.Close()

	msg, err := ReadMessage(conn)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if msg.Type != "command_cancel" {
		t.Errorf("msg.Type = %q, want command_cancel", msg.Type)
	}
}

func TestReadMessage_MalformedFrameReturnsError(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.WriteMessage(websocket.TextMessage, []byte("not json"))
	}))
	defer server.Close()

	conn, err := DialAgentWS(server.URL, "a1", "")
	if err != nil {
		t.Fatalf("DialAgentWS: %v", err)
	}
	defer conn.Close()

	if _, err := ReadMessage(conn); err == nil {
		t.Fatal("ReadMessage: want error decoding malformed JSON, got nil")
	}
}

func TestScenarioCommand_DecodesFromRealisticPayload(t *testing.T) {
	// Captures the shape a real dispatch takes -- ScenarioStep.Resource/.Timeout
	// arrive as opaque JSON objects and must round-trip without error even
	// though agent/protocol never decodes their internal shape.
	raw := `{"runId":"r1","scenarioId":"s1","name":"Test","steps":[
		{"taskId":"t1","techniqueId":"T1003","name":"Dump","executor":"powershell","command":"...",
		 "resource":{"kind":"credential_access","exclusive":true},
		 "timeout":{"scheduleSec":30,"executeSec":60}}
	]}`
	var cmd ScenarioCommand
	if err := json.Unmarshal([]byte(raw), &cmd); err != nil {
		t.Fatalf("Unmarshal ScenarioCommand: %v", err)
	}
	if len(cmd.Steps) != 1 || cmd.Steps[0].TaskID != "t1" {
		t.Fatalf("cmd.Steps = %+v, want 1 step with TaskID=t1", cmd.Steps)
	}
	if len(cmd.Steps[0].Resource) == 0 || len(cmd.Steps[0].Timeout) == 0 {
		t.Error("Resource/Timeout raw JSON not preserved")
	}
}
```

- [ ] **Step 4: Write result-submission wire-contract tests**

```go
// agent/protocol/result_test.go
package protocol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubmitResult_SignsBodyWhenSecretSet(t *testing.T) {
	var gotMAC string
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMAC = r.Header.Get("X-Result-MAC")
		gotBody, _ = io.ReadAll(r.Body)
	}))
	defer server.Close()

	payload := RawRunResult{RunID: "r1", AgentID: "a1"}
	if err := SubmitResult(context.Background(), server.Client(), server.URL, "secret123", payload); err != nil {
		t.Fatalf("SubmitResult: %v", err)
	}
	want := SignBody(gotBody, "secret123")
	if gotMAC != want {
		t.Errorf("X-Result-MAC = %q, want %q", gotMAC, want)
	}
}

func TestSubmitResult_NoSecretOmitsMACHeader(t *testing.T) {
	var gotMAC string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMAC = r.Header.Get("X-Result-MAC")
	}))
	defer server.Close()

	if err := SubmitResult(context.Background(), server.Client(), server.URL, "", RawRunResult{}); err != nil {
		t.Fatalf("SubmitResult: %v", err)
	}
	if gotMAC != "" {
		t.Errorf("X-Result-MAC = %q, want empty when no secret configured", gotMAC)
	}
}

func TestSignBody_DeterministicAndSecretSensitive(t *testing.T) {
	body := []byte(`{"runId":"r1"}`)
	a := SignBody(body, "secret-a")
	b := SignBody(body, "secret-a")
	c := SignBody(body, "secret-b")
	if a != b {
		t.Error("SignBody is not deterministic for the same body+secret")
	}
	if a == c {
		t.Error("SignBody produced the same MAC for two different secrets")
	}
}
```

Add `"io"` to `result_test.go`'s imports.

- [ ] **Step 5: Run the new tests**

Run: `cd agent && go test ./protocol/... -v`
Expected: PASS, all tests listed above green.

- [ ] **Step 6: Commit**

```bash
git add agent/protocol/messages_test.go agent/protocol/enroll_test.go agent/protocol/heartbeat_test.go agent/protocol/websocket_test.go agent/protocol/result_test.go
git commit -m "test: add wire-contract tests for agent/protocol"
git push
```

(`messages_test.go` can stay a near-empty placeholder-free file with a single `package protocol` line plus a short doc comment noting the wire-shape tests for message types live alongside the function that uses them — Go requires the file to exist per the File Structure section, but there's no free-standing behavior to test in `messages.go` beyond what Steps 1-4 above already exercise through `Enroll`/`SendHeartbeat`/`ReadMessage`/`SubmitResult`.)

---

### Task 3: `go.work` and CI verification

**Files:**
- Create: `go.work` (repo root)

**Interfaces:**
- Consumes: `agent` module (`audspect/agent`), `orchestrator` module (`github.com/audspect/bas`) — both already `go 1.26.0`.

- [ ] **Step 1: Create `go.work`**

```
go 1.26.0

use (
	./agent
	./orchestrator
)
```

- [ ] **Step 2: Verify the orchestrator module still builds and tests standalone**

Run: `cd orchestrator && go build ./... && go vet ./...`
Expected: success — confirms workspace mode doesn't change what `orchestrator`'s own `./...` resolves to.

- [ ] **Step 3: Verify the agent module still builds and tests standalone**

Run: `cd agent && go build ./... && go test ./...`
Expected: success — the same regression check as Task 1 Step 13, re-run now that `go.work` is present, to catch any workspace-mode-only build difference.

- [ ] **Step 4: Commit**

```bash
git add go.work
git commit -m "build: add go.work workspace for agent+orchestrator"
git push
```

(This step's CI-still-green confirmation happens for real once Task 4 lands `orchestrator/cmd/loadgen` — the first thing that actually imports across the workspace boundary. Re-verify then, not now, since there's nothing cross-module to break yet.)

---

### Task 4: `loadgen` — state machine, config, metrics

**Files:**
- Create: `orchestrator/cmd/loadgen/main.go`
- Create: `orchestrator/cmd/loadgen/agent.go`
- Create: `orchestrator/cmd/loadgen/metrics.go`

**Interfaces:**
- Consumes: `agent/protocol.{EnrollRequest, EnrollResponse, Heartbeat, HeartbeatResponse, HeartbeatJobProgress, WSMessage, ScenarioCommand, RawRunResult, ExecResult, Enroll, SendHeartbeat, DialAgentWS, ReadMessage, SubmitResult}` (Task 1).
- Produces: `type Config struct` (CLI-flag-derived run config), `type simulatedAgent struct` + `func newSimulatedAgent(...) *simulatedAgent` + `func (s *simulatedAgent) run(ctx context.Context)`, `type Metrics struct` + recording methods, consumed by Task 5 (unit tests) and Task 6 (real-server validation).

- [ ] **Step 1: Create `orchestrator/cmd/loadgen/metrics.go`**

```go
package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics aggregates client-side observations across every simulated agent
// in one loadgen run. All fields are safe for concurrent use.
type Metrics struct {
	activeAgents int64 // atomic gauge

	mu                    sync.Mutex
	enrollLatencies       []time.Duration
	wsConnectLatencies    []time.Duration
	heartbeatOK           int64
	heartbeatFailed       int64
	dispatchLatencies     []time.Duration
	resultSubmitLatencies []time.Duration
	reconnectLatencies    []time.Duration
	connectionDrops       int64
	protocolErrors        int64
	httpErrors            int64
	messagesTotal         int64
	resultsTotal          int64
}

func NewMetrics() *Metrics { return &Metrics{} }

func (m *Metrics) AgentStarted()   { atomic.AddInt64(&m.activeAgents, 1) }
func (m *Metrics) AgentStopped()   { atomic.AddInt64(&m.activeAgents, -1) }
func (m *Metrics) ActiveAgents() int64 { return atomic.LoadInt64(&m.activeAgents) }

func (m *Metrics) RecordEnroll(d time.Duration) {
	m.mu.Lock()
	m.enrollLatencies = append(m.enrollLatencies, d)
	m.mu.Unlock()
}
func (m *Metrics) RecordWSConnect(d time.Duration) {
	m.mu.Lock()
	m.wsConnectLatencies = append(m.wsConnectLatencies, d)
	m.mu.Unlock()
}
func (m *Metrics) RecordHeartbeat(ok bool) {
	if ok {
		atomic.AddInt64(&m.heartbeatOK, 1)
	} else {
		atomic.AddInt64(&m.heartbeatFailed, 1)
	}
}
func (m *Metrics) RecordDispatch(d time.Duration) {
	m.mu.Lock()
	m.dispatchLatencies = append(m.dispatchLatencies, d)
	m.mu.Unlock()
	atomic.AddInt64(&m.messagesTotal, 1)
}
func (m *Metrics) RecordResultSubmit(d time.Duration) {
	m.mu.Lock()
	m.resultSubmitLatencies = append(m.resultSubmitLatencies, d)
	m.mu.Unlock()
	atomic.AddInt64(&m.resultsTotal, 1)
}
func (m *Metrics) RecordReconnect(d time.Duration) {
	m.mu.Lock()
	m.reconnectLatencies = append(m.reconnectLatencies, d)
	m.mu.Unlock()
}
func (m *Metrics) RecordConnectionDrop() { atomic.AddInt64(&m.connectionDrops, 1) }
func (m *Metrics) RecordProtocolError()  { atomic.AddInt64(&m.protocolErrors, 1) }
func (m *Metrics) RecordHTTPError()      { atomic.AddInt64(&m.httpErrors, 1) }

// Snapshot is a point-in-time, human-readable summary.
type Snapshot struct {
	ActiveAgents       int64
	HeartbeatOK        int64
	HeartbeatFailed    int64
	ConnectionDrops    int64
	ProtocolErrors     int64
	HTTPErrors         int64
	MessagesTotal      int64
	ResultsTotal       int64
	EnrollP50, EnrollP95       time.Duration
	WSConnectP50, WSConnectP95 time.Duration
	DispatchP50, DispatchP95   time.Duration
	ResultP50, ResultP95       time.Duration
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func (m *Metrics) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	enroll := sortedCopy(m.enrollLatencies)
	ws := sortedCopy(m.wsConnectLatencies)
	dispatch := sortedCopy(m.dispatchLatencies)
	result := sortedCopy(m.resultSubmitLatencies)
	return Snapshot{
		ActiveAgents:    atomic.LoadInt64(&m.activeAgents),
		HeartbeatOK:     m.heartbeatOK,
		HeartbeatFailed: m.heartbeatFailed,
		ConnectionDrops: m.connectionDrops,
		ProtocolErrors:  m.protocolErrors,
		HTTPErrors:      m.httpErrors,
		MessagesTotal:   m.messagesTotal,
		ResultsTotal:    m.resultsTotal,
		EnrollP50: percentile(enroll, 0.50), EnrollP95: percentile(enroll, 0.95),
		WSConnectP50: percentile(ws, 0.50), WSConnectP95: percentile(ws, 0.95),
		DispatchP50: percentile(dispatch, 0.50), DispatchP95: percentile(dispatch, 0.95),
		ResultP50: percentile(result, 0.50), ResultP95: percentile(result, 0.95),
	}
}

func sortedCopy(in []time.Duration) []time.Duration {
	out := make([]time.Duration, len(in))
	copy(out, in)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

func (s Snapshot) String() string {
	return fmt.Sprintf(
		"active=%d hb_ok=%d hb_fail=%d drops=%d proto_err=%d http_err=%d msgs=%d results=%d "+
			"enroll_p50=%s enroll_p95=%s ws_p50=%s ws_p95=%s dispatch_p50=%s dispatch_p95=%s result_p50=%s result_p95=%s",
		s.ActiveAgents, s.HeartbeatOK, s.HeartbeatFailed, s.ConnectionDrops, s.ProtocolErrors, s.HTTPErrors, s.MessagesTotal, s.ResultsTotal,
		s.EnrollP50, s.EnrollP95, s.WSConnectP50, s.WSConnectP95, s.DispatchP50, s.DispatchP95, s.ResultP50, s.ResultP95,
	)
}
```

(A basic insertion sort is intentional — loadgen's per-interval sample counts are small enough for this to be irrelevant to overhead, and it keeps the file free of a sort-import dependency footgun around reusing the same backing array. If a later interval's data volume ever makes this measurably slow, switch to `slices.Sort` then — YAGNI for now.)

- [ ] **Step 2: Create `orchestrator/cmd/loadgen/agent.go`**

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"audspect/agent/protocol"
)

// simConfig holds one simulated agent's run parameters, derived from the
// process-wide Config (main.go) plus this agent's index.
type simConfig struct {
	ServerURL         string
	AgentSecret       string
	AgentID           string
	Hostname          string
	Heartbeat         time.Duration
	ExecutionLatency  time.Duration
	ResultSizeBytes   int
	DisconnectRate    float64 // 0.0-1.0, chance per heartbeat interval of a forced reconnect
}

type simulatedAgent struct {
	cfg     simConfig
	metrics *Metrics
	client  *http.Client
}

func newSimulatedAgent(cfg simConfig, metrics *Metrics) *simulatedAgent {
	return &simulatedAgent{
		cfg:     cfg,
		metrics: metrics,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// run drives one simulated agent through its full lifecycle until ctx is
// cancelled: ENROLL -> WS CONNECT -> HEARTBEAT LOOP + WAIT FOR DISPATCH ->
// (on dispatch) SIMULATE EXECUTION -> SUBMIT RESULT -> back to waiting.
// Execution is always fake (a configurable sleep + a synthetic result),
// never the real agent's technique-execution path -- this deliberately
// tests control-plane behavior, not endpoint execution.
func (s *simulatedAgent) run(ctx context.Context) {
	s.metrics.AgentStarted()
	defer s.metrics.AgentStopped()

	t0 := time.Now()
	_, err := protocol.Enroll(ctx, s.client, s.cfg.ServerURL, s.cfg.AgentSecret, protocol.EnrollRequest{
		AgentID:      s.cfg.AgentID,
		Hostname:     s.cfg.Hostname,
		EnvLabel:     "loadgen",
		AgentVersion: "loadgen-1.0",
	})
	s.metrics.RecordEnroll(time.Since(t0))
	if err != nil {
		s.metrics.RecordHTTPError()
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := s.connectAndServe(ctx); err != nil {
			s.metrics.RecordConnectionDrop()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// connectAndServe holds one WS connection open, sending heartbeats on the
// configured interval and reacting to any dispatched scenario, until the
// connection drops, ctx is cancelled, or the configured disconnect-rate
// randomly forces a reconnect (to exercise the real agent's reconnect path
// under load).
func (s *simulatedAgent) connectAndServe(ctx context.Context) error {
	t0 := time.Now()
	conn, err := protocol.DialAgentWS(s.cfg.ServerURL, s.cfg.AgentID, s.cfg.AgentSecret)
	if err != nil {
		s.metrics.RecordHTTPError()
		return err
	}
	s.metrics.RecordWSConnect(time.Since(t0))
	defer conn.Close()

	msgCh := make(chan protocol.WSMessage, 8)
	errCh := make(chan error, 1)
	go func() {
		for {
			msg, err := protocol.ReadMessage(conn)
			if err != nil {
				errCh <- err
				return
			}
			msgCh <- msg
		}
	}()

	hbTicker := time.NewTicker(s.cfg.Heartbeat)
	defer hbTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			_ = err
			return fmt.Errorf("WS read: %w", err)
		case msg := <-msgCh:
			s.handleMessage(ctx, msg)
		case <-hbTicker.C:
			ok := s.sendHeartbeat(ctx)
			s.metrics.RecordHeartbeat(ok)
			if s.cfg.DisconnectRate > 0 && rand.Float64() < s.cfg.DisconnectRate {
				return nil // forced reconnect -- exercises the real agent's reconnect path
			}
		}
	}
}

func (s *simulatedAgent) sendHeartbeat(ctx context.Context) bool {
	_, err := protocol.SendHeartbeat(ctx, s.client, s.cfg.ServerURL, s.cfg.AgentSecret, protocol.Heartbeat{
		AgentID:         s.cfg.AgentID,
		Hostname:        s.cfg.Hostname,
		Status:          "idle",
		EnvLabel:        "loadgen",
		AgentVersion:    "loadgen-1.0",
		SchemaVersion:   protocol.SchemaVersion,
		ProtocolVersion: protocol.ProtocolVersion,
		EmitsEvents:     true,
	})
	return err == nil
}

func (s *simulatedAgent) handleMessage(ctx context.Context, msg protocol.WSMessage) {
	if msg.Type != "command_scenario" {
		return // loadgen only reacts to dispatch -- pause/resume/cancel/stop are out of scope for this sub-project
	}
	var cmd protocol.ScenarioCommand
	if err := json.Unmarshal(msg.Data, &cmd); err != nil {
		s.metrics.RecordProtocolError()
		return
	}
	dispatchedAt := time.Now()
	s.metrics.RecordDispatch(time.Since(dispatchedAt)) // dispatch latency is measured server-side too; this is the receipt timestamp

	// SIMULATE EXECUTION: configurable sleep, never real technique logic.
	select {
	case <-ctx.Done():
		return
	case <-time.After(s.cfg.ExecutionLatency):
	}

	results := make([]protocol.ExecResult, len(cmd.Steps))
	for i, step := range cmd.Steps {
		results[i] = protocol.ExecResult{
			TaskID:     step.TaskID,
			ExitCode:   0,
			Stdout:     fakePayload(s.cfg.ResultSizeBytes),
			DurationMs: s.cfg.ExecutionLatency.Milliseconds(),
			ExecutedAt: time.Now(),
		}
	}

	t0 := time.Now()
	err := protocol.SubmitResult(ctx, s.client, s.cfg.ServerURL, s.cfg.AgentSecret, protocol.RawRunResult{
		RunID:      cmd.RunID,
		ScenarioID: cmd.ScenarioID,
		AgentID:    s.cfg.AgentID,
		Results:    results,
	})
	s.metrics.RecordResultSubmit(time.Since(t0))
	if err != nil {
		s.metrics.RecordHTTPError()
	}
}

func fakePayload(size int) string {
	if size <= 0 {
		return ""
	}
	b := make([]byte, size)
	for i := range b {
		b[i] = 'a' + byte(i%26)
	}
	return string(b)
}
```

- [ ] **Step 3: Create `orchestrator/cmd/loadgen/main.go`**

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	server := flag.String("server", "", "target orchestrator base URL, e.g. https://staging.example.com:9443")
	agents := flag.Int("agents", 100, "total simulated fleet size")
	rampPerSec := flag.Int("ramp-rate", 10, "agents enrolled per second during ramp-up")
	duration := flag.Duration("duration", 5*time.Minute, "how long to hold steady-state after ramp-up completes")
	heartbeat := flag.Duration("heartbeat", 30*time.Second, "per-agent heartbeat interval")
	executionLatency := flag.Duration("execution-latency", 3*time.Second, "fake-execution sleep duration per dispatched scenario")
	resultSize := flag.Int("result-size", 512, "approximate size in bytes of each fake step result's Stdout field")
	disconnectRate := flag.Float64("disconnect-rate", 0, "fraction (0.0-1.0) of heartbeat intervals that trigger a forced WS reconnect")
	agentSecret := flag.String("agent-secret", "", "shared agent secret, matching the orchestrator's AGENT_SECRET if configured")
	reportInterval := flag.Duration("report-interval", 10*time.Second, "how often to print a metrics snapshot")
	flag.Parse()

	if *server == "" {
		fmt.Fprintln(os.Stderr, "loadgen: -server is required")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() { <-sigCh; log.Println("[loadgen] interrupt received, shutting down..."); cancel() }()

	metrics := NewMetrics()

	go func() {
		ticker := time.NewTicker(*reportInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				log.Printf("[loadgen] %s", metrics.Snapshot())
			}
		}
	}()

	var wg sync.WaitGroup
	rampDelay := time.Second / time.Duration(*rampPerSec)
	for i := 0; i < *agents; i++ {
		select {
		case <-ctx.Done():
			goto steadyState
		default:
		}
		cfg := simConfig{
			ServerURL:        *server,
			AgentSecret:      *agentSecret,
			AgentID:          fmt.Sprintf("loadgen-%06d", i),
			Hostname:         fmt.Sprintf("LOADGEN-%06d", i),
			Heartbeat:        *heartbeat,
			ExecutionLatency: *executionLatency,
			ResultSizeBytes:  *resultSize,
			DisconnectRate:   *disconnectRate,
		}
		agent := newSimulatedAgent(cfg, metrics)
		wg.Add(1)
		go func() { defer wg.Done(); agent.run(ctx) }()
		time.Sleep(rampDelay)
	}

steadyState:
	log.Printf("[loadgen] ramp complete, holding steady-state for %s", *duration)
	select {
	case <-ctx.Done():
	case <-time.After(*duration):
		cancel()
	}

	wg.Wait()
	log.Printf("[loadgen] final: %s", metrics.Snapshot())
}
```

- [ ] **Step 4: Build `orchestrator/cmd/loadgen`**

Run: `cd orchestrator && go build ./cmd/loadgen/...`
Expected: success. This is the first real cross-module import (`orchestrator/cmd/loadgen` importing `audspect/agent/protocol`) — if `go.work` (Task 3) isn't correctly set up, this fails with a "module not found" style error naming `audspect/agent/protocol`.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/cmd/loadgen/main.go orchestrator/cmd/loadgen/agent.go orchestrator/cmd/loadgen/metrics.go
git commit -m "feat: add loadgen agent-fleet simulator"
git push
```

---

### Task 5: `loadgen` unit tests against a mock server

**Files:**
- Create: `orchestrator/cmd/loadgen/agent_test.go`

**Interfaces:**
- Consumes: `simConfig`, `newSimulatedAgent`, `Metrics`, `NewMetrics` (Task 4).

- [ ] **Step 1: Write the failing tests**

```go
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"audspect/agent/protocol"
	"github.com/gorilla/websocket"
)

// newMockServer returns an httptest.Server handling enroll/heartbeat/result
// over HTTP and one scenario dispatch over WS, close enough to the real
// orchestrator's wire behavior to drive simulatedAgent.run through a full
// lifecycle without a live orchestrator.
func newMockServer(t *testing.T, dispatchAfter time.Duration) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/agents/enroll", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(protocol.EnrollResponse{State: "active"})
	})
	mux.HandleFunc("/api/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(protocol.HeartbeatResponse{State: "active"})
	})
	mux.HandleFunc("/api/scenarios/result", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/ws/agent", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		if dispatchAfter > 0 {
			time.Sleep(dispatchAfter)
			data, _ := json.Marshal(protocol.ScenarioCommand{
				RunID: "r1", ScenarioID: "s1",
				Steps: []protocol.ScenarioStep{{TaskID: "t1"}},
			})
			conn.WriteJSON(protocol.WSMessage{Type: "command_scenario", Data: data})
		}
		// keep the connection open until the test tears it down
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	})
	return httptest.NewServer(mux)
}

func TestSimulatedAgent_Run_EnrollsAndReportsActive(t *testing.T) {
	server := newMockServer(t, 0)
	defer server.Close()

	metrics := NewMetrics()
	agent := newSimulatedAgent(simConfig{
		ServerURL: server.URL, AgentID: "test-1", Hostname: "TEST-1",
		Heartbeat: 50 * time.Millisecond, ExecutionLatency: 10 * time.Millisecond,
	}, metrics)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	agent.run(ctx)

	snap := metrics.Snapshot()
	if snap.HeartbeatOK == 0 {
		t.Error("expected at least one successful heartbeat")
	}
}

func TestSimulatedAgent_Run_DispatchTriggersResultSubmission(t *testing.T) {
	server := newMockServer(t, 50*time.Millisecond)
	defer server.Close()

	metrics := NewMetrics()
	agent := newSimulatedAgent(simConfig{
		ServerURL: server.URL, AgentID: "test-2", Hostname: "TEST-2",
		Heartbeat: 500 * time.Millisecond, ExecutionLatency: 20 * time.Millisecond,
	}, metrics)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	agent.run(ctx)

	snap := metrics.Snapshot()
	if snap.ResultsTotal == 0 {
		t.Error("expected at least one result submitted after dispatch")
	}
}

func TestSimulatedAgent_Run_EnrollFailureStopsCleanly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	metrics := NewMetrics()
	agent := newSimulatedAgent(simConfig{ServerURL: server.URL, AgentID: "test-3", Heartbeat: time.Second}, metrics)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	agent.run(ctx) // must return promptly, not hang, on enroll failure

	if metrics.Snapshot().ActiveAgents != 0 {
		t.Error("AgentStopped was not called after enroll failure")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail (or reveal a real bug) before any fix**

Run: `cd orchestrator && go test ./cmd/loadgen/... -v`
Expected: given Task 4 already implemented `agent.go`/`metrics.go` correctly, these should largely PASS on first run — this step is a genuine correctness check, not a placeholder red-green step. If anything fails, treat it as a real bug in Task 4's implementation (most likely candidate: `connectAndServe`'s `dispatchedAt`/`RecordDispatch` pairing measures ~0 duration since it's computed immediately before use rather than from the message's actual send time — this is a known, accepted limitation, not a bug: true dispatch latency needs the orchestrator's own dispatch timestamp, which isn't in `WSMessage` today. Note this explicitly in the Task 8 capacity report rather than fixing it here) and fix the implementation, not the test.

- [ ] **Step 3: Run again to confirm green**

Run: `cd orchestrator && go test ./cmd/loadgen/... -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/cmd/loadgen/agent_test.go
git commit -m "test: add loadgen state-machine tests against a mock server"
git push
```

---

### Task 6: Validate against the real staging server (staged ramp)

**Files:** none created — this task runs the `loadgen` binary built in Task 4 against the real staging server. No plan-authored code; this is execution + observation + a short results note appended to this task's own commit message (the full report is Task 8's deliverable).

**Interfaces:**
- Consumes: `orchestrator/cmd/loadgen` binary (Task 4).

- [ ] **Step 1: Build the loadgen binary**

Run: `cd orchestrator && go build -o loadgen ./cmd/loadgen`

- [ ] **Step 2: Stage 1 — 100 agents, protocol correctness**

Run: `./loadgen -server <staging-url> -agents 100 -ramp-rate 20 -duration 2m -heartbeat 10s`
Expected: `ActiveAgents` reaches 100, `HeartbeatOK` climbing steadily, zero `ProtocolErrors`. If this stage shows protocol errors, stop and root-cause before proceeding to any larger stage — a fleet-scale problem is much harder to diagnose than a 100-agent one.

- [ ] **Step 3: Stage 2 — 500 agents, basic stability**

Run: `./loadgen -server <staging-url> -agents 500 -ramp-rate 50 -duration 5m -heartbeat 30s`
Expected: stable heartbeat success rate, no unbounded growth in `ConnectionDrops`.

- [ ] **Step 4: Stage 3 — 1,000 agents, baseline capacity**

Run: `./loadgen -server <staging-url> -agents 1000 -ramp-rate 50 -duration 10m -heartbeat 30s`
Record the final `Snapshot()` output — this becomes the baseline the 5,000/10,000-agent stages are compared against.

- [ ] **Step 5: Stage 4 — 2,500 agents, scale validation**

Run: `./loadgen -server <staging-url> -agents 2500 -ramp-rate 100 -duration 10m -heartbeat 30s`

- [ ] **Step 6: Stage 5 — 5,000 agents, primary capacity milestone**

Run: `./loadgen -server <staging-url> -agents 5000 -ramp-rate 100 -duration 15m -heartbeat 30s`
Check against the SLOs from the spec: heartbeat success rate ≥99.5%, dispatch p95 under 5s, result-submission p95 under 5s, zero unexpected connection drops outside the configured `-disconnect-rate`. If any SLO is missed, this is a real finding for the capacity report (Task 8) — not a failure of this task; the task is to observe and record accurately, not to make the numbers pass.

- [ ] **Step 7: Stage 6 — 10,000 agents, stretch/characterization**

Run: `./loadgen -server <staging-url> -agents 10000 -ramp-rate 150 -duration 15m -heartbeat 30s`
No SLO requirement here — record whatever the numbers show, including if/where things degrade. This stage's entire purpose is finding the knee of the curve.

- [ ] **Step 8: Commit the raw stage outputs**

```bash
mkdir -p orchestrator/loadtest/results
# save each stage's final Snapshot() line (and any stderr) into
# orchestrator/loadtest/results/agent-plane-stage-{1..6}.txt as each stage completes
git add orchestrator/loadtest/results
git commit -m "chore: record agent-plane staged-ramp validation results (100-10k)"
git push
```

---

### Task 7: k6 API workload script

**Files:**
- Create: `orchestrator/loadtest/k6/api-mix.js`

**Interfaces:** none (k6 scripts are standalone; no Go interfaces).

- [ ] **Step 1: Write `api-mix.js`**

```javascript
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const BASE_URL = __ENV.BAS_SERVER_URL || 'https://localhost:9443';
const TOKEN = __ENV.BAS_JWT || ''; // a valid bas_token, obtained out-of-band before the run

const errorRate = new Rate('api_error_rate');
const dashboardTrend = new Trend('dashboard_read_duration');
const runResultTrend = new Trend('run_result_duration');
const findingsTrend = new Trend('findings_duration');
const reportTrend = new Trend('report_gen_duration');

export const options = {
	scenarios: {
		mixed_api_load: {
			executor: 'ramping-vus',
			startVUs: 0,
			stages: [
				{ duration: '2m', target: 50 },
				{ duration: '10m', target: 50 },
				{ duration: '2m', target: 0 },
			],
		},
	},
	thresholds: {
		api_error_rate: ['rate<0.01'],
		dashboard_read_duration: ['p(95)<2000'],
		run_result_duration: ['p(95)<3000'],
		findings_duration: ['p(95)<3000'],
		report_gen_duration: ['p(95)<8000'],
	},
};

function authedGet(path) {
	return http.get(`${BASE_URL}${path}`, { headers: { Cookie: `bas_token=${TOKEN}` } });
}
function authedPost(path, body) {
	return http.post(`${BASE_URL}${path}`, JSON.stringify(body || {}), {
		headers: { Cookie: `bas_token=${TOKEN}`, 'Content-Type': 'application/json' },
	});
}

// report_handlers.go's CreateReport (POST /api/reports) requires a real,
// currently-enrolled agentId for every reportType (posture/audit/
// compliance all reject an empty one) -- fetch one real agent once via
// k6's setup() rather than hardcoding an ID that may not exist on the
// target server.
export function setup() {
	const res = authedGet('/api/agents');
	const agents = res.json();
	if (!Array.isArray(agents) || agents.length === 0) {
		throw new Error('setup: /api/agents returned no agents -- seed at least one enrolled agent on staging before running this script');
	}
	return { agentId: agents[0].agentId || agents[0].id };
}

// Working mix: 60% dashboard/read, 20% run/result queries, 10% findings/posture, 10% report gen.
// Paths grounded against orchestrator/internal/api/routes.go's actual
// registered GET/POST routes at plan-writing time -- re-verify with
// `grep -n 'r\.Get("/api/dashboard\|r\.Get("/api/agents"\|r\.Get("/api/scenarios/runs"\|r\.Get("/api/campaigns"\|r\.Get("/api/findings"\|r\.Post("/api/reports"' orchestrator/internal/api/routes.go`
// before running, in case routes have changed since.
const DASHBOARD_ENDPOINTS = ['/api/dashboard/current', '/api/dashboard/trends', '/api/agents', '/api/campaigns'];
const RUN_ENDPOINTS = ['/api/scenarios/runs'];
const FINDINGS_ENDPOINTS = ['/api/findings'];

export default function (data) {
	const roll = Math.random();
	let res, group;

	if (roll < 0.60) {
		group = 'dashboard';
		const path = DASHBOARD_ENDPOINTS[Math.floor(Math.random() * DASHBOARD_ENDPOINTS.length)];
		res = authedGet(path);
		dashboardTrend.add(res.timings.duration);
	} else if (roll < 0.80) {
		group = 'run_result';
		const path = RUN_ENDPOINTS[Math.floor(Math.random() * RUN_ENDPOINTS.length)];
		res = authedGet(path);
		runResultTrend.add(res.timings.duration);
	} else if (roll < 0.90) {
		group = 'findings';
		res = authedGet(FINDINGS_ENDPOINTS[0]);
		findingsTrend.add(res.timings.duration);
	} else {
		group = 'report';
		res = authedPost('/api/reports', { reportType: 'posture', format: 'pdf', agentId: data.agentId });
		reportTrend.add(res.timings.duration);
	}

	const ok = check(res, { [`${group}: status is 2xx`]: (r) => r.status >= 200 && r.status < 300 });
	errorRate.add(!ok);
	sleep(1 + Math.random() * 2); // 1-3s think time between requests, per simulated user
}
```

**Note on the endpoint paths:** every path above (`/api/dashboard/current`, `/api/dashboard/trends`, `/api/agents`, `/api/campaigns`, `/api/scenarios/runs`, `/api/findings`, `/api/reports`) was confirmed against the real registered routes in `orchestrator/internal/api/routes.go` at plan-writing time, and `/api/reports`'s request body (`reportType`/`format`/`agentId`) was confirmed against `CreateReport`'s actual decode struct in `orchestrator/internal/api/report_handlers.go` — every `reportType` case (`posture`/`audit`/`compliance`) requires a real, non-empty `agentId`, which is why `setup()` fetches one from `/api/agents` rather than hardcoding an ID that may not exist on the target server. Routes may still drift between plan-writing and execution — re-run the grep in the comment above `DASHBOARD_ENDPOINTS` if any request in the run starts failing with 404.

- [ ] **Step 2: Smoke-test the script's syntax**

Run: `k6 run --vus 1 --duration 10s orchestrator/loadtest/k6/api-mix.js -e BAS_SERVER_URL=<staging-url> -e BAS_JWT=<a-real-token>`
Expected: k6 starts, makes a handful of requests, exits cleanly with a summary — confirms the script parses and the mix logic runs, ahead of the full ramping-VUs run used in Task 8's combined test.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/loadtest/k6/api-mix.js
git commit -m "feat: add k6 script for API/dashboard workload mix"
git push
```

---

### Task 8: Combined fleet + API stress test, capacity report

**Files:**
- Create: `orchestrator/loadtest/runbook.sh`
- Create: `docs/load-testing-capacity-report.md`

**Interfaces:**
- Consumes: `orchestrator/cmd/loadgen` binary (Task 4/6), `orchestrator/loadtest/k6/api-mix.js` (Task 7), the orchestrator's `GET /metrics` endpoint (already shipped, [[project_observability_foundation]]).

- [ ] **Step 1: Write `orchestrator/loadtest/runbook.sh`**

```bash
#!/usr/bin/env bash
# Combined agent-plane + API-plane load test against a staging server.
# Usage: ./runbook.sh <agents> <stage-label> <server-url> <duration>
set -euo pipefail

AGENTS="${1:?agent count required}"
LABEL="${2:?stage label required, e.g. stage5-5000}"
SERVER_URL="${3:?staging server URL required}"
DURATION="${4:-15m}"
JWT="${BAS_JWT:?set BAS_JWT to a valid session token before running}"

OUT_DIR="orchestrator/loadtest/results/combined/${LABEL}"
mkdir -p "$OUT_DIR"

echo "[runbook] scraping /metrics every 15s for the duration of this stage..."
(
  while true; do
    curl -fsS "${SERVER_URL}/metrics" >> "${OUT_DIR}/metrics-snapshots.txt" 2>&1 || true
    echo "---$(date -u +%FT%TZ)---" >> "${OUT_DIR}/metrics-snapshots.txt"
    sleep 15
  done
) &
SCRAPE_PID=$!
trap 'kill $SCRAPE_PID 2>/dev/null || true' EXIT

echo "[runbook] starting loadgen ($AGENTS agents)..."
./loadgen -server "$SERVER_URL" -agents "$AGENTS" -ramp-rate 100 -duration "$DURATION" -heartbeat 30s \
  > "${OUT_DIR}/loadgen.log" 2>&1 &
LOADGEN_PID=$!

echo "[runbook] starting k6 API mix..."
k6 run --vus 50 --duration "$DURATION" orchestrator/loadtest/k6/api-mix.js \
  -e BAS_SERVER_URL="$SERVER_URL" -e BAS_JWT="$JWT" \
  --summary-export="${OUT_DIR}/k6-summary.json" \
  > "${OUT_DIR}/k6.log" 2>&1 &
K6_PID=$!

wait "$LOADGEN_PID" "$K6_PID"
kill "$SCRAPE_PID" 2>/dev/null || true

echo "[runbook] stage $LABEL complete. Results in $OUT_DIR"
```

- [ ] **Step 2: Run the combined test at each ramp stage**

For each stage, run:
```bash
chmod +x orchestrator/loadtest/runbook.sh
BAS_JWT=<token> ./orchestrator/loadtest/runbook.sh 100 stage1-100 <staging-url> 5m
BAS_JWT=<token> ./orchestrator/loadtest/runbook.sh 500 stage2-500 <staging-url> 5m
BAS_JWT=<token> ./orchestrator/loadtest/runbook.sh 1000 stage3-1000 <staging-url> 10m
BAS_JWT=<token> ./orchestrator/loadtest/runbook.sh 2500 stage4-2500 <staging-url> 10m
BAS_JWT=<token> ./orchestrator/loadtest/runbook.sh 5000 stage5-5000 <staging-url> 15m
BAS_JWT=<token> ./orchestrator/loadtest/runbook.sh 10000 stage6-10000 <staging-url> 15m
```
Each produces `orchestrator/loadtest/results/combined/<label>/{loadgen.log, k6-summary.json, metrics-snapshots.txt}`.

- [ ] **Step 3: Write the capacity report**

Read every stage's `loadgen.log` final snapshot line, `k6-summary.json`'s p95/error-rate fields, and `metrics-snapshots.txt`'s `process_resident_memory_bytes`/`process_cpu_seconds_total`/`jobs_active` values, then populate:

```markdown
# Audspect Load/Capacity Report

**Server:** <staging host/spec — CPU/RAM/disk, so the numbers below are read against a known baseline>
**Date:** <run date>
**Method:** a Go loadgen simulating the real agent wire protocol (built on the extracted `agent/protocol` package) plus k6 exercising the dashboard/API workload, run simultaneously per fleet-size stage, with the orchestrator's own `/metrics` endpoint ([[project_observability_foundation]]) scraped throughout for server-side impact. Full methodology: `orchestrator/docs/superpowers/plans/2026-08-31-load-perf-scale-testing.md`.

## Results by fleet size

| Agents | Heartbeat success | Dispatch p95 | Result-submit p95 | k6 API error rate | k6 API p95 | Orchestrator RSS | Orchestrator CPU |
|---|---|---|---|---|---|---|---|
| 100 | | | | | | | |
| 500 | | | | | | | |
| 1,000 | | | | | | | |
| 2,500 | | | | | | | |
| 5,000 | | | | | | | |
| 10,000 | | | | | | | |

## Primary capacity milestone (5,000 agents)

<Fill in: met/missed each SLO from the spec (heartbeat ≥99.5%, dispatch p95 <5s,
result-submit p95 <5s, zero unexpected drops). State plainly if any were
missed — this report exists to give a real answer, not a reassuring one.>

## 10,000-agent characterization

<Where did the curve bend, if it did? Which resource (CPU, memory, connection
count, DB) hit its limit first, based on the /metrics snapshots?>

## Known limitations of this measurement

- Dispatch latency is measured as loadgen's message-receipt timestamp, not a
  true server-send-to-client-receive delta (the wire protocol doesn't carry a
  server-side dispatch timestamp today) — treat the reported dispatch p95 as
  an upper bound on true latency, not an exact figure.
- Postgres-side metrics (connection pool saturation, query latency) are not
  captured — only the orchestrator process's own CPU/RSS via /metrics.
- k6's workload mix is an informed estimate, not measured production
  traffic (staging had no traffic history at the time of this report).

## Answer

<One paragraph, plain language: "Audspect can support N concurrently
connected agents with concurrent dashboard/API usage at P95 latency of Xms
and error rate of Y%, based on testing against <staging spec> on <date>.
Beyond N agents, <what degrades first and how>.">
```

- [ ] **Step 4: Commit**

```bash
git add orchestrator/loadtest/runbook.sh orchestrator/loadtest/results/combined docs/load-testing-capacity-report.md
git commit -m "docs: add combined load-test runbook and capacity report"
git push
```

---

### Task 9: Full-suite verification (no commit)

**Files:** none — verification only.

- [ ] **Step 1: Verify the agent module**

Run: `cd agent && go build ./... && go test ./...`
Expected: PASS, same as Task 1's gate — confirms nothing in Tasks 2-8 regressed the agent module.

- [ ] **Step 2: Verify the orchestrator module**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./... -p 1`
Expected: PASS across every package, including the new `cmd/loadgen`. Use `-p 1` per this session's established guidance for the full-module test run on this host (`-p 2` has caused shared-testcontainer resource contention before).

- [ ] **Step 3: Verify CI would still pass**

Re-read `.github/workflows/test.yml` and confirm every step (`gofmt -l .`, `go vet ./...`, `staticcheck ./...`, `go build ./...`, `go test ./... -race -coverprofile=coverage.out`, all run with `working-directory: orchestrator`) still only builds/tests `orchestrator`'s own package set, now including `orchestrator/cmd/loadgen` — the Task 3 CI-verification concern, closed out for real now that `loadgen` exists and actually imports across the workspace boundary. Run the same commands locally from `orchestrator/` to confirm before trusting a real CI run:
Run: `cd orchestrator && gofmt -l . && go vet ./... && go build ./... && go test ./... -race -coverprofile=coverage.out -p 1`
Expected: `gofmt -l .` prints nothing (no unformatted files); everything else passes.

- [ ] **Step 4: Report**

Summarize for the user: confirmation that both modules build/test clean, that CI's existing scope is unchanged, and a pointer to `docs/load-testing-capacity-report.md` for the actual capacity findings. State plainly which stages of Task 6/8's staged ramp were actually run against the real staging server versus which are still pending, if the full 100→10,000 sequence wasn't completed in one sitting.

---

## Post-Plan: Update Memory

After Task 9, update the two-file memory system:
- Add a new topic file `project_load_perf_scale_testing.md` documenting: the protocol-extraction architecture, the real file list touched, the loadgen design, the k6 mix, and — most importantly — the actual capacity numbers from `docs/load-testing-capacity-report.md` once real runs complete.
- Update `project_platform_roadmap_2026h2.md`'s Phase 8 section to reflect this item's new status, leaving upgrade validation and release documentation as the phase's remaining open items.
- Add one line to `MEMORY.md`'s index for the new topic file.
