package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/audspect/bas-agent/sched"
	"github.com/gorilla/websocket"
)

type Agent struct {
	cfg            Config
	id             Identity
	status         string
	state          string // server-assigned lifecycle state: active|restricted|quarantined|retired
	mu             sync.Mutex
	client         *http.Client
	cancelScenario context.CancelFunc
	scenarioMu     sync.Mutex
	binaryHash     string            // SHA-256 of own binary, computed once at startup
	logger         *Logger           // 3-tier structured logger
	localSt        *LocalAgentState  // in-memory state for local status API
}

func newAgent(cfg Config, id Identity) *Agent {
	a := &Agent{
		cfg:     cfg,
		id:      id,
		status:  "idle",
		client:  &http.Client{Timeout: 30 * time.Second},
		logger:  NewLogger(id.AgentID, cfg.ServerURL, cfg.AgentSecret),
		localSt: newLocalAgentState(),
	}
	if h, err := SelfHash(); err == nil {
		a.binaryHash = h
		log.Printf("[*] binary hash: %s", h[:16]+"...")
	} else {
		log.Printf("[!] could not hash binary: %v", err)
	}
	a.logger.Op("info", "lifecycle", fmt.Sprintf("agent started v%s hash=%s...", version, func() string {
		if len(a.binaryHash) >= 16 {
			return a.binaryHash[:16]
		}
		return a.binaryHash
	}()))
	return a
}

func (a *Agent) setStatus(s string) {
	a.mu.Lock()
	a.status = s
	a.mu.Unlock()
}

func (a *Agent) getStatus() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.status
}

// postJSONDecode POSTs body as JSON and optionally decodes the response into out.
// Pass nil for out to discard the response body.
func (a *Agent) postJSONDecode(path string, body interface{}, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, a.cfg.ServerURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if a.cfg.AgentSecret != "" {
		req.Header.Set("X-Agent-Token", a.cfg.AgentSecret)
		if path == "/api/scenarios/result" {
			req.Header.Set("X-Result-MAC", SignBody(data, a.cfg.AgentSecret))
		}
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server %d on %s", resp.StatusCode, path)
	}
	if out != nil {
		// Non-fatal if body can't be decoded — old server versions return 200 with no body.
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (a *Agent) postJSON(path string, body interface{}) error {
	return a.postJSONDecode(path, body, nil)
}

// enrollWithServer performs the pre-operation handshake: validates URL+secret
// are accepted by the server and receives the initial policy bundle.
// Failure is non-fatal — the agent continues and will retry on next heartbeat.
func (a *Agent) enrollWithServer() {
	req := EnrollRequest{
		AgentID:      a.id.AgentID,
		Hostname:     a.id.Hostname,
		IPAddress:    a.id.IPAddress,
		OSVersion:    a.id.OSVersion,
		Username:     a.id.Username,
		EnvLabel:     a.cfg.EnvLabel,
		BinaryHash:   a.binaryHash,
		AgentVersion: version,
	}
	var resp EnrollResponse
	if err := a.postJSONDecode("/api/agents/enroll", req, &resp); err != nil {
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

func (a *Agent) sendHeartbeat(status string) {
	hb := Heartbeat{
		AgentID:       a.id.AgentID,
		Hostname:      a.id.Hostname,
		IPAddress:     a.id.IPAddress,
		OSVersion:     a.id.OSVersion,
		Username:      a.id.Username,
		Status:        status,
		EnvLabel:      a.cfg.EnvLabel,
		BinaryHash:    a.binaryHash,
		AgentVersion:  version,
		SchemaVersion: schemaVersion,

		ProtocolVersion: protocolVersion,
		EmitsEvents:     true,
	}
	t0 := time.Now()
	var resp HeartbeatResponse
	if err := a.postJSONDecode("/api/heartbeat", hb, &resp); err != nil {
		log.Printf("[!] heartbeat: %v", err)
		a.logger.Op("warn", "connectivity", fmt.Sprintf("heartbeat failed: %v", err))
		a.localSt.SetConnected(false)
		return
	}
	a.localSt.SetConnected(true)
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

// cancelCurrentScenario cancels the in-flight scenario run, if any. The run's
// context cancellation makes runScenario drain the scheduler, emit run_cancelled,
// and submit partial results. Returns true if a run was active. Safe to call when
// idle (cancelling an already-finished context is a no-op).
func (a *Agent) cancelCurrentScenario() bool {
	a.scenarioMu.Lock()
	defer a.scenarioMu.Unlock()
	if a.cancelScenario == nil {
		return false
	}
	a.cancelScenario()
	return true
}

func (a *Agent) runScenario(ctx context.Context, cmd ScenarioCommand) {
	// Local state guard — defense-in-depth alongside server-side enforcement.
	a.mu.Lock()
	st := a.state
	a.mu.Unlock()
	if st == "quarantined" || st == "restricted" || st == "retired" {
		log.Printf("[!] scenario blocked locally — agent state=%s (run %s)", st, cmd.RunID)
		a.logger.Sec("error", cmd.ScenarioID, cmd.RunID, "", "", "blocked",
			fmt.Sprintf("scenario blocked — agent state=%s", st))
		return
	}
	log.Printf("[*] scenario started: run=%s scenario=%s steps=%d mode=%s",
		cmd.RunID, cmd.ScenarioID, len(cmd.Steps), cmd.Mode)
	a.logger.Sec("info", cmd.ScenarioID, cmd.RunID, "", "", "scenario_start",
		fmt.Sprintf("scenario started: %s steps=%d mode=%s", cmd.Name, len(cmd.Steps), cmd.Mode))

	// Start the dialog auto-dismisser for the duration of this scenario.
	// It scans for dialog boxes belonging to step processes every 500ms and
	// dismisses them automatically — last line of defence after CREATE_NO_WINDOW,
	// SetErrorMode, and the Job Object tree-kill.
	dismissCtx, dismissCancel := context.WithCancel(ctx)
	defer dismissCancel()
	startDismisser(dismissCtx)

	// ── Domain-controller safety interlock ───────────────────────────────────
	// Live AD drills must never run directly on a domain controller. If policy
	// requires it and this host is a DC, abort the whole run before any step.
	if cmd.Policy != nil && cmd.Policy.BlockOnDomainController && hostIsDomainController() {
		log.Printf("[!] ABORT: host is a domain controller and policy blocks live execution on DCs (run %s)", cmd.RunID)
		a.submitResults(cmd, []ExecResult{{
			ExitCode:      -1,
			Blocked:       true,
			BlockedReason: "aborted by domain-controller safety interlock — live AD techniques must not run on a domain controller",
			ExecutedAt:    time.Now(),
		}}, false, nil)
		a.setStatus("idle")
		a.sendHeartbeat("idle")
		return
	}

	a.setStatus("scanning")
	a.sendHeartbeat("scanning")
	a.localSt.StartOperation(cmd.ScenarioID, cmd.Name, cmd.ScenarioID, len(cmd.Steps))

	// Policy variables exposed to every step command as environment variables.
	policyEnv := map[string]string{"BAS_RUN_MODE": cmd.Mode}
	if cmd.Policy != nil {
		if cmd.Policy.MaxSprayAttempts > 0 {
			policyEnv["BAS_MAX_SPRAY_ATTEMPTS"] = fmt.Sprintf("%d", cmd.Policy.MaxSprayAttempts)
		}
		if len(cmd.Policy.SprayAccountAllowlist) > 0 {
			policyEnv["BAS_SPRAY_ALLOWLIST"] = strings.Join(cmd.Policy.SprayAccountAllowlist, ",")
		}
	}

	snap := captureSnapshot(cmd.RunID)
	log.Printf("[*] snapshot taken: run=%s", cmd.RunID)

	payloadDir, err := os.MkdirTemp("", "bas-"+cmd.RunID+"-*")
	if err != nil {
		log.Printf("[!] payload dir: %v", err)
		payloadDir = os.TempDir()
	}
	defer func() {
		if err := os.RemoveAll(payloadDir); err != nil {
			log.Printf("[!] payload dir cleanup: %v", err)
		}
	}()

	start := time.Now()
	total := len(cmd.Steps)

	// Steps run through the resource-lock scheduler: independent steps execute
	// concurrently, conflicting ones serialize, and unlabeled steps run serially.
	// Results are written to a fixed index per step so the submitted order is
	// deterministic (identical to a serial run) regardless of completion order.
	results := make([]ExecResult, total)
	ran := make([]bool, total)
	var completed int64

	workers := cmd.Workers
	if workers < 1 {
		workers = sched.DefaultWorkers()
	}

	// Warm PowerShell host pool for read-only discovery steps (skips per-step
	// process cold start). Created only if the scenario has a pooled candidate,
	// sized to the worker count, and torn down after the scheduler drains.
	var pool *HostPool
	if slices.ContainsFunc(cmd.Steps, pooledCandidate) {
		pool = NewHostPool(workers)
	}
	defer pool.Close()

	// Phase B-1: best-effort live event stream. nextSeq is the per-run monotonic
	// sequence; emit() never blocks the run.
	var nextSeq int64
	seq := func() int64 { return atomic.AddInt64(&nextSeq, 1) }
	emitter := newEventEmitter(
		func(b []RunEvent) error { return a.postJSON("/api/scenarios/events", b) },
		1000, 300*time.Millisecond,
	)
	defer emitter.close()
	emit := func(ev RunEvent) { ev.RunID = cmd.RunID; ev.Seq = seq(); emitter.emit(ev) }

	emit(RunEvent{Type: "run_started", Payload: map[string]any{"stepsTotal": total, "mode": cmd.Mode}})

	jobs := make([]sched.Job, total)
	for i := range cmd.Steps {
		step := cmd.Steps[i] // per-job copy (PayloadDir/Env set below)

		// Layer 1 (schedule timeout): bound how long this step may wait for its
		// resource locks. On expiry the scheduler records an explicit timeout
		// verdict rather than blocking the worker indefinitely.
		var schedDur time.Duration
		schedSec := 0
		if step.Timeout != nil && step.Timeout.ScheduleSec > 0 {
			schedSec = step.Timeout.ScheduleSec
			schedDur = time.Duration(schedSec) * time.Second
		}

		emit(RunEvent{Type: "queued", TaskID: step.TaskID, TechniqueID: step.TechniqueID})

		jobs[i] = sched.Job{
			Resource: step.Resource,
			Schedule: schedDur,
			OnScheduleTimeout: func() {
				n := atomic.AddInt64(&completed, 1)
				a.localSt.UpdateProgress(int(n), total, "Execution")
				log.Printf("[*]   [%d/%d] %s — schedule timeout after %ds (locks unavailable)", i+1, total, step.TechniqueID, schedSec)
				results[i] = ExecResult{
					TaskID:     step.TaskID,
					ExitCode:   -1,
					Stderr:     fmt.Sprintf("schedule timeout: resource locks unavailable within %ds", schedSec),
					ExecutedAt: time.Now(),
					TimedOut:   true,
				}
				ran[i] = true
				emit(RunEvent{Type: "timeout", TaskID: step.TaskID, TechniqueID: step.TechniqueID,
					Payload: map[string]any{"reason": "schedule"}})
			},
			Run: func(ctx context.Context) {
				n := atomic.AddInt64(&completed, 1)
				a.localSt.UpdateProgress(int(n), total, "Execution")
				log.Printf("[*]   [%d/%d] %s (%s) — %s", i+1, total, step.TechniqueID, step.Executor, step.Name)
				a.logger.Sec("info", cmd.ScenarioID, cmd.RunID, step.TaskID, step.TechniqueID,
					"scenario_step", fmt.Sprintf("[%d/%d] %s executor=%s", i+1, total, step.Name, step.Executor))

				emit(RunEvent{Type: "started", TaskID: step.TaskID, TechniqueID: step.TechniqueID})

				// Stage payloads into a per-step subdir so concurrent steps never
				// collide on BAS_PAYLOAD_DIR. Steps without payloads use the run dir.
				stepDir := payloadDir
				if len(step.Payloads) > 0 {
					stepDir = filepath.Join(payloadDir, fmt.Sprintf("step-%d", i))
					if err := os.MkdirAll(stepDir, 0o700); err != nil {
						log.Printf("[!]   payload dir: %v", err)
						stepDir = payloadDir
					}
					if err := StagePayloads(step.Payloads, stepDir); err != nil {
						log.Printf("[!]   payload stage: %v", err)
					} else {
						// AV/EDR may quarantine a payload immediately after staging.
						if name := CheckPayloadQuarantine(step.Payloads, stepDir); name != "" {
							log.Printf("[!]   payload quarantined by security control: %s", name)
							results[i] = ExecResult{
								TaskID:        step.TaskID,
								ExitCode:      -1,
								Blocked:       true,
								BlockedReason: fmt.Sprintf("payload '%s' quarantined by security control before execution", name),
								ExecutedAt:    time.Now(),
							}
							ran[i] = true
							emit(RunEvent{Type: "completed", TaskID: step.TaskID, TechniqueID: step.TechniqueID,
								Payload: map[string]any{"verdict": "blocked"}})
							return
						}
						log.Printf("[*]   staged %d payload(s) to %s", len(step.Payloads), stepDir)
					}
				}

				step.PayloadDir = stepDir
				step.Env = policyEnv
				r := execStep(ctx, step, pool)

				evtSummary := ""
				if len(r.Events) > 0 {
					evtSummary = fmt.Sprintf(" events=%d", len(r.Events))
				}
				log.Printf("[*]   → exit=%d dur=%dms%s", r.ExitCode, r.DurationMs, evtSummary)
				results[i] = r
				ran[i] = true
				typ, verdict := eventForResult(r)
				payload := map[string]any{"durationMs": r.DurationMs, "exitCode": r.ExitCode}
				if verdict != "" {
					payload["verdict"] = verdict
				}
				if typ == "timeout" {
					payload["reason"] = "execute"
				}
				emit(RunEvent{Type: typ, TaskID: step.TaskID, TechniqueID: step.TechniqueID, Payload: payload})
			},
		}
	}

	sched.Run(ctx, workers, sched.NewLockManager(), jobs)

	// Collect completed results in submission order. On cancellation the
	// scheduler skips not-yet-started jobs, so some indices stay unran.
	final := make([]ExecResult, 0, total)
	for i := range total {
		if ran[i] {
			final = append(final, results[i])
		}
	}
	partial := ctx.Err() != nil

	if partial {
		emit(RunEvent{Type: "run_cancelled", Payload: map[string]any{"stepsDone": len(final)}})
	} else {
		emit(RunEvent{Type: "run_completed", Payload: map[string]any{"stepsDone": len(final), "partial": false}})
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	if partial {
		log.Printf("[*] scenario interrupted — %d/%d steps completed, submitting partial results", len(final), total)
	} else {
		log.Printf("[*] scenario done: run=%s steps=%d elapsed=%v (workers=%d)", cmd.RunID, len(final), elapsed, workers)
		a.logger.Sec("info", cmd.ScenarioID, cmd.RunID, "", "", "scenario_done",
			fmt.Sprintf("completed: steps=%d elapsed=%v", len(final), elapsed))
		a.logger.Metric("scenario_duration_ms", float64(elapsed.Milliseconds()), "ms")
	}

	reverted := revertFromSnapshot(snap)
	if len(reverted) > 0 {
		log.Printf("[*] reverted %d change(s) after run", len(reverted))
	}
	a.submitResults(cmd, final, partial, reverted)
	a.setStatus("idle")
	a.sendHeartbeat("idle")
}

func (a *Agent) submitResults(cmd ScenarioCommand, results []ExecResult, partial bool, reverted []string) {
	// Tally evidence collected across all steps for the local status API.
	var ev LocalEvidenceStats
	for _, r := range results {
		ev.EventsCollected += len(r.Events)
		for _, e := range r.Events {
			el := strings.ToLower(e)
			if strings.Contains(el, "defender") || strings.Contains(el, "antimalware") {
				ev.DefenderAlerts++
			}
			if strings.Contains(el, "sysmon") || strings.Contains(el, "microsoft-windows-sysmon") {
				ev.SysmonDetections++
			}
		}
	}
	// Derive overall result label for the local status display.
	resultLabel := "Completed"
	if partial {
		resultLabel = "Partial"
	} else {
		blocked := 0
		for _, r := range results {
			if r.Blocked {
				blocked++
			}
		}
		switch {
		case blocked == len(results) && len(results) > 0:
			resultLabel = "Detected"
		case blocked > 0:
			resultLabel = "Partial"
		default:
			resultLabel = "Evaded"
		}
	}
	a.localSt.UpdateProgress(len(results), len(results), "Upload")
	a.localSt.CompleteOperation(resultLabel, ev)

	payload := RawRunResult{
		RunID:      cmd.RunID,
		ScenarioID: cmd.ScenarioID,
		AgentID:    a.id.AgentID,
		Results:    results,
		Partial:    partial,
		Reverted:   reverted,
	}
	label := "completed"
	if partial {
		label = "partial"
	}
	if err := a.postJSON("/api/scenarios/result", payload); err != nil {
		log.Printf("[!] result submit (%s): %v", label, err)
	} else {
		log.Printf("[+] results submitted (%s): run=%s steps=%d", label, cmd.RunID, len(results))
	}
}

func (a *Agent) runLocalScan(scenarioID, runID string) {
	a.mu.Lock()
	st := a.state
	a.mu.Unlock()
	if st == "quarantined" || st == "restricted" || st == "retired" {
		log.Printf("[!] local scan blocked — agent state=%s (run %s)", st, runID)
		return
	}
	log.Printf("[*] local scan started: scenario=%s run=%s", scenarioID, runID)
	a.setStatus("scanning")
	a.sendHeartbeat("scanning")

	categories := RunScenarioChecks(scenarioID)

	// Submit full SimCheck metadata so the orchestrator can correctly populate
	// technique ID, tactic, severity, threat impact, and remediation without
	// having to re-derive them from an empty step definition.
	checks := make([]SimCheckResult, 0)
	for _, cat := range categories {
		for _, ch := range cat.Checks {
			checks = append(checks, SimCheckResult{
				ID:            ch.ID,
				TechniqueID:   ch.Technique.ID,
				TechniqueName: ch.Technique.Name,
				Tactic:        ch.Technique.Tactic,
				Result:        ch.Result,
				Severity:      ch.Severity,
				ThreatImpact:  ch.ThreatImpact,
				Details:       ch.Details,
				Remediation:   ch.Remediation,
				Framework:     ch.Framework,
				DurationMs:    ch.DurationMs,
				ExecutedAt:    ch.ExecutedAt,
			})
		}
	}

	payload := RawRunResult{
		RunID:      runID,
		ScenarioID: scenarioID,
		AgentID:    a.id.AgentID,
		Checks:     checks,
	}
	if err := a.postJSON("/api/scenarios/result", payload); err != nil {
		log.Printf("[!] local scan submit: %v", err)
	} else {
		log.Printf("[+] local scan submitted: scenario=%s checks=%d", scenarioID, len(checks))
	}

	a.setStatus("idle")
	a.sendHeartbeat("idle")
}

func (a *Agent) connectWS() {
	rawURL := strings.Replace(a.cfg.ServerURL, "http://", "ws://", 1)
	rawURL = strings.Replace(rawURL, "https://", "wss://", 1)

	u, err := url.Parse(rawURL + "/ws/agent")
	if err != nil {
		log.Printf("[!] invalid WS URL: %v", err)
		return
	}
	q := u.Query()
	q.Set("agentId", a.id.AgentID)
	if a.cfg.AgentSecret != "" {
		q.Set("agentSecret", a.cfg.AgentSecret)
	}
	u.RawQuery = q.Encode()

	for {
		conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
		if err != nil {
			log.Printf("[!] WS connect failed: %v — retry in 5s", err)
			time.Sleep(wsReconnectDelay)
			continue
		}
		log.Printf("[+] WS connected: %s", u.String())
		a.logger.Op("info", "connectivity", fmt.Sprintf("WebSocket connected to %s", a.cfg.ServerURL))
		// Flush events buffered while the connection was down.
		go a.logger.Flush()

		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				log.Printf("[!] WS read: %v — reconnecting", err)
				a.logger.Op("warn", "connectivity", fmt.Sprintf("WebSocket disconnected: %v", err))
				conn.Close()
				break
			}

			var msg WSMessage
			if err := json.Unmarshal(data, &msg); err != nil {
				continue
			}

			switch msg.Type {
			case "command_scenario":
				var cmd ScenarioCommand
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
				go a.runScenario(ctx, cmd)

			case "command_simulate":
				var sim struct {
					ScenarioID string `json:"scenarioId"`
					RunID      string `json:"runId"`
				}
				if err := json.Unmarshal(msg.Data, &sim); err != nil || sim.ScenarioID == "" {
					log.Printf("[!] WS: bad command_simulate payload: %v", err)
					continue
				}
				go a.runLocalScan(sim.ScenarioID, sim.RunID)

			case "command_cancel":
				if a.cancelCurrentScenario() {
					log.Printf("[*] scenario cancelled by operator")
					a.logger.Op("warn", "lifecycle", "scenario stopped by operator request")
				} else {
					log.Printf("[~] command_cancel received but no scenario is running")
				}

			default:
				log.Printf("[~] WS: unhandled message type %q", msg.Type)
			}
		}

		time.Sleep(wsReconnectDelay)
	}
}
