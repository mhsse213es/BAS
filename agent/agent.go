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
	binaryHash     string           // SHA-256 of own binary, computed once at startup
	logger         *Logger          // 3-tier structured logger
	localSt        *LocalAgentState // in-memory state for local status API
	secProducts    []string         // installed security products, enumerated once at startup (guarded by mu)
	spoolMu        sync.Mutex       // serializes spool drains so a tick and a reconnect-kick can't double-send
	spoolKick      chan struct{}    // buffered (cap 1): nudges the drainer to deliver immediately on reconnect

	// Disconnect tracking for the pause-then-finalize watchdog (guarded by mu).
	disconnectedSince time.Time // when the server link was lost; zero = connected
	watchdogTripped   bool      // the watchdog already finalized the run for this outage (one-shot)

	runWG sync.WaitGroup // tracks in-flight scenario/scan goroutines so shutdown can wait for them to spool a Partial
}

func newAgent(cfg Config, id Identity) *Agent {
	a := &Agent{
		cfg:       cfg,
		id:        id,
		status:    "idle",
		client:    &http.Client{Timeout: 30 * time.Second},
		logger:    NewLogger(id.AgentID, cfg.ServerURL, cfg.AgentSecret),
		localSt:   newLocalAgentState(),
		spoolKick: make(chan struct{}, 1),
	}
	if h, err := SelfHash(); err == nil {
		a.binaryHash = h
		log.Printf("[*] binary hash: %s", h[:16]+"...")
	} else {
		log.Printf("[!] could not hash binary: %v", err)
	}
	// Enumerate installed security products once, off the startup path (the WMI /
	// Defender queries can take a few seconds). Cached for the heartbeat.
	go func() {
		products := enumerateSecurityProducts()
		a.mu.Lock()
		a.secProducts = products
		a.mu.Unlock()
		if len(products) > 0 {
			log.Printf("[*] security products detected: %s", strings.Join(products, ", "))
		}
	}()
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
	a.mu.Lock()
	products := a.secProducts
	a.mu.Unlock()
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

		ProtocolVersion:  protocolVersion,
		EmitsEvents:      true,
		SecurityProducts: products,
	}
	t0 := time.Now()
	var resp HeartbeatResponse
	if err := a.postJSONDecode("/api/heartbeat", hb, &resp); err != nil {
		log.Printf("[!] heartbeat: %v", err)
		a.logger.Op("warn", "connectivity", fmt.Sprintf("heartbeat failed: %v", err))
		// Stamp the start of the outage so the watchdog can measure how long a
		// running simulation has been without a server link.
		a.mu.Lock()
		if a.disconnectedSince.IsZero() {
			a.disconnectedSince = time.Now()
		}
		a.mu.Unlock()
		a.localSt.SetConnected(false)
		return
	}
	// Link restored — clear the outage clock and re-arm the watchdog.
	a.mu.Lock()
	a.disconnectedSince = time.Time{}
	a.watchdogTripped = false
	a.mu.Unlock()
	a.localSt.SetConnected(true)
	// The link is up — nudge the drainer so any results buffered during an outage
	// ship now rather than waiting for its next tick.
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

const (
	// disconnectGracePeriod is how long a running simulation may continue without a
	// server link before the agent finalizes it as Partial. It matches the server's
	// AgentOfflineAfter, so the agent stops itself at the same instant the server
	// would flag it offline — and the spooled partial then delivers the real
	// outcome instead of a synthesized one.
	disconnectGracePeriod = 90 * time.Second
	watchdogInterval      = 5 * time.Second
	// shutdownGrace bounds how long a Stop/Shutdown waits for an in-flight run to
	// finalize and spool its Partial. The Windows SCM is told this via WaitHint.
	shutdownGrace = 15 * time.Second
)

// shutdownFinalize stops any in-flight simulation on agent shutdown and waits,
// bounded by grace, for it to finalize so its Partial result is written to the
// durable spool before the process exits. The spool delivers that Partial on the
// next start. Without this, stopping or closing the agent mid-run would discard
// everything executed so far instead of reporting it as Partial.
func (a *Agent) shutdownFinalize(grace time.Duration) {
	if a.getStatus() == "idle" {
		return // nothing running
	}
	log.Println("[*] interrupting active simulation — finalizing partial results before exit")
	a.cancelCurrentScenario()
	done := make(chan struct{})
	go func() { a.runWG.Wait(); close(done) }()
	select {
	case <-done:
		log.Println("[*] in-flight simulation finalized; partial result spooled for delivery")
	case <-time.After(grace):
		log.Printf("[!] simulation did not finalize within %s — partial may be incomplete", grace)
	}
}

// disconnectedFor reports how long the server link has been down, or 0 if connected.
func (a *Agent) disconnectedFor() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.disconnectedSince.IsZero() {
		return 0
	}
	return time.Since(a.disconnectedSince)
}

// runDisconnectWatchdog finalizes a simulation that has run too long without a
// server link. A lost link does NOT freeze the run — the agent is a local executor,
// so the atomics keep going and the dashboard shows the run "Paused". But an
// endpoint the console can't reach can't be observed or stopped, so a sim must not
// run there unbounded: once the outage passes disconnectGracePeriod the agent stops
// the run itself. Cancellation makes runScenario submit a Partial, which the spool
// holds until the link returns. The trip is one-shot per outage (re-armed only when
// a heartbeat reconnects), so it can't re-fire while the run is winding down. The
// idle+disconnected case is intentionally left to the server's offline reaper —
// there is no local run to finalize.
func (a *Agent) runDisconnectWatchdog() {
	t := time.NewTicker(watchdogInterval)
	defer t.Stop()
	for range t.C {
		if a.getStatus() == "idle" {
			continue // nothing running to finalize
		}
		if a.disconnectedFor() < disconnectGracePeriod {
			continue
		}
		a.mu.Lock()
		if a.watchdogTripped {
			a.mu.Unlock()
			continue
		}
		a.watchdogTripped = true
		a.mu.Unlock()

		log.Printf("[!] server link down for >%s while a simulation is running — stopping the run and finalizing as Partial", disconnectGracePeriod)
		a.logger.Op("warn", "lifecycle", fmt.Sprintf("server unreachable for >%s mid-simulation — finalizing as Partial", disconnectGracePeriod))
		a.localSt.RecordActivity("Server link lost for over 90s — simulation finalized as Partial")
		a.cancelCurrentScenario()
	}
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
	// Derive overall result label for the local status display, aligned with the
	// server's 4-verdict taxonomy (ERROR steps are excluded, never counted as Evaded).
	resultLabel := deriveLocalResultLabel(results, partial)
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
	a.submitRunResult(payload, label)

	// After results are durably queued, fire a grace-delayed detection sweep in a
	// tracked goroutine. Best-effort: never affects the authoritative run result.
	if cmd.RunID != "" {
		runStart := time.Now()
		for _, r := range results {
			if !r.ExecutedAt.IsZero() && r.ExecutedAt.Before(runStart) {
				runStart = r.ExecutedAt
			}
		}
		a.runWG.Add(1)
		go func() { defer a.runWG.Done(); a.collectAndSubmitDetections(cmd.RunID, runStart) }()
	}
}

// collectAndSubmitDetections runs AFTER results are delivered. It waits a grace
// period (defenders alert seconds-to-minutes late), sweeps the run's time window
// once for rich alerts, and posts them. Best-effort: any failure is logged and
// dropped — it never affects the authoritative run result.
func (a *Agent) collectAndSubmitDetections(runID string, runStart time.Time) {
	const graceWait = 90 * time.Second
	const windowPad = 300 * time.Second // catch late alerts up to 5 min after the run
	const maxEvents = 500
	const maxBytes = 512 * 1024

	time.Sleep(graceWait)
	from := runStart.Add(-5 * time.Second)
	to := time.Now()
	alerts, truncated := collectAlerts(from, to, maxEvents, maxBytes)
	if len(alerts) == 0 {
		log.Printf("[detect] run %s: no alerts collected in window", runID)
		return
	}
	payload := RunDetections{
		RunID: runID, AgentID: a.id.AgentID, Alerts: alerts,
		WindowFrom: from, WindowTo: to, Truncated: truncated,
	}
	if err := a.postJSON("/api/scenarios/runs/"+runID+"/detections", payload); err != nil {
		log.Printf("[detect] run %s: detection submit failed: %v", runID, err)
		return
	}
	log.Printf("[detect] run %s: submitted %d alert(s)", runID, len(alerts))
	_ = windowPad
}

// submitRunResult durably delivers a run's authoritative results to the server. A
// lost server link must never lose an assessment, and neither must a process or
// endpoint restart: the result is FIRST persisted to the on-disk spool, then the
// drainer is triggered to ship it. In the common online case it leaves immediately;
// during an outage it stays on disk and the drainer retries on its tick and on the
// next reconnect — across restarts. The payload is a COMPLETE snapshot and the
// server REPLACES (never appends), so re-delivery is idempotent: a retry after a
// dropped response, or a late delivery that reconciles a run the server already
// flagged 'partial', converges to the same final state. See spool.go.
func (a *Agent) submitRunResult(payload RawRunResult, label string) {
	if _, err := a.spoolWrite(payload, label); err != nil {
		// Could not persist — fall back to a direct best-effort send so an online
		// agent still delivers even if the spool dir is unwritable.
		log.Printf("[!] could not spool result run=%s: %v — attempting direct delivery", payload.RunID, err)
		if err := a.postJSON("/api/scenarios/result", payload); err != nil {
			log.Printf("[x] result submit (%s) run=%s failed and could not be spooled: %v", label, payload.RunID, err)
		} else {
			log.Printf("[+] results submitted (%s): run=%s", label, payload.RunID)
		}
		return
	}
	// Persisted durably; let the drainer deliver and delete on success.
	a.drainSpool()
}

// deriveLocalResultLabel rolls per-step results up to the single label shown on
// the agent's local console. It mirrors the server's 4-verdict taxonomy
// (PASS/FAIL/ERROR/SKIPPED): a step the agent could not conclusively execute —
// it timed out, or exited non-zero without being blocked — is an ERROR and is
// excluded from the Detected/Evaded decision, exactly as the server excludes
// ERROR/SKIPPED from scoring. The agent stays a dumb executor: it classifies
// only on the signals it owns (Blocked / TimedOut / ExitCode), never by
// re-parsing command output — that interpretation is the server's job.
func deriveLocalResultLabel(results []ExecResult, partial bool) string {
	if partial {
		return "Partial" // run was cancelled before finishing
	}
	blocked, evaded := 0, 0
	for _, r := range results {
		switch {
		case r.Blocked:
			blocked++ // a control stopped the technique → PASS
		case r.TimedOut:
			// ran but never returned → ERROR, excluded from scoring
		case r.ExitCode == 0:
			evaded++ // technique ran cleanly and unblocked → FAIL
		default:
			// non-zero exit, not blocked → inconclusive → ERROR, excluded
		}
	}
	scored := blocked + evaded // ERROR steps excluded, mirroring the server
	switch {
	case scored == 0:
		return "Error" // nothing executed conclusively — inconclusive run
	case blocked == scored:
		return "Detected"
	case blocked > 0:
		return "Partial"
	default:
		return "Evaded"
	}
}

func (a *Agent) runLocalScan(scenarioID, runID string, selected []string) {
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
	// Populate the local operation so the status console's operation panel agrees
	// with the "Simulation In Progress" banner (the banner is driven by status,
	// the panel by currentOp — without this the panel reads "No active simulation"
	// during a posture scan). The ART path does this in runScenario.
	a.localSt.StartOperation(scenarioID, scenarioID, "", 0)

	categories := RunScenarioChecks(scenarioID)

	sel := make(map[string]bool, len(selected))
	for _, id := range selected {
		sel[id] = true
	}
	categories = runChecks(categories, sel) // execute (filtered) — checks no longer run at list time
	if len(categories) == 0 {
		log.Printf("[!] local scan %s: no checks matched selection (%d ids) — nothing to run", runID, len(selected))
	}

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
	a.submitRunResult(payload, "scan")

	// Close out the local operation so the console shows the completed scan
	// instead of leaving a stale "running" panel.
	a.localSt.UpdateProgress(len(checks), len(checks), "Upload")
	a.localSt.CompleteOperation("Completed", LocalEvidenceStats{EventsCollected: len(checks)})

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

		// Keepalive: arm a read deadline and reset it whenever the server pings.
		// The agent never sends app frames over the WS (heartbeats/events go over
		// HTTP), and ReadMessage does NOT return for ping control frames — so the
		// ping handler is what keeps a healthy connection alive. If the server
		// dies, pings stop, the deadline fires, ReadMessage errors, and we
		// reconnect. We reply with a pong (mirroring gorilla's default handler).
		conn.SetReadDeadline(time.Now().Add(wsPongWait))
		conn.SetPingHandler(func(appData string) error {
			conn.SetReadDeadline(time.Now().Add(wsPongWait))
			err := conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(wsWriteWait))
			if err == websocket.ErrCloseSent {
				return nil
			}
			return err
		})

		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				log.Printf("[!] WS read: %v — reconnecting", err)
				a.logger.Op("warn", "connectivity", fmt.Sprintf("WebSocket disconnected: %v", err))
				conn.Close()
				break
			}
			// Any inbound frame is also proof of life — extend the deadline.
			conn.SetReadDeadline(time.Now().Add(wsPongWait))

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
				a.runWG.Add(1)
				go func() { defer a.runWG.Done(); a.runLocalScan(sim.ScenarioID, sim.RunID, sim.Checks) }()

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
