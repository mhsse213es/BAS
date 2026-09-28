package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"audspect/agent/protocol"
	"audspect/agent/sched"
)

type Agent struct {
	// cfgPtr/clientPtr are atomic rather than plain fields: a never-enrolled
	// agent starts on the legacy transport and a background goroutine
	// (retryBootstrapUntilEnrolled) can upgrade both to the mTLS transport
	// mid-process the moment bootstrap finally succeeds (agent/bootstrap.go's
	// outcomeLegacyPending). Every caller reaches them through cfg()/
	// httpClient() so the swap is visible atomically, with no torn read and
	// no client rebuild required at any call site.
	cfgPtr         atomic.Pointer[Config]
	id             Identity
	status         string
	state          string // server-assigned lifecycle state: active|restricted|quarantined|retired
	mu             sync.Mutex
	clientPtr      atomic.Pointer[http.Client]
	// wsConn/wsConnMu track the currently active WebSocket connection so
	// upgradeToMTLS can force it closed from another goroutine: closing it
	// unblocks connectWS's in-flight ReadMessage, which sends it back to the
	// outer reconnect loop, which rebuilds its dialer from the just-upgraded
	// cfg() and reconnects over mTLS. nil when disconnected.
	wsConnMu       sync.Mutex
	wsConn         *websocket.Conn
	cancelScenario context.CancelFunc
	scenarioMu     sync.Mutex
	// pauseGate and pauseEmit belong to whichever run is currently active
	// through runScenario's scheduler (nil when idle or between runs — see
	// runScenario's defer cleanup, which is why this differs from
	// cancelScenario: calling a stale cancel() again is a harmless no-op,
	// but calling a stale emit() would incorrectly mark an already-finished
	// run as paused).
	pauseGate   *sched.Gate
	pauseEmit   func(RunEvent)
	// activeLimiter, activeWorkers, and activeRiskGate belong to whichever run
	// is currently active, exactly like pauseGate/pauseEmit above (nil/0 when
	// idle or between runs) -- the pressure loop reads these every tick under
	// scenarioMu to know which limiter/gate to adjust and what its
	// un-throttled ceiling should be.
	activeLimiter  *sched.ConcurrencyLimiter
	activeWorkers  int
	activeRiskGate *sched.RiskGate
	binaryHash    string           // SHA-256 of own binary, computed once at startup
	logger      *Logger          // 3-tier structured logger
	localSt     *LocalAgentState // in-memory state for local status API
	secProducts []string         // installed security products, enumerated once at startup (guarded by mu)
	spoolMu     sync.Mutex       // serializes spool drains so a tick and a reconnect-kick can't double-send
	spoolKick   chan struct{}    // buffered (cap 1): nudges the drainer to deliver immediately on reconnect

	// Disconnect tracking for the pause-then-finalize watchdog (guarded by mu).
	disconnectedSince time.Time // when the server link was lost; zero = connected
	watchdogTripped   bool      // the watchdog already finalized the run for this outage (one-shot)

	runWG sync.WaitGroup // tracks in-flight scenario/scan goroutines so shutdown can wait for them to spool a Partial

	// Attack-path job progress reported in each heartbeat (guarded by mu).
	currentJobID        string
	currentJobStage     string
	currentJobCompleted int
	currentJobTotal     int
	currentJobPercent   int
}

// setCurrentJob records the active attack-path job so heartbeats carry progress.
// progressPercent is computed by the caller; pass 0 when unknown.
func (a *Agent) setCurrentJob(jobID, stage string, completed, total int) {
	pct := 0
	if total > 0 {
		pct = completed * 100 / total
	}
	a.mu.Lock()
	a.currentJobID = jobID
	a.currentJobStage = stage
	a.currentJobCompleted = completed
	a.currentJobTotal = total
	a.currentJobPercent = pct
	a.mu.Unlock()
}

// clearCurrentJob zeroes out the active job after collection finishes.
func (a *Agent) clearCurrentJob() {
	a.mu.Lock()
	a.currentJobID = ""
	a.currentJobStage = ""
	a.currentJobCompleted = 0
	a.currentJobTotal = 0
	a.currentJobPercent = 0
	a.mu.Unlock()
}

var errDisableFailedForTest = errors.New("disable failed (test)")

func newAgent(cfg Config, id Identity) *Agent {
	transport := &http.Transport{DialContext: proxyAwareNetDialContext(cfg), Proxy: nil}
	transport.TLSClientConfig = agentTLSConfig(cfg)
	a := &Agent{
		id:        id,
		status:    "idle",
		logger:    NewLogger(cfg, id.AgentID),
		localSt:   newLocalAgentState(),
		spoolKick: make(chan struct{}, 1),
	}
	a.cfgPtr.Store(&cfg)
	a.clientPtr.Store(&http.Client{Timeout: 30 * time.Second, Transport: transport})
	if h, err := SelfHash(); err == nil {
		a.binaryHash = h
		log.Printf("[*] binary hash: %s", h[:16]+"...")
	} else {
		log.Printf("[!] could not hash binary: %v", err)
	}
	// Enumerate installed security products once, off the startup path (the WMI /
	// Defender queries can take a few seconds). Cached for the heartbeat.
	go func() {
		products, diag := enumerateSecurityProducts()
		a.mu.Lock()
		a.secProducts = products
		a.mu.Unlock()
		if len(products) > 0 {
			log.Printf("[*] security products detected: %s", strings.Join(products, ", "))
		}
		for _, d := range diag {
			log.Printf("[!] security product detection: %s", d)
			a.logger.Op("warn", "secproducts", d)
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

// cfg returns the agent's current operational Config. See cfgPtr's doc
// comment on the Agent struct for why this is atomic rather than a plain
// field read.
func (a *Agent) cfg() Config { return *a.cfgPtr.Load() }

// httpClient returns the agent's current plain-HTTP client (heartbeat,
// enroll, submitResult, uninstall-result). See clientPtr's doc comment.
func (a *Agent) httpClient() *http.Client { return a.clientPtr.Load() }

// upgradeToMTLS atomically swaps the agent's operational Config and HTTP
// client to newCfg's mTLS transport, then force-closes the current
// WebSocket connection (if any) so connectWS's reconnect loop picks up the
// new transport on its very next attempt, rather than waiting out however
// long the current connection happens to stay up. Called exactly once, by
// retryBootstrapUntilEnrolled, the moment a never-enrolled agent's
// background bootstrap finally succeeds.
//
// After this call, legacy transport is permanently retired for this
// process: cfg()/httpClient() only ever return the mTLS-backed values from
// here on, matching the security invariant that legacy transport is a
// bootstrap compatibility mechanism, never something an already-enrolled
// identity returns to.
func (a *Agent) upgradeToMTLS(newCfg Config) {
	transport := &http.Transport{DialContext: proxyAwareNetDialContext(newCfg), Proxy: nil}
	transport.TLSClientConfig = agentTLSConfig(newCfg)
	a.cfgPtr.Store(&newCfg)
	a.clientPtr.Store(&http.Client{Timeout: 30 * time.Second, Transport: transport})
	log.Printf("[+] certificate obtained -- switched permanently to mTLS (%s); legacy transport disabled for this process", newCfg.ServerURL)
	a.logger.Op("info", "connectivity", fmt.Sprintf("upgraded to mTLS transport: %s", newCfg.ServerURL))

	a.wsConnMu.Lock()
	if a.wsConn != nil {
		a.wsConn.Close()
	}
	a.wsConnMu.Unlock()
}

// retryBootstrapUntilEnrolled runs only when the agent started on the
// legacy fallback transport -- a never-enrolled identity whose initial
// bootstrap attempt failed (agent/bootstrap.go's outcomeLegacyPending).
// It periodically retries bootstrap with bootstrapRetryBackoff (never a
// tight loop) until resolveOperationalConfig reports outcomeMTLSReady,
// then upgrades exactly once via upgradeToMTLS and returns. Never invoked
// for an already-enrolled identity: outcomeBlocked's retry loop runs
// entirely in main(), before newAgent is ever called, and never touches
// legacy transport at all.
func (a *Agent) retryBootstrapUntilEnrolled(ctx context.Context) {
	attempt := 0
	for {
		newCfg, outcome := resolveOperationalConfig(ctx, a.cfg(), a.id.AgentID)
		if outcome == outcomeMTLSReady {
			a.upgradeToMTLS(newCfg)
			return
		}
		delay := bootstrapRetryBackoff(attempt)
		log.Printf("[!] still on legacy transport, retrying enrollment in %s (attempt %d)", delay.Round(time.Second), attempt+1)
		attempt++
		time.Sleep(delay)
	}
}

// postJSONDecode POSTs body as JSON and optionally decodes the response into out.
// Pass nil for out to discard the response body.
func (a *Agent) postJSONDecode(path string, body interface{}, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, a.cfg().ServerURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if a.cfg().AgentSecret != "" {
		req.Header.Set("X-Agent-Token", a.cfg().AgentSecret)
	}
	resp, err := a.httpClient().Do(req)
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
	req := protocol.EnrollRequest{
		AgentID:        a.id.AgentID,
		Hostname:       a.id.Hostname,
		IPAddress:      a.id.IPAddress,
		OSVersion:      a.id.OSVersion,
		Username:       a.id.Username,
		EnvLabel:       a.cfg().EnvLabel,
		BinaryHash:     a.binaryHash,
		AgentVersion:   version,
		PostureCatalog: BuildPostureCatalog(),
	}
	resp, err := protocol.Enroll(context.Background(), a.httpClient(), a.cfg().ServerURL, a.cfg().AgentSecret, req)
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
		DomainJoined:  a.id.DomainJoined,
		Username:      a.id.Username,
		Status:        status,
		EnvLabel:      a.cfg().EnvLabel,
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
	resp, err := protocol.SendHeartbeat(context.Background(), a.httpClient(), a.cfg().ServerURL, a.cfg().AgentSecret, hb)
	if err != nil {
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

// pauseCurrentScenario pauses the in-flight scenario's step scheduler, if
// any. Already-executing step(s) always finish -- only the next step(s) a
// worker would otherwise start are held. Returns true if a run was active to
// pause. Idempotent: pausing an already-paused run is a harmless no-op.
func (a *Agent) pauseCurrentScenario() bool {
	a.scenarioMu.Lock()
	defer a.scenarioMu.Unlock()
	if a.pauseGate == nil {
		return false
	}
	a.pauseGate.Pause()
	if a.pauseEmit != nil {
		a.pauseEmit(RunEvent{Type: "paused"})
	}
	return true
}

// resumeCurrentScenario resumes a paused in-flight scenario's step
// scheduler, if any. Returns true if a run was active to resume. Idempotent.
func (a *Agent) resumeCurrentScenario() bool {
	a.scenarioMu.Lock()
	defer a.scenarioMu.Unlock()
	if a.pauseGate == nil {
		return false
	}
	a.pauseGate.Resume()
	if a.pauseEmit != nil {
		a.pauseEmit(RunEvent{Type: "resumed"})
	}
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

// platformDisableAutoStartFn, platformExitAfterStopFn, and
// platformSelfUninstallFn are indirections over the real platform-specific
// functions (defined per-OS in service.go/service_linux.go/service_darwin.go)
// so tests can substitute no-op stand-ins instead of actually touching
// service state or exiting the test process.
var (
	platformDisableAutoStartFn = platformDisableAutoStart
	platformExitAfterStopFn    = platformExitAfterStop
	platformSelfUninstallFn    = platformSelfUninstall
)

// stopSelf performs a durable, operator-requested shutdown: finalize any
// in-flight run, send a final heartbeat, disable the platform service so it
// does not come back (not on crash-recovery, not on next boot), then exit.
// See docs/superpowers/specs/2026-07-22-agent-remote-stop-design.md for why
// the disable step must run before exit, and why it differs per platform.
func (a *Agent) stopSelf(reason string) {
	log.Printf("[*] Stop requested by operator: %s", reason)
	a.logger.Op("warn", "lifecycle", "agent stopped by operator request: "+reason)
	a.shutdownFinalize(shutdownGrace)
	a.sendHeartbeat("offline")
	platformRestoreOnShutdown()
	if err := platformDisableAutoStartFn(); err != nil {
		log.Printf("[!] disable auto-start: %v — agent may restart at next boot", err)
	}
	platformExitAfterStopFn()
}

// uninstallSelf performs a durable, operator-requested full uninstall:
// finalize any in-flight run, remove the artifacts that make the agent come
// back (service/unit/daemon registration, tray autostart -- see
// platformSelfUninstall per platform), report the real outcome to the
// server BEFORE the process might exit, then disable+exit exactly like
// stopSelf does. Reporting before disable/exit matters because on some
// platforms disabling has the documented side effect of ending this very
// process (see platformDisableAutoStart's macOS implementation) -- if the
// report happened after, a failure could go unreported. See
// docs/superpowers/specs/2026-08-07-verified-agent-uninstall-design.md for
// why this never asks the OS service manager to stop the process from
// within itself.
func (a *Agent) uninstallSelf(reason string) {
	log.Printf("[*] Uninstall requested by operator: %s", reason)
	a.logger.Op("warn", "lifecycle", "agent uninstall requested by operator: "+reason)
	a.shutdownFinalize(shutdownGrace)
	a.sendHeartbeat("offline")
	platformRestoreOnShutdown()

	uninstallErr := platformSelfUninstallFn()
	if uninstallErr != nil {
		log.Printf("[!] self-uninstall cleanup failed: %v", uninstallErr)
	}
	reportUninstallResultFn(a, uninstallErr)

	if err := platformDisableAutoStartFn(); err != nil {
		log.Printf("[!] disable auto-start: %v — agent may restart at next boot", err)
	}
	platformExitAfterStopFn()
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

// ScenarioStep is the agent's own execution-facing step representation,
// decoded once (via decodeStep) from protocol.ScenarioStep's wire form
// when a scenario is dispatched. Kept as a package-local type rather than
// using protocol.ScenarioStep directly because Resource/Timeout need to be
// the real *sched.ResourceProfile/*sched.TimeoutProfile pointer types every
// execution file (executor.go, executor_windows.go, pool_windows.go, ...)
// already expects -- the wire type carries them as opaque JSON since
// agent/protocol must not depend on sched (an execution-scheduling
// package). Every other field mirrors protocol.ScenarioStep exactly.
type ScenarioStep struct {
	TaskID       string
	TechniqueID  string
	Name         string
	Executor     string
	Command      string
	TimeoutSec   int
	Payloads     []protocol.Payload
	Cleanup      string
	PayloadDir   string
	Resource     *sched.ResourceProfile
	Timeout      *sched.TimeoutProfile
	Env          map[string]string
	RequiresPriv string
}

// decodeStep converts one wire-format protocol.ScenarioStep into the
// agent's local, execution-facing ScenarioStep, decoding the opaque
// Resource/Timeout JSON into their real sched types. A step whose
// Resource/Timeout JSON is absent or fails to decode simply gets a nil
// pointer for that field -- the same "no profile" behavior the original
// pre-refactor code had for an absent *sched.ResourceProfile/*TimeoutProfile.
func decodeStep(w protocol.ScenarioStep) ScenarioStep {
	s := ScenarioStep{
		TaskID: w.TaskID, TechniqueID: w.TechniqueID, Name: w.Name,
		Executor: w.Executor, Command: w.Command, TimeoutSec: w.TimeoutSec,
		Payloads: w.Payloads, Cleanup: w.Cleanup, RequiresPriv: w.RequiresPriv,
	}
	if len(w.Resource) > 0 {
		var rp sched.ResourceProfile
		if json.Unmarshal(w.Resource, &rp) == nil {
			s.Resource = &rp
		}
	}
	if len(w.Timeout) > 0 {
		var tp sched.TimeoutProfile
		if json.Unmarshal(w.Timeout, &tp) == nil {
			s.Timeout = &tp
		}
	}
	return s
}

func (a *Agent) runScenario(ctx context.Context, cmd protocol.ScenarioCommand) {
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

	// Per-scenario screen-timeout inhibition — only activated when the scenario
	// author explicitly sets prevent_screen_timeout: true in the YAML. Never on
	// by default; enterprise idle/lock policies apply for all other scenarios.
	if cmd.PreventScreenTimeout {
		inhibitScreenTimeout()
		defer restoreScreenTimeout()
	}

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
		a.submitResults(cmd, []protocol.ExecResult{{
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
	a.localSt.StartOperation(cmd.ScenarioID, cmd.Name, cmd.ScenarioID, cmd.SweepLabel, len(cmd.Steps))

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

	// Decode the wire-format steps into the agent's own execution-facing
	// ScenarioStep once, up front. protocol.ScenarioStep carries
	// Resource/Timeout as opaque JSON (agent/protocol must not depend on
	// sched); everything below this point needs the real decoded
	// *sched.ResourceProfile/*sched.TimeoutProfile, exactly as before this
	// package's types moved to agent/protocol.
	steps := make([]ScenarioStep, total)
	for i, w := range cmd.Steps {
		steps[i] = decodeStep(w)
	}

	// Steps run through the resource-lock scheduler: independent steps execute
	// concurrently, conflicting ones serialize, and unlabeled steps run serially.
	// Results are written to a fixed index per step so the submitted order is
	// deterministic (identical to a serial run) regardless of completion order.
	results := make([]protocol.ExecResult, total)
	ran := make([]bool, total)
	attemptCounters := make([]int32, total)
	var completed int64
	// started/finished feed runGaugeSampler's active/queued gauges below --
	// separate from `completed` (which is really "dispatched", used only for
	// the local progress bar and incremented before a step even begins).
	var startedJobs, finishedJobs int64

	workers := cmd.Workers
	if workers < 1 {
		workers = sched.DefaultWorkers()
	}

	// Warm PowerShell host pool for read-only discovery steps (skips per-step
	// process cold start). Created only if the scenario has a pooled candidate,
	// sized to the worker count, and torn down after the scheduler drains.
	var pool *HostPool
	if slices.ContainsFunc(steps, pooledCandidate) {
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
	emitCritical := func(ev RunEvent) { ev.RunID = cmd.RunID; ev.Seq = seq(); emitter.emitCritical(ev) }

	gate := sched.NewGate()
	a.scenarioMu.Lock()
	a.pauseGate = gate
	a.pauseEmit = emit
	a.scenarioMu.Unlock()
	defer func() {
		a.scenarioMu.Lock()
		a.pauseGate = nil
		a.pauseEmit = nil
		a.activeLimiter = nil
		a.activeWorkers = 0
		a.activeRiskGate = nil
		a.scenarioMu.Unlock()
	}()

	emitCritical(RunEvent{Type: "run_started", Payload: map[string]any{"stepsTotal": total, "mode": cmd.Mode}})

	// Constructed here (before the jobs-building loop below) rather than
	// alongside limiter/riskGate: the Run closures built inside that loop
	// reference cb, and Go requires a local variable's declaration to
	// textually precede any reference to it in the enclosing function --
	// unlike limiter/riskGate, cb is used inside those closures, not just
	// later at sched.Run(). Same per-run lifecycle as limiter/riskGate
	// otherwise (fresh breaker state per scenario run).
	cb := newCircuitBreaker(circuitBreakerThreshold)

	// Also constructed here, ahead of its usual position alongside
	// gaugeDone/limiter/riskGate below, for the same forward-reference
	// reason as cb: the Run closures call metrics.BreakerOpened/
	// BreakerSuppressed directly (breaker telemetry, not part of
	// sched.Recorder -- see sched_metrics.go), so metrics must exist
	// before those closures are built.
	metrics := &runMetrics{}

	jobs := make([]sched.Job, total)
	for i := range steps {
		step := steps[i] // per-job copy (PayloadDir/Env set below)

		// Layer 1 (schedule timeout): bound how long this step may wait for its
		// resource locks. On expiry the scheduler records an explicit timeout
		// verdict rather than blocking the worker indefinitely.
		var schedDur time.Duration
		schedSec := 0
		if step.Timeout != nil && step.Timeout.ScheduleSec > 0 {
			schedSec = step.Timeout.ScheduleSec
			schedDur = time.Duration(schedSec) * time.Second
		}

		risk := sched.EffectiveRisk(step.Resource)
		retryPolicy := retryPolicyForRisk(risk)
		breakerKeys := breakerKeysForStep(step.TechniqueID, step.Resource)

		emit(RunEvent{Type: "queued", TaskID: step.TaskID, TechniqueID: step.TechniqueID, StepName: step.Name})

		jobs[i] = sched.Job{
			Resource: step.Resource,
			Schedule: schedDur,
			Queued:   time.Now(),
			Retry:    retryPolicy,
			OnScheduleTimeout: func() {
				atomic.AddInt64(&startedJobs, 1)
				atomic.AddInt64(&finishedJobs, 1)
				n := atomic.AddInt64(&completed, 1)
				a.localSt.UpdateProgress(int(n), total, "Execution", step.TechniqueID+" — "+step.Name)
				log.Printf("[*]   [%d/%d] %s — schedule timeout after %ds (locks unavailable)", i+1, total, step.TechniqueID, schedSec)
				results[i] = protocol.ExecResult{
					TaskID:     step.TaskID,
					ExitCode:   -1,
					Stderr:     fmt.Sprintf("schedule timeout: resource locks unavailable within %ds", schedSec),
					ExecutedAt: time.Now(),
					TimedOut:   true,
				}
				ran[i] = true
				emit(RunEvent{Type: "timeout", TaskID: step.TaskID, TechniqueID: step.TechniqueID, StepName: step.Name,
					Payload: map[string]any{"reason": "schedule"}})
			},
			Run: func(ctx context.Context) bool {
				// firstAttempt is read before attemptCounters[i] is incremented below
				// (Phase 7 invokes this closure once per retry attempt, not once per
				// step) -- startedJobs/completed/UpdateProgress must fire exactly
				// once per step, not once per attempt, or a retrying step inflates
				// them past total.
				firstAttempt := atomic.LoadInt32(&attemptCounters[i]) == 0
				var willRetry bool
				if firstAttempt {
					atomic.AddInt64(&startedJobs, 1)
				}
				defer func() {
					// finishedJobs must likewise fire only once the step is truly
					// done (no further attempt coming), not once per attempt.
					// willRetry's bool zero value (false) is exactly right for both
					// early-return paths (quarantine block below, and Phase 8's
					// future circuit-breaker skip) -- they never reach the
					// assignment further down, so this still counts them as
					// terminal.
					if !willRetry {
						atomic.AddInt64(&finishedJobs, 1)
					}
				}()
				if firstAttempt {
					n := atomic.AddInt64(&completed, 1)
					a.localSt.UpdateProgress(int(n), total, "Execution", step.TechniqueID+" — "+step.Name)
				}
				log.Printf("[*]   [%d/%d] %s (%s) — %s", i+1, total, step.TechniqueID, step.Executor, step.Name)
				a.logger.Sec("info", cmd.ScenarioID, cmd.RunID, step.TaskID, step.TechniqueID,
					"scenario_step", fmt.Sprintf("[%d/%d] %s executor=%s", i+1, total, step.Name, step.Executor))

				emit(RunEvent{Type: "started", TaskID: step.TaskID, TechniqueID: step.TechniqueID, StepName: step.Name})

				// Only block a step's first attempt -- a retry that already wrote a real
				// result to results[i] must never have it silently clobbered by a breaker
				// that opened after that attempt ran.
				if firstAttempt && cb.anyOpen(breakerKeys) {
					metrics.BreakerSuppressed()
					keys := strings.Join(breakerKeys, ", ")
					log.Printf("[!]   [%d/%d] %s skipped -- circuit breaker open for %s", i+1, total, step.TechniqueID, keys)
					results[i] = protocol.ExecResult{
						TaskID:     step.TaskID,
						ExitCode:   -1,
						Stdout:     fmt.Sprintf("skip: circuit breaker open for %s", keys),
						ExecutedAt: time.Now(),
					}
					ran[i] = true
					emit(RunEvent{Type: "completed", TaskID: step.TaskID, TechniqueID: step.TechniqueID, StepName: step.Name,
						Payload: map[string]any{"verdict": "skipped", "reason": "circuit_open"}})
					return false
				}

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
							results[i] = protocol.ExecResult{
								TaskID:        step.TaskID,
								ExitCode:      -1,
								Blocked:       true,
								BlockedReason: fmt.Sprintf("payload '%s' quarantined by security control before execution", name),
								ExecutedAt:    time.Now(),
							}
							ran[i] = true
							emit(RunEvent{Type: "completed", TaskID: step.TaskID, TechniqueID: step.TechniqueID, StepName: step.Name,
								Payload: map[string]any{"verdict": "blocked"}})
							return false
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
				emit(RunEvent{Type: typ, TaskID: step.TaskID, TechniqueID: step.TechniqueID, StepName: step.Name, Payload: payload})

				retry := isRetryableResult(r)
				attemptNum := atomic.AddInt32(&attemptCounters[i], 1)
				willRetry = retry && int(attemptNum) < retryPolicy.MaxAttempts
				if willRetry {
					log.Printf("[*]   [%d/%d] %s will retry (attempt %d/%d)", i+1, total, step.TechniqueID, attemptNum, retryPolicy.MaxAttempts)
					emit(RunEvent{Type: "retrying", TaskID: step.TaskID, TechniqueID: step.TechniqueID, StepName: step.Name,
						Payload: map[string]any{"attempt": int(attemptNum), "maxAttempts": retryPolicy.MaxAttempts}})
				} else {
					// Terminal outcome for this step (success, or its own retry
					// budget exhausted): record it against every key it touched.
					// success iff not retryable -- a genuine pass, or a
					// non-retryable block encountered mid-execution (as opposed to
					// the pre-execution quarantine early-return above, which is
					// never recorded at all -- a security-control block is not
					// evidence the underlying domain/technique is broken).
					for range cb.recordAll(breakerKeys, !retry) {
						metrics.BreakerOpened()
					}
				}
				return willRetry
			},
		}
	}

	gaugeDone := make(chan struct{})
	go runGaugeSampler(a.logger, &startedJobs, &finishedJobs, total, gaugeSampleInterval, gaugeDone)

	// Admission ceiling defaults to the worker count -- a no-op until the
	// pressure loop's ticker (agent/pressure_loop.go) observes sustained host
	// pressure and calls SetLimit to lower it. riskGate similarly starts at
	// its default admit-everything policy until the pressure loop narrows it.
	limiter := sched.NewConcurrencyLimiter(workers)
	riskGate := sched.NewRiskGate()
	a.scenarioMu.Lock()
	a.activeLimiter = limiter
	a.activeWorkers = workers
	a.activeRiskGate = riskGate
	a.scenarioMu.Unlock()

	sched.Run(ctx, workers, sched.NewLockManager(), jobs, gate,
		sched.WithRecorder(metrics), sched.WithConcurrencyLimiter(limiter), sched.WithRiskGate(riskGate))

	close(gaugeDone)
	metrics.report(a.logger, total)

	// Collect completed results in submission order. On cancellation the
	// scheduler skips not-yet-started jobs, so some indices stay unran.
	final := make([]protocol.ExecResult, 0, total)
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

func (a *Agent) submitResults(cmd protocol.ScenarioCommand, results []protocol.ExecResult, partial bool, reverted []string) {
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
	a.localSt.UpdateProgress(len(results), len(results), "Upload", "")
	a.localSt.CompleteOperation(resultLabel, ev, cmd.SweepID, cmd.SweepName, cmd.SweepFinal)

	payload := protocol.RawRunResult{
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
	if posixDetectionGatedOff() {
		log.Printf("[detect] run %s: POSIX detection submission is gated off; not collecting", runID)
		return
	}
	alerts, truncated := collectAlerts(from, to, maxEvents, maxBytes)
	if len(alerts) == 0 {
		log.Printf("[detect] run %s: no alerts collected in window", runID)
		return
	}
	payload := protocol.RunDetections{
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
func (a *Agent) submitRunResult(payload protocol.RawRunResult, label string) {
	if _, err := a.spoolWrite(payload, label); err != nil {
		// Could not persist — fall back to a direct best-effort send so an online
		// agent still delivers even if the spool dir is unwritable.
		log.Printf("[!] could not spool result run=%s: %v — attempting direct delivery", payload.RunID, err)
		if err := protocol.SubmitResult(context.Background(), a.httpClient(), a.cfg().ServerURL, a.cfg().AgentSecret, payload); err != nil {
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
func deriveLocalResultLabel(results []protocol.ExecResult, partial bool) string {
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

func (a *Agent) runLocalScan(ctx context.Context, scenarioID, runID string, selected []string) {
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
	a.localSt.StartOperation(scenarioID, scenarioID, "", "", 0)

	categories := RunScenarioChecks(scenarioID)

	sel := make(map[string]bool, len(selected))
	for _, id := range selected {
		sel[id] = true
	}

	// Live progress events -- without these the orchestrator's Live Run view
	// (driven entirely by run_events) never receives a single event for a
	// local-check scan and stays stuck at "Waiting for the first step…"
	// forever, even after the scan has genuinely completed with real results.
	// Mirrors the same event shape/plumbing runScenario uses for ART/Custom
	// steps (see events.go).
	var nextSeq int64
	seq := func() int64 { return atomic.AddInt64(&nextSeq, 1) }
	emitter := newEventEmitter(
		func(b []RunEvent) error { return a.postJSON("/api/scenarios/events", b) },
		1000, 300*time.Millisecond,
	)
	defer emitter.close()
	emit := func(ev RunEvent) { ev.RunID = runID; ev.Seq = seq(); emitter.emit(ev) }
	emitCritical := func(ev RunEvent) { ev.RunID = runID; ev.Seq = seq(); emitter.emitCritical(ev) }

	// Pause/Resume reuses the exact shared a.pauseGate/a.pauseEmit fields
	// runScenario uses -- command_pause/command_resume already operate
	// generically on whatever's set here, so no WS dispatch changes were
	// needed to extend pause to posture-mode scans. ctx (wired by the caller
	// from a.cancelScenario, same as runScenario) lets command_cancel stop a
	// scan that's mid-flight OR currently paused -- gate.Wait(ctx) unblocks
	// on either Resume or ctx cancellation.
	gate := sched.NewGate()
	a.scenarioMu.Lock()
	a.pauseGate = gate
	a.pauseEmit = emit
	a.scenarioMu.Unlock()
	defer func() {
		a.scenarioMu.Lock()
		a.pauseGate = nil
		a.pauseEmit = nil
		a.scenarioMu.Unlock()
	}()

	total := 0
	for _, cat := range categories {
		for _, c := range cat.Checks {
			if len(sel) > 0 && !sel[c.ID] {
				continue
			}
			total++
		}
	}
	emitCritical(RunEvent{Type: "run_started", Payload: map[string]any{"stepsTotal": total}})

	categories, partial := runChecks(ctx, categories, sel, gate, func(c SimCheck) { // execute (filtered) — checks no longer run at list time
		emit(RunEvent{Type: "started", TaskID: c.ID, TechniqueID: c.Technique.ID, StepName: c.Technique.Name})
		emit(RunEvent{Type: "completed", TaskID: c.ID, TechniqueID: c.Technique.ID, StepName: c.Technique.Name,
			Payload: map[string]any{"verdict": c.Result, "durationMs": c.DurationMs}})
	})
	if len(categories) == 0 && !partial {
		log.Printf("[!] local scan %s: no checks matched selection (%d ids) — nothing to run", runID, len(selected))
	}
	stepsDone := 0
	for _, cat := range categories {
		stepsDone += len(cat.Checks)
	}
	if partial {
		emit(RunEvent{Type: "run_cancelled", Payload: map[string]any{"stepsDone": stepsDone}})
		log.Printf("[*] local scan %s cancelled — %d/%d checks completed, submitting partial results", runID, stepsDone, total)
	} else {
		emit(RunEvent{Type: "run_completed", Payload: map[string]any{"stepsDone": stepsDone}})
	}

	// Submit full SimCheck metadata so the orchestrator can correctly populate
	// technique ID, tactic, severity, threat impact, and remediation without
	// having to re-derive them from an empty step definition.
	checks := make([]protocol.SimCheckResult, 0)
	for _, cat := range categories {
		for _, ch := range cat.Checks {
			checks = append(checks, protocol.SimCheckResult{
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

	payload := protocol.RawRunResult{
		RunID:      runID,
		ScenarioID: scenarioID,
		AgentID:    a.id.AgentID,
		Checks:     checks,
		Partial:    partial,
	}
	scanLabel := "scan"
	if partial {
		scanLabel = "scan-partial"
	}
	a.submitRunResult(payload, scanLabel)

	// Close out the local operation so the console shows the completed scan
	// instead of leaving a stale "running" panel.
	opResult := "Completed"
	if partial {
		opResult = "Partial"
	}
	a.localSt.UpdateProgress(len(checks), len(checks), "Upload", "")
	a.localSt.CompleteOperation(opResult, LocalEvidenceStats{EventsCollected: len(checks)}, "", "", false)

	a.setStatus("idle")
	a.sendHeartbeat("idle")
}

func (a *Agent) connectWS() {
	// attempt counts consecutive failed/bounced connections. It drives the
	// exponential-backoff delay before the next dial and is reset only once a
	// connection proves itself genuinely established (see wsShouldResetBackoff) —
	// never merely because Dial returned no error. Across a fleet, this plus
	// wsJitter's full jitter is what keeps a server restart from bringing every
	// agent back in lockstep.
	attempt := 0
	for {
		// Rebuilt every attempt (not once outside the loop) so a cfg()
		// upgrade from legacy to mTLS transport (upgradeToMTLS) is picked
		// up by the very next dial, not just by whichever dialer happened
		// to be in scope when connectWS started.
		cfg := a.cfg()
		dialer := &websocket.Dialer{HandshakeTimeout: 45 * time.Second, NetDialContext: proxyAwareNetDialContext(cfg)}
		dialer.TLSClientConfig = agentTLSConfig(cfg) // GetClientCertificate re-reads the cert per handshake, so every reconnect picks up a renewal

		conn, err := protocol.DialAgentWSWithDialer(cfg.ServerURL, a.id.AgentID, cfg.AgentSecret, dialer)
		if err != nil {
			delay := wsReconnectBackoff(attempt)
			if errors.Is(err, ErrProxyCredentialsRejected) {
				delay = wsProxyAuthReconnectBackoff(attempt)
			}
			log.Printf("[!] WS connect failed: %v — retry in %s (attempt %d)", err, delay.Round(time.Millisecond), attempt+1)
			a.logger.Op("warn", "connectivity", fmt.Sprintf("WebSocket dial failed (attempt %d): %v — retrying in %s", attempt+1, err, delay.Round(time.Millisecond)))
			attempt++
			time.Sleep(delay)
			continue
		}
		log.Printf("[+] WS connected: %s (after %d attempt(s))", cfg.ServerURL, attempt+1)
		a.logger.Op("info", "connectivity", fmt.Sprintf("WebSocket connected to %s (after %d attempt(s))", cfg.ServerURL, attempt+1))
		a.logger.Metric("ws_reconnect_attempts", float64(attempt), "count")
		// Flush events buffered while the connection was down.
		go a.logger.Flush()

		a.wsConnMu.Lock()
		a.wsConn = conn
		a.wsConnMu.Unlock()

		connectedAt := time.Now()
		gotMessage := false

		for {
			msg, err := protocol.ReadMessage(conn)
			if err != nil {
				heldFor := time.Since(connectedAt)
				log.Printf("[!] WS read: %v — reconnecting (connection held %s)", err, heldFor.Round(time.Millisecond))
				a.logger.Op("warn", "connectivity", fmt.Sprintf("WebSocket disconnected after %s: %v", heldFor.Round(time.Millisecond), err))
				a.logger.Metric("ws_connection_duration_seconds", heldFor.Seconds(), "seconds")
				conn.Close()
				a.wsConnMu.Lock()
				if a.wsConn == conn {
					a.wsConn = nil
				}
				a.wsConnMu.Unlock()
				if wsShouldResetBackoff(heldFor, gotMessage) {
					attempt = 0
				}
				break
			}
			gotMessage = true

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

		delay := wsReconnectBackoff(attempt)
		attempt++
		time.Sleep(delay)
	}
}
