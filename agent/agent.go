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
	"strings"
	"sync"
	"time"

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
	binaryHash     string // SHA-256 of own binary, computed once at startup
}

func newAgent(cfg Config, id Identity) *Agent {
	a := &Agent{
		cfg:    cfg,
		id:     id,
		status: "idle",
		client: &http.Client{Timeout: 30 * time.Second},
	}
	if h, err := SelfHash(); err == nil {
		a.binaryHash = h
		log.Printf("[*] binary hash: %s", h[:16]+"...")
	} else {
		log.Printf("[!] could not hash binary: %v", err)
	}
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
		if path == "/api/scenarios/result" || path == "/api/report" {
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
	if resp.State == "quarantined" {
		log.Printf("[!] AGENT IS QUARANTINED — scenario execution blocked; contact your BAS administrator")
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
	}
	var resp HeartbeatResponse
	if err := a.postJSONDecode("/api/heartbeat", hb, &resp); err != nil {
		log.Printf("[!] heartbeat: %v", err)
		return
	}
	if resp.State != "" {
		a.mu.Lock()
		prev := a.state
		a.state = resp.State
		a.mu.Unlock()
		if resp.State == "quarantined" && prev != "quarantined" {
			log.Printf("[!] SERVER HAS QUARANTINED THIS AGENT — scenario execution blocked; contact administrator")
		}
	}
	log.Printf("[~] heartbeat: %s (state=%s)", status, resp.State)
}

func (a *Agent) runScenario(ctx context.Context, cmd ScenarioCommand) {
	// Local state guard — defense-in-depth alongside server-side enforcement.
	a.mu.Lock()
	st := a.state
	a.mu.Unlock()
	if st == "quarantined" || st == "restricted" || st == "retired" {
		log.Printf("[!] scenario blocked locally — agent state=%s (run %s)", st, cmd.RunID)
		return
	}
	log.Printf("[*] scenario started: run=%s scenario=%s steps=%d mode=%s",
		cmd.RunID, cmd.ScenarioID, len(cmd.Steps), cmd.Mode)

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
	results := make([]ExecResult, 0, len(cmd.Steps))

	for i, step := range cmd.Steps {
		select {
		case <-ctx.Done():
			log.Printf("[*] scenario interrupted at step %d/%d — submitting partial results", i+1, len(cmd.Steps))
			reverted := revertFromSnapshot(snap)
			if len(reverted) > 0 {
				log.Printf("[*] reverted %d change(s) after partial run", len(reverted))
			}
			a.submitResults(cmd, results, true, reverted)
			a.setStatus("idle")
			a.sendHeartbeat("idle")
			return
		default:
		}

		log.Printf("[*]   [%d/%d] %s (%s) — %s", i+1, len(cmd.Steps), step.TechniqueID, step.Executor, step.Name)

		if len(step.Payloads) > 0 {
			if err := StagePayloads(step.Payloads, payloadDir); err != nil {
				log.Printf("[!]   payload stage: %v", err)
			} else {
				// Check if AV/EDR quarantined a payload immediately after staging
				if name := CheckPayloadQuarantine(step.Payloads, payloadDir); name != "" {
					log.Printf("[!]   payload quarantined by security control: %s", name)
					results = append(results, ExecResult{
						TaskID:        step.TaskID,
						ExitCode:      -1,
						Blocked:       true,
						BlockedReason: fmt.Sprintf("payload '%s' quarantined by security control before execution", name),
						ExecutedAt:    time.Now(),
					})
					continue
				}
				log.Printf("[*]   staged %d payload(s) to %s", len(step.Payloads), payloadDir)
			}
		}

		step.PayloadDir = payloadDir
		step.Env = policyEnv
		r := execStep(ctx, step)

		evtSummary := ""
		if len(r.Events) > 0 {
			evtSummary = fmt.Sprintf(" events=%d", len(r.Events))
		}
		log.Printf("[*]   → exit=%d dur=%dms%s", r.ExitCode, r.DurationMs, evtSummary)
		results = append(results, r)
	}

	log.Printf("[*] scenario done: run=%s steps=%d elapsed=%v",
		cmd.RunID, len(results), time.Since(start).Round(time.Millisecond))

	reverted := revertFromSnapshot(snap)
	if len(reverted) > 0 {
		log.Printf("[*] reverted %d change(s) after run", len(reverted))
	}
	a.submitResults(cmd, results, false, reverted)
	a.setStatus("idle")
	a.sendHeartbeat("idle")
}

func (a *Agent) submitResults(cmd ScenarioCommand, results []ExecResult, partial bool, reverted []string) {
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

		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				log.Printf("[!] WS read: %v — reconnecting", err)
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

			default:
				log.Printf("[~] WS: unhandled message type %q", msg.Type)
			}
		}

		time.Sleep(wsReconnectDelay)
	}
}
