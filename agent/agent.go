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
	mu             sync.Mutex
	client         *http.Client
	cancelScenario context.CancelFunc
	scenarioMu     sync.Mutex
}

func newAgent(cfg Config, id Identity) *Agent {
	return &Agent{
		cfg:    cfg,
		id:     id,
		status: "idle",
		client: &http.Client{Timeout: 30 * time.Second},
	}
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

func (a *Agent) postJSON(path string, body interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	resp, err := a.client.Post(a.cfg.ServerURL+path, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server %d on %s", resp.StatusCode, path)
	}
	return nil
}

func (a *Agent) sendHeartbeat(status string) {
	hb := Heartbeat{
		AgentID:   a.id.AgentID,
		Hostname:  a.id.Hostname,
		IPAddress: a.id.IPAddress,
		OSVersion: a.id.OSVersion,
		Username:  a.id.Username,
		Status:    status,
		EnvLabel:  a.cfg.EnvLabel,
	}
	if err := a.postJSON("/api/heartbeat", hb); err != nil {
		log.Printf("[!] heartbeat: %v", err)
	} else {
		log.Printf("[~] heartbeat: %s", status)
	}
}

func (a *Agent) runScenario(ctx context.Context, cmd ScenarioCommand) {
	log.Printf("[*] scenario started: run=%s scenario=%s steps=%d",
		cmd.RunID, cmd.ScenarioID, len(cmd.Steps))
	a.setStatus("scanning")
	a.sendHeartbeat("scanning")

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
			a.submitResults(cmd, results, true)
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
				log.Printf("[*]   staged %d payload(s) to %s", len(step.Payloads), payloadDir)
			}
		}

		step.PayloadDir = payloadDir
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

	a.submitResults(cmd, results, false)
	a.setStatus("idle")
	a.sendHeartbeat("idle")
}

func (a *Agent) submitResults(cmd ScenarioCommand, results []ExecResult, partial bool) {
	payload := RawRunResult{
		RunID:      cmd.RunID,
		ScenarioID: cmd.ScenarioID,
		AgentID:    a.id.AgentID,
		Results:    results,
		Partial:    partial,
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
	log.Printf("[*] local scan started: scenario=%s run=%s", scenarioID, runID)
	a.setStatus("scanning")
	a.sendHeartbeat("scanning")

	categories := RunScenarioChecks(scenarioID)

	results := make([]ExecResult, 0)
	for _, cat := range categories {
		for _, ch := range cat.Checks {
			var stdout string
			exitCode := 0
			switch ch.Result {
			case "pass":
				stdout = "PASS: " + ch.Details
			case "fail":
				stdout = "FAIL: " + ch.Details
				exitCode = 1
			default:
				stdout = "SKIP: " + ch.Details
			}
			results = append(results, ExecResult{
				TaskID:     ch.ID,
				ExitCode:   exitCode,
				Stdout:     stdout,
				DurationMs: ch.DurationMs,
				ExecutedAt: ch.ExecutedAt,
			})
		}
	}

	payload := RawRunResult{
		RunID:      runID,
		ScenarioID: scenarioID,
		AgentID:    a.id.AgentID,
		Results:    results,
	}
	if err := a.postJSON("/api/scenarios/result", payload); err != nil {
		log.Printf("[!] local scan submit: %v", err)
	} else {
		log.Printf("[+] local scan submitted: scenario=%s checks=%d", scenarioID, len(results))
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
