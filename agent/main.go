package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

const (
	version           = "2.1.0"
	heartbeatInterval = 30 * time.Second
	wsReconnectDelay  = 5 * time.Second
)

// ── Config ────────────────────────────────────────────────────────────────────

type Config struct {
	ServerURL string
	EnvLabel  string
}

func loadConfig() Config {
	serverURL := os.Getenv("BAS_SERVER_URL")
	envLabel := os.Getenv("BAS_ENV_LABEL")

	if serverURL == "" || envLabel == "" {
		if u, e := readServiceParams(); u != "" || e != "" {
			if serverURL == "" {
				serverURL = u
			}
			if envLabel == "" {
				envLabel = e
			}
		}
	}
	if serverURL == "" {
		serverURL = "http://localhost:9000"
	}
	if envLabel == "" {
		envLabel = "Production"
	}
	return Config{
		ServerURL: strings.TrimRight(serverURL, "/"),
		EnvLabel:  envLabel,
	}
}

// ── Identity ──────────────────────────────────────────────────────────────────

type Identity struct {
	AgentID   string
	Hostname  string
	IPAddress string
	OSVersion string
	Username  string
}

func collectIdentity() Identity {
	hostname, _ := os.Hostname()

	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}
	if username == "" {
		username = "unknown"
	}

	h := sha256.Sum256([]byte(hostname))
	agentID := hex.EncodeToString(h[:])[:16]

	osVer := fmt.Sprintf("Windows/%s (%s)", runtime.GOARCH, getWindowsVersion())

	return Identity{
		AgentID:   agentID,
		Hostname:  hostname,
		IPAddress: getOutboundIP(),
		OSVersion: osVer,
		Username:  username,
	}
}

func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// ── Wire Protocol ─────────────────────────────────────────────────────────────

type Heartbeat struct {
	AgentID   string `json:"agentId"`
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ipAddress"`
	OSVersion string `json:"osVersion"`
	Username  string `json:"username"`
	Status    string `json:"status"`
	EnvLabel  string `json:"envLabel"`
}

type WSMessage struct {
	Type    string          `json:"type"`
	AgentID string          `json:"agentId,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// ScenarioCommand is sent by the server to trigger a scenario run.
// Steps contain fully-resolved commands — no framework knowledge required by the agent.
type ScenarioCommand struct {
	RunID      string         `json:"runId"`
	ScenarioID string         `json:"scenarioId"`
	Name       string         `json:"name"`
	Steps      []ScenarioStep `json:"steps"`
}

// RawRunResult is what the agent posts back after executing all steps.
// Partial=true means the agent was interrupted and results are incomplete.
type RawRunResult struct {
	RunID      string       `json:"runId"`
	ScenarioID string       `json:"scenarioId"`
	AgentID    string       `json:"agentId"`
	Results    []ExecResult `json:"results"`
	Partial    bool         `json:"partial,omitempty"`
}

// ── Agent ─────────────────────────────────────────────────────────────────────

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

// runScenario executes each step sent by the server and returns raw results.
// All intelligence (command building, result interpretation) lives on the server.
// ctx is cancelled on agent shutdown — partial results are submitted immediately.
func (a *Agent) runScenario(ctx context.Context, cmd ScenarioCommand) {
	log.Printf("[*] scenario started: run=%s scenario=%s steps=%d",
		cmd.RunID, cmd.ScenarioID, len(cmd.Steps))
	a.setStatus("scanning")
	a.sendHeartbeat("scanning")

	payloadDir := filepath.Join(os.TempDir(), "bas-"+cmd.RunID)
	if err := os.MkdirAll(payloadDir, 0700); err != nil {
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
		// Check for shutdown before starting each step.
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

// runLocalScan runs built-in registry/PowerShell posture checks (no ART/Caldera needed).
// Results are posted to /api/scenarios/result using PASS:/FAIL:/SKIP: prefixes
// so the server's interpretCustom picks them up correctly.
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

// connectWS maintains the WebSocket connection to the orchestrator.
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

// ── Entry Point ───────────────────────────────────────────────────────────────

func main() {
	log.SetFlags(log.Ltime | log.Lmsgprefix)

	var (
		flagInstall   = flag.Bool("install", false, "Install BASAgent as a Windows Service")
		flagUninstall = flag.Bool("uninstall", false, "Uninstall BASAgent Windows Service")
		flagUpdate    = flag.Bool("update", false, "In-place binary update without reinstall")
		flagConsole   = flag.Bool("console", false, "Force interactive console mode")
		flagServer    = flag.String("server", "", "Override BAS_SERVER_URL")
		flagEnv       = flag.String("env", "Production", "Override BAS_ENV_LABEL")
	)
	flag.Parse()

	if *flagUpdate {
		if err := svcUpdate(); err != nil {
			fmt.Fprintf(os.Stderr, "update failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *flagInstall {
		serverURL := *flagServer
		if serverURL == "" {
			serverURL = os.Getenv("BAS_SERVER_URL")
		}
		if serverURL == "" {
			fmt.Fprintln(os.Stderr, "error: provide --server <url> or set BAS_SERVER_URL")
			os.Exit(1)
		}
		if err := svcInstall(serverURL, *flagEnv); err != nil {
			fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *flagUninstall {
		if err := svcUninstall(); err != nil {
			fmt.Fprintf(os.Stderr, "uninstall failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if !*flagConsole && isWindowsService() {
		if err := svcRun(); err != nil {
			log.Fatalf("[!] service run: %v", err)
		}
		return
	}

	if !isElevated() {
		log.Println("[!] Not running as Administrator — attempting UAC elevation...")
		if err := selfElevate(); err != nil {
			log.Printf("[!] UAC elevation failed: %v", err)
			log.Println("[!] Some checks will be skipped without admin rights.")
		} else {
			os.Exit(0)
		}
	}

	enablePrivileges()

	cfg := loadConfig()
	id := collectIdentity()

	fmt.Printf("\n")
	fmt.Printf("  BAS Agent v%s\n", version)
	fmt.Printf("  Hostname  : %s\n", id.Hostname)
	fmt.Printf("  AgentID   : %s\n", id.AgentID)
	fmt.Printf("  IP        : %s\n", id.IPAddress)
	fmt.Printf("  OS        : %s\n", id.OSVersion)
	fmt.Printf("  Server    : %s\n", cfg.ServerURL)
	fmt.Printf("  Env       : %s\n", cfg.EnvLabel)
	fmt.Printf("  Elevated  : %v\n", isElevated())
	fmt.Printf("\n")

	agent := newAgent(cfg, id)

	go agent.connectWS()
	agent.sendHeartbeat("idle")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			agent.sendHeartbeat(agent.getStatus())
		case <-quit:
			log.Println("[*] Shutting down — interrupting active scenario if any...")
			agent.scenarioMu.Lock()
			if agent.cancelScenario != nil {
				agent.cancelScenario()
			}
			agent.scenarioMu.Unlock()
			time.Sleep(3 * time.Second) // allow partial result submit to complete
			agent.sendHeartbeat("offline")
			return
		}
	}
}
