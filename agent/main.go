package main

import (
	"bytes"
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
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

const (
	version           = "1.0.0"
	heartbeatInterval = 30 * time.Second
	wsReconnectDelay  = 5 * time.Second
)

// ── Config ────────────────────────────────────────────────────────────────────

type Config struct {
	ServerURL string
	EnvLabel  string
}

func loadConfig() Config {
	// Env vars take priority (interactive use).
	// Registry fallback is used when running as a Windows Service (no user env).
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

	// Stable agent ID: first 16 hex chars of SHA256(hostname)
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

// Heartbeat matches orchestrator models.Heartbeat JSON tags.
type Heartbeat struct {
	AgentID   string `json:"agentId"`
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ipAddress"`
	OSVersion string `json:"osVersion"`
	Username  string `json:"username"`
	Status    string `json:"status"`
	EnvLabel  string `json:"envLabel"`
}

// WSMessage matches orchestrator models.WSMessage.
type WSMessage struct {
	Type    string          `json:"type"`
	AgentID string          `json:"agentId,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// ScenarioCommand is sent by the orchestrator to trigger a scenario run.
type ScenarioCommand struct {
	RunID      string `json:"runId"`
	ScenarioID string `json:"scenarioId"`
	Name       string `json:"name"`
}

// ── Agent ─────────────────────────────────────────────────────────────────────

type Agent struct {
	cfg    Config
	id     Identity
	status string
	mu     sync.Mutex
	client *http.Client
}

func newAgent(cfg Config, id Identity) *Agent {
	return &Agent{
		cfg:    cfg,
		id:     id,
		status: "idle",
		client: &http.Client{Timeout: 20 * time.Second},
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

func (a *Agent) runScan() {
	log.Printf("[*] scan started")
	a.setStatus("scanning")
	a.sendHeartbeat("scanning")

	start := time.Now()
	cats := RunAllChecks()

	total, failed := 0, 0
	for _, c := range cats {
		total += len(c.Checks)
		for _, chk := range c.Checks {
			if chk.Result == "fail" {
				failed++
			}
		}
	}
	log.Printf("[*] scan done: %d checks, %d failed (%v)", total, failed, time.Since(start).Round(time.Millisecond))

	report := map[string]interface{}{
		"agentId":       a.id.AgentID,
		"hostname":      a.id.Hostname,
		"ipAddress":     a.id.IPAddress,
		"osVersion":     a.id.OSVersion,
		"username":      a.id.Username,
		"status":        "completed",
		"envLabel":      a.cfg.EnvLabel,
		"securityTools": []interface{}{},
		"categories":    cats,
	}

	if err := a.postJSON("/api/report", report); err != nil {
		log.Printf("[!] report submit: %v", err)
	} else {
		log.Printf("[+] report submitted (%d categories, %d checks)", len(cats), total)
	}

	a.setStatus("idle")
	a.sendHeartbeat("idle")
}

func (a *Agent) runScenario(cmd ScenarioCommand) {
	log.Printf("[*] scenario started: runId=%s scenarioId=%s", cmd.RunID, cmd.ScenarioID)
	a.setStatus("scanning")
	a.sendHeartbeat("scanning")

	start := time.Now()
	cats := RunScenarioChecks(cmd.ScenarioID)

	// Flatten all checks into a single results slice for the run record
	var results []interface{}
	for _, cat := range cats {
		for _, chk := range cat.Checks {
			results = append(results, chk)
		}
	}

	payload := map[string]interface{}{
		"id":          cmd.RunID,
		"scenarioId":  cmd.ScenarioID,
		"agentId":     a.id.AgentID,
		"status":      "completed",
		"results":     results,
		"startedAt":   start,
		"completedAt": time.Now(),
	}

	if err := a.postJSON("/api/scenarios/result", payload); err != nil {
		log.Printf("[!] scenario result submit: %v", err)
	} else {
		log.Printf("[+] scenario result submitted: runId=%s", cmd.RunID)
	}

	a.setStatus("idle")
	a.sendHeartbeat("idle")
}

// connectWS maintains the WebSocket connection to the orchestrator.
// Reconnects automatically on disconnect.
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
				log.Printf("[!] WS read error: %v — reconnecting", err)
				conn.Close()
				break
			}

			var msg WSMessage
			if err := json.Unmarshal(data, &msg); err != nil {
				continue
			}

			switch msg.Type {
			case "command_scan":
				log.Printf("[*] WS: command_scan received")
				go a.runScan()

			case "command_scenario":
				var cmd ScenarioCommand
				if err := json.Unmarshal(msg.Data, &cmd); err != nil {
					log.Printf("[!] WS: failed to parse scenario command: %v", err)
					continue
				}
				go a.runScenario(cmd)
			}
		}

		time.Sleep(wsReconnectDelay)
	}
}

// ── Entry Point ───────────────────────────────────────────────────────────────

func main() {
	log.SetFlags(log.Ltime | log.Lmsgprefix)

	// ── Flags ─────────────────────────────────────────────────────────────────
	var (
		flagInstall   = flag.Bool("install", false, "Install BASAgent as a Windows Service (SYSTEM, auto-start)")
		flagUninstall = flag.Bool("uninstall", false, "Uninstall BASAgent Windows Service")
		flagUpdate    = flag.Bool("update", false, "Stop service, replace binary in-place, restart — no reinstall needed")
		flagConsole   = flag.Bool("console", false, "Force interactive console mode even if service detection triggers")
		flagServer    = flag.String("server", "", "Override BAS_SERVER_URL (used with --install)")
		flagEnv       = flag.String("env", "Production", "Override BAS_ENV_LABEL (used with --install)")
	)
	flag.Parse()

	if *flagUpdate {
		if err := svcUpdate(); err != nil {
			fmt.Fprintf(os.Stderr, "update failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// ── Service management commands ───────────────────────────────────────────
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

	// ── Windows Service mode ──────────────────────────────────────────────────
	if !*flagConsole && isWindowsService() {
		if err := svcRun(); err != nil {
			log.Fatalf("[!] service run: %v", err)
		}
		return
	}

	// ── Interactive mode ──────────────────────────────────────────────────────
	// Self-elevate via UAC if not already admin — most BAS checks need it.
	if !isElevated() {
		log.Println("[!] Not running as Administrator — attempting UAC elevation...")
		if err := selfElevate(); err != nil {
			log.Printf("[!] UAC elevation failed: %v", err)
			log.Println("[!] Some checks will be skipped or inaccurate without admin rights.")
		} else {
			// Elevated child process is now running; exit this unelevated instance.
			os.Exit(0)
		}
	}

	// Enable all available Windows privileges for maximum check coverage.
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
			log.Println("[*] Shutting down — sending offline heartbeat...")
			agent.sendHeartbeat("offline")
			return
		}
	}
}
