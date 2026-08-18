//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const agentAPIBase = "http://127.0.0.1:9001"

// ── API response types ────────────────────────────────────────────────────────

type StatusResp struct {
	AgentVersion    string    `json:"agentVersion"`
	AgentID         string    `json:"agentId"`
	Hostname        string    `json:"hostname"`
	State           string    `json:"state"`
	Status          string    `json:"status"`
	ServerURL       string    `json:"serverUrl"`
	ServerConnected bool      `json:"serverConnected"`
	LastHeartbeat   time.Time `json:"lastHeartbeat"`
	ServiceRunning  bool      `json:"serviceRunning"`
	LastUploadOk    bool      `json:"lastUploadOk"`
	LastUploadTime  time.Time `json:"lastUploadTime"`
	UptimeSec       int       `json:"uptimeSec"`
	RAMMB           uint64    `json:"ramMB"`
}

type ActivityResp struct {
	CurrentOperation *OperationInfo `json:"currentOperation"`
	LastOperation    *OperationInfo `json:"lastOperation"`
	RecentActivity   []ActivityItem `json:"recentActivity"`
}

type OperationInfo struct {
	ScenarioID   string     `json:"scenarioId"`
	ScenarioName string     `json:"scenarioName"`
	TechniqueID  string     `json:"techniqueId"`
	Phase        string     `json:"phase"`
	Progress     int        `json:"progress"`
	TotalSteps   int        `json:"totalSteps"`
	StartTime    time.Time  `json:"startTime"`
	Running      bool       `json:"running"`
	Result       string     `json:"result"`
	CompletedAt  *time.Time `json:"completedAt"`
	DurationSec  int        `json:"durationSec"`
}

type ActivityItem struct {
	Time  time.Time `json:"time"`
	Event string    `json:"event"`
}

type EvidenceResp struct {
	EventsCollected  int        `json:"eventsCollected"`
	DefenderAlerts   int        `json:"defenderAlerts"`
	SysmonDetections int        `json:"sysmonDetections"`
	LastCollection   *time.Time `json:"lastCollectionTime"`
	LastUpload       *time.Time `json:"lastUploadTime"`
	QueueSize        int        `json:"uploadQueueSize"`
}

type ControlsResp struct {
	Defender  DefCtrl  `json:"defender"`
	Sysmon    SysCtrl  `json:"sysmon"`
	Firewall  FwCtrl   `json:"firewall"`
	AppLocker ALCtrl   `json:"appLocker"`
	WDAC      WDCtrl   `json:"wdac"`
	AMSI      AMCtrl   `json:"amsi"`
}

type DefCtrl  struct { Present bool `json:"present"`;  RTPEnabled bool `json:"rtpEnabled"`; TamperProtected bool `json:"tamperProtected"` }
type SysCtrl  struct { Present bool `json:"present"`;  ServiceName string `json:"serviceName"` }
type FwCtrl   struct { Enabled bool `json:"enabled"` }
type ALCtrl   struct { Enabled bool `json:"enabled"` }
type WDCtrl   struct { Enabled bool `json:"enabled"` }
type AMCtrl   struct { Enabled bool `json:"enabled"` }

type LogsResp struct {
	Lines []string `json:"lines"`
}

// AllData bundles everything fetched in one poll cycle.
type AllData struct {
	Status    *StatusResp
	Activity  *ActivityResp
	Evidence  *EvidenceResp
	Controls  *ControlsResp
	FetchedAt time.Time
	Err       error // non-nil = agent not reachable
}

// ── HTTP client ───────────────────────────────────────────────────────────────

type APIClient struct {
	token string
	http  *http.Client
}

func newAPIClient() (*APIClient, error) {
	path := filepath.Join(os.Getenv("ProgramData"), "BASAgent", "api.token")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("token not found at %s — is BASAgent service running?", path)
	}
	return &APIClient{
		token: strings.TrimSpace(string(data)),
		http:  &http.Client{Timeout: 3 * time.Second},
	}, nil
}

func (c *APIClient) get(path string, out interface{}) error {
	req, err := http.NewRequest(http.MethodGet, agentAPIBase+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *APIClient) fetchAll() *AllData {
	d := &AllData{FetchedAt: time.Now()}

	var st StatusResp
	if err := c.get("/status", &st); err != nil {
		d.Err = err
		return d
	}
	d.Status = &st

	var act ActivityResp
	if err := c.get("/activity", &act); err == nil {
		d.Activity = &act
	}

	var ev EvidenceResp
	if err := c.get("/evidence", &ev); err == nil {
		d.Evidence = &ev
	}

	var ctrl ControlsResp
	if err := c.get("/controls", &ctrl); err == nil {
		d.Controls = &ctrl
	}

	return d
}

func fmtUptime(sec int) string {
	h := sec / 3600
	m := (sec % 3600) / 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}
