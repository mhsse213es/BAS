// Package statusclient is the single place that speaks HTTP/JSON to the
// agent's own local status API (see agent/local_api_windows.go). Every
// consumer -- the native status window, its browser fallback, or any
// future UI -- goes through here instead of building requests directly,
// so there is exactly one timeout policy, one retry policy, and one set
// of typed response shapes.
package statusclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// DefaultAddr matches localAPIAddr in agent/local_api_windows.go.
const DefaultAddr = "127.0.0.1:9001"

type Client struct {
	addr    string
	token   string
	http    *http.Client
	retries int
}

// New creates a Client. addr is host:port (DefaultAddr in production);
// token is the bearer token read from the local API token file.
func New(addr, token string) *Client {
	return &Client{
		addr:    addr,
		token:   token,
		http:    &http.Client{Timeout: 4 * time.Second},
		retries: 1,
	}
}

func (c *Client) Status(ctx context.Context) (StatusResponse, error) {
	var out StatusResponse
	err := c.get(ctx, "/status", &out)
	return out, err
}

func (c *Client) Activity(ctx context.Context) (ActivityResponse, error) {
	var out ActivityResponse
	err := c.get(ctx, "/activity", &out)
	return out, err
}

func (c *Client) Evidence(ctx context.Context) (EvidenceResponse, error) {
	var out EvidenceResponse
	err := c.get(ctx, "/evidence", &out)
	return out, err
}

func (c *Client) Controls(ctx context.Context) (ControlsResponse, error) {
	var out ControlsResponse
	err := c.get(ctx, "/controls", &out)
	return out, err
}

// get fetches path and decodes the JSON body into out, retrying once on
// any failure (network error or non-200 status) with a short fixed delay.
// A context deadline is honored on every attempt, including the retry.
func (c *Client) get(ctx context.Context, path string, out interface{}) error {
	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(300 * time.Millisecond):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+c.addr+path, nil)
		if err != nil {
			return err
		}
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("status %d from %s", resp.StatusCode, path)
			continue
		}
		err = json.NewDecoder(resp.Body).Decode(out)
		resp.Body.Close()
		return err
	}
	return lastErr
}

// ── Response types (mirror agent/local_api_windows.go's JSON exactly) ──────

type StatusResponse struct {
	AgentVersion    string     `json:"agentVersion"`
	AgentID         string     `json:"agentId"`
	Hostname        string     `json:"hostname"`
	State           string     `json:"state"`
	Status          string     `json:"status"`
	ServerURL       string     `json:"serverUrl"`
	ServerConnected bool       `json:"serverConnected"`
	LastHeartbeat   *time.Time `json:"lastHeartbeat"`
	ServiceRunning  bool       `json:"serviceRunning"`
	LastUploadOk    bool       `json:"lastUploadOk"`
	LastUploadTime  time.Time  `json:"lastUploadTime"`
	UptimeSec       int        `json:"uptimeSec"`
	RamMB           uint64     `json:"ramMB"`
	Paused          bool       `json:"paused"`
	DisconnectedSec int        `json:"disconnectedSec"`
	GraceSec        int        `json:"graceSec"`
}

type Operation struct {
	ScenarioID     string     `json:"scenarioId"`
	ScenarioName   string     `json:"scenarioName"`
	TechniqueID    string     `json:"techniqueId,omitempty"`
	Phase          string     `json:"phase"`
	Progress       int        `json:"progress"`
	CurrentStep    string     `json:"currentStep,omitempty"`
	CompletedSteps int        `json:"completedSteps"`
	TotalSteps     int        `json:"totalSteps"`
	StartTime      time.Time  `json:"startTime"`
	Running        bool       `json:"running"`
	Result         string     `json:"result,omitempty"`
	CompletedAt    *time.Time `json:"completedAt,omitempty"`
	DurationSec    int        `json:"durationSec,omitempty"`
	// SweepLabel/SweepAggregateLabel/SweepAggregateResult mirror LocalOperation
	// in ../local_status_windows.go -- see that type's doc comment.
	SweepLabel           string `json:"sweepLabel,omitempty"`
	SweepAggregateLabel  string `json:"sweepAggregateLabel,omitempty"`
	SweepAggregateResult string `json:"sweepAggregateResult,omitempty"`
}

type Activity struct {
	Time  time.Time `json:"time"`
	Event string    `json:"event"`
}

type ActivityResponse struct {
	CurrentOperation *Operation `json:"currentOperation"`
	LastOperation    *Operation `json:"lastOperation"`
	RecentActivity   []Activity `json:"recentActivity"`
}

type EvidenceResponse struct {
	EventsCollected  int        `json:"eventsCollected"`
	DefenderAlerts   int        `json:"defenderAlerts"`
	SysmonDetections int        `json:"sysmonDetections"`
	LastCollection   *time.Time `json:"lastCollectionTime,omitempty"`
	LastUpload       *time.Time `json:"lastUploadTime,omitempty"`
	QueueSize        int        `json:"uploadQueueSize"`
}

type DefenderCtrl struct {
	Present         bool `json:"present"`
	RTPEnabled      bool `json:"rtpEnabled"`
	TamperProtected bool `json:"tamperProtected"`
}
type SysmonCtrl struct {
	Present bool `json:"present"`
}
type FirewallCtrl struct {
	Enabled bool `json:"enabled"`
}
type AppLockerCtrl struct {
	Enabled bool `json:"enabled"`
}
type WDACCtrl struct {
	Enabled bool `json:"enabled"`
}
type AMSICtrl struct {
	Enabled bool `json:"enabled"`
}

type ControlsResponse struct {
	Defender  DefenderCtrl  `json:"defender"`
	Sysmon    SysmonCtrl    `json:"sysmon"`
	Firewall  FirewallCtrl  `json:"firewall"`
	AppLocker AppLockerCtrl `json:"appLocker"`
	WDAC      WDACCtrl      `json:"wdac"`
	AMSI      AMSICtrl      `json:"amsi"`
	CheckedAt time.Time     `json:"checkedAt"`
}
