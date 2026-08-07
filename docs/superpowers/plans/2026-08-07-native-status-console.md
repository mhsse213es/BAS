# Native Status Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide a native Windows status application that follows standard Windows desktop conventions while presenting Audspect agent status — replacing today's browser-based console with a real native window, built with `windigo` (pure-Go, zero-CGo Win32 toolkit).

**Architecture:** Four layers, cleanly separated:
- **`agent/statusclient`** (new subpackage, portable, no build tag) — the only code that speaks HTTP/JSON to the agent's own local API. One shared timeout/retry policy, one decoder, typed response structs.
- **`StatusWindow` interface + `StatusSnapshot`** (`agent/statuswindow.go`, portable, no build tag) — the platform-agnostic contract. `windigoWindow` (Windows, native) and `browserWindow` (Windows, fallback — opens the existing HTML page) both implement it today; a future Linux/macOS agent adds `gtkWindow`/`cocoaWindow` here without touching anything else.
- **`StatusController`** (`agent/statuswindow.go`) — owns the poll loop (adaptive interval), owns every user-triggered action (export, open dashboard), and is the only thing that calls both `statusclient` and existing agent business logic (`exportDiagnosticBundle`, `openInBrowser`). `StatusWindow` implementations never call either directly — they only render `Refresh(StatusSnapshot)` and forward button clicks to the controller.
- **`windigoWindow`** (`agent/statuswindow_windows.go`) — pure presentation, implements `StatusWindow`, renders whatever `Refresh` hands it.

Zero backend changes anywhere in this plan — `statusclient` talks to the same, unmodified `127.0.0.1:9001` endpoints the old HTML page's JS already used.

**Tech Stack:** Go 1.26 (`agent` module), `github.com/rodrigocfd/windigo` (new dependency — pure Go, zero CGo, wraps native Win32 controls).

## Global Constraints

- Zero backend/API changes — every field this window shows already exists at `/status`, `/activity`, `/evidence`, `/controls` (`agent/local_api_windows.go`, unmodified by this plan).
- No CGo — `windigo` is pure Go over raw syscalls, matching `tray_windows.go`'s existing approach.
- `StatusWindow` implementations (`windigoWindow`, `browserWindow`) never import `statusclient` or call agent business logic directly — only `StatusController` does. A `Refresh(StatusSnapshot)` call and a controller method call on button click are the *only* two ways data or actions cross the presentation/logic boundary.
- `openStatusWindow()` in `tray_windows.go` (spawns `--status-window` as a separate process) is unchanged — this plan only changes what that separate process does once it starts.
- `ui_dashboard.html` and its `/` route in `local_api_windows.go` are **not deleted** — `browserWindow` uses them as the fallback path if native window creation fails.
- This environment cannot render or interact with a native Win32 window — every task's automated verification is "builds cleanly"; Task 9's expanded manual-scenario checklist is the real verification and must be run by the user on a real Windows machine before this is production-ready.
- `windigo`'s method names beyond what's been verified against its real godoc (listed in Task 1) may need small corrections during the actual build-and-fix cycle — this is a less common library; Task 1 Step 2 runs `go doc` against the downloaded module as an explicit first step, not something taken on faith.

---

### Task 1: `agent/statusclient` package

**Files:**
- Create: `agent/statusclient/statusclient.go`
- Create: `agent/statusclient/statusclient_test.go`

**Interfaces:**
- Produces: `statusclient.New(addr, token string) *Client`; `(*Client) Status/Activity/Evidence/Controls(ctx context.Context) (T, error)`; typed response structs `StatusResponse`, `ActivityResponse`, `Operation`, `Activity`, `EvidenceResponse`, `ControlsResponse` (+ its 6 nested control structs) — all mirroring the exact JSON shapes already emitted by `agent/local_api_windows.go`'s handlers (`handleLocalStatus`, `handleLocalActivity`, `handleLocalEvidence`, `handleLocalControls`), confirmed by reading that file directly, not guessed. Consumed by Task 2's `StatusSnapshot` and Task 3's `StatusController`.

- [ ] **Step 1: Write the failing test**

Create `agent/statusclient/statusclient_test.go`:

```go
package statusclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClient_Status_DecodesResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization = %q, want Bearer test-token", got)
		}
		json.NewEncoder(w).Encode(StatusResponse{
			AgentVersion:    "2.1.0",
			Hostname:        "TESTHOST",
			ServerConnected: true,
			UptimeSec:       120,
		})
	}))
	defer srv.Close()

	c := New(srv.Listener.Addr().String(), "test-token")
	got, err := c.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got.Hostname != "TESTHOST" || !got.ServerConnected || got.UptimeSec != 120 {
		t.Fatalf("got %+v, want hostname=TESTHOST serverConnected=true uptimeSec=120", got)
	}
}

func TestClient_Status_RetriesOnceThenFails(t *testing.T) {
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(srv.Listener.Addr().String(), "")
	_, err := c.Status(context.Background())
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2 (1 initial + 1 retry)", attempts)
	}
}

func TestClient_Status_RespectsContextTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()

	c := New(srv.Listener.Addr().String(), "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := c.Status(ctx)
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd agent && go test ./statusclient/... -v`
Expected: `FAIL` — package `statusclient` doesn't exist yet (compile error).

- [ ] **Step 3: Implement the package**

Create `agent/statusclient/statusclient.go`:

```go
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
	ScenarioID   string     `json:"scenarioId"`
	ScenarioName string     `json:"scenarioName"`
	TechniqueID  string     `json:"techniqueId,omitempty"`
	Phase        string     `json:"phase"`
	Progress     int        `json:"progress"`
	TotalSteps   int        `json:"totalSteps"`
	StartTime    time.Time  `json:"startTime"`
	Running      bool       `json:"running"`
	Result       string     `json:"result,omitempty"`
	CompletedAt  *time.Time `json:"completedAt,omitempty"`
	DurationSec  int        `json:"durationSec,omitempty"`
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd agent && go test ./statusclient/... -v`
Expected: `PASS` for all three tests.

- [ ] **Step 5: Commit**

```bash
git add statusclient/statusclient.go statusclient/statusclient_test.go
git commit -m "$(cat <<'EOF'
feat(agent): add statusclient package

Single place that speaks HTTP/JSON to the agent's own local status
API -- one timeout policy, one retry policy (1 retry, 300ms delay),
one set of typed response structs mirroring local_api_windows.go's
JSON exactly. No UI or business-logic code will build raw HTTP
requests to the local API directly after this; StatusWindow
implementations and StatusController (next tasks) consume this
package instead.
EOF
)"
git push
```

---

### Task 2: `StatusWindow` interface, `StatusSnapshot`, and `browserWindow`

**Files:**
- Create: `agent/statuswindow.go` (portable, no build tag — the interface and snapshot type themselves have no platform-specific code)
- Create: `agent/browserwindow_windows.go`

**Interfaces:**
- Consumes: `statusclient`'s response types from Task 1.
- Produces: `StatusWindow` interface (`Show() error`, `Close()`, `Refresh(StatusSnapshot)`); `StatusSnapshot` struct; `browserWindow` (implements `StatusWindow`). Task 3's `StatusController` holds a `StatusWindow` and calls `Refresh`. Task 4's `windigoWindow` implements the same interface.

- [ ] **Step 1: Define the interface and snapshot type**

Create `agent/statuswindow.go`:

```go
package main

import "audspect/agent/statusclient"

// StatusSnapshot is the fully-resolved view of the agent's current status,
// combining all four statusclient endpoints into one value passed to
// StatusWindow.Refresh in a single call. Online is false when the local
// API was unreachable this poll cycle -- implementations show an offline
// state instead of rendering stale field values in that case.
type StatusSnapshot struct {
	Online   bool
	Status   statusclient.StatusResponse
	Activity statusclient.ActivityResponse
	Evidence statusclient.EvidenceResponse
	Controls statusclient.ControlsResponse
}

// StatusWindow is the platform-agnostic contract for the agent's local
// status console. windigoWindow (statuswindow_windows.go) is the native
// Windows implementation; browserWindow (browserwindow_windows.go) is the
// fallback used when native window creation fails. A future Linux/macOS
// agent adds gtkWindow/cocoaWindow here without changing StatusController
// or runStatusWindow.
//
// Implementations are pure presentation -- they render whatever Refresh
// hands them and forward user actions to a StatusController (see
// StatusController's doc comment for why business logic never lives here).
type StatusWindow interface {
	// Show displays the window and blocks for its lifetime. Returns an
	// error only if window creation itself fails (e.g. the native toolkit
	// errors) -- callers fall back to a different StatusWindow
	// implementation in that case, not on a later Refresh call, which
	// cannot itself fail this way.
	Show() error
	// Close requests the window close, unblocking a pending Show call.
	Close()
	// Refresh updates the window's displayed content from a new snapshot.
	// Called by StatusController after every poll and after every action.
	Refresh(StatusSnapshot)
}
```

- [ ] **Step 2: Implement `browserWindow`**

Create `agent/browserwindow_windows.go`:

```go
//go:build windows

package main

// browserWindow implements StatusWindow by opening the existing HTML
// status page (ui_dashboard.html, served by local_api_windows.go's "/"
// route -- both unmodified) in the user's default browser. Used as the
// fallback when windigoWindow fails to create its native window.
//
// Refresh is a no-op: the HTML page polls itself via its own embedded JS,
// same as it always has -- this implementation exists only to give the
// fallback path the same Show/Close/Refresh shape StatusController expects
// from any StatusWindow, not to actively drive the browser tab.
type browserWindow struct {
	token string
}

func newBrowserWindow(token string) *browserWindow {
	return &browserWindow{token: token}
}

func (b *browserWindow) Show() error {
	url := "http://127.0.0.1:9001/"
	if b.token != "" {
		url += "?t=" + b.token
	}
	openInBrowser(url)
	return nil
}

func (b *browserWindow) Close() {}

func (b *browserWindow) Refresh(_ StatusSnapshot) {}
```

- [ ] **Step 3: Build**

```bash
cd agent
go build ./...
```

Expected: succeeds.

- [ ] **Step 4: Commit**

```bash
git add statuswindow.go browserwindow_windows.go
git commit -m "$(cat <<'EOF'
feat(agent): add StatusWindow interface, StatusSnapshot, browserWindow

StatusWindow (Show/Close/Refresh) is the platform-agnostic contract
for the local status console, living in a portable file with no
Windows-specific code -- windigo stays confined to its own
implementation file, never leaking into the rest of the agent.
browserWindow implements it as the existing HTML-page-in-a-browser
fallback, used when native window creation fails.
EOF
)"
git push
```

---

### Task 3: `StatusController` — adaptive polling and action mediation

**Files:**
- Create: `agent/statuscontroller.go` (`//go:build windows` — despite otherwise having no platform-specific code, it calls `exportDiagnosticBundle`/`revealInExplorer`/`openInBrowser`, which today only exist on Windows; caught by the cross-compile check during implementation and corrected there)
- Create: `agent/statuscontroller_test.go`

**Interfaces:**
- Consumes: `statusclient.Client` (Task 1), `StatusWindow`/`StatusSnapshot` (Task 2), and the existing `exportDiagnosticBundle()`/`openInBrowser()` functions (already defined elsewhere in the `agent` package).
- Produces: `NewStatusController(client *statusclient.Client, window StatusWindow) *StatusController`; `(*StatusController) Run()`, `.Stop()`, `.ExportDiagnostics()`, `.OpenDashboard(serverURL string)`. Task 4's `windigoWindow` holds a `*StatusController` reference (set after construction) to forward its two button clicks to `ExportDiagnostics`/`OpenDashboard`.

- [ ] **Step 1: Write the failing tests**

Create `agent/statuscontroller_test.go`:

```go
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"audspect/agent/statusclient"
)

// fakeWindow records every Refresh call so tests can assert on cadence and content.
type fakeWindow struct {
	mu        sync.Mutex
	refreshes []StatusSnapshot
}

func (f *fakeWindow) Show() error { return nil }
func (f *fakeWindow) Close()      {}
func (f *fakeWindow) Refresh(s StatusSnapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshes = append(f.refreshes, s)
}
func (f *fakeWindow) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.refreshes)
}
func (f *fakeWindow) last() StatusSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refreshes[len(f.refreshes)-1]
}

func newTestServer(t *testing.T, running bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(statusclient.StatusResponse{Hostname: "H", ServerConnected: true})
		case "/activity":
			var cur *statusclient.Operation
			if running {
				cur = &statusclient.Operation{Running: true, ScenarioName: "test-scenario"}
			}
			json.NewEncoder(w).Encode(statusclient.ActivityResponse{CurrentOperation: cur})
		case "/evidence":
			json.NewEncoder(w).Encode(statusclient.EvidenceResponse{})
		case "/controls":
			json.NewEncoder(w).Encode(statusclient.ControlsResponse{})
		}
	}))
}

func TestStatusController_Run_RefreshesUntilStopped(t *testing.T) {
	srv := newTestServer(t, false)
	defer srv.Close()

	win := &fakeWindow{}
	c := NewStatusController(statusclient.New(srv.Listener.Addr().String(), ""), win)
	go c.Run()
	defer c.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for win.count() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if win.count() < 1 {
		t.Fatal("expected at least one Refresh call")
	}
	if !win.last().Online {
		t.Fatalf("last snapshot Online = false, want true")
	}
}

func TestPollInterval_FastWhileRunning_SlowWhenIdle(t *testing.T) {
	running := StatusSnapshot{Activity: statusclient.ActivityResponse{
		CurrentOperation: &statusclient.Operation{Running: true},
	}}
	idle := StatusSnapshot{Activity: statusclient.ActivityResponse{}}

	if got := pollInterval(running); got != 1*time.Second {
		t.Errorf("pollInterval(running) = %v, want 1s", got)
	}
	if got := pollInterval(idle); got != 5*time.Second {
		t.Errorf("pollInterval(idle) = %v, want 5s", got)
	}
}

func TestStatusController_Poll_OfflineWhenUnreachable(t *testing.T) {
	c := NewStatusController(statusclient.New("127.0.0.1:1", ""), &fakeWindow{})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	snap := c.pollWithContext(ctx)
	if snap.Online {
		t.Fatal("expected Online = false when the local API is unreachable")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd agent && go test . -run TestStatusController -v`
Expected: `FAIL` — `NewStatusController`, `pollInterval`, `pollWithContext` undefined.

- [ ] **Step 3: Implement `StatusController`**

Create `agent/statuscontroller.go`:

```go
package main

import (
	"context"
	"time"

	"audspect/agent/statusclient"
)

// pollInterval returns the adaptive polling cadence for the given
// snapshot: fast while an assessment is actively running, so the progress
// bar feels responsive, settling back to a slower idle cadence otherwise.
func pollInterval(s StatusSnapshot) time.Duration {
	if s.Activity.CurrentOperation != nil && s.Activity.CurrentOperation.Running {
		return 1 * time.Second
	}
	return 5 * time.Second
}

// StatusController owns the poll loop and every user-triggered action.
// StatusWindow implementations only render (Refresh) and forward button
// clicks here -- they never call statusclient or agent business logic
// (exportDiagnosticBundle, openInBrowser) themselves. This keeps
// presentation code free of both networking and side effects, and means a
// future second StatusWindow implementation gets identical polling/action
// behavior for free.
type StatusController struct {
	client *statusclient.Client
	window StatusWindow
	stop   chan struct{}
}

func NewStatusController(client *statusclient.Client, window StatusWindow) *StatusController {
	return &StatusController{client: client, window: window, stop: make(chan struct{})}
}

// Run polls in a loop with an adaptive interval (see pollInterval),
// refreshing the window after every cycle, until Stop is called. Meant to
// be run in its own goroutine.
func (c *StatusController) Run() {
	for {
		snap := c.poll()
		c.window.Refresh(snap)
		select {
		case <-time.After(pollInterval(snap)):
		case <-c.stop:
			return
		}
	}
}

// Stop ends the poll loop. Safe to call once; a second call panics on the
// closed channel by design -- StatusController has exactly one owner
// (runStatusWindow) and is not meant to be stopped from multiple places.
func (c *StatusController) Stop() { close(c.stop) }

func (c *StatusController) poll() StatusSnapshot {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	return c.pollWithContext(ctx)
}

// pollWithContext is poll's real body, taking an explicit context so tests
// can control the timeout without waiting for the production default.
func (c *StatusController) pollWithContext(ctx context.Context) StatusSnapshot {
	status, err := c.client.Status(ctx)
	if err != nil {
		return StatusSnapshot{Online: false}
	}
	activity, _ := c.client.Activity(ctx)
	evidence, _ := c.client.Evidence(ctx)
	controls, _ := c.client.Controls(ctx)
	return StatusSnapshot{
		Online:   true,
		Status:   status,
		Activity: activity,
		Evidence: evidence,
		Controls: controls,
	}
}

// ExportDiagnostics runs the existing export flow and reveals the result
// in Explorer. Called by a StatusWindow implementation's Export button
// handler -- see StatusWindow's doc comment for why the window itself
// never calls exportDiagnosticBundle directly.
func (c *StatusController) ExportDiagnostics() {
	if path, err := exportDiagnosticBundle(); err == nil {
		revealInExplorer(path)
	}
}

// OpenDashboard opens the full BAS web console for the given server URL
// (the most recently known value from a StatusSnapshot.Status.ServerURL).
// A no-op if serverURL is empty (not yet known).
func (c *StatusController) OpenDashboard(serverURL string) {
	if serverURL != "" {
		openInBrowser(serverURL)
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd agent && go test . -run TestStatusController -v && go test . -run TestPollInterval -v`
Expected: `PASS` for all three tests.

- [ ] **Step 5: Commit**

```bash
git add statuscontroller.go statuscontroller_test.go
git commit -m "$(cat <<'EOF'
feat(agent): add StatusController (adaptive polling + action mediation)

Owns the poll loop -- 1s cadence while an assessment is running, 5s
otherwise -- and every user-triggered action (export, open dashboard).
StatusWindow implementations only render and forward button clicks
here; this is the only code that calls both statusclient and existing
agent business logic (exportDiagnosticBundle, openInBrowser).
EOF
)"
git push
```

---

### Task 4: `windigoWindow` shell — window creation, controller wiring, hero + connection panel

**Files:**
- Modify: `agent/go.mod`, `agent/go.sum` (add `github.com/rodrigocfd/windigo`)
- Modify: `agent/statuswindow_windows.go` (replace `runStatusWindow`, add `windigoWindow`)

**Interfaces:**
- Consumes: `StatusWindow`/`StatusSnapshot` (Task 2), `StatusController` (Task 3), `statusclient.New` (Task 1).
- Produces: `windigoWindow` (implements `StatusWindow`) with a `Refresh` that this task only wires the hero + connection panel into; Tasks 5-7 extend the same `Refresh` method for their own panels, each replacing the prior task's closing lines (quoted exactly per step, same pattern as this session's other multi-task plans).

- [ ] **Step 1: Add the dependency and verify its real API**

```bash
cd agent
go get github.com/rodrigocfd/windigo@latest
go doc github.com/rodrigocfd/windigo/ui Static
go doc github.com/rodrigocfd/windigo/ui ProgressBar
go doc github.com/rodrigocfd/windigo/ui ListView
go doc github.com/rodrigocfd/windigo/ui Main
go doc github.com/rodrigocfd/windigo/ui OptsStatic
go doc github.com/rodrigocfd/windigo/ui OptsButton
go doc github.com/rodrigocfd/windigo/ui OptsProgressBar
go doc github.com/rodrigocfd/windigo/ui OptsListView
```

Confirm `SetTextAndResize`, `SetPos`, `SetRange`, `AddItem`, `DeleteAllItems`, and the options-builder methods (`.Position(x,y)`, `.Size(cx,cy)`, `.Text(s)`) match every later step in this plan. If any name differs, note the real name now — every subsequent step in Tasks 4-7 assumes these exact names.

**Corrections found when this step was actually run against the downloaded module** (the plan's original code sketches below predate this verification and are wrong in these specific ways — the real, committed `statuswindow_windows.go` uses the corrected forms):
- `ListView` columns are set via `.Column(title, width)` chained on `VarOptsListView` *at construction*, not via a post-construction `.Cols().Add(...)` accessor (no such accessor exists).
- `Button` sizing is two separate methods, `.Width(w)` and `.Height(h)` on `VarOptsButton` — there is no `.Size(cx, cy)` for buttons (unlike `Static`/`ProgressBar`/`ListView`, which do have `.Size`).
- `HWND.DestroyWindow() error` is the real close mechanism — not a raw `SendMessage(WM_CLOSE, ...)` syscall.
- `HWND.SetTimer(timerId, msTimeout int) error` and `.KillTimer(timerId int) error` are real, verified methods — no need for a raw `user32.dll` `SetTimer` syscall. In the end this plan's window doesn't use either: `StatusController` already owns the poll cadence via its own goroutine timer (Task 3), so a second, window-level `WM_TIMER` would have been redundant. It was cut entirely during Task 4.
- **Threading, not just naming:** `StatusController.Run()` calls `window.Refresh()` from its own polling goroutine (by design, per Task 3), but Win32 controls may only be touched from the thread that owns the message loop. `Main.UiThread(fun func())` (confirmed in `go doc ... Main`) is windigo's marshaling primitive for exactly this. `windigoWindow.Refresh` wraps the real rendering (renamed `render` in the committed code) in `sw.wnd.UiThread(func() { sw.render(snap) })` rather than calling control setters directly — every code sketch in Tasks 4-7 below that shows `Refresh` calling setters inline should be read as running inside that `render` method, not `Refresh` itself.

- [ ] **Step 2: Replace `statuswindow_windows.go`'s `runStatusWindow` and add `windigoWindow`**

Replace (currently the full file):

```go
//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// runStatusWindow opens the agent's status console in the user's default
// browser, pointed at the agent's local HTTP server. Invoked via
// `bas_agent.exe --status-window`.
//
// This used to host the console in an embedded WebView2 window instead.
// That was abandoned: WebView2 hosted in a process launched via the
// service's CreateProcessAsUser/WTSQueryUserToken chain (exactly this
// agent's tray -> status-window launch path) reliably created the host
// window but left it permanently invisible (IsWindowVisible false from the
// moment of creation, with no error at any layer) -- confirmed via live
// diagnostic logging against the real production launch path, not a
// synthetic reproduction. This is a known, Microsoft-acknowledged
// limitation of WebView2 under a service-launched/impersonated-token
// session process, not something fixable in this codebase:
// https://github.com/MicrosoftEdge/WebView2Feedback/issues/4850
// https://github.com/MicrosoftEdge/WebView2Feedback/issues/2434 (closed by
// Microsoft as "not planned")
// The default browser has no such limitation and needs no embedding at all.
func runStatusWindow() {
	token := readAPIToken()
	url := "http://127.0.0.1:9001/"
	if token != "" {
		url += "?t=" + token
	}
	openInBrowser(url)
}

// readAPIToken reads the local API token written by the service.
func readAPIToken() string {
	path := filepath.Join(os.Getenv("ProgramData"), "BASAgent", "api.token")
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func openInBrowser(url string) {
	verb, _ := windows.UTF16PtrFromString("open")
	target, _ := windows.UTF16PtrFromString(url)
	shell32 := windows.NewLazySystemDLL("shell32.dll")
	shell32.NewProc("ShellExecuteW").Call(0,
		uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(target)), 0, 0, 5 /*SW_SHOW*/)
}

func revealInExplorer(path string) {
	cmd := exec.Command("explorer.exe", "/select,"+path)
	_ = cmd.Start()
}
```

with:

```go
//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/rodrigocfd/windigo/ui"
	"golang.org/x/sys/windows"

	"audspect/agent/statusclient"
)

// runStatusWindow opens the agent's status console as a native Win32
// window (windigoWindow, below) instead of the browser. Invoked via
// `bas_agent.exe --status-window`. Falls back to browserWindow if native
// window creation fails.
//
// This used to open the console in the user's default browser, and before
// that in an embedded WebView2 window (abandoned -- WebView2 hosted via the
// service's CreateProcessAsUser/WTSQueryUserToken launch chain reliably
// created the host window but left it permanently invisible, a documented
// Microsoft limitation: https://github.com/MicrosoftEdge/WebView2Feedback/issues/4850).
func runStatusWindow() {
	token := readAPIToken()
	client := statusclient.New(statusclient.DefaultAddr, token)

	win := newWindigoWindow()
	controller := NewStatusController(client, win)
	win.controller = controller

	go controller.Run()
	defer controller.Stop()

	if err := win.Show(); err != nil {
		log.Printf("[status-window] native window failed, falling back to browser: %v", err)
		controller.Stop()
		fallback := newBrowserWindow(token)
		fallback.Show()
	}
}

// readAPIToken reads the local API token written by the service.
func readAPIToken() string {
	path := filepath.Join(os.Getenv("ProgramData"), "BASAgent", "api.token")
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func openInBrowser(url string) {
	verb, _ := windows.UTF16PtrFromString("open")
	target, _ := windows.UTF16PtrFromString(url)
	shell32 := windows.NewLazySystemDLL("shell32.dll")
	shell32.NewProc("ShellExecuteW").Call(0,
		uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(target)), 0, 0, 5 /*SW_SHOW*/)
}

func revealInExplorer(path string) {
	cmd := exec.Command("explorer.exe", "/select,"+path)
	_ = cmd.Start()
}

// windigoWindow implements StatusWindow as a real native Win32 window
// (github.com/rodrigocfd/windigo -- pure Go, zero CGo). Pure presentation:
// it never calls statusclient or agent business logic itself -- every
// button handler forwards to controller (set by runStatusWindow right
// after construction, since StatusController's own constructor needs a
// StatusWindow reference, creating the chicken-and-egg this two-step
// wiring resolves).
type windigoWindow struct {
	wnd        *ui.Main
	controller *StatusController

	lastServerURL string

	lblHeroTitle     *ui.Static
	lblConnServer    *ui.Static
	lblConnLink      *ui.Static
	lblConnState     *ui.Static
	lblConnUptime    *ui.Static
	lblConnHeartbeat *ui.Static
}

func newWindigoWindow() *windigoWindow {
	sw := &windigoWindow{}

	sw.wnd = ui.NewMain(
		ui.OptsMain().
			Title("Audspect BAS Agent").
			Size(ui.Dpi(720, 640)),
	)

	sw.lblHeroTitle = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Connecting...").Position(ui.Dpi(16, 16)).Size(ui.Dpi(680, 24)))

	sw.lblConnServer = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Server: —").Position(ui.Dpi(16, 56)).Size(ui.Dpi(360, 20)))
	sw.lblConnLink = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Link: —").Position(ui.Dpi(16, 80)).Size(ui.Dpi(360, 20)))
	sw.lblConnState = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Lifecycle State: —").Position(ui.Dpi(16, 104)).Size(ui.Dpi(360, 20)))
	sw.lblConnUptime = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Uptime: —").Position(ui.Dpi(16, 128)).Size(ui.Dpi(360, 20)))
	sw.lblConnHeartbeat = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Last Heartbeat: —").Position(ui.Dpi(16, 152)).Size(ui.Dpi(360, 20)))

	return sw
}

func (sw *windigoWindow) Show() error {
	sw.wnd.RunAsMain()
	return nil
}

func (sw *windigoWindow) Close() {
	sw.wnd.Hwnd().SendMessage(0x0010 /*WM_CLOSE*/, 0, 0) // co.WM_CLOSE once Step 1's go doc confirms the constant's real name/package
}

// Refresh renders a new snapshot. This task wires the hero banner and
// Connection panel; Tasks 5-7 extend this same method (each quoting the
// prior task's closing lines as its own "replace" target) for the
// remaining panels.
func (sw *windigoWindow) Refresh(snap StatusSnapshot) {
	if !snap.Online {
		sw.lblHeroTitle.SetTextAndResize("Agent service not reachable")
		sw.lblConnLink.SetTextAndResize("Link: Offline")
		return
	}
	s := snap.Status
	sw.lastServerURL = s.ServerURL

	sw.lblConnServer.SetTextAndResize("Server: " + s.ServerURL)
	switch {
	case s.ServerConnected:
		sw.lblConnLink.SetTextAndResize("Link: Connected")
	case s.Paused:
		sw.lblConnLink.SetTextAndResize("Link: Paused (server unreachable, run continues locally)")
	default:
		sw.lblConnLink.SetTextAndResize("Link: Disconnected")
	}
	sw.lblConnState.SetTextAndResize("Lifecycle State: " + orDash(s.State))
	sw.lblConnUptime.SetTextAndResize("Uptime: " + formatUptime(s.UptimeSec))
	if s.LastHeartbeat != nil {
		sw.lblConnHeartbeat.SetTextAndResize("Last Heartbeat: " + s.LastHeartbeat.Format("15:04:05"))
	} else {
		sw.lblConnHeartbeat.SetTextAndResize("Last Heartbeat: —")
	}

	title := "Audspect BAS Agent — " + s.Hostname
	switch {
	case !s.ServerConnected && s.Paused:
		title += "  [PAUSED — SERVER LINK LOST]"
	case !s.ServerConnected:
		title += "  [DISCONNECTED]"
	case s.State == "quarantined":
		title += "  [QUARANTINED]"
	case s.State == "restricted":
		title += "  [RESTRICTED]"
	default:
		title += "  [OK]  v" + s.AgentVersion
	}
	sw.lblHeroTitle.SetTextAndResize(title)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func formatUptime(sec int) string {
	h := sec / 3600
	m := (sec % 3600) / 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm %ds", m, sec%60)
}
```

`Close`'s exact `WM_CLOSE` constant/method — confirm during Step 1's `go doc github.com/rodrigocfd/windigo/win Hwnd` (or wherever `SendMessage`/close helpers live) whether windigo exposes a named `co.WM_CLOSE` constant or a direct `.Close()`/`.Destroy()` method on `ui.Main`; prefer whichever is idiomatic for the real API over the raw `0x0010` shown above, which is a correctness placeholder for "the real WM_CLOSE value" (the Win32 constant itself is not in question, only which windigo helper to call it through) — adjust before Step 3's build if `go doc` surfaces a cleaner path.

- [ ] **Step 3: Build**

```bash
go build ./...
```

Expected: succeeds against the real, downloaded `windigo` module.

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum statuswindow_windows.go
git commit -m "$(cat <<'EOF'
feat(agent): windigoWindow shell - native window, controller wiring,
hero + connection panel

windigoWindow implements StatusWindow as a real native Win32 window
(windigo -- pure Go, zero CGo). Pure presentation: never calls
statusclient or business logic directly, only StatusController
(wired in right after construction). Falls back to browserWindow if
native window creation fails. This task wires the hero banner and
Connection panel; Tasks 5-7 add the remaining panels to the same
Refresh method.
EOF
)"
git push
```

---

### Task 5: Current Operation panel

**Files:**
- Modify: `agent/statuswindow_windows.go`

**Interfaces:**
- Consumes: `windigoWindow.Refresh` from Task 4; `StatusSnapshot.Activity.CurrentOperation`/`.LastOperation` (typed `statusclient.Operation`, Task 1).
- Produces: nothing new consumed by later tasks — self-contained panel.

- [ ] **Step 1: Add the fields**

Add to the `windigoWindow` struct:

```go
	lblOpTitle  *ui.Static
	lblOpMeta   *ui.Static
	progOp      *ui.ProgressBar
	lblOpResult *ui.Static
```

- [ ] **Step 2: Create the controls**

Add to `newWindigoWindow`, after the Connection panel's controls:

```go
	sw.lblOpTitle = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("No active simulation").Position(ui.Dpi(400, 56)).Size(ui.Dpi(300, 20)))
	sw.lblOpMeta = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Awaiting tasking from the BAS console").Position(ui.Dpi(400, 80)).Size(ui.Dpi(300, 20)))
	sw.progOp = ui.NewProgressBar(sw.wnd, ui.OptsProgressBar().
		Position(ui.Dpi(400, 104)).Size(ui.Dpi(300, 16)))
	sw.progOp.SetRange(0, 100)
	sw.lblOpResult = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("").Position(ui.Dpi(400, 128)).Size(ui.Dpi(300, 20)))
```

- [ ] **Step 3: Extend `Refresh`**

Replace (Task 4's `Refresh`, its closing lines):

```go
	sw.lblHeroTitle.SetTextAndResize(title)
}
```

with:

```go
	sw.lblHeroTitle.SetTextAndResize(title)
	sw.renderOperation(snap.Activity)
}

// renderOperation updates the Current Operation panel.
func (sw *windigoWindow) renderOperation(a statusclient.ActivityResponse) {
	if a.CurrentOperation != nil && a.CurrentOperation.Running {
		op := a.CurrentOperation
		title := op.ScenarioName
		if op.TechniqueID != "" {
			title = op.TechniqueID + "  " + op.ScenarioName
		}
		sw.lblOpTitle.SetTextAndResize(title)
		sw.lblOpMeta.SetTextAndResize(fmt.Sprintf("%d steps · phase: %s", op.TotalSteps, orDash(op.Phase)))
		sw.progOp.SetPos(op.Progress)
		sw.lblOpResult.SetTextAndResize("")
		return
	}
	if a.LastOperation != nil {
		op := a.LastOperation
		title := op.ScenarioName
		if op.TechniqueID != "" {
			title = op.TechniqueID + "  " + op.ScenarioName
		}
		sw.lblOpTitle.SetTextAndResize(title)
		sw.lblOpMeta.SetTextAndResize(fmt.Sprintf("Completed · %ds", op.DurationSec))
		sw.progOp.SetPos(100)
		if op.Result != "" {
			sw.lblOpResult.SetTextAndResize("Result: " + op.Result)
		}
		return
	}
	sw.lblOpTitle.SetTextAndResize("No active simulation")
	sw.lblOpMeta.SetTextAndResize("Awaiting tasking from the BAS console")
	sw.progOp.SetPos(0)
	sw.lblOpResult.SetTextAndResize("")
}
```

- [ ] **Step 4: Build**

```bash
go build ./...
```

Expected: succeeds.

- [ ] **Step 5: Commit**

```bash
git add statuswindow_windows.go
git commit -m "feat(agent): native status window - current operation panel"
git push
```

---

### Task 6: Security Controls, Evidence, Self-Protection, Resources panels

**Files:**
- Modify: `agent/statuswindow_windows.go`

**Interfaces:**
- Consumes: `windigoWindow.Refresh` from Task 5; `StatusSnapshot.Controls`/`.Evidence`/`.Status` (typed, Task 1).
- Produces: nothing new consumed by later tasks.

- [ ] **Step 1: Add the fields**

```go
	// Security Controls
	lblCtrlDefender  *ui.Static
	lblCtrlSysmon    *ui.Static
	lblCtrlFirewall  *ui.Static
	lblCtrlAppLocker *ui.Static
	lblCtrlWDAC      *ui.Static
	lblCtrlAMSI      *ui.Static

	// Evidence tiles
	lblEvEvents   *ui.Static
	lblEvDefender *ui.Static
	lblEvSysmon   *ui.Static
	lblEvQueue    *ui.Static

	// Self-Protection rows
	lblSpService *ui.Static
	lblSpPolicy  *ui.Static
	lblSpQueue   *ui.Static
	lblSpUpload  *ui.Static
	lblSpContact *ui.Static

	// Resources
	lblResRam     *ui.Static
	lblResVersion *ui.Static
	lblResId      *ui.Static
```

- [ ] **Step 2: Create the controls**

Add to `newWindigoWindow`, after the Current Operation panel's controls:

```go
	// Security Controls
	sw.lblCtrlDefender = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Defender RTP: —").Position(ui.Dpi(16, 184)).Size(ui.Dpi(340, 20)))
	sw.lblCtrlSysmon = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Sysmon: —").Position(ui.Dpi(16, 208)).Size(ui.Dpi(340, 20)))
	sw.lblCtrlFirewall = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Firewall: —").Position(ui.Dpi(16, 232)).Size(ui.Dpi(340, 20)))
	sw.lblCtrlAppLocker = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("AppLocker: —").Position(ui.Dpi(16, 256)).Size(ui.Dpi(340, 20)))
	sw.lblCtrlWDAC = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("WDAC: —").Position(ui.Dpi(16, 280)).Size(ui.Dpi(340, 20)))
	sw.lblCtrlAMSI = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("AMSI: —").Position(ui.Dpi(16, 304)).Size(ui.Dpi(340, 20)))

	// Evidence
	sw.lblEvEvents = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Events Collected: —").Position(ui.Dpi(400, 184)).Size(ui.Dpi(300, 20)))
	sw.lblEvDefender = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Defender Alerts: —").Position(ui.Dpi(400, 208)).Size(ui.Dpi(300, 20)))
	sw.lblEvSysmon = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Sysmon Detections: —").Position(ui.Dpi(400, 232)).Size(ui.Dpi(300, 20)))
	sw.lblEvQueue = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Upload Queue: —").Position(ui.Dpi(400, 256)).Size(ui.Dpi(300, 20)))

	// Self-Protection
	sw.lblSpService = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Service Running: —").Position(ui.Dpi(400, 288)).Size(ui.Dpi(300, 20)))
	sw.lblSpPolicy = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Policy Sync: —").Position(ui.Dpi(400, 312)).Size(ui.Dpi(300, 20)))
	sw.lblSpQueue = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Evidence Queue: —").Position(ui.Dpi(400, 336)).Size(ui.Dpi(300, 20)))
	sw.lblSpUpload = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Last Upload OK: —").Position(ui.Dpi(400, 360)).Size(ui.Dpi(300, 20)))
	sw.lblSpContact = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Server Contact: —").Position(ui.Dpi(400, 384)).Size(ui.Dpi(300, 20)))

	// Resources
	sw.lblResRam = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Memory: —").Position(ui.Dpi(16, 336)).Size(ui.Dpi(340, 20)))
	sw.lblResVersion = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Agent Version: —").Position(ui.Dpi(16, 360)).Size(ui.Dpi(340, 20)))
	sw.lblResId = ui.NewStatic(sw.wnd, ui.OptsStatic().
		Text("Agent ID: —").Position(ui.Dpi(16, 384)).Size(ui.Dpi(340, 20)))
```

- [ ] **Step 3: Extend `Refresh`**

Replace (Task 5's `Refresh`, its closing lines):

```go
	sw.lblHeroTitle.SetTextAndResize(title)
	sw.renderOperation(snap.Activity)
}
```

with:

```go
	sw.lblHeroTitle.SetTextAndResize(title)
	sw.renderOperation(snap.Activity)
	sw.renderControls(snap.Controls)
	sw.renderEvidence(snap.Evidence)
	sw.renderSelfProtection(s, snap.Evidence)
	sw.lblResRam.SetTextAndResize(fmt.Sprintf("Memory: %d MB", s.RamMB))
	sw.lblResVersion.SetTextAndResize("Agent Version: v" + s.AgentVersion)
	sw.lblResId.SetTextAndResize("Agent ID: " + s.AgentID)
}

// renderControls updates the Security Controls panel.
func (sw *windigoWindow) renderControls(c statusclient.ControlsResponse) {
	status := "ABSENT"
	if c.Defender.Present {
		if c.Defender.RTPEnabled {
			status = "ACTIVE"
		} else {
			status = "DEGRADED"
		}
	}
	extra := ""
	if c.Defender.TamperProtected {
		extra = " +Tamper"
	}
	sw.lblCtrlDefender.SetTextAndResize(fmt.Sprintf("Defender RTP: [%s]%s", status, extra))

	setBool := func(lbl *ui.Static, name string, on bool) {
		s := "ABSENT"
		if on {
			s = "ACTIVE"
		}
		lbl.SetTextAndResize(fmt.Sprintf("%s: [%s]", name, s))
	}
	setBool(sw.lblCtrlSysmon, "Sysmon", c.Sysmon.Present)
	setBool(sw.lblCtrlFirewall, "Firewall", c.Firewall.Enabled)
	setBool(sw.lblCtrlAppLocker, "AppLocker", c.AppLocker.Enabled)
	setBool(sw.lblCtrlWDAC, "WDAC", c.WDAC.Enabled)
	setBool(sw.lblCtrlAMSI, "AMSI", c.AMSI.Enabled)
}

// renderEvidence updates the Evidence tiles.
func (sw *windigoWindow) renderEvidence(ev statusclient.EvidenceResponse) {
	sw.lblEvEvents.SetTextAndResize(fmt.Sprintf("Events Collected: %d", ev.EventsCollected))
	sw.lblEvDefender.SetTextAndResize(fmt.Sprintf("Defender Alerts: %d", ev.DefenderAlerts))
	sw.lblEvSysmon.SetTextAndResize(fmt.Sprintf("Sysmon Detections: %d", ev.SysmonDetections))
	sw.lblEvQueue.SetTextAndResize(fmt.Sprintf("Upload Queue: %d", ev.QueueSize))
}

// renderSelfProtection updates the Self-Protection rows.
func (sw *windigoWindow) renderSelfProtection(s statusclient.StatusResponse, ev statusclient.EvidenceResponse) {
	setRow := func(lbl *ui.Static, name string, on bool) {
		status := "CHECK"
		if on {
			status = "HEALTHY"
		}
		lbl.SetTextAndResize(fmt.Sprintf("%s: %s", name, status))
	}
	setRow(sw.lblSpService, "Service Running", s.ServiceRunning)
	setRow(sw.lblSpPolicy, "Policy Sync", s.State == "active" || s.State == "restricted")
	setRow(sw.lblSpQueue, "Evidence Queue", ev.QueueSize < 100)
	setRow(sw.lblSpUpload, "Last Upload OK", s.LastUploadOk)
	setRow(sw.lblSpContact, "Server Contact", s.ServerConnected)
}
```

- [ ] **Step 4: Build**

```bash
go build ./...
```

Expected: succeeds.

- [ ] **Step 5: Commit**

```bash
git add statuswindow_windows.go
git commit -m "feat(agent): native status window - controls/evidence/self-protection/resources panels"
git push
```

---

### Task 7: Activity feed (diff-aware) and action buttons

**Files:**
- Modify: `agent/statuswindow_windows.go`

**Interfaces:**
- Consumes: `windigoWindow.Refresh` from Task 6; `StatusSnapshot.Activity.RecentActivity` (Task 1); `StatusController.ExportDiagnostics`/`.OpenDashboard` (Task 3).
- Produces: nothing new consumed by later tasks — last panel.

- [ ] **Step 1: Add the fields**

```go
	listActivity          *ui.ListView
	btnExport             *ui.Button
	btnDashboard          *ui.Button
	lastActivityFingerprint string
```

`lastActivityFingerprint` is how this task avoids rebuilding the list every poll (see Step 4) — a cheap summary of "what's currently displayed" (item count + newest item's timestamp+event text) compared against the incoming snapshot before touching the `ListView` at all. True per-row diffing would need a windigo `ListView` insert-at-index method beyond what Task 4 Step 1's `go doc` confirmed exists (`AddItem`/`DeleteAllItems`/`AllItems`/`ItemCount` were the verified methods) — this fingerprint approach gets the real win (skip all `ListView` calls on unchanged data, which is most polls) without assuming an unverified API.

- [ ] **Step 2: Create the controls**

Add to `newWindigoWindow`, after the Resources panel's controls:

```go
	sw.listActivity = ui.NewListView(sw.wnd, ui.OptsListView().
		Position(ui.Dpi(16, 416)).Size(ui.Dpi(684, 140)))
	sw.listActivity.Cols().Add("Time", ui.Dpi(100))
	sw.listActivity.Cols().Add("Event", ui.Dpi(560))

	sw.btnExport = ui.NewButton(sw.wnd, ui.OptsButton().
		Text("Export Diagnostic Bundle").Position(ui.Dpi(16, 568)).Size(ui.Dpi(200, 28)))
	sw.btnDashboard = ui.NewButton(sw.wnd, ui.OptsButton().
		Text("Open BAS Console").Position(ui.Dpi(232, 568)).Size(ui.Dpi(160, 28)))
```

- [ ] **Step 3: Wire the button handlers to the controller**

Add to `newWindigoWindow`, after control creation (button click handlers reference `sw.controller`, which is nil at construction time and set by `runStatusWindow` right after — safe because these closures only run later, after a user click, by which point wiring is complete):

```go
	sw.btnExport.On().BnClicked(func() {
		if sw.controller != nil {
			sw.controller.ExportDiagnostics()
		}
	})
	sw.btnDashboard.On().BnClicked(func() {
		if sw.controller != nil {
			sw.controller.OpenDashboard(sw.lastServerURL)
		}
	})
```

Note: unlike the old HTML page (which needed `window.basExport`/`window.basOpenDashboard` host-binding checks that never worked, since WebView2 never actually hosted the page), these handlers forward to `StatusController` — the window still never touches `exportDiagnosticBundle`/`openInBrowser` directly, matching `StatusWindow`'s presentation-only contract.

- [ ] **Step 4: Extend `Refresh` with diff-aware activity rendering**

Replace (Task 6's `Refresh`, its closing lines):

```go
	sw.lblResRam.SetTextAndResize(fmt.Sprintf("Memory: %d MB", s.RamMB))
	sw.lblResVersion.SetTextAndResize("Agent Version: v" + s.AgentVersion)
	sw.lblResId.SetTextAndResize("Agent ID: " + s.AgentID)
}
```

with:

```go
	sw.lblResRam.SetTextAndResize(fmt.Sprintf("Memory: %d MB", s.RamMB))
	sw.lblResVersion.SetTextAndResize("Agent Version: v" + s.AgentVersion)
	sw.lblResId.SetTextAndResize("Agent ID: " + s.AgentID)
	sw.renderActivity(snap.Activity.RecentActivity)
}

// renderActivity rebuilds the activity ListView only when its content has
// actually changed since the last Refresh, using a cheap fingerprint
// (item count + newest entry) instead of comparing every row -- most 5s
// (or 1s, mid-assessment) polls see no new activity at all, so this
// avoids the ListView churn a full delete+rebuild on every single tick
// would otherwise cost.
func (sw *windigoWindow) renderActivity(items []statusclient.Activity) {
	fp := activityFingerprint(items)
	if fp == sw.lastActivityFingerprint {
		return
	}
	sw.lastActivityFingerprint = fp

	sw.listActivity.DeleteAllItems()
	if len(items) == 0 {
		sw.listActivity.AddItem("—", "No recent activity recorded.")
		return
	}
	for _, item := range items {
		sw.listActivity.AddItem(item.Time.Format("15:04:05"), item.Event)
	}
}

func activityFingerprint(items []statusclient.Activity) string {
	if len(items) == 0 {
		return "empty"
	}
	newest := items[0]
	return fmt.Sprintf("%d|%s|%s", len(items), newest.Time.Format(time.RFC3339), newest.Event)
}
```

Add `"time"` to this file's import block if not already present (it is not, as of Task 4 Step 2 — add it now).

- [ ] **Step 5: Build**

```bash
go build ./...
```

Expected: succeeds. If `exportDiagnosticBundle`'s real signature differs from `(path string, err error)` (used in `StatusController.ExportDiagnostics`, Task 3, mirroring its existing call site in `tray_windows.go`'s `tIDM_EXPORT` handler exactly), this is where that would surface — but that call site is already correct and unchanged in the codebase today, so this should compile without adjustment.

- [ ] **Step 6: Commit**

```bash
git add statuswindow_windows.go
git commit -m "feat(agent): native status window - diff-aware activity feed + action buttons"
git push
```

---

### Task 8: Fix stale comments, final build, cross-compile check

**Files:**
- Modify: `agent/platform_windows.go` (flag description)
- Modify: `agent/tray_windows.go` (doc comment)

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing — closing task before the manual verification gate (Task 9).

- [ ] **Step 1: Fix the stale flag description**

In `agent/platform_windows.go`, replace (currently line 49):

```go
	flagStatusWindow = flag.Bool("status-window", false, "Open the WebView2 status console (user session)")
```

with:

```go
	flagStatusWindow = flag.Bool("status-window", false, "Open the native status console (user session)")
```

- [ ] **Step 2: Fix the stale tray doc comment**

In `agent/tray_windows.go`, replace (currently lines 145-146):

```go
// runTray shows the persistent system-tray icon. Left-click / double-click opens
// the WebView2 status console (spawned as a separate --status-window process).
```

with:

```go
// runTray shows the persistent system-tray icon. Left-click / double-click opens
// the native status console (spawned as a separate --status-window process).
```

- [ ] **Step 3: Full build, vet, and cross-compile checks**

```bash
cd agent
go build ./...
go vet ./...
go test ./... -v
GOOS=linux GOARCH=amd64 go build ./...
GOOS=darwin GOARCH=amd64 go build ./...
```

Expected: native build/vet/test all succeed against the real `windigo` dependency, `statusclient`'s tests pass, `StatusController`'s tests pass. Both cross-compiles succeed — `windigoWindow`/`browserWindow`/`statuswindow_windows.go`/`statuscontroller.go` are all behind `//go:build windows` (the last one only because of its `exportDiagnosticBundle`/`revealInExplorer`/`openInBrowser` calls, corrected during Task 3), and `statusclient`/`statuswindow.go` are portable Go with no platform-specific imports, so this confirms the client and interface layers really are platform-agnostic, not just in comment.

- [ ] **Step 4: Commit**

```bash
git add platform_windows.go tray_windows.go
git commit -m "$(cat <<'EOF'
chore(agent): fix stale WebView2 comments now that the console is native
EOF
)"
git push
```

---

### Task 9: Manual verification (required — cannot be done in this environment)

No code changes. This environment cannot render or interact with a native Win32 window, so every scenario below must be run for real on a Windows machine before this feature is considered production-ready — same "required acceptance gate" pattern as the Verified Agent Uninstall plan's per-OS validation earlier this session.

- [ ] **Step 1: Basic lifecycle**
  - First launch from the tray icon — window appears, populates within one poll cycle.
  - Close the window, click the tray icon again — reopens cleanly (confirm no "already running" false-positive, no leaked handle from the previous instance).
  - Minimize, then restore from the taskbar.
  - Resize the window — controls don't overlap or get clipped at the smallest/largest reasonable sizes.

- [ ] **Step 2: Display environment variations**
  - DPI scaling at 100%, 125%, 150%, and 200% (Windows Display Settings → Scale) — text and control positions remain legible and non-overlapping at each.
  - Windows Dark theme and Light theme (Settings → Personalization → Colors) — window is legible in both (native controls follow the OS theme automatically; confirm nothing looks broken/invisible in either).
  - Over an RDP session — window renders and the poll loop keeps working (RDP sessions can affect timer/paint behavior on some Win32 apps).

- [ ] **Step 3: Data and network conditions**
  - Start a real scenario run from the BAS console — confirm the Current Operation panel updates within ~1s (fast polling cadence) and the progress bar advances smoothly, not in visible jumps.
  - Let a run complete — confirm polling settles back to the slower 5s cadence and the Result tag appears.
  - Disconnect the machine's network entirely (server unreachable, local API still fine) — confirm the Connection panel shows "Disconnected" or "Paused" correctly, no crash.
  - Stop the `BASAgent` service (local API becomes unreachable too) — confirm the window shows the offline state within one poll cycle, not a hang or crash.
  - Restart the `BASAgent` service — confirm the window recovers automatically on the next poll, no restart of the status window itself required.

- [ ] **Step 4: Fallback and edge cases**
  - Simulate native window creation failing (e.g. temporarily rename/break the `windigo`-dependent code path in a test build, or note this is best confirmed via code review of the `Show()` error path if a real failure can't be induced) — confirm `browserWindow` opens instead and shows the same data via the existing HTML page.
  - Launch the status window multiple times in a row (rapid repeated tray clicks) — confirm no crash, no duplicate windows in a broken state, no orphaned poll-loop goroutines (check Task Manager for `bas_agent.exe` process count staying sane).
  - Close the window while a scenario is actively running — confirm the poll loop/goroutine actually stops (no lingering CPU usage from `bas_agent.exe --status-window` after the window is gone).

- [ ] **Step 5: Resource regression checks**
  - Leave the window open for an extended period (at least 30-60 minutes, ideally through a few scenario runs) — watch Task Manager for the `bas_agent.exe --status-window` process's memory usage; it should stay flat, not climb steadily (a climb indicates a leak, most likely from the diff-aware `ListView` rendering in Task 7 or from `windigo` control handles not being released).
  - Compare CPU usage of the native window's process against the old browser-based approach's typical idle CPU — the native version should be equal or lower at idle (5s polling, no browser rendering engine), and should not spike unexpectedly during the 1s fast-polling window.

- [ ] **Step 6: Record the outcome**

Report back per-scenario pass/fail. Only once all of the above pass should this feature be considered complete — no commit needed for this task, it is a verification gate on the work already committed in Tasks 1-8.

---

## Self-Review Notes

- **Spec coverage:** Every point from the architecture review has a task — `statusclient` package (Task 1), `StatusWindow`/`StatusSnapshot`/`browserWindow` (Task 2), `StatusController` with adaptive polling + action mediation (Task 3), the native window shell wired to the controller (Task 4), each remaining panel (Tasks 5-6), diff-aware activity rendering + controller-mediated buttons (Task 7), stale-comment cleanup (Task 8), and the expanded 6-category manual verification scenario list replacing the old generic "manual run" step (Task 9). The Goal section no longer names specific competitor products.
- **Placeholder scan:** No TBD/TODO. The one explicitly-flagged uncertainty (`Close()`'s exact `WM_CLOSE` mechanism in Task 4 Step 2) is called out by name with a concrete resolution path (check `go doc` output from Task 4 Step 1, prefer an idiomatic windigo method if one exists) rather than left vague — consistent with this plan's stated policy on windigo API details not yet confirmed against the real package.
- **Type consistency:** `StatusSnapshot`'s fields (`Online`, `Status`, `Activity`, `Evidence`, `Controls`) are used identically across `StatusController.poll`/`pollWithContext` (Task 3) and every `windigoWindow.Refresh`/render-helper (Tasks 4-7). `statusclient`'s typed structs (`StatusResponse`, `ActivityResponse`, `Operation`, `Activity`, `EvidenceResponse`, `ControlsResponse` + its 6 nested types) are defined once in Task 1 and referenced by exact field name in every later task with no renaming. `StatusWindow`'s three methods (`Show`/`Close`/`Refresh`) are implemented identically in both `browserWindow` (Task 2) and `windigoWindow` (Task 4).
- **Scope check:** 9 tasks, each independently reviewable — a reviewer could accept Task 1 (`statusclient`) while still having concerns about Task 3's polling-interval thresholds, or accept the whole window (Tasks 4-7) while flagging Task 9's verification results as incomplete. The four-layer architecture (client / interface+snapshot / controller / window) maps directly to four of the nine tasks, with the remaining five being panel-by-panel `Refresh` extensions plus cleanup and verification.
