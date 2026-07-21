# EPP Response Actions — Plan 3: Kill Process + Quarantine File Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `internal/vendors/crowdstrike` and `internal/vendors/defender` `KillProcess`/`QuarantineFile` methods, completing the four response actions this feature commits to (Isolate, Release, KillProcess, QuarantineFile).

**Architecture:** CrowdStrike has no single-call REST action for either capability — both go through a Real Time Response (RTR) session: start session → run a responder command → best-effort close the session. Defender's two actions are asymmetric: `QuarantineFile` is a normal one-call machine action (`StopAndQuarantineFile`, reusing Plan 2's `machineAction` helper) but `KillProcess` has no native machine action at all — it requires Defender's Live Response API to run a customer-provided PowerShell script, a real external dependency this plan cannot remove.

**Tech Stack:** Go 1.26, stdlib `net/http`/`net/http/httptest` only.

## Global Constraints

- This is Plan 3 of 5 for EPP Response Actions (spec: `docs/superpowers/specs/2026-07-21-epp-response-actions-design.md`). Plans 1-2 (vendor extraction; device resolution + Isolate/Release) are done — commits `d3328c1`, `f581127`, `84ecbd5`, `1aff9c2`, `bc5e030`. Plan 4 (`internal/actions` package + DB + permissions + API) and Plan 5 (UI) come after this one.
- **Vendor-API confidence note, read before implementing:** unlike Plan 2's Isolate/Release (stable, long-documented single-call endpoints), everything in this plan touches less-standardized vendor surface — CrowdStrike RTR's exact response field names and Defender Live Response's exact request shape are more likely to have drifted from what's below by the time this is implemented. Treat the endpoint paths and JSON field names in this plan as "this is how the documented API works as of this design" — confirm against current CrowdStrike Falcon and Microsoft Defender for Endpoint API docs before pointing either at a real tenant for the first time. The tests in this plan validate that this package's own code sends what it claims to send and parses what it claims to parse — they cannot validate that a real vendor tenant behaves this way.
- **No polling to completion.** Matching Plan 2's Isolate/Release (which return immediately once the vendor API *accepts* the request, not once containment is confirmed in effect), every method in this plan returns as soon as the vendor API acknowledges the request — a CrowdStrike `cloud_request_id` or a Defender machine-action `id`. Confirming the RTR command or Live Response script actually finished executing would require polling a status endpoint on an unbounded timeline (the device could be offline); that's out of scope here, consistent with this codebase's existing "no retries, simple" convention for these connectors.
- **Defender's `KillProcess` has a hard external dependency this plan cannot remove:** Defender for Endpoint has no built-in "kill process by PID" action. The only way to do it via API is Live Response's `RunScript` command, which runs a script the *customer* must have already uploaded to their own Defender Live Response script library. If that script doesn't exist in a given tenant, this call fails with a vendor error at request time — there is no way to detect or prevent that ahead of time from this codebase. This is fundamentally different from every other action in this feature (all of which work against any correctly-permissioned tenant with zero pre-staged customer assets).
- Module path: `github.com/audspect/bas`.

---

### Task 1: CrowdStrike KillProcess + QuarantineFile via RTR

**Files:**
- Modify: `orchestrator/internal/vendors/crowdstrike/client.go`
- Modify: `orchestrator/internal/vendors/crowdstrike/client_test.go`

**Interfaces:**
- Consumes: `Client.tokens`, `Client.httpClient` (Plan 1); `Client.ResolveDevice` (Plan 2, called by `internal/actions` in Plan 4, not by this task directly — this task's methods take an already-resolved `deviceID`, matching `Isolate`/`Release`'s existing signature shape).
- Produces: `(*Client).KillProcess(ctx context.Context, deviceID string, pid int) (string, error)`, `(*Client).QuarantineFile(ctx context.Context, deviceID, filePath string) (string, error)` — both consumed by Plan 4's `internal/actions` package. `Client.RTRSessionURL`, `Client.RTRCommandURL string` exported for test overrides.

- [ ] **Step 1: Write the failing tests**

Add to the end of `orchestrator/internal/vendors/crowdstrike/client_test.go` (after the last test, `TestDeviceAction_VendorReportsError_ReturnsError`, same file, same package):
```go

func newTestClientWithRTRURLs(t *testing.T, tokenURL, sessionURL, commandURL string) *Client {
	t.Helper()
	c := New(Config{BaseURL: "https://api.crowdstrike.com", ClientID: "c1", ClientSecret: "s1"})
	*c.TokenURL() = tokenURL
	c.RTRSessionURL = sessionURL
	c.RTRCommandURL = commandURL
	return c
}

func TestKillProcess_RunsSessionThenKillCommand(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	var gotSessionDeviceID string
	var gotCommand map[string]string
	var sessionDeleteCalled bool
	rtrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/sessions":
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			gotSessionDeviceID = body["device_id"]
			json.NewEncoder(w).Encode(map[string]any{"resources": []map[string]any{{"session_id": "sess-1"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/commands":
			json.NewDecoder(r.Body).Decode(&gotCommand)
			json.NewEncoder(w).Encode(map[string]any{"cloud_request_id": "req-1"})
		case r.Method == http.MethodDelete && r.URL.Path == "/sessions":
			sessionDeleteCalled = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer rtrSrv.Close()

	c := newTestClientWithRTRURLs(t, tokenSrv.URL, rtrSrv.URL+"/sessions", rtrSrv.URL+"/commands")
	reqID, err := c.KillProcess(context.Background(), "device-123", 4821)
	if err != nil {
		t.Fatalf("KillProcess: %v", err)
	}
	if reqID != "req-1" {
		t.Fatalf("reqID = %q, want req-1", reqID)
	}
	if gotSessionDeviceID != "device-123" {
		t.Fatalf("session device_id = %q, want device-123", gotSessionDeviceID)
	}
	if gotCommand["base_command"] != "kill" || gotCommand["command_string"] != "kill 4821" || gotCommand["session_id"] != "sess-1" {
		t.Fatalf("command = %+v, want base_command=kill command_string='kill 4821' session_id=sess-1", gotCommand)
	}
	if !sessionDeleteCalled {
		t.Fatal("expected the RTR session to be closed after the command was sent")
	}
}

func TestQuarantineFile_RunsSessionThenRmCommand(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	var gotCommand map[string]string
	rtrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/sessions":
			json.NewEncoder(w).Encode(map[string]any{"resources": []map[string]any{{"session_id": "sess-2"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/commands":
			json.NewDecoder(r.Body).Decode(&gotCommand)
			json.NewEncoder(w).Encode(map[string]any{"cloud_request_id": "req-2"})
		case r.Method == http.MethodDelete && r.URL.Path == "/sessions":
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer rtrSrv.Close()

	c := newTestClientWithRTRURLs(t, tokenSrv.URL, rtrSrv.URL+"/sessions", rtrSrv.URL+"/commands")
	reqID, err := c.QuarantineFile(context.Background(), "device-123", `C:\Users\victim\evil.exe`)
	if err != nil {
		t.Fatalf("QuarantineFile: %v", err)
	}
	if reqID != "req-2" {
		t.Fatalf("reqID = %q, want req-2", reqID)
	}
	if gotCommand["base_command"] != "rm" || gotCommand["command_string"] != `rm "C:\Users\victim\evil.exe"` {
		t.Fatalf(`command = %+v, want base_command=rm command_string='rm "C:\Users\victim\evil.exe"'`, gotCommand)
	}
}

func TestKillProcess_SessionStartFails_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	rtrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer rtrSrv.Close()

	c := newTestClientWithRTRURLs(t, tokenSrv.URL, rtrSrv.URL+"/sessions", rtrSrv.URL+"/commands")
	if _, err := c.KillProcess(context.Background(), "device-123", 1234); err == nil {
		t.Fatal("expected an error when the RTR session fails to start")
	}
}

func TestKillProcess_CommandReportsError_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	rtrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/sessions":
			json.NewEncoder(w).Encode(map[string]any{"resources": []map[string]any{{"session_id": "sess-3"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/commands":
			json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]any{{"message": "device offline"}}})
		case r.Method == http.MethodDelete && r.URL.Path == "/sessions":
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer rtrSrv.Close()

	c := newTestClientWithRTRURLs(t, tokenSrv.URL, rtrSrv.URL+"/sessions", rtrSrv.URL+"/commands")
	if _, err := c.KillProcess(context.Background(), "device-123", 1234); err == nil {
		t.Fatal("expected an error when the RTR command response carries an errors[] entry")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/vendors/crowdstrike/... -run 'TestKillProcess|TestQuarantineFile' -v` (from `orchestrator/`)
Expected: compile failure — `KillProcess`, `QuarantineFile`, `RTRSessionURL`, `RTRCommandURL` are undefined on `Client`.

- [ ] **Step 3: Implement RTR session lifecycle and KillProcess/QuarantineFile**

In `orchestrator/internal/vendors/crowdstrike/client.go`, find:
```go
// Client is a CrowdStrike Falcon API client. QueryURL/DetailURL/
// DeviceQueryURL/ActionURL are exported so tests outside this package
// (internal/detectverify) can point them at an httptest.Server.
type Client struct {
	QueryURL       string // defaults to <baseURL>/alerts/queries/alerts/v2
	DetailURL      string // defaults to <baseURL>/alerts/entities/alerts/v2
	DeviceQueryURL string // defaults to <baseURL>/devices/queries/devices/v1
	ActionURL      string // defaults to <baseURL>/devices/entities/devices-actions/v2
	tokens         *tokenSource
	httpClient     *http.Client

	deviceCacheMu sync.Mutex
	deviceCache   map[string]deviceCacheEntry
}

func New(cfg Config) *Client {
	base := strings.TrimRight(cfg.BaseURL, "/")
	return &Client{
		QueryURL:       base + "/alerts/queries/alerts/v2",
		DetailURL:      base + "/alerts/entities/alerts/v2",
		DeviceQueryURL: base + "/devices/queries/devices/v1",
		ActionURL:      base + "/devices/entities/devices-actions/v2",
		tokens:         newTokenSource(cfg.BaseURL, cfg.ClientID, cfg.ClientSecret),
		httpClient:     &http.Client{Timeout: 30 * time.Second},
		deviceCache:    make(map[string]deviceCacheEntry),
	}
}
```
Replace with:
```go
// Client is a CrowdStrike Falcon API client. QueryURL/DetailURL/
// DeviceQueryURL/ActionURL/RTRSessionURL/RTRCommandURL are exported so
// tests outside this package (internal/detectverify) can point them at an
// httptest.Server.
type Client struct {
	QueryURL       string // defaults to <baseURL>/alerts/queries/alerts/v2
	DetailURL      string // defaults to <baseURL>/alerts/entities/alerts/v2
	DeviceQueryURL string // defaults to <baseURL>/devices/queries/devices/v1
	ActionURL      string // defaults to <baseURL>/devices/entities/devices-actions/v2
	RTRSessionURL  string // defaults to <baseURL>/real-time-response/entities/sessions/v1
	RTRCommandURL  string // defaults to <baseURL>/real-time-response/entities/active-responder-command/v1
	tokens         *tokenSource
	httpClient     *http.Client

	deviceCacheMu sync.Mutex
	deviceCache   map[string]deviceCacheEntry
}

func New(cfg Config) *Client {
	base := strings.TrimRight(cfg.BaseURL, "/")
	return &Client{
		QueryURL:       base + "/alerts/queries/alerts/v2",
		DetailURL:      base + "/alerts/entities/alerts/v2",
		DeviceQueryURL: base + "/devices/queries/devices/v1",
		ActionURL:      base + "/devices/entities/devices-actions/v2",
		RTRSessionURL:  base + "/real-time-response/entities/sessions/v1",
		RTRCommandURL:  base + "/real-time-response/entities/active-responder-command/v1",
		tokens:         newTokenSource(cfg.BaseURL, cfg.ClientID, cfg.ClientSecret),
		httpClient:     &http.Client{Timeout: 30 * time.Second},
		deviceCache:    make(map[string]deviceCacheEntry),
	}
}
```

Find the end of `deviceAction` (the closing `}` right before `func buildFQLFilter`):
```go
	if len(out.Errors) > 0 {
		return "", fmt.Errorf("crowdstrike device action %s: %s", actionName, out.Errors[0].Message)
	}
	return out.Meta.TraceID, nil
}

func buildFQLFilter(q AlertQuery) string {
```
Replace with:
```go
	if len(out.Errors) > 0 {
		return "", fmt.Errorf("crowdstrike device action %s: %s", actionName, out.Errors[0].Message)
	}
	return out.Meta.TraceID, nil
}

// KillProcess runs Falcon RTR's "kill" responder command for pid on
// deviceID, via a short-lived RTR session. Returns the vendor's
// cloud_request_id — this acknowledges the vendor accepted the command, not
// that it has finished executing (see Global Constraints: no polling to
// completion).
func (c *Client) KillProcess(ctx context.Context, deviceID string, pid int) (string, error) {
	return c.runRTRCommand(ctx, deviceID, "kill", fmt.Sprintf("kill %d", pid))
}

// QuarantineFile runs Falcon RTR's "rm" responder command against filePath
// on deviceID. CrowdStrike RTR has no command verb named "quarantine" —
// deletion via "rm" is the closest available responder action; confirm
// against current Falcon RTR command docs before relying on this in
// production (see Global Constraints).
func (c *Client) QuarantineFile(ctx context.Context, deviceID, filePath string) (string, error) {
	return c.runRTRCommand(ctx, deviceID, "rm", fmt.Sprintf(`rm "%s"`, filePath))
}

// runRTRCommand starts an RTR session on deviceID, sends one responder
// command, and best-effort closes the session (cleanup uses a fresh
// background context so a caller-cancelled ctx doesn't leave a dangling
// session).
func (c *Client) runRTRCommand(ctx context.Context, deviceID, baseCommand, commandString string) (string, error) {
	sessionID, err := c.startRTRSession(ctx, deviceID)
	if err != nil {
		return "", err
	}
	defer c.closeRTRSession(context.Background(), sessionID)

	return c.executeRTRCommand(ctx, deviceID, sessionID, baseCommand, commandString)
}

func (c *Client) startRTRSession(ctx context.Context, deviceID string) (string, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]string{"device_id": deviceID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.RTRSessionURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("crowdstrike start RTR session: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("crowdstrike start RTR session: HTTP %d: %s", resp.StatusCode, data)
	}
	var out struct {
		Resources []struct {
			SessionID string `json:"session_id"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("crowdstrike: parse RTR session response: %w", err)
	}
	if len(out.Resources) == 0 || out.Resources[0].SessionID == "" {
		return "", fmt.Errorf("crowdstrike: RTR session response did not include a session_id")
	}
	return out.Resources[0].SessionID, nil
}

func (c *Client) executeRTRCommand(ctx context.Context, deviceID, sessionID, baseCommand, commandString string) (string, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]string{
		"base_command": baseCommand, "command_string": commandString,
		"session_id": sessionID, "device_id": deviceID,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.RTRCommandURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("crowdstrike RTR command %s: %w", baseCommand, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("crowdstrike RTR command %s: HTTP %d: %s", baseCommand, resp.StatusCode, data)
	}
	var out struct {
		CloudRequestID string `json:"cloud_request_id"`
		Errors         []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("crowdstrike: parse RTR command response: %w", err)
	}
	if len(out.Errors) > 0 {
		return "", fmt.Errorf("crowdstrike RTR command %s: %s", baseCommand, out.Errors[0].Message)
	}
	if out.CloudRequestID == "" {
		return "", fmt.Errorf("crowdstrike: RTR command response did not include a cloud_request_id")
	}
	return out.CloudRequestID, nil
}

// closeRTRSession is best-effort cleanup — a failure to close a session
// leaves it to expire on its own on CrowdStrike's side, so errors here are
// not surfaced to the caller (the response action itself already
// succeeded or failed by the time this runs).
func (c *Client) closeRTRSession(ctx context.Context, sessionID string) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return
	}
	reqURL := c.RTRSessionURL + "?" + url.Values{"session_id": {sessionID}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, reqURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

func buildFQLFilter(q AlertQuery) string {
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/vendors/crowdstrike/... -v` (from `orchestrator/`)
Expected: `PASS` — all tests green, including every test from Plans 1-2 (unaffected by this change).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/vendors/crowdstrike/client.go orchestrator/internal/vendors/crowdstrike/client_test.go
git commit -m "feat(vendors/crowdstrike): add kill process and quarantine file via RTR"
```

---

### Task 2: Defender QuarantineFile via StopAndQuarantineFile

**Files:**
- Modify: `orchestrator/internal/vendors/defender/client.go`
- Modify: `orchestrator/internal/vendors/defender/client_test.go`

**Interfaces:**
- Consumes: `Client.machineAction` (Plan 2 — this task reuses it as-is, no changes to that helper).
- Produces: `(*Client).QuarantineFile(ctx context.Context, deviceID, sha1 string) (string, error)`, consumed by Plan 4. Note the parameter is a SHA1 hash, not a file path — Defender's `StopAndQuarantineFile` machine action identifies the file by hash, unlike CrowdStrike's `QuarantineFile(ctx, deviceID, filePath string)` from Task 1. `internal/actions` (Plan 4) will map its vendor-agnostic `Parameters map[string]any` to whichever of `filePath`/`sha1` the target vendor's method actually takes.

- [ ] **Step 1: Write the failing tests**

Add to the end of `orchestrator/internal/vendors/defender/client_test.go` (after the last test, `TestMachineAction_HTTPError_ReturnsError`, same file, same package):
```go

func TestQuarantineFile_CallsStopAndQuarantineFileEndpoint(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var gotPath string
	var gotBody map[string]any
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]any{"id": "action-quarantine-1"})
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	actionID, err := c.QuarantineFile(context.Background(), "machine-123", "aabbccddeeff00112233445566778899aabbccdd")
	if err != nil {
		t.Fatalf("QuarantineFile: %v", err)
	}
	if actionID != "action-quarantine-1" {
		t.Fatalf("actionID = %q, want action-quarantine-1", actionID)
	}
	if gotPath != "/machines/machine-123/StopAndQuarantineFile" {
		t.Fatalf("path = %q, want /machines/machine-123/StopAndQuarantineFile", gotPath)
	}
	if gotBody["Sha1"] != "aabbccddeeff00112233445566778899aabbccdd" {
		t.Fatalf("body Sha1 = %v, want the test sha1", gotBody["Sha1"])
	}
}

func TestQuarantineFile_HTTPError_ReturnsError(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	if _, err := c.QuarantineFile(context.Background(), "machine-123", "badhash"); err == nil {
		t.Fatal("expected an error from a 400 StopAndQuarantineFile response")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/vendors/defender/... -run 'TestQuarantineFile' -v` (from `orchestrator/`)
Expected: compile failure — `QuarantineFile` is undefined on `Client`.

- [ ] **Step 3: Implement QuarantineFile**

In `orchestrator/internal/vendors/defender/client.go`, find:
```go
// Release lifts isolation on deviceID.
func (c *Client) Release(ctx context.Context, deviceID string) (string, error) {
	return c.machineAction(ctx, deviceID, "unisolate", map[string]any{
		"Comment": "Released by Audspect BAS response action",
	})
}
```
Replace with:
```go
// Release lifts isolation on deviceID.
func (c *Client) Release(ctx context.Context, deviceID string) (string, error) {
	return c.machineAction(ctx, deviceID, "unisolate", map[string]any{
		"Comment": "Released by Audspect BAS response action",
	})
}

// QuarantineFile stops and quarantines the file identified by sha1
// wherever it's running/present on deviceID. Defender identifies files by
// hash for this action, not by path — this is the vendor-documented
// StopAndQuarantineFile machine action.
func (c *Client) QuarantineFile(ctx context.Context, deviceID, sha1 string) (string, error) {
	return c.machineAction(ctx, deviceID, "StopAndQuarantineFile", map[string]any{
		"Sha1": sha1, "Comment": "Quarantined by Audspect BAS response action",
	})
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/vendors/defender/... -v` (from `orchestrator/`)
Expected: `PASS` — all tests green, including every test from Plans 1-2.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/vendors/defender/client.go orchestrator/internal/vendors/defender/client_test.go
git commit -m "feat(vendors/defender): add quarantine file via StopAndQuarantineFile"
```

---

### Task 3: Defender KillProcess via Live Response RunScript

**Files:**
- Modify: `orchestrator/internal/vendors/defender/client.go`
- Modify: `orchestrator/internal/vendors/defender/client_test.go`

**Interfaces:**
- Consumes: `Client.actionTokens`, `Client.httpClient`, `Client.ActionBaseURL` (Plan 2/this file).
- Produces: `(*Client).KillProcess(ctx context.Context, deviceID string, pid int) (string, error)`, consumed by Plan 4. `Config.KillProcessScriptName string` — the name of the customer-uploaded Live Response script this calls; defaults to `"Audspect-KillProcess.ps1"` if left empty, but **this default will not exist in a fresh tenant** — see Global Constraints. `Client.LiveResponseURL string` exported for test overrides.

- [ ] **Step 1: Write the failing tests**

Add to the end of `orchestrator/internal/vendors/defender/client_test.go` (after `TestQuarantineFile_HTTPError_ReturnsError` from Task 2, same file, same package):
```go

func newTestClientWithLiveResponseURL(t *testing.T, actionTokenURL, liveResponseURL, scriptName string) *Client {
	t.Helper()
	c := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1", KillProcessScriptName: scriptName})
	*c.ActionTokenURL() = actionTokenURL
	c.LiveResponseURL = liveResponseURL
	return c
}

func TestKillProcess_CallsRunLiveResponseWithConfiguredScript(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var gotBody map[string]any
	lrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]any{"id": "machineaction-1"})
	}))
	defer lrSrv.Close()

	c := newTestClientWithLiveResponseURL(t, actionTokenSrv.URL, lrSrv.URL, "Contoso-KillProc.ps1")
	actionID, err := c.KillProcess(context.Background(), "machine-123", 4821)
	if err != nil {
		t.Fatalf("KillProcess: %v", err)
	}
	if actionID != "machineaction-1" {
		t.Fatalf("actionID = %q, want machineaction-1", actionID)
	}
	commands, ok := gotBody["Commands"].([]any)
	if !ok || len(commands) != 1 {
		t.Fatalf("Commands = %v, want exactly one command", gotBody["Commands"])
	}
	cmd, ok := commands[0].(map[string]any)
	if !ok || cmd["type"] != "RunScript" {
		t.Fatalf("commands[0] = %v, want type=RunScript", commands[0])
	}
	params, ok := cmd["params"].([]any)
	if !ok || len(params) != 2 {
		t.Fatalf("params = %v, want ScriptName and Args", cmd["params"])
	}
	scriptParam, ok := params[0].(map[string]any)
	if !ok || scriptParam["key"] != "ScriptName" || scriptParam["value"] != "Contoso-KillProc.ps1" {
		t.Fatalf("params[0] = %v, want key=ScriptName value=Contoso-KillProc.ps1", params[0])
	}
	argsParam, ok := params[1].(map[string]any)
	if !ok || argsParam["key"] != "Args" || argsParam["value"] != "4821" {
		t.Fatalf("params[1] = %v, want key=Args value=4821", params[1])
	}
}

func TestKillProcess_EmptyScriptName_DefaultsToAudspectScript(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var gotBody map[string]any
	lrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]any{"id": "machineaction-2"})
	}))
	defer lrSrv.Close()

	c := newTestClientWithLiveResponseURL(t, actionTokenSrv.URL, lrSrv.URL, "")
	if _, err := c.KillProcess(context.Background(), "machine-123", 100); err != nil {
		t.Fatalf("KillProcess: %v", err)
	}
	commands := gotBody["Commands"].([]any)
	cmd := commands[0].(map[string]any)
	params := cmd["params"].([]any)
	scriptParam := params[0].(map[string]any)
	if scriptParam["value"] != "Audspect-KillProcess.ps1" {
		t.Fatalf("default script name = %v, want Audspect-KillProcess.ps1", scriptParam["value"])
	}
}

func TestKillProcess_HTTPError_ReturnsError(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()
	lrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"message":"Script not found in library"}}`))
	}))
	defer lrSrv.Close()

	c := newTestClientWithLiveResponseURL(t, actionTokenSrv.URL, lrSrv.URL, "")
	if _, err := c.KillProcess(context.Background(), "machine-123", 100); err == nil {
		t.Fatal("expected an error when the vendor reports the script isn't found")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/vendors/defender/... -run 'TestKillProcess' -v` (from `orchestrator/`)
Expected: compile failure — `KillProcess`, `Config.KillProcessScriptName`, `Client.LiveResponseURL` are undefined.

- [ ] **Step 3: Implement KillProcess via Live Response**

In `orchestrator/internal/vendors/defender/client.go`, find:
```go
// Config holds the connection settings for one Defender/Entra tenant.
type Config struct {
	TenantID     string
	ClientID     string
	ClientSecret string
}
```
Replace with:
```go
// Config holds the connection settings for one Defender/Entra tenant.
type Config struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	// KillProcessScriptName is the filename of a PowerShell script the
	// customer has already uploaded to their Defender Live Response script
	// library. Defender has no built-in "kill process" machine action —
	// this is the only way to do it via API. Defaults to
	// "Audspect-KillProcess.ps1" if empty, which will NOT exist in a fresh
	// tenant; KillProcess fails with a vendor error until the customer
	// uploads a script under this name (or configures a different name).
	KillProcessScriptName string
}
```

Find:
```go
func New(cfg Config) *Client {
	return &Client{
		BaseURL:       "https://graph.microsoft.com/v1.0",
		ActionBaseURL: "https://api.securitycenter.microsoft.com/api",
		tokens: msauth.NewEntraTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret,
			"https://graph.microsoft.com/.default"),
		actionTokens: msauth.NewEntraTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret,
			"https://api.securitycenter.microsoft.com/.default"),
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		deviceCache: make(map[string]deviceCacheEntry),
	}
}
```
Replace with:
```go
func New(cfg Config) *Client {
	scriptName := cfg.KillProcessScriptName
	if scriptName == "" {
		scriptName = "Audspect-KillProcess.ps1"
	}
	return &Client{
		BaseURL:                "https://graph.microsoft.com/v1.0",
		ActionBaseURL:          "https://api.securitycenter.microsoft.com/api",
		killProcessScriptName:  scriptName,
		tokens: msauth.NewEntraTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret,
			"https://graph.microsoft.com/.default"),
		actionTokens: msauth.NewEntraTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret,
			"https://api.securitycenter.microsoft.com/.default"),
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		deviceCache: make(map[string]deviceCacheEntry),
	}
}
```

Find:
```go
type Client struct {
	BaseURL       string // defaults to https://graph.microsoft.com/v1.0
	ActionBaseURL string // defaults to https://api.securitycenter.microsoft.com/api
	tokens        *msauth.EntraTokenSource
	actionTokens  *msauth.EntraTokenSource
	httpClient    *http.Client

	deviceCacheMu sync.Mutex
	deviceCache   map[string]deviceCacheEntry
}
```
Replace with:
```go
type Client struct {
	BaseURL          string // defaults to https://graph.microsoft.com/v1.0
	ActionBaseURL    string // defaults to https://api.securitycenter.microsoft.com/api
	LiveResponseURL  string // defaults to "" — see New(), it's built from ActionBaseURL per machine ID, not a fixed URL; kept as an explicit override point for tests
	tokens           *msauth.EntraTokenSource
	actionTokens     *msauth.EntraTokenSource
	httpClient       *http.Client
	killProcessScriptName string

	deviceCacheMu sync.Mutex
	deviceCache   map[string]deviceCacheEntry
}
```

Note: unlike `ActionBaseURL`, `LiveResponseURL` is per-machine (`.../machines/{id}/runliveresponse`), so it can't be a fixed prefix set once in `New()` the way `RTRSessionURL` could for CrowdStrike. Find:
```go
func (c *Client) machineAction(ctx context.Context, deviceID, verb string, body map[string]any) (string, error) {
```
Add immediately before it:
```go
// KillProcess runs a customer-provided PowerShell script via Defender Live
// Response to kill pid on deviceID. Returns the machine action ID — this
// acknowledges the vendor accepted the request, not that the script
// finished running (see Global Constraints: no polling to completion).
// Requires Config.KillProcessScriptName (or its default) to already exist
// in the tenant's Live Response script library — see the Config field doc.
func (c *Client) KillProcess(ctx context.Context, deviceID string, pid int) (string, error) {
	token, err := c.actionTokens.Token(ctx)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]any{
		"Comment": "Kill process via Audspect BAS response action",
		"Commands": []map[string]any{
			{
				"type": "RunScript",
				"params": []map[string]string{
					{"key": "ScriptName", "value": c.killProcessScriptName},
					{"key": "Args", "value": strconv.Itoa(pid)},
				},
			},
		},
	})
	reqURL := c.ActionBaseURL + "/machines/" + deviceID + "/runliveresponse"
	if c.LiveResponseURL != "" {
		reqURL = c.LiveResponseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("defender kill process: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("defender kill process: HTTP %d: %s", resp.StatusCode, data)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("defender: parse live response action: %w", err)
	}
	return out.ID, nil
}

```

Find the import block:
```go
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/audspect/bas/internal/platform/msauth"
)
```
Replace with:
```go
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/audspect/bas/internal/platform/msauth"
)
```

- [ ] **Step 4: Run `gofmt` to fix struct field alignment** (the `Client` struct edit above has inconsistent tab alignment, which `gofmt` normalizes automatically — Go doesn't require manual alignment, but this codebase's existing files are consistently `gofmt`-clean)

Run: `gofmt -w internal/vendors/defender/client.go` (from `orchestrator/`)
Expected: no output; the file is reformatted in place.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/vendors/defender/... -v` (from `orchestrator/`)
Expected: `PASS` — all tests green, including every test from Plans 1-2 and Task 2 of this plan.

- [ ] **Step 6: Run detectverify's tests and the whole module's build/vet as a final regression check**

Run: `go test ./internal/detectverify/... -v && go build ./... && go vet ./...` (from `orchestrator/`)
Expected: `PASS` and no build/vet errors.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/vendors/defender/client.go orchestrator/internal/vendors/defender/client_test.go
git commit -m "feat(vendors/defender): add kill process via Live Response RunScript"
```

---

## Self-Review Notes

**Spec coverage:** completes the spec's four in-scope actions (Isolate, Release from Plan 2; KillProcess, QuarantineFile from this plan) for both in-scope vendors. The spec's UI section already documents that Kill Process/Quarantine File take operator-entered parameters (PID, file path) since run results don't capture this data — this plan's method signatures (`KillProcess(ctx, deviceID, pid int)`, CrowdStrike's `QuarantineFile(ctx, deviceID, filePath string)`, Defender's `QuarantineFile(ctx, deviceID, sha1 string)`) are exactly what Plan 5's UI will need to collect from the operator, with Defender additionally needing a SHA1 rather than a path (a detail the spec didn't anticipate, now recorded here and in memory for Plan 5).

**Placeholder scan:** none — every step contains complete code or an exact command with expected output.

**Type/name consistency:** all four vendor methods across both packages return `(string, error)` where the string is a vendor-assigned request/action ID, consistent with Plan 2's `Isolate`/`Release`. CrowdStrike's `QuarantineFile(ctx, deviceID, filePath string)` and Defender's `QuarantineFile(ctx, deviceID, sha1 string)` intentionally have different second-parameter semantics despite the same method name and package-external shape — flagged explicitly above and in Global Constraints so Plan 4 doesn't assume they're interchangeable.

**A deviation worth flagging to the user:** Defender's `KillProcess` depends on a customer-uploaded Live Response script that this codebase cannot guarantee exists (see Global Constraints). This is a materially different reliability story than every other action in this feature. Options for Plan 4/5 to consider, not decided here: surface this prerequisite prominently in the Response Connectors admin config screen (Plan 5), or let it simply fail with the vendor's own "script not found" error the first time an operator tries it. Flagging now rather than silently building UI that implies this action is as reliable as the other three.
