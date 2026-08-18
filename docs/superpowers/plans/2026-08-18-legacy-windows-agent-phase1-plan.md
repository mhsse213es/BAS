# Legacy Windows Agent — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a new, separately-toolchained `agent-legacy/` Windows agent that enrolls with the orchestrator, sends heartbeats, and appears in the console — proving the legacy-agent architecture end-to-end before any collector or BAS/ART content is built.

**Architecture:** A sibling Go module (`agent-legacy/`, module path `audspect/agent-legacy`) pinned to a verified Go 1.20.14 toolchain (the last Go release supporting Windows 7 SP1/8/8.1/Server 2008 R2–2012 R2), speaking the exact same enrollment/heartbeat/WS wire protocol the modern agent already uses — no backend changes, no shared Go source between the two modules. It ships through the same Docker-image-baked agent-download pipeline the modern agent uses, plus a new plain-styled card in the console's Deploy Agent section.

**Tech Stack:** Go 1.20.14 (pinned via `toolchain` directive + `GOTOOLCHAIN` env + verified `go version` assertion), `golang.org/x/sys/windows` + `.../svc` + `.../svc/mgr` + `.../svc/eventlog` (Windows service registration), `github.com/gorilla/websocket` (WS client), Docker multi-stage build, PowerShell build scripts.

**Spec:** `docs/superpowers/specs/2026-08-18-legacy-windows-agent-phase1-design.md`

## Global Constraints

- **Architecture support:** amd64 only. 32-bit (x86) is explicitly out of scope for v1 — do not add it, do not add scaffolding for it.
- **Toolchain:** the resolved build toolchain MUST be verified as exactly `go1.20.14` (via an actual `go version` check that fails the build otherwise) — a bare `go 1.20` line in go.mod is not sufficient on its own, since a newer `go` on PATH will silently build against it instead.
- **No shared Go source** between `agent/` and `agent-legacy/`. Protocol compatibility is enforced by both modules implementing the same wire shapes independently, not by importing a common package.
- **No backend enrollment code changes.** The legacy agent must work against the orchestrator's existing `/api/agents/enroll`, `/api/heartbeat`, and `/ws/agent` endpoints exactly as they exist today.
- **Phase 1 scope only:** enrollment, secure comms, health/status, service install/uninstall, and the release pipeline. No inventory/posture collectors, no ART/BAS simulation, no server-side compatibility gating. `PostureCatalog` in the enrollment payload is empty/nil for Phase 1 — this is expected, not a bug.
- Every touched Go file gets `gofmt`'d before commit. Run the full relevant test package (not just new tests) before each commit. Commit and push after each task.

---

### Task 1: Scaffold `agent-legacy/` module with a verified Go 1.20.14 toolchain

**Files:**
- Create: `agent-legacy/go.mod`
- Create: `agent-legacy/CAPABILITY_MATRIX.md`
- Create: `agent-legacy/.gitignore` (mirror `agent/.gitignore` if one exists; otherwise ignore built binaries)
- Test: `agent-legacy/toolchain_test.go`

**Interfaces:**
- Produces: the `agent-legacy` module root other tasks build files into. `go.mod` declares `module audspect/agent-legacy`, `go 1.20` — no `toolchain` directive (see Step 1's note on why).

- [ ] **Step 1: Create the module**

```bash
mkdir agent-legacy
cd agent-legacy
GOTOOLCHAIN=go1.20.14 go mod init audspect/agent-legacy
```

This downloads and caches Go 1.20.14 locally (if not already present) and initializes `go.mod` with a bare `go 1.20` line.

**Do not add a `toolchain go1.20.14` line to `go.mod`.** Verified empirically: the `toolchain`
directive syntax is itself a Go 1.21+ concept. Once `GOTOOLCHAIN=go1.20.14` correctly re-execs
into the real go1.20.14 binary, that binary parses `go.mod` itself — and go1.20.14 doesn't
recognize the `toolchain` keyword, since it predates it, so the build fails immediately with
`unknown directive: toolchain`. `GOTOOLCHAIN` (set in the environment, everywhere this module is
built) is the *only* pinning mechanism — `go.mod` stays at a bare `go 1.20`:

```go
module audspect/agent-legacy

go 1.20
```

- [ ] **Step 2: Write the failing toolchain-verification test**

```go
// agent-legacy/toolchain_test.go
package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestBuildToolchain_IsExactlyGo1_20_14 is the load-bearing check for this
// entire module: a bare `go 1.20` line in go.mod only enforces minimum
// LANGUAGE compatibility -- if a newer `go` binary is on PATH it will still
// build against it, producing a binary linked against a newer runtime than
// the one Windows 7/8/Server 2008R2-2012 compatibility actually depends on.
// This test fails loudly if GOTOOLCHAIN isn't pinned correctly in whatever
// environment runs it.
func TestBuildToolchain_IsExactlyGo1_20_14(t *testing.T) {
	out, err := exec.Command("go", "version").CombinedOutput()
	if err != nil {
		t.Fatalf("go version failed: %v (%s)", err, out)
	}
	got := strings.TrimSpace(string(out))
	if !strings.Contains(got, "go1.20.14") {
		t.Fatalf("resolved toolchain = %q, want it to contain \"go1.20.14\" -- set GOTOOLCHAIN=go1.20.14 in the environment running this build/test", got)
	}
}
```

- [ ] **Step 3: Run the test to verify it currently reflects the environment's real toolchain**

```bash
cd agent-legacy
GOTOOLCHAIN=go1.20.14 go test -run TestBuildToolchain_IsExactlyGo1_20_14 -v .
```

Expected: PASS, with output showing `go version go1.20.14 windows/amd64` or `go version go1.20.14 <host-os>/<host-arch>` (the test host's own OS/arch — GOOS/GOARCH only affect what's *targeted*, not which toolchain binary runs `go version` itself). If this fails because Go 1.20.14 isn't downloadable in this environment (offline build host, proxy blocking `sum.golang.org`), note the failure and its exact error — this is a real environment prerequisite to resolve before Task 6, not something to work around by weakening the assertion.

- [ ] **Step 4: Write the capability matrix doc**

Copy the full capability matrix tables from `docs/superpowers/specs/2026-08-18-legacy-windows-agent-phase1-design.md` (both the "Platform support (v1)" table and the "Capability matrix (target — Phases 1–3 combined)" table) verbatim into `agent-legacy/CAPABILITY_MATRIX.md`, plus the exact "Architecture support" sentence from the spec:

```markdown
# Legacy Windows Agent — Capability Matrix

**Architecture support: Legacy Windows Agent v1 supports Windows x86-64 (amd64) only.
32-bit Windows (386/x86) is explicitly out of scope for v1.** Support for 32-bit systems
may be evaluated separately based on customer demand and compatibility feasibility.

This is a compatibility agent, not an old version of Audspect. It is not held to feature
parity with the modern agent. Every future feature is classified before it's considered
for this agent:

- **A — Legacy-compatible**: implemented for both agents from the start.
- **B — Modern-only**: requires Windows 10+ APIs, newer OS security facilities, or
  newer Go/runtime/dependencies this toolchain can't build. Modern agent only, by design.
- **C — Legacy-backportable**: technically portable but not automatic; an explicit,
  separate decision each time.

[... paste both full tables from the spec here, unmodified ...]
```

- [ ] **Step 5: Commit**

```bash
git add agent-legacy/go.mod agent-legacy/toolchain_test.go agent-legacy/CAPABILITY_MATRIX.md
git commit -m "feat(agent-legacy): scaffold module pinned to verified Go 1.20.14 toolchain"
git push
```

---

### Task 2: Identity + config loading

**Files:**
- Create: `agent-legacy/config.go`
- Create: `agent-legacy/identity.go`
- Create: `agent-legacy/sysinfo_windows.go`
- Test: `agent-legacy/config_test.go`
- Test: `agent-legacy/identity_test.go`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `type Config struct { ServerURL, EnvLabel, AgentSecret string }` and `func loadConfig() Config` (mirrors `agent/config.go`'s exact env vars: `BAS_SERVER_URL`, `BAS_ENV_LABEL`, `BAS_AGENT_SECRET`). `type Identity struct { AgentID, Hostname, IPAddress, Username, OSVersion string }` and `func buildIdentity() Identity`. `func getWindowsVersion() string` (used by `buildIdentity`). Task 3 consumes `Config` and `Identity` directly.

- [ ] **Step 1: Write the failing config test**

```go
// agent-legacy/config_test.go
package main

import (
	"os"
	"testing"
)

func TestLoadConfig_ReadsFromEnv(t *testing.T) {
	os.Setenv("BAS_SERVER_URL", "http://example.com:9000")
	os.Setenv("BAS_ENV_LABEL", "Production")
	os.Setenv("BAS_AGENT_SECRET", "s3cr3t")
	defer os.Unsetenv("BAS_SERVER_URL")
	defer os.Unsetenv("BAS_ENV_LABEL")
	defer os.Unsetenv("BAS_AGENT_SECRET")

	cfg := loadConfig()
	if cfg.ServerURL != "http://example.com:9000" {
		t.Errorf("ServerURL = %q, want http://example.com:9000", cfg.ServerURL)
	}
	if cfg.EnvLabel != "Production" {
		t.Errorf("EnvLabel = %q, want Production", cfg.EnvLabel)
	}
	if cfg.AgentSecret != "s3cr3t" {
		t.Errorf("AgentSecret = %q, want s3cr3t", cfg.AgentSecret)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd agent-legacy && GOTOOLCHAIN=go1.20.14 go test -run TestLoadConfig_ReadsFromEnv -v .
```

Expected: FAIL (build error — `loadConfig`/`Config` not defined).

- [ ] **Step 3: Implement config loading**

```go
// agent-legacy/config.go
package main

import "os"

// Config mirrors agent/config.go's Config exactly -- same env var names, so
// the same install/deployment tooling and documentation (BAS_SERVER_URL,
// BAS_ENV_LABEL, BAS_AGENT_SECRET) works for both agents without an operator
// needing to know which one they're configuring.
type Config struct {
	ServerURL   string
	EnvLabel    string
	AgentSecret string
}

func loadConfig() Config {
	return Config{
		ServerURL:   os.Getenv("BAS_SERVER_URL"),
		EnvLabel:    os.Getenv("BAS_ENV_LABEL"),
		AgentSecret: os.Getenv("BAS_AGENT_SECRET"),
	}
}
```

- [ ] **Step 4: Run the config test to verify it passes**

```bash
cd agent-legacy && GOTOOLCHAIN=go1.20.14 go test -run TestLoadConfig_ReadsFromEnv -v .
```

Expected: PASS.

- [ ] **Step 5: Add the `golang.org/x/sys` dependency, pinned to a Go-1.20-compatible version**

```bash
cd agent-legacy
GOTOOLCHAIN=go1.20.14 go get golang.org/x/sys@latest
```

If `@latest` resolves to a version whose own `go.mod` declares a newer `go` directive than 1.20 (check the error message — Go will refuse the get and say so directly), pin an explicit older version instead, e.g. `GOTOOLCHAIN=go1.20.14 go get golang.org/x/sys@v0.15.0` (a version contemporaneous with Go 1.20's own support window) and adjust until `go mod tidy` succeeds cleanly under the pinned toolchain.

- [ ] **Step 6: Write the failing Windows-version test**

```go
// agent-legacy/sysinfo_windows.go has getWindowsVersion(); the test lives in
// a build-tag-free file so `go vet`/`go test` on a non-Windows dev machine
// still sees identity.go's other exported behavior, but this specific test
// only compiles on Windows.
```

```go
// agent-legacy/identity_test.go
package main

import "testing"

func TestBuildIdentity_PopulatesRequiredFields(t *testing.T) {
	id := buildIdentity()
	if id.Hostname == "" {
		t.Error("Hostname is empty")
	}
	if id.OSVersion == "" {
		t.Error("OSVersion is empty")
	}
}
```

- [ ] **Step 7: Run it to verify it fails**

```bash
cd agent-legacy && GOTOOLCHAIN=go1.20.14 go test -run TestBuildIdentity_PopulatesRequiredFields -v .
```

Expected: FAIL (`buildIdentity`/`Identity` not defined).

- [ ] **Step 8: Implement `getWindowsVersion` and `buildIdentity`**

```go
// agent-legacy/sysinfo_windows.go
//go:build windows

package main

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

// getWindowsVersion mirrors agent/sysinfo_windows.go's getWindowsVersion
// exactly -- RtlGetVersion bypasses the compatibility shim that makes older
// apps see a wrong version on newer Windows; here it correctly reports the
// real legacy build number (e.g. 6.1.7601 for Windows 7 SP1).
func getWindowsVersion() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}

func getOSVersion() string {
	return fmt.Sprintf("Windows/%s (%s)", runtime.GOARCH, getWindowsVersion())
}
```

```go
// agent-legacy/identity.go
package main

import (
	"net"
	"os"
	"os/user"
)

// Identity mirrors the fields agent/identity.go's Identity carries that
// EnrollRequest/Heartbeat actually consume -- AgentID is a stable
// hostname-derived value (Phase 1 has no persisted-ID store yet; if a
// stable-across-reinstalls ID is needed later, that's a Phase 2+ decision,
// not blocking Phase 1's enrollment proof).
type Identity struct {
	AgentID   string
	Hostname  string
	IPAddress string
	Username  string
	OSVersion string
}

func buildIdentity() Identity {
	hostname, _ := os.Hostname()
	ip := localIPAddress()
	username := "unknown"
	if u, err := user.Current(); err == nil {
		username = u.Username
	}
	return Identity{
		AgentID:   hostname,
		Hostname:  hostname,
		IPAddress: ip,
		Username:  username,
		OSVersion: getOSVersion(),
	}
}

// localIPAddress mirrors agent/identity.go's approach: dial a well-known
// external address (no packet actually sent for UDP) purely to let the OS
// pick the outbound-routable local address.
func localIPAddress() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
```

- [ ] **Step 9: Run both tests to verify they pass**

```bash
cd agent-legacy && GOTOOLCHAIN=go1.20.14 go test -v .
```

Expected: PASS for both `TestLoadConfig_ReadsFromEnv` and `TestBuildIdentity_PopulatesRequiredFields`.

- [ ] **Step 10: gofmt and commit**

```bash
cd agent-legacy && GOTOOLCHAIN=go1.20.14 gofmt -l .
# fix any files it lists, then:
git add agent-legacy/config.go agent-legacy/identity.go agent-legacy/sysinfo_windows.go \
        agent-legacy/config_test.go agent-legacy/identity_test.go agent-legacy/go.mod agent-legacy/go.sum
git commit -m "feat(agent-legacy): config loading + identity/OS-version reporting"
git push
```

---

### Task 3: Enrollment + heartbeat HTTP client

**Files:**
- Create: `agent-legacy/protocol.go`
- Create: `agent-legacy/client.go`
- Test: `agent-legacy/client_test.go`

**Interfaces:**
- Consumes: `Config` and `Identity` from Task 2.
- Produces: `type EnrollRequest`, `type EnrollResponse`, `type Heartbeat`, `type HeartbeatResponse`, `type PolicyConf` (exact same JSON shape as `agent/types.go`'s equivalents). `func (c *Client) Enroll(id Identity) (EnrollResponse, error)`, `func (c *Client) SendHeartbeat(id Identity, status string) (HeartbeatResponse, error)`, `func NewClient(cfg Config) *Client`. Task 4 consumes `Client.Enroll`/`Client.SendHeartbeat` and `EnrollResponse.State`.

- [ ] **Step 1: Define the protocol structs, matching `agent/types.go` field-for-field**

```go
// agent-legacy/protocol.go
package main

// EnrollRequest matches agent/types.go's EnrollRequest exactly -- this is
// the orchestrator's existing, unmodified /api/agents/enroll contract.
// PostureCatalog is intentionally omitted (nil): Phase 1 ships no posture
// checks, and the server already treats an absent/empty catalog as normal
// (see project note: "catalog harvested at ENROLL", empty is a valid state
// for an agent with nothing to harvest yet).
type EnrollRequest struct {
	AgentID      string `json:"agentId"`
	Hostname     string `json:"hostname"`
	IPAddress    string `json:"ipAddress"`
	OSVersion    string `json:"osVersion"`
	Username     string `json:"username"`
	EnvLabel     string `json:"envLabel"`
	BinaryHash   string `json:"binaryHash,omitempty"`
	AgentVersion string `json:"agentVersion,omitempty"`
}

type EnrollResponse struct {
	AgentID string     `json:"agentId"`
	State   string     `json:"state"`
	Policy  PolicyConf `json:"policy"`
	Trusted bool       `json:"trusted"`
}

type PolicyConf struct {
	LogLevel          string   `json:"logLevel"`
	AllowedScenarios  []string `json:"allowedScenarios"`
	ExecutionWindow   string   `json:"executionWindow"`
	MaxConcurrentRuns int      `json:"maxConcurrentRuns"`
	HeartbeatInterval int      `json:"heartbeatIntervalS"`
}

// Heartbeat matches agent/types.go's Heartbeat -- fields Phase 1 doesn't
// populate yet (SecurityProducts, CurrentJobID, JobProgress) are left at
// their zero value; all are `omitempty` server-side so this is a normal,
// well-formed heartbeat, not a degraded one.
type Heartbeat struct {
	AgentID      string `json:"agentId"`
	Hostname     string `json:"hostname"`
	IPAddress    string `json:"ipAddress"`
	OSVersion    string `json:"osVersion"`
	Username     string `json:"username"`
	Status       string `json:"status"`
	EnvLabel     string `json:"envLabel"`
	BinaryHash   string `json:"binaryHash,omitempty"`
	AgentVersion string `json:"agentVersion,omitempty"`
}

type HeartbeatResponse struct {
	State  string     `json:"state"`
	Policy PolicyConf `json:"policy"`
}
```

- [ ] **Step 2: Write the failing client test (using a local `httptest.Server`, no real orchestrator needed)**

```go
// agent-legacy/client_test.go
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_Enroll_SendsExpectedFieldsAndParsesResponse(t *testing.T) {
	var gotReq EnrollRequest
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agents/enroll" {
			t.Errorf("path = %s, want /api/agents/enroll", r.URL.Path)
		}
		gotToken = r.Header.Get("X-Agent-Token")
		json.NewDecoder(r.Body).Decode(&gotReq)
		json.NewEncoder(w).Encode(EnrollResponse{AgentID: gotReq.AgentID, State: "active", Trusted: false})
	}))
	defer srv.Close()

	c := NewClient(Config{ServerURL: srv.URL, AgentSecret: "s3cr3t", EnvLabel: "Test"})
	id := Identity{AgentID: "test-host", Hostname: "test-host", IPAddress: "10.0.0.5", Username: "svc", OSVersion: "Windows/amd64 (6.1.7601)"}

	resp, err := c.Enroll(id)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if gotToken != "s3cr3t" {
		t.Errorf("X-Agent-Token = %q, want s3cr3t", gotToken)
	}
	if gotReq.AgentID != "test-host" || gotReq.OSVersion != "Windows/amd64 (6.1.7601)" {
		t.Errorf("EnrollRequest sent = %+v, missing expected identity fields", gotReq)
	}
	if resp.State != "active" {
		t.Errorf("State = %q, want active", resp.State)
	}
}

func TestClient_SendHeartbeat_PostsToHeartbeatEndpoint(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewEncoder(w).Encode(HeartbeatResponse{State: "active"})
	}))
	defer srv.Close()

	c := NewClient(Config{ServerURL: srv.URL})
	id := Identity{AgentID: "test-host", Hostname: "test-host"}
	resp, err := c.SendHeartbeat(id, "idle")
	if err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	if gotPath != "/api/heartbeat" {
		t.Errorf("path = %s, want /api/heartbeat", gotPath)
	}
	if resp.State != "active" {
		t.Errorf("State = %q, want active", resp.State)
	}
}
```

- [ ] **Step 3: Run to verify both fail**

```bash
cd agent-legacy && GOTOOLCHAIN=go1.20.14 go test -run TestClient -v .
```

Expected: FAIL (`Client`/`NewClient`/`Enroll`/`SendHeartbeat` not defined).

- [ ] **Step 4: Implement the client**

```go
// agent-legacy/client.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// Client is the legacy agent's HTTP client for enrollment/heartbeat --
// mirrors agent/agent.go's postJSONDecode pattern (X-Agent-Token header
// carries the shared secret; the orchestrator's existing auth middleware
// for these two endpoints is untouched, so this must match it exactly).
type Client struct {
	cfg        Config
	httpClient *http.Client
}

func NewClient(cfg Config) *Client {
	return &Client{cfg: cfg, httpClient: &http.Client{}}
}

func (c *Client) postJSON(path string, body interface{}, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, c.cfg.ServerURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.AgentSecret != "" {
		req.Header.Set("X-Agent-Token", c.cfg.AgentSecret)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server %d on %s", resp.StatusCode, path)
	}
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) Enroll(id Identity) (EnrollResponse, error) {
	req := EnrollRequest{
		AgentID:      id.AgentID,
		Hostname:     id.Hostname,
		IPAddress:    id.IPAddress,
		OSVersion:    id.OSVersion,
		Username:     id.Username,
		EnvLabel:     c.cfg.EnvLabel,
		AgentVersion: agentVersion,
	}
	var resp EnrollResponse
	err := c.postJSON("/api/agents/enroll", req, &resp)
	return resp, err
}

func (c *Client) SendHeartbeat(id Identity, status string) (HeartbeatResponse, error) {
	hb := Heartbeat{
		AgentID:      id.AgentID,
		Hostname:     id.Hostname,
		IPAddress:    id.IPAddress,
		OSVersion:    id.OSVersion,
		Username:     id.Username,
		Status:       status,
		EnvLabel:     c.cfg.EnvLabel,
		AgentVersion: agentVersion,
	}
	var resp HeartbeatResponse
	err := c.postJSON("/api/heartbeat", hb, &resp)
	return resp, err
}

const agentVersion = "1.0.0-legacy"
```

- [ ] **Step 5: Run to verify both pass**

```bash
cd agent-legacy && GOTOOLCHAIN=go1.20.14 go test -v .
```

Expected: PASS for `TestClient_Enroll_SendsExpectedFieldsAndParsesResponse` and `TestClient_SendHeartbeat_PostsToHeartbeatEndpoint`, plus everything from Tasks 1–2 still passing.

- [ ] **Step 6: gofmt and commit**

```bash
cd agent-legacy && GOTOOLCHAIN=go1.20.14 gofmt -l .
git add agent-legacy/protocol.go agent-legacy/client.go agent-legacy/client_test.go
git commit -m "feat(agent-legacy): enrollment + heartbeat HTTP client"
git push
```

---

### Task 4: WS connection loop + main.go entry point

**Files:**
- Create: `agent-legacy/ws.go`
- Create: `agent-legacy/main.go`
- Test: `agent-legacy/ws_test.go`

**Interfaces:**
- Consumes: `Client` from Task 3, `Identity`/`Config` from Task 2.
- Produces: `func connectWS(cfg Config, id Identity)` (blocking reconnect loop). `func main()` wiring config → identity → enroll → heartbeat-ticker goroutine → connectWS. Nothing later in Phase 1 consumes this task's output directly — it's the composition root.

- [ ] **Step 1: Add the `gorilla/websocket` dependency**

```bash
cd agent-legacy
GOTOOLCHAIN=go1.20.14 go get github.com/gorilla/websocket@latest
```

Same caveat as Task 2 Step 5: if `@latest` requires a newer `go` directive than 1.20, pin an explicit older tag and re-run `go mod tidy` until it's clean under the pinned toolchain.

- [ ] **Step 2: Write the failing WS URL-construction test (this is the part worth unit-testing; the actual blocking Dial loop is exercised manually per the plan's Task 7 verification step, not by an automated test)**

```go
// agent-legacy/ws_test.go
package main

import "testing"

func TestBuildWSURL_ConvertsSchemeAndAddsQueryParams(t *testing.T) {
	got := buildWSURL(Config{ServerURL: "http://example.com:9000", AgentSecret: "s3cr3t"}, "agent-1")
	want := "ws://example.com:9000/ws/agent?agentId=agent-1&agentSecret=s3cr3t"
	if got != want {
		t.Errorf("buildWSURL = %q, want %q", got, want)
	}
}

func TestBuildWSURL_HTTPSBecomesWSS(t *testing.T) {
	got := buildWSURL(Config{ServerURL: "https://example.com:9443"}, "agent-1")
	want := "wss://example.com:9443/ws/agent?agentId=agent-1"
	if got != want {
		t.Errorf("buildWSURL = %q, want %q", got, want)
	}
}
```

- [ ] **Step 3: Run to verify it fails**

```bash
cd agent-legacy && GOTOOLCHAIN=go1.20.14 go test -run TestBuildWSURL -v .
```

Expected: FAIL (`buildWSURL` not defined).

- [ ] **Step 4: Implement `buildWSURL` and the connection loop**

```go
// agent-legacy/ws.go
package main

import (
	"encoding/json"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	wsReconnectDelay = 5 * time.Second
	wsPongWait       = 60 * time.Second
	wsWriteWait      = 10 * time.Second
)

// buildWSURL mirrors agent/agent.go's connectWS URL construction exactly --
// same query param names (agentId, agentSecret), same http->ws / https->wss
// scheme swap, so the orchestrator's WS handshake auth sees an identical
// request shape regardless of which agent connected.
func buildWSURL(cfg Config, agentID string) string {
	raw := strings.Replace(cfg.ServerURL, "http://", "ws://", 1)
	raw = strings.Replace(raw, "https://", "wss://", 1)
	u, err := url.Parse(raw + "/ws/agent")
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("agentId", agentID)
	if cfg.AgentSecret != "" {
		q.Set("agentSecret", cfg.AgentSecret)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// connectWS blocks forever, reconnecting on any failure. Phase 1 has no
// scenario/simulate command handlers yet -- an inbound WSMessage is parsed
// only far enough to log its type, proving the wire format round-trips
// correctly; actual command dispatch is Phase 2/3 scope once there's
// something on the legacy agent capable of executing a command.
func connectWS(cfg Config, id Identity) {
	wsURL := buildWSURL(cfg, id.AgentID)
	for {
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			log.Printf("[!] WS connect failed: %v -- retry in 5s", err)
			time.Sleep(wsReconnectDelay)
			continue
		}
		log.Printf("[+] WS connected: %s", wsURL)

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
				log.Printf("[!] WS read: %v -- reconnecting", err)
				conn.Close()
				break
			}
			conn.SetReadDeadline(time.Now().Add(wsPongWait))
			var msg struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(data, &msg); err == nil {
				log.Printf("[*] WS message received: type=%s (no handler yet -- Phase 1)", msg.Type)
			}
		}
	}
}
```

```go
// agent-legacy/main.go
package main

import (
	"log"
	"time"
)

const heartbeatInterval = 30 * time.Second

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	log.Printf("[*] Audspect Legacy Windows Agent v%s starting", agentVersion)

	cfg := loadConfig()
	if cfg.ServerURL == "" {
		log.Fatal("[!] BAS_SERVER_URL is not set")
	}
	id := buildIdentity()
	log.Printf("[*] identity: host=%s os=%s", id.Hostname, id.OSVersion)

	client := NewClient(cfg)
	resp, err := client.Enroll(id)
	if err != nil {
		log.Printf("[!] enrollment failed: %v -- continuing; will retry on next heartbeat", err)
	} else {
		log.Printf("[+] enrolled -- state=%s trusted=%v", resp.State, resp.Trusted)
	}

	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for range ticker.C {
			if _, err := client.SendHeartbeat(id, "idle"); err != nil {
				log.Printf("[!] heartbeat failed: %v", err)
			}
		}
	}()

	connectWS(cfg, id)
}
```

- [ ] **Step 5: Run to verify the URL tests pass**

```bash
cd agent-legacy && GOTOOLCHAIN=go1.20.14 go test -v .
```

Expected: PASS for `TestBuildWSURL_ConvertsSchemeAndAddsQueryParams` and `TestBuildWSURL_HTTPSBecomesWSS`, plus every earlier task's tests.

- [ ] **Step 6: Verify the whole module builds for the real target**

```bash
cd agent-legacy
GOTOOLCHAIN=go1.20.14 GOOS=windows GOARCH=amd64 go build -o /tmp/bas-agent-legacy-windows-amd64.exe .
GOTOOLCHAIN=go1.20.14 go version # sanity check it's still go1.20.14 in this shell
```

Expected: builds cleanly, no errors. This is the first point in the plan where the actual target artifact exists.

- [ ] **Step 7: gofmt and commit**

```bash
cd agent-legacy && GOTOOLCHAIN=go1.20.14 gofmt -l .
git add agent-legacy/ws.go agent-legacy/main.go agent-legacy/ws_test.go agent-legacy/go.mod agent-legacy/go.sum
git commit -m "feat(agent-legacy): WS connection loop + main entry point"
git push
```

---

### Task 5: Windows service install/uninstall

**Files:**
- Create: `agent-legacy/service_windows.go`
- Modify: `agent-legacy/main.go` (add `--install`/`--uninstall` flags)
- Test: manual only (installing a Windows service cannot be meaningfully unit-tested — see spec's Testing section)

**Interfaces:**
- Consumes: `Config` from Task 2, `agentVersion` const from Task 3.
- Produces: `func svcInstall(serverURL, envLabel, secret string) error`, `func svcUninstall() error`, `func svcRun() error`, `func isWindowsService() bool`. `main()` (modified) branches on `--install`/`--uninstall` flags before falling into the normal enroll/heartbeat/WS flow.

- [ ] **Step 1: Read `agent/service.go` in full before writing this file**

This task deliberately has no failing-test step first — Windows service registration APIs (`svc.Install`, `mgr.Connect`) only function when actually running on Windows with appropriate privileges, so there is no meaningful host-independent unit test to write. Read `agent/service.go`'s `svcInstall`/`svcUninstall`/`svcRun`/`isWindowsService` functions completely before starting this task; they are the pattern to follow.

- [ ] **Step 2: Implement service registration**

```go
// agent-legacy/service_windows.go
//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "BASLegacyAgent"

type legacySvc struct{}

func (s *legacySvc) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	stop := make(chan struct{})
	go func() {
		cfg := loadConfig()
		id := buildIdentity()
		client := NewClient(cfg)
		client.Enroll(id)
		go func() {
			for range tickerChan(heartbeatInterval) {
				client.SendHeartbeat(id, "idle")
			}
		}()
		connectWS(cfg, id)
	}()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		req := <-r
		switch req.Cmd {
		case svc.Stop, svc.Shutdown:
			close(stop)
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
}

func isWindowsService() bool {
	isSvc, err := svc.IsWindowsService()
	return err == nil && isSvc
}

func svcRun() error {
	elog, err := eventlog.Open(serviceName)
	if err == nil {
		defer elog.Close()
	}
	return svc.Run(serviceName, &legacySvc{})
}

func svcInstall(serverURL, envLabel, secret string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	os.Setenv("BAS_SERVER_URL", serverURL)
	os.Setenv("BAS_ENV_LABEL", envLabel)
	os.Setenv("BAS_AGENT_SECRET", secret)

	s, err := m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName: "Audspect Legacy Windows Agent",
		StartType:   mgr.StartAutomatic,
		Description: "Audspect BAS legacy Windows compatibility agent",
	})
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()
	return s.Start()
}

func svcUninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()
	s.Control(svc.Stop)
	return s.Delete()
}
```

Note: `tickerChan` is a small helper (`func tickerChan(d time.Duration) <-chan time.Time { return time.NewTicker(d).C }`) — add it to `ws.go` or inline a `time.NewTicker(heartbeatInterval).C` directly in `Execute` instead if that reads more cleanly; either is fine, this plan doesn't prescribe which.

- [ ] **Step 3: Wire `--install`/`--uninstall` flags into `main.go`**

```go
// agent-legacy/main.go -- replace the body of main() with:
func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)

	flagInstall := flag.Bool("install", false, "Install agent as a Windows service (requires Administrator)")
	flagUninstall := flag.Bool("uninstall", false, "Uninstall agent Windows service")
	flagServer := flag.String("server", "", "Override BAS_SERVER_URL")
	flagEnv := flag.String("env", "Production", "Override BAS_ENV_LABEL")
	flagSecret := flag.String("secret", "", "Agent shared secret")
	flag.Parse()

	if *flagInstall {
		serverURL := *flagServer
		if serverURL == "" {
			serverURL = os.Getenv("BAS_SERVER_URL")
		}
		if err := svcInstall(serverURL, *flagEnv, *flagSecret); err != nil {
			log.Fatalf("[!] service install failed: %v", err)
		}
		log.Println("[+] service installed and started")
		return
	}
	if *flagUninstall {
		if err := svcUninstall(); err != nil {
			log.Fatalf("[!] service uninstall failed: %v", err)
		}
		log.Println("[+] service uninstalled")
		return
	}
	if isWindowsService() {
		if err := svcRun(); err != nil {
			log.Fatalf("[!] service run failed: %v", err)
		}
		return
	}

	log.Printf("[*] Audspect Legacy Windows Agent v%s starting", agentVersion)
	cfg := loadConfig()
	if cfg.ServerURL == "" {
		log.Fatal("[!] BAS_SERVER_URL is not set")
	}
	id := buildIdentity()
	log.Printf("[*] identity: host=%s os=%s", id.Hostname, id.OSVersion)

	client := NewClient(cfg)
	resp, err := client.Enroll(id)
	if err != nil {
		log.Printf("[!] enrollment failed: %v -- continuing; will retry on next heartbeat", err)
	} else {
		log.Printf("[+] enrolled -- state=%s trusted=%v", resp.State, resp.Trusted)
	}

	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for range ticker.C {
			if _, err := client.SendHeartbeat(id, "idle"); err != nil {
				log.Printf("[!] heartbeat failed: %v", err)
			}
		}
	}()

	connectWS(cfg, id)
}
```

Add `"flag"` and `"os"` to `main.go`'s imports.

- [ ] **Step 4: Verify the module still builds for Windows**

```bash
cd agent-legacy
GOTOOLCHAIN=go1.20.14 GOOS=windows GOARCH=amd64 go build -o /tmp/bas-agent-legacy-windows-amd64.exe .
```

Expected: builds cleanly.

- [ ] **Step 5: Run the full test suite (Windows-only files won't compile/run on a non-Windows dev machine — that's expected; run what the host can run)**

```bash
cd agent-legacy && GOTOOLCHAIN=go1.20.14 go test -v .
```

Expected: all tests from Tasks 1-4 still PASS.

- [ ] **Step 6: gofmt and commit**

```bash
cd agent-legacy && GOTOOLCHAIN=go1.20.14 gofmt -l .
git add agent-legacy/service_windows.go agent-legacy/main.go agent-legacy/go.mod agent-legacy/go.sum
git commit -m "feat(agent-legacy): Windows service install/uninstall"
git push
```

- [ ] **Step 7: MANUAL — verify service install/enroll/heartbeat on a real legacy VM**

There is no Windows 7/2008R2 CI runner. On a Windows 7 SP1 (or Server 2008 R2) VM, with the orchestrator reachable:

```powershell
$env:BAS_SERVER_URL = "http://<orchestrator-host>:9000"
.\bas-agent-legacy-windows-amd64.exe --install --server $env:BAS_SERVER_URL --secret <AGENT_SECRET> --env Production
```

Confirm: the service starts (`Get-Service BASLegacyAgent`), the agent appears in the console's Agents list within ~30s, its OS Version shows the real legacy build number (not a Windows 8 compatibility-shim value), and it keeps sending heartbeats (state stays "active", not stale). This step cannot be skipped or deferred — it's the actual proof this phase exists to establish.

---

### Task 6: `scripts/build-agent-legacy.ps1` — standalone dev build script

**Files:**
- Create: `scripts/build-agent-legacy.ps1`

**Interfaces:**
- Consumes: the `agent-legacy/` module from Tasks 1-5.
- Produces: `ag-legacy\bas_agent_legacy.exe` for local manual testing. No later task consumes this script programmatically — it's a developer convenience mirroring `scripts/build-agent.ps1`'s existing role for the modern agent.

- [ ] **Step 1: Write the script**

```powershell
# scripts/build-agent-legacy.ps1
param(
    [string]$OutDir = "ag-legacy"
)

Write-Host "[*] Building BAS Legacy Windows Agent..."

Push-Location "$PSScriptRoot\..\agent-legacy"

$env:GOTOOLCHAIN = "go1.20.14"

Write-Host "[*] Fetching dependencies..."
go mod tidy
if ($LASTEXITCODE -ne 0) { Write-Host "[!] go mod tidy failed"; Pop-Location; exit 1 }

# Hard assertion, not a log line: a silently-wrong toolchain here produces a
# binary linked against a runtime newer than the legacy OSes actually
# support, defeating the entire point of this build. See
# docs/superpowers/specs/2026-08-18-legacy-windows-agent-phase1-design.md.
$goVersionOutput = (go version)
Write-Host "[*] Resolved toolchain: $goVersionOutput"
if ($goVersionOutput -notmatch "go1\.20\.14") {
    Write-Host "[!] Wrong toolchain resolved. Expected go1.20.14, got: $goVersionOutput"
    Write-Host "[!] Check that GOTOOLCHAIN=go1.20.14 is actually set -- go.mod must NOT have a toolchain directive (go1.20.14 can't parse that syntax)."
    Pop-Location
    exit 1
}

$env:GOOS   = "windows"
$env:GOARCH = "amd64"
$outPath = "..\$OutDir\bas_agent_legacy.exe"

Write-Host "[*] Compiling..."
go build -ldflags="-s -w -H windowsgui" -o $outPath .
if ($LASTEXITCODE -ne 0) { Write-Host "[!] Build failed"; Pop-Location; exit 1 }

Pop-Location

$size = [math]::Round((Get-Item "$PSScriptRoot\..\$OutDir\bas_agent_legacy.exe").Length / 1MB, 1)
Write-Host "[+] Built: $OutDir\bas_agent_legacy.exe ($size MB)"
Write-Host ""
Write-Host "Deploy to a Windows 7 SP1 / Server 2008 R2+ test VM:"
Write-Host "  1. Copy bas_agent_legacy.exe to the VM"
Write-Host "  2. Open an elevated command prompt"
Write-Host "  3. bas_agent_legacy.exe --install --server http://<host>:9000 --secret <SECRET>"
```

- [ ] **Step 2: Run it and confirm the artifact is produced**

```powershell
.\scripts\build-agent-legacy.ps1
```

Expected: `[+] Built: ag-legacy\bas_agent_legacy.exe (N MB)` with no toolchain-mismatch error.

- [ ] **Step 3: Commit**

```bash
git add scripts/build-agent-legacy.ps1
git commit -m "build(agent-legacy): add standalone dev build script with verified toolchain pinning"
git push
```

---

### Task 7: Backend — `agentFiles` map entries + download test

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (the `agentFiles` map, currently ~line 792-805)
- Modify: `orchestrator/internal/api/download_agent_test.go`

**Interfaces:**
- Consumes: nothing from Go code (the map is a static allowlist).
- Produces: `agentFiles["windows-legacy-amd64"]` and `agentFiles["windows-legacy-amd64-setup"]`, servable via the existing `GET /api/agents/download/{platform}` route with zero handler-logic changes.

- [ ] **Step 1: Read the existing `TestDownloadAgent_SuccessPath` test in full**

Open `orchestrator/internal/api/download_agent_test.go` and read `TestDownloadAgent_SuccessPath` completely — it's the exact pattern the new test below mirrors (how it stages a fake file on disk, what it asserts about status/headers/body).

- [ ] **Step 2: Write the failing test**

Add to `orchestrator/internal/api/download_agent_test.go`, following the exact staging pattern `TestDownloadAgent_SuccessPath` uses (same temp-dir/env-var setup):

```go
func TestDownloadAgent_WindowsLegacyPlatform_KnownButFileMissing(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, testJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req = withURLParam(req, "platform", "windows-legacy-amd64")
	rec := httptest.NewRecorder()
	h.DownloadAgent(rec, req)
	// Platform IS recognized (not 404 "unknown platform") -- it's the
	// backing file that's absent in this bare-handler test, same distinction
	// TestDownloadAgent_KnownPlatformNoFilePresent already draws for
	// windows-amd64. A 404 here with "unknown platform" in the body would
	// mean the agentFiles map entry is missing; any other outcome
	// (including a different-flavored error about the missing file) proves
	// the map entry exists.
	if rec.Code == http.StatusNotFound && strings.Contains(rec.Body.String(), "unknown platform") {
		t.Fatalf("windows-legacy-amd64 not recognized as a platform: %s", rec.Body.String())
	}
}
```

Check `download_agent_test.go`'s imports for `strings` — add it if not already present.

- [ ] **Step 3: Run to verify it fails**

```bash
cd orchestrator && go test ./internal/api/... -run TestDownloadAgent_WindowsLegacyPlatform -v
```

Expected: FAIL (`windows-legacy-amd64` not in `agentFiles`, so the handler currently returns the "unknown platform" 404 the test explicitly rejects).

- [ ] **Step 4: Add the map entries**

```go
// orchestrator/internal/api/handlers.go -- inside the agentFiles map literal,
// immediately after the existing "windows-amd64" entry:
	"windows-legacy-amd64-setup": {"bas-agent-windows-legacy-amd64-setup.zip", "application/zip"},
	"windows-legacy-amd64":       {"bas-agent-windows-legacy-amd64.exe", "application/octet-stream"},
```

- [ ] **Step 5: Run to verify it passes**

```bash
cd orchestrator && go test ./internal/api/... -run TestDownloadAgent -v
```

Expected: PASS for the new test and every existing `TestDownloadAgent_*` test.

- [ ] **Step 6: Run the full `internal/api` suite (background — this package takes 8-15 minutes)**

```bash
cd orchestrator && go test ./internal/api/... > /tmp/legacy-agent-task7.log 2>&1 &
```

Wait for completion, then confirm the log ends with `ok` for `github.com/audspect/bas/internal/api`, not `FAIL`.

- [ ] **Step 7: gofmt and commit**

```bash
cd orchestrator && gofmt -l internal/api/handlers.go internal/api/download_agent_test.go
git add internal/api/handlers.go internal/api/download_agent_test.go
git commit -m "feat(agents): add windows-legacy-amd64 download platform entries"
git push
```

---

### Task 8: Docker multi-stage build — legacy builder stage + combined manifest

**Files:**
- Modify: `orchestrator/Dockerfile`

**Interfaces:**
- Consumes: `agent-legacy/` module (Tasks 1-5).
- Produces: `/agents/bas-agent-windows-legacy-amd64.exe` and `/agents/bas-agent-windows-legacy-amd64-setup.zip` inside the final orchestrator image, plus their entries in the same `BINARIES.sha256` the modern binaries are hashed into — this is what Task 7's `agentFiles` map entries actually serve at runtime.

**Read first:** the current `Dockerfile`'s `agent-builder` stage (lines ~23-57) builds all modern-agent platform binaries and generates `BINARIES.sha256` in one `RUN` step scoped to that stage's own `/agents` output. The final image (`FROM gcr.io/distroless/static-debian12`, near the bottom) does `COPY --from=agent-builder /agents /agents`. Adding a second, independently-toolchained builder stage means `BINARIES.sha256` can no longer be generated inside `agent-builder` alone — it needs both stages' binaries present at hash time.

- [ ] **Step 1: Add the `agent-legacy-builder` stage, immediately after the existing `agent-builder` stage**

```dockerfile
# ── Legacy Windows Agent Builder ─────────────────────────────────────────────
# Separately toolchained via GOTOOLCHAIN=go1.20.14 (go.mod itself stays at a
# bare `go 1.20` -- the `toolchain` directive predates Go 1.21 and go1.20.14
# can't parse it). go1.20.14 is the
# last Go release supporting Windows 7 SP1/8/8.1/Server 2008 R2-2012 R2.
# GOTOOLCHAIN is set explicitly (not relying on the base image's own `go`
# binary) so this stage is correct even if the base image's Go version ever
# changes independently of agent-legacy/go.mod's pin.
FROM golang:1.26-alpine AS agent-legacy-builder
RUN apk add --no-cache git zip
WORKDIR /agent-legacy
COPY agent-legacy/go.mod agent-legacy/go.sum ./
ENV GOTOOLCHAIN=go1.20.14
RUN go mod download
COPY agent-legacy/ .
# Hard assertion: fail the image build outright if the resolved toolchain
# isn't exactly go1.20.14, rather than silently shipping a binary built
# against a newer runtime than the legacy OSes this agent targets support.
RUN GOVERSION=$(go version) && \
    echo "Resolved toolchain: $GOVERSION" && \
    case "$GOVERSION" in \
      *go1.20.14*) ;; \
      *) echo "FATAL: expected go1.20.14, got: $GOVERSION" >&2; exit 1 ;; \
    esac
RUN CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /agents-legacy/bas-agent-windows-legacy-amd64.exe .
RUN cd /agents-legacy && zip -q bas-agent-windows-legacy-amd64-setup.zip bas-agent-windows-legacy-amd64.exe
```

(Note: Phase 1's legacy agent has no separate installer wrapper the way the modern agent does via `installer/` — the setup zip here just wraps the standalone exe for now. If Phase 1's manual VM testing in Task 5 Step 7 shows operators genuinely need an install wizard rather than the CLI `--install` flag, that's a follow-up, not a Phase 1 blocker.)

- [ ] **Step 2: Combine both stages' hashes into one `BINARIES.sha256`, replacing the existing single-stage hash step**

The existing `RUN cd /agents && sha256sum ... > /agents/BINARIES.sha256` step (inside `agent-builder`) only has access to that stage's own files. Move manifest generation to a new, minimal stage that can `COPY --from=` both builders:

```dockerfile
# ── Combined Binary Manifest ─────────────────────────────────────────────────
# Must run after BOTH agent-builder and agent-legacy-builder so the manifest
# covers every binary an endpoint can download -- generated from a single
# COPY of each stage's real output, not duplicated/recomputed elsewhere, so
# the hashes always match what's actually shipped.
FROM alpine AS binaries-manifest
RUN mkdir /agents
COPY --from=agent-builder /agents/bas-agent-linux-amd64 /agents/bas-agent-linux-arm64 \
     /agents/bas-agent-windows-amd64.exe /agents/bas-agent-darwin-amd64 /agents/bas-agent-darwin-arm64 \
     /agents/
COPY --from=agent-legacy-builder /agents-legacy/bas-agent-windows-legacy-amd64.exe /agents/
RUN cd /agents && sha256sum \
      bas-agent-linux-amd64 bas-agent-linux-arm64 bas-agent-windows-amd64.exe \
      bas-agent-darwin-amd64 bas-agent-darwin-arm64 bas-agent-windows-legacy-amd64.exe \
    > /agents/BINARIES.sha256
```

Remove the old `RUN cd /agents && sha256sum ... > /agents/BINARIES.sha256` step from inside `agent-builder` (lines ~37-42 currently) — it's now redundant with (and would conflict/be overwritten by) this new stage's output.

- [ ] **Step 3: Update the final image's `COPY` steps to pull from the new manifest stage and the legacy builder**

Find the final `FROM gcr.io/distroless/static-debian12` stage's existing lines:
```dockerfile
COPY --from=agent-builder /agents /agents
```
Replace with:
```dockerfile
COPY --from=binaries-manifest /agents/BINARIES.sha256 /agents/BINARIES.sha256
COPY --from=agent-builder /agents /agents
COPY --from=agent-legacy-builder /agents-legacy/bas-agent-windows-legacy-amd64.exe /agents/bas-agent-windows-legacy-amd64.exe
COPY --from=agent-legacy-builder /agents-legacy/bas-agent-windows-legacy-amd64-setup.zip /agents/bas-agent-windows-legacy-amd64-setup.zip
```
(The `agent-builder` copy still brings in its own now-stale `BINARIES.sha256` if that stage's old hash step wasn't removed in Step 2 — confirm it was removed, so the only `BINARIES.sha256` present is the combined one copied first from `binaries-manifest`, and it isn't overwritten by a second `COPY --from=agent-builder` bringing back a partial one.)

- [ ] **Step 4: Build the image locally and verify all six files + one combined manifest are present**

```bash
docker build -t bas-orchestrator:legacy-test -f orchestrator/Dockerfile .
docker create --name legacy-test-check bas-orchestrator:legacy-test
docker cp legacy-test-check:/agents /tmp/agents-check
docker rm legacy-test-check
ls /tmp/agents-check
cat /tmp/agents-check/BINARIES.sha256
```

Expected: `/tmp/agents-check` contains `bas-agent-linux-amd64`, `bas-agent-linux-arm64`, `bas-agent-windows-amd64.exe`, `bas-agent-darwin-amd64`, `bas-agent-darwin-arm64`, `bas-agent-windows-legacy-amd64.exe`, `bas-agent-windows-legacy-amd64-setup.zip`, and `BINARIES.sha256` with exactly six hash lines (the setup zip is not itself hashed into `BINARIES.sha256`, matching how `bas-agent-windows-amd64-setup.zip` isn't hashed today either — confirm this against the current file's actual six-vs-more-line count before assuming).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/Dockerfile
git commit -m "build(docker): add legacy Windows agent builder stage + combined BINARIES.sha256"
git push
```

---

### Task 9: `packaging/windows-build.ps1` — client-delivery bundle stage

**Files:**
- Modify: `packaging/windows-build.ps1` (new stage inserted after the existing "-- 5a. Build Windows agent binary + installer EXE --" section, before "-- 5b. Build Linux agent binaries --")

**Interfaces:**
- Consumes: `agent-legacy/` module (Tasks 1-5). This stage's output isn't consumed by anything else in this plan — it's a sibling artifact in the same `dist\bas-install-<version>\` folder the modern agent's standalone binary already lands in.

- [ ] **Step 1: Insert the new stage**

In `packaging/windows-build.ps1`, after the existing standalone-Windows-agent block (ends around the line building `$OutDir\bas-agent-windows-amd64.exe`, just before the `# -- 5b. Build Linux agent binaries --` comment), insert:

```powershell
# -- 5a2. Build Legacy Windows agent binary (amd64 only) ---------------------
# Separately toolchained via GOTOOLCHAIN=go1.20.14 (go.mod itself stays at a
# bare `go 1.20` -- the `toolchain` directive predates Go 1.21 and go1.20.14
# can't parse it). go1.20.14 is the
# last Go release supporting Windows 7 SP1/8/8.1/Server 2008 R2-2012 R2. See
# docs/superpowers/specs/2026-08-18-legacy-windows-agent-phase1-design.md.
Log "Building Legacy Windows agent binary (go1.20.14, amd64 only)..."
$LegacyAgentDir = Join-Path $RepoRoot "agent-legacy"
Push-Location $LegacyAgentDir
$env:GOTOOLCHAIN = "go1.20.14"
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"

$legacyGoVersion = (go version)
Log "  Resolved toolchain: $legacyGoVersion"
if ($legacyGoVersion -notmatch "go1\.20\.14") {
    Pop-Location
    Err "Legacy agent toolchain mismatch. Expected go1.20.14, got: $legacyGoVersion"
}

go build -trimpath -ldflags="-s -w" -o "$OutDir\bas-agent-windows-legacy-amd64.exe" . 2>&1
if ($LASTEXITCODE -ne 0) {
    Warn "Legacy Windows agent build failed."
} else {
    $legacySizeMB = [math]::Round((Get-Item "$OutDir\bas-agent-windows-legacy-amd64.exe").Length / 1MB, 1)
    Log "  bas-agent-windows-legacy-amd64.exe (${legacySizeMB}MB)"
}
Compress-Archive -Path "$OutDir\bas-agent-windows-legacy-amd64.exe" -DestinationPath "$OutDir\bas-agent-windows-legacy-amd64-setup.zip" -Force

$env:GOTOOLCHAIN = ""; $env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""
Pop-Location
```

- [ ] **Step 2: Verify the whole packager script still runs end-to-end**

```powershell
.\packaging\windows-build.ps1 -Version 0.0.0-test -SkipBuild
```

(`-SkipBuild` reuses the already-existing Docker image from Task 8's manual test rather than rebuilding it, since this step is only verifying the legacy-agent PowerShell stage itself, not re-testing the whole Docker pipeline.) Confirm `dist\bas-install-0.0.0-test\bas-agent-windows-legacy-amd64.exe` and its `-setup.zip` exist afterward, with no `GOTOOLCHAIN mismatch` error in the output.

- [ ] **Step 3: Commit**

```bash
git add packaging/windows-build.ps1
git commit -m "build(packaging): build legacy Windows agent binary in client-delivery bundle"
git push
```

---

### Task 10: Frontend — Legacy Windows Agent card

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (Deploy Agent section, currently ~line 1819-1856 for the featured Windows card, ~1858 onward for the plain `.agent-dl-card` grid)

**Interfaces:**
- Consumes: `GET /api/agents/download/windows-legacy-amd64` and `GET /api/agents/download/windows-legacy-amd64-setup` from Task 7.

- [ ] **Step 1: Read the existing Linux card's markup in full (the exact `.agent-dl-card` structure to mirror) and the featured Windows card's placement, to confirm current line numbers before editing**

- [ ] **Step 2: Add the new card, in the `.agent-dl-grid` alongside Linux/macOS, immediately after the closing tag of the featured Windows card and before the Linux/macOS grid's own opening tag (so it visually sits directly beneath/alongside the primary Windows card per the original request)**

```html
<!-- Windows (Legacy) -->
<div class="agent-dl-card">
  <div class="agent-dl-os">
    <svg viewBox="0 0 24 24" fill="currentColor" width="26" height="26"><path d="M3 5.5h8v-2H3v2zm0 5h8v-2H3v2zm0 5h8v-2H3v2zm10-10h8v-2h-8v2zm0 5h8v-2h-8v2zm0 5h8v-2h-8v2z"/></svg>
    Windows (Legacy)
  </div>
  <div class="agent-dl-btns">
    <a class="btn btn-sm btn-outline" href="/api/agents/download/windows-legacy-amd64-setup" download="bas-agent-windows-legacy-amd64-setup.zip">Setup .zip</a>
    <a class="btn btn-sm btn-outline" href="/api/agents/download/windows-legacy-amd64" download="bas-agent-windows-legacy-amd64.exe">CLI Binary</a>
  </div>
  <div class="agent-dl-hint">Windows 7 SP1 / 8 / 8.1 / Server 2008 R2 &ndash; 2012 R2 (x64 only) &mdash; reduced capability, see compatibility notes below</div>
  <div class="agent-dl-usage" style="margin-bottom:0">
    <strong>Install:</strong>
    <code id="win-legacy-cli-cmd">bas-agent-windows-legacy-amd64.exe --install --server &lt;URL&gt; --secret &lt;SECRET&gt; --env Production</code>
    <div style="margin-top:0.4rem;font-size:0.7rem">This is a compatibility agent, not a full-featured build: enrollment, health/status, and (in later releases) core inventory/posture checks only. Advanced telemetry and Windows-10+-only capabilities are not available on these OS versions. <a href="https://github.com/audspect/bas/blob/main/agent-legacy/CAPABILITY_MATRIX.md" style="color:var(--muted);text-decoration:underline" target="_blank" rel="noopener">Compatibility matrix</a></div>
  </div>
</div>
```

(Confirm the actual capability-matrix link target once the repo's real hosting/visibility for `agent-legacy/CAPABILITY_MATRIX.md` is known at implementation time — if the console has no way to serve raw repo files to an operator, link to wherever the matrix is actually published instead, e.g. a docs page; don't ship a link that 404s.)

- [ ] **Step 3: Verify the file's JS is still syntactically valid (this file has one giant inline `<script>` block; adding HTML doesn't touch JS, but confirm nothing was accidentally clipped mid-edit)**

```bash
node -e "
const fs = require('fs');
const html = fs.readFileSync('orchestrator/wwwroot/index.html', 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
try { new Function(scripts.join('\n;\n')); console.log('SYNTAX_OK'); }
catch (e) { console.log('SYNTAX_ERROR:', e.message); }
"
```

Expected: `SYNTAX_OK`.

- [ ] **Step 4: Manual visual check** — open the console's Agents page in a browser (or via a screenshot tool), confirm the new card renders in the grid, download links resolve (once Task 7/8 are deployed), and it visually reads as secondary/compatibility-tier next to the featured modern card, not competing with it for attention.

- [ ] **Step 5: Commit**

```bash
cd orchestrator && git add wwwroot/index.html
git commit -m "feat(ui): add Windows Agent (Legacy) download card to Deploy Agent section"
git push
```

---

## Self-Review Notes (from the plan-writer's own pass)

- **Spec coverage:** every Phase-1 bullet in the spec's "Phase 1 Scope" section maps to a task: build/toolchain (Tasks 1, 6, 8, 9), enroll (Task 3-4), install as service (Task 5), heartbeat (Task 3-4), console visibility (Task 4's OS-version reporting + Task 10's card), release pipeline (Tasks 7-9).
- **Explicitly NOT done here, matching the spec's deferrals:** no collector, no ART/BAS content, no compatibility-gating logic, no 32-bit build target anywhere in any task.
- **Toolchain verification is enforced at three independent layers** (module test in Task 1, dev build script in Task 6, Docker build stage in Task 8, client-delivery script in Task 9) — deliberately redundant, since a silent toolchain drift in any one of these paths would undermine the entire premise of the phase.
