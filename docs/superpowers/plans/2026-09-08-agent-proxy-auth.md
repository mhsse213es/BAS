# Agent Outbound Proxy Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The agent's outbound WebSocket connection to the orchestrator succeeds through an authenticating forward proxy requiring NTLM (Windows) or HTTP Basic (any platform), and fails with a diagnostic message (not a generic error) when it can't.

**Architecture:** A new `NetDialContext` hook, injected into a `*websocket.Dialer` the agent constructs itself (replacing `websocket.DefaultDialer`), owns the entire proxy `CONNECT` negotiation: unauthenticated attempt first, then NTLM via Windows SSPI (agent's own service identity, no stored password) if offered and available, then HTTP Basic via a proper `407`-retry with securely-stored credentials as fallback. Everything above the TCP-establishment layer (gorilla's TLS handshake, the WS upgrade, `connectWS()`'s outer reconnect loop) is unchanged.

**Tech Stack:** Go, `gorilla/websocket` (existing dependency), `github.com/alexbrainman/sspi` (new dependency, Windows SSPI/NTLM wrapper), standard library only otherwise.

**Spec:** `docs/superpowers/specs/2026-09-08-agent-proxy-auth-design.md`

## Global Constraints

- **Kerberos/Negotiate proxy auth is out of scope.** Do not add it.
- **NTLM is Windows-only.** Non-Windows platforms get the Basic-via-407 fix only.
- **`agent/protocol.DialAgentWS`'s existing signature must not change** — it is shared with `orchestrator/cmd/loadgen/agent.go`, a separate module that has no need for proxy-auth support. Add a new function instead; make `DialAgentWS` a thin wrapper over it.
- **No new install-time CLI flags in this pass.** Proxy credentials are configured the same way `AgentSecret` already supports operator override: `BAS_PROXY_USER`/`BAS_PROXY_PASSWORD` environment variables (checked first, works immediately, zero new code needed to use it), falling back to platform-secure storage (Windows: DPAPI registry; POSIX: the existing `EnvironmentFile=` config file) as the durable path. Wiring a `--proxy-user`/`--proxy-password` install flag is an explicit fast-follow, not required by any of the spec's 5 success criteria.
- **Lockout-aware backoff ceiling: exactly 30 minutes** (`proxyAuthBackoffMax = 30 * time.Minute`), reusing the existing exponential-with-full-jitter shape (`wsBackoffDelay`/`wsJitter` pattern in `agent/backoff.go`) with only the ceiling changed. Only a **confirmed-rejected** credential (a `407`/`403` *after* a completed NTLM or Basic attempt) uses this; the initial unauthenticated `407` and any other failure keep using the existing 120s `wsBackoffMax`.
- **NTLM-vs-Basic priority:** if a proxy offers both and we're on Windows, attempt NTLM first (needs no stored credential). If the SSPI handshake itself errors out before completing (a hard negotiation failure, not a completed-and-rejected attempt), that failure uses the **standard** backoff, not the lockout-aware one, and does **not** fall back to Basic within the same connection attempt — the next reconnect cycle tries NTLM again first.
- **Operational caveat, not a defect:** the Windows agent service runs as `LocalSystem` (confirmed in `agent/service.go`'s `mgr.Config{ServiceStartName: "LocalSystem", ...}`). SSPI/NTLM under `LocalSystem` authenticates to the network as the machine's own domain computer account (`DOMAIN\COMPUTERNAME$`), not a named user. A proxy ACL scoped to specific user accounts only (not machine accounts) will reject this even though the NTLM negotiation itself completes mechanically — that's a legitimate "confirmed rejected" outcome the lockout-aware backoff already handles correctly, not a bug to fix here.

---

## Task 1: Lockout-aware backoff

**Files:**
- Modify: `agent/backoff.go`
- Test: `agent/backoff_test.go`

**Interfaces:**
- Produces: `const proxyAuthBackoffMax = 30 * time.Minute`; `func wsBackoffDelayCapped(attempt int, max time.Duration) time.Duration`; `func wsProxyAuthReconnectBackoff(attempt int) time.Duration` — Task 5 selects between `wsReconnectBackoff` (existing) and this one based on whether the dial error is a confirmed credential rejection.
- Consumes: nothing new (this task only touches `agent/backoff.go`, self-contained).

This task is fully independent of every other task — start here.

- [ ] **Step 1: Write the failing tests**

Append to `agent/backoff_test.go`:

```go
func TestWsBackoffDelayCapped_UsesGivenCeiling(t *testing.T) {
	cases := []struct {
		attempt int
		max     time.Duration
		want    time.Duration
	}{
		{0, 5 * time.Second, 1 * time.Second},
		{1, 5 * time.Second, 2 * time.Second},
		{2, 5 * time.Second, 4 * time.Second},
		{3, 5 * time.Second, 5 * time.Second}, // 8s would exceed the 5s cap
		{100, 5 * time.Second, 5 * time.Second},
	}
	for _, c := range cases {
		got := wsBackoffDelayCapped(c.attempt, c.max)
		if got != c.want {
			t.Errorf("wsBackoffDelayCapped(%d, %s) = %s, want %s", c.attempt, c.max, got, c.want)
		}
	}
}

func TestWsBackoffDelay_MatchesCappedWithWsBackoffMax(t *testing.T) {
	// wsBackoffDelay must stay byte-for-byte equivalent to the general
	// function called with the existing package ceiling -- this is what
	// proves the refactor changed nothing about existing behavior.
	for attempt := 0; attempt <= 10; attempt++ {
		got := wsBackoffDelay(attempt)
		want := wsBackoffDelayCapped(attempt, wsBackoffMax)
		if got != want {
			t.Errorf("wsBackoffDelay(%d) = %s, want %s (wsBackoffDelayCapped with wsBackoffMax)", attempt, got, want)
		}
	}
}

func TestWsProxyAuthReconnectBackoff_WithinProxyAuthCeiling(t *testing.T) {
	for attempt := 0; attempt <= 20; attempt++ {
		got := wsProxyAuthReconnectBackoff(attempt)
		if got < 0 || got > proxyAuthBackoffMax {
			t.Errorf("wsProxyAuthReconnectBackoff(%d) = %s, want within [0, %s]", attempt, got, proxyAuthBackoffMax)
		}
	}
}

func TestProxyAuthBackoffMax_ExceedsNormalCeiling(t *testing.T) {
	// Guards against someone "simplifying" proxyAuthBackoffMax back down to
	// wsBackoffMax -- the whole point of this constant is that it's higher.
	if proxyAuthBackoffMax <= wsBackoffMax {
		t.Fatalf("proxyAuthBackoffMax (%s) must exceed wsBackoffMax (%s)", proxyAuthBackoffMax, wsBackoffMax)
	}
	delay := wsBackoffDelayCapped(20, proxyAuthBackoffMax)
	if delay != proxyAuthBackoffMax {
		t.Fatalf("wsBackoffDelayCapped(20, proxyAuthBackoffMax) = %s, want %s (should have saturated)", delay, proxyAuthBackoffMax)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd agent && go test -run "TestWsBackoffDelayCapped|TestWsBackoffDelay_MatchesCapped|TestWsProxyAuthReconnectBackoff|TestProxyAuthBackoffMax" -v ./...`
Expected: FAIL with `undefined: wsBackoffDelayCapped` / `undefined: wsProxyAuthReconnectBackoff` / `undefined: proxyAuthBackoffMax` (compile error — none of these exist yet).

- [ ] **Step 3: Implement**

In `agent/backoff.go`, add the new constant to the existing `const` block:

```go
const (
	// wsBackoffBase is the delay before the first reconnect retry.
	wsBackoffBase = 1 * time.Second
	// wsBackoffMax caps the exponential climb so a long outage still retries
	// at a bounded cadence instead of backing off indefinitely.
	wsBackoffMax = 120 * time.Second
	// wsHealthyConnection is how long a connection must survive (absent any
	// real message) before a subsequent disconnect is allowed to reset the
	// backoff counter. Set comfortably above the server's ping period
	// (orchestrator/internal/ws/hub.go: pingPeriod=25s) so surviving this long
	// proves at least one real keepalive round-trip succeeded — not just that
	// the TCP handshake and HTTP upgrade completed.
	wsHealthyConnection = 30 * time.Second
	// proxyAuthBackoffMax caps backoff for a CONFIRMED-rejected proxy
	// credential (a completed NTLM or Basic negotiation the proxy explicitly
	// rejected) at a much higher ceiling than ordinary connectivity failures.
	// Retrying a wrong credential against a real AD-integrated proxy on the
	// normal wsBackoffMax schedule risks tripping the domain account's
	// lockout policy -- a real operational hazard, not a theoretical one.
	// This value is a deliberately conservative, safety-first choice, not
	// evidence-derived (unlike e.g. this project's T1018 timeout tuning) --
	// the cost of being too conservative here is only a delayed reconnect,
	// while the cost of being too aggressive is a disruptive account lockout
	// that can affect other services sharing that account. Ordinary
	// connectivity failures (proxy unreachable, no mechanism available) keep
	// using wsBackoffMax; only a confirmed-rejected credential uses this.
	proxyAuthBackoffMax = 30 * time.Minute
)
```

Replace `wsBackoffDelay`'s body to delegate to a new general function, and add the new proxy-auth wrapper (after `wsReconnectBackoff`):

```go
// wsBackoffDelay returns the deterministic exponential-backoff ceiling for
// the given number of consecutive failed connection attempts (0 = before the
// first retry). Doubles from wsBackoffBase, capped at wsBackoffMax. Callers
// apply jitter on top via wsJitter — this function is pure and unjittered so
// it stays simple to test.
func wsBackoffDelay(attempt int) time.Duration {
	return wsBackoffDelayCapped(attempt, wsBackoffMax)
}

// wsBackoffDelayCapped is wsBackoffDelay generalized to an explicit ceiling.
// wsBackoffDelay is the common case (wsBackoffMax); wsProxyAuthReconnectBackoff
// below is the other — both share this one implementation so the exponential
// shape can't drift between the two.
func wsBackoffDelayCapped(attempt int, max time.Duration) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	d := wsBackoffBase
	for i := 0; i < attempt; i++ {
		d *= 2
		if d >= max {
			return max
		}
	}
	return d
}
```

```go
// wsReconnectBackoff is the actual sleep duration before the next connection
// attempt: the exponential ceiling for this attempt count, with full jitter
// applied.
func wsReconnectBackoff(attempt int) time.Duration {
	return wsJitter(wsBackoffDelay(attempt))
}

// wsProxyAuthReconnectBackoff is wsReconnectBackoff's counterpart for a
// CONFIRMED-rejected proxy credential (see proxyAuthBackoffMax) — same
// exponential-with-full-jitter shape, a much higher ceiling.
func wsProxyAuthReconnectBackoff(attempt int) time.Duration {
	return wsJitter(wsBackoffDelayCapped(attempt, proxyAuthBackoffMax))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd agent && go test -run "TestWsBackoffDelayCapped|TestWsBackoffDelay|TestWsProxyAuthReconnectBackoff|TestProxyAuthBackoffMax|TestWsJitter|TestWsShouldResetBackoff" -v ./...`
Expected: PASS — all new tests, plus every existing `backoff_test.go` test (`TestWsBackoffDelay_*`, `TestWsJitter_*`, `TestWsShouldResetBackoff_*`) unchanged and still green.

- [ ] **Step 5: Commit**

```bash
cd agent
git add backoff.go backoff_test.go
git commit -m "feat(agent): add lockout-aware backoff ceiling for confirmed proxy-auth rejection

wsBackoffDelayCapped generalizes the existing exponential-backoff shape
to an explicit ceiling; wsBackoffDelay becomes a thin wrapper over it
(byte-for-byte unchanged behavior, proven by test). New
wsProxyAuthReconnectBackoff uses a 30-minute ceiling instead of the
normal 120s one, for the one failure class where retrying quickly is a
real hazard: a confirmed-rejected credential against an AD-integrated
proxy risks account lockout. Not yet wired into connectWS() (Task 5).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 2: Proxy credential storage

**Files:**
- Modify: `agent/tamper.go` (Windows, `//go:build windows`)
- Modify: `agent/platform_windows.go`
- Modify: `agent/platform_posix.go` (`//go:build linux || darwin`)
- Modify: `agent/service_linux.go`
- Modify: `agent/service_darwin.go`
- Modify: `agent/config.go`
- Test: `agent/tamper_test.go` (Windows-only test file, new)
- Test: `agent/config_posix_test.go` (existing file, add cases)

**Interfaces:**
- Produces: `Config.ProxyUser string`, `Config.ProxyPassword string` (added to the existing `Config` struct in `agent/config.go`) — Task 3/4 read these off the `Config` passed to the dialer-construction code. Also produces `StoreProxyCredentials(user, password string) error` (Windows, exported, for a future install-flow fast-follow — not called from any production code path in this plan, per Global Constraints) and the per-platform `readProxyCredentialsPlatform() (user, password string)` wrapper both platforms implement.
- Consumes: nothing from earlier tasks.

Independent of Task 1; can run in parallel conceptually, but this plan executes tasks in order.

- [ ] **Step 1: Write the failing test (Windows DPAPI round-trip)**

Create `agent/tamper_test.go`:

```go
//go:build windows

package main

import "testing"

func TestStoreAndReadProxyCredentials_RoundTrips(t *testing.T) {
	if err := StoreProxyCredentials("branch-svc-account", "s3cr3t-p@ss"); err != nil {
		t.Fatalf("StoreProxyCredentials: %v", err)
	}
	user, password := ReadProxyCredentials()
	if user != "branch-svc-account" {
		t.Errorf("user = %q, want branch-svc-account", user)
	}
	if password != "s3cr3t-p@ss" {
		t.Errorf("password = %q, want s3cr3t-p@ss", password)
	}
}

func TestReadProxyCredentials_AbsentReturnsEmpty(t *testing.T) {
	// Overwrite with an empty password, then confirm an absent
	// BAS_PROXY_PASSWORD_ENC value (never written) reads back as "" rather
	// than erroring -- an agent with no configured proxy credentials is the
	// normal, common case.
	if err := StoreProxyCredentials("only-user-no-password", ""); err != nil {
		t.Fatalf("StoreProxyCredentials: %v", err)
	}
	user, password := ReadProxyCredentials()
	if user != "only-user-no-password" {
		t.Errorf("user = %q, want only-user-no-password", user)
	}
	if password != "" {
		t.Errorf("password = %q, want empty (never stored)", password)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agent && go test -run TestStoreAndReadProxyCredentials -v .` (Windows host required — this is a `//go:build windows` test)
Expected: FAIL with `undefined: StoreProxyCredentials` / `undefined: ReadProxyCredentials`.

- [ ] **Step 3: Implement Windows storage**

In `agent/tamper.go`, add after `StoreEncryptedSecret` (which ends at line 114):

```go
// StoreProxyCredentials DPAPI-encrypts the proxy password and writes both the
// username (plain — not a secret) and the encrypted password blob to the
// service Parameters registry key, mirroring StoreEncryptedSecret's pattern
// for the agent secret. Not called from any production code path in this
// pass (see the plan's Global Constraints) — exported for a future
// install-flow fast-follow; operators configure this via BAS_PROXY_USER/
// BAS_PROXY_PASSWORD environment variables today, same as AgentSecret's own
// documented override path.
func StoreProxyCredentials(user, password string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, paramKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("registry create key: %w", err)
	}
	defer k.Close()
	if err := k.SetStringValue("BAS_PROXY_USER", user); err != nil {
		return fmt.Errorf("write BAS_PROXY_USER: %w", err)
	}
	if password == "" {
		return nil
	}
	blob, err := EncryptSecret(password)
	if err != nil {
		return fmt.Errorf("encrypt proxy password: %w", err)
	}
	return k.SetStringValue("BAS_PROXY_PASSWORD_ENC", hex.EncodeToString(blob))
}

// ReadProxyCredentials reads the proxy username and DPAPI-decrypts the proxy
// password from the service Parameters registry key. Returns ("", "") if
// either is absent — mirrors ReadEncryptedSecret's "absent or fails ->
// empty" contract, since an agent with no configured proxy credentials is a
// normal, common case, not an error.
func ReadProxyCredentials() (user, password string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, paramKey, registry.QUERY_VALUE)
	if err != nil {
		return "", ""
	}
	defer k.Close()
	user, _, _ = k.GetStringValue("BAS_PROXY_USER")
	hexBlob, _, err := k.GetStringValue("BAS_PROXY_PASSWORD_ENC")
	if err != nil || hexBlob == "" {
		return user, ""
	}
	blob, err := hex.DecodeString(hexBlob)
	if err != nil {
		return user, ""
	}
	password, err = DecryptSecret(blob)
	if err != nil {
		log.Printf("[config] proxy password DPAPI decrypt failed: %v", err)
		return user, ""
	}
	return user, password
}
```

(`encoding/hex`, `fmt`, `log` are all already imported in `tamper.go`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd agent && go test -run TestStoreAndReadProxyCredentials -v .`
Expected: PASS (both tests). Windows host required.

- [ ] **Step 5: Wire the Windows platform wrapper**

In `agent/platform_windows.go`, add after `readEncryptedSecretPlatform` (line 127-128):

```go
// readProxyCredentialsPlatform returns the DPAPI-decrypted proxy credentials
// from the registry (Windows service installs).
func readProxyCredentialsPlatform() (user, password string) {
	return ReadProxyCredentials()
}
```

- [ ] **Step 6: Implement POSIX storage — config-file fields**

In `agent/service_linux.go`, change the `cfg := fmt.Sprintf(...)` line (currently `"BAS_SERVER_URL=%s\nBAS_ENV_LABEL=%s\nBAS_AGENT_SECRET=%s\n"`) to also carry the two new fields, reading them from environment variables at install time (so `--install` picks up whatever `BAS_PROXY_USER`/`BAS_PROXY_PASSWORD` are already set in the installer's own environment, without adding new CLI flags per the Global Constraints):

```go
	proxyUser := os.Getenv("BAS_PROXY_USER")
	proxyPassword := os.Getenv("BAS_PROXY_PASSWORD")
	cfg := fmt.Sprintf("BAS_SERVER_URL=%s\nBAS_ENV_LABEL=%s\nBAS_AGENT_SECRET=%s\nBAS_PROXY_USER=%s\nBAS_PROXY_PASSWORD=%s\n",
		serverURL, envLabel, secret, proxyUser, proxyPassword)
```

(`os` is already imported in `service_linux.go` for `os.MkdirAll`/`os.WriteFile`.) Add, after `readAgentSecret` (ends at line 142):

```go
// readProxyCredentials reads BAS_PROXY_USER/BAS_PROXY_PASSWORD from the
// config file written at install time, mirroring readAgentSecret's rationale
// for the agent secret: a service-managed agent already has these injected
// as real env vars via EnvironmentFile=, but code that runs outside that
// context (or before the file exists) needs this fallback.
func readProxyCredentials() (user, password string) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "BAS_PROXY_USER="); ok {
			user = v
		} else if v, ok := strings.CutPrefix(line, "BAS_PROXY_PASSWORD="); ok {
			password = v
		}
	}
	return user, password
}
```

Apply the identical two changes to `agent/service_darwin.go` (same `cfg := fmt.Sprintf(...)` line shape, same `readAgentSecret` function to add `readProxyCredentials` after).

- [ ] **Step 7: Wire the POSIX platform wrapper**

In `agent/platform_posix.go`, add after `readEncryptedSecretPlatform` (line 27):

```go
// posixReadProxyCredentials indirects readProxyCredentials the same way
// posixReadAgentSecret indirects readAgentSecret above, for the same
// testing reason.
var posixReadProxyCredentials = readProxyCredentials

// readProxyCredentialsPlatform returns the proxy credentials from the
// installed service config (see readProxyCredentials in
// service_linux.go / service_darwin.go).
func readProxyCredentialsPlatform() (user, password string) {
	return posixReadProxyCredentials()
}
```

- [ ] **Step 8: Wire `Config` and `loadConfig()`**

In `agent/config.go`, add two fields to `Config`:

```go
type Config struct {
	ServerURL     string
	EnvLabel      string
	AgentSecret   string // shared secret for X-Agent-Token + result HMAC signing
	ProxyUser     string // forward-proxy username, Basic auth only (NTLM needs none)
	ProxyPassword string // forward-proxy password, Basic auth only
}
```

In `loadConfig()`, after the existing `agentSecret` env-var-then-platform-fallback block (lines 31-33), add the same pattern for proxy credentials, and include both new fields in the returned `Config`:

```go
	proxyUser := os.Getenv("BAS_PROXY_USER")
	proxyPassword := os.Getenv("BAS_PROXY_PASSWORD")
	if proxyUser == "" && proxyPassword == "" {
		proxyUser, proxyPassword = readProxyCredentialsPlatform()
	}
```

```go
	return Config{
		ServerURL:     strings.TrimRight(serverURL, "/"),
		EnvLabel:      envLabel,
		AgentSecret:   agentSecret,
		ProxyUser:     proxyUser,
		ProxyPassword: proxyPassword,
	}
```

- [ ] **Step 9: Write and run the cross-platform config test**

Append to `agent/config_posix_test.go` (existing file — confirms it already has a pattern for stubbing `posixReadAgentSecret`; follow that same pattern for the new var):

```go
func TestLoadConfig_ProxyCredentials_EnvVarTakesPriority(t *testing.T) {
	t.Setenv("BAS_PROXY_USER", "env-user")
	t.Setenv("BAS_PROXY_PASSWORD", "env-pass")
	orig := posixReadProxyCredentials
	posixReadProxyCredentials = func() (string, string) { return "file-user", "file-pass" }
	defer func() { posixReadProxyCredentials = orig }()

	cfg := loadConfig()
	if cfg.ProxyUser != "env-user" || cfg.ProxyPassword != "env-pass" {
		t.Errorf("ProxyUser/ProxyPassword = %q/%q, want env-user/env-pass (env var must win)", cfg.ProxyUser, cfg.ProxyPassword)
	}
}

func TestLoadConfig_ProxyCredentials_FallsBackToPlatformWhenEnvAbsent(t *testing.T) {
	t.Setenv("BAS_PROXY_USER", "")
	t.Setenv("BAS_PROXY_PASSWORD", "")
	orig := posixReadProxyCredentials
	posixReadProxyCredentials = func() (string, string) { return "file-user", "file-pass" }
	defer func() { posixReadProxyCredentials = orig }()

	cfg := loadConfig()
	if cfg.ProxyUser != "file-user" || cfg.ProxyPassword != "file-pass" {
		t.Errorf("ProxyUser/ProxyPassword = %q/%q, want file-user/file-pass (fallback)", cfg.ProxyUser, cfg.ProxyPassword)
	}
}
```

Run: `cd agent && go test -run TestLoadConfig_ProxyCredentials -v .`
Expected: PASS. This test file has no build tag restricting it to POSIX specifically for these two new tests (check the existing file's build tag — if it's `//go:build linux || darwin`, that's fine, these tests only need to prove the env-var-priority behavior, which is platform-agnostic logic even if the file itself only compiles on POSIX; a Windows-side equivalent isn't required since `readProxyCredentialsPlatform` is swapped per-platform and the loadConfig() logic being tested is identical either way).

- [ ] **Step 10: Run the full agent package test suite**

Run: `cd agent && go build ./... && go test ./... -v 2>&1 | tail -150`
Expected: builds clean; all tests PASS, including every pre-existing test in `agent/config_posix_test.go`, `agent/tamper_test.go` (if run on Windows), and unrelated packages.

- [ ] **Step 11: Commit**

```bash
cd agent
git add tamper.go platform_windows.go platform_posix.go service_linux.go service_darwin.go config.go tamper_test.go config_posix_test.go
git commit -m "feat(agent): add proxy credential storage (Windows DPAPI, POSIX EnvironmentFile)

New Config.ProxyUser/ProxyPassword fields, sourced from BAS_PROXY_USER/
BAS_PROXY_PASSWORD env vars first (works immediately, matches
AgentSecret's own documented override path), falling back to
platform-secure storage: DPAPI-encrypted registry value on Windows
(StoreProxyCredentials/ReadProxyCredentials, same pattern as the
existing agent secret), the same EnvironmentFile= config file POSIX
already uses for the agent secret. No new install-time CLI flags in
this pass -- not yet consumed by the dial path (Tasks 3-5).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 3: Basic-via-407 proxy negotiation

**Files:**
- Create: `agent/proxyauth.go`
- Test: `agent/proxyauth_test.go`

**Interfaces:**
- Consumes: `Config.ProxyUser`/`Config.ProxyPassword` (Task 2).
- Produces: `var ErrProxyCredentialsRejected = errors.New(...)` — Task 5 checks this via `errors.Is` to select the lockout-aware backoff. `func proxyAwareNetDialContext(cfg Config) func(ctx context.Context, network, addr string) (net.Conn, error)` — Task 5 wires this into the `websocket.Dialer`'s `NetDialContext` field. `var attemptNTLMProxyAuth func(conn net.Conn, targetAddr string) (net.Conn, error)` — a nil-by-default package variable Task 4's Windows-only file sets via `init()`; this task's negotiation logic calls it when non-nil and the proxy offers NTLM.

- [ ] **Step 1: Write the failing tests**

Create `agent/proxyauth_test.go`:

```go
package main

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

// fakeConnectProxy is a minimal CONNECT-speaking proxy for tests: it accepts
// one connection, reads a CONNECT request, and replies according to script --
// each entry is either "407" (with the given WWW-Authenticate-style header
// value) or "200" (tunnel established, then the proxy just holds the
// connection open for the test to close).
type fakeConnectProxy struct {
	ln net.Listener
}

func newFakeConnectProxy(t *testing.T, handle func(net.Conn)) *fakeConnectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &fakeConnectProxy{ln: ln}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handle(conn)
	}()
	t.Cleanup(func() { ln.Close() })
	return p
}

func (p *fakeConnectProxy) addr() string { return p.ln.Addr().String() }

func TestDialThroughProxy_NoAuthRequired_Succeeds(t *testing.T) {
	proxy := newFakeConnectProxy(t, func(conn net.Conn) {
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != http.MethodConnect {
			return
		}
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		time.Sleep(50 * time.Millisecond) // hold open long enough for the client to observe success
	})

	conn, err := dialThroughProxy(context.Background(), proxy.addr(), "target.example:9443", "", "")
	if err != nil {
		t.Fatalf("dialThroughProxy: %v", err)
	}
	conn.Close()
}

func TestDialThroughProxy_BasicChallenge_RetriesAndSucceeds(t *testing.T) {
	proxy := newFakeConnectProxy(t, func(conn net.Conn) {
		defer conn.Close()
		br := bufio.NewReader(conn)
		// First CONNECT: unauthenticated -- challenge with Basic.
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != http.MethodConnect {
			return
		}
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"))

		// Second CONNECT on the same connection: must carry Basic creds.
		req2, err := http.ReadRequest(br)
		if err != nil || req2.Method != http.MethodConnect {
			return
		}
		auth := req2.Header.Get("Proxy-Authorization")
		if auth != "Basic YnJhbmNoLXVzZXI6czNjcjN0" { // base64("branch-user:s3cr3t")
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"))
			return
		}
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		time.Sleep(50 * time.Millisecond)
	})

	conn, err := dialThroughProxy(context.Background(), proxy.addr(), "target.example:9443", "branch-user", "s3cr3t")
	if err != nil {
		t.Fatalf("dialThroughProxy: %v", err)
	}
	conn.Close()
}

func TestDialThroughProxy_BasicChallenge_WrongCredentialReturnsConfirmedRejection(t *testing.T) {
	proxy := newFakeConnectProxy(t, func(conn net.Conn) {
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, _ := http.ReadRequest(br)
		if req == nil || req.Method != http.MethodConnect {
			return
		}
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"))
		req2, _ := http.ReadRequest(br)
		if req2 == nil {
			return
		}
		// Always reject, regardless of what was sent -- simulates a genuinely wrong credential.
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"))
	})

	_, err := dialThroughProxy(context.Background(), proxy.addr(), "target.example:9443", "branch-user", "wrong-password")
	if err == nil {
		t.Fatal("dialThroughProxy: want error for rejected credential, got nil")
	}
	if !errors.Is(err, ErrProxyCredentialsRejected) {
		t.Errorf("err = %v, want errors.Is(err, ErrProxyCredentialsRejected)", err)
	}
}

func TestDialThroughProxy_BasicOffered_NoCredentialsConfigured_FailsWithDiagnostic(t *testing.T) {
	proxy := newFakeConnectProxy(t, func(conn net.Conn) {
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, _ := http.ReadRequest(br)
		if req == nil || req.Method != http.MethodConnect {
			return
		}
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"))
	})

	_, err := dialThroughProxy(context.Background(), proxy.addr(), "target.example:9443", "", "")
	if err == nil {
		t.Fatal("dialThroughProxy: want error when no credentials are configured, got nil")
	}
	if errors.Is(err, ErrProxyCredentialsRejected) {
		t.Error("err should NOT be ErrProxyCredentialsRejected -- no attempt was ever made, nothing was rejected")
	}
}

func TestProxyAwareNetDialContext_NoProxyConfigured_DialsDirect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("https_proxy", "")

	dial := proxyAwareNetDialContext(Config{})
	conn, err := dial(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd agent && go test -run "TestDialThroughProxy|TestProxyAwareNetDialContext" -v .`
Expected: FAIL with `undefined: dialThroughProxy` / `undefined: ErrProxyCredentialsRejected` / `undefined: proxyAwareNetDialContext` (compile error).

- [ ] **Step 3: Implement**

Create `agent/proxyauth.go`:

```go
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ErrProxyCredentialsRejected marks a CONFIRMED-rejected proxy credential: a
// completed NTLM or Basic negotiation the proxy explicitly rejected (a
// 407/403 AFTER a full attempt), not the initial unauthenticated 407 every
// negotiation starts with. connectWS() checks this via errors.Is to select
// the lockout-aware backoff (agent/backoff.go's wsProxyAuthReconnectBackoff)
// instead of the normal one -- retrying a wrong credential against a real
// AD-integrated proxy quickly risks tripping its lockout policy.
var ErrProxyCredentialsRejected = errors.New("proxy rejected the configured credentials")

// attemptNTLMProxyAuth is set by agent/proxyauth_windows.go's init() on
// Windows builds only; nil on every other platform, which is exactly the
// signal dialThroughProxy uses to know NTLM isn't available here. Takes the
// already-connected proxy connection (NTLM is bound to this one TCP
// connection, not stateless like Basic) and the CONNECT target; returns the
// same connection on success (now an authenticated tunnel), or an error --
// wrapping ErrProxyCredentialsRejected specifically if the proxy completed
// the handshake and then rejected it, a plain error for any other failure
// (network error, malformed challenge, etc., which uses the standard
// backoff, not the lockout-aware one).
var attemptNTLMProxyAuth func(conn net.Conn, targetAddr string) (net.Conn, error)

// proxyAwareNetDialContext returns a NetDialContext-shaped function (see
// gorilla/websocket's Dialer.NetDialContext) that resolves whether a proxy
// applies to the target using the same logic http.ProxyFromEnvironment uses
// (so HTTP_PROXY/HTTPS_PROXY/NO_PROXY behave exactly as they do today), and
// if so, owns the full CONNECT negotiation via dialThroughProxy. No proxy
// resolved -> a plain net.Dial, byte-for-byte the same as today's behavior.
func proxyAwareNetDialContext(cfg Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		targetURL := &url.URL{Scheme: "https", Host: addr}
		req := &http.Request{URL: targetURL}
		proxyURL, err := http.ProxyFromEnvironment(req)
		if err != nil {
			return nil, fmt.Errorf("resolve proxy: %w", err)
		}
		if proxyURL == nil {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}

		user, password := cfg.ProxyUser, cfg.ProxyPassword
		if user == "" && proxyURL.User != nil {
			// Legacy fallback: credentials embedded directly in HTTP_PROXY/
			// HTTPS_PROXY still work, matching gorilla's old (preemptive-only)
			// behavior -- just no longer the recommended path since it has no
			// at-rest protection.
			user = proxyURL.User.Username()
			password, _ = proxyURL.User.Password()
		}
		return dialThroughProxy(ctx, proxyURL.Host, addr, user, password)
	}
}

// dialThroughProxy performs the full CONNECT negotiation against proxyAddr
// for targetAddr: unauthenticated first, then NTLM (Windows, if offered and
// attemptNTLMProxyAuth is set) or Basic (any platform, if offered and a
// credential is available) on a 407, per the priority rule in the plan's
// Global Constraints. Returns the established tunnel connection, or an error
// -- wrapping ErrProxyCredentialsRejected specifically when a negotiation
// completed and was rejected.
func dialThroughProxy(ctx context.Context, proxyAddr, targetAddr, user, password string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxyAddr, err)
	}

	resp, err := sendConnect(conn, targetAddr, "")
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("CONNECT %s via %s: %w", targetAddr, proxyAddr, err)
	}
	if resp.StatusCode == http.StatusOK {
		return conn, nil
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		conn.Close()
		return nil, fmt.Errorf("CONNECT %s via %s: unexpected status %s", targetAddr, proxyAddr, resp.Status)
	}

	offered := parseProxyAuthenticate(resp.Header.Values("Proxy-Authenticate"))

	if offered["ntlm"] && attemptNTLMProxyAuth != nil {
		tunnelConn, err := attemptNTLMProxyAuth(conn, targetAddr)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("NTLM proxy auth via %s: %w", proxyAddr, err)
		}
		return tunnelConn, nil
	}

	if offered["basic"] && user != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
		resp2, err := sendConnect(conn, targetAddr, "Basic "+cred)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("CONNECT %s via %s (Basic retry): %w", targetAddr, proxyAddr, err)
		}
		if resp2.StatusCode == http.StatusOK {
			return conn, nil
		}
		conn.Close()
		return nil, fmt.Errorf("CONNECT %s via %s: %w (status %s)", targetAddr, proxyAddr, ErrProxyCredentialsRejected, resp2.Status)
	}

	conn.Close()
	return nil, fmt.Errorf("proxy %s requires authentication (offered: %s); %s",
		proxyAddr, strings.Join(offeredNames(offered), ", "), unavailableReason(offered, user))
}

// sendConnect writes one CONNECT request for targetAddr on conn (optionally
// with a Proxy-Authorization header) and reads the response. NTLM's 3-leg
// handshake and Basic's single retry both reuse this on the same connection
// -- CONNECT is the only method this whole negotiation ever sends.
func sendConnect(conn net.Conn, targetAddr, proxyAuth string) (*http.Response, error) {
	header := make(http.Header)
	if proxyAuth != "" {
		header.Set("Proxy-Authorization", proxyAuth)
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: targetAddr},
		Host:   targetAddr,
		Header: header,
	}
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	return http.ReadResponse(br, req)
}

// parseProxyAuthenticate reduces zero or more Proxy-Authenticate header
// values (a proxy can offer several) to a lowercase scheme-name set.
func parseProxyAuthenticate(values []string) map[string]bool {
	offered := make(map[string]bool)
	for _, v := range values {
		scheme, _, _ := strings.Cut(v, " ")
		offered[strings.ToLower(strings.TrimSpace(scheme))] = true
	}
	return offered
}

func offeredNames(offered map[string]bool) []string {
	names := make([]string, 0, len(offered))
	for name := range offered {
		names = append(names, name)
	}
	return names
}

// unavailableReason explains WHY none of the offered mechanisms could be
// used, for the diagnostic error -- this is the piece that turns today's
// generic dial failure into something an operator can actually act on.
func unavailableReason(offered map[string]bool, user string) string {
	var reasons []string
	if offered["ntlm"] && attemptNTLMProxyAuth == nil {
		reasons = append(reasons, "SSPI unavailable on this platform")
	}
	if offered["basic"] && user == "" {
		reasons = append(reasons, "no Basic credentials configured (set BAS_PROXY_USER/BAS_PROXY_PASSWORD)")
	}
	if len(reasons) == 0 {
		return "no supported mechanism was offered"
	}
	return strings.Join(reasons, "; ")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd agent && go test -run "TestDialThroughProxy|TestProxyAwareNetDialContext" -v .`
Expected: PASS (all 5 tests). This runs on every platform — none of this file is Windows-specific.

- [ ] **Step 5: Run the full agent package test suite**

Run: `cd agent && go build ./... && go test ./... -v 2>&1 | tail -150`
Expected: builds clean; all tests PASS, no regressions in `agent/backoff_test.go`, `agent/config_posix_test.go`, or any other existing test.

- [ ] **Step 6: Commit**

```bash
cd agent
git add proxyauth.go proxyauth_test.go
git commit -m "feat(agent): add HTTP Basic proxy auth via proper 407 challenge-retry

New agent/proxyauth.go replaces gorilla/websocket's built-in proxy
CONNECT handling (which only sent Basic preemptively via credentials
embedded in the proxy URL, and failed immediately on any non-200
response) with a full negotiation: unauthenticated CONNECT first, then
retry with Basic on a 407 if offered and a credential is available.
ErrProxyCredentialsRejected distinguishes a confirmed-rejected
credential from every other failure. attemptNTLMProxyAuth is a nil
extension point Task 4's Windows-only SSPI handler fills in via
init() -- on every other platform, NTLM-offering proxies fall straight
through to the diagnostic-error path with a specific 'SSPI unavailable
on this platform' reason. Not yet wired into DialAgentWS/connectWS
(Task 5).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 4: SSPI NTLM proxy negotiation (Windows only)

**Files:**
- Create: `agent/proxyauth_windows.go`
- Test: `agent/proxyauth_windows_test.go`
- Modify: `agent/go.mod`, `agent/go.sum` (new dependency)

**Interfaces:**
- Consumes: `attemptNTLMProxyAuth` (Task 3's extension point, this task's `init()` sets it), `sendConnect`/`parseProxyAuthenticate` (Task 3, same package, no import needed).
- Produces: nothing new consumed by later tasks — Task 5 only relies on `attemptNTLMProxyAuth` being non-nil on Windows builds, already declared in Task 3.

- [ ] **Step 1: Add the new dependency**

Run: `cd agent && go get github.com/alexbrainman/sspi@latest`

Verified reachable and resolvable during planning: `v0.0.0-20250919150558-7d374ff0d59e` (a pseudo-version — this package has no tagged releases, which is normal for it). Let `go get` re-resolve for real at implementation time rather than hand-pinning this value; if it resolves to something newer, that's expected and fine.

- [ ] **Step 2: Write the failing tests**

Create `agent/proxyauth_windows_test.go`:

```go
//go:build windows

package main

import (
	"bufio"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"testing"
)

// TestAttemptNTLMProxyAuth_SendsWellFormedType1Message proves the
// NEGOTIATION SHAPE: given a proxy that challenges with NTLM, the handler
// sends a syntactically valid NTLM Type1 message as the first
// Proxy-Authorization attempt. This does not validate real NTLM crypto
// against a genuine authenticating proxy (impractical without a real
// Windows domain) -- see the plan's Task 4 Step 5 for that manual/staging
// verification step.
func TestAttemptNTLMProxyAuth_SendsWellFormedType1Message(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type1Received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != http.MethodConnect {
			return
		}
		auth := req.Header.Get("Proxy-Authorization")
		type1Received <- auth
		// Reply with a 407 carrying no further challenge -- this test only
		// checks the FIRST message's shape, not a full successful handshake.
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM\r\n\r\n"))
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	go attemptNTLMProxyAuth(conn, "target.example:9443")

	select {
	case auth := <-type1Received:
		if !strings.HasPrefix(auth, "NTLM ") {
			t.Fatalf("Proxy-Authorization = %q, want prefix 'NTLM '", auth)
		}
		payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "NTLM "))
		if err != nil {
			t.Fatalf("NTLM payload is not valid base64: %v", err)
		}
		// NTLM messages start with the fixed 8-byte signature "NTLMSSP\x00".
		if len(payload) < 8 || string(payload[:7]) != "NTLMSSP" {
			t.Fatalf("NTLM payload does not start with the NTLMSSP signature: %x", payload[:min(len(payload), 16)])
		}
		// Type1 is message type 1 -- the 4 bytes right after the signature.
		if len(payload) < 12 || payload[8] != 1 {
			t.Fatalf("NTLM payload type = %d, want 1 (Type1)", payload[8])
		}
	case <-timeoutChan(t):
		t.Fatal("timed out waiting for the NTLM Type1 CONNECT")
	}
}

func timeoutChan(t *testing.T) <-chan struct{} {
	t.Helper()
	ch := make(chan struct{})
	go func() {
		// This is a unit test against a local in-process listener -- 5s is
		// generous, not a real network timeout being tuned.
		<-time.After(5 * time.Second)
		close(ch)
	}()
	return ch
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd agent && go test -run TestAttemptNTLMProxyAuth -v .` (Windows host required)
Expected: FAIL — `attemptNTLMProxyAuth` (Task 3's package var, type `func(net.Conn, string) (net.Conn, error)`) exists but is `nil` until this task's `init()` sets it (Step 4 below), so this test panics on the nil call rather than failing to compile. Either failure mode (compile error or nil-call panic) is acceptable RED evidence — the point is the test fails for the expected reason (the real implementation doesn't exist yet), not that it passes prematurely.

- [ ] **Step 4: Implement**

Create `agent/proxyauth_windows.go`. The exact API below was verified during
planning against the real package source
(`github.com/alexbrainman/sspi/ntlm@v0.0.0-20250919150558-7d374ff0d59e`'s
`ntlm.go`) and its own official usage example
(`ntlm/http_test.go`'s `TestNTLMHTTPClient`) — `AcquireCurrentUserCredentials`,
`NewClientContext` (returns `(*ClientContext, []byte, error)` — context,
Type1 negotiate bytes, error), `(*ClientContext).Update` (returns
`([]byte, error)` — Type3 authenticate bytes, error), and `.Release()` on
both the credentials and the context are all real, confirmed signatures,
not a guess. The package's own test even documents the same "must stay on
one connection" NTLM constraint this design already relies on. If `go get`
in Step 1 resolves a materially newer version, spot-check this shape still
holds (`go doc github.com/alexbrainman/sspi/ntlm` after `go get`) before
trusting it unchanged, but treat this as verified, not speculative.

```go
//go:build windows

package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/alexbrainman/sspi/ntlm"
)

func init() {
	attemptNTLMProxyAuth = sspiAttemptNTLM
}

// sspiAttemptNTLM performs the 3-leg NTLM handshake against a proxy that
// has already replied 407 with a Proxy-Authenticate: NTLM challenge on
// conn (see dialThroughProxy in agent/proxyauth.go, which called this).
// Uses the calling process's own security context -- whatever identity the
// Windows Service runs as (see the plan's Global Constraints on what that
// means for a LocalSystem-run agent) -- no separate credential is
// requested or stored for this path.
func sspiAttemptNTLM(conn net.Conn, targetAddr string) (net.Conn, error) {
	creds, err := ntlm.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, fmt.Errorf("acquire current user credentials: %w", err)
	}
	defer creds.Release()

	secCtx, type1, err := ntlm.NewClientContext(creds)
	if err != nil {
		return nil, fmt.Errorf("build NTLM client context: %w", err)
	}
	defer secCtx.Release()

	resp1, err := sendConnect(conn, targetAddr, "NTLM "+base64.StdEncoding.EncodeToString(type1))
	if err != nil {
		return nil, fmt.Errorf("send Type1: %w", err)
	}
	if resp1.StatusCode == http.StatusOK {
		// Some proxies accept after Type1 alone in edge configurations --
		// treat it the same as a normal success.
		return conn, nil
	}
	if resp1.StatusCode != http.StatusProxyAuthRequired {
		return nil, fmt.Errorf("unexpected status after Type1: %s", resp1.Status)
	}

	type2 := extractNTLMChallenge(resp1.Header.Values("Proxy-Authenticate"))
	if type2 == nil {
		return nil, fmt.Errorf("proxy did not return an NTLM Type2 challenge after Type1")
	}

	type3, err := secCtx.Update(type2)
	if err != nil {
		return nil, fmt.Errorf("compute NTLM Type3 response: %w", err)
	}

	resp2, err := sendConnect(conn, targetAddr, "NTLM "+base64.StdEncoding.EncodeToString(type3))
	if err != nil {
		return nil, fmt.Errorf("send Type3: %w", err)
	}
	if resp2.StatusCode == http.StatusOK {
		return conn, nil
	}
	return nil, fmt.Errorf("%w (status %s)", ErrProxyCredentialsRejected, resp2.Status)
}

// extractNTLMChallenge finds the base64 Type2 payload in a set of
// Proxy-Authenticate header values, or nil if none carries one.
func extractNTLMChallenge(values []string) []byte {
	for _, v := range values {
		scheme, rest, found := strings.Cut(v, " ")
		if !found || !strings.EqualFold(strings.TrimSpace(scheme), "NTLM") {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
		if err != nil {
			continue
		}
		return payload
	}
	return nil
}
```

This is the real, verified API (see the note above Step 4's heading) — implement it as written. Only deviate if the actually-resolved `go get` version differs from what was verified during planning, and note any such deviation in the task's report.

- [ ] **Step 5: Run test to verify it passes**

Run: `cd agent && go test -run TestAttemptNTLMProxyAuth -v .` (Windows host required)
Expected: PASS. This proves the negotiation *shape* only (a well-formed Type1 message reaches the proxy). Real end-to-end success against a genuine NTLM-authenticating corporate proxy is NOT provable here — call this out explicitly in the task report as a manual/staging verification step, per the spec's own testing strategy.

- [ ] **Step 6: Run the full agent package test suite**

Run: `cd agent && go build ./... && go test ./... -v 2>&1 | tail -150`
Expected: builds clean on Windows; all tests PASS, including Tasks 1-3's tests and every pre-existing test, no regressions.

- [ ] **Step 7: Commit**

```bash
cd agent
git add proxyauth_windows.go proxyauth_windows_test.go go.mod go.sum
git commit -m "feat(agent): add NTLM proxy auth via Windows SSPI

New agent/proxyauth_windows.go (Windows-only) fills in
attemptNTLMProxyAuth's extension point from Task 3, using
github.com/alexbrainman/sspi to drive the standard 3-leg NTLM
handshake (Type1 -> proxy's Type2 challenge -> Type3) against a proxy
that offered NTLM on a 407. Uses the calling process's own security
context -- the Windows Service's own identity, no separate proxy
credential requested or stored.

Negotiation shape verified by unit test (well-formed Type1 message
sent, correctly parsed NTLMSSP signature/type byte). Real end-to-end
success against a genuine NTLM-authenticating corporate proxy needs a
real Windows domain and is not provable in this test run -- called out
as an explicit manual/staging verification step, same honesty this
project already applies elsewhere to what can't be proven locally.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 5: Wire the proxy-aware dialer into DialAgentWS/connectWS

**Files:**
- Modify: `agent/protocol/websocket.go`
- Modify: `agent/agent.go`
- Test: `agent/protocol/websocket_test.go`
- Test: `agent/agent_test.go` (if it doesn't exist yet for this kind of test, check first — see Step 5's note)

**Interfaces:**
- Consumes: `proxyAwareNetDialContext(cfg Config)` (Task 3), `ErrProxyCredentialsRejected` (Task 3), `wsProxyAuthReconnectBackoff`/`wsReconnectBackoff` (Task 1, `wsReconnectBackoff` already existed before this plan).
- Produces: `func DialAgentWSWithDialer(serverURL, agentID, agentSecret string, dialer *websocket.Dialer) (*websocket.Conn, error)` in `agent/protocol` — no other task consumes this, it's the final integration point.

- [ ] **Step 1: Write the failing test for the new protocol-layer function**

Append to `agent/protocol/websocket_test.go`:

```go
func TestDialAgentWSWithDialer_UsesSuppliedDialer(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.WriteJSON(WSMessage{Type: "command_cancel"})
	}))
	defer server.Close()

	dialCalled := false
	dialer := &websocket.Dialer{
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialCalled = true
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}

	conn, err := DialAgentWSWithDialer(server.URL, "a1", "", dialer)
	if err != nil {
		t.Fatalf("DialAgentWSWithDialer: %v", err)
	}
	defer conn.Close()

	if !dialCalled {
		t.Error("supplied dialer's NetDialContext was never called -- DialAgentWSWithDialer did not use it")
	}

	msg, err := ReadMessage(conn)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if msg.Type != "command_cancel" {
		t.Errorf("msg.Type = %q, want command_cancel", msg.Type)
	}
}

func TestDialAgentWS_StillWorksUnchanged(t *testing.T) {
	// Regression guard: DialAgentWS itself (the function loadgen calls) must
	// keep working exactly as before now that it's a thin wrapper.
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.WriteJSON(WSMessage{Type: "command_cancel"})
	}))
	defer server.Close()

	conn, err := DialAgentWS(server.URL, "a1", "")
	if err != nil {
		t.Fatalf("DialAgentWS: %v", err)
	}
	defer conn.Close()
	if _, err := ReadMessage(conn); err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
}
```

(Add `"context"` and `"net"` to this test file's imports.)

- [ ] **Step 2: Run tests to verify the new one fails**

Run: `cd agent/protocol && go test -run "TestDialAgentWSWithDialer|TestDialAgentWS_StillWorksUnchanged" -v .`
Expected: `TestDialAgentWS_StillWorksUnchanged` PASSes already (nothing's changed yet); `TestDialAgentWSWithDialer_UsesSuppliedDialer` FAILs with `undefined: DialAgentWSWithDialer`.

- [ ] **Step 3: Implement**

In `agent/protocol/websocket.go`, replace `DialAgentWS`'s body with a thin wrapper and add the new function:

```go
// DialAgentWS connects to /ws/agent and arms the ping/pong keepalive
// handshake, using the default dialer (no custom proxy handling). Shared by
// the real agent and loadgen -- the single network-calling implementation of
// the WS connect step. Reconnect timing is the caller's concern (the real
// agent and loadgen each retry differently), so this makes exactly one
// connection attempt and returns.
func DialAgentWS(serverURL, agentID, agentSecret string) (*websocket.Conn, error) {
	return DialAgentWSWithDialer(serverURL, agentID, agentSecret, websocket.DefaultDialer)
}

// DialAgentWSWithDialer is DialAgentWS with an explicit *websocket.Dialer --
// the real agent uses this with a proxy-aware NetDialContext (see
// agent/proxyauth.go's proxyAwareNetDialContext); loadgen and every other
// caller keeps using DialAgentWS, unaffected by this addition.
func DialAgentWSWithDialer(serverURL, agentID, agentSecret string, dialer *websocket.Dialer) (*websocket.Conn, error) {
	rawURL := strings.Replace(serverURL, "http://", "ws://", 1)
	rawURL = strings.Replace(rawURL, "https://", "wss://", 1)

	u, err := url.Parse(rawURL + "/ws/agent")
	if err != nil {
		return nil, fmt.Errorf("invalid WS URL: %w", err)
	}
	q := u.Query()
	q.Set("agentId", agentID)
	if agentSecret != "" {
		q.Set("agentSecret", agentSecret)
	}
	u.RawQuery = q.Encode()

	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("WS dial: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(wsPongWait))
	conn.SetPingHandler(func(appData string) error {
		conn.SetReadDeadline(time.Now().Add(wsPongWait))
		err := conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(wsWriteWait))
		if err == websocket.ErrCloseSent {
			return nil
		}
		return err
	})
	return conn, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd agent/protocol && go test -v .`
Expected: PASS — both new tests, plus every existing test in this package (`TestDialAgentWS_ConnectsAndReadsMessage`, `TestReadMessage_MalformedFrameReturnsError`, `TestScenarioCommand_DecodesFromRealisticPayload`), unchanged.

- [ ] **Step 5: Wire `connectWS()` to use the proxy-aware dialer and select backoff class**

In `agent/agent.go`, modify `connectWS()` (starting at line 1201). Replace:

```go
	attempt := 0
	for {
		conn, err := protocol.DialAgentWS(a.cfg.ServerURL, a.id.AgentID, a.cfg.AgentSecret)
		if err != nil {
			delay := wsReconnectBackoff(attempt)
			log.Printf("[!] WS connect failed: %v — retry in %s (attempt %d)", err, delay.Round(time.Millisecond), attempt+1)
			a.logger.Op("warn", "connectivity", fmt.Sprintf("WebSocket dial failed (attempt %d): %v — retrying in %s", attempt+1, err, delay.Round(time.Millisecond)))
			attempt++
			time.Sleep(delay)
			continue
		}
```

with:

```go
	dialer := &websocket.Dialer{NetDialContext: proxyAwareNetDialContext(a.cfg)}
	attempt := 0
	for {
		conn, err := protocol.DialAgentWSWithDialer(a.cfg.ServerURL, a.id.AgentID, a.cfg.AgentSecret, dialer)
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
```

Add `"errors"` and `"github.com/gorilla/websocket"` to `agent.go`'s import block if not already present (check the existing imports first — `agent.go` almost certainly already imports `"errors"` given its size; only add what's actually missing).

- [ ] **Step 6: Verify no other call site of `protocol.DialAgentWS` needs changing**

Run: `grep -rn "protocol.DialAgentWS" agent/*.go` — confirm `agent.go`'s `connectWS()` was the only call site inside the `agent` module using the plain (non-`WithDialer`) form that needed upgrading. `orchestrator/cmd/loadgen/agent.go` is a different module and is explicitly NOT touched by this plan (Global Constraints).

- [ ] **Step 7: Run the full agent package test suite**

Run: `cd agent && go build ./... && go test ./... -v 2>&1 | tail -200`
Expected: builds clean; all tests PASS across every package (`agent`, `agent/protocol`, and any others), including all of Tasks 1-4's tests and every pre-existing test, no regressions.

- [ ] **Step 8: Commit**

```bash
cd agent
git add protocol/websocket.go protocol/websocket_test.go agent.go
git commit -m "feat(agent): wire proxy-aware dialer into connectWS

DialAgentWS becomes a thin wrapper over new DialAgentWSWithDialer,
which accepts an explicit *websocket.Dialer -- DialAgentWS's own
signature and behavior are unchanged (loadgen, the only other caller,
is unaffected). connectWS() now constructs a Dialer with
proxyAwareNetDialContext(a.cfg) as its NetDialContext, replacing
websocket.DefaultDialer, and selects the lockout-aware backoff
(wsProxyAuthReconnectBackoff) instead of the normal one specifically
when the dial error wraps ErrProxyCredentialsRejected -- every other
failure keeps using the existing 120s-ceiling backoff, unchanged.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 6: Final regression verification

**Files:** none modified — verification only.

**Interfaces:** none — this task confirms Tasks 1-5's combined result, nothing new is produced or consumed.

- [ ] **Step 1: Full build**

Run: `cd agent && go build ./... 2>&1`
Expected: clean, no errors, on whatever platform this step runs on (note in the report if run on non-Windows, since `proxyauth_windows.go`/`tamper.go`/`proxyauth_windows_test.go` won't compile-check there — flag this explicitly rather than silently skip it, and if possible also confirm via `GOOS=windows go build ./...` cross-compile even on a non-Windows runner, which at least catches syntax/type errors in the Windows-only files without needing to execute their tests).

- [ ] **Step 2: Full test suite**

Run: `cd agent && go test ./... -v 2>&1 | tail -300`
Expected: every package `ok`, zero regressions. Explicitly confirm by name: `agent` package (backoff, proxyauth, agent.go-adjacent tests), `agent/protocol` package, and — if run on Windows — the Windows-only test files from Tasks 2 and 4.

- [ ] **Step 3: Confirm the spec's 5 success criteria, one by one**

1. Basic-via-407 with stored credentials succeeds: `TestDialThroughProxy_BasicChallenge_RetriesAndSucceeds` (Task 3) — confirm PASS.
2. NTLM via SSPI: negotiation shape confirmed by `TestAttemptNTLMProxyAuth_SendsWellFormedType1Message` (Task 4) — confirm PASS, and explicitly note in this task's report that real end-to-end NTLM success against a genuine corporate proxy remains an OPEN manual/staging verification item, not something this plan closes.
3. Unavailable-mechanism diagnostic: `TestDialThroughProxy_BasicOffered_NoCredentialsConfigured_FailsWithDiagnostic` (Task 3) — confirm PASS, and manually inspect the error message it asserts against to confirm it's genuinely more specific than the old generic "WS dial: ..." error (read the test's assertions plus `unavailableReason`'s implementation together).
4. Lockout-aware backoff ceiling: `TestProxyAuthBackoffMax_ExceedsNormalCeiling` and `TestWsProxyAuthReconnectBackoff_WithinProxyAuthCeiling` (Task 1) — confirm PASS.
5. No-proxy path unchanged: `TestProxyAwareNetDialContext_NoProxyConfigured_DialsDirect` (Task 3) and `TestDialAgentWS_StillWorksUnchanged` (Task 5) — confirm PASS.

- [ ] **Step 4: Confirm scope boundaries held**

- `grep -rn "Kerberos\|Negotiate" agent/proxyauth*.go` — expect zero matches (out of scope, confirm nothing crept in).
- `grep -rln "attemptNTLMProxyAuth\|sspiAttemptNTLM" agent/*.go` — confirm NTLM code exists only in `agent/proxyauth_windows.go` (the assignment/implementation) and `agent/proxyauth.go` (the extension-point declaration), never in a non-Windows-tagged file's actual logic path.
- `git diff main --stat` (or `git log --stat` across this plan's commits) — confirm no changes to `orchestrator/cmd/loadgen/agent.go` or any file outside `agent/`.

No commit for this task — it's verification only. If any check fails, that's a real defect: stop and fix it as part of whichever earlier task actually owns the gap, don't patch it here.
