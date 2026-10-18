# Agent Tray Settings + Troubleshoot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (native, inline execution — already chosen). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator change the Windows agent's orchestrator host, test it before committing, and run the existing manual connectivity runbook as a guided live diagnostic — all from the tray icon, with no registry editing.

**Architecture:** The unprivileged tray process (already spawned by the SYSTEM service into the user's session) gains two new windigo-native windows, Settings and Troubleshoot. They talk to the SYSTEM-privileged agent process over two channels: the existing read-only loopback HTTP API (static bearer token, unchanged) for reads, and a new named pipe (SID-scoped + client-PID-checked) for the two actions that mutate config (`test-server`, `set-server`). No new persistence mechanism — `writeServiceParams` (existing) still owns the registry write.

**Tech Stack:** Go 1.26, `golang.org/x/sys/windows`, `github.com/rodrigocfd/windigo` (existing), `github.com/Microsoft/go-winio` (new dependency — named pipe listener with SDDL security descriptors; the standard, Microsoft-maintained choice for this exact need, used by Docker/containerd on Windows).

**Spec:** `docs/superpowers/specs/2026-10-18-agent-tray-settings-troubleshoot-design.md`

## Global Constraints

- Windows only. Linux/macOS agents are unmodified in this plan.
- No new persistence mechanism for the server URL — only `writeServiceParams` (`agent/service.go:577`) writes it.
- The existing read-only local-API endpoints (`/status`, `/activity`, `/evidence`, `/controls`, `/logs`) and their static bearer token are unchanged.
- No "Exit" tray menu item — matches the existing deliberate omission (`agent/tray_windows.go:302-306`).
- Every windigo window's message loop runs on a locked OS thread (`runtime.LockOSThread()`) — missing this previously caused a real, hard-to-reproduce AppHang (see `agent/statuswindow_windows.go:34-45`'s doc comment). Every new window task must include this.
- A completed TLS handshake alone is never reported as "Connected" — always followed by one real authenticated call.
- "Saved" is never reported on the strength of a registry write alone — only after the service restarts and either reconnects, or is rolled back and the real outcome is reported.

## Review Focus

- A user pastes a URL with a path or query string (`https://host:9443/foo?x=1`) into the Settings field — the five-way classifier must not silently strip it and test a different host than what's shown; reject as Invalid host or normalize visibly, not silently.
- The configured host is unreachable at Troubleshoot-check time but *was* reachable when Settings last tested it (network flapped in between) — step 3's result must reflect the live check, never a cached Test result from a different window's lifetime.
- Two mutating calls arrive back-to-back (user double-clicks Save) — the rollback logic must not race itself (e.g. the second call reverting a value the first call hasn't finished applying yet).
- The named pipe's SID-scoped ACL is satisfied (same user) but the PID check target process has already exited and a new, unrelated process reused that PID before the check runs — the plan must verify more than PID alone (image path of the connecting process) or explicitly document this as an accepted residual risk with its likelihood.
- `writeServiceParams` succeeds but the subsequent service restart command itself fails to even launch (not just "restarted but didn't reconnect") — the rollback path must trigger on this failure mode too, not only on a timed-out reconnection.

---

### Task 1: Candidate-host validation and the five-way test-outcome classifier

**Files:**
- Create: `agent/hostcheck.go`
- Test: `agent/hostcheck_test.go`

**Interfaces:**
- Produces: `func ValidateCandidateHost(raw string) (string, error)` — returns the exact, normalized URL to use everywhere downstream (never a silently-stripped variant; a URL with a path/query is rejected, not truncated) or a descriptive error.
- Produces: `type TestOutcome string` with exact values `TestOutcomeConnected`, `TestOutcomeServerRejected`, `TestOutcomeCertInvalid`, `TestOutcomeHostUnreachable`, `TestOutcomeInvalidHost`.
- Produces: `func ClassifyTestResult(tlsErr error, authErr error) TestOutcome` — given the error (or nil) from the TLS dial step and the error (or nil) from the follow-up authenticated call, returns exactly one `TestOutcome`. `ValidateCandidateHost`'s own rejection is handled by the caller before this function is ever invoked (it never sees `TestOutcomeInvalidHost` itself — that path never reaches a network call, per the spec).

- [ ] **Step 1: Write the failing tests**

```go
func TestValidateCandidateHost_RejectsPathAndQuery(t *testing.T) {
	_, err := ValidateCandidateHost("https://host:9443/foo?x=1")
	if err == nil {
		t.Fatal("expected rejection of a URL with a path/query, got none")
	}
}

func TestValidateCandidateHost_AcceptsSchemeHostPort(t *testing.T) {
	got, err := ValidateCandidateHost("https://10.0.0.5:9443")
	if err != nil || got != "https://10.0.0.5:9443" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestClassifyTestResult_TLSHandshakeFails_IsCertInvalid(t *testing.T) {
	got := ClassifyTestResult(errors.New("x509: certificate signed by unknown authority"), nil)
	if got != TestOutcomeCertInvalid {
		t.Fatalf("got %q, want %q", got, TestOutcomeCertInvalid)
	}
}

func TestClassifyTestResult_TLSOK_AuthRejected_IsServerRejected(t *testing.T) {
	got := ClassifyTestResult(nil, errors.New("401 unauthorized"))
	if got != TestOutcomeServerRejected {
		t.Fatalf("got %q, want %q", got, TestOutcomeServerRejected)
	}
}

func TestClassifyTestResult_BothOK_IsConnected(t *testing.T) {
	if got := ClassifyTestResult(nil, nil); got != TestOutcomeConnected {
		t.Fatalf("got %q, want %q", got, TestOutcomeConnected)
	}
}
```

Dial-level failures (DNS/TCP) are a third case the test file must also cover: a `TestClassifyTestResult_DialFails_IsHostUnreachable` case, distinguishing a dial error from a TLS-handshake error by wrapping the dial error distinctly (e.g. `&net.OpError{}`) in the test's fixture — `ClassifyTestResult`'s first parameter represents "any pre-authenticated-call failure," and the implementation must distinguish a dial/DNS failure from a handshake failure by error type, not by string-matching.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./agent/... -run TestValidateCandidateHost -run TestClassifyTestResult -v`
Expected: FAIL — `ValidateCandidateHost`/`ClassifyTestResult` undefined.

- [ ] **Step 3: Implement `ValidateCandidateHost` and `ClassifyTestResult` in `agent/hostcheck.go`**

Use `net/url.Parse` plus an explicit check that `Path`, `RawQuery`, and `Fragment` are all empty (reject otherwise, don't strip). For `ClassifyTestResult`'s dial-vs-handshake distinction, use `errors.As` against `*net.OpError` / `*net.DNSError` for the unreachable case and `*tls.CertificateVerificationError` (or `x509.CertificateInvalidError`/`x509.UnknownAuthorityError` via `errors.As`) for the cert-invalid case; anything else non-nil in the first parameter falls through to `TestOutcomeHostUnreachable` as the safe default (never silently reported as Connected).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./agent/... -run TestValidateCandidateHost -run TestClassifyTestResult -v`
Expected: PASS, all cases.

- [ ] **Step 5: Commit**

```bash
git add agent/hostcheck.go agent/hostcheck_test.go
git commit -m "feat(agent): add candidate-host validation and test-outcome classifier"
```

---

### Task 2: Structured last-connection-error field

**Files:**
- Modify: `agent/statusclient/statusclient.go:104-121` (`StatusResponse`)
- Modify: `agent/bootstrap.go` (wherever a connection attempt's failure is currently only logged — identify the exact call site at implementation time; this is the point that calls into `retryBootstrapUntilEnrolled`/the mTLS upgrade path referenced in `agent/agent.go:25-33`'s comment)
- Create: `agent/connerror.go` (the classification type, decoupled from both the status struct and bootstrap so Task 5's Troubleshoot check and Task 1's test classifier can share vocabulary without importing each other)
- Test: `agent/connerror_test.go`

**Interfaces:**
- Consumes: nothing from Task 1 (deliberately decoupled — see Review Focus item 2: a Troubleshoot check must reflect its own live result, not reuse a cached Settings-window classification).
- Produces: `type ConnErrorCategory string` with values `ConnErrorNone`, `ConnErrorDNS`, `ConnErrorTCP`, `ConnErrorTLS`, `ConnErrorProxyAuth`, `ConnErrorServerRejected`, `ConnErrorUnknown`.
- Produces: `type LastConnError struct { Category ConnErrorCategory; Detail string; At time.Time }`.
- Produces: `func ClassifyConnError(err error) LastConnError` — classifies a real connection-attempt error, matching the runbook's known proxy-auth log strings (`docs/guides/troubleshooting.md` Section 2.5: "SSPI unavailable", "no Basic credentials configured", "no supported mechanism", "proxy rejected the configured credentials") via `strings.Contains` against `err.Error()` for the proxy case specifically, and `errors.As` for DNS/TCP/TLS like Task 1. A `nil` error produces `ConnErrorNone`.
- Produces: a new field on `StatusResponse`: `LastConnError *LastConnError \`json:"lastConnError,omitempty"\`` (pointer so "no failure recorded yet" serializes as absent, not a zero-value category).

- [ ] **Step 1: Write the failing tests**

```go
func TestClassifyConnError_ProxyAuthString_IsProxyAuth(t *testing.T) {
	got := ClassifyConnError(errors.New("proxy rejected the configured credentials"))
	if got.Category != ConnErrorProxyAuth {
		t.Fatalf("category = %q, want %q", got.Category, ConnErrorProxyAuth)
	}
}

func TestClassifyConnError_Nil_IsNone(t *testing.T) {
	got := ClassifyConnError(nil)
	if got.Category != ConnErrorNone {
		t.Fatalf("category = %q, want %q", got.Category, ConnErrorNone)
	}
}

func TestClassifyConnError_SetsTimestamp(t *testing.T) {
	before := time.Now()
	got := ClassifyConnError(errors.New("connection refused"))
	if got.At.Before(before) {
		t.Fatal("At was not set to the time of classification")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./agent/... -run TestClassifyConnError -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement `agent/connerror.go`**

Order the `errors.As`/string checks so proxy-auth string matches are checked before the generic TCP/DNS `errors.As` fallbacks (a proxy rejection often also wraps a `*net.OpError`, and the more specific classification must win).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./agent/... -run TestClassifyConnError -v`
Expected: PASS.

- [ ] **Step 5: Wire `LastConnError` into `StatusResponse` and set it at the real failure point**

Add the field to `StatusResponse`. In `agent/bootstrap.go`, find the exact point where a connection attempt's error is currently passed only to `log.Printf` (not before — identify it by reading the file at this step) and additionally store `ClassifyConnError(err)` on the `Agent`'s state (mirroring the existing `cfgPtr atomic.Pointer[Config]` pattern at `agent/agent.go:33` — add `lastConnErrPtr atomic.Pointer[LastConnError]`, same rationale: read from multiple goroutines, no torn read). `handleLocalStatus` (`agent/local_api_windows.go:112`) reads it into the response.

- [ ] **Step 6: Write a focused test proving the wiring, not just the classifier**

```go
func TestAgent_RecordsLastConnErrorOnFailedAttempt(t *testing.T) {
	// Drive a real failed connection attempt against an unreachable
	// address through the agent's existing bootstrap retry path, then
	// assert a.lastConnErrPtr.Load() is non-nil with a plausible category.
	// Exact fixture depends on bootstrap_test.go's existing test-harness
	// conventions -- read that file first and follow its pattern rather
	// than building a new one.
}
```

- [ ] **Step 7: Run the full existing bootstrap test suite plus the new test**

Run: `go test ./agent/... -run TestAgent_RecordsLastConnErrorOnFailedAttempt -v && go test ./agent/... -run TestBootstrap -v`
Expected: PASS, and no existing `TestBootstrap*` case regresses.

- [ ] **Step 8: Commit**

```bash
git add agent/connerror.go agent/connerror_test.go agent/statusclient/statusclient.go agent/bootstrap.go agent/agent.go agent/local_api_windows.go
git commit -m "feat(agent): add structured last-connection-error classification"
```

---

### Task 3: Named-pipe transport for mutating local-API calls

**Files:**
- Create: `agent/localmutate_windows.go`
- Test: `agent/localmutate_windows_test.go`
- Modify: `go.mod` / `go.sum` (add `github.com/Microsoft/go-winio`)

**Interfaces:**
- Consumes: nothing yet (this task builds the transport only; Task 4 adds the two real handlers on top of it).
- Produces: `const mutatePipeName = \`\\\\.\\pipe\\BASAgentMutate\`\`.
- Produces: `func startLocalMutateAPI(a *Agent, expectedClientPID func() int32) error` — creates the pipe listener (SID-scoped SDDL: `D:(A;;GA;;;<the logged-in user's SID>)`, built from the SID the service already resolves via `activeUserToken()`/`WTSQueryUserToken` in `agent/usertoken_windows.go` — read that file's existing SID-resolution code at implementation time rather than re-deriving it), and for every accepted connection calls `expectedClientPID()` and rejects (closes the connection, no response) if the connecting process's PID — and, per Review Focus item 4, its image path via `windows.QueryFullProcessImageName` — do not both match what was recorded at tray-spawn time.
- Produces: in `agent/usertoken_windows.go` (modify): `launchTrayForActiveSession` must capture `cmd.Process.Pid` right after a successful `cmd.Start()` (before the existing `cmd.Process.Release()` call) and store it where `startLocalMutateAPI`'s `expectedClientPID` closure can read it — add a package-level `atomic.Int32` (e.g. `trayPID`), mirroring the `atomic.Pointer`/`atomic.Bool` convention already used elsewhere in this package.

- [ ] **Step 1: Write the failing tests**

```go
func TestStartLocalMutateAPI_RejectsWrongPID(t *testing.T) {
	// Start the pipe with expectedClientPID returning a PID that is NOT
	// this test process's own PID, dial the pipe as this test process,
	// and assert the connection is closed/refused rather than served.
}

func TestStartLocalMutateAPI_AcceptsMatchingPID(t *testing.T) {
	// Start the pipe with expectedClientPID returning os.Getpid() (this
	// test process IS the expected client), dial it, and assert the
	// connection is accepted (e.g. a trivial echo handler responds).
}

func TestStartLocalMutateAPI_RejectsMatchingPIDWrongImagePath(t *testing.T) {
	// Review Focus item 4: PID alone is insufficient if it's been reused.
	// Fake/override the image-path lookup so it returns a path that does
	// NOT match this test process's own image path, even though the PID
	// passed to expectedClientPID matches os.Getpid() -- assert the
	// connection is still refused. This is what makes the PID check more
	// than a bare PID comparison.
}
```

Exact dial mechanics (how a test process connects to its own named pipe) depend on `go-winio`'s client-dial API (`winio.DialPipe`) — confirm its exact signature when writing this step; it takes a context and the pipe path.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./agent/... -run TestStartLocalMutateAPI -v`
Expected: FAIL — undefined / connection refused in both cases (no server started yet).

- [ ] **Step 3: Add the `go-winio` dependency and implement `startLocalMutateAPI`**

```bash
go get github.com/Microsoft/go-winio@latest
```

Use `winio.ListenPipe(mutatePipeName, &winio.PipeConfig{SecurityDescriptor: sddl, MessageMode: false})` for the listener. For the per-connection PID check, `go-winio`'s pipe connection type exposes the underlying handle for calling `windows.GetNamedPipeClientProcessId` (confirm the exact accessor — likely a method on the connection or its `Fd()` — at implementation time; if `go-winio` does not expose this cleanly, fall back to `golang.org/x/sys/windows.GetNamedPipeClientProcessId` called directly against a duplicated handle, which is still reachable since `go-winio`'s `net.Conn` wraps a real Windows handle).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./agent/... -run TestStartLocalMutateAPI -v`
Expected: PASS, both cases.

- [ ] **Step 5: Wire PID capture into `launchTrayForActiveSession`**

- [ ] **Step 6: Commit**

```bash
git add agent/localmutate_windows.go agent/localmutate_windows_test.go agent/usertoken_windows.go go.mod go.sum
git commit -m "feat(agent): add SID- and PID-scoped named pipe transport for config mutations"
```

---

### Task 4: `/config/test-server` and `/config/set-server` handlers

**Files:**
- Create: `agent/configmutate_windows.go`
- Test: `agent/configmutate_windows_test.go`

**Interfaces:**
- Consumes: `ValidateCandidateHost`, `TestOutcome`, `ClassifyTestResult` (Task 1); `startLocalMutateAPI` (Task 3); `withServerURL(cfg Config, serverURL string) Config` and `operationalURL(serverURL string) (string, error)` (existing, `agent/bootstrap.go:273,297`); `writeServiceParams(serverURL, envLabel, enrollPort string) error` (existing, `agent/service.go:577`).
- Produces: `func (a *Agent) handleTestServer(candidateHost string) (TestOutcome, string)` — returns the classified outcome and a human-readable detail string. Called by the pipe's request router (built in this task) on `test-server` requests.
- Produces: `func (a *Agent) handleSetServer(candidateHost string) (ok bool, detail string)` — persists, restarts, verifies reconnection within a bounded timeout (define as a named constant, e.g. `const reconnectTimeout = 30 * time.Second`), and rolls back + reports the real outcome on failure. Returns `false` with a detail string on *any* failure mode — write failure, restart-launch failure, or reconnect timeout — never `true` on the strength of persistence alone (Review Focus item 5).

- [ ] **Step 1: Write the failing tests for `handleTestServer`**

```go
func TestHandleTestServer_InvalidHost_NoNetworkCallMade(t *testing.T) {
	// Pass a candidate with a path/query; assert the returned outcome is
	// TestOutcomeInvalidHost and that no dial was attempted (inject a
	// fake dialer the test can assert was never called).
}

func TestHandleTestServer_DialFails_HostUnreachable(t *testing.T) {
	// Fake dialer returns a *net.OpError; assert TestOutcomeHostUnreachable.
}

func TestHandleTestServer_TLSOK_AuthRejected_ServerRejected(t *testing.T) {
	// Fake dialer succeeds; fake authenticated-call returns 401; assert
	// TestOutcomeServerRejected.
}
```

`handleTestServer` needs its network calls injected (a dialer/HTTP-client interface the production code satisfies with real `tls.Dial` + the existing heartbeat call, and tests satisfy with fakes) — define that seam in this step, matching whatever fake-injection convention `bootstrap_test.go` already uses for `Config`/HTTP client substitution.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./agent/... -run TestHandleTestServer -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement `handleTestServer`**

Validate via `ValidateCandidateHost` first (zero network calls on rejection, per Global Constraints). On success, build the candidate `Config` via `withServerURL`, resolve the port via `operationalURL`, dial, then make one real authenticated call reusing the existing heartbeat/status-check logic (identify the exact existing function at implementation time — likely already called periodically elsewhere in `agent.go`/`bootstrap.go`), feed both errors into `ClassifyTestResult`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./agent/... -run TestHandleTestServer -v`
Expected: PASS.

- [ ] **Step 5: Write the failing tests for `handleSetServer`**

```go
func TestHandleSetServer_ReconnectSucceeds_ReturnsOK(t *testing.T) {
	// Fake persist + fake restart + fake post-restart test-connection
	// check that succeeds; assert ok == true.
}

func TestHandleSetServer_ReconnectTimesOut_RollsBackAndReportsFailure(t *testing.T) {
	// Fake post-restart check always fails within the fixture's injected
	// (shortened) timeout; assert: ok == false, the fake persist function
	// was called a SECOND time with the ORIGINAL host (the rollback), and
	// detail mentions the revert.
}

func TestHandleSetServer_PersistFails_NeverAttemptsRestart(t *testing.T) {
	// Fake persist returns an error; assert the fake restart function was
	// never called, ok == false.
}

func TestHandleSetServer_RestartLaunchFails_RollsBack(t *testing.T) {
	// Review Focus item 5: distinct from the timeout case above -- here
	// the restart trigger itself returns an error (e.g. the SCM call
	// fails to even launch), not "launched but didn't reconnect in time."
	// Assert this is treated as a failure requiring rollback too: the
	// fake persist function is called a second time with the original
	// host, ok == false.
}

func TestHandleSetServer_ConcurrentCalls_Serialized(t *testing.T) {
	// Review Focus item 3: two overlapping calls (the pipe server must
	// serialize handleSetServer invocations, e.g. via a mutex on the
	// Agent, not let a second call's rollback race a first call's
	// in-flight persist/restart). Launch two calls concurrently with
	// different candidate hosts against a fake persist/restart/reconnect
	// set that records call order; assert the second call's full
	// sequence (persist, restart-wait, success-or-rollback) only begins
	// after the first call's sequence has fully completed -- never
	// interleaved.
}
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `go test ./agent/... -run TestHandleSetServer -v`
Expected: FAIL — undefined.

- [ ] **Step 7: Implement `handleSetServer`**

Inject `writeServiceParams`-equivalent, the restart trigger, and the reconnection check as interfaces/function fields so tests can fake all three (production wiring calls the real `writeServiceParams`, a real SCM restart call, and `handleTestServer` against the now-configured host). Record the previous value before writing; on any failure path — persist failure, restart-launch failure, or reconnect timeout — call the persist function again with the previous value and attempt restart again before returning the failure detail. Guard the whole sequence (read-previous → persist → restart → verify-or-rollback) with a mutex on the `Agent` so two `handleSetServer` calls can never interleave (Review Focus item 3) — a second call must block until the first's full sequence, including any rollback, has completed.

- [ ] **Step 8: Run tests to verify they pass**

Run: `go test ./agent/... -run TestHandleSetServer -v`
Expected: PASS, all three cases.

- [ ] **Step 9: Wire both handlers onto the Task 3 pipe's request router**

- [ ] **Step 10: Commit**

```bash
git add agent/configmutate_windows.go agent/configmutate_windows_test.go
git commit -m "feat(agent): add test-server and set-server handlers with rollback-on-failure"
```

---

### Task 5: Tray menu — Settings and Troubleshoot items

**Files:**
- Modify: `agent/tray_windows.go:79-82` (add `tIDM_SETTINGS`, `tIDM_TROUBLESHOOT` constants), `:291-306` (`trayShowMenu`), `:265-277` (the `tWM_COMMAND` switch)
- Test: `agent/tray_windows_test.go` (new, if `tray_windows.go` has no existing test file — confirm at implementation time)

**Interfaces:**
- Consumes: nothing from earlier tasks (this task only wires menu entries to process-spawn calls; Tasks 6-7 build what they spawn).
- Produces: two new spawn functions mirroring `openStatusWindow` (`agent/tray_windows.go:332-355`) exactly — `openSettingsWindow()` spawning `exe --settings-window`, `openTroubleshootWindow()` spawning `exe --troubleshoot-window`, both with the same "bring existing window to front instead of duplicating" check `openStatusWindow` already does.

- [ ] **Step 1: Add `tIDM_SETTINGS = 0x2004` and `tIDM_TROUBLESHOOT = 0x2005`** next to the existing `tIDM_*` constants (`agent/tray_windows.go:79-82`) — chosen to not collide with the existing `tIDM_EXIT = 0x2009`.

- [ ] **Step 2: Add the two menu entries to `trayShowMenu`**, between the existing `"Open Status Console"` item and its following separator (so the final order is: Open Status Console, Settings..., Troubleshoot..., separator, Export Diagnostic Bundle, Open Logs Folder — matching the spec's stated order). Still no Exit entry.

- [ ] **Step 3: Add the two `case` branches to the `tWM_COMMAND` switch**, each calling its new spawn function, following the exact pattern of `case tIDM_OPEN: openStatusWindow()`.

- [ ] **Step 4: Implement `openSettingsWindow()` and `openTroubleshootWindow()`** as near-identical copies of `openStatusWindow()`'s structure (find-existing-window-and-focus, else spawn `exe --settings-window`/`--troubleshoot-window` with `createNoWindow`).

- [ ] **Step 5: Write a test asserting the menu's exact item set and order**

```go
func TestTrayShowMenu_ItemOrder(t *testing.T) {
	// If trayShowMenu's items aren't independently introspectable without
	// a live Win32 menu handle, extract the ordered list of (id, label)
	// pairs it builds into a small testable helper first (e.g.
	// buildTrayMenuItems() []trayMenuEntry), then assert its output here,
	// rather than testing the Win32 call itself.
	items := buildTrayMenuItems()
	wantLabels := []string{"Open Status Console", "Settings...", "Troubleshoot...", "", "Export Diagnostic Bundle", "Open Logs Folder"}
	// "" marks the separator position.
	if len(items) != len(wantLabels) {
		t.Fatalf("got %d items, want %d", len(items), len(wantLabels))
	}
	for i, want := range wantLabels {
		if items[i].Label != want {
			t.Errorf("item %d label = %q, want %q", i, items[i].Label, want)
		}
	}
	for _, it := range items {
		if it.ID == tIDM_EXIT {
			t.Fatal("Exit must not appear in the user-facing menu")
		}
	}
}
```

- [ ] **Step 6: Run the test**

Run: `go test ./agent/... -run TestTrayShowMenu_ItemOrder -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add agent/tray_windows.go agent/tray_windows_test.go
git commit -m "feat(agent): add Settings and Troubleshoot items to the tray menu"
```

---

### Task 6: Settings window

**Files:**
- Create: `agent/settingswindow_windows.go`
- Test: `agent/settingscontroller_test.go` (controller logic only — the windigo window itself is not unit-testable; see Task 8)

**Interfaces:**
- Consumes: `ValidateCandidateHost`/`TestOutcome` (Task 1); the pipe client for calling `test-server`/`set-server` (Task 3/4 — define a small `mutateClient` type here that dials the named pipe, mirroring how `statusclient.New(statusclient.DefaultAddr, token)` is used for the read-only API in `agent/statuswindow_windows.go:48-49`); `newWindigoWindow`-equivalent pattern (`agent/statuswindow_windows.go:250`); `StatusResponse.ServerURL` (existing) to pre-fill the field with the *current* value at window open.
- Produces: `func runSettingsWindow()`, invoked via `bas_agent.exe --settings-window` (wire the flag dispatch alongside the existing `--status-window` flag — find that dispatch point, likely in `main.go`, at implementation time). Produces a `SettingsController` with `Run()`/`Stop()`, mirroring `StatusController`'s shape (`agent/statuswindow_windows.go:52-53`) so the controller's Test/Save button-click logic is unit-testable independent of the real window.

- [ ] **Step 1: Write the failing tests for the controller's button logic**

```go
func TestSettingsController_Test_InvalidHost_ShowsInvalidHostImmediately(t *testing.T) {
	// Fake mutateClient whose TestServer method must NOT be called;
	// assert the controller's displayed result is TestOutcomeInvalidHost.
}

func TestSettingsController_Save_WarnsBeforeCommitting(t *testing.T) {
	// Assert the controller surfaces a confirmation/warning state before
	// calling mutateClient.SetServer -- exact mechanism (a bool field the
	// UI reads, a two-step click) is this task's call; the test just
	// proves SetServer is not called on the first click alone.
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./agent/... -run TestSettingsController -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement `SettingsController`**

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./agent/... -run TestSettingsController -v`
Expected: PASS.

- [ ] **Step 5: Implement the windigo window itself (`runSettingsWindow`, `agent/settingswindow_windows.go`)**

Mirror `runStatusWindow`'s structure exactly (`agent/statuswindow_windows.go:34-60`), including `runtime.LockOSThread()` as the first line — this is a Global Constraint, not optional. A text field pre-filled from `StatusResponse.ServerURL`, a Test button, a Save button, and a result area. No automated test for this step — manual verification only (see Task 9).

- [ ] **Step 6: Wire `--settings-window` into the executable's flag dispatch**

- [ ] **Step 7: Commit**

```bash
git add agent/settingswindow_windows.go agent/settingscontroller_test.go
git commit -m "feat(agent): add Settings window with Test/Save controller logic"
```

---

### Task 7: Troubleshoot window — the six checks

**Files:**
- Create: `agent/troubleshootwindow_windows.go`
- Test: `agent/troubleshootcontroller_test.go`

**Interfaces:**
- Consumes: Task 1's `ClassifyTestResult`/`TestOutcome` (check 3, reusing the same test as Settings, against the *currently configured* host, not a candidate); Task 2's `LastConnError`/`ClassifyConnError` (checks 5-6); `StatusResponse.ServerURL`/`ServiceRunning` (existing, checks 1-2).
- Produces: `type DiagnosticCheck struct { Name string; Status CheckStatus; Cause, Evidence, Action string; ActionButton *ActionButton }` and `type CheckStatus string` (`CheckPass`, `CheckFail`, `CheckWarn`, `CheckPending`).
- Produces: `func RunDiagnostics(client ...) []DiagnosticCheck` — runs all six checks in order; each check is independently re-runnable (`func RunDiagnosticCheck(n int, ...) DiagnosticCheck`).

- [ ] **Step 1: Write the failing tests, one per check's classification logic**

```go
func TestRunDiagnostics_ServiceStopped_Check1Fails(t *testing.T) {
	// Fake SCM query returns stopped; assert checks[0].Status == CheckFail
	// and ActionButton offers to start it.
}

func TestRunDiagnostics_ClockSkewOnlyFlaggedWithEvidence(t *testing.T) {
	// Fake TLS-handshake timestamp close to local time; assert check[3]
	// (clock skew) is CheckPass, not a default-to-warn.
	// Separately: fake a >5min skew; assert CheckWarn with the skew duration
	// in Evidence.
}

func TestRunDiagnostics_ProxyAuthOnlyLabeledWithEvidence(t *testing.T) {
	// Fake LastConnError with Category == ConnErrorTCP (not proxy); assert
	// check[5] does NOT claim a proxy issue -- this pins the spec's "only
	// label a failure as a proxy issue when the evidence supports it."
}

func TestRunDiagnostics_Check3_AlwaysCallsLiveTest_NeverCached(t *testing.T) {
	// Review Focus item 2: a Troubleshoot run must never reuse a result
	// value from a prior Settings-window Test call or a prior
	// RunDiagnostics call. Inject a fake network-test function that
	// returns a DIFFERENT TestOutcome on each successive call (e.g.
	// HostUnreachable then Connected); call RunDiagnosticCheck(3, ...)
	// twice and assert the second call's result reflects the second
	// (changed) fake outcome, proving check 3 has no memoized/cached
	// result of its own.
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./agent/... -run TestRunDiagnostics -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement the six checks in `agent/troubleshootwindow_windows.go`**

Check 2 reads `StatusResponse.ServerURL` directly (the service's effective config), never the Settings window's unsaved field — this is a named Global Constraint-adjacent requirement from the spec, worth a one-line comment at the call site, not just in this plan.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./agent/... -run TestRunDiagnostics -v`
Expected: PASS, all cases including the two evidence-gated cases.

- [ ] **Step 5: Implement the windigo window itself**

Same `runtime.LockOSThread()` requirement as Task 6. Six rows, each independently re-runnable (a per-row "Retry" affordance), action buttons per the spec's examples ("Test Connection", "Change Server...", "Open Windows Date & Time Settings" — the last one shells out to `control.exe /name Microsoft.DateAndTime` or the modern Settings URI equivalent, confirm the exact invocation at implementation time). The existing "Export Diagnostic Bundle" tray item is unchanged and not duplicated inside this window — the spec calls it the escalation fallback, not a feature of this window.

- [ ] **Step 6: Wire `--troubleshoot-window` into the flag dispatch**

- [ ] **Step 7: Commit**

```bash
git add agent/troubleshootwindow_windows.go agent/troubleshootcontroller_test.go
git commit -m "feat(agent): add Troubleshoot window with six guided diagnostic checks"
```

---

### Task 8: End-to-end verification

**Files:** none created — this task is verification only.

This is Windows-service-level behavior (registry, named pipes, `CreateProcessAsUser`, SCM, live windigo windows) that cannot be meaningfully exercised in this session's environment the way the Postgres-container-backed `internal/api` tests are. Per this project's standing split (build happens here, heavy/real-environment verification happens on staging), this task is a checklist for the user to run on a real Windows install, not automated tests this session executes.

- [ ] **Step 1: Run the full automated suite from Tasks 1-7 one more time together**

Run: `go test ./agent/... -v 2>&1 | tee /tmp/agent-tray-settings-full.log`
Expected: every test from every task above passes; no pre-existing `agent` package test regresses.

- [ ] **Step 2: Build the agent binary and confirm it still builds clean**

Run: `go build ./...` from `agent/`.
Expected: clean build, no errors (confirms the new `go-winio` dependency resolves and all new files compile under the `//go:build windows` tags).

- [ ] **Step 3: Write the manual verification checklist for the user to run on a real Windows install**

Document in this plan's final commit message or a short note in the PR description — not a new file — covering: valid host Test → Connected; a host with a listening TCP port but wrong/no cert → Certificate validation failed; a host that's down → Host unreachable; a malformed URL → Invalid host (and confirm via a packet capture or firewall log that *no* network call was attempted); Save on a good host → service restarts, reconnects, UI confirms; Save on a host that will fail to reconnect → UI shows the rollback, registry value is back to the original, confirmed via `reg query`; a second, unprivileged local process attempting to dial the named pipe directly (not through the tray) → connection refused; all six Troubleshoot checks against a healthy agent → all pass; stop the service and re-run Troubleshoot → check 1 fails with a recovery action.

- [ ] **Step 4: Commit the plan's completion**

```bash
git add -A
git commit -m "chore: complete agent tray Settings/Troubleshoot implementation, pending manual staging verification"
```
