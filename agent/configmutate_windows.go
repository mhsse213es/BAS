//go:build windows

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// handleTestServer is handleSetServer's non-disruptive counterpart: it
// never persists, never restarts, never touches the live connection.
// Validation happens before any network call (Global Constraint: an
// invalid host never reaches the network); on a valid host it performs a
// real TLS handshake against the candidate, then -- only if that
// succeeds -- one real authenticated call, so a completed handshake alone
// is never reported as Connected. The server's own clock (from the
// authenticated call's response) is discarded here; callers that need it
// for clock-skew measurement (Troubleshoot check 4) use
// testServerWithServerTime directly.
func (a *Agent) handleTestServer(candidateHost string) (TestOutcome, string) {
	outcome, detail, _ := a.testServerWithServerTime(candidateHost)
	return outcome, detail
}

// testServerWithServerTime is handleTestServer's real implementation,
// additionally returning the server's clock at the moment of the
// authenticated call (zero value if that call never ran or didn't
// succeed) -- the one signal Troubleshoot's clock-skew check needs that
// handleTestServer's public two-value contract (already relied on by
// existing tests) doesn't carry.
func (a *Agent) testServerWithServerTime(candidateHost string) (TestOutcome, string, time.Time) {
	validated, err := ValidateCandidateHost(candidateHost)
	if err != nil {
		return TestOutcomeInvalidHost, err.Error(), time.Time{}
	}
	opURL, err := operationalURL(validated)
	if err != nil {
		return TestOutcomeInvalidHost, err.Error(), time.Time{}
	}
	candidateCfg := withServerURL(a.cfg(), opURL)

	host, _, port, err := splitServerURL(candidateCfg.ServerURL)
	if err != nil {
		return TestOutcomeInvalidHost, err.Error(), time.Time{}
	}

	tlsErr := dialTLSCheck(net.JoinHostPort(host, port), candidateCfg)
	var authErr error
	var serverTime time.Time
	if tlsErr == nil {
		authErr, serverTime = authCheck(a, candidateCfg)
	}
	outcome := ClassifyTestResult(tlsErr, authErr)
	return outcome, testOutcomeDetail(outcome, tlsErr, authErr), serverTime
}

// dialTLSCheck performs the real TLS-handshake step. A package-level var
// (like imagePathForPID/resolvePipeSDDL in localmutate_windows.go) so
// tests can inject network failures without a real second host.
var dialTLSCheck = func(addr string, cfg Config) error {
	d := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, agentTLSConfig(cfg))
	if err != nil {
		return err
	}
	return conn.Close()
}

// authCheck performs the real authenticated-call step: one heartbeat POST
// against the candidate config's own client (never a.httpClient(), which
// is bound to the live/current config), carrying this agent's REAL
// identity and status -- never a bogus partial payload. The orchestrator's
// heartbeat handler upserts hostname/IP/username/status/binary_trusted
// from the body and rejects an empty AgentID outright, so a placeholder
// payload would either always be rejected or, if "fixed" by adding just
// an AgentID, silently overwrite this agent's real server-side record
// with blank/fake fields on every Test click. Sending the real heartbeat
// is exactly what the agent will do anyway once this host is actually in
// use, so it's the correct call here, not a test-only construct. The
// response's Date header is returned too, letting a successful call
// double as the clock-skew measurement (testServerWithServerTime) without
// a second, separately-authenticated round trip. A package-level var for
// the same injection reason as dialTLSCheck.
var authCheck = func(a *Agent, cfg Config) (error, time.Time) {
	transport := &http.Transport{DialContext: proxyAwareNetDialContext(cfg), TLSClientConfig: agentTLSConfig(cfg)}
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}

	hb := a.buildHeartbeat(a.getStatus())
	data, err := json.Marshal(hb)
	if err != nil {
		return fmt.Errorf("marshal heartbeat: %w", err), time.Time{}
	}
	req, err := http.NewRequest(http.MethodPost, cfg.ServerURL+"/api/heartbeat", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("new request: %w", err), time.Time{}
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.AgentSecret != "" {
		req.Header.Set("X-Agent-Token", cfg.AgentSecret)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST /api/heartbeat: %w", err), time.Time{}
	}
	defer resp.Body.Close()
	serverTime, _ := http.ParseTime(resp.Header.Get("Date")) // zero value if absent/unparseable
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server %d on /api/heartbeat", resp.StatusCode), serverTime
	}
	return nil, serverTime
}

func testOutcomeDetail(outcome TestOutcome, tlsErr, authErr error) string {
	switch outcome {
	case TestOutcomeConnected:
		return "Connected"
	case TestOutcomeCertInvalid, TestOutcomeHostUnreachable:
		return tlsErr.Error()
	case TestOutcomeServerRejected:
		return authErr.Error()
	default:
		return ""
	}
}

// reconnectTimeout/reconnectPollInterval bound handleSetServer's post-
// apply reconnection wait. Named constants per the design's Global
// Constraint that "Saved" is never reported from persistence alone.
const (
	reconnectTimeout      = 30 * time.Second
	reconnectPollInterval = 2 * time.Second
)

// setServerPersist/setServerApply/setServerVerifyReconnect are the three
// seams handleSetServer's sequence is built from -- package-level vars (the
// same pattern as dialTLSCheck/authCheck) so tests can fake each
// independently.
//
// Production: persist writes the literal host the user entered to the
// registry (for durability across a real future reboot) while preserving
// the current envLabel/enrollPort; apply hot-swaps this already-running
// process's live config and forces a reconnect -- it deliberately does
// NOT ask the SCM to stop+start the Windows service, because
// handleSetServer runs INSIDE that same service process: stopping it
// would kill the very goroutine running this function before it could
// ever verify, roll back, or report anything back over the pipe (the
// codebase already documents this exact hazard at platformSelfUninstall's
// call site in service.go). Hot-swapping cfgPtr/clientPtr and force-
// closing the active WS connection is the same technique upgradeToMTLS
// (agent.go) already uses for a live config change with zero process
// restart. verify reuses handleTestServer itself (never a cached
// classification -- Review Focus item 2's decoupling applies here too).
var setServerPersist = func(serverURL string) error {
	_, envLabel := readServiceParamsFrom(svcName)
	return writeServiceParams(serverURL, envLabel, readServiceEnrollPort())
}

// setServerReadPrevious reads the literal host currently in the registry
// -- a separate seam (rather than inlining readServiceParamsFrom at the
// call site) so tests can pin a deterministic "previous" value instead of
// depending on whatever this build machine's own service installation
// (if any) happens to have written there.
var setServerReadPrevious = func() string {
	url, _ := readServiceParamsFrom(svcName)
	return url
}

var setServerApply = func(a *Agent, newCfg Config) error {
	a.swapLiveConfig(newCfg)
	log.Printf("[*] server host changed via Settings: %s", newCfg.ServerURL)
	return nil
}

var setServerVerifyReconnect = func(a *Agent, host string) bool {
	outcome, _ := a.handleTestServer(host)
	return outcome == TestOutcomeConnected
}

// handleSetServer validates, warns-via-caller-already-having-confirmed,
// persists, applies, and verifies reconnection within reconnectTimeout --
// rolling back to the previous host and reporting the real outcome on any
// failure mode (persist failure, apply failure, or reconnect timeout).
// Never reports true on the strength of persistence alone.
func (a *Agent) handleSetServer(candidateHost string) (ok bool, detail string) {
	return a.handleSetServerWithTimeout(candidateHost, reconnectTimeout, reconnectPollInterval)
}

// handleSetServerWithTimeout is handleSetServer's real implementation,
// taking the timeout/poll interval as parameters so tests can use small
// values instead of waiting out the real 30s constant.
func (a *Agent) handleSetServerWithTimeout(candidateHost string, timeout, pollInterval time.Duration) (ok bool, detail string) {
	a.setServerMu.Lock()
	defer a.setServerMu.Unlock()

	validated, err := ValidateCandidateHost(candidateHost)
	if err != nil {
		return false, err.Error()
	}
	opURL, err := operationalURL(validated)
	if err != nil {
		return false, err.Error()
	}
	newCfg := withServerURL(a.cfg(), opURL)

	// The previous value for persist/rollback comes from the registry --
	// what's actually written there today -- never a.cfg().ServerURL,
	// which already holds the mTLS-DERIVED URL (e.g. https://h:9443), not
	// the literal configured value (e.g. http://h:9000) writeServiceParams
	// itself expects. Using the derived value as "previous" would persist
	// a different, wrong value on rollback.
	prevURL := setServerReadPrevious()

	if err := setServerPersist(validated); err != nil {
		return false, fmt.Sprintf("failed to save the new host: %v", err)
	}
	if err := setServerApply(a, newCfg); err != nil {
		if rerr := rollback(a, prevURL); rerr != nil {
			return false, fmt.Sprintf("apply failed (%v), AND reverting to the previous host also failed (%v) -- the agent may now be misconfigured", err, rerr)
		}
		return false, fmt.Sprintf("apply failed, reverted to the previous host: %v", err)
	}

	deadline := time.Now().Add(timeout)
	for {
		if setServerVerifyReconnect(a, opURL) {
			return true, "Saved and reconnected"
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(pollInterval)
	}

	if rerr := rollback(a, prevURL); rerr != nil {
		return false, fmt.Sprintf("could not reconnect within the timeout, AND reverting to the previous host also failed (%v) -- the agent may now be misconfigured", rerr)
	}
	return false, "could not reconnect within the timeout, reverted to the previous host"
}

// rollback reverts both the persisted registry value and the live config
// to prevURL, returning the first error encountered (if any) so callers
// can report a genuine revert failure instead of claiming "reverted" on
// the strength of having merely attempted it.
func rollback(a *Agent, prevURL string) error {
	if err := setServerPersist(prevURL); err != nil {
		return err
	}
	prevOpURL, err := operationalURL(prevURL)
	if err != nil {
		return err
	}
	return setServerApply(a, withServerURL(a.cfg(), prevOpURL))
}

// mutateAPIStarted guards startMutateAPIOnce: the pipe listener, once
// created, serves for the agent's whole lifetime (no close path), so a
// second session-logon event (fast user switching, RDP reconnect) must
// not attempt to recreate it.
var mutateAPIStarted atomic.Bool

// startMutateAPIOnce calls startMutateAPI the first time an interactive
// session is known to exist (service.go calls this everywhere it calls
// launchTrayForActiveSession, since both need the same WTS-resolved user
// session) and is a no-op on every later call.
func startMutateAPIOnce(a *Agent) {
	if !mutateAPIStarted.CompareAndSwap(false, true) {
		return
	}
	if err := a.startMutateAPI(); err != nil {
		log.Printf("[!] start mutate API (Settings/Troubleshoot config changes unavailable): %v", err)
		mutateAPIStarted.Store(false) // allow the next session event to retry
	}
}

// startMutateAPI wires handleTestServer/handleSetServer onto the Task 3
// named pipe as its single handler, mapping the wire protocol's "op" field
// to each. The outcome string is either a TestOutcome value (test-server)
// or "ok"/"error" (set-server) -- the two operations' result shapes
// deliberately differ, so the Settings window's client dispatches on
// which op it sent, not on the outcome string alone. test-server also
// returns the server's clock from its (successful) authenticated call,
// carried over the wire so Troubleshoot's clock-skew check can use the
// SAME round trip instead of a second, separately-authenticated request.
func (a *Agent) startMutateAPI() error {
	return startLocalMutateAPI(a, func() int32 { return trayPID.Load() }, func(op, host string) (string, string, time.Time) {
		switch op {
		case "test-server":
			outcome, detail, serverTime := a.testServerWithServerTime(host)
			return string(outcome), detail, serverTime
		case "set-server":
			ok, detail := a.handleSetServer(host)
			if ok {
				return "ok", detail, time.Time{}
			}
			return "error", detail, time.Time{}
		default:
			return "error", "unknown operation: " + op, time.Time{}
		}
	})
}
