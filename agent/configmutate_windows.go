//go:build windows

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"audspect/agent/protocol"
	"golang.org/x/sys/windows/svc/mgr"
)

// handleTestServer is handleSetServer's non-disruptive counterpart: it
// never persists, never restarts, never touches the live connection.
// Validation happens before any network call (Global Constraint: an
// invalid host never reaches the network); on a valid host it performs a
// real TLS handshake against the candidate, then -- only if that
// succeeds -- one real authenticated call, so a completed handshake alone
// is never reported as Connected.
func (a *Agent) handleTestServer(candidateHost string) (TestOutcome, string) {
	validated, err := ValidateCandidateHost(candidateHost)
	if err != nil {
		return TestOutcomeInvalidHost, err.Error()
	}
	opURL, err := operationalURL(validated)
	if err != nil {
		return TestOutcomeInvalidHost, err.Error()
	}
	candidateCfg := withServerURL(a.cfg(), opURL)

	host, _, port, err := splitServerURL(candidateCfg.ServerURL)
	if err != nil {
		return TestOutcomeInvalidHost, err.Error()
	}

	tlsErr := dialTLSCheck(net.JoinHostPort(host, port), candidateCfg)
	var authErr error
	if tlsErr == nil {
		authErr = authCheck(candidateCfg)
	}
	outcome := ClassifyTestResult(tlsErr, authErr)
	return outcome, testOutcomeDetail(outcome, tlsErr, authErr)
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
// is bound to the live/current config) -- a package-level var for the
// same injection reason as dialTLSCheck.
var authCheck = func(cfg Config) error {
	transport := &http.Transport{DialContext: proxyAwareNetDialContext(cfg), TLSClientConfig: agentTLSConfig(cfg)}
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}
	_, err := protocol.SendHeartbeat(context.Background(), client, cfg.ServerURL, cfg.AgentSecret, protocol.Heartbeat{Status: "test"})
	return err
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
// restart reconnection wait. Named constants per the design's Global
// Constraint that "Saved" is never reported from persistence alone.
const (
	reconnectTimeout      = 30 * time.Second
	reconnectPollInterval = 2 * time.Second
)

// setServerPersist/setServerRestart/setServerVerifyReconnect are the three
// seams handleSetServer's sequence is built from -- package-level vars (the
// same pattern as dialTLSCheck/authCheck) so tests can fake each
// independently. Production: persist writes the new host while preserving
// the current envLabel/enrollPort; restart performs a real SCM stop+start;
// verify reuses handleTestServer itself (never a cached classification --
// Review Focus item 2's decoupling applies here too).
var setServerPersist = func(serverURL string) error {
	_, envLabel := readServiceParamsFrom(svcName)
	return writeServiceParams(serverURL, envLabel, readServiceEnrollPort())
}

var setServerRestart = func() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()

	if err := stopServiceAndWait(s, 15*time.Second, 250*time.Millisecond, terminateProcessByPID); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	return nil
}

var setServerVerifyReconnect = func(a *Agent, host string) bool {
	outcome, _ := a.handleTestServer(host)
	return outcome == TestOutcomeConnected
}

// handleSetServer validates, warns-via-caller-already-having-confirmed,
// persists, restarts, and verifies reconnection within reconnectTimeout --
// rolling back to the previous host and reporting the real outcome on any
// failure mode (persist failure, restart-launch failure, or reconnect
// timeout). Never reports true on the strength of persistence alone.
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

	prevURL := a.cfg().ServerURL

	if err := setServerPersist(opURL); err != nil {
		return false, fmt.Sprintf("failed to save the new host: %v", err)
	}
	if err := setServerRestart(); err != nil {
		_ = setServerPersist(prevURL)
		_ = setServerRestart()
		return false, fmt.Sprintf("service restart failed, reverted to the previous host: %v", err)
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

	_ = setServerPersist(prevURL)
	_ = setServerRestart()
	return false, "could not reconnect within the timeout, reverted to the previous host"
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
// which op it sent, not on the outcome string alone.
func (a *Agent) startMutateAPI() error {
	return startLocalMutateAPI(a, func() int32 { return trayPID.Load() }, func(op, host string) (string, string) {
		switch op {
		case "test-server":
			outcome, detail := a.handleTestServer(host)
			return string(outcome), detail
		case "set-server":
			ok, detail := a.handleSetServer(host)
			if ok {
				return "ok", detail
			}
			return "error", detail
		default:
			return "error", "unknown operation: " + op
		}
	})
}
