package main

import (
	"math/rand"
	"time"
)

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

// wsJitter applies full jitter: a uniform random duration in [0, d]. This is
// what prevents a fleet of agents that all disconnected at the same moment
// (e.g. a server restart) from reconnecting in lockstep.
func wsJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(d) + 1))
}

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

// wsShouldResetBackoff decides whether a just-ended connection counts as
// "genuinely established" for backoff-reset purposes. A bare Dial() success
// is not sufficient evidence: the server could accept the HTTP upgrade and
// then immediately close the connection (capacity shedding, a duplicate
// agentId kick, transient network flap), which would falsely reset the
// counter every retry and defeat the backoff entirely. Resetting requires
// either a real application message to have been exchanged, or the
// connection to have survived long enough to prove it wasn't instantly
// bounced.
func wsShouldResetBackoff(heldFor time.Duration, gotMessage bool) bool {
	return gotMessage || heldFor >= wsHealthyConnection
}
