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
)

// wsBackoffDelay returns the deterministic exponential-backoff ceiling for
// the given number of consecutive failed connection attempts (0 = before the
// first retry). Doubles from wsBackoffBase, capped at wsBackoffMax. Callers
// apply jitter on top via wsJitter — this function is pure and unjittered so
// it stays simple to test.
func wsBackoffDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	d := wsBackoffBase
	for i := 0; i < attempt; i++ {
		d *= 2
		if d >= wsBackoffMax {
			return wsBackoffMax
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
