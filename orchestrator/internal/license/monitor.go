package license

import (
	"context"
	"log"
	"sync/atomic"
	"time"
)

var current atomic.Value // holds Info

// SetInitial seeds the state atomic.Value read by Current, synchronously,
// before StartMonitor's ticker begins. Call once, at startup, right after
// the first Evaluate — guarantees Current() never reads a zero-valued Info
// once the caller has started up (an unseeded Current() before this is
// ever called returns a zero-value Info{} whose State is "", which every
// enforcement point in this codebase treats as "not locked" — fail-open
// by construction, never fail-closed on a forgotten seed).
func SetInitial(info Info) {
	current.Store(info)
}

// Current returns the most recently stored evaluation (from SetInitial
// until the first tick, from the ticker thereafter).
func Current() Info {
	v := current.Load()
	if v == nil {
		return Info{}
	}
	return v.(Info)
}

// StartMonitor begins a background ticker that re-verifies and
// re-evaluates the license at licPath every interval, overwriting the
// value SetInitial seeded. Every tick calls VerifiedRead, which re-checks
// the RSA signature from scratch — a license is never trusted on the
// strength of an earlier tick (or the startup Check) alone, since the
// file on disk can be edited at any later moment the process keeps
// running. Any verification failure (missing file, bad signature, a
// field edited after signing, malformed data) fails CLOSED into
// StateInvalid: the previous state is never kept around on error, so
// tampering is never masked by "last known good". Restoring the
// original, correctly-signed file is re-verified like any other tick —
// there is no separate, weaker recovery path.
//
// Skips entirely (no ticker ever runs) when PublicKeyPEM is still the
// KEYGEN_REQUIRED placeholder — mirrors Check()'s own dev-mode bypass, so
// a local dev build with no bas.lic ever configured does not get
// fail-closed into StateInvalid five minutes after Check() deliberately
// let it start with enforcement disabled.
//
// onLock is called at most once per transition into a blocking state
// (State.Blocked — StateLocked or StateInvalid), nil-safe. Stops when
// ctx is cancelled.
func StartMonitor(ctx context.Context, licPath string, interval time.Duration, onLock func()) {
	if PublicKeyPEM == "KEYGEN_REQUIRED" {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		wasBlocked := Current().State.Blocked()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				info := verifiedTick(licPath)
				current.Store(info)
				nowBlocked := info.State.Blocked()
				if nowBlocked && !wasBlocked && onLock != nil {
					onLock()
				}
				wasBlocked = nowBlocked
			}
		}
	}()
}

// verifiedTick runs one verify-and-evaluate cycle, collapsing every
// failure mode (unreadable file, bad signature, tampered field,
// malformed expiry) into StateInvalid rather than propagating an error
// the caller might be tempted to swallow into "keep the old state".
func verifiedTick(licPath string) Info {
	lic, err := VerifiedRead(licPath)
	if err != nil {
		log.Printf("[license] monitor: verification failed: %v — treating license as invalid", err)
		return Info{State: StateInvalid}
	}
	info, err := Evaluate(lic, time.Now().UTC())
	if err != nil {
		log.Printf("[license] monitor: re-evaluate failed: %v — treating license as invalid", err)
		return Info{State: StateInvalid}
	}
	return info
}
