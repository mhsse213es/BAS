package license

import (
	"fmt"
	"time"
)

// State is one of the three license enforcement states.
type State string

const (
	StateValid State = "valid"
	StateGrace State = "grace"
	// StateLocked is a correctly-signed, genuinely-verified license whose
	// grace period has elapsed -- produced only by Evaluate.
	StateLocked State = "locked"
	// StateInvalid means the license file could not be verified at all:
	// missing, unreadable, malformed, or signed incorrectly (including a
	// well-formed file whose fields were edited after signing). It is
	// never produced by Evaluate -- only VerifiedRead's callers (Check,
	// StartMonitor) assign it directly, on verification failure. Enforced
	// identically to StateLocked (see State.Blocked), but tracked
	// separately so diagnostics/support can tell "tampered or unreadable"
	// apart from "a real license's grace period ran out".
	StateInvalid State = "invalid"
)

// Blocked reports whether s should block protected operations. StateLocked
// and StateInvalid both mean "no access"; StateValid and StateGrace both
// mean normal access (grace only warns, see monitor.go/main.go's log
// lines). Every enforcement point in this codebase should gate on this
// method rather than comparing against StateLocked directly, so a new
// blocking state never requires hunting down every call site again.
func (s State) Blocked() bool {
	return s == StateLocked || s == StateInvalid
}

// GracePeriodDays is fixed, not per-license-configurable — see
// docs/superpowers/specs/2026-08-14-license-grace-period-design.md.
const GracePeriodDays = 5

// Info is a point-in-time evaluation of a license's enforcement state.
type Info struct {
	State         State
	Customer      string
	ExpiresAt     time.Time
	LockoutAt     time.Time
	DaysRemaining int // 0 unless State == StateGrace
	// Tier is the licence tier the state grants. Empty grants nothing, so a state built without a
	// tier fails closed in PermitsNow.
	Tier Tier
}

// Evaluate computes the enforcement state of lic as of now. now is an
// explicit parameter (not time.Now()) so this stays a pure function —
// callers pass time.Now() in production and fixed instants in tests.
//
// lic.ExpiresAt is a date-only string ("2006-01-02"); the existing signed
// license payload cannot change, so the exact instant is derived as the
// end of that calendar day in UTC (23:59:59), not midnight — this keeps
// a customer's license valid through the entire day printed on it,
// regardless of the timezone they're actually in.
func Evaluate(lic *License, now time.Time) (Info, error) {
	expiryDate, err := time.Parse("2006-01-02", lic.ExpiresAt)
	if err != nil {
		return Info{}, fmt.Errorf("license: invalid expiry date: %w", err)
	}
	expiresAt := time.Date(
		expiryDate.Year(), expiryDate.Month(), expiryDate.Day(),
		23, 59, 59, 0, time.UTC,
	)
	lockoutAt := expiresAt.Add(GracePeriodDays * 24 * time.Hour)

	info := Info{
		Customer:  lic.Customer,
		Tier:      lic.EffectiveTier(),
		ExpiresAt: expiresAt,
		LockoutAt: lockoutAt,
	}

	switch {
	case now.Before(expiresAt):
		info.State = StateValid
	case now.Before(lockoutAt):
		info.State = StateGrace
		remaining := lockoutAt.Sub(now)
		info.DaysRemaining = int(remaining/(24*time.Hour)) + 1 // ceil, and never 0 while still in grace
	default:
		info.State = StateLocked
	}
	return info, nil
}
