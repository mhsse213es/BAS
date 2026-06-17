// Package findings holds the pure logic behind the persistent findings store:
// mapping a technique's ATT&CK data sources to an expected control class, and
// the state machine that turns a stream of per-run observations into a single,
// de-duplicated, analyst-triaged finding (create / recur / refine / auto-heal /
// reopen), with out-of-order and idempotency guards. No I/O — the API layer maps
// DB rows to State and persists the result.
package findings

import (
	"strings"
	"time"
)

// ControlClass maps a technique's ATT&CK data sources to the expected control
// class. First match in priority order wins (Identity > Network > DNS > Cloud >
// Endpoint); Endpoint is the default. Stable per technique so it can anchor the
// dedup key.
func ControlClass(dataSources []string) string {
	joined := strings.ToLower(strings.Join(dataSources, " | "))
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(joined, s) {
				return true
			}
		}
		return false
	}
	switch {
	case has("logon session", "active directory", "user account", "authentication"):
		return "Identity"
	case has("network traffic", "network connection", "network flow", "network share"):
		return "Network"
	case has("domain name", "dns"):
		return "DNS"
	case has("cloud service", "cloud storage", "saas", "instance", "snapshot"):
		return "Cloud"
	default:
		return "Endpoint"
	}
}

// Transition names the state change Apply produced, so the caller can react
// (e.g. stamp resolved fields on Healed).
type Transition string

const (
	Noop     Transition = "noop"
	Created  Transition = "created"
	Recurred Transition = "recurred"
	Refined  Transition = "refined"
	Healed   Transition = "healed"
	Reopened Transition = "reopened"
	Stale    Transition = "stale"
)

// Observation is one run's outcome for a (technique, control) on an agent.
type Observation struct {
	Outcome    string // "prevented" | "missed" | "detected_only"
	RunID      string
	ObservedAt time.Time
}

// State is the persisted finding projection (Exists=false → no row yet).
type State struct {
	Exists          bool
	Status          string // open | triaged | remediated | risk_accepted
	ExposureState   string // missed | detected_only
	OccurrenceCount int
	ReopenedCount   int
	LastRunID       string
	LastObservedAt  time.Time
	Resolved        bool // resolved_at is set
}

// worse returns the more severe exposure (missed beats detected_only).
func worse(a, b string) string {
	if a == "missed" || b == "missed" {
		return "missed"
	}
	return "detected_only"
}

// Apply runs the finding state machine. Returns the next state and the
// transition. A prevented observation against a non-existent finding is a Noop.
func Apply(s State, o Observation) (State, Transition) {
	gap := o.Outcome == "missed" || o.Outcome == "detected_only"

	if !s.Exists {
		if !gap {
			return s, Noop // nothing to heal
		}
		return State{
			Exists: true, Status: "open", ExposureState: o.Outcome,
			OccurrenceCount: 1, LastRunID: o.RunID, LastObservedAt: o.ObservedAt,
		}, Created
	}

	// Same-run refinement (e.g. detection arrives after results): latest signal
	// wins for exposure, no occurrence change, never stale.
	if o.RunID == s.LastRunID {
		if gap {
			s.ExposureState = o.Outcome
			return s, Refined
		}
		return s, Noop
	}

	// Out-of-order guard: an older run never overwrites newer state or heals.
	if !o.ObservedAt.After(s.LastObservedAt) {
		return s, Stale
	}

	s.LastRunID = o.RunID
	s.LastObservedAt = o.ObservedAt

	// risk_accepted is sticky: record recurrence but never auto-transition.
	if s.Status == "risk_accepted" {
		if gap {
			s.OccurrenceCount++
			s.ExposureState = worse(s.ExposureState, o.Outcome)
			return s, Recurred
		}
		return s, Noop
	}

	if !gap { // prevented in a newer run
		if s.Status == "remediated" {
			return s, Noop
		}
		s.Status = "remediated"
		s.Resolved = true
		return s, Healed
	}

	// A gap in a newer run.
	if s.Status == "remediated" {
		s.Status = "open"
		s.Resolved = false
		s.ReopenedCount++
		s.OccurrenceCount++
		s.ExposureState = o.Outcome
		return s, Reopened
	}
	s.OccurrenceCount++
	s.ExposureState = worse(s.ExposureState, o.Outcome)
	return s, Recurred
}
