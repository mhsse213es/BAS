package dbprobe

import (
	"context"
	"fmt"
	"time"
)

// Policy is the agent-local policy input to CheckSpec. Both flags default off
// and are never set from the dispatched spec.
type Policy struct {
	// ClientEnabled permits client mode (read-only role + read-only probes).
	ClientEnabled bool
	// LabMutationAllowed permits non-read_only probes in lab mode.
	LabMutationAllowed bool
}

// CheckSpec is the agent-side safety gate (spec section 8, R4, R6, R8). It
// runs before any connection is opened.
//
//   - The probe must exist in the catalog (the only source of a probe's class)
//     and def must agree with it; unknown ids are rejected in every mode.
//   - The observed target identity (PG system_identifier / MySQL server_uuid)
//     must be non-empty and equal the pre-registered expectedIdentity exactly,
//     in every mode (never trust on first use).
//   - Client mode needs Policy.ClientEnabled and only runs read_only probes.
//   - Lab mode runs read_only probes on identity alone; any other class also
//     needs Policy.LabMutationAllowed, so a dispatch alone cannot mutate.
func CheckSpec(spec DBProbeSpec, def ProbeDef, observedIdentity string, expectedIdentity string, p Policy) error {
	if def.ID != spec.ProbeID {
		return fmt.Errorf("dbprobe: gate: probe definition %q does not match spec probe %q", def.ID, spec.ProbeID)
	}
	real, ok := LookupProbe(spec.ProbeID)
	if !ok {
		return fmt.Errorf("dbprobe: gate: unknown probe %q", spec.ProbeID)
	}
	if real.Class != def.Class {
		return fmt.Errorf("dbprobe: gate: probe %q definition class %q disagrees with catalog class %q",
			spec.ProbeID, def.Class, real.Class)
	}
	class := real.Class
	if expectedIdentity == "" || observedIdentity == "" {
		return fmt.Errorf("dbprobe: gate: target identity and registered identity must both be present")
	}
	if observedIdentity != expectedIdentity {
		return fmt.Errorf("dbprobe: gate: target identity does not match the registered identity")
	}
	// A fixture-aware probe reads a per-run seeded fixture, which exists only in
	// lab mode; it is refused elsewhere whatever its class says.
	if real.FixtureParam != "" && spec.Mode != ModeLab {
		return fmt.Errorf("dbprobe: gate: %s mode refuses fixture-aware probe %q (lab only)", spec.Mode, spec.ProbeID)
	}
	// R-AI: a run that seeds a fixture mutates the lab database, so any step that
	// names one is gated as a mutation whatever the probe's own class says.
	mutates := class != ClassReadOnly || spec.FixtureID != ""
	switch spec.Mode {
	case ModeLab:
		if mutates && !p.LabMutationAllowed {
			return fmt.Errorf("dbprobe: gate: lab mode refuses %s probe %q (fixture %q) without local mutation allowance", class, spec.ProbeID, spec.FixtureID)
		}
	case ModeClient:
		if !p.ClientEnabled {
			return fmt.Errorf("dbprobe: gate: client mode is disabled on this agent")
		}
		if mutates {
			return fmt.Errorf("dbprobe: gate: client mode refuses %s probe %q", class, spec.ProbeID)
		}
	default:
		return fmt.Errorf("dbprobe: gate: invalid mode %q", spec.Mode)
	}
	return nil
}

// Budget enforces the per-probe row budget from Limits.MaxRows.
type Budget struct {
	max  int
	used int
}

// NewBudget returns a Budget for the given limits.
func NewBudget(l Limits) *Budget { return &Budget{max: l.MaxRows} }

// Charge records rows read and fails once the cumulative total exceeds the
// maximum. A failed charge is not recorded.
func (b *Budget) Charge(rows int) error {
	if rows < 0 {
		return fmt.Errorf("dbprobe: budget: negative row charge %d", rows)
	}
	if rows > b.max-b.used {
		return fmt.Errorf("dbprobe: budget: row limit %d exceeded", b.max)
	}
	b.used += rows
	return nil
}

// Used returns rows charged so far.
func (b *Budget) Used() int { return b.used }

// WithDeadline derives a context bounded by Limits.TimeoutSec. A zero or
// negative timeout yields an already-expired context.
func WithDeadline(ctx context.Context, l Limits) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, time.Duration(l.TimeoutSec)*time.Second)
}
