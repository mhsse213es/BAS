package dbprobe

import (
	"context"
	"fmt"
	"time"
)

// CheckSpec is the agent-side safety gate (spec section 8, R4, R6, R8). It
// runs before any connection is opened.
//
//   - Target identity (PG system_identifier / MySQL server_uuid) must match the
//     pre-registered expectedIdentity exactly. Client mode additionally
//     refuses an empty expectedIdentity: it never trusts on first use.
//   - Client mode is hard-refused unless clientEnabled (a local agent policy
//     flag, default off).
//   - Client mode only runs read_only probes. The class is taken from the
//     probe's real catalog entry, never from what the spec or scenario label
//     claims; if def disagrees with the catalog, the stricter reading wins
//     and a disagreement is itself rejected.
func CheckSpec(spec DBProbeSpec, def ProbeDef, observedIdentity string, expectedIdentity string, clientEnabled bool) error {
	if def.ID != spec.ProbeID {
		return fmt.Errorf("dbprobe: gate: probe definition %q does not match spec probe %q", def.ID, spec.ProbeID)
	}
	class := def.Class
	if real, ok := LookupProbe(spec.ProbeID); ok {
		if real.Class != def.Class {
			return fmt.Errorf("dbprobe: gate: probe %q definition class %q disagrees with catalog class %q",
				spec.ProbeID, def.Class, real.Class)
		}
		class = real.Class
	}
	if observedIdentity != expectedIdentity {
		return fmt.Errorf("dbprobe: gate: target identity does not match the registered identity")
	}
	switch spec.Mode {
	case ModeLab:
	case ModeClient:
		if !clientEnabled {
			return fmt.Errorf("dbprobe: gate: client mode is disabled on this agent")
		}
		if expectedIdentity == "" {
			return fmt.Errorf("dbprobe: gate: client mode requires a pre-registered target identity")
		}
		if class != ClassReadOnly {
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
	if b.used+rows > b.max {
		return fmt.Errorf("dbprobe: budget: row limit %d exceeded", b.max)
	}
	b.used += rows
	return nil
}

// Used returns rows charged so far.
func (b *Budget) Used() int { return b.used }

// WithDeadline derives a context bounded by Limits.TimeoutSec.
func WithDeadline(ctx context.Context, l Limits) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, time.Duration(l.TimeoutSec)*time.Second)
}
