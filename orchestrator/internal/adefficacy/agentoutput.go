package adefficacy

import (
	"context"
	"strings"

	"github.com/audspect/bas/internal/controlval"
)

// ParseDRSUAPIResult classifies a single step's recorded output text (the
// agent's own stdout, as produced by the DCSync live-verification scenario's
// PowerShell) into the primary DRSUAPI evidence. It recognizes only the
// scenario's own fixed phrasing; anything it does not recognize -- a SKIP
// line, an unrelated step, empty text -- returns ok=false rather than
// guessing a result.
func ParseDRSUAPIResult(details string) (DRSUAPIResult, bool) {
	switch {
	case !strings.HasPrefix(details, "EXEC T1003.006:"):
		return "", false
	case strings.Contains(details, "inconclusive"):
		return DRSUAPIIndeterminate, true
	case strings.Contains(details, "was refused"):
		return DRSUAPIAccessDenied, true
	case strings.Contains(details, "returned account data"):
		return DRSUAPISucceeded, true
	default:
		return "", false
	}
}

// StepDetailsLookup is the seam to stored scenario-run results. A real
// implementation reads a run's SimulationResult.Details for the step whose
// action this key names; it performs the I/O, this package never does.
type StepDetailsLookup interface {
	DetailsFor(ctx context.Context, runID, action string) (details string, found bool, err error)
}

// AgentOutputDecisionSource is the real ControlDecisionSource for the DCSync
// live-verification scenario: it reads the agent's own recorded step output
// and classifies it via ParseDRSUAPIResult. It never calls a live DC itself --
// the scenario already did that; this only interprets what came back.
//
// It does not yet read Windows Security Event 4662 (the secondary,
// corroboration-only signal) -- Audit4662 is always CorroborationUnknown.
// DRSUAPI alone remains the sole determinant of Outcome (see provider.go), so
// this is a complete, correct source as-is; a later addition can enrich
// Detail/Audit4662 without changing any Outcome this produces today.
type AgentOutputDecisionSource struct {
	Lookup StepDetailsLookup
}

func (s *AgentOutputDecisionSource) Decision(ctx context.Context, key controlval.CorrelationKey) (ControlDecision, error) {
	details, found, err := s.Lookup.DetailsFor(ctx, key.RunID, key.Action)
	if err != nil {
		return ControlDecision{}, err
	}
	if !found {
		return ControlDecision{DRSUAPI: DRSUAPIIndeterminate, Audit4662: CorroborationUnknown, Correlated: false, Detail: "no stored step result for this run/action"}, nil
	}
	result, ok := ParseDRSUAPIResult(details)
	if !ok {
		return ControlDecision{DRSUAPI: DRSUAPIIndeterminate, Audit4662: CorroborationUnknown, Correlated: false, Detail: details}, nil
	}
	return ControlDecision{DRSUAPI: result, Audit4662: CorroborationUnknown, Correlated: true, Detail: details}, nil
}
