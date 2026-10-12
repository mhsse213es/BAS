// Package adefficacy is the first real control-efficacy vertical: it validates
// whether AD's native directory-replication-rights control prevents DCSync by
// an unauthorized principal. It is thin and lab-gated -- it ships a fake-backed
// ControlDecisionSource only; the real source (reading a live DC via
// adlabhyperv) and any CapabilityStates()/dispatchRun wiring are deferred until
// a lab run is authorized.
package adefficacy

import (
	"context"
	"time"

	"github.com/audspect/bas/internal/controlval"
)

// DRSUAPIResult is the PRIMARY enforcement evidence: the replication call's own
// result. It alone determines the control Outcome.
type DRSUAPIResult string

const (
	DRSUAPIAccessDenied  DRSUAPIResult = "access_denied"
	DRSUAPISucceeded     DRSUAPIResult = "succeeded"
	DRSUAPIIndeterminate DRSUAPIResult = "indeterminate"
)

// Corroboration is the SECONDARY signal (Windows Security event 4662). It may
// support a result but NEVER establishes an outcome on its own.
type Corroboration string

const (
	Corroborated         Corroboration = "corroborated"
	Uncorroborated       Corroboration = "uncorroborated"
	CorroborationUnknown Corroboration = "unknown"
)

// ControlDecision is the native AD control's enforcement decision for one
// DCSync attempt, as read from the lab.
type ControlDecision struct {
	DRSUAPI    DRSUAPIResult
	Audit4662  Corroboration
	Correlated bool
	Detail     string
}

// ControlDecisionSource is the seam the real lab implements to report a DC's
// enforcement decision. A fake implements it for tests; no real implementation
// ships in this slice.
type ControlDecisionSource interface {
	Decision(ctx context.Context, key controlval.CorrelationKey) (ControlDecision, error)
}

// NativeADProvider adapts a ControlDecisionSource to controlval.Provider.
type NativeADProvider struct {
	Src   ControlDecisionSource
	Clock func() time.Time
}

// Name identifies this provider.
func (p *NativeADProvider) Name() string { return "native-ad" }

// Observe reads the DC's decision and maps it to a controlval.Observation. The
// DRSUAPI result is the sole determinant of Outcome; the 4662 corroboration
// only affects Detail, never the outcome, and never raises/establishes it.
func (p *NativeADProvider) Observe(ctx context.Context, key controlval.CorrelationKey) (controlval.Observation, error) {
	d, err := p.Src.Decision(ctx, key)
	if err != nil {
		return controlval.Observation{}, err
	}
	obs := controlval.Observation{
		Key:          key,
		Provider:     p.Name(),
		EvidenceKind: controlval.EvidenceObserved,
		Confidence:   confidenceFor(d),
		Source:       "drsuapi+4662",
		Detail:       d.Detail + " [4662=" + string(d.Audit4662) + "]",
	}
	if p.Clock != nil {
		obs.ObservedAt = p.Clock()
	}
	switch d.DRSUAPI {
	case DRSUAPIAccessDenied:
		obs.Outcome = controlval.OutcomeBlocked
	case DRSUAPISucceeded:
		obs.Outcome = controlval.OutcomeAllowed
	default:
		obs.Outcome = controlval.OutcomeUnknown
	}
	return obs, nil
}

// confidenceFor grades correlation + primary-evidence quality. DRSUAPI is
// authoritative: a conclusive, correlated result is High regardless of 4662.
// Anything short fails closed to None.
func confidenceFor(d ControlDecision) controlval.Confidence {
	if !d.Correlated || d.DRSUAPI == DRSUAPIIndeterminate {
		return controlval.ConfidenceNone
	}
	return controlval.ConfidenceHigh
}
