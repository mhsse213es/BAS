package adefficacy

import (
	"github.com/audspect/bas/internal/adcontrolval"
	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/controlval"
)

// Principal identities under test (match the runbook section 3.3).
const (
	PrincipalAttacker = "attacker" // positive control: replication rights granted
	PrincipalLabuser  = "labuser"  // negative control: no replication rights
)

// DCSyncPrimitive returns the real catalog dcsync primitive (T1003.006).
func DCSyncPrimitive() adprimitive.Primitive {
	for _, p := range adprimitive.DCSyncCatalog {
		if p.ID == "dcsync" {
			return p
		}
	}
	return adprimitive.Primitive{ID: "dcsync"} // defensive; catalog always has it
}

// KeyFor builds the correlation key for a DCSync attempt in a given run. Each
// principal runs under its own runID, so the key identifies the attempt.
func KeyFor(runID, target string, window controlval.TimeWindow) controlval.CorrelationKey {
	return adcontrolval.CorrelationKeyFor(DCSyncPrimitive(), runID, target, window)
}

// NegativeExpectation is the labuser case: no rights, so DCSync must be blocked.
func NegativeExpectation() controlval.Expectation {
	return controlval.Expectation{
		Expected:       controlval.OutcomeBlocked,
		PolicyBasis:    "LAB\\labuser holds neither DS-Replication-Get-Changes nor -All on the domain head",
		PolicyVerified: false,
		MinConfidence:  controlval.ConfidenceHigh,
	}
}

// PositiveExpectation is the attacker case: rights granted, so DCSync succeeds.
func PositiveExpectation() controlval.Expectation {
	return controlval.Expectation{
		Expected:       controlval.OutcomeAllowed,
		PolicyBasis:    "LAB\\attacker deliberately granted DS-Replication-Get-Changes[-All] (positive control)",
		PolicyVerified: false,
		MinConfidence:  controlval.ConfidenceHigh,
	}
}
