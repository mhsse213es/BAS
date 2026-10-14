// Package adgate is AD executable-content sub-project B: a pure, fail-closed
// policy that decides whether an action may run against a given environment.
// It is DISTINCT from classification -- scenario.ExecutionClass says what an
// action is; adgate says whether this action may run in this environment now.
// It executes nothing and is not wired into dispatch; turning this decision
// into an enforced control is sub-project D. Depends one-way on scenario.
package adgate

import "github.com/audspect/bas/internal/scenario"

type provenanceKind int

const (
	provUnknown provenanceKind = iota // zero value -> fail closed
	provSynthetic
	provLiveAD
	provVerifiedLab
)

// Provenance records where an environment came from. It is unforgeable by
// struct literal: the kind field is unexported, so a plain Provenance{} is
// Unknown, which denies. A synthetic value is obtainable only via
// SyntheticProvenance, called by environment producers at origin.
type Provenance struct {
	kind     provenanceKind
	runID    string // set only for provVerifiedLab: run-binding
	targetID string // set only for provVerifiedLab: target-binding
}

// SyntheticProvenance mints the synthetic stamp. Producers call it at the
// environment's point of origin (in v1, adlab.SyntheticProvider).
func SyntheticProvenance() Provenance { return Provenance{kind: provSynthetic} }

// LiveADProvenance marks a real/live AD environment. Such environments deny
// in B; a live-authorization policy is a future sub-project.
func LiveADProvenance() Provenance { return Provenance{kind: provLiveAD} }

// VerifiedControlledLabProvenance marks a real environment the lab-runtime has
// provisioned AND independently verified as isolated. It is minted only by the
// lab-runtime, after verification, and is bound to a specific run and target --
// so verified isolation can be allowed without opening the door to uncontrolled
// live AD. It still carries no authorization: Decide requires Auth separately.
func VerifiedControlledLabProvenance(runID, targetID string) Provenance {
	return Provenance{kind: provVerifiedLab, runID: runID, targetID: targetID}
}

// BoundTo reports whether this is a verified-controlled-lab provenance minted
// for exactly this run and target. Non-lab provenance is never bound.
func (p Provenance) BoundTo(runID, targetID string) bool {
	return p.kind == provVerifiedLab && p.runID == runID && p.targetID == targetID
}

// Authorization is the operator consent / policy context the caller supplies.
type Authorization struct {
	Authorized          bool // operator consented to this controlled run
	DestructiveApproved bool // extra consent required for a destructive-class action
}

// Request is one gate query.
type Request struct {
	Class scenario.ExecutionClass // consumed, never re-derived
	Env   Provenance
	Auth  Authorization
}

// Reason is a stable, machine-readable decision reason.
type Reason string

const (
	ReasonAllowedSyntheticAuthorized     Reason = "allowed_synthetic_authorized"
	ReasonAllowedControlledLabAuthorized Reason = "allowed_controlled_lab_authorized"
	ReasonDeniedNotSynthetic             Reason = "denied_environment_not_synthetic"
	ReasonDeniedUnknownClass             Reason = "denied_unknown_classification"
	ReasonDeniedMissingAuth              Reason = "denied_missing_authorization"
	ReasonDeniedDestructiveNotApproved   Reason = "denied_destructive_not_approved"
)

// Decision is the gate's answer.
type Decision struct {
	Allowed bool
	Reason  Reason
}

// Decide applies the fail-closed rule order; the first failing rule wins.
func Decide(req Request) Decision {
	if req.Env.kind != provSynthetic && req.Env.kind != provVerifiedLab {
		return deny(ReasonDeniedNotSynthetic)
	}
	if !knownClass(req.Class) {
		return deny(ReasonDeniedUnknownClass)
	}
	if !req.Auth.Authorized {
		return deny(ReasonDeniedMissingAuth)
	}
	if req.Class == scenario.ClassDestructive && !req.Auth.DestructiveApproved {
		return deny(ReasonDeniedDestructiveNotApproved)
	}
	if req.Env.kind == provVerifiedLab {
		return Decision{Allowed: true, Reason: ReasonAllowedControlledLabAuthorized}
	}
	return Decision{Allowed: true, Reason: ReasonAllowedSyntheticAuthorized}
}

func deny(r Reason) Decision { return Decision{Allowed: false, Reason: r} }

func knownClass(c scenario.ExecutionClass) bool {
	switch c {
	case scenario.ClassNonDestructive, scenario.ClassPotentiallyDestructive, scenario.ClassDestructive:
		return true
	default:
		return false
	}
}
