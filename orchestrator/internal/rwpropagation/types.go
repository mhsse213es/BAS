// Package rwpropagation joins three evidence sources -- AD-mastery graph
// reachability (admatrix), lateral-movement execution/discovery evidence
// (latmove), and ransomware-payload containment evidence (rwevidence, via
// db.RWAttemptRow) -- into one report for a single simulated propagation
// incident. Pure Go, no I/O: it imports internal/db, internal/latmove,
// internal/admatrix, internal/adprimitive, and internal/controlval only
// for their types, mirroring internal/rwresponse's own precedent of
// importing internal/db for RWAttemptRow's type without ever calling the
// database. See docs/superpowers/specs/2026-10-12-cross-module-propagation-join-design.md.
package rwpropagation

import (
	"time"

	"github.com/audspect/bas/internal/admatrix"
	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/latmove"
)

// AssessmentContext identifies the single simulated incident a Report
// covers. RunID ties the ransomware leg to rwevidence's run-scoped rows;
// AssessmentID is the correlation anchor for the AD and lateral-movement
// legs, which have no run-scoped store to anchor them instead.
type AssessmentContext struct {
	AssessmentID string
	RunID        string
}

// ADReachability is one admatrix.Simulate result, carried through with
// its validation level explicit. Level is always admatrix.LevelModelSimulated
// today -- a simulated graph-reachability answer, never a claim that a
// real account can reach a live target.
type ADReachability struct {
	Target    adprimitive.Capability
	Reachable bool
	Steps     []adprimitive.Primitive
	Level     admatrix.ValidationLevel
}

// LateralMovementAccess is one latmove discovery result. Condition is
// preserved exactly (Granted/Denied/Unknown) -- never collapsed to a
// bool, and never read as if it were an ADReachability.Reachable value
// or vice versa. AD authorization and OS/network reachability are
// different questions; conflating them is exactly the
// segmentation-effectiveness mistake this package exists to avoid.
type LateralMovementAccess struct {
	Technique   latmove.Technique
	Principal   string
	Destination string
	Condition   latmove.AccessCondition
}

// LateralMovementExecution is one latmove attempt's classified outcome.
type LateralMovementExecution struct {
	Key    latmove.AttemptKey
	Result latmove.AttemptResult
}

// TechniqueContainmentStatus distinguishes WHY a technique's containment
// entry has no real verdict, when it has none -- three semantically
// different situations that must never be collapsed into one another.
type TechniqueContainmentStatus string

const (
	// ContainmentStatusEvaluated means a real PASS/FAIL/ERROR containment
	// row exists for this technique: a genuine verdict was reached.
	ContainmentStatusEvaluated TechniqueContainmentStatus = "evaluated"
	// ContainmentStatusNotApplicable means rwevidence itself decided
	// containment does not apply to this technique (a SKIPPED row with
	// SkipReason == not_applicable exists) -- a decided "no", not a gap.
	ContainmentStatusNotApplicable TechniqueContainmentStatus = "not_applicable"
	// ContainmentStatusNotInstrumented means this technique was attempted
	// in the run (it appears in the ransomware rows under some OTHER
	// capability) but carries ZERO containment-capability rows at all --
	// an instrumentation gap, never silently dropped or treated as a
	// negative (FAIL) result.
	ContainmentStatusNotInstrumented TechniqueContainmentStatus = "not_instrumented"
)

// RansomwareContainment is one ransomware technique's containment
// evidence. Scope note, load-bearing: this measures containment of the
// SPECIFIC ransomware capability attempt only -- never a claim about the
// AD or lateral-movement legs, which have no containment observer at
// all (see ContainmentNoObserver below). Verdict and CreatedAt are
// zero-valued when Status == ContainmentStatusNotInstrumented.
type RansomwareContainment struct {
	TechniqueID string
	Status      TechniqueContainmentStatus
	Verdict     controlval.Verdict
	Reason      string
	CreatedAt   time.Time
}

// ContainmentAvailability distinguishes "this leg has at least one
// technique-level entry to report" from "there is no observer for this
// leg at all" -- the latter is not a verdict, it is an honest statement
// that nothing in this codebase can answer the question yet.
type ContainmentAvailability string

const (
	ContainmentMeasured   ContainmentAvailability = "measured"
	ContainmentNoObserver ContainmentAvailability = "no_observer"
)

// LegContainment pairs a propagation leg with its containment
// availability and, only when Measured, one entry per distinct
// TechniqueID attempted on that leg. Never one value standing in for
// several techniques: T1486's containment outcome must never be read as
// speaking for T1490's, T1567.002's, or T1560.001's.
type LegContainment struct {
	Leg          string // "ad" | "lateral_movement" | "ransomware_payload"
	Availability ContainmentAvailability
	Containment  []RansomwareContainment
}

// TimeToIsolateStatus mirrors rwresponse.ResponseLatencyStatus's
// semantics exactly: a fixed status, never a computed duration, because
// no causal link between a detection event and an isolation action
// exists anywhere in this codebase today. Reused rather than reinvented.
type TimeToIsolateStatus string

const TimeToIsolateNotEstablishable TimeToIsolateStatus = "not_establishable"
