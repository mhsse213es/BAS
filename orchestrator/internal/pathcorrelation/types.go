// Package pathcorrelation joins three existing subsystems — the attack-path
// graph engine (internal/attackpath), the Detection Rule Library
// (internal/rulelib), and Detection Verification (internal/verification via
// its verification_history table) — to answer: for a dangerous lateral-
// movement path through the environment, would we actually catch the
// attacker? It is a pure consumer: it does not modify any of the three
// subsystems' own scoring or state, and owns no database tables.
package pathcorrelation

import (
	"context"
	"time"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/rulelib"
)

// ExpectedStatus says whether the Rule Library has a rule for a technique,
// independent of whether that rule has ever been proven to fire.
type ExpectedStatus string

const (
	ExpectedCovered ExpectedStatus = "covered"
	ExpectedGap     ExpectedStatus = "gap"
)

// VerifiedStatus says whether a technique has actually been proven detected
// by a real simulation run, independent of whether a rule exists for it.
type VerifiedStatus string

const (
	VerifiedCovered VerifiedStatus = "covered"
	VerifiedPartial VerifiedStatus = "partial" // some but not all mapped techniques verified
	VerifiedGap     VerifiedStatus = "gap"     // none verified, but Expected is Covered
	VerifiedUnknown VerifiedStatus = "unknown" // none verified, and no rule exists either
)

// VerificationConfidence says WHERE verified evidence came from.
type VerificationConfidence string

const (
	ConfidenceHost        VerificationConfidence = "host"
	ConfidenceEnvironment VerificationConfidence = "environment"
	ConfidenceUnknown     VerificationConfidence = "unknown"
)

// GapPriority values are exact matches for internal/reporting/html.go's
// exposureColor template func — do not lowercase these.
type GapPriority string

const (
	PriorityCritical GapPriority = "Critical"
	PriorityHigh     GapPriority = "High"
	PriorityMedium   GapPriority = "Medium"
	PriorityLow      GapPriority = "Low"
)

// Evidence is why a technique's status is what it is. InvestigationURL is not
// populated in this slice — verification.Record carries no such field today;
// a future connector slice can add it once it exists.
type Evidence struct {
	RuleIDs    []string   `json:"ruleIds,omitempty"`
	AlertIDs   []string   `json:"alertIds,omitempty"`
	RunID      string     `json:"runId,omitempty"`
	VerifiedAt *time.Time `json:"verifiedAt,omitempty"`
	Provider   string     `json:"provider,omitempty"`
}

// DetectionStatus is the combined expected/verified status of every
// technique mapped to one graph edge.
type DetectionStatus struct {
	Techniques []TechniqueMapping     `json:"techniques"`
	Expected   ExpectedStatus         `json:"expected"`
	Verified   VerifiedStatus         `json:"verified"`
	Confidence VerificationConfidence `json:"confidence"`
	Evidence   Evidence               `json:"evidence,omitempty"`
}

// AnnotatedEdge is one graph edge plus its combined DetectionStatus.
type AnnotatedEdge struct {
	Edge   attackpath.Edge `json:"edge"`
	Status DetectionStatus `json:"status"`
}

// AttackPath is a named sequence of edges to correlate — the Domain-Admin
// path, a crown-jewel path (see DefaultPaths), or a path a future caller
// (e.g. Exposure Explorer) supplies directly. Weight is this path's
// contribution to DetectionCoverageScore; the producer of the path sets it
// (DefaultPaths sets it for this slice's two path kinds).
type AttackPath struct {
	Label  string            `json:"label"`
	Edges  []attackpath.Edge `json:"-"`
	Weight float64           `json:"-"`
}

// AnnotatedPath is an AttackPath with every edge's DetectionStatus attached.
type AnnotatedPath struct {
	Label       string          `json:"label"`
	Edges       []AnnotatedEdge `json:"edges"`
	WeakestLink *AnnotatedEdge  `json:"weakestLink,omitempty"`
	Weight      float64         `json:"-"`
}

// AnnotatedChokePoint is an attackpath.ChokePoint plus every edge feeding
// into it (via attackpath.Graph.EdgesTo), annotated.
type AnnotatedChokePoint struct {
	ChokePoint    attackpath.ChokePoint `json:"chokePoint"`
	IncomingEdges []AnnotatedEdge       `json:"incomingEdges"`
	WeakestLink   *AnnotatedEdge        `json:"weakestLink,omitempty"`
}

// PrioritizedGap is one edge whose Verified status is not Covered, ranked by
// an internal (unexported, unserialized) score derived from path frequency,
// proximity to a high-value target, technique criticality, and how bad the
// gap is.
type PrioritizedGap struct {
	Edge        attackpath.Edge    `json:"edge"`
	Techniques  []TechniqueMapping `json:"techniques"`
	Priority    GapPriority        `json:"priority"`
	Reason      string             `json:"reason"`
	Remediation string             `json:"remediation"`
	score       float64
}

// Statistics summarizes the canonical edge set (deduplicated by
// From+To+Kind across every correlated path and choke point).
type Statistics struct {
	EdgesTotal           int              `json:"edgesTotal"`
	ExpectedCovered      int              `json:"expectedCovered"`
	ExpectedGap          int              `json:"expectedGap"`
	VerifiedCovered      int              `json:"verifiedCovered"`
	VerifiedPartial      int              `json:"verifiedPartial"`
	VerifiedGap          int              `json:"verifiedGap"`
	VerifiedUnknown      int              `json:"verifiedUnknown"`
	HighestRiskTechnique string           `json:"highestRiskTechnique,omitempty"`
	HighestRiskEdge      *attackpath.Edge `json:"highestRiskEdge,omitempty"`
}

// AttackPathCorrelation is named for extensibility: future slices (Exposure
// Explorer, Asset Criticality) can add fields to this same object without a
// redesign. The report renders it under the title "Attack Path Detection
// Coverage".
type AttackPathCorrelation struct {
	Summary string `json:"summary"`
	Score   int    `json:"detectionCoverageScore"`
	// Measurable is false when there were no weighted attack paths to score
	// at all -- i.e. no attack-path collection has run yet, or the graph
	// yielded no path to a Domain Admin or crown jewel. Score is a hardcoded
	// 100 in that case (a pure-deficit model over an empty set: no paths ->
	// no deficit -> "perfect"), which is NOT a real result and must never be
	// presented as one -- an endpoint nothing is known about would otherwise
	// read as flawlessly defended. Consumers must check this before
	// displaying Score or folding it into any aggregate.
	Measurable  bool                  `json:"measurable"`
	Paths       []AnnotatedPath       `json:"paths"`
	ChokePoints []AnnotatedChokePoint `json:"chokePoints"`
	Gaps        []PrioritizedGap      `json:"gaps"`
	Statistics  Statistics            `json:"statistics"`
}

// VerificationResult is what a RunLookup returns for a found match.
type VerificationResult struct {
	Confidence VerificationConfidence
	Evidence   Evidence
}

// RunLookup answers "has this technique been verified as detected, on this
// host or anywhere in the environment?" hostname == "" searches every host.
// SQLRunLookup (runlookup.go) is the production implementation; tests use a
// fake.
type RunLookup interface {
	VerifiedDetection(ctx context.Context, techniqueID, hostname string) (VerificationResult, bool, error)
}

// RuleLibrary is the slice of the SP2 Rule Library engine pathcorrelation
// needs. *rulelib.Engine satisfies it; tests substitute a fake. Declared as
// an interface (not the concrete *rulelib.Engine) so a nil *rulelib.Engine
// passed in by a careless caller is caught at the call site instead of
// silently becoming a non-nil interface wrapping a nil pointer — callers
// MUST guard `if h.rules != nil` before assigning into this parameter.
type RuleLibrary interface {
	RulesByTechnique(techniqueID string) []rulelib.Rule
}
