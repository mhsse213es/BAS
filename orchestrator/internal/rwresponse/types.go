// Package rwresponse joins Detection, Containment, and Recovery evidence
// for one run into a response-effectiveness view, per technique. It is
// pure Go, with no DB or HTTP import -- same discipline as dxcorrelate.
// The API-layer adapter (internal/api) is the one place that calls
// db.RWCapabilityAttempts and passes its rows in here.
//
// Prevention and DataProtection rows are deliberately never read by this
// package: distinguishing prevention, detection, containment and recovery
// (this sub-project's own exit criterion) means keeping each dimension's
// independent verdict legible, not collapsing five capabilities into one
// join.
//
// ResponseLatency is always NotEstablishable today (design spec section
// A): internal/actions' action_requests table carries run_id but no
// technique_id/action column, so no causal link between a detection event
// and the containment action that answered it exists in this codebase.
// DetectionLatency is different -- a real field on detectverify.VerifyResult
// -- but nothing in this sub-project calls a real Connector, so it stays
// nil on every row built from a real run today; it exists only so a
// caller that HAS resolved a VerifyResult (via rwdetect, later, lab-gated)
// has somewhere to put it.
package rwresponse

import (
	"time"

	"github.com/audspect/bas/internal/controlval"
)

// DimensionEvidence is one capability's selected evidence for one
// technique. A nil *DimensionEvidence on an EffectivenessRow means no row
// exists at all for that (technique, capability) pair -- distinct from a
// present row whose Verdict is SKIPPED, which still carries a SkipReason
// and Reason explaining why.
type DimensionEvidence struct {
	Verdict    controlval.Verdict
	SkipReason controlval.SkipReason
	Reason     string
	Action     string
	CreatedAt  time.Time
}

// ResponseLatencyStatus is a distinct type, not a *time.Duration left nil,
// so a caller cannot mistake "not establishable" for "zero latency" -- the
// same reasoning dxcorrelate.BehaviorStatus applies to BehaviorOccurred vs
// BehaviorNotEstablished.
type ResponseLatencyStatus string

const ResponseLatencyNotEstablishable ResponseLatencyStatus = "not_establishable"

const responseLatencyNotEstablishableReason = "no causal link between a detection event and a specific containment action exists in this codebase today (action_requests carries run_id only, not technique_id/action)"

// DetectionLatencyEvidence is one technique's measured detection latency,
// supplied by a caller that has resolved a detectverify.VerifyResult.
// Keyed by TechniqueID+Action, matching rwevidence.AttemptKey's own
// identity. BuildEffectivenessReport performs no detectverify call itself.
type DetectionLatencyEvidence struct {
	TechniqueID string
	Action      string
	Latency     time.Duration
}

// EffectivenessRow is one technique's Detection/Containment/Recovery
// evidence side by side, plus latency context.
type EffectivenessRow struct {
	TechniqueID           string
	Detection              *DimensionEvidence
	Containment            *DimensionEvidence
	Recovery               *DimensionEvidence
	DetectionLatency       *time.Duration
	ResponseLatency        ResponseLatencyStatus
	ResponseLatencyReason  string
}

// EffectivenessReport is the full join for one run. Rows is empty (never
// nil) when the run has no Detection/Containment/Recovery evidence for any
// technique -- not an error.
type EffectivenessReport struct {
	Rows []EffectivenessRow
}
