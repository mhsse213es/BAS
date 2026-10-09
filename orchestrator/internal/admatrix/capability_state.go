package admatrix

import "github.com/audspect/bas/internal/adprimitive"

// ExecutionValidation is the independent axis answering whether a capability's
// expected postcondition has been verified against a REAL execution. It is
// never inferred from a modeled simulation, from scenario-composability, or
// from a command merely returning success -- only a real, attributable run
// advances it (AD Mastery E2E Directive Phase 1 + Phase 4).
type ExecutionValidation string

const (
	// ExecNotExecuted is the honest default: no execution attempt exists for
	// this capability in the current build. Every capability starts here.
	ExecNotExecuted ExecutionValidation = "not_executed"

	// ExecAttempted: a real execution was dispatched through the supported
	// workflow but completion/outcome is not yet confirmed.
	ExecAttempted ExecutionValidation = "execution_attempted"

	// ExecCompleted: the execution ran to completion. This alone does not
	// prove the intended AD security-state change occurred -- see
	// ExecPostconditionVerified.
	ExecCompleted ExecutionValidation = "execution_completed"

	// ExecPostconditionVerified: the expected postcondition was independently
	// confirmed (not inferred from command exit status).
	ExecPostconditionVerified ExecutionValidation = "postcondition_verified"
)

// DetectionValidation is the independent axis answering whether detection
// evidence was observed and attributed to the specific run and target that
// produced it. A connector existing, or a fixture passing, is never
// sufficient on its own (AD Mastery E2E Directive Phase 6).
type DetectionValidation string

const (
	// DetNotValidated is the honest default: no attributable telemetry exists
	// for this capability in the current build.
	DetNotValidated DetectionValidation = "not_validated"

	// DetSimulatedEvidence: only fixture/synthetic evidence has been used,
	// explicitly labeled as simulated -- never equated with real detection.
	DetSimulatedEvidence DetectionValidation = "simulated_evidence_only"

	// DetTelemetryObserved: real, attributable telemetry from an actual
	// execution of this capability was observed.
	DetTelemetryObserved DetectionValidation = "telemetry_observed"
)

// CapabilityState is the single authoritative, evidence-backed record for one
// of the 21 AD primitives. It tracks Phase 1's independent axes -- modeling,
// content availability/provenance, scenario composition, execution
// validation, and detection validation -- rather than collapsing them into
// one coverage status the way CoverageStatus (report.go) does for the 18 gap
// primitives. It composes the existing adprimitive catalog and ContentStates
// (content_state.go); it is not a new inventory, primitive, matrix, or
// validation package, and it changes no production dispatch behavior.
type CapabilityState struct {
	PrimitiveID string
	Name        string
	TechniqueID string

	// Modeled: represented in the adprimitive catalog with adenv predicates
	// and an adlab resolver. True for every primitive adprimitive.All()
	// returns -- that is what "modeled" means in this codebase.
	Modeled bool

	// ContentAvailability/ContentSource/ContentRepoVerified/ContentReason
	// mirror content_state.go's ContentEvidence exactly -- the single
	// existing source of truth for what reusable execution content exists
	// and its provenance. Not duplicated logic, just carried through.
	ContentAvailability ContentState
	ContentSource       string
	ContentRepoVerified bool
	ContentReason       string

	// ScenarioComposed is true only when a committed Audspect scenario
	// actually performs this capability. Being scenario-composed does NOT
	// imply execution occurred -- that is ExecutionValidation's job. These
	// two axes are deliberately allowed to disagree (e.g. DCSync: reusable
	// content is cited but nothing is scenario-composed or executed).
	ScenarioComposed bool

	ExecutionValidation ExecutionValidation
	DetectionValidation DetectionValidation

	Prerequisites          adprimitive.Prerequisites
	ExpectedPostconditions []adprimitive.Capability

	// Outstanding is the explicit, honest list of remaining work for this
	// capability. Never silently inferred from a promoted status -- every
	// entry is traceable to a concrete gap (no content mapping, not
	// integrated into a scenario, not executed, not detection-validated).
	Outstanding []string
}

// CapabilityStateSummary is the measurable rollup across CapabilityStates.
// Every count is traceable back to the per-capability records; nothing here
// is derived independently of them.
type CapabilityStateSummary struct {
	Total              int
	Modeled            int
	ScenarioComposed   int
	Executed           int
	DetectionValidated int
}

// outstandingFor derives the honest outstanding-work list for a capability
// from its already-assigned axes. It never promotes a state to make the list
// shorter -- a capability with real content still needs executing; a
// scenario-composed capability still needs running and detecting.
func outstandingFor(cs CapabilityState) []string {
	var out []string
	switch cs.ContentAvailability {
	case ContentModelOnly:
		out = append(out, "no verified executable-content mapping in this repository; establish one (committed scenario or cited reusable content) before attempting execution")
	case ContentReusableUnmapped:
		out = append(out, "integrate the cited upstream content ("+cs.ContentSource+") into a committed Audspect scenario")
	case ContentMissingExecutable:
		out = append(out, "author new executable content; a scoped inventory found no suitable reusable content")
	}
	if cs.ExecutionValidation == ExecNotExecuted {
		out = append(out, "execute through the supported workflow and independently verify the expected postcondition")
	}
	if cs.DetectionValidation == DetNotValidated {
		out = append(out, "validate detection with real, attributable telemetry from an actual execution")
	}
	return out
}

// CapabilityStates returns the single authoritative state record for every AD
// primitive across all 8 catalogs (21 primitives), in adprimitive.All()'s
// deterministic order. It composes adprimitive.All() (the full primitive set)
// with ContentStates() (content_state.go's provenance-bearing classification)
// -- it does not re-derive or duplicate either.
func CapabilityStates() []CapabilityState {
	content := make(map[string]ContentEvidence, len(adprimitive.All()))
	for _, ev := range ContentStates() {
		content[ev.PrimitiveID] = ev
	}

	var out []CapabilityState
	for _, p := range adprimitive.All() {
		ev := content[p.ID]
		cs := CapabilityState{
			PrimitiveID:            p.ID,
			Name:                   p.Name,
			TechniqueID:            p.TechniqueID,
			Modeled:                true,
			ContentAvailability:    ev.State,
			ContentSource:          ev.Source,
			ContentRepoVerified:    ev.RepoVerified,
			ContentReason:          ev.Reason,
			ScenarioComposed:       ev.State == ContentScenarioComposable,
			ExecutionValidation:    ExecNotExecuted,
			DetectionValidation:    DetNotValidated,
			Prerequisites:          p.Prerequisites,
			ExpectedPostconditions: p.Postconditions,
		}
		cs.Outstanding = outstandingFor(cs)
		out = append(out, cs)
	}
	return out
}

// SummarizeCapabilityStates tallies CapabilityStates into a
// CapabilityStateSummary.
func SummarizeCapabilityStates() CapabilityStateSummary {
	s := CapabilityStateSummary{}
	for _, cs := range CapabilityStates() {
		s.Total++
		if cs.Modeled {
			s.Modeled++
		}
		if cs.ScenarioComposed {
			s.ScenarioComposed++
		}
		if cs.ExecutionValidation == ExecCompleted || cs.ExecutionValidation == ExecPostconditionVerified {
			s.Executed++
		}
		if cs.DetectionValidation == DetTelemetryObserved {
			s.DetectionValidated++
		}
	}
	return s
}
