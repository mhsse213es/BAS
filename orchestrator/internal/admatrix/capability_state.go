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

	// RiskClass is the safety-requirement signal, carried straight from the
	// adprimitive catalog (non_destructive / potentially_destructive /
	// destructive) -- never re-derived or guessed here.
	RiskClass adprimitive.RiskClass

	// Cleanup, EvidenceRequirements and TelemetrySources are grounded in the
	// matrix Entry for the 18 gap primitives (matrix.go) and in the real,
	// committed scenario YAML for the 3 Kerberoasting-baseline primitives
	// (see kerberoastingScenarioEvidenceByID) -- never invented.
	Cleanup              []string
	EvidenceRequirements []string
	TelemetrySources     []string

	// Limitations are the known constraints on what has actually been
	// demonstrated so far -- distinct from Outstanding (what remains to be
	// done): a capability can be scenario-composed and still have the
	// limitation "not yet executed against a real domain".
	Limitations []string

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

// kerberoastingEvidence is the Cleanup/EvidenceRequirements/TelemetrySources
// citation for the 3 Kerberoasting-baseline primitives, grounded in the real,
// committed scenarios/kerberoasting-ad-drill.yaml (Stages 1-3). It is the only
// curated citation needed because these are the only primitives that are both
// scenario-composed AND have a real scenario in this repository -- the 18 gap
// primitives get the same fields from their existing matrix Entry instead.
// TestCapabilityStates_KerberoastingCitesRealScenarioContent parses that file
// and proves every string below actually appears in the cited stage.
type kerberoastingEvidence struct {
	Cleanup              []string
	EvidenceRequirements []string
	TelemetrySources     []string
}

var kerberoastingScenarioEvidenceByID = map[string]kerberoastingEvidence{
	"spn-enumerate": {
		Cleanup: []string{"No cleanup required: Stage 1 is read-only LDAP/Kerberos enumeration (setspn -Q + LDAP SPN sweep); no state change (scenarios/kerberoasting-ad-drill.yaml Stage 1)."},
		EvidenceRequirements: []string{
			"EDR: setspn.exe -Q enumeration — Sigma proc_creation_win_setspn_enum.yml",
			"SIEM: LDAP query for all servicePrincipalName values — Kerberoast reconnaissance IOC",
		},
		TelemetrySources: []string{
			"Sysmon EID 1: setspn.exe -Q */*",
			"DC: LDAP search filter (servicePrincipalName=*) — Directory Services / 1644 if verbose LDAP logging enabled",
		},
	},
	"kerberoast-tgs-request": {
		Cleanup: []string{"No cleanup required: Stage 2 requests but never extracts, exports or cracks the service ticket; no account or ticket state is modified (scenarios/kerberoasting-ad-drill.yaml Stage 2)."},
		EvidenceRequirements: []string{
			"SIEM: EID 4769 with Ticket Encryption Type 0x17 (RC4) — high-fidelity Kerberoast IOC",
			"SIEM: single principal requesting many distinct service tickets in a short window",
		},
		TelemetrySources: []string{
			"DC Security EID 4769: Kerberos service ticket requested (ticket encryption 0x17=RC4 is the Kerberoast tell)",
			"Sysmon EID 1: powershell.exe requesting a service ticket",
		},
	},
	"asrep-roast-discover": {
		Cleanup: []string{"No cleanup required: Stage 3 is a read-only LDAP query for DONT_REQ_PREAUTH accounts; no ticket requested, no state change (scenarios/kerberoasting-ad-drill.yaml Stage 3)."},
		EvidenceRequirements: []string{
			"SIEM: LDAP query filtering on DONT_REQ_PREAUTH — AS-REP Roast reconnaissance IOC",
			"SIEM: EID 4768 AS-REQ without pre-auth (encryption 0x17) — AS-REP roast in progress",
		},
		TelemetrySources: []string{
			"DC: LDAP search for userAccountControl:1.2.840.113556.1.4.803:=4194304",
			"Sysmon EID 1: powershell.exe LDAP enumeration",
		},
	},
}

// kerberoastingLimitations is shared by all 3 Kerberoasting-baseline
// primitives: identical real constraint (committed scenario, not yet run
// through the supported workflow in this build).
var kerberoastingLimitations = []string{
	"Scenario-composed (scenarios/kerberoasting-ad-drill.yaml) but not yet executed through the supported agent/orchestrator workflow in this build; execution and detection validation are outstanding.",
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
	entries := make(map[string]Entry, len(AllEntries()))
	for _, e := range AllEntries() {
		entries[e.PrimitiveID] = e
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
			RiskClass:              p.RiskClass,
		}
		if e, ok := entries[p.ID]; ok {
			// One of the 18 gap-matrix primitives: reuse its real Entry and
			// the same honest limitations report.go already derives for it.
			cs.Cleanup = e.Cleanup
			cs.EvidenceRequirements = e.EvidenceRequirements
			cs.TelemetrySources = e.TelemetrySources
			cs.Limitations = limitationsFor(e, coverageStatusFor(e))
		} else if kev, ok := kerberoastingScenarioEvidenceByID[p.ID]; ok {
			// One of the 3 Kerberoasting-baseline primitives: cite the real
			// committed scenario instead (grounding test parses the file).
			cs.Cleanup = kev.Cleanup
			cs.EvidenceRequirements = kev.EvidenceRequirements
			cs.TelemetrySources = kev.TelemetrySources
			cs.Limitations = kerberoastingLimitations
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
