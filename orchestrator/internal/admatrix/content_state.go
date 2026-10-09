package admatrix

import "github.com/audspect/bas/internal/adprimitive"

// ContentState is the evidence-backed availability of EXECUTION content for a
// capability. It is a distinct axis from CoverageStatus: CoverageStatus tracks
// validation progress (modeled -> composable -> executed -> telemetry-observed),
// while ContentState answers "what reusable execution content actually exists,
// and what is missing or unverified." See AD.txt line 1194.
type ContentState string

const (
	// ContentScenarioComposable: a committed Audspect scenario demonstrably
	// implements the capability and its mapping is documented.
	ContentScenarioComposable ContentState = "scenario-composable"

	// ContentReusableUnmapped: a specific upstream ART/Caldera implementation is
	// identified by source and technique, but has not been integrated into an
	// Audspect scenario.
	ContentReusableUnmapped ContentState = "reusable-unmapped"

	// ContentModelOnly: the capability is modeled in Audspect, but no verifiable
	// execution-content mapping is established in this repository.
	ContentModelOnly ContentState = "model-only"

	// ContentMissingExecutable: a sufficiently scoped inventory has established
	// that no suitable reusable content is available. This must NOT be used to
	// mean "absent from Git" -- the live ART/Caldera stores may still carry it.
	ContentMissingExecutable ContentState = "missing-executable-content"
)

// reasonNoRepoMapping is the explicit reason for a model-only assignment: the
// repository carries no committed scenario and no cited reusable-content mapping.
// It deliberately does not claim the content is absent everywhere -- a scoped
// live-store inventory on staging is what would establish missing-executable.
const reasonNoRepoMapping = "no_verified_content_mapping_in_repository"

// reasonNotIntegrated marks a reusable-unmapped capability: an upstream atomic is
// cited, but nothing in the repository integrates it into an executable scenario.
const reasonNotIntegrated = "upstream_content_not_integrated_into_scenario"

// ContentEvidence is the provenance record behind a ContentState assignment
// (AD.txt section 5). A state above model-only requires a cited Source and a
// technique mapping; model-only requires an explicit Reason. RepoVerified
// distinguishes repository-verified evidence from an external reference. None of
// these fields asserts that an atomic is safe, compatible, executable, or
// validated -- only that the cited content exists and where.
type ContentEvidence struct {
	PrimitiveID  string       `json:"primitiveId"`
	TechniqueID  string       `json:"techniqueId,omitempty"`
	State        ContentState `json:"state"`
	Source       string       `json:"source,omitempty"`
	RepoVerified bool         `json:"repoVerified"`
	Rationale    string       `json:"rationale,omitempty"`
	Reason       string       `json:"reason,omitempty"`
}

// contentEvidenceByID is the curated, provenance-bearing classification, grounded
// in current repository content. Only two kinds of entry appear here:
//   - scenario-composable: cites the committed scenario that performs it (repo-verified)
//   - reusable-unmapped: cites a specific upstream atomic (externally referenced)
//
// Every other primitive is left out and defaults to model-only (see ContentStates)
// with reasonNoRepoMapping -- never missing-executable-content, which requires a
// scoped live inventory the repository cannot provide.
var contentEvidenceByID = map[string]ContentEvidence{
	// Kerberoasting baseline -- scenarios/kerberoasting-ad-drill.yaml performs each.
	"spn-enumerate": {
		State: ContentScenarioComposable, RepoVerified: true,
		Source:    "scenarios/kerberoasting-ad-drill.yaml (Stage 1, T1558.003)",
		Rationale: "committed scenario enumerates SPNs via setspn -Q + an LDAP servicePrincipalName sweep",
	},
	"kerberoast-tgs-request": {
		State: ContentScenarioComposable, RepoVerified: true,
		Source:    "scenarios/kerberoasting-ad-drill.yaml (Stage 2, T1558.003)",
		Rationale: "committed scenario requests a TGS-REP service ticket for a service SPN",
	},
	"asrep-roast-discover": {
		State: ContentScenarioComposable, RepoVerified: true,
		Source:    "scenarios/kerberoasting-ad-drill.yaml (Stage 3, T1558.004)",
		Rationale: "committed scenario discovers accounts with DONT_REQ_PREAUTH set",
	},
	// DCSync -- upstream public atomic identified in current source (admatrix
	// DCSyncEntries ReuseSource), not integrated into any committed scenario.
	"dcsync": {
		State: ContentReusableUnmapped, RepoVerified: false,
		Source:    "Atomic Red Team T1003.006 (redcanaryco); cited in admatrix DCSyncEntries, not in Git",
		Rationale: "a public DCSync atomic exists upstream and is cited in source; no committed Audspect scenario integrates it",
		Reason:    reasonNotIntegrated,
	},
}

// ContentStates returns the content-availability classification for every AD
// primitive across all catalogs, in a deterministic order. A primitive not in the
// curated map defaults, fail-closed, to model-only with reasonNoRepoMapping -- so
// a newly added primitive is never silently promoted or dropped.
func ContentStates() []ContentEvidence {
	cats := [][]adprimitive.Primitive{
		adprimitive.KerberoastingCatalog,
		adprimitive.ACLAbuseCatalog,
		adprimitive.RBCDCatalog,
		adprimitive.DCSyncCatalog,
		adprimitive.ADCSCatalog,
		adprimitive.DelegationCatalog,
		adprimitive.TrustAbuseCatalog,
		adprimitive.GPOAbuseCatalog,
	}
	var out []ContentEvidence
	for _, c := range cats {
		for _, p := range c {
			ev, ok := contentEvidenceByID[p.ID]
			if !ok {
				ev = ContentEvidence{
					State:     ContentModelOnly,
					Reason:    reasonNoRepoMapping,
					Rationale: "modeled only; no committed scenario and no cited reusable content in this repository (live ART/Caldera inventory not yet run)",
				}
			}
			ev.PrimitiveID = p.ID
			ev.TechniqueID = p.TechniqueID
			out = append(out, ev)
		}
	}
	return out
}

// ContentSummary is a measurable rollup of the content-availability classification
// -- the repository-backed measure of modeled versus executable-content coverage.
type ContentSummary struct {
	Total              int `json:"total"`
	ScenarioComposable int `json:"scenarioComposable"`
	ReusableUnmapped   int `json:"reusableUnmapped"`
	ModelOnly          int `json:"modelOnly"`
	MissingExecutable  int `json:"missingExecutableContent"`
}

// SummarizeContent tallies ContentStates into a ContentSummary.
func SummarizeContent() ContentSummary {
	s := ContentSummary{}
	for _, e := range ContentStates() {
		s.Total++
		switch e.State {
		case ContentScenarioComposable:
			s.ScenarioComposable++
		case ContentReusableUnmapped:
			s.ReusableUnmapped++
		case ContentModelOnly:
			s.ModelOnly++
		case ContentMissingExecutable:
			s.MissingExecutable++
		}
	}
	return s
}
