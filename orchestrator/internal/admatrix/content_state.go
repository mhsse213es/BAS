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
	// DCSync replication-rights exposure check -- a SEPARATE, narrower
	// primitive from dcsync above. It has its own real committed scenario
	// (deliberately NOT bound to the real ART atomic -- a prerequisite-only
	// check, never full DCSync execution) so it is scenario-composable in
	// its own right, independent of dcsync's own reusable-unmapped status.
	"dcsync-replication-right-exposure-check": {
		State: ContentScenarioComposable, RepoVerified: true,
		Source:    "scenarios/dcsync-replication-rights-audit.yaml (Stage 1, T1003.006)",
		Rationale: "committed scenario checks whether the current principal holds DS-Replication-Get-Changes[-All] on the domain object",
	},
	// ACL privilege exposure audit -- the read-only DISCOVERY counterpart to
	// the four ACL ABUSE primitives, with its own real committed scenario
	// (reads privileged objects' DACLs, never resets a password / takes over
	// an object / adds a member). Scenario-composable in its own right; the
	// four abuse primitives stay model-only, unchanged.
	"acl-privilege-exposure-check": {
		State: ContentScenarioComposable, RepoVerified: true,
		Source:    "scenarios/acl-privilege-exposure-audit.yaml (Stage 1, T1069)",
		Rationale: "committed scenario reads privileged objects' DACLs for dangerous rights granted to non-tier-0 principals",
	},
	// ADCS ESC template exposure audit -- the read-only DISCOVERY counterpart
	// to the six ESC ABUSE primitives, with its own real committed scenario
	// (reads the Configuration partition's certificate templates, requests no
	// certificate, takes over no template). Scenario-composable in its own
	// right; the six ESC abuse primitives stay model-only, unchanged.
	"adcs-esc-exposure-check": {
		State: ContentScenarioComposable, RepoVerified: true,
		Source:    "scenarios/adcs-esc-template-exposure-audit.yaml (Stage 1, T1649)",
		Rationale: "committed scenario reads certificate-template configuration for ESC1-4-class misconfigurations enrollable by non-tier-0 principals",
	},
	// Kerberos delegation exposure audit -- read-only DISCOVERY counterpart to
	// the two delegation ABUSE primitives, with its own real committed
	// scenario. Scenario-composable in its own right; the abuse primitives
	// stay model-only, unchanged.
	"kerberos-delegation-exposure-check": {
		State: ContentScenarioComposable, RepoVerified: true,
		Source:    "scenarios/kerberos-delegation-exposure-audit.yaml (Stage 1, T1558)",
		Rationale: "committed scenario reads the directory for unconstrained/constrained/resource-based delegation misconfigurations",
	},
	// Trust / SID-history exposure audit -- read-only DISCOVERY counterpart to
	// the two trust ABUSE primitives, with its own real committed scenario.
	"trust-sid-history-exposure-check": {
		State: ContentScenarioComposable, RepoVerified: true,
		Source:    "scenarios/trust-sid-history-exposure-audit.yaml (Stage 1, T1134.005)",
		Rationale: "committed scenario reads trustedDomain SID-filtering state and accounts' populated sIDHistory",
	},
	// GPO writable-linked exposure audit -- read-only DISCOVERY counterpart to
	// the GPO ABUSE primitive, with its own real committed scenario.
	"gpo-abuse-exposure-check": {
		State: ContentScenarioComposable, RepoVerified: true,
		Source:    "scenarios/gpo-writable-linked-exposure-audit.yaml (Stage 1, T1484.001)",
		Rationale: "committed scenario reads groupPolicyContainer DACLs for non-tier-0 write access on GPOs linked to a populated scope",
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
