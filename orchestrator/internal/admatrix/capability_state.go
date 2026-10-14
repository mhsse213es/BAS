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
	PrimitiveID string `json:"primitiveId"`
	Name        string `json:"name"`
	TechniqueID string `json:"techniqueId,omitempty"`

	// Family is the attack-family grouping label (which catalog the
	// primitive belongs to: Kerberoasting / ACL / RBCD / DCSync / ADCS /
	// Delegation / Trust / GPO). A static presentation grouping derived
	// once here from catalog membership so the UI never has to classify
	// primitives itself -- it is NOT a coverage or validation state.
	Family string `json:"family"`

	// Modeled: represented in the adprimitive catalog with adenv predicates
	// and an adlab resolver. True for every primitive adprimitive.All()
	// returns -- that is what "modeled" means in this codebase.
	Modeled bool `json:"modeled"`

	// ContentAvailability/ContentSource/ContentRepoVerified/ContentReason
	// mirror content_state.go's ContentEvidence exactly -- the single
	// existing source of truth for what reusable execution content exists
	// and its provenance. Not duplicated logic, just carried through.
	ContentAvailability ContentState `json:"contentAvailability"`
	ContentSource       string       `json:"contentSource,omitempty"`
	ContentRepoVerified bool         `json:"contentRepoVerified"`
	ContentReason       string       `json:"contentReason,omitempty"`

	// ScenarioComposed is true only when a committed Audspect scenario
	// actually performs this capability. Being scenario-composed does NOT
	// imply execution occurred -- that is ExecutionValidation's job. These
	// two axes are deliberately allowed to disagree (e.g. DCSync: reusable
	// content is cited but nothing is scenario-composed or executed).
	ScenarioComposed bool `json:"scenarioComposed"`

	ExecutionValidation ExecutionValidation `json:"executionValidation"`
	DetectionValidation DetectionValidation `json:"detectionValidation"`

	// ControlEfficacy is the sixth, INDEPENDENT axis: whether a DEPLOYED
	// security control produced its expected response to this capability. Zero
	// value = not evaluated. It never modifies or collapses the five axes
	// above, and it is independent of DetectionValidation -- a blocked attempt
	// with no SIEM alert may be a PASS here and a detection failure. Populated
	// only via the adcontrolval bridge from real provider observations; live
	// wiring is DEFERRED (lab-gated), so CapabilityStates() leaves this at its
	// zero value in this slice.
	ControlEfficacy ControlEfficacyState `json:"controlEfficacy"`

	Prerequisites          adprimitive.Prerequisites `json:"prerequisites"`
	ExpectedPostconditions []adprimitive.Capability  `json:"expectedPostconditions,omitempty"`

	// RiskClass is the safety-requirement signal, carried straight from the
	// adprimitive catalog (non_destructive / potentially_destructive /
	// destructive) -- never re-derived or guessed here.
	RiskClass adprimitive.RiskClass `json:"riskClass"`

	// Cleanup, EvidenceRequirements and TelemetrySources are grounded in the
	// matrix Entry for the 18 gap primitives (matrix.go) and in the real,
	// committed scenario YAML for the 3 Kerberoasting-baseline primitives
	// (see realScenarioEvidenceByID) -- never invented.
	Cleanup              []string `json:"cleanup,omitempty"`
	EvidenceRequirements []string `json:"evidenceRequirements,omitempty"`
	TelemetrySources     []string `json:"telemetrySources,omitempty"`

	// Limitations are the known constraints on what has actually been
	// demonstrated so far -- distinct from Outstanding (what remains to be
	// done): a capability can be scenario-composed and still have the
	// limitation "not yet executed against a real domain".
	Limitations []string `json:"limitations"`

	// Outstanding is the explicit, honest list of remaining work for this
	// capability. Never silently inferred from a promoted status -- every
	// entry is traceable to a concrete gap (no content mapping, not
	// integrated into a scenario, not executed, not detection-validated).
	Outstanding []string `json:"outstanding"`
}

// controlEfficacyPass is the one verdict string this package tests for in the
// rollup. It is the SAME PASS value as the shared scoring taxonomy
// (controlval.VerdictPass / project_scoring_verdicts); declared locally only so
// admatrix need not import controlval. It is not a second taxonomy.
const controlEfficacyPass = "PASS"

// ControlEfficacyState is the admatrix-local view of a control-efficacy
// result. It is filled by the adcontrolval bridge from a controlval.Validation;
// admatrix imports no controlval or vendor code. Verdict reuses the existing
// PASS/FAIL/ERROR/SKIPPED taxonomy -- there is no second verdict vocabulary,
// and Evaluated=true does NOT imply success.
type ControlEfficacyState struct {
	Evaluated    bool   `json:"evaluated"`
	Verdict      string `json:"verdict,omitempty"`
	Provider     string `json:"provider,omitempty"`
	Observed     string `json:"observedOutcome,omitempty"`
	Expected     string `json:"expectedOutcome,omitempty"`
	EvidenceKind string `json:"evidenceKind,omitempty"`
	Confidence   string `json:"confidence,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// CapabilityStateSummary is the measurable rollup across CapabilityStates.
// Every count is traceable back to the per-capability records; nothing here
// is derived independently of them.
type CapabilityStateSummary struct {
	Total              int `json:"total"`
	Modeled            int `json:"modeled"`
	ScenarioComposed   int `json:"scenarioComposed"`
	Executed           int `json:"executed"`
	DetectionValidated int `json:"detectionValidated"`
	ControlValidated   int `json:"controlValidated"`
}

// realScenarioEvidence is the Cleanup/EvidenceRequirements/TelemetrySources/
// Limitations citation for a primitive that is scenario-composed via a REAL,
// committed scenario YAML but is NOT one of the 18 gap-matrix primitives
// (matrix.go) -- currently the 3 Kerberoasting-baseline primitives
// (scenarios/kerberoasting-ad-drill.yaml) and
// dcsync-replication-right-exposure-check
// (scenarios/dcsync-replication-rights-audit.yaml). Grounding tests parse
// each cited file and prove every string below actually appears in it --
// never invented. The 18 gap primitives get the same fields from their
// existing matrix Entry instead.
type realScenarioEvidence struct {
	Cleanup              []string
	EvidenceRequirements []string
	TelemetrySources     []string
	Limitations          []string
}

var realScenarioEvidenceByID = map[string]realScenarioEvidence{
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
		Limitations: kerberoastingLimitations,
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
		Limitations: kerberoastingLimitations,
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
		Limitations: kerberoastingLimitations,
	},
	"dcsync-replication-right-exposure-check": {
		Cleanup: []string{"No cleanup required: the check only reads the domain object's own access-control list; no state change (scenarios/dcsync-replication-rights-audit.yaml Stage 1)."},
		EvidenceRequirements: []string{
			"SIEM: a non-DC, non-tier-0 principal holds DS-Replication-Get-Changes / -All on the domain object — DCSync-prerequisite exposure IOC",
		},
		TelemetrySources: []string{
			"DC: access-control read of the domain object's own security descriptor (nTSecurityDescriptor) — not separately audited by default",
		},
		Limitations: dcsyncExposureCheckLimitations,
	},
	"acl-privilege-exposure-check": {
		Cleanup: []string{"No cleanup required: the check only reads privileged objects' access-control lists; no state change (scenarios/acl-privilege-exposure-audit.yaml Stage 1)."},
		EvidenceRequirements: []string{
			"SIEM: a non-tier-0 principal holds a takeover-enabling right (GenericAll/GenericWrite/WriteDacl/WriteOwner/ForceChangePassword/AddMember/AddSelf/AllExtendedRights) over a privileged object — ACL exposure IOC",
		},
		TelemetrySources: []string{
			"DC: access-control read of privileged objects' security descriptors (nTSecurityDescriptor) — not separately audited by default",
		},
		Limitations: aclExposureCheckLimitations,
	},
	"adcs-esc-exposure-check": {
		Cleanup: []string{"No cleanup required: the check only reads certificate-template configuration from the AD Configuration partition; no state change (scenarios/adcs-esc-template-exposure-audit.yaml Stage 1)."},
		EvidenceRequirements: []string{
			"SIEM: a certificate template enrollable by a non-tier-0 principal carries an ESC1-4-class misconfiguration (enrollee-supplied subject + authentication EKU, Any-Purpose/no EKU, enrollment-agent EKU, or a non-tier-0-writable template DACL) — AD CS template exposure IOC",
		},
		TelemetrySources: []string{
			"DC: LDAP read of pKICertificateTemplate objects under the Configuration partition — not separately audited by default",
		},
		Limitations: adcsExposureCheckLimitations,
	},
	"kerberos-delegation-exposure-check": {
		Cleanup: []string{"No cleanup required: the check only reads delegation attributes from the directory; no state change (scenarios/kerberos-delegation-exposure-audit.yaml Stage 1)."},
		EvidenceRequirements: []string{
			"SIEM: a non-DC account trusted for unconstrained delegation, or a constrained/resource-based delegation configuration, is present in the directory — Kerberos delegation exposure IOC",
		},
		TelemetrySources: []string{
			"DC: LDAP read of userAccountControl / msDS-AllowedToDelegateTo / msDS-AllowedToActOnBehalfOfOtherIdentity — not separately audited by default",
		},
		Limitations: delegationExposureCheckLimitations,
	},
	"trust-sid-history-exposure-check": {
		Cleanup: []string{"No cleanup required: the check only reads trust and sIDHistory attributes from the directory; no state change (scenarios/trust-sid-history-exposure-audit.yaml Stage 1)."},
		EvidenceRequirements: []string{
			"SIEM: a cross-forest trust with SID filtering disabled, or an account carrying a populated sIDHistory, is present in the directory — trust / SID-history exposure IOC",
		},
		TelemetrySources: []string{
			"DC: LDAP read of trustedDomain trustAttributes and accounts' sIDHistory — not separately audited by default",
		},
		Limitations: trustExposureCheckLimitations,
	},
	"gpo-abuse-exposure-check": {
		Cleanup: []string{"No cleanup required: the check only reads groupPolicyContainer DACLs and gPLinks from the directory; no state change (scenarios/gpo-writable-linked-exposure-audit.yaml Stage 1)."},
		EvidenceRequirements: []string{
			"SIEM: a Group Policy object writable by a non-tier-0 principal is linked to a populated scope (domain/OU/site) — GPO exposure IOC",
		},
		TelemetrySources: []string{
			"DC: LDAP read of groupPolicyContainer security descriptors and gPLink attributes — not separately audited by default",
		},
		Limitations: gpoExposureCheckLimitations,
	},
	"rbcd-configure-exposure-check": {
		Cleanup: []string{"No cleanup required: the check only reads computer DACLs and the domain's ms-DS-MachineAccountQuota; no state change (scenarios/rbcd-configure-exposure-audit.yaml Stage 1)."},
		EvidenceRequirements: []string{
			"SIEM: a non-tier-0 principal holds write access over a computer object while ms-DS-MachineAccountQuota is non-zero — RBCD configure-surface exposure IOC",
		},
		TelemetrySources: []string{
			"DC: LDAP read of computer-object security descriptors and the domain ms-DS-MachineAccountQuota — not separately audited by default",
		},
		Limitations: rbcdExposureCheckLimitations,
	},
}

// kerberoastingLimitations is shared by all 3 Kerberoasting-baseline
// primitives: identical real constraint (committed scenario, not yet run
// through the supported workflow in this build).
var kerberoastingLimitations = []string{
	"Scenario-composed (scenarios/kerberoasting-ad-drill.yaml) but not yet executed through the supported agent/orchestrator workflow in this build; execution and detection validation are outstanding.",
}

// dcsyncExposureCheckLimitations: the check proves whether the DCSync
// prerequisite is held, never that replication succeeded -- distinct from
// dcsync's own limitation, which is about the unintegrated real atomic.
var dcsyncExposureCheckLimitations = []string{
	"Scenario-composed (scenarios/dcsync-replication-rights-audit.yaml) but not yet executed through the supported agent/orchestrator workflow in this build; execution and detection validation are outstanding.",
	"Proves only whether the DS-Replication prerequisite is held -- never binds to the real DCSync atomic (lsadump::dcsync / Get-ADReplAccount) and is not evidence that replication itself would succeed or has been attempted.",
}

// aclExposureCheckLimitations: the audit proves whether a takeover-enabling
// ACL right is exposed, never that it was used -- distinct from the four
// ACL ABUSE primitives, which remain model-only and unintegrated.
var aclExposureCheckLimitations = []string{
	"Scenario-composed (scenarios/acl-privilege-exposure-audit.yaml) but not yet executed through the supported agent/orchestrator workflow in this build; execution and detection validation are outstanding.",
	"Reads DACLs to report which dangerous rights are exposed -- never exercises any of them (resets no password, takes over no object, adds no group member) and is not evidence that a takeover would succeed or has been attempted.",
}

// adcsExposureCheckLimitations: the audit proves whether an ESC1-4-class
// template misconfiguration is exposed, never that a certificate was
// requested -- distinct from the six ESC ABUSE primitives, which remain
// model-only and unintegrated. Scoped to the LDAP-readable template surface.
var adcsExposureCheckLimitations = []string{
	"Scenario-composed (scenarios/adcs-esc-template-exposure-audit.yaml) but not yet executed through the supported agent/orchestrator workflow in this build; execution and detection validation are outstanding.",
	"Reads certificate-template configuration to report ESC1-4-class exposure -- never requests a certificate or takes over a template, and is not evidence that abuse would succeed or has been attempted.",
	"Scoped to the LDAP-readable template surface (ESC1-4); the CA-host-level SAN policy flag (ESC6) and HTTP web-enrollment reach (ESC8) are outside a Configuration-partition read and are not assessed.",
}

// delegationExposureCheckLimitations: the audit proves whether a delegation
// misconfiguration is exposed, never that it was abused -- distinct from the
// two delegation ABUSE primitives, which remain model-only and unintegrated.
var delegationExposureCheckLimitations = []string{
	"Scenario-composed (scenarios/kerberos-delegation-exposure-audit.yaml) but not yet executed through the supported agent/orchestrator workflow in this build; execution and detection validation are outstanding.",
	"Reads delegation attributes to report exposure -- never coerces an authentication or forges/uses a ticket, and is not evidence that abuse would succeed or has been attempted.",
}

// trustExposureCheckLimitations: the audit proves whether a trust/SID-history
// abuse condition is exposed, never that it was abused -- distinct from the
// two trust ABUSE primitives, which remain model-only and unintegrated.
var trustExposureCheckLimitations = []string{
	"Scenario-composed (scenarios/trust-sid-history-exposure-audit.yaml) but not yet executed through the supported agent/orchestrator workflow in this build; execution and detection validation are outstanding.",
	"Reads trust SID-filtering state and sIDHistory to report exposure -- never forges an inter-realm ticket, and is not evidence that abuse would succeed or has been attempted.",
}

// gpoExposureCheckLimitations: the audit proves whether a writable linked GPO
// is exposed, never that policy was pushed -- distinct from the GPO ABUSE
// primitive, which remains model-only and unintegrated.
var gpoExposureCheckLimitations = []string{
	"Scenario-composed (scenarios/gpo-writable-linked-exposure-audit.yaml) but not yet executed through the supported agent/orchestrator workflow in this build; execution and detection validation are outstanding.",
	"Reads GPO DACLs and gPLinks to report exposure -- never pushes policy or creates a scheduled task, and is not evidence that abuse would succeed or has been attempted.",
}

// rbcdExposureCheckLimitations: the audit proves whether the RBCD-configure
// precondition (non-tier-0 write over a computer + non-zero MachineAccountQuota)
// is exposed, never that RBCD was configured or abused -- distinct from the two
// RBCD ABUSE primitives, which remain model-only and unintegrated.
var rbcdExposureCheckLimitations = []string{
	"Scenario-composed (scenarios/rbcd-configure-exposure-audit.yaml) but not yet executed through the supported agent/orchestrator workflow in this build; execution and detection validation are outstanding.",
	"Reads computer DACLs and ms-DS-MachineAccountQuota to report the configure-surface -- never writes msDS-AllowedToActOnBehalfOfOtherIdentity, creates a machine account, or impersonates anyone, and is not evidence that abuse would succeed or has been attempted.",
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
// familyByPrimitiveID maps every primitive to its attack-family label from the
// catalog it belongs to -- the single place this grouping is defined, so the UI
// renders it rather than classifying primitives itself.
func familyByPrimitiveID() map[string]string {
	fams := []struct {
		label string
		cat   []adprimitive.Primitive
	}{
		{"Kerberoasting", adprimitive.KerberoastingCatalog},
		{"ACL", adprimitive.ACLAbuseCatalog},
		{"RBCD", adprimitive.RBCDCatalog},
		{"DCSync", adprimitive.DCSyncCatalog},
		{"ADCS", adprimitive.ADCSCatalog},
		{"Delegation", adprimitive.DelegationCatalog},
		{"Trust", adprimitive.TrustAbuseCatalog},
		{"GPO", adprimitive.GPOAbuseCatalog},
	}
	m := map[string]string{}
	for _, f := range fams {
		for _, p := range f.cat {
			m[p.ID] = f.label
		}
	}
	return m
}

func CapabilityStates() []CapabilityState {
	content := make(map[string]ContentEvidence, len(adprimitive.All()))
	for _, ev := range ContentStates() {
		content[ev.PrimitiveID] = ev
	}
	entries := make(map[string]Entry, len(AllEntries()))
	for _, e := range AllEntries() {
		entries[e.PrimitiveID] = e
	}

	family := familyByPrimitiveID()
	var out []CapabilityState
	for _, p := range adprimitive.All() {
		ev := content[p.ID]
		cs := CapabilityState{
			PrimitiveID:            p.ID,
			Name:                   p.Name,
			TechniqueID:            p.TechniqueID,
			Family:                 family[p.ID],
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
		} else if rev, ok := realScenarioEvidenceByID[p.ID]; ok {
			// A primitive with a real committed scenario that isn't one of
			// the 18 gap-matrix primitives (Kerberoasting baseline, or the
			// DCSync exposure-check): cite that scenario instead (grounding
			// tests parse each file).
			cs.Cleanup = rev.Cleanup
			cs.EvidenceRequirements = rev.EvidenceRequirements
			cs.TelemetrySources = rev.TelemetrySources
			cs.Limitations = rev.Limitations
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
		// Independent sixth axis: counted only for an explicit PASS verdict.
		// Evaluated-but-not-PASS (FAIL/ERROR/SKIPPED) never increments this.
		if cs.ControlEfficacy.Verdict == string(controlEfficacyPass) {
			s.ControlValidated++
		}
	}
	return s
}
