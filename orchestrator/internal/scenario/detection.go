package scenario

// Detection Validation Pack — Sub-project 1 data model.
//
// A scenario step declares which security controls SHOULD respond to the
// behavior it exercises (the "expected" baseline). Combined with the actual
// telemetry the agent collects, this lets the report perform gap analysis:
// "Microsoft Defender was expected to detect this and did NOT" is a finding;
// "no detection observed" with no baseline is just noise.
//
// Expectations are authored once as reusable, behavioral DetectionProfiles and
// referenced by name from any step that exercises that behavior. The schema is
// deliberately stable across verification models: an expectation carries
// verification: automatic|manual|api, and moving from manual to api later
// changes only which Verifier resolves it — never the scenario content.

// ExpectedDetection is one control response a step expects to observe.
type ExpectedDetection struct {
	// ID is a stable identifier unique within a resolved step (e.g.
	// "defender_ps_encoded"). Used to merge profile + inline expectations and to
	// correlate verification results back to the expectation.
	ID string `yaml:"id" json:"id"`

	// Provider is a Provider Registry key (e.g. "microsoft_defender"). The
	// registry maps it to a display name, product category, and default verifier
	// so vendor names are never hardcoded in engine logic.
	Provider string `yaml:"provider" json:"provider"`

	// Type is the validation-matrix domain this expectation belongs to:
	// endpoint | identity | network | cloud | email | dlp | siem. Empty falls
	// back to the provider's DefaultDomain.
	Type string `yaml:"type,omitempty" json:"type,omitempty"`

	// Verification selects how "actual" is determined: automatic (on-host, from
	// agent events — SP1), manual (analyst attests — SP2), api (connector pulls
	// the alert — SP3). Empty falls back to the provider's default verifier.
	Verification string `yaml:"verification,omitempty" json:"verification,omitempty"`

	// Confidence weights this expectation in scoring: required (1.0),
	// recommended (0.7), optional (informational — never in a denominator).
	Confidence string `yaml:"confidence" json:"confidence"`

	// Evidence is the structured proof slot. Populated by the automatic verifier
	// in SP1 (provider/timestamp), by analysts in SP2 (alertId/screenshot/notes),
	// and by connectors in SP3. Structured — not a free-text blob — so future
	// verifiers write typed fields.
	Evidence ExpectedEvidence `yaml:"evidence,omitempty" json:"evidence,omitempty"`

	// Finding is the report entry emitted verbatim when this expectation is NOT
	// met (a False Silence gap). The report invents no message text — it uses
	// exactly what the expectation author wrote.
	Finding ExpectedFinding `yaml:"finding,omitempty" json:"finding,omitempty"`

	// RuleIDs optionally links this expectation to one or more Detection Rule
	// Library entries (internal/rulelib.Rule.ID, e.g. "AUDRULE-000001"). Empty
	// is fully backward compatible — existing profiles render exactly as
	// before. One technique commonly maps to several rules, hence a slice.
	RuleIDs []string `yaml:"rule_ids,omitempty" json:"ruleIds,omitempty"`

	// OutcomeFamily selects which outcome vocabulary and comparison semantics
	// this expectation uses. Empty defaults to "detection" — today's implicit
	// binary detected/not-detected model — so every existing scenario and
	// detection profile is unaffected. Distinct from Type/domain: domain
	// answers where a finding groups in the report matrix, OutcomeFamily
	// answers what shape its expected/observed values take. They are not 1:1
	// — two incompatible outcome vocabularies could share one domain.
	OutcomeFamily string `yaml:"outcome_family,omitempty" json:"outcomeFamily,omitempty"`

	// ExpectedOutcome is the outcome value this expectation requires, drawn
	// from its family's catalog. Empty defaults to the family's implicit
	// expectation ("Detected" for the "detection" family).
	ExpectedOutcome string `yaml:"expected_outcome,omitempty" json:"expectedOutcome,omitempty"`
}

// ExpectedEvidence is the structured proof attached to an expected detection.
type ExpectedEvidence struct {
	AlertID       string `yaml:"alertId,omitempty"       json:"alertId,omitempty"`
	Provider      string `yaml:"provider,omitempty"      json:"provider,omitempty"`
	Timestamp     string `yaml:"timestamp,omitempty"     json:"timestamp,omitempty"`
	EvidenceURI   string `yaml:"evidenceUri,omitempty"   json:"evidenceUri,omitempty"`
	ScreenshotURI string `yaml:"screenshotUri,omitempty" json:"screenshotUri,omitempty"`
	Notes         string `yaml:"notes,omitempty"         json:"notes,omitempty"`
}

// ExpectedFinding is the report finding produced when an expectation is unmet.
type ExpectedFinding struct {
	Severity    string `yaml:"severity"            json:"severity"` // Critical|High|Medium|Low
	Title       string `yaml:"title"               json:"title"`
	Remediation string `yaml:"remediation"         json:"remediation"`
	Reference   string `yaml:"reference,omitempty" json:"reference,omitempty"`
}

// DetectionProfile is a reusable, versioned, behavioral bundle of expected
// detections loaded from scenarios/detection-profiles/*.yaml. Profiles are named
// by behavior (e.g. "windows_lsass_access"), not ATT&CK ID, because one behavior
// maps to several techniques and one technique yields different detections by
// implementation. A profile may extend one or more parent profiles.
type DetectionProfile struct {
	// Profile is the unique behavioral name referenced by steps.
	Profile string `yaml:"profile" json:"profile"`

	// Version increments when expectations change. Recorded on each run's report
	// so historical expectations never shift under a re-versioned profile.
	Version int `yaml:"version" json:"version"`

	// Extends names parent profiles whose expectations are inherited. A child
	// overrides an inherited expectation by re-declaring the same id. Cycles are
	// rejected at load time.
	Extends []string `yaml:"extends,omitempty" json:"extends,omitempty"`

	// Expected is this profile's own expectations (before inheritance merge).
	Expected []ExpectedDetection `yaml:"expected_detection" json:"expectedDetection"`

	// Source is set at load time from the file location; not persisted. Mirrors
	// Scenario.Source semantics ("builtin" content must be signature-verified).
	Source string `yaml:"-" json:"source,omitempty"`

	// TechniqueIDs lists the ATT&CK techniques this behavioral profile is
	// relevant to. Additive metadata only -- does not change resolution,
	// inheritance, or scoring. A many-to-many hint, consistent with this
	// struct's design philosophy above: one profile can cover several
	// techniques (e.g. windows_dlp_exfiltration spans 5 DLP channels), and
	// one technique can legitimately have several profiles for different
	// sub-behaviors (e.g. T1562.001 has windows_defender_tampering,
	// windows_security_process_termination, and
	// windows_vulnerable_driver_load -- three different implementations
	// of "impair defenses"). Consumed by connector.Generator (Detection
	// Profile Inheritance) and internal/coverage (Coverage Matrix).
	TechniqueIDs []string `yaml:"technique_ids,omitempty" json:"techniqueIds,omitempty"`
}

// ProfileRef records a resolved profile + its version for a run's audit line
// ("Validated against windows_lsass_access v1").
type ProfileRef struct {
	Profile string `json:"profile"`
	Version int    `json:"version"`
}

// Confidence weights for scoring. Optional is informational: it never appears in
// any scoring denominator, so a customer is never penalized for a detection that
// depends on an optional product or custom content.
const (
	ConfidenceRequired    = "required"
	ConfidenceRecommended = "recommended"
	ConfidenceOptional    = "optional"
)

// ConfidenceWeight returns the numeric scoring weight for a confidence level.
// Optional returns 0 and is additionally excluded from denominators by callers
// (weight 0 alone would already exclude it from a weighted average).
func ConfidenceWeight(confidence string) float64 {
	switch confidence {
	case ConfidenceRequired:
		return 1.0
	case ConfidenceRecommended:
		return 0.7
	default: // optional / unknown → informational
		return 0.0
	}
}

// Verification models.
const (
	VerificationAutomatic = "automatic"
	VerificationManual    = "manual"
	VerificationAPI       = "api"
)

// Validation-matrix domains.
const (
	DomainEndpoint = "endpoint"
	DomainIdentity = "identity"
	DomainNetwork  = "network"
	DomainCloud    = "cloud"
	DomainEmail    = "email"
	DomainDLP      = "dlp"
	DomainSIEM     = "siem"
)
