// Package phishval is a vendor-neutral, I/O-free model for grading what
// happened to a Phishing BAS scenario execution across phishing.txt §6's
// seven independent outcome dimensions: delivery, enforcement, detection,
// user interaction, response, evidence quality and confidence.
//
// It is architecturally independent of internal/controlval,
// internal/avval, internal/wafval, and internal/emailgwefficacy -- no
// import of any of them. This corrects course from
// docs/superpowers/specs/2026-10-18-phishing-bas-mastery-phase0-roadmap-design.md
// §1.1, which proposed a one-way bridge INTO internal/controlval
// (mirroring internal/adcontrolval's bridge). Further research for Phase
// 1 found that adcontrolval's bridge is the EXCEPTION in this codebase,
// not the rule: internal/avval and internal/emailgwefficacy both
// explicitly declare full independence from internal/controlval and from
// every sibling domain's own taxonomy ("any cross-package relationship
// this initiative ever takes on borrows a structural pattern, never a
// shared type" -- emailgwefficacy/types.go, locked). Phishing BAS Mastery
// follows the dominant, three-times-repeated pattern (AV, WAF, Email) over
// the one-off AD exception: its own independent taxonomy, shaped by
// phishing.txt §6's dimensions, never a shared type with another domain.
//
// Translating another domain's already-produced result (e.g.
// emailgwefficacy.EfficacyResult, exercise evidence) into this package's
// own types is a one-way dependency that lives in internal/phishbridge,
// never here.
package phishval

import "time"

// DeliveryOutcome is what happened to the message/payload at the
// transport layer, independent of whether anything downstream enforced,
// detected, or responded to it.
type DeliveryOutcome string

const (
	DeliveryDelivered   DeliveryOutcome = "delivered"
	DeliveryQuarantined DeliveryOutcome = "quarantined"
	DeliveryRejected    DeliveryOutcome = "rejected"
	DeliveryNotObserved DeliveryOutcome = "not_observed"
	DeliveryUnknown     DeliveryOutcome = "unknown"
)

// EnforcementOutcome is what a security control actively did about the
// scenario, independent of whether it was ever detected or responded to
// afterward.
type EnforcementOutcome string

const (
	EnforcementBlocked      EnforcementOutcome = "blocked"
	EnforcementAllowed      EnforcementOutcome = "allowed"
	EnforcementChallenged   EnforcementOutcome = "challenged"
	EnforcementPolicyExempt EnforcementOutcome = "policy_exempt"
	EnforcementUnknown      EnforcementOutcome = "unknown"
)

// DetectionOutcome is whether an alert was generated for the scenario,
// independent of enforcement. NotDetectedWithinWindow is assertable ONLY
// when the evaluator has verified complete search coverage for the
// window -- never from a provider simply returning zero records (see
// Evaluate).
type DetectionOutcome string

const (
	DetectionDetected                DetectionOutcome = "detected"
	DetectionNotDetectedWithinWindow DetectionOutcome = "not_detected_within_window"
	DetectionInconclusive            DetectionOutcome = "inconclusive"
)

// UserInteractionOutcome is what the targeted human actually did,
// independent of every control dimension above. Values match
// phishing.txt §6's "User interaction" dimension exactly.
type UserInteractionOutcome string

const (
	InteractionReported            UserInteractionOutcome = "reported"
	InteractionOpened              UserInteractionOutcome = "opened"
	InteractionClicked             UserInteractionOutcome = "clicked"
	InteractionSimulatedSubmission UserInteractionOutcome = "simulated_submission"
	InteractionNone                UserInteractionOutcome = "no_interaction"
	InteractionUnknown             UserInteractionOutcome = "unknown"
)

// ResponseOutcome is what happened after detection: remediation,
// containment, or neither. NotApplicable is a legitimate outcome when
// nothing required a response (e.g. the message never reached anyone).
type ResponseOutcome string

const (
	ResponseRemediated          ResponseOutcome = "remediated"
	ResponseContained           ResponseOutcome = "contained"
	ResponsePartiallyRemediated ResponseOutcome = "partially_remediated"
	ResponseFailed              ResponseOutcome = "failed"
	ResponseNotApplicable       ResponseOutcome = "not_applicable"
)

// EvidenceQuality classifies how a dimension's observation was actually
// obtained -- phishing.txt §6's "Evidence" dimension. It is attached per
// observation, never once per whole Outcome: distinct dimensions feeding
// the same Outcome can carry different evidence quality (e.g. enforcement
// observed via a real control receipt, detection inferred from a
// correlation-ID timeout).
type EvidenceQuality string

const (
	EvidenceVerifiedTelemetry EvidenceQuality = "verified_telemetry"
	EvidenceControlReceipt    EvidenceQuality = "control_receipt"
	EvidenceFixture           EvidenceQuality = "fixture"
	EvidenceInferred          EvidenceQuality = "inferred"
	EvidenceMissing           EvidenceQuality = "missing"
)

// Confidence is how much the collected evidence supports the dimension's
// verdict, separate from EvidenceQuality: an observed signal can still be
// low-confidence (e.g. a correlation window wide enough to admit doubt).
type Confidence string

const (
	ConfidenceHigh         Confidence = "high"
	ConfidenceMedium       Confidence = "medium"
	ConfidenceLow          Confidence = "low"
	ConfidenceInsufficient Confidence = "insufficient_evidence"
)

// Verdict is one dimension's terminal grade. Shaped like
// emailgwefficacy.EmailGWVerdict (5 values, not avval's 3) because a
// Phishing BAS outcome needs the same granularity emailgwefficacy
// established for its own 3-dimension model, extended to 5 -- declared
// independently, never imported, per this package's own doc comment.
type Verdict string

const (
	VerdictPass          Verdict = "pass"
	VerdictFail          Verdict = "fail"
	VerdictInconclusive  Verdict = "inconclusive"
	VerdictNotTested     Verdict = "not_tested"
	VerdictNotApplicable Verdict = "not_applicable"
)

// TimeWindow bounds when a dimension's evidence must fall within to count
// as relevant.
type TimeWindow struct {
	Start, End time.Time
}

// DeliveryObservation is one evidence record for the Delivery dimension.
type DeliveryObservation struct {
	Outcome    DeliveryOutcome
	Timestamp  time.Time
	Source     string
	Evidence   EvidenceQuality
	Confidence Confidence
	Detail     string
}

// EnforcementObservation is one evidence record for the Enforcement
// dimension.
type EnforcementObservation struct {
	Outcome        EnforcementOutcome
	ControlProduct string
	PolicyRule     string
	Timestamp      time.Time
	Source         string
	Evidence       EvidenceQuality
	Confidence     Confidence
	Detail         string
}

// DetectionObservation is one evidence record for the Detection
// dimension. SearchedComplete must be true before NotDetectedWithinWindow
// is a safe conclusion -- see Evaluate.
type DetectionObservation struct {
	Outcome          DetectionOutcome
	Product          string
	Rule             string
	CorrelationID    string
	Timestamp        time.Time
	Source           string
	Evidence         EvidenceQuality
	Confidence       Confidence
	SearchedComplete bool
	Detail           string
}

// UserInteractionObservation is one evidence record for the User
// Interaction dimension.
type UserInteractionObservation struct {
	Outcome    UserInteractionOutcome
	Timestamp  time.Time
	Source     string
	Evidence   EvidenceQuality
	Confidence Confidence
	Detail     string
}

// ResponseObservation is one evidence record for the Response dimension.
type ResponseObservation struct {
	Outcome            ResponseOutcome
	ActionRequired     string
	DurationToComplete time.Duration
	CorrelationID      string
	Timestamp          time.Time
	Source             string
	Evidence           EvidenceQuality
	Confidence         Confidence
	Detail             string
}

// Expectation declares what a Phishing BAS scenario expects on each
// applicable dimension, and the policy basis it derives from.
// PolicyVerified is false whenever the policy was merely supplied as test
// input, never confirmed in force -- same discipline as
// controlval.Expectation/avval.Expectation/emailgwefficacy's own
// PolicyVerified-shaped fields, independently declared here.
type Expectation struct {
	ScenarioID      string
	Delivery        *DeliveryOutcome
	Enforcement     *EnforcementOutcome
	Detection       *DetectionOutcome
	UserInteraction *UserInteractionOutcome
	Response        *ResponseOutcome
	PolicyBasis     string
	PolicyVerified  bool
}

// Observation is the full set of per-dimension evidence collected for one
// scenario execution. Any dimension may be nil when that evidence stream
// was never collected -- never fabricated from another dimension.
type Observation struct {
	Delivery        *DeliveryObservation
	Enforcement     *EnforcementObservation
	Detection       *DetectionObservation
	UserInteraction *UserInteractionObservation
	Response        *ResponseObservation
}

// DimensionResult is one dimension's graded result.
type DimensionResult struct {
	Verdict    Verdict
	Reason     string
	Evidence   EvidenceQuality
	Confidence Confidence
}

// Outcome is the full seven-dimension result of one Phishing BAS scenario
// execution: five independently-verdicted dimensions
// (Delivery/Enforcement/Detection/UserInteraction/Response) plus the
// Expectation/Observation that produced them. Evidence quality and
// confidence are per-dimension fields on DimensionResult, not additional
// top-level verdicts -- phishing.txt §6 lists them as dimensions of the
// outcome MODEL, not as a sixth/seventh pass-or-fail axis, and every
// DimensionResult already carries its own Evidence/Confidence pair.
type Outcome struct {
	RunID       string
	ScenarioID  string
	Variant     string
	Expectation Expectation
	Observation Observation

	Delivery        DimensionResult
	Enforcement     DimensionResult
	Detection       DimensionResult
	UserInteraction DimensionResult
	Response        DimensionResult
}
