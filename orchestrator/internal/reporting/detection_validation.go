package reporting

// Detection Validation Pack — Sub-project 1 verification engine + scoring.
//
// Given a step's EXPECTED detections (resolved from detection profiles) and the
// ACTUAL signal the agent observed for that step, this produces gap analysis:
// which expected controls responded, which stayed silent (a finding), and which
// products alerted that nobody expected (noise/coverage). The engine is a pure
// function of (expectations, evidence) so it is fully unit-testable and has no
// I/O — SP2 (manual) and SP3 (API) add verifiers without changing it.

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/verification"
)

// Verification statuses for a single expected detection.
const (
	StatusDetected      = "Detected"      // the expected control responded
	StatusNotDetected   = "NotDetected"   // resolved: control was silent (a gap)
	StatusNotApplicable = "NotApplicable" // expectation does not apply to this run
	StatusUnknown       = "Unknown"       // could not be auto-verified on-host (SP1)
	StatusPending       = "Pending"       // awaits manual (SP2) or API (SP3) verification
)

// Unexpected-detection severities (a product alerted with no matching expectation).
const (
	UnexpectedInfo    = "Info"
	UnexpectedReview  = "Review"
	UnexpectedWarning = "Warning"
)

// StepEvidence is the actual signal observed for one executed step. Built from a
// models.SimulationResult by the caller; the verifier evaluates it in isolation.
type StepEvidence struct {
	TechniqueID       string
	DetectionVerdict  string   // prevented | detected | undetected | ""
	AlertProvider     string   // DetectionAlert.Provider when detected
	BlockingControl   string   // BlockingControl.Name when prevented
	Events            []string // raw Windows event tokens ("1116:...Defender/Operational")
	ExpectedTelemetry []string // step's expected telemetry lines (for completeness)
	RawOutput         string   // full step output text; read by verifiers that parse a self-reported marker, e.g. dlpVerifier
	// SinkTokenObserved mirrors models.SimulationResult's field of the same
	// name -- see its doc comment.
	SinkTokenObserved *bool
}

// VerificationResult is the outcome of checking one expected detection.
type VerificationResult struct {
	ExpectedID  string
	Provider    string
	Domain      string
	Confidence  string
	Status      string
	Source      string
	VerifiedBy  string // "automatic" | analyst id (SP2) | connector (SP3)
	Timestamp   time.Time
	Finding     scenario.ExpectedFinding
	TechniqueID string

	// ExpectedOutcome/ObservedOutcome/Comparison are the Outcome Validation
	// Framework's richer internal computation — not surfaced in any report
	// JSON (ExpectationRow has no equivalent fields). Status remains the only
	// field existing scoring/report code consumes, now derived from Comparison.
	ExpectedOutcome string
	ObservedOutcome string
	Comparison      ComparisonResult

	// RuleIDs links this verdict to Detection Rule Library entries
	// (internal/rulelib.Rule.ID), carried through from the live
	// ExpectedDetection.RuleIDs at verification time. Not surfaced in any
	// report JSON today — read by the automatic-verdict-persistence poller
	// (internal/verifysync) so it can persist the linkage onto
	// verification.Record.
	RuleIDs []string
}

// Verifier resolves one expectation against observed evidence. The dispatch in
// verifyExpectation selects the concrete verifier by the expectation's
// (resolved) verification model — automatic today, manual/api as stubs.
type Verifier interface {
	Verify(exp scenario.ExpectedDetection, ev StepEvidence) VerificationResult
}

// verifyExpectation dispatches to the verifier for the expectation's resolved
// verification model.
func verifyExpectation(exp scenario.ExpectedDetection, ev StepEvidence) VerificationResult {
	switch scenario.ResolveVerification(exp) {
	case scenario.VerificationAutomatic:
		if scenario.ResolveOutcomeFamily(exp) == "dlp" {
			return dlpVerifier{}.Verify(exp, ev)
		}
		return automaticVerifier{}.Verify(exp, ev)
	case scenario.VerificationAPI:
		return apiVerifier{}.Verify(exp, ev)
	default: // manual
		return manualVerifier{}.Verify(exp, ev)
	}
}

func baseResult(exp scenario.ExpectedDetection, ev StepEvidence, verifiedBy string) VerificationResult {
	return VerificationResult{
		ExpectedID:  exp.ID,
		Provider:    exp.Provider,
		Domain:      scenario.ResolveDomain(exp),
		Confidence:  exp.Confidence,
		VerifiedBy:  verifiedBy,
		Timestamp:   time.Now().UTC(),
		Finding:     exp.Finding,
		TechniqueID: ev.TechniqueID,
		RuleIDs:     exp.RuleIDs,
	}
}

// automaticVerifier resolves on-host endpoint expectations from the run's own
// detection correlation (DetectionVerdict + alert/blocking provider). Domains it
// cannot observe from the endpoint (SIEM/identity/cloud/email) return Unknown so
// they never inflate a score without real evidence.
type automaticVerifier struct{}

func (automaticVerifier) Verify(exp scenario.ExpectedDetection, ev StepEvidence) VerificationResult {
	r := baseResult(exp, ev, "automatic")
	r.ExpectedOutcome = scenario.ResolveExpectedOutcome(exp)
	r.ObservedOutcome, r.Source = observeDetectionOutcome(exp, ev)
	r.Comparison = comparatorFor(scenario.ResolveOutcomeFamily(exp)).Compare(r.ExpectedOutcome, r.ObservedOutcome)
	r.Status = collapseToStatus(r.Comparison)
	return r
}

// observeDetectionOutcome is automaticVerifier's pre-existing evidence switch,
// extracted verbatim and translated into a (token, source) pair instead of
// setting Status/Source directly. The empty-string token means "not
// observable by this verifier at all" (non-endpoint domain) — distinct from
// the "NotDetected" token, which means "observable, but no matching control
// responded." Collapsing both to the same empty signal would make MissingEvidence
// and Mismatch indistinguishable, breaking today's Unknown-vs-NotDetected split.
func observeDetectionOutcome(exp scenario.ExpectedDetection, ev StepEvidence) (outcome, source string) {
	if scenario.ResolveDomain(exp) != scenario.DomainEndpoint {
		return "", ""
	}
	switch ev.DetectionVerdict {
	case "detected":
		src := ev.AlertProvider
		if src == "" {
			src = classifyDetection(ev.Events).Source
		}
		if providerMatches(exp.Provider, src) {
			return "Detected", src
		}
		return "NotDetected", ""
	case "prevented":
		if providerMatches(exp.Provider, ev.BlockingControl) {
			return "Detected", ev.BlockingControl
		}
		return "NotDetected", ""
	default: // undetected / empty
		return "NotDetected", ""
	}
}

// manualVerifier is an SP1 stub — off-host expectations await analyst attestation
// (SP2). Returns Pending so they count toward Verification Completeness's
// denominator but never toward Coverage.
type manualVerifier struct{}

func (manualVerifier) Verify(exp scenario.ExpectedDetection, ev StepEvidence) VerificationResult {
	r := baseResult(exp, ev, "manual")
	r.Status = StatusPending
	return r
}

// apiVerifier is an SP1 stub — connector-based verification arrives in SP3.
type apiVerifier struct{}

func (apiVerifier) Verify(exp scenario.ExpectedDetection, ev StepEvidence) VerificationResult {
	r := baseResult(exp, ev, "api")
	r.Status = StatusPending
	return r
}

// applyOverride replaces an automatic verdict with a stored attestation. Only an
// Approved workflow yields a resolved status that feeds Coverage; Pending,
// NeedsReview and Rejected all read as Pending (unresolved) for scoring so an
// in-flight review never inflates the score.
func applyOverride(vr *VerificationResult, ov StoredVerification) {
	if ov.Source != "" {
		vr.Source = ov.Source
	}
	vr.VerifiedBy = ov.VerifiedBy
	if !ov.VerifiedAt.IsZero() {
		vr.Timestamp = ov.VerifiedAt.UTC()
	}
	if ov.WorkflowState != verification.StateApproved {
		vr.Status = StatusPending
		return
	}
	switch ov.Result {
	case verification.ResultDetected:
		vr.Status = StatusDetected
	case verification.ResultNotDetected:
		vr.Status = StatusNotDetected
	case verification.ResultNotApplicable:
		vr.Status = StatusNotApplicable
	default:
		vr.Status = StatusPending
	}
}

// providerMatches reports whether an observed provider/control string
// corresponds to an expected provider registry key. Matches on the provider's
// display name or the distinctive trailing token of its key
// ("microsoft_defender" → "defender", which also matches "Defender ASR: …").
func providerMatches(expKey, observed string) bool {
	if strings.TrimSpace(observed) == "" {
		return false
	}
	obs := strings.ToLower(observed)
	if p, ok := scenario.LookupProvider(expKey); ok && p.DisplayName != "" {
		if strings.Contains(obs, strings.ToLower(p.DisplayName)) {
			return true
		}
	}
	parts := strings.Split(strings.ToLower(strings.TrimSpace(expKey)), "_")
	token := parts[len(parts)-1]
	return token != "" && strings.Contains(obs, token)
}

// ─────────────────────────────────────────────────────────────────────────────
// Scoring / gap analysis
// ─────────────────────────────────────────────────────────────────────────────

// StepDetectionSpec is one executed step's resolved detection expectations plus
// its expected telemetry, as authored/resolved from detection profiles. The
// caller correlates these to run results by TechniqueID.
type StepDetectionSpec struct {
	TechniqueID string
	Expected    []scenario.ExpectedDetection
	Telemetry   []string
	ProfileRefs []scenario.ProfileRef
}

// ComputeAutomaticVerifications runs the automatic verification engine over
// every step's expectations for one run and returns the raw, unaggregated
// per-expectation results — the same per-expectation computation
// BuildDetectionValidationWithStore performs internally, exposed here for
// callers (the automatic-verdict-persistence poller, internal/verifysync)
// that need individual verdicts rather than a rendered report section. Kept
// as its own small loop rather than sharing BuildDetectionValidationWithStore's
// larger loop — that loop also builds report rows and running score
// aggregates in the same pass, and forcing a shared call there would risk
// the byte-identical-report guarantee TestBuildDetectionValidationGoldenOutput
// protects.
func ComputeAutomaticVerifications(specs []StepDetectionSpec, results []models.SimulationResult) []VerificationResult {
	evByTech := evidenceByTechnique(results)
	var out []VerificationResult
	for _, spec := range specs {
		ev := evByTech[spec.TechniqueID]
		ev.TechniqueID = spec.TechniqueID
		for _, exp := range spec.Expected {
			out = append(out, verifyExpectation(exp, ev))
		}
	}
	return out
}

// ResolveStepDetectionSpecs resolves a scenario's steps into their detection
// expectations via the given resolver. Returns nil if the scenario is
// unknown or declares no expectations anywhere — callers should treat that
// as nothing to verify, not an error.
func ResolveStepDetectionSpecs(scenarios ScenarioResolver, scenarioID string) []StepDetectionSpec {
	sc, ok := scenarios.Get(scenarioID)
	if !ok {
		return nil
	}
	var specs []StepDetectionSpec
	for _, step := range sc.Steps {
		exp, refs := scenarios.ResolveStepExpectations(step)
		if len(exp) == 0 {
			continue
		}
		specs = append(specs, StepDetectionSpec{
			TechniqueID: step.TechniqueID,
			Expected:    exp,
			Telemetry:   step.Telemetry,
			ProfileRefs: refs,
		})
	}
	return specs
}

// DetectionValidationSection is the report section for expected-vs-actual gap
// analysis. HasData is false when no step in the run declared any expectation
// (backward-compatible: such runs render exactly as before).
type DetectionValidationSection struct {
	HasData                  bool                     `json:"hasData"`
	Coverage                 float64                  `json:"coverage"`                 // Σ(weight·detected)/Σ(weight), required+recommended, verifiable
	VerificationCompleteness float64                  `json:"verificationCompleteness"` // verified/expected, required+recommended
	Overall                  float64                  `json:"overall"`                  // = weighted global coverage (roll-up of domains)
	TelemetryCompleteness    float64                  `json:"telemetryCompleteness"`
	Expected                 int                      `json:"expected"`
	Verified                 int                      `json:"verified"`
	Detected                 int                      `json:"detected"`
	ByDomain                 []DomainValidationRow    `json:"byDomain"`
	Rows                     []ExpectationRow         `json:"rows"`
	FalseSilence             []GapFinding             `json:"falseSilence"`
	UnexpectedDetections     []UnexpectedDetectionRow `json:"unexpectedDetections"`
	Profiles                 []scenario.ProfileRef    `json:"profiles"`
}

// DomainValidationRow is the per-domain slice of the validation matrix.
type DomainValidationRow struct {
	Domain                   string  `json:"domain"`
	Expected                 int     `json:"expected"`
	Verified                 int     `json:"verified"`
	Detected                 int     `json:"detected"`
	Coverage                 float64 `json:"coverage"`
	VerificationCompleteness float64 `json:"verificationCompleteness"`
}

// ExpectationRow is one expected-vs-observed row in the detail table. The
// attestation columns (Analyst … Comments) are populated from the Verification
// Store when a manual/API verdict overrides the automatic one.
type ExpectationRow struct {
	TechniqueID   string `json:"techniqueId"`
	ExpectedID    string `json:"expectedId"`
	Provider      string `json:"provider"`
	Domain        string `json:"domain"`
	Confidence    string `json:"confidence"`
	Verification  string `json:"verification"`
	Status        string `json:"status"`
	Source        string `json:"source,omitempty"`
	WorkflowState string `json:"workflowState,omitempty"` // Pending/NeedsReview/Approved/Rejected
	Analyst       string `json:"analyst,omitempty"`       // who attested
	Timestamp     string `json:"timestamp,omitempty"`     // when attested (RFC3339)
	EvidenceCount int    `json:"evidenceCount"`
	Integrity     string `json:"integrity,omitempty"` // "SHA-256 recorded at upload"
	Comments      string `json:"comments,omitempty"`
}

// StoredVerification is the reporting-layer view of one active attestation from
// the Verification Store. It carries only what scoring and the report table
// need, so the pure builder never imports the store's persistence types.
type StoredVerification struct {
	Result        string    // Detected / NotDetected / NotApplicable
	WorkflowState string    // Pending / NeedsReview / Approved / Rejected
	Source        string    // automatic / manual / api / imported / migration
	VerifiedBy    string    // analyst id or connector name
	VerifiedAt    time.Time // attestation time
	Note          string    // analyst comment
	AlertID       string    // linked alert / ticket reference
	EvidenceCount int       // non-deleted evidence items attached
	HashRecorded  bool      // at least one evidence item carries a content hash
}

// GapFinding is a False Silence — an expected (required/recommended) control that
// stayed silent. The finding text is the expectation's own, verbatim.
type GapFinding struct {
	TechniqueID string `json:"techniqueId"`
	Provider    string `json:"provider"`
	Domain      string `json:"domain"`
	Confidence  string `json:"confidence"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Remediation string `json:"remediation"`
	Reference   string `json:"reference,omitempty"`
}

// UnexpectedDetectionRow is a product alert that matched no expectation for the
// step — either welcome extra coverage or a noisy/false-positive rule to review.
type UnexpectedDetectionRow struct {
	TechniqueID string `json:"techniqueId"`
	Provider    string `json:"provider"`
	Severity    string `json:"severity"`
	Detail      string `json:"detail"`
}

// buildDetectionValidation resolves a run's scenario into per-step detection
// specs (expected detections + telemetry, resolved from detection profiles) and
// runs the verification engine over them. Returns an empty (HasData=false)
// section when the resolver is unwired, the scenario is unknown, or no step
// declares any expectation — all of which render exactly as before.
func (e *Engine) buildDetectionValidation(ctx context.Context, runID, scenarioID string, results []models.SimulationResult) DetectionValidationSection {
	if e.scenarios == nil || scenarioID == "" {
		return DetectionValidationSection{}
	}
	specs := ResolveStepDetectionSpecs(e.scenarios, scenarioID)
	// Overlay stored attestations (manual SP2 / API SP3). Off-host expectations
	// the automatic engine could only mark Pending become resolved here once an
	// analyst or connector has verified them. Kept read-only: reporting consumes
	// the store, never writes it.
	overrides := e.storedVerifications(ctx, runID)
	return BuildDetectionValidationWithStore(specs, results, overrides)
}

// storedVerifications loads the run's active attestations from the Verification
// Store and folds in each verification's evidence count. Returns nil when the
// store is unwired or runID is empty (campaign roll-up), so scoring falls back
// to automatic-only — identical to SP1.
func (e *Engine) storedVerifications(ctx context.Context, runID string) map[string]StoredVerification {
	if e.verifications == nil || runID == "" {
		return nil
	}
	recs, err := e.verifications.CurrentForRun(ctx, runID)
	if err != nil || len(recs) == 0 {
		return nil
	}
	counts, _ := e.verifications.EvidenceCountsForRun(ctx, runID)
	out := make(map[string]StoredVerification, len(recs))
	for expID, r := range recs {
		n := counts[r.ID]
		out[expID] = StoredVerification{
			Result:        r.Result,
			WorkflowState: r.WorkflowState,
			Source:        r.Source,
			VerifiedBy:    r.VerifiedBy,
			VerifiedAt:    r.VerifiedAt,
			Note:          r.Note,
			AlertID:       r.AlertID,
			EvidenceCount: n,
			HashRecorded:  n > 0,
		}
	}
	return out
}

// BuildDetectionValidation runs the automatic verification engine over every
// step's expectations and rolls the results into the report section. Equivalent
// to BuildDetectionValidationWithStore with no stored attestations.
func BuildDetectionValidation(specs []StepDetectionSpec, results []models.SimulationResult) DetectionValidationSection {
	return BuildDetectionValidationWithStore(specs, results, nil)
}

// BuildDetectionValidationWithStore is BuildDetectionValidation plus an overlay
// of stored attestations keyed by expectation id. Where a stored attestation
// exists it is authoritative — the automatic verdict is replaced by the
// analyst/API verdict, and only an Approved workflow feeds Coverage.
func BuildDetectionValidationWithStore(specs []StepDetectionSpec, results []models.SimulationResult, overrides map[string]StoredVerification) DetectionValidationSection {
	sec := DetectionValidationSection{}

	// Any expectations at all?
	total := 0
	for _, s := range specs {
		total += len(s.Expected)
	}
	if total == 0 {
		return sec // HasData=false → backward-compatible rendering
	}
	sec.HasData = true

	evByTech := evidenceByTechnique(results)
	domAgg := map[string]*domainAcc{}
	profSet := map[string]int{}

	var covNum, covDen float64
	var telExpected, telPresent int

	for _, spec := range specs {
		ev := evByTech[spec.TechniqueID]
		ev.TechniqueID = spec.TechniqueID
		ev.ExpectedTelemetry = spec.Telemetry

		// Telemetry completeness for this step.
		en, ep := telemetryCompleteness(spec.Telemetry, ev.Events)
		telExpected += en
		telPresent += ep

		for _, ref := range spec.ProfileRefs {
			profSet[ref.Profile] = ref.Version
		}

		expected := spec.Expected

		for _, exp := range expected {
			vr := verifyExpectation(exp, ev)
			row := ExpectationRow{
				TechniqueID:   spec.TechniqueID,
				ExpectedID:    exp.ID,
				Provider:      providerDisplay(exp.Provider),
				Confidence:    exp.Confidence,
				Verification:  scenario.ResolveVerification(exp),
				Status:        vr.Status,
				Source:        vr.Source,
				WorkflowState: verification.StateApproved, // automatic verdicts are final
			}
			// A stored attestation (manual/API) overrides the automatic verdict.
			if ov, ok := overrides[exp.ID]; ok {
				applyOverride(&vr, ov)
				row.Status = vr.Status
				row.Source = vr.Source
				row.WorkflowState = ov.WorkflowState
				row.Analyst = ov.VerifiedBy
				if !ov.VerifiedAt.IsZero() {
					row.Timestamp = ov.VerifiedAt.UTC().Format(time.RFC3339)
				}
				row.EvidenceCount = ov.EvidenceCount
				row.Comments = ov.Note
				if ov.HashRecorded {
					row.Integrity = "SHA-256 recorded at upload"
				}
			}
			domain := vr.Domain
			dw := domAgg[domain]
			if dw == nil {
				dw = &domainAcc{row: DomainValidationRow{Domain: domain}}
				domAgg[domain] = dw
			}
			w := scenario.ConfidenceWeight(exp.Confidence)

			row.Domain = domain
			sec.Rows = append(sec.Rows, row)

			// Optional expectations are informational; NotApplicable attestations
			// are excluded by the analyst — neither is scored.
			if exp.Confidence == scenario.ConfidenceOptional || vr.Status == StatusNotApplicable {
				continue
			}

			sec.Expected++
			dw.row.Expected++

			resolved := vr.Status == StatusDetected || vr.Status == StatusNotDetected
			if resolved {
				sec.Verified++
				dw.row.Verified++
				covDen += w
				dw.covDen += w
			}
			if vr.Status == StatusDetected {
				sec.Detected++
				dw.row.Detected++
				covNum += w
				dw.covNum += w
			}
			// False Silence: a resolved-but-not-detected required/recommended
			// expectation emits its finding verbatim.
			if vr.Status == StatusNotDetected && vr.Finding.Title != "" {
				sec.FalseSilence = append(sec.FalseSilence, GapFinding{
					TechniqueID: spec.TechniqueID,
					Provider:    providerDisplay(exp.Provider),
					Domain:      domain,
					Confidence:  exp.Confidence,
					Severity:    vr.Finding.Severity,
					Title:       vr.Finding.Title,
					Remediation: vr.Finding.Remediation,
					Reference:   vr.Finding.Reference,
				})
			}
		}

		// Unexpected detection: the step actually fired a detection whose provider
		// matches none of its expectations.
		if ev.DetectionVerdict == "detected" || ev.DetectionVerdict == "prevented" {
			observed := ev.AlertProvider
			if observed == "" {
				observed = ev.BlockingControl
			}
			if observed == "" {
				observed = classifyDetection(ev.Events).Source
			}
			if observed != "" && !anyExpectationMatches(expected, observed) {
				sec.UnexpectedDetections = append(sec.UnexpectedDetections, UnexpectedDetectionRow{
					TechniqueID: spec.TechniqueID,
					Provider:    observed,
					Severity:    UnexpectedReview, // default; Info/Warning tuning is SP2
					Detail:      "A control alerted with no matching expectation for this step — confirm it is intended coverage, not a noisy or duplicate rule.",
				})
			}
		}
	}

	if covDen > 0 {
		sec.Coverage = round1(covNum / covDen * 100)
	}
	sec.Overall = sec.Coverage
	if sec.Expected > 0 {
		sec.VerificationCompleteness = round1(float64(sec.Verified) / float64(sec.Expected) * 100)
	}
	if telExpected > 0 {
		sec.TelemetryCompleteness = round1(float64(telPresent) / float64(telExpected) * 100)
	}

	// Finalize per-domain rates.
	for _, d := range domAgg {
		if d.covDen > 0 {
			d.row.Coverage = round1(d.covNum / d.covDen * 100)
		}
		if d.row.Expected > 0 {
			d.row.VerificationCompleteness = round1(float64(d.row.Verified) / float64(d.row.Expected) * 100)
		}
		sec.ByDomain = append(sec.ByDomain, d.row)
	}
	sort.Slice(sec.ByDomain, func(i, j int) bool { return sec.ByDomain[i].Domain < sec.ByDomain[j].Domain })

	for name, ver := range profSet {
		sec.Profiles = append(sec.Profiles, scenario.ProfileRef{Profile: name, Version: ver})
	}
	sort.Slice(sec.Profiles, func(i, j int) bool { return sec.Profiles[i].Profile < sec.Profiles[j].Profile })

	sort.Slice(sec.FalseSilence, func(i, j int) bool {
		return severityRank(sec.FalseSilence[i].Severity) > severityRank(sec.FalseSilence[j].Severity)
	})

	return sec
}

// domainAcc holds a domain row plus the running weighted numerator/denominator
// used to compute its coverage; the row's rate fields are finalized at the end.
type domainAcc struct {
	row            DomainValidationRow
	covNum, covDen float64
}

func evidenceByTechnique(results []models.SimulationResult) map[string]StepEvidence {
	out := map[string]StepEvidence{}
	for _, r := range results {
		ev := StepEvidence{
			TechniqueID:       r.ID,
			DetectionVerdict:  r.DetectionVerdict,
			Events:            r.Events,
			RawOutput:         r.RawOutput,
			SinkTokenObserved: r.SinkTokenObserved,
		}
		if r.DetectionAlert != nil {
			ev.AlertProvider = r.DetectionAlert.Provider
		}
		if r.BlockingControl != nil {
			ev.BlockingControl = r.BlockingControl.Name
		}
		// If multiple steps share a technique, prefer the one that actually fired
		// a detection so the expectation isn't marked silent by a sibling step.
		if prev, ok := out[r.ID]; ok {
			if prev.DetectionVerdict == "detected" || prev.DetectionVerdict == "prevented" {
				continue
			}
		}
		out[r.ID] = ev
	}
	return out
}

func anyExpectationMatches(exps []scenario.ExpectedDetection, observed string) bool {
	for _, e := range exps {
		if providerMatches(e.Provider, observed) {
			return true
		}
	}
	return false
}

var telemetryEIDRe = regexp.MustCompile(`(?i)\b(?:EID|Event\s*ID)\s*(\d{1,5})`)

// telemetryCompleteness returns (expectedCount, presentCount): how many of the
// step's expected telemetry lines carry an EID that appears in observed events.
// Telemetry lines with no parseable EID are excluded from the denominator.
func telemetryCompleteness(expected, events []string) (int, int) {
	observed := map[string]bool{}
	for _, ev := range events {
		if id := leadingEventID(ev); id != "" {
			observed[id] = true
		}
	}
	var en, ep int
	for _, line := range expected {
		m := telemetryEIDRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		en++
		if observed[m[1]] {
			ep++
		}
	}
	return en, ep
}

// leadingEventID extracts the numeric id from an event token "1116:LogName".
func leadingEventID(token string) string {
	if i := strings.IndexByte(token, ':'); i > 0 {
		return strings.TrimSpace(token[:i])
	}
	return ""
}

func providerDisplay(key string) string {
	if p, ok := scenario.LookupProvider(key); ok {
		return p.DisplayName
	}
	return key
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}
