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
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
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
	}
}

// automaticVerifier resolves on-host endpoint expectations from the run's own
// detection correlation (DetectionVerdict + alert/blocking provider). Domains it
// cannot observe from the endpoint (SIEM/identity/cloud/email) return Unknown so
// they never inflate a score without real evidence.
type automaticVerifier struct{}

func (automaticVerifier) Verify(exp scenario.ExpectedDetection, ev StepEvidence) VerificationResult {
	r := baseResult(exp, ev, "automatic")
	if scenario.ResolveDomain(exp) != scenario.DomainEndpoint {
		r.Status = StatusUnknown
		return r
	}
	switch ev.DetectionVerdict {
	case "detected":
		src := ev.AlertProvider
		if src == "" {
			src = classifyDetection(ev.Events).Source
		}
		if providerMatches(exp.Provider, src) {
			r.Status, r.Source = StatusDetected, src
		} else {
			r.Status = StatusNotDetected
		}
	case "prevented":
		if providerMatches(exp.Provider, ev.BlockingControl) {
			r.Status, r.Source = StatusDetected, ev.BlockingControl
		} else {
			r.Status = StatusNotDetected
		}
	default: // undetected / empty
		r.Status = StatusNotDetected
	}
	return r
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

// ExpectationRow is one expected-vs-observed row in the detail table.
type ExpectationRow struct {
	TechniqueID  string `json:"techniqueId"`
	ExpectedID   string `json:"expectedId"`
	Provider     string `json:"provider"`
	Domain       string `json:"domain"`
	Confidence   string `json:"confidence"`
	Verification string `json:"verification"`
	Status       string `json:"status"`
	Source       string `json:"source,omitempty"`
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
func (e *Engine) buildDetectionValidation(scenarioID string, results []models.SimulationResult) DetectionValidationSection {
	if e.scenarios == nil || scenarioID == "" {
		return DetectionValidationSection{}
	}
	sc, ok := e.scenarios.Get(scenarioID)
	if !ok {
		return DetectionValidationSection{}
	}
	var specs []StepDetectionSpec
	for _, step := range sc.Steps {
		exp, refs := e.scenarios.ResolveStepExpectations(step)
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
	return BuildDetectionValidation(specs, results)
}

// BuildDetectionValidation runs the verification engine over every step's
// expectations and rolls the results into the report section.
func BuildDetectionValidation(specs []StepDetectionSpec, results []models.SimulationResult) DetectionValidationSection {
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
			domain := vr.Domain
			dw := domAgg[domain]
			if dw == nil {
				dw = &domainAcc{row: DomainValidationRow{Domain: domain}}
				domAgg[domain] = dw
			}
			w := scenario.ConfidenceWeight(exp.Confidence)

			sec.Rows = append(sec.Rows, ExpectationRow{
				TechniqueID:  spec.TechniqueID,
				ExpectedID:   exp.ID,
				Provider:     providerDisplay(exp.Provider),
				Domain:       domain,
				Confidence:   exp.Confidence,
				Verification: scenario.ResolveVerification(exp),
				Status:       vr.Status,
				Source:       vr.Source,
			})

			// Optional expectations are informational: counted nowhere.
			if exp.Confidence == scenario.ConfidenceOptional {
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
			TechniqueID:      r.ID,
			DetectionVerdict: r.DetectionVerdict,
			Events:           r.Events,
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
