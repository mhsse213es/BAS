package reporting

import (
	"reflect"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/verification"
)

func endpointExp(id, provider, confidence string) scenario.ExpectedDetection {
	return scenario.ExpectedDetection{
		ID:         id,
		Provider:   provider,
		Type:       scenario.DomainEndpoint,
		Confidence: confidence,
		Finding:    scenario.ExpectedFinding{Title: "gap: " + id, Severity: "High", Remediation: "fix it"},
	}
}

func TestProviderMatches(t *testing.T) {
	cases := []struct {
		expKey, observed string
		want             bool
	}{
		{"microsoft_defender", "Microsoft Defender", true},
		{"microsoft_defender", "Defender ASR: Block obfuscated scripts", true},
		{"crowdstrike", "CrowdStrike Falcon Sensor", true},
		{"microsoft_defender", "Splunk", false},
		{"microsoft_defender", "", false},
	}
	for _, c := range cases {
		if got := providerMatches(c.expKey, c.observed); got != c.want {
			t.Errorf("providerMatches(%q,%q)=%v want %v", c.expKey, c.observed, got, c.want)
		}
	}
}

func TestAutomaticVerifier(t *testing.T) {
	exp := endpointExp("e1", "microsoft_defender", scenario.ConfidenceRequired)

	// detected by the expected provider → Detected
	r := automaticVerifier{}.Verify(exp, StepEvidence{DetectionVerdict: "detected", AlertProvider: "Microsoft Defender"})
	if r.Status != StatusDetected {
		t.Errorf("detected-match: got %s want Detected", r.Status)
	}
	if r.ExpectedOutcome != "Detected" || r.ObservedOutcome != "Detected" || r.Comparison != Match {
		t.Errorf("detected-match outcome fields: got expected=%q observed=%q comparison=%v", r.ExpectedOutcome, r.ObservedOutcome, r.Comparison)
	}

	// detected by a different provider → NotDetected (the expected one stayed silent)
	r = automaticVerifier{}.Verify(exp, StepEvidence{DetectionVerdict: "detected", AlertProvider: "CrowdStrike Falcon"})
	if r.Status != StatusNotDetected {
		t.Errorf("detected-mismatch: got %s want NotDetected", r.Status)
	}
	if r.ObservedOutcome != "NotDetected" || r.Comparison != Mismatch {
		t.Errorf("detected-mismatch outcome fields: got observed=%q comparison=%v", r.ObservedOutcome, r.Comparison)
	}

	// prevented by the expected control → Detected
	r = automaticVerifier{}.Verify(exp, StepEvidence{DetectionVerdict: "prevented", BlockingControl: "Defender ASR"})
	if r.Status != StatusDetected {
		t.Errorf("prevented-match: got %s want Detected", r.Status)
	}
	if r.Comparison != Match {
		t.Errorf("prevented-match comparison: got %v want Match", r.Comparison)
	}

	// undetected → NotDetected
	r = automaticVerifier{}.Verify(exp, StepEvidence{DetectionVerdict: "undetected"})
	if r.Status != StatusNotDetected {
		t.Errorf("undetected: got %s want NotDetected", r.Status)
	}
	if r.ObservedOutcome != "NotDetected" || r.Comparison != Mismatch {
		t.Errorf("undetected outcome fields: got observed=%q comparison=%v", r.ObservedOutcome, r.Comparison)
	}

	// non-endpoint domain is not on-host observable → Unknown
	netExp := scenario.ExpectedDetection{ID: "n", Provider: "microsoft_sentinel", Type: scenario.DomainNetwork, Confidence: scenario.ConfidenceRequired, Finding: scenario.ExpectedFinding{Title: "t", Severity: "High"}}
	r = automaticVerifier{}.Verify(netExp, StepEvidence{DetectionVerdict: "detected", AlertProvider: "Microsoft Defender"})
	if r.Status != StatusUnknown {
		t.Errorf("non-endpoint: got %s want Unknown", r.Status)
	}
	if r.ObservedOutcome != "" || r.Comparison != MissingEvidence {
		t.Errorf("non-endpoint outcome fields: got observed=%q comparison=%v want empty/MissingEvidence", r.ObservedOutcome, r.Comparison)
	}
}

func TestAutomaticVerifier_ThreadsRuleIDs(t *testing.T) {
	exp := endpointExp("e1", "microsoft_defender", scenario.ConfidenceRequired)
	exp.RuleIDs = []string{"AUDRULE-000001", "AUDRULE-000002"}

	r := automaticVerifier{}.Verify(exp, StepEvidence{DetectionVerdict: "detected", AlertProvider: "Microsoft Defender"})
	if len(r.RuleIDs) != 2 || r.RuleIDs[0] != "AUDRULE-000001" || r.RuleIDs[1] != "AUDRULE-000002" {
		t.Errorf("RuleIDs = %v, want [AUDRULE-000001 AUDRULE-000002]", r.RuleIDs)
	}
}

func TestComputeAutomaticVerifications(t *testing.T) {
	specs := []StepDetectionSpec{
		{
			TechniqueID: "T1055",
			Expected:    []scenario.ExpectedDetection{endpointExp("e1", "microsoft_defender", scenario.ConfidenceRequired)},
		},
	}
	results := []models.SimulationResult{
		{ID: "T1055", DetectionVerdict: "detected", DetectionAlert: &models.DetectionAlert{Provider: "Microsoft Defender"}},
	}
	got := ComputeAutomaticVerifications(specs, results)
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	if got[0].ExpectedID != "e1" || got[0].Status != StatusDetected {
		t.Errorf("got[0] = %+v, want ExpectedID=e1 Status=Detected", got[0])
	}
}

type fakeScenarioResolver struct {
	scenarios map[string]*scenario.Scenario
	expByStep map[string][]scenario.ExpectedDetection
}

func (f fakeScenarioResolver) Get(id string) (*scenario.Scenario, bool) {
	sc, ok := f.scenarios[id]
	return sc, ok
}

func (f fakeScenarioResolver) ResolveStepExpectations(step scenario.Step) ([]scenario.ExpectedDetection, []scenario.ProfileRef) {
	return f.expByStep[step.TechniqueID], nil
}

func TestResolveStepDetectionSpecs(t *testing.T) {
	resolver := fakeScenarioResolver{
		scenarios: map[string]*scenario.Scenario{
			"sc-1": {
				ID: "sc-1",
				Steps: []scenario.Step{
					{TechniqueID: "T1055", Telemetry: []string{"Sysmon EID 1"}},
					{TechniqueID: "T1003"}, // no expectations declared
				},
			},
		},
		expByStep: map[string][]scenario.ExpectedDetection{
			"T1055": {endpointExp("e1", "microsoft_defender", scenario.ConfidenceRequired)},
		},
	}

	specs := ResolveStepDetectionSpecs(resolver, "sc-1")
	if len(specs) != 1 {
		t.Fatalf("len(specs) = %d, want 1 (step with zero expectations must be excluded)", len(specs))
	}
	if specs[0].TechniqueID != "T1055" || len(specs[0].Expected) != 1 {
		t.Errorf("specs[0] = %+v, want TechniqueID=T1055 with 1 expectation", specs[0])
	}

	if got := ResolveStepDetectionSpecs(resolver, "unknown-scenario"); got != nil {
		t.Errorf("unknown scenario: got %v, want nil", got)
	}
}

func TestBuildDetectionValidationScoring(t *testing.T) {
	specs := []StepDetectionSpec{
		{
			TechniqueID: "T1003.002",
			Telemetry:   []string{"Security EID 4688: reg.exe", "Sysmon EID 13: registry write"},
			Expected: []scenario.ExpectedDetection{
				endpointExp("req-detected", "microsoft_defender", scenario.ConfidenceRequired),
			},
		},
		{
			TechniqueID: "T1090.001",
			Telemetry:   []string{"Sysmon EID 1: netsh.exe"},
			Expected: []scenario.ExpectedDetection{
				endpointExp("req-silent", "microsoft_defender", scenario.ConfidenceRequired),
				// optional expectations are informational: never scored.
				endpointExp("opt", "crowdstrike", scenario.ConfidenceOptional),
			},
		},
	}
	results := []models.SimulationResult{
		{
			ID:               "T1003.002",
			DetectionVerdict: "detected",
			DetectionAlert:   &models.DetectionAlert{Provider: "Microsoft Defender"},
			Events:           []string{"4688:Security", "13:Microsoft-Windows-Sysmon/Operational"},
		},
		{
			ID:               "T1090.001",
			DetectionVerdict: "undetected",
			Events:           []string{}, // telemetry gap: expected EID 1 absent
		},
	}

	sec := BuildDetectionValidation(specs, results)
	if !sec.HasData {
		t.Fatal("HasData should be true")
	}
	// Two required expectations scored (optional excluded); one detected.
	if sec.Expected != 2 {
		t.Errorf("Expected=%d want 2", sec.Expected)
	}
	if sec.Verified != 2 {
		t.Errorf("Verified=%d want 2 (both resolvable on-host)", sec.Verified)
	}
	if sec.Detected != 1 {
		t.Errorf("Detected=%d want 1", sec.Detected)
	}
	// Both required (weight 1.0): 1 of 2 → 50% coverage.
	if sec.Coverage != 50 {
		t.Errorf("Coverage=%.1f want 50", sec.Coverage)
	}
	if sec.VerificationCompleteness != 100 {
		t.Errorf("VerificationCompleteness=%.1f want 100", sec.VerificationCompleteness)
	}
	// The silent required expectation emits its finding as a False Silence gap.
	if len(sec.FalseSilence) != 1 {
		t.Fatalf("FalseSilence=%d want 1", len(sec.FalseSilence))
	}
	if sec.FalseSilence[0].TechniqueID != "T1090.001" {
		t.Errorf("false silence technique=%q want T1090.001", sec.FalseSilence[0].TechniqueID)
	}
	// Telemetry: 3 EID-bearing lines, 2 observed (4688,13); netsh EID 1 absent.
	if sec.TelemetryCompleteness == 0 || sec.TelemetryCompleteness == 100 {
		t.Errorf("TelemetryCompleteness=%.1f want partial", sec.TelemetryCompleteness)
	}
	// Optional expectation still appears as a detail row.
	if len(sec.Rows) != 3 {
		t.Errorf("Rows=%d want 3 (incl. optional)", len(sec.Rows))
	}
}

func TestBuildDetectionValidationNoExpectations(t *testing.T) {
	sec := BuildDetectionValidation(nil, []models.SimulationResult{{ID: "T1000"}})
	if sec.HasData {
		t.Error("HasData should be false with no expectations (backward compatible)")
	}
}

// siemExp is a required off-host (manual) SIEM expectation — Pending until an
// analyst attests it.
func siemExp(id string) scenario.ExpectedDetection {
	return scenario.ExpectedDetection{
		ID:         id,
		Provider:   "microsoft_sentinel",
		Confidence: scenario.ConfidenceRequired,
		Finding:    scenario.ExpectedFinding{Title: "gap: " + id, Severity: "High"},
	}
}

func TestBuildDetectionValidationStoreOverlay(t *testing.T) {
	specs := []StepDetectionSpec{{
		TechniqueID: "T1078",
		Expected:    []scenario.ExpectedDetection{siemExp("siem-signin")},
	}}
	results := []models.SimulationResult{{ID: "T1078", DetectionVerdict: "undetected"}}

	// No attestation → the required SIEM expectation is Pending: it counts toward
	// the Expected denominator but is unresolved, so Coverage/Completeness are 0.
	base := BuildDetectionValidation(specs, results)
	if base.Expected != 1 || base.Verified != 0 {
		t.Fatalf("no-attestation: Expected=%d Verified=%d want 1/0", base.Expected, base.Verified)
	}
	if base.Coverage != 0 || base.VerificationCompleteness != 0 {
		t.Errorf("no-attestation: Coverage=%.0f Completeness=%.0f want 0/0", base.Coverage, base.VerificationCompleteness)
	}

	// Approved + Detected → resolved detected → full coverage + completeness.
	det := BuildDetectionValidationWithStore(specs, results, map[string]StoredVerification{
		"siem-signin": {Result: verification.ResultDetected, WorkflowState: verification.StateApproved,
			Source: verification.SourceManual, VerifiedBy: "amy", VerifiedAt: time.Now(), EvidenceCount: 2, HashRecorded: true},
	})
	if det.Detected != 1 || det.Coverage != 100 || det.VerificationCompleteness != 100 {
		t.Errorf("approved-detected: Detected=%d Coverage=%.0f Completeness=%.0f want 1/100/100", det.Detected, det.Coverage, det.VerificationCompleteness)
	}
	if len(det.Rows) != 1 || det.Rows[0].Analyst != "amy" || det.Rows[0].EvidenceCount != 2 || det.Rows[0].Integrity == "" {
		t.Errorf("approved-detected: row attestation columns not populated: %+v", det.Rows[0])
	}

	// NeedsReview must NOT count — an in-flight review can't inflate the score.
	rev := BuildDetectionValidationWithStore(specs, results, map[string]StoredVerification{
		"siem-signin": {Result: verification.ResultDetected, WorkflowState: verification.StateNeedsReview, Source: verification.SourceManual},
	})
	if rev.Verified != 0 || rev.Coverage != 0 {
		t.Errorf("needs-review: Verified=%d Coverage=%.0f want 0/0 (unresolved)", rev.Verified, rev.Coverage)
	}

	// Approved + NotApplicable → excluded from scoring entirely.
	na := BuildDetectionValidationWithStore(specs, results, map[string]StoredVerification{
		"siem-signin": {Result: verification.ResultNotApplicable, WorkflowState: verification.StateApproved, Source: verification.SourceManual},
	})
	if na.Expected != 0 {
		t.Errorf("not-applicable: Expected=%d want 0 (excluded)", na.Expected)
	}
	if len(na.Rows) != 1 {
		t.Errorf("not-applicable: still expected 1 detail row, got %d", len(na.Rows))
	}
}

func TestUnexpectedDetection(t *testing.T) {
	specs := []StepDetectionSpec{{
		TechniqueID: "T1059.001",
		Expected:    []scenario.ExpectedDetection{endpointExp("req", "microsoft_defender", scenario.ConfidenceRequired)},
	}}
	// A control the step never expected fires the alert.
	results := []models.SimulationResult{{
		ID:               "T1059.001",
		DetectionVerdict: "detected",
		DetectionAlert:   &models.DetectionAlert{Provider: "CrowdStrike Falcon"},
	}}
	sec := BuildDetectionValidation(specs, results)
	if len(sec.UnexpectedDetections) != 1 {
		t.Fatalf("UnexpectedDetections=%d want 1", len(sec.UnexpectedDetections))
	}
	if sec.UnexpectedDetections[0].Severity != UnexpectedReview {
		t.Errorf("default severity=%q want %q", sec.UnexpectedDetections[0].Severity, UnexpectedReview)
	}
}

// TestBuildDetectionValidationGoldenOutput locks in the full
// DetectionValidationSection output for a representative multi-domain,
// multi-confidence fixture — the automated form of the Outcome Validation
// Framework's "byte-identical existing reports" acceptance criterion. It must
// pass before and after the Phase A refactor with zero changes to `want`.
func TestBuildDetectionValidationGoldenOutput(t *testing.T) {
	specs := []StepDetectionSpec{
		{
			TechniqueID: "T1003.002",
			ProfileRefs: []scenario.ProfileRef{{Profile: "windows_credential_access", Version: 2}},
			Expected: []scenario.ExpectedDetection{
				endpointExp("ep-match", "microsoft_defender", scenario.ConfidenceRequired),
			},
		},
		{
			TechniqueID: "T1562.001",
			Expected: []scenario.ExpectedDetection{
				endpointExp("ep-mismatch", "microsoft_defender", scenario.ConfidenceRequired),
			},
		},
		{
			TechniqueID: "T1090.001",
			Expected: []scenario.ExpectedDetection{
				{ID: "net-unknown", Provider: "microsoft_sentinel", Type: scenario.DomainNetwork, Verification: scenario.VerificationAutomatic, Confidence: scenario.ConfidenceRequired, Finding: scenario.ExpectedFinding{Title: "t", Severity: "High"}},
			},
		},
		{
			TechniqueID: "T1055",
			Expected: []scenario.ExpectedDetection{
				endpointExp("ep-optional", "crowdstrike", scenario.ConfidenceOptional),
			},
		},
	}
	results := []models.SimulationResult{
		{ID: "T1003.002", DetectionVerdict: "detected", DetectionAlert: &models.DetectionAlert{Provider: "Microsoft Defender"}},
		{ID: "T1562.001", DetectionVerdict: "detected", DetectionAlert: &models.DetectionAlert{Provider: "CrowdStrike Falcon"}},
		{ID: "T1090.001", DetectionVerdict: "detected", DetectionAlert: &models.DetectionAlert{Provider: "Microsoft Sentinel"}},
		{ID: "T1055", DetectionVerdict: "undetected"},
	}

	got := BuildDetectionValidation(specs, results)
	want := DetectionValidationSection{
		HasData:                  true,
		Coverage:                 50,
		VerificationCompleteness: 66.7,
		Overall:                  50,
		TelemetryCompleteness:    0,
		Expected:                 3,
		Verified:                 2,
		Detected:                 1,
		ByDomain: []DomainValidationRow{
			{Domain: "endpoint", Expected: 2, Verified: 2, Detected: 1, Coverage: 50, VerificationCompleteness: 100},
			{Domain: "network", Expected: 1, Verified: 0, Detected: 0, Coverage: 0, VerificationCompleteness: 0},
		},
		Rows: []ExpectationRow{
			{TechniqueID: "T1003.002", ExpectedID: "ep-match", Provider: "Microsoft Defender", Domain: "endpoint", Confidence: "required", Verification: "automatic", Status: "Detected", Source: "Microsoft Defender", WorkflowState: "Approved"},
			{TechniqueID: "T1562.001", ExpectedID: "ep-mismatch", Provider: "Microsoft Defender", Domain: "endpoint", Confidence: "required", Verification: "automatic", Status: "NotDetected", WorkflowState: "Approved"},
			{TechniqueID: "T1090.001", ExpectedID: "net-unknown", Provider: "Microsoft Sentinel", Domain: "network", Confidence: "required", Verification: "automatic", Status: "Unknown", WorkflowState: "Approved"},
			{TechniqueID: "T1055", ExpectedID: "ep-optional", Provider: "CrowdStrike Falcon", Domain: "endpoint", Confidence: "optional", Verification: "automatic", Status: "NotDetected", WorkflowState: "Approved"},
		},
		FalseSilence: []GapFinding{
			{TechniqueID: "T1562.001", Provider: "Microsoft Defender", Domain: "endpoint", Confidence: "required", Severity: "High", Title: "gap: ep-mismatch", Remediation: "fix it"},
		},
		UnexpectedDetections: []UnexpectedDetectionRow{
			{TechniqueID: "T1562.001", Provider: "CrowdStrike Falcon", Severity: "Review", Detail: "A control alerted with no matching expectation for this step — confirm it is intended coverage, not a noisy or duplicate rule."},
		},
		Profiles: []scenario.ProfileRef{
			{Profile: "windows_credential_access", Version: 2},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("golden output changed.\ngot:  %+v\nwant: %+v", got, want)
	}
}

// TestVerifyExpectationDispatchesByOutcomeFamily proves the DLP dispatch
// branch added in Phase B only affects outcome_family: dlp expectations —
// every "detection"-family expectation (the default, and the only family
// that existed before Phase B) keeps routing to automaticVerifier exactly as
// Phase A left it.
func TestVerifyExpectationDispatchesByOutcomeFamily(t *testing.T) {
	dlpExpDetection := scenario.ExpectedDetection{
		ID: "d", Provider: "trellix_dlp", Type: scenario.DomainDLP,
		OutcomeFamily: "dlp", ExpectedOutcome: "Block",
		Verification: scenario.VerificationAutomatic, Confidence: scenario.ConfidenceRequired,
		Finding: scenario.ExpectedFinding{Title: "t", Severity: "High"},
	}
	r := verifyExpectation(dlpExpDetection, StepEvidence{RawOutput: "DLP_OBSERVATION: OperationBlocked"})
	if r.Comparison != Match {
		t.Errorf("dlp-family expectation: got comparison=%v want Match (should have routed to dlpVerifier)", r.Comparison)
	}

	detExp := endpointExp("e", "microsoft_defender", scenario.ConfidenceRequired)
	r = verifyExpectation(detExp, StepEvidence{DetectionVerdict: "detected", AlertProvider: "Microsoft Defender"})
	if r.Status != StatusDetected || r.Comparison != Match {
		t.Errorf("detection-family expectation: got status=%s comparison=%v — Phase A dispatch must be unaffected", r.Status, r.Comparison)
	}
}
