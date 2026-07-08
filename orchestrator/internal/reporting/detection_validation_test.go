package reporting

import (
	"testing"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
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
	// detected by a different provider → NotDetected (the expected one stayed silent)
	r = automaticVerifier{}.Verify(exp, StepEvidence{DetectionVerdict: "detected", AlertProvider: "CrowdStrike Falcon"})
	if r.Status != StatusNotDetected {
		t.Errorf("detected-mismatch: got %s want NotDetected", r.Status)
	}
	// prevented by the expected control → Detected
	r = automaticVerifier{}.Verify(exp, StepEvidence{DetectionVerdict: "prevented", BlockingControl: "Defender ASR"})
	if r.Status != StatusDetected {
		t.Errorf("prevented-match: got %s want Detected", r.Status)
	}
	// undetected → NotDetected
	r = automaticVerifier{}.Verify(exp, StepEvidence{DetectionVerdict: "undetected"})
	if r.Status != StatusNotDetected {
		t.Errorf("undetected: got %s want NotDetected", r.Status)
	}
	// non-endpoint domain is not on-host observable → Unknown
	netExp := scenario.ExpectedDetection{ID: "n", Provider: "microsoft_sentinel", Type: scenario.DomainNetwork, Confidence: scenario.ConfidenceRequired, Finding: scenario.ExpectedFinding{Title: "t", Severity: "High"}}
	r = automaticVerifier{}.Verify(netExp, StepEvidence{DetectionVerdict: "detected", AlertProvider: "Microsoft Defender"})
	if r.Status != StatusUnknown {
		t.Errorf("non-endpoint: got %s want Unknown", r.Status)
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
