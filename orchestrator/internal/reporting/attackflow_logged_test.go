package reporting

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

// A "logged" result carries its co-occurring alert so an analyst can review it.
// The attack flow must not read that attached alert as proof of detection --
// doing so would put the inflated verdict straight back into the client report,
// through a different door than the one the correlator closed.
func TestBuildAttackFlow_LoggedVerdictIsNotDetected(t *testing.T) {
	results := []models.SimulationResult{{
		Technique:        models.AttackTechnique{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "execution"},
		StepName:         "T1059 - Test 1",
		Result:           models.ResultFail,
		DetectionVerdict: "logged",
		DetectionAlert: &models.DetectionAlert{
			Channel:  "journal",
			Provider: "systemd",
		},
	}}
	nodes := BuildAttackFlow(results)
	if len(nodes) != 1 {
		t.Fatalf("len(nodes) = %d, want 1", len(nodes))
	}
	if nodes[0].Verdict != "logged" {
		t.Errorf("Verdict = %q, want logged (an attached alert is context, not a detection)", nodes[0].Verdict)
	}
	if nodes[0].VerdictLabel == "Detected — Not Stopped" {
		t.Errorf("VerdictLabel = %q, must not claim detection", nodes[0].VerdictLabel)
	}
}

// The genuine case must be untouched: an attributed detection still reports as
// detected, and still names the control that saw it.
func TestBuildAttackFlow_DetectedVerdictUnchanged(t *testing.T) {
	results := []models.SimulationResult{{
		Technique:        models.AttackTechnique{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "execution"},
		StepName:         "T1059 - Test 1",
		Result:           models.ResultFail,
		DetectionVerdict: "detected",
		DetectionAlert: &models.DetectionAlert{
			Channel:    "Microsoft-Windows-Windows Defender/Operational",
			Provider:   "Microsoft Defender",
			ThreatName: "Trojan:Win32/Meterpreter",
		},
	}}
	nodes := BuildAttackFlow(results)
	if nodes[0].Verdict != "detected" {
		t.Fatalf("Verdict = %q, want detected", nodes[0].Verdict)
	}
	if nodes[0].ControlName != "Microsoft Defender" {
		t.Errorf("ControlName = %q, want the alert provider", nodes[0].ControlName)
	}
}

// Older runs stored an alert without ever setting a verdict string. Those must
// keep reading as detected, so this change cannot silently rewrite history.
func TestBuildAttackFlow_LegacyAlertWithoutVerdictStillDetected(t *testing.T) {
	results := []models.SimulationResult{{
		Technique:      models.AttackTechnique{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "execution"},
		StepName:       "T1059 - Test 1",
		Result:         models.ResultFail,
		DetectionAlert: &models.DetectionAlert{Provider: "Microsoft Defender"},
	}}
	nodes := BuildAttackFlow(results)
	if nodes[0].Verdict != "detected" {
		t.Errorf("Verdict = %q, want detected for a legacy result", nodes[0].Verdict)
	}
}
