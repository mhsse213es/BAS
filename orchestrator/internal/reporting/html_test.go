package reporting

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
)

// TestGenerateHTMLRendersAllSections renders a fully-populated report and
// asserts each section's data appears in the output. It guards the garble-safe
// json-map render path: the template resolves fields by json-tag key, numbers
// arrive as float64 and times as RFC3339 strings. A regression (wrong tag, a
// func typed for the struct shape, or an int/float comparison) truncates the
// output mid-template, so these substring checks catch it.
func TestGenerateHTMLRendersAllSections(t *testing.T) {
	now := time.Date(2026, 6, 9, 10, 30, 0, 0, time.UTC)
	rep := &FullReport{
		GeneratedAt: now,
		Agent: models.Agent{
			AgentID: "agent-123", Hostname: "BANK-WS-01", IPAddress: "10.0.0.5",
			OSVersion: "Windows 11 Pro 23H2", Username: "svc-bas", EnvLabel: "Production",
		},
		Summary: ExecutiveSummary{
			RiskScore: 72, Classification: "High Risk",
			PreventionScore: 41, ExposureScore: 63, CoverageScore: 0,
			KillChainCoverage: 21, KillChainAmplifier: 1.8, Trend: "Baseline",
			TotalRuns: 1, TotalTechniques: 12, PassedTechniques: 5, FailedTechniques: 7,
			LastRunAt: now, LastScenarioName: "RBI Ransomware Resilience Sweep",
			ExposureLevel: "High", DetectionScore: 50, DetectionMeasured: true,
			PenetrationTested: 12, PenetrationFailed: 7, PenetrationPct: 58,
			MTTDMs: 192000,
		},
		ExecutiveConclusion: "This assessment executed 12 techniques against the endpoint, of which 7 were not prevented.",
		TopRiskDrivers: []RiskDriver{
			{TechniqueID: "T1003", Name: "OS Credential Dumping", Tactic: "credential-access",
				Severity: "Critical", Failures: 3, ScorePoints: 30},
		},
		Insights: Insights{
			HasData: true,
			Least:   &TacticInsight{Tactic: "credential-access", PassPct: 0, Tested: 3},
			Most:    &TacticInsight{Tactic: "execution", PassPct: 100, Tested: 2},
		},
		ActionPlan: []ActionItem{
			{Tactic: "credential-access", Objective: "Credential Theft", Failures: 3, ScorePoints: 30,
				Recommendation: "Enable Credential Guard / LSASS protection and alert on LSASS access."},
		},
		Reliability: Reliability{Attempted: 12, Valid: 12, Confidence: "High"},
		Glossary: []GlossaryEntry{
			{TechniqueID: "T1003", Name: "OS Credential Dumping", Tactic: "credential-access",
				Description: "Adversaries may dump credentials from the OS.", Detection: "Monitor LSASS access."},
		},
		TacticHeatmap: []TacticEntry{
			{Tactic: "credential-access", Passed: 0, Failed: 3, Total: 3, PassPct: 0,
				Detected: 1, DetectedPct: 33, MTTDMs: 192000, Weight: "Critical"},
		},
		TopFindings: []Finding{
			{TechniqueID: "T1003", TechniqueName: "OS Credential Dumping", Tactic: "credential-access",
				Severity: "Critical", Details: "LSASS memory was read without being blocked.",
				Remediation: "Enable Credential Guard."},
		},
		ObjectiveRisks: []ObjectiveRisk{
			{Objective: "Credential Theft", Tactic: "credential-access", Risk: "High", Tested: 3, Failed: 3},
		},
		AttackPath: AttackPath{Steps: []AttackPathStep{
			{Tactic: "credential-access", Techniques: []string{"T1003 — OS Credential Dumping"}},
		}},
		Runs: []RunSummary{
			{ID: "run-1", ScenarioName: "RBI Ransomware Resilience Sweep", Status: "completed",
				StartedAt: now, RiskScore: 72, Classification: "High Risk",
				PreventionScore: 41, ExposureScore: 63, TotalTechniques: 12, FailedTechniques: 7},
		},
	}
	compliance := []ComplianceSummaryRow{
		{Framework: "SEBI CSCRF 1.0", TotalControls: 50, Tested: 20, Passing: 12,
			Failing: 8, Untested: 30, CompliancePct: 60, CoveragePct: 40},
	}

	var buf bytes.Buffer
	if err := GenerateHTML(&buf, rep, compliance); err != nil {
		t.Fatalf("GenerateHTML errored after %d bytes: %v", buf.Len(), err)
	}
	out := buf.String()
	for _, want := range []string{
		"BANK-WS-01",              // agent.hostname
		"10.0.0.5",                // agent.ipAddress
		"High Risk",               // summary.classification
		"Assessment Summary",      // §2 heading
		"Detection Score",         // elevated alongside prevention
		"Exposure: High",          // exposure level chip
		"7/12",                    // penetration ratio
		"Top Risk Drivers",        // §3 heading
		"Credential Access",       // humanized tactic
		"Action Plan",             // §9 heading
		"Enable Credential Guard", // action-plan recommendation
		"Technical Appendix",      // §13 glossary heading
		"OS Credential Dumping",   // topFindings / glossary technique
		"Most Protected",          // insights
		"SEBI CSCRF 1.0",          // compliance.framework
		"09 Jun 2026, 10:30 UTC",  // fmtTime(generatedAt)
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered report missing %q (output %d bytes)", want, len(out))
		}
	}
}
