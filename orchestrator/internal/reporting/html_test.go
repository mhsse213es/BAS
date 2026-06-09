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
			Recommendations: []string{"Enable Credential Guard and LSA protection."},
		},
		TacticHeatmap: []TacticEntry{
			{Tactic: "credential-access", Passed: 0, Failed: 3, Total: 3, PassPct: 0, Weight: "Critical"},
		},
		TopFindings: []Finding{
			{TechniqueID: "T1003", TechniqueName: "OS Credential Dumping", Tactic: "credential-access",
				Severity: "Critical", Details: "LSASS memory was read without being blocked.",
				Remediation: "Enable Credential Guard."},
		},
		DetectionCategories: []Category{
			{Name: "credential-access", Result: "fail"},
		},
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
		"BANK-WS-01",                      // agent.hostname
		"10.0.0.5",                        // agent.ipAddress
		"High Risk",                       // summary.classification
		"Enable Credential Guard and LSA", // summary.recommendations
		"OS Credential Dumping",           // topFindings.techniqueName
		"credential-access",               // tacticHeatmap.tactic / detectionCategories.name
		"FAIL",                            // upper(detectionCategories.result)
		"SEBI CSCRF 1.0",                  // compliance.framework
		"09 Jun 2026, 10:30 UTC",          // fmtTime(generatedAt)
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered report missing %q (output %d bytes)", want, len(out))
		}
	}
}
