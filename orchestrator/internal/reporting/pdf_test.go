package reporting

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
)

func TestRenderReportPDF(t *testing.T) {
	now := time.Now().UTC()
	rep := &FullReport{
		GeneratedAt: now,
		Agent: models.Agent{
			AgentID: "agent-123", Hostname: "BANK-WS-01",
			OSVersion: "Windows 11 Pro 23H2", EnvLabel: "Production",
		},
		Summary: ExecutiveSummary{
			RiskScore: 72, Classification: "High Risk",
			PreventionScore: 41, ExposureScore: 63,
			CoverageScore: 0, KillChainCoverage: 21, KillChainAmplifier: 1.8,
			Trend: "Baseline", TotalTechniques: 12, PassedTechniques: 5, FailedTechniques: 7,
			LastRunAt: now, LastScenarioName: "RBI Ransomware Resilience Sweep",
			CriticalFailures: []models.CriticalFailure{
				{TechniqueID: "T1486", Name: "Data Encrypted for Impact", Tactic: "impact", Severity: "Critical"},
			},
			Recommendations: []string{
				"Deploy application allow-listing to block unsigned binaries.",
				"Enable tamper protection on the EDR agent.",
			},
		},
		TacticHeatmap: []TacticEntry{
			{Tactic: "execution", Passed: 2, Failed: 1, Total: 3, PassPct: 66, Weight: "High"},
			{Tactic: "credential-access", Passed: 0, Failed: 3, Total: 3, PassPct: 0, Weight: "Critical"},
		},
		TopFindings: []Finding{
			{TechniqueID: "T1003", TechniqueName: "OS Credential Dumping", Tactic: "credential-access",
				Severity: "Critical", Details: "LSASS memory was read without being blocked.",
				Remediation: "Enable Credential Guard and LSA protection."},
		},
		Runs: []RunSummary{{ID: "run-abcdef123456", ScenarioName: "RBI Ransomware Resilience Sweep"}},
	}
	results := []models.SimulationResult{
		{Technique: models.AttackTechnique{ID: "T1059.001", Name: "PowerShell", Tactic: "execution"},
			Result: models.ResultFail, Severity: "High",
			Details: "Encoded PowerShell command executed successfully.",
			ThreatImpact: "An attacker can run arbitrary code in memory, evading file-based AV.",
			Remediation:  "Enable Constrained Language Mode and script block logging.",
			Framework:    "art"},
		{Technique: models.AttackTechnique{ID: "T1003", Name: "OS Credential Dumping", Tactic: "credential-access"},
			Result: models.ResultPass, Severity: "Critical",
			Details: "Access to LSASS was denied by the security control.", Framework: "art"},
		{Technique: models.AttackTechnique{ID: "T1547", Name: "Boot Autostart", Tactic: "persistence"},
			Result: models.ResultSkipped, Severity: "Medium", Framework: "art"},
	}

	var buf bytes.Buffer
	if err := RenderReportPDF(&buf, rep, results); err != nil {
		t.Fatalf("RenderReportPDF: %v", err)
	}
	if !strings.HasPrefix(buf.String(), "%PDF-") {
		t.Errorf("output is not a PDF (prefix %q)", buf.String()[:min(8, buf.Len())])
	}
	if buf.Len() < 3000 {
		t.Errorf("PDF suspiciously small: %d bytes", buf.Len())
	}
	if out := os.Getenv("BAS_PDF_OUT"); out != "" {
		if err := os.WriteFile(out, buf.Bytes(), 0644); err != nil {
			t.Fatalf("write sample: %v", err)
		}
		t.Logf("wrote sample PDF to %s (%d bytes)", out, buf.Len())
	}
}
