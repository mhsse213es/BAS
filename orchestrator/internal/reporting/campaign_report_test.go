package reporting

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
)

// campaignScopeReport returns a FullReport shaped like BuildFromCampaign's output:
// fleet scope + per-agent breakdown + the usual derivations.
func campaignScopeReport() *FullReport {
	now := time.Date(2026, 6, 18, 9, 0, 0, 0, time.UTC)
	rep := &FullReport{
		GeneratedAt: now,
		Agent:       models.Agent{Hostname: "Q2 Ransomware Drill"}, // footers/fallback
		Summary: ExecutiveSummary{
			RiskScore: 68, Classification: "High Risk",
			PreventionScore: 55, ExposureScore: 48, CoverageScore: 20,
			KillChainCoverage: 30, KillChainAmplifier: 1.5, Trend: "Baseline",
			TotalRuns: 3, TotalTechniques: 30, PassedTechniques: 17, FailedTechniques: 13,
			LastRunAt: now, LastScenarioName: "Ransomware Resilience Sweep",
			ExposureLevel: "High", DetectionScore: 40, DetectionMeasured: true,
			PenetrationTested: 30, PenetrationFailed: 13, PenetrationPct: 43,
		},
		Scope: &ReportScope{
			Kind: "campaign", Title: "Q2 Ransomware Drill",
			Subtitle: "Campaign Assessment — Ransomware Resilience Sweep",
			Scenario: "Ransomware Resilience Sweep", AgentCount: 3, RunCount: 3,
		},
		CampaignAgents: []CampaignAgentRow{
			{Hostname: "BANK-WS-01", Status: "completed", PreventionScore: 41, Tested: 10, Failed: 6},
			{Hostname: "BANK-WS-02", Status: "completed", PreventionScore: 70, Tested: 10, Failed: 3},
			{Hostname: "BANK-DC-01", Status: "partial", PreventionScore: 55, Tested: 10, Failed: 4},
		},
		Reliability: Reliability{Attempted: 30, Valid: 30, Confidence: "High"},
		Insights: Insights{
			HasData: true,
			Most:    &TacticInsight{Tactic: "execution", PassPct: 80, Tested: 5},
			Least:   &TacticInsight{Tactic: "impact", PassPct: 20, Tested: 5},
		},
		ActionPlan: []ActionItem{
			{Tactic: "impact", Objective: "Ransomware / Impact", Failures: 4, ScorePoints: 18,
				Recommendation: "Protect backups (immutable/offline) and alert on shadow-copy deletion."},
		},
		TopRiskDrivers: []RiskDriver{
			{TechniqueID: "T1486", Name: "Data Encrypted for Impact", Tactic: "impact", Severity: "Critical", Failures: 3, ScorePoints: 14},
		},
		TacticHeatmap: []TacticEntry{
			{Tactic: "impact", Passed: 1, Failed: 4, Total: 5, PassPct: 20, Weight: "High"},
		},
		Runs: []RunSummary{
			{ID: "r1", ScenarioName: "Ransomware Resilience Sweep", Status: "completed", StartedAt: now},
		},
	}
	return rep
}

func TestCampaignReportHTMLRendersScope(t *testing.T) {
	var buf bytes.Buffer
	if err := GenerateHTML(&buf, campaignScopeReport(), nil); err != nil {
		t.Fatalf("GenerateHTML(campaign) errored after %d bytes: %v", buf.Len(), err)
	}
	out := buf.String()
	for _, want := range []string{
		"Campaign Assessment", // cover subtitle
		"Q2 Ransomware Drill", // campaign title
		"Per-Agent Breakdown", // asset-context per-agent table
		"BANK-WS-02",          // an endpoint row
		"3 agent(s)",          // scope summary on cover
		"Action Plan",         // shared section still renders
	} {
		if !strings.Contains(out, want) {
			t.Errorf("campaign HTML missing %q", want)
		}
	}
	// A campaign report must NOT render the single-agent "IP Address" asset row.
	if strings.Contains(out, "IP Address") {
		t.Errorf("campaign report should not show single-agent IP Address row")
	}
}

func TestCampaignReportPDFRenders(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderReportPDF(&buf, campaignScopeReport(), nil); err != nil {
		t.Fatalf("RenderReportPDF(campaign): %v", err)
	}
	if !strings.HasPrefix(buf.String(), "%PDF-") {
		t.Errorf("campaign output is not a PDF")
	}
	if buf.Len() < 3000 {
		t.Errorf("campaign PDF suspiciously small: %d bytes", buf.Len())
	}
}
