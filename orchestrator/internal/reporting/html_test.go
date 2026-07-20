package reporting

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/models"
)

// apSummary builds a small attack-path graph and analyzes it for report tests.
func apSummary() *attackpath.Summary {
	g := attackpath.New()
	g.AddNode(attackpath.Node{ID: "WS01", Kind: attackpath.KindHost, Label: "WS01", Role: attackpath.RoleEndpoint, Segment: "user-vlan"})
	g.AddNode(attackpath.Node{ID: "JUMP01", Kind: attackpath.KindHost, Label: "JUMP01", Role: attackpath.RoleServer, Segment: "dmz-vlan"})
	g.AddNode(attackpath.Node{ID: "FILE01", Kind: attackpath.KindHost, Label: "FILE01", Role: attackpath.RoleServer, Segment: "server-vlan", CrownJewel: "FileServer"})
	g.AddNode(attackpath.Node{ID: "DC01", Kind: attackpath.KindHost, Label: "DC01", Role: attackpath.RoleDC, Segment: "server-vlan"})
	g.AddNode(attackpath.Node{ID: "alice", Kind: attackpath.KindUser, Label: "alice@corp"})
	g.AddNode(attackpath.Node{ID: "DA", Kind: attackpath.KindGroup, Label: "Domain Admins", HighValue: true})
	g.AddEdge(attackpath.Edge{From: "WS01", To: "JUMP01", Kind: attackpath.EdgeWinRM})
	g.AddEdge(attackpath.Edge{From: "JUMP01", To: "FILE01", Kind: attackpath.EdgeSMB})
	g.AddEdge(attackpath.Edge{From: "FILE01", To: "alice", Kind: attackpath.EdgeHasSession})
	g.AddEdge(attackpath.Edge{From: "alice", To: "DA", Kind: attackpath.EdgeMemberOf})
	g.AddEdge(attackpath.Edge{From: "DA", To: "DC01", Kind: attackpath.EdgeAdminTo})
	s := g.Analyze()
	return &s
}

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
		AttackSurfaceAge:       147,
		OldestFindingName:      "OS Credential Dumping",
		OldestFindingID:        "T1003",
		OldestFindingSeverity:  "Critical",
		AttackSurfaceSLAStatus: "critical-sla",
		DetectionSources: []DetectionSource{
			{Product: "Trellix", Detections: 18, MinMTTDMs: 4500, AvgMTTDMs: 8200},
			{Product: "Defender", Detections: 14, MinMTTDMs: 2100, AvgMTTDMs: 4900},
		},
		PerfCPUBefore:          2.1,
		PerfCPUAfter:           2.3,
		PerfRAMBefore:          5.4,
		PerfRAMAfter:           5.4,
		PerfDiskBefore:         62.5,
		PerfDiskAfter:          62.5,
		CleanupFailed:          true,
		CleanupFailedCount:     2,
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
		Reliability:   Reliability{Attempted: 12, Valid: 12, Confidence: "High"},
		SkipBreakdown: SkipBreakdown{Policy: 4, Content: 1, Platform: 2},
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
		AttackPathValidation: apSummary(),
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
		"Execution Summary",       // new §2 sub-table heading
		"Skipped (Policy)",        // execution-summary row label
		"Skipped (Content)",       // execution-summary row label
		"Skipped (Platform)",      // execution-summary row label
		"Detection Score",         // elevated alongside prevention
		"Exposure: High",          // exposure level chip
		"7/12",                    // penetration ratio
		"Top Risk Drivers",        // §3 heading
		"Credential Access",       // humanized tactic
		"Action Plan",             // action-plan heading
		"Enable Credential Guard", // action-plan recommendation
		"Kill-Chain Path",         // renamed §6 (was "Attack Path Analysis")
		"Attack Path Validation",  // new §7 section heading
		"Attack Path Score",       // attack-path scorecard label
		"Crown-Jewel Exposure",    // crown-jewel table from the graph
		"FileServer",              // crown-jewel tag rendered from the summary
		"Choke Points",            // choke-point table
		"JUMP01",                  // choke-point node label
		"Segmentation Violations", // segmentation table
		"Technical Appendix",      // glossary heading
		"OS Credential Dumping",   // topFindings / glossary technique
		"Most Protected",          // insights
		"SEBI CSCRF 1.0",          // compliance.framework
		"09 Jun 2026, 10:30 UTC",  // fmtTime(generatedAt)
		"Attack Surface Age",
		"147 days",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered report missing %q (output %d bytes)", want, len(out))
		}
	}
}
