package reporting

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
)

// TestDumpReportHTML is a measurement harness, not an assertion. It renders a
// representative report to the path in AUDSPECT_LAYOUT_HTML so the print layout
// can be measured in a real browser.
//
// It exists because the PDF's shrink-to-fit factor cannot be reasoned about
// from the stylesheet: Chrome scales the whole job when ANY element makes the
// document wider than the paper, and the offender is routinely an invisible
// decorative box. Skipped unless the env var is set, so it never runs in CI.
func TestDumpReportHTML(t *testing.T) {
	out := os.Getenv("AUDSPECT_LAYOUT_HTML")
	if out == "" {
		t.Skip("set AUDSPECT_LAYOUT_HTML to dump the report HTML")
	}

	now := time.Date(2026, 9, 3, 11, 42, 0, 0, time.UTC)
	rep := &FullReport{
		GeneratedAt: now,
		Agent: models.Agent{
			AgentID: "agent-probe", Hostname: "audspecterver", IPAddress: "192.168.10.78",
			OSVersion: "Linux/amd64 (Ubuntu 24.04.4 LTS)", Status: "idle",
		},
		Summary: ExecutiveSummary{
			RiskScore: 12, Classification: "Critical", TotalRuns: 1, TotalTechniques: 14,
			LastRunAt: now, LastScenarioName: "Linux Defense Evasion - Log Clearing, Timestomping, History Wipe",
		},
		Reliability: Reliability{Attempted: 14, Valid: 14, Confidence: "High"},
	}

	// Every ATT&CK tactic — the heatmap's column count is what drives its width.
	for _, tac := range []string{
		"reconnaissance", "resource-development", "initial-access", "execution",
		"persistence", "privilege-escalation", "defense-evasion", "credential-access",
		"discovery", "lateral-movement", "collection", "command-and-control",
		"exfiltration", "impact",
	} {
		rep.TacticHeatmap = append(rep.TacticHeatmap, TacticEntry{
			Tactic: tac, Passed: 2, Failed: 5, Total: 7, PassPct: 28,
			Detected: 3, DetectedPct: 60, MTTDMs: 4200, Weight: "High",
		})
	}

	// The 13-column per-technique detection table, with the long values that
	// make it the widest structure in the document.
	for i := 0; i < 25; i++ {
		rep.TechniqueMatrix = append(rep.TechniqueMatrix, TechniqueRow{
			TechniqueID:      fmt.Sprintf("T1070.%03d", i+1),
			TechniqueName:    "Indicator Removal: Clear Linux or Mac System Logs",
			StepName:         fmt.Sprintf("T1070.002 - Test %d: Overwrite Linux Mail Spool", i+1),
			Tactic:           "defense-evasion",
			Severity:         "High",
			ExecVerdict:      "fail",
			DetectionVerdict: "undetected",
			AlertChannel:     "Microsoft-Windows-Sysmon/Operational",
			AlertProvider:    "Microsoft Defender for Endpoint",
			AlertEventID:     4688,
			AlertThreatName:  "Behavior:Linux/IndicatorRemoval.A!ml",
			AlertCommandLine: "/bin/bash -c 'cat /dev/null > /var/log/auth.log'",
			Confidence:       "high",
			MTTDMs:           4200,
			DurationMs:       1234,
			CleanupVerdict:   "leaked",
		})
	}

	f, err := os.Create(out)
	if err != nil {
		t.Fatalf("create %s: %v", out, err)
	}
	defer f.Close()
	if err := GenerateHTML(f, rep, nil); err != nil {
		t.Fatalf("GenerateHTML: %v", err)
	}
	fi, _ := f.Stat()
	t.Logf("wrote %s (%d bytes)", out, fi.Size())
}
