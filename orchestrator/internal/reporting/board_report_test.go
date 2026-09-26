package reporting

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
)

func sampleBoardReport() *FullReport {
	return &FullReport{
		Agent: models.Agent{AgentID: "WIN-PROD-01", Hostname: "WIN-PROD-01", EnvLabel: "Production"},
		Summary: ExecutiveSummary{
			RiskScore: 78, Classification: "Critical", ExposureLevel: "High",
			PreventionScore: 34.2, DetectionScore: 62.3, DetectionMeasured: true,
			PenetrationPct: 66, CoverageScore: 41.0, UndetectedRate: 38,
			TotalTechniques: 101, MTTDMs: 4200, LastRunAt: time.Now().UTC(),
			LastScenarioName: "Atomic Red Team — Selective Sweep",
		},
		TrendAnalysis: TrendSummary{
			HasPrevious: true, CurrentPrevention: 34.2, PreviousPrevention: 29.0, DeltaPrevention: 5.2,
			History: []TrendPoint{
				{PreventionScore: 20}, {PreventionScore: 25}, {PreventionScore: 29}, {PreventionScore: 34.2},
			},
		},
		TopRiskDrivers: []RiskDriver{
			{TechniqueID: "T1003", Name: "OS Credential Dumping", Tactic: "credential-access", Severity: "Critical", Failures: 3, ScorePoints: 18.5},
			{TechniqueID: "T1486", Name: "Data Encrypted for Impact", Tactic: "impact", Severity: "High", Failures: 1, ScorePoints: 9.0},
		},
		ActionPlan: []ActionItem{
			{Tactic: "credential-access", Objective: "Protect LSASS", Failures: 3, ScorePoints: 18.5, Recommendation: "Enable Credential Guard and restrict SeDebugPrivilege."},
		},
	}
}

func TestRenderBoardOnePager(t *testing.T) {
	rep := sampleBoardReport()
	comp := []ComplianceSummaryRow{
		{Framework: "SEBI CSCRF 2023", CompliancePct: 20.0, CoveragePct: 41.7},
		{Framework: "RBI CSF", CompliancePct: 55.5, CoveragePct: 60.0},
	}
	var buf bytes.Buffer
	if err := RenderBoardOnePager(&buf, rep, comp, "analyst@bank.example"); err != nil {
		t.Fatalf("RenderBoardOnePager: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"<!DOCTYPE html>", "Executive Security Scorecard", "Security Posture at a Glance",
		"Regulatory Compliance", "Top Risk Drivers", "Priority Actions",
		"OS Credential Dumping", "SEBI CSCRF 2023", "78", // risk score
		"<polyline", "Tamper-evidence", // sparkline + attestation
	} {
		if !strings.Contains(out, want) {
			t.Errorf("board output missing %q", want)
		}
	}
	// Single physical page: exactly one .page container.
	if n := strings.Count(out, `class="page"`); n != 1 {
		t.Errorf("expected exactly 1 page, got %d", n)
	}
}

func TestRenderBoardOnePager_Nil(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderBoardOnePager(&buf, nil, nil, ""); err == nil {
		t.Error("expected error for nil report")
	}
}

func TestRenderBoardOnePager_Empty(t *testing.T) {
	// A report with no drivers/actions/compliance/trend must still render.
	rep := &FullReport{Agent: models.Agent{AgentID: "A1", Hostname: "A1"}}
	var buf bytes.Buffer
	if err := RenderBoardOnePager(&buf, rep, nil, ""); err != nil {
		t.Fatalf("empty render failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No compliance data yet") {
		t.Error("empty report should show the no-compliance placeholder")
	}
}

func TestRenderBoardOnePagerPDF_NoSidecar(t *testing.T) {
	t.Setenv("CHROME_WS_URL", "")
	rep := sampleBoardReport()
	var buf bytes.Buffer
	if err := RenderBoardOnePagerPDF(context.Background(), &buf, rep, nil, ""); err == nil {
		t.Error("expected error when chrome sidecar unconfigured")
	}
}

func TestBoardSparkline(t *testing.T) {
	if s := boardSparkline(TrendSummary{}); s != "" {
		t.Errorf("empty history should yield empty sparkline, got %q", s)
	}
	s := boardSparkline(TrendSummary{History: []TrendPoint{{PreventionScore: 0}, {PreventionScore: 100}}})
	if !strings.HasPrefix(s, "0.0,40.0") { // first point: x=0, y=h (score 0 = bottom)
		t.Errorf("unexpected sparkline points: %q", s)
	}
}
