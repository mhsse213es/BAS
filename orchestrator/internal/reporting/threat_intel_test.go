package reporting

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/ioc"
)

func seedRunIOCForReport(t *testing.T, runID string) {
	t.Helper()
	indicators := []ioc.RunIndicator{
		{Type: "ip", Value: "45.33.32.156", Confidence: 95, Source: "stdout", TechniqueIDs: []string{"T1071"}, SimulationIDs: []string{"T1071::A"}},
		{Type: "domain", Value: "evil.example.com", Confidence: 80, Source: "stdout", TechniqueIDs: []string{"T1071"}, SimulationIDs: []string{"T1071::A"}},
		{Type: "hash", Value: "44d88612fea8a8f36de82e1278abb02f", Confidence: 100, Source: "details", TechniqueIDs: []string{"T1105"}, SimulationIDs: []string{"T1105::B"}},
	}
	if err := db.UpsertRunIOCs(context.Background(), sharedDB.Pool, runID, "test-scenario", indicators); err != nil {
		t.Fatalf("seedRunIOCForReport: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(context.Background(), `DELETE FROM run_iocs WHERE run_id = $1`, runID)
	})
}

func seedEnrichment(t *testing.T, typ, val string, pulseCount int) {
	t.Helper()
	result := &ioc.Result{Indicator: val, Type: typ, Provider: "otx", PulseCount: pulseCount}
	if err := db.UpsertIOCEnrichmentSuccess(context.Background(), sharedDB.Pool, typ, val, "otx", result, 10, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("seedEnrichment: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(context.Background(), `DELETE FROM ioc_enrichment WHERE indicator_type=$1 AND indicator_value=$2`, typ, val)
	})
}

// seedScenarioRun inserts the minimal agents + scenario_runs rows BuildFromRun
// needs to find the run at all (it errors with "run not found" otherwise).
// Every other scenario_runs column BuildFromRun reads is either nullable or
// has a table-level default (results/reverted default to '[]', score/
// completed_at/detection_summary/detection_rate/undetected_rate/mttd_ms are
// nullable, all perf_*/alerts_*/noise_score/steps_*_base columns default to
// 0) -- confirmed against the CREATE TABLE + ALTER TABLE statements in
// internal/db/postgres.go.
func seedScenarioRun(t *testing.T, runID, agentID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := sharedDB.Pool.Exec(ctx,
		`INSERT INTO agents (agent_id) VALUES ($1) ON CONFLICT (agent_id) DO NOTHING`, agentID,
	); err != nil {
		t.Fatalf("seedScenarioRun: insert agent: %v", err)
	}
	if _, err := sharedDB.Pool.Exec(ctx,
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, status) VALUES ($1, 'test-scenario', $2, 'completed')`,
		runID, agentID,
	); err != nil {
		t.Fatalf("seedScenarioRun: insert scenario_run: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(context.Background(), `DELETE FROM scenario_runs WHERE id = $1`, runID)
		_, _ = sharedDB.Pool.Exec(context.Background(), `DELETE FROM agents WHERE agent_id = $1`, agentID)
	})
}

func TestPopulateThreatIntel_MixedTiers(t *testing.T) {
	const runID = "test-report-threatintel"
	seedScenarioRun(t, runID, "test-agent-threatintel")
	seedRunIOCForReport(t, runID)
	seedEnrichment(t, "ip", "45.33.32.156", 5)         // malicious-associated
	seedEnrichment(t, "domain", "evil.example.com", 1) // suspicious
	// hash "44d88612..." is left un-enriched -> pending

	e := NewEngine(sharedDB.Pool).WithThreatIntelProvider("otx")
	report, err := e.BuildFromRun(context.Background(), runID, "")
	if err != nil {
		t.Fatalf("BuildFromRun: %v", err)
	}
	if report.ThreatIntel == nil {
		t.Fatal("ThreatIntel is nil, want a populated section")
	}
	s := report.ThreatIntel.Summary
	if s.ExtractedCount != 3 {
		t.Errorf("ExtractedCount = %d, want 3", s.ExtractedCount)
	}
	if s.MaliciousAssociatedCount != 1 || s.SuspiciousCount != 1 || s.PendingCount != 1 {
		t.Errorf("got %+v", s)
	}
	if len(report.ThreatIntel.Indicators) != 3 {
		t.Fatalf("got %d indicators, want 3", len(report.ThreatIntel.Indicators))
	}
	if report.ThreatIntel.Indicators[0].Tier != "malicious-associated" {
		t.Errorf("Indicators[0].Tier = %q, want malicious-associated (worst-first sort)", report.ThreatIntel.Indicators[0].Tier)
	}
}

func TestPopulateThreatIntel_NoProviderConfigured_NilSection(t *testing.T) {
	const runID = "test-report-threatintel-noprovider"
	seedScenarioRun(t, runID, "test-agent-threatintel-noprovider")
	seedRunIOCForReport(t, runID)

	e := NewEngine(sharedDB.Pool) // WithThreatIntelProvider never called
	report, err := e.BuildFromRun(context.Background(), runID, "")
	if err != nil {
		t.Fatalf("BuildFromRun: %v", err)
	}
	if report.ThreatIntel != nil {
		t.Error("ThreatIntel should be nil when no provider is configured")
	}
}

func TestPopulateThreatIntel_NoIOCs_NilSection(t *testing.T) {
	const runID = "test-report-threatintel-noiocs"
	seedScenarioRun(t, runID, "test-agent-threatintel-noiocs")

	e := NewEngine(sharedDB.Pool).WithThreatIntelProvider("otx")
	report, err := e.BuildFromRun(context.Background(), runID, "")
	if err != nil {
		t.Fatalf("BuildFromRun: %v", err)
	}
	if report.ThreatIntel != nil {
		t.Error("ThreatIntel should be nil for a run with no run_iocs rows")
	}
}
