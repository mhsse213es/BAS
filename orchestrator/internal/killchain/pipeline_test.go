package killchain

import (
	"strings"
	"testing"
)

func validPipelineSpec() *PipelineSpec {
	return &PipelineSpec{ConnectorID: "dc-1", Index: "logs-*", Field: "event.id", Identifier: "bas-probe-1", LookbackMinutes: 15}
}

func pipelineCampaign(st StageDef) CampaignDef {
	return CampaignDef{ID: "pl", Version: 1, Stages: []StageDef{st}}
}

// A pipeline stage must name a connector, an index, a field, an identifier and a bounded window.
func TestPipelineSpec_RejectsIncompleteOrUnboundedSpecs(t *testing.T) {
	cases := map[string]func(p *PipelineSpec){
		"no connector":       func(p *PipelineSpec) { p.ConnectorID = "" },
		"no index":           func(p *PipelineSpec) { p.Index = "" },
		"no field":           func(p *PipelineSpec) { p.Field = "" },
		"no identifier":      func(p *PipelineSpec) { p.Identifier = "" },
		"zero lookback":      func(p *PipelineSpec) { p.LookbackMinutes = 0 },
		"unbounded lookback": func(p *PipelineSpec) { p.LookbackMinutes = 1441 },
	}
	for name, mutate := range cases {
		p := validPipelineSpec()
		mutate(p)
		if err := p.Validate("s"); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if err := validPipelineSpec().Validate("s"); err != nil {
		t.Fatalf("valid spec refused: %v", err)
	}
}

// A pipeline stage is read-only and names no agent scenario.
func TestPipelineStage_CampaignRules(t *testing.T) {
	ok := pipelineCampaign(StageDef{Key: "ingest", Pipeline: validPipelineSpec()})
	if _, err := ok.Validate(); err != nil {
		t.Fatalf("valid pipeline stage refused: %v", err)
	}

	withScenario := pipelineCampaign(StageDef{Key: "ingest", ScenarioID: "credential-access", Pipeline: validPipelineSpec()})
	if _, err := withScenario.Validate(); err == nil || !strings.Contains(err.Error(), "must not name a scenario") {
		t.Fatalf("pipeline with a scenario: %v", err)
	}

	live := pipelineCampaign(StageDef{Key: "ingest", Pipeline: validPipelineSpec(), Mode: ModeTelemetry})
	if _, err := live.Validate(); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("pipeline in a live mode: %v", err)
	}

	neither := pipelineCampaign(StageDef{Key: "x"})
	if _, err := neither.Validate(); err == nil || !strings.Contains(err.Error(), "needs a scenarioId, a pipeline or an injection") {
		t.Fatalf("stage with neither scenario nor pipeline: %v", err)
	}
}

// Connectivity and ingestion evidence is never ALLOWED, DETECTED or BLOCKED.
func TestPipelineVerdict_NeverAnAttackVerdict(t *testing.T) {
	for _, status := range []string{"VERIFIED", "INCONCLUSIVE", "ERROR", "NOT_TESTED"} {
		v, _ := PipelineVerdict([]PipelineStageResult{{Stage: "ingestion", Status: status, Reason: "r"}})
		switch v {
		case VerdictAllowed, VerdictDetected, VerdictBlocked, VerdictDetectedNotContained:
			t.Fatalf("status %s produced attack verdict %s", status, v)
		}
	}
}

// One ERROR among other stages makes the stage ERROR, and names the failing stage.
func TestPipelineVerdict_ErrorIsNeverHiddenByEvidence(t *testing.T) {
	v, reasons := PipelineVerdict([]PipelineStageResult{
		{Stage: "connectivity", Status: "VERIFIED", Reason: "reachable"},
		{Stage: "ingestion", Status: "ERROR", Reason: "permission denied (403)"},
	})
	if v != VerdictError || !strings.Contains(strings.Join(reasons, " "), "permission denied") {
		t.Fatalf("verdict=%s reasons=%v, want ERROR naming the ingestion failure", v, reasons)
	}
}

// Evidence without an error is INCONCLUSIVE, and every unverified stage is listed as NOT_TESTED.
func TestPipelineVerdict_EvidenceIsInconclusiveAndListsUntested(t *testing.T) {
	v, reasons := PipelineVerdict([]PipelineStageResult{
		{Stage: "ingestion", Status: "VERIFIED", Reason: "2 matches"},
		{Stage: "normalization", Status: "NOT_TESTED", Reason: "no check"},
	})
	joined := strings.Join(reasons, " | ")
	if v != VerdictInconclusive || !strings.Contains(joined, "normalization NOT_TESTED") {
		t.Fatalf("verdict=%s reasons=%s", v, joined)
	}
}

// No evidence at all is NOT_TESTED, never a pass.
func TestPipelineVerdict_NothingCheckedIsNotTested(t *testing.T) {
	if v, _ := PipelineVerdict(nil); v != VerdictNotTested {
		t.Fatalf("verdict=%s, want NOT_TESTED", v)
	}
	if v, _ := PipelineVerdict([]PipelineStageResult{{Stage: "ingestion", Status: "NOT_TESTED"}}); v != VerdictNotTested {
		t.Fatalf("verdict=%s, want NOT_TESTED", v)
	}
}
