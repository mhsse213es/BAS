package killchain

import (
	"strings"
	"testing"
)

func injectCampaign(st StageDef) CampaignDef {
	return CampaignDef{ID: "inj", Version: 1, Stages: []StageDef{st}}
}

// An injection stage is valid with one explicit index and no scenario or pipeline.
func TestInjectStage_ValidWithOneExplicitIndex(t *testing.T) {
	if _, err := injectCampaign(StageDef{Key: "inject", Inject: &InjectSpec{Index: "logs-bas"}}).Validate(); err != nil {
		t.Fatalf("valid injection stage refused: %v", err)
	}
}

// Patterns, lists and empty names are refused, so an injection can never widen beyond one index.
func TestInjectStage_RefusesPatternIndexes(t *testing.T) {
	for _, idx := range []string{"", "logs-*", "logs-a,logs-b", "_all", "logs bas", "logs?"} {
		if _, err := injectCampaign(StageDef{Key: "inject", Inject: &InjectSpec{Index: idx}}).Validate(); err == nil {
			t.Fatalf("index %q accepted", idx)
		}
	}
}

// An injection stage must not name a scenario or a pipeline.
func TestInjectStage_RefusesMixedStageKinds(t *testing.T) {
	spec := &InjectSpec{Index: "logs-bas"}
	withScenario := injectCampaign(StageDef{Key: "inject", ScenarioID: "credential-access", Inject: spec})
	if _, err := withScenario.Validate(); err == nil || !strings.Contains(err.Error(), "must not name a scenario") {
		t.Fatalf("injection with a scenario: %v", err)
	}
	withPipeline := injectCampaign(StageDef{Key: "inject", Inject: spec,
		Pipeline: &PipelineSpec{ConnectorID: "dc-1", Index: "logs-*", Field: "event.id", Identifier: "x", LookbackMinutes: 5}})
	if _, err := withPipeline.Validate(); err == nil {
		t.Fatal("injection with a pipeline accepted")
	}
}

// An injection stage is posture only: a live mode is refused.
func TestInjectStage_LiveModeRefused(t *testing.T) {
	if _, err := injectCampaign(StageDef{Key: "inject", Mode: ModeTelemetry, Inject: &InjectSpec{Index: "logs-bas"}}).Validate(); err == nil {
		t.Fatal("injection in a live mode accepted")
	}
}
