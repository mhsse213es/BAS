package wafassessment

import "testing"

func TestEvaluateScenarioBySlug_ExploitPrevention_ReturnsRealFail(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("exploit-prevention")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "WAFSCENARIO-EXPLOIT-PREVENTION" {
		t.Errorf("scenario.ID = %q, want WAFSCENARIO-EXPLOIT-PREVENTION", scenario.ID)
	}
	if result.Outcome != ScenarioFail {
		t.Errorf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
}

func TestEvaluateScenarioBySlug_HTTPProtocolIntegrity_ReturnsRealFail(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("http-protocol-integrity")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "WAFSCENARIO-HTTP-PROTOCOL-INTEGRITY" {
		t.Errorf("scenario.ID = %q, want WAFSCENARIO-HTTP-PROTOCOL-INTEGRITY", scenario.ID)
	}
	if result.Outcome != ScenarioFail {
		t.Errorf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
}

func TestEvaluateScenarioBySlug_UnknownSlug_ReturnsError(t *testing.T) {
	if _, _, err := EvaluateScenarioBySlug("does-not-exist"); err == nil {
		t.Fatal("want error for unknown slug, got nil")
	}
}
