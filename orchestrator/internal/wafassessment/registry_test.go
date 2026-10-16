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

func TestEvaluateScenarioBySlug_APIProtection_ReturnsRealFail(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("api-protection")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "WAFSCENARIO-API-PROTECTION" {
		t.Errorf("scenario.ID = %q, want WAFSCENARIO-API-PROTECTION", scenario.ID)
	}
	if result.Outcome != ScenarioFail {
		t.Errorf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
}

func TestEvaluateScenarioBySlug_AutomatedAbuse_ReturnsRealFail(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("automated-abuse")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "WAFSCENARIO-AUTOMATED-ABUSE" {
		t.Errorf("scenario.ID = %q, want WAFSCENARIO-AUTOMATED-ABUSE", scenario.ID)
	}
	if result.Outcome != ScenarioFail {
		t.Errorf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
}

func TestEvaluateScenarioBySlug_PolicyIntegrity_ReturnsRealFail(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("policy-integrity")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "WAFSCENARIO-POLICY-INTEGRITY" {
		t.Errorf("scenario.ID = %q, want WAFSCENARIO-POLICY-INTEGRITY", scenario.ID)
	}
	if result.Outcome != ScenarioFail {
		t.Errorf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
}

func TestEvaluateScenarioBySlug_RoutingCacheIntegrity_ReturnsRealFail(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("routing-cache-integrity")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "WAFSCENARIO-ROUTING-CACHE-INTEGRITY" {
		t.Errorf("scenario.ID = %q, want WAFSCENARIO-ROUTING-CACHE-INTEGRITY", scenario.ID)
	}
	if result.Outcome != ScenarioFail {
		t.Errorf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
}

func TestEvaluateScenarioBySlug_FileUploadContentTrust_ReturnsRealFail(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("file-upload-content-trust")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "WAFSCENARIO-FILE-UPLOAD-CONTENT-TRUST" {
		t.Errorf("scenario.ID = %q, want WAFSCENARIO-FILE-UPLOAD-CONTENT-TRUST", scenario.ID)
	}
	if result.Outcome != ScenarioFail {
		t.Errorf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
}

func TestEvaluateScenarioBySlug_DetectionTelemetry_ReturnsRealFail(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("detection-telemetry")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "WAFSCENARIO-DETECTION-TELEMETRY" {
		t.Errorf("scenario.ID = %q, want WAFSCENARIO-DETECTION-TELEMETRY", scenario.ID)
	}
	if result.Outcome != ScenarioFail {
		t.Errorf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
}

func TestEvaluateScenarioBySlug_LegitimateTraffic_ReturnsRealFail(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("legitimate-traffic")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "WAFSCENARIO-LEGITIMATE-TRAFFIC" {
		t.Errorf("scenario.ID = %q, want WAFSCENARIO-LEGITIMATE-TRAFFIC", scenario.ID)
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
