package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetWAFExploitPreventionScenario_ReturnsRealFailOutcome(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetWAFExploitPreventionScenario(rr, httptest.NewRequest(http.MethodGet, "/api/waf/scenarios/exploit-prevention", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	body := rr.Body.String()
	if !strings.Contains(body, `"outcome":"fail"`) {
		t.Error(`body missing "outcome":"fail" (camelCase key)`)
	}
	if !strings.Contains(body, `"vectorId":"SQLI-002"`) {
		t.Error(`body missing "vectorId":"SQLI-002" (camelCase key)`)
	}

	var got struct {
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Outcome != "fail" {
		t.Errorf("Outcome = %q, want %q", got.Outcome, "fail")
	}
}

// Review Focus: the generic slug handler must serve a SECOND, different
// scenario correctly through the shared closure, not just the one it
// was first built for.
func TestWafScenarioJSONHandler_HTTPProtocolIntegrity_ReturnsRealFailOutcome(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.wafScenarioJSONHandler("http-protocol-integrity")(rr, httptest.NewRequest(http.MethodGet, "/api/waf/scenarios/http-protocol-integrity", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"outcome":"fail"`) {
		t.Error(`body missing "outcome":"fail"`)
	}
	if !strings.Contains(body, `"vectorId":"HTTPPARSE-001"`) {
		t.Error(`body missing "vectorId":"HTTPPARSE-001"`)
	}
	if !strings.Contains(body, `"scenarioName":"HTTP Protocol Integrity and Parser Consistency"`) {
		t.Error("body missing scenarioName for the correct scenario")
	}
}

// Review Focus: a THIRD scenario, spanning two real catalogs
// internally (wafcatalog + wafapiflow), must serve correctly through
// the same shared closure with no handler changes.
func TestWafScenarioJSONHandler_APIProtection_ReturnsRealFailOutcome(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.wafScenarioJSONHandler("api-protection")(rr, httptest.NewRequest(http.MethodGet, "/api/waf/scenarios/api-protection", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"outcome":"fail"`) {
		t.Error(`body missing "outcome":"fail"`)
	}
	if !strings.Contains(body, `"vectorId":"APIFLOW-003"`) {
		t.Error(`body missing "vectorId":"APIFLOW-003"`)
	}
	if !strings.Contains(body, `"vectorId":"API-001"`) {
		t.Error(`body missing "vectorId":"API-001" (confirms both catalogs' vectors are present)`)
	}
}

// Review Focus: scenario 08 (detection-telemetry) has no catalog
// severity and a non-wafval verdict taxonomy -- the generic handler
// must still serve it correctly with an empty severity field, not a
// crash or a fabricated one.
func TestWafScenarioJSONHandler_DetectionTelemetry_ReturnsRealFailOutcome(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.wafScenarioJSONHandler("detection-telemetry")(rr, httptest.NewRequest(http.MethodGet, "/api/waf/scenarios/detection-telemetry", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"outcome":"fail"`) {
		t.Error(`body missing "outcome":"fail"`)
	}
	if !strings.Contains(body, `"vectorId":"WAFDETECT-002"`) {
		t.Error(`body missing "vectorId":"WAFDETECT-002"`)
	}
	if !strings.Contains(body, `"verdict":"lost"`) {
		t.Error(`body missing "verdict":"lost" (the real completeness verdict, not a wafval one)`)
	}
}

// Review Focus: scenario 10 mixes two wafval.Verdict-backed kinds with
// one that carries waforigin's own ConsistencyVerdict -- the generic
// handler must serve both without special-casing.
func TestWafScenarioJSONHandler_OriginResilience_ReturnsRealFailOutcome(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.wafScenarioJSONHandler("origin-resilience")(rr, httptest.NewRequest(http.MethodGet, "/api/waf/scenarios/origin-resilience", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"outcome":"fail"`) {
		t.Error(`body missing "outcome":"fail"`)
	}
	if !strings.Contains(body, `"vectorId":"WAFORIGIN-005"`) {
		t.Error(`body missing "vectorId":"WAFORIGIN-005"`)
	}
	if !strings.Contains(body, `"verdict":"drift_detected"`) {
		t.Error(`body missing "verdict":"drift_detected" (the real consistency verdict, not a wafval one)`)
	}
}

func TestGetWAFExploitPreventionScenarioHTML_RendersFailOutcome(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetWAFExploitPreventionScenarioHTML(rr, httptest.NewRequest(http.MethodGet, "/api/waf/scenarios/exploit-prevention.html", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("body is not a full HTML document")
	}
	if !strings.Contains(body, "SQLI-002") {
		t.Error("body missing SQLI-002")
	}
}
