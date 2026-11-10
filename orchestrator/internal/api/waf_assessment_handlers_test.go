package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/wafmodsec"
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

// Review Focus: a FOURTH scenario must serve correctly through the same shared closure with no handler changes
// (closes WAF QA log item #4 in part: automated-abuse had no scenario-specific handler test).
func TestWafScenarioJSONHandler_AutomatedAbuse_ReturnsRealFailOutcome(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.wafScenarioJSONHandler("automated-abuse")(rr, httptest.NewRequest(http.MethodGet, "/api/waf/scenarios/automated-abuse", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"outcome":"fail"`) {
		t.Error(`body missing "outcome":"fail"`)
	}
	if !strings.Contains(body, `"vectorId":"BOTABUSE-004"`) {
		t.Error(`body missing "vectorId":"BOTABUSE-004"`)
	}
	if !strings.Contains(body, `"scenarioName":"Automated Abuse and Resource Protection"`) {
		t.Error("body missing scenarioName for the correct scenario")
	}
}

// Review Focus: a FIFTH scenario must serve correctly through the same shared closure with no handler changes
// (closes WAF QA log item #4 in part: file-upload had no scenario-specific handler test).
func TestWafScenarioJSONHandler_FileUpload_ReturnsRealFailOutcome(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.wafScenarioJSONHandler("file-upload-content-trust")(rr, httptest.NewRequest(http.MethodGet, "/api/waf/scenarios/file-upload-content-trust", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"outcome":"fail"`) {
		t.Error(`body missing "outcome":"fail"`)
	}
	if !strings.Contains(body, `"vectorId":"FILEUP-001"`) {
		t.Error(`body missing "vectorId":"FILEUP-001"`)
	}
	if !strings.Contains(body, `"scenarioName":"File Upload and Content Trust"`) {
		t.Error("body missing scenarioName for the correct scenario")
	}
}

// Review Focus: a SIXTH scenario must serve correctly through the same shared closure with no handler changes
// (closes WAF QA log item #4 in part: routing-cache had no scenario-specific handler test).
func TestWafScenarioJSONHandler_RoutingCache_ReturnsRealFailOutcome(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.wafScenarioJSONHandler("routing-cache-integrity")(rr, httptest.NewRequest(http.MethodGet, "/api/waf/scenarios/routing-cache-integrity", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"outcome":"fail"`) {
		t.Error(`body missing "outcome":"fail"`)
	}
	if !strings.Contains(body, `"vectorId":"CACHE-001"`) {
		t.Error(`body missing "vectorId":"CACHE-001"`)
	}
	if !strings.Contains(body, `"scenarioName":"Application Routing and Cache Integrity"`) {
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

// Review Focus: the live exploit-prevention endpoint must refuse cleanly,
// never silently fall back to the fixture-backed result, when no live WAF
// lab is configured -- WAF_MODSEC_LAB_URL unset is the normal state in this
// test suite and in production unless an operator has set it.
func TestWafExploitPreventionLiveJSONHandler_NoLabConfigured_Returns503(t *testing.T) {
	t.Setenv(wafModsecLabURLEnv, "")
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.wafExploitPreventionLiveJSONHandler(rr, httptest.NewRequest(http.MethodGet, "/api/waf/scenarios/exploit-prevention/live", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rr.Body.String(), wafModsecLabURLEnv) {
		t.Errorf("body should name %s so an operator knows what to set, got: %s", wafModsecLabURLEnv, rr.Body.String())
	}
}

// Review Focus: the other 5 live scenario endpoints share
// wafScenarioLiveJSONHandler with exploit-prevention's -- this proves the
// 503 refusal path generically, for each one's own Run<Scenario>Live,
// rather than retesting the shared handler body 5 more times.
func TestWafScenarioLiveJSONHandler_NoLabConfigured_Returns503(t *testing.T) {
	t.Setenv(wafModsecLabURLEnv, "")
	h := &Handler{}
	for _, run := range []liveScenarioRunner{
		wafmodsec.RunHTTPProtocolIntegrityLive,
		wafmodsec.RunRoutingCacheIntegrityLive,
		wafmodsec.RunAPIProtectionLive,
		wafmodsec.RunLegitimateTrafficLive,
		wafmodsec.RunFileUploadContentTrustLive,
	} {
		rr := httptest.NewRecorder()
		h.wafScenarioLiveJSONHandler(run)(rr, httptest.NewRequest(http.MethodGet, "/api/waf/scenarios/x/live", nil))
		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
		}
		if !strings.Contains(rr.Body.String(), wafModsecLabURLEnv) {
			t.Errorf("body should name %s, got: %s", wafModsecLabURLEnv, rr.Body.String())
		}
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
