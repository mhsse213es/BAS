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
