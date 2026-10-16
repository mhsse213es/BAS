package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAvScenarioJSONHandler_AVAssessment_ReturnsRealFailOutcome(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.avScenarioJSONHandler("av-assessment")(rr, httptest.NewRequest(http.MethodGet, "/api/av/scenarios/av-assessment", nil))

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
	if !strings.Contains(body, `"vectorId":"AV-PERSIST-002"`) {
		t.Error(`body missing "vectorId":"AV-PERSIST-002" (camelCase key)`)
	}
	if !strings.Contains(body, `"finding":"confirmed_gap"`) {
		t.Error(`body missing "finding":"confirmed_gap" -- the independent finding dimension, not a collapsed verdict`)
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

func TestAvScenarioJSONHandler_UnknownSlug_ReturnsServerError(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.avScenarioJSONHandler("does-not-exist")(rr, httptest.NewRequest(http.MethodGet, "/api/av/scenarios/does-not-exist", nil))

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestAvScenarioHTMLHandler_AVAssessment_RendersFailOutcome(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.avScenarioHTMLHandler("av-assessment")(rr, httptest.NewRequest(http.MethodGet, "/api/av/scenarios/av-assessment.html", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("body is not a full HTML document")
	}
	if !strings.Contains(body, "AV-PERSIST-002") {
		t.Error("body missing AV-PERSIST-002")
	}
}
