package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/admatrix"
)

func TestGetADCoverage_ReturnsMatrixReport(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetADCoverage(rr, httptest.NewRequest(http.MethodGet, "/api/ad/coverage", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	var got admatrix.CoverageReport
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// The reported status must match the underlying matrix, not a copy.
	want := admatrix.Report()
	if got.Summary.Total != want.Summary.Total || len(got.Capabilities) != len(want.Capabilities) {
		t.Fatalf("report drifted from matrix: got total=%d caps=%d, want total=%d caps=%d",
			got.Summary.Total, len(got.Capabilities), want.Summary.Total, len(want.Capabilities))
	}
	if got.Summary.Total != len(admatrix.AllEntries()) {
		t.Fatalf("report total %d != matrix entries %d", got.Summary.Total, len(admatrix.AllEntries()))
	}
	// Spot-check a known entry's status is carried through serialization.
	var dcsync *admatrix.CapabilityCoverage
	for i := range got.Capabilities {
		if got.Capabilities[i].PrimitiveID == "dcsync" {
			dcsync = &got.Capabilities[i]
		}
	}
	if dcsync == nil || dcsync.CoverageStatus != admatrix.StatusScenarioComposable {
		t.Fatalf("dcsync coverage status not reported correctly: %+v", dcsync)
	}
	if dcsync.ValidationLevel != "model_simulated" {
		t.Fatalf("dcsync must remain model_simulated in the report, got %q", dcsync.ValidationLevel)
	}
}

// TestGetADCoverage_CapabilityStatesUseCamelCaseJSON locks the UI-facing
// contract: every object in the payload (including capabilityStates[], which
// once serialized with PascalCase Go field names) uses camelCase keys, so the
// frontend reads one consistent convention across the whole report.
func TestGetADCoverage_CapabilityStatesUseCamelCaseJSON(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetADCoverage(rr, httptest.NewRequest(http.MethodGet, "/api/ad/coverage", nil))

	var raw struct {
		CapabilityStates []map[string]json.RawMessage `json:"capabilityStates"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(raw.CapabilityStates) == 0 {
		t.Fatal("expected capabilityStates in the report")
	}
	first := raw.CapabilityStates[0]
	for _, want := range []string{"primitiveId", "contentAvailability", "executionValidation", "detectionValidation", "riskClass"} {
		if _, ok := first[want]; !ok {
			t.Errorf("capabilityStates[0] missing camelCase key %q (keys: %v)", want, keysOf(first))
		}
	}
	for _, bad := range []string{"PrimitiveID", "ContentAvailability", "ExecutionValidation"} {
		if _, ok := first[bad]; ok {
			t.Errorf("capabilityStates[0] still has PascalCase key %q", bad)
		}
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
