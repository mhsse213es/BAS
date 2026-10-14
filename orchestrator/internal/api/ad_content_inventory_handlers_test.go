package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func decodeInventory(t *testing.T, body []byte) contentInventoryResponse {
	t.Helper()
	var resp contentInventoryResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

func inTechIDs(tcs []techID) map[string]bool { // helper type alias below
	m := map[string]bool{}
	for _, tc := range tcs {
		m[tc.TechniqueID] = true
	}
	return m
}

// mirror of adlibinv.TechCoverage's json for assertion convenience
type techID struct {
	TechniqueID string `json:"techniqueId"`
	Covered     bool   `json:"covered"`
}

func TestGetADContentInventory_ReflectsAttachedStores(t *testing.T) {
	// A Caldera store that carries an ability for T1558.003 only, no ART store.
	cal := scenario.NewCalderaStoreFromSteps(map[string][]scenario.ScenarioStep{
		"T1558.003": {{TechniqueID: "T1558.003", Name: "kerberoast ability", Framework: "caldera"}},
	})
	h := (&Handler{}).WithCalderaStore(cal)

	rr := httptest.NewRecorder()
	h.GetADContentInventory(rr, httptest.NewRequest(http.MethodGet, "/api/ad/content-inventory", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	resp := decodeInventory(t, rr.Body.Bytes())

	if resp.ARTStoreLoaded {
		t.Error("ART store should report not-loaded")
	}
	if !resp.CalderaStoreLoaded {
		t.Error("Caldera store should report loaded")
	}
	if resp.Note == "" {
		t.Error("exactly one store attached: a note must flag that 'missing' is not a verified absence")
	}

	// Re-decode the report's technique coverage to assert on it.
	var full struct {
		Report struct {
			Covered []techID `json:"covered"`
			Missing []techID `json:"missing"`
		} `json:"report"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &full); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	covered := inTechIDs(full.Report.Covered)
	missing := inTechIDs(full.Report.Missing)

	if !covered["T1558.003"] {
		t.Errorf("T1558.003 has a Caldera ability and must be Covered; covered=%v", covered)
	}
	// A technique with no seeded content must be Missing, not Covered.
	if !missing["T1649"] || covered["T1649"] {
		t.Errorf("T1649 has no attached content and must be Missing; covered=%v missing=%v", covered, missing)
	}
}

func TestGetADContentInventory_NoStoresIsNotVerifiedAbsence(t *testing.T) {
	h := &Handler{} // neither store attached
	rr := httptest.NewRecorder()
	h.GetADContentInventory(rr, httptest.NewRequest(http.MethodGet, "/api/ad/content-inventory", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	resp := decodeInventory(t, rr.Body.Bytes())
	if resp.ARTStoreLoaded || resp.CalderaStoreLoaded {
		t.Fatal("no stores attached, yet one reported loaded")
	}
	if resp.Note == "" {
		t.Fatal("with no stores attached, the response must state this is not a verified absence of content")
	}
}
