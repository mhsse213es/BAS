package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func realScenarioEngineForBridgeTest(t *testing.T) *scenario.Engine {
	dir, err := filepath.Abs("../../../scenarios")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("scenarios dir not found at %s: %v", dir, err)
	}
	e := scenario.NewEngine(dir)
	if err := e.Load(); err != nil {
		t.Fatalf("engine.Load(): %v", err)
	}
	return e
}

// Review Focus: this bridge must report real coverage computed from the
// engine's actual loaded scenarios, never a hardcoded list that could go
// stale -- T1486/T1490 are known (via the real YAML corpus) to be
// declared by ransomware-drill and most kill-chain scenarios, so a
// correct implementation must surface ransomware-drill as one of
// T1486's RealScenarioIDs.
func TestGetAVRansomwarePrecursorCoverage_RealCorpus_T1486CoveredByRansomwareDrill(t *testing.T) {
	h := &Handler{engine: realScenarioEngineForBridgeTest(t)}

	req := httptest.NewRequest(http.MethodGet, "/api/av/ransomware-precursor-coverage", nil)
	rec := httptest.NewRecorder()
	h.GetAVRansomwarePrecursorCoverage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	var resp avRansomwarePrecursorCoverageResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal: %v, body: %s", err, rec.Body.String())
	}

	if resp.ScoreEndpointFormat != "/api/scenarios/runs/{runId}/rw-score" {
		t.Errorf("ScoreEndpointFormat = %q, want the real rw-score endpoint format", resp.ScoreEndpointFormat)
	}

	var t1486Found bool
	for _, tech := range resp.Techniques {
		if tech.TechniqueID != "T1486" {
			continue
		}
		t1486Found = true
		var sawRansomwareDrill bool
		for _, id := range tech.RealScenarioIDs {
			if id == "ransomware-drill" {
				sawRansomwareDrill = true
			}
		}
		if !sawRansomwareDrill {
			t.Errorf("T1486.RealScenarioIDs = %v, want \"ransomware-drill\" present (its real T1486 step is production-safe and already in ransomwareScenarioIDs)", tech.RealScenarioIDs)
		}
	}
	if !t1486Found {
		t.Fatal("T1486 not present in response -- rwevidence.DataEncryptedForImpact() should always produce a row")
	}
}

// TestGetAVRansomwarePrecursorCoverage_NilEngine_ReturnsAllTechniquesEmptyCoverage
// proves a nil engine fails closed to an honest "no real coverage known"
// answer -- every one of rwevidence's 4 modeled techniques still appears
// in the response, each with an empty RealScenarioIDs, never a panic and
// never a silently dropped row.
func TestGetAVRansomwarePrecursorCoverage_NilEngine_ReturnsAllTechniquesEmptyCoverage(t *testing.T) {
	h := &Handler{}

	req := httptest.NewRequest(http.MethodGet, "/api/av/ransomware-precursor-coverage", nil)
	rec := httptest.NewRecorder()
	h.GetAVRansomwarePrecursorCoverage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	var resp avRansomwarePrecursorCoverageResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal: %v, body: %s", err, rec.Body.String())
	}

	if len(resp.Techniques) != 4 {
		t.Fatalf("len(Techniques) = %d, want 4", len(resp.Techniques))
	}
	for _, tech := range resp.Techniques {
		if len(tech.RealScenarioIDs) != 0 {
			t.Errorf("technique %s: RealScenarioIDs = %v, want empty with a nil engine", tech.TechniqueID, tech.RealScenarioIDs)
		}
	}
}
