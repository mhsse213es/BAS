package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/threatpriority"
	"github.com/audspect/bas/internal/ws"
)

func TestThreatPriorityActors_EmptyRoster_ReturnsEmptyArray(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		engine := scenario.NewEngine(t.TempDir())
		if err := engine.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}
		pe := threatpriority.NewEngine(pool, engine, nil, nil)
		h := New(pool, ws.NewHub(), engine, "").WithThreatPriority(pe)

		req := httptest.NewRequest("GET", "/api/threat-priority/actors", nil)
		w := httptest.NewRecorder()
		h.ThreatPriorityActors(w, req)

		if w.Code != 200 {
			t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
		}
	})
}

func TestThreatPriorityActorDetail_UnknownActor_ReturnsEmptyButOK(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		engine := scenario.NewEngine(t.TempDir())
		if err := engine.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}
		pe := threatpriority.NewEngine(pool, engine, nil, nil)
		h := New(pool, ws.NewHub(), engine, "").WithThreatPriority(pe)

		req := httptest.NewRequest("GET", "/api/threat-priority/actors/Nonexistent-Actor", nil)
		req = withURLParams(req, map[string]string{"name": "Nonexistent-Actor"})
		w := httptest.NewRecorder()
		h.ThreatPriorityActorDetail(w, req)

		if w.Code != 200 {
			t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"techniqueCoverage":[]`) {
			t.Errorf("body should contain an empty techniqueCoverage array, got: %s", w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"uncoveredTechniques":[]`) {
			t.Errorf("body should still contain an empty uncoveredTechniques array (unchanged), got: %s", w.Body.String())
		}
	})
}

func TestBuildTechniqueCoverage_NoContentIsGap(t *testing.T) {
	out := buildTechniqueCoverage(
		[]string{"T1059.001"},
		map[string]bool{}, map[string]bool{}, map[string]bool{},
		map[string]threatpriority.VerdictEntry{}, map[string]threatpriority.VerdictEntry{},
	)
	if len(out) != 1 {
		t.Fatalf("want 1 row, got %d", len(out))
	}
	if out[0].Status != "gap-no-content" {
		t.Errorf("Status = %q, want gap-no-content", out[0].Status)
	}
}

func TestBuildTechniqueCoverage_ContentNoVerdictsIsUntested(t *testing.T) {
	out := buildTechniqueCoverage(
		[]string{"T1059.001"},
		map[string]bool{"T1059.001": true}, map[string]bool{}, map[string]bool{},
		map[string]threatpriority.VerdictEntry{}, map[string]threatpriority.VerdictEntry{},
	)
	if out[0].Status != "untested" {
		t.Errorf("Status = %q, want untested", out[0].Status)
	}
	if !out[0].HasSimulation {
		t.Error("HasSimulation = false, want true")
	}
}

func TestBuildTechniqueCoverage_PreventionVerdictOnly(t *testing.T) {
	out := buildTechniqueCoverage(
		[]string{"T1059.001"},
		map[string]bool{"T1059.001": true}, map[string]bool{}, map[string]bool{},
		map[string]threatpriority.VerdictEntry{"T1059.001": {Verdict: "pass"}}, map[string]threatpriority.VerdictEntry{},
	)
	if out[0].Status != "has-outcomes" {
		t.Errorf("Status = %q, want has-outcomes", out[0].Status)
	}
	if out[0].PreventionVerdict != "pass" {
		t.Errorf("PreventionVerdict = %q, want pass", out[0].PreventionVerdict)
	}
	if out[0].DetectionVerdict != "" {
		t.Errorf("DetectionVerdict = %q, want empty", out[0].DetectionVerdict)
	}
}

func TestBuildTechniqueCoverage_DetectionVerdictOnly(t *testing.T) {
	out := buildTechniqueCoverage(
		[]string{"T1059.001"},
		map[string]bool{"T1059.001": true}, map[string]bool{}, map[string]bool{},
		map[string]threatpriority.VerdictEntry{}, map[string]threatpriority.VerdictEntry{"T1059.001": {Verdict: "Detected"}},
	)
	if out[0].Status != "has-outcomes" {
		t.Errorf("Status = %q, want has-outcomes", out[0].Status)
	}
	if out[0].DetectionVerdict != "Detected" {
		t.Errorf("DetectionVerdict = %q, want Detected", out[0].DetectionVerdict)
	}
	if out[0].PreventionVerdict != "" {
		t.Errorf("PreventionVerdict = %q, want empty", out[0].PreventionVerdict)
	}
}

func TestBuildTechniqueCoverage_BothVerdicts(t *testing.T) {
	out := buildTechniqueCoverage(
		[]string{"T1059.001"},
		map[string]bool{"T1059.001": true}, map[string]bool{}, map[string]bool{},
		map[string]threatpriority.VerdictEntry{"T1059.001": {Verdict: "fail"}},
		map[string]threatpriority.VerdictEntry{"T1059.001": {Verdict: "NotDetected"}},
	)
	if out[0].Status != "has-outcomes" {
		t.Errorf("Status = %q, want has-outcomes", out[0].Status)
	}
	if out[0].PreventionVerdict != "fail" || out[0].DetectionVerdict != "NotDetected" {
		t.Errorf("got Prevention=%q Detection=%q, want fail/NotDetected", out[0].PreventionVerdict, out[0].DetectionVerdict)
	}
}

func TestThreatPriorityActors_NoEngineAttached_ReturnsEmptyArray(t *testing.T) {
	engine := scenario.NewEngine(t.TempDir())
	if err := engine.Load(); err != nil {
		t.Fatalf("engine.Load: %v", err)
	}
	h := New(nil, ws.NewHub(), engine, "")

	req := httptest.NewRequest("GET", "/api/threat-priority/actors", nil)
	w := httptest.NewRecorder()
	h.ThreatPriorityActors(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}
	if strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("body = %q, want an empty JSON array (nil-safe when no priority engine attached)", w.Body.String())
	}
}

func TestThreatPriorityActorDetail_ReturnsPerSourceProvenance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source, confidence)
			 VALUES ('API-PROV-ACTOR','{}','{}','{}','misp','high')
			 ON CONFLICT (name) DO NOTHING`); err != nil {
			t.Fatalf("seed profile: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO threat_actor_sources (actor_name, source, source_id, name, aliases, sectors, regions, confidence, technique_count)
			 VALUES ('API-PROV-ACTOR','misp','evt-1','API-PROV-ACTOR','{}','{"financial services"}','{}','high',2),
			        ('API-PROV-ACTOR','opencti','ta-9','API-PROV-Tempest','{"API-PROV-ACTOR"}','{}','{}','medium',1)
			 ON CONFLICT (actor_name, source) DO NOTHING`); err != nil {
			t.Fatalf("seed sources: %v", err)
		}

		engine := scenario.NewEngine(t.TempDir())
		if err := engine.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}
		pe := threatpriority.NewEngine(pool, engine, nil, nil)
		h := New(pool, ws.NewHub(), engine, "").WithThreatPriority(pe)

		req := httptest.NewRequest("GET", "/api/threat-priority/actors/API-PROV-ACTOR", nil)
		req = withURLParams(req, map[string]string{"name": "API-PROV-ACTOR"})
		w := httptest.NewRecorder()
		h.ThreatPriorityActorDetail(w, req)

		if w.Code != 200 {
			t.Fatalf("status = %d, body: %s", w.Code, w.Body.String())
		}
		var got struct {
			Sources []ActorSource `json:"sources"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got.Sources) != 2 {
			t.Fatalf("sources = %+v, want 2 entries", got.Sources)
		}
		// ORDER BY source -> misp, opencti
		if got.Sources[0].Source != "misp" || got.Sources[0].Confidence != "high" ||
			len(got.Sources[0].Sectors) != 1 || got.Sources[0].Sectors[0] != "financial services" {
			t.Errorf("misp entry = %+v, want its own sectors/confidence", got.Sources[0])
		}
		if got.Sources[1].Source != "opencti" || got.Sources[1].Name != "API-PROV-Tempest" ||
			got.Sources[1].TechniqueCount != 1 {
			t.Errorf("opencti entry = %+v, want its OWN name (not the canonical one)", got.Sources[1])
		}
	})
}

func TestThreatPriorityActorDetail_ReturnsTechniqueEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source, confidence)
			 VALUES ('API-EVID-ACTOR','{}','{}','{}','opencti','high')
			 ON CONFLICT (name) DO NOTHING`); err != nil {
			t.Fatalf("seed profile: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO technique_evidence (actor_name, technique_id, via, via_name, source, confidence)
			 VALUES ('API-EVID-ACTOR','T1059.001','','','opencti',80),
			        ('API-EVID-ACTOR','T1566.001','campaign','Operation Ghost','opencti',40)
			 ON CONFLICT (actor_name, technique_id, via, via_name, source) DO NOTHING`); err != nil {
			t.Fatalf("seed evidence: %v", err)
		}

		engine := scenario.NewEngine(t.TempDir())
		if err := engine.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}
		pe := threatpriority.NewEngine(pool, engine, nil, nil)
		h := New(pool, ws.NewHub(), engine, "").WithThreatPriority(pe)

		req := httptest.NewRequest("GET", "/api/threat-priority/actors/API-EVID-ACTOR", nil)
		req = withURLParams(req, map[string]string{"name": "API-EVID-ACTOR"})
		w := httptest.NewRecorder()
		h.ThreatPriorityActorDetail(w, req)

		if w.Code != 200 {
			t.Fatalf("status = %d, body: %s", w.Code, w.Body.String())
		}
		var got struct {
			TechniqueEvidence []TechniqueEvidenceRow `json:"techniqueEvidence"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got.TechniqueEvidence) != 2 {
			t.Fatalf("techniqueEvidence = %+v, want 2 entries", got.TechniqueEvidence)
		}
	})
}
