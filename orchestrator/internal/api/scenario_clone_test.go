package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCloneScenario_IntelSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir, e := newFileEngine(t)
		src := minimalScenario("intel-clone-src")
		src.IntelSource = "connector-x"
		src.IntelSourceID = "abc123"
		src.IntelActor = "APT99"
		src.IntelConfidence = "high"
		src.IntelGeneratedAt = time.Now().UTC()
		seedIntelScenario(t, dir, e, src)

		h := New(pool, ws.NewHub(), e, "")
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/intel-clone-src/clone", nil), "id", "intel-clone-src")
		rec := httptest.NewRecorder()
		h.CloneScenario(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
		}

		var out scenario.Scenario
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.ID != "intel-clone-src-copy" {
			t.Fatalf("id = %q, want intel-clone-src-copy", out.ID)
		}
		if out.Name != "Test Scenario intel-clone-src (copy)" {
			t.Fatalf("name = %q", out.Name)
		}
		if out.Source != "custom" {
			t.Fatalf("source = %q, want custom", out.Source)
		}
		if out.IntelSource != "" || out.IntelSourceID != "" || out.IntelActor != "" || out.IntelConfidence != "" || !out.IntelGeneratedAt.IsZero() {
			t.Fatalf("intel provenance not stripped: %+v", out)
		}

		orig, ok := e.Get("intel-clone-src")
		if !ok || orig.IntelSource != "connector-x" {
			t.Fatalf("original scenario mutated or missing: %+v", orig)
		}
		if _, ok := e.Get("intel-clone-src-copy"); !ok {
			t.Fatalf("clone not present in memory")
		}
		want := filepath.Join(dir, "custom", "intel-clone-src-copy.yaml")
		if _, err := os.Stat(want); err != nil {
			t.Fatalf("expected clone file at %s: %v", want, err)
		}
	})
}

func TestCloneScenario_CustomSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("custom-clone-src"))
		h := New(pool, ws.NewHub(), e, "")
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/custom-clone-src/clone", nil), "id", "custom-clone-src")
		rec := httptest.NewRecorder()
		h.CloneScenario(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
		}
		var out scenario.Scenario
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.ID != "custom-clone-src-copy" || out.Source != "custom" {
			t.Fatalf("unexpected clone: %+v", out)
		}
		want := filepath.Join(dir, "custom", "custom-clone-src-copy.yaml")
		if _, err := os.Stat(want); err != nil {
			t.Fatalf("expected clone file at %s: %v", want, err)
		}
	})
}

func TestCloneScenario_ExplicitNewIDAndName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("explicit-src"))
		h := New(pool, ws.NewHub(), e, "")
		body := strings.NewReader(`{"newId":"explicit-target","name":"Custom Clone Name"}`)
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/explicit-src/clone", body), "id", "explicit-src")
		rec := httptest.NewRecorder()
		h.CloneScenario(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
		}
		var out scenario.Scenario
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.ID != "explicit-target" {
			t.Fatalf("id = %q, want explicit-target", out.ID)
		}
		if out.Name != "Custom Clone Name" {
			t.Fatalf("name = %q, want Custom Clone Name", out.Name)
		}
	})
}

func TestCloneScenario_IDCollision(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("collide-src"))
		seedCustomScenario(t, e, minimalScenario("collide-src-copy")) // pre-occupies the default clone id
		h := New(pool, ws.NewHub(), e, "")
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/collide-src/clone", nil), "id", "collide-src")
		rec := httptest.NewRecorder()
		h.CloneScenario(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409", rec.Code)
		}
	})
}

// TestCloneScenario_InvalidNewIDFailsValidate exercises CloneScenario's
// Save() call directly (handlers.go:1355-1358): a caller-supplied newId that
// fails idPattern produces a clone that fails Validate() even though the
// source scenario was itself valid.
func TestCloneScenario_InvalidNewIDFailsValidate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("invalid-newid-src"))
		h := New(pool, ws.NewHub(), e, "")
		body := strings.NewReader(`{"newId":"Bad ID!"}`)
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/invalid-newid-src/clone", body), "id", "invalid-newid-src")
		rec := httptest.NewRecorder()
		h.CloneScenario(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422, body = %s", rec.Code, rec.Body.String())
		}
		if _, ok := e.Get("Bad ID!"); ok {
			t.Fatalf("invalid clone should not have been saved")
		}
	})
}

func TestCloneScenario_SourceNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		h := New(pool, ws.NewHub(), e, "")
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/missing-src/clone", nil), "id", "missing-src")
		rec := httptest.NewRecorder()
		h.CloneScenario(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestCloneScenario_IndependentFromOriginal exercises the documented public
// contract only: after cloning, editing the clone through the real API
// (UpdateScenario) must never affect the original. It does NOT assert
// independence of the underlying slice-typed fields (Steps/Tags/MITREPhases/
// SupportedOS/CalderaAbilities/ARTTechniques) — CloneScenario does a shallow
// `clone := *src` (handlers.go:1333) that shares those slices' backing arrays
// with the source until the clone is independently re-saved. That is a
// latent aliasing hazard, recorded as a finding in the phase summary, not a
// contractual guarantee: a future in-place slice mutation on either side
// (e.g. an append within capacity, or `clone.Tags[0] = ...`) could corrupt
// the other. See
// docs/superpowers/specs/2026-07-12-test-phase3b3-scenario-authoring-design.md.
func TestCloneScenario_IndependentFromOriginal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("indep-src"))
		h := New(pool, ws.NewHub(), e, "")

		cloneReq := withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/indep-src/clone", nil), "id", "indep-src")
		cloneRec := httptest.NewRecorder()
		h.CloneScenario(cloneRec, cloneReq)
		if cloneRec.Code != http.StatusCreated {
			t.Fatalf("clone status = %d, want 201", cloneRec.Code)
		}

		updated := minimalScenario("indep-src-copy")
		updated.Name = "Mutated Clone Name"
		updateReq := withURLParam(httptest.NewRequest(http.MethodPut, "/api/scenarios/indep-src-copy", scenarioJSON(t, updated)), "id", "indep-src-copy")
		updateRec := httptest.NewRecorder()
		h.UpdateScenario(updateRec, updateReq)
		if updateRec.Code != http.StatusOK {
			t.Fatalf("update status = %d, want 200", updateRec.Code)
		}

		orig, ok := e.Get("indep-src")
		if !ok {
			t.Fatalf("original scenario missing")
		}
		if orig.Name != "Test Scenario indep-src" {
			t.Fatalf("original mutated by editing its clone: name = %q", orig.Name)
		}
	})
}
