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

// TestCloneScenario_IndependentFromOriginal exercises the public contract:
// after cloning, editing the clone through the real API (UpdateScenario)
// must never affect the original.
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

// TestCloneScenario_SlicesAndLivePolicyAreIndependentCopies pins the fix for
// a real aliasing bug: CloneScenario used to do a shallow `clone := *src`,
// which only copies slice headers and the LivePolicy pointer itself — the
// backing arrays and the pointed-to struct stayed shared with the source
// until the clone was independently re-saved. An in-place mutation on either
// side (e.g. `clone.Tags[0] = ...`, or through the LivePolicy pointer) could
// corrupt the other. CloneScenario now deep-copies via a JSON round-trip;
// this test mutates the CLONE'S in-memory fields directly (not through the
// API, to catch aliasing regardless of how UpdateScenario happens to behave)
// and confirms the ORIGINAL's backing data is untouched.
func TestCloneScenario_SlicesAndLivePolicyAreIndependentCopies(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		src := minimalScenario("alias-src")
		src.Tags = []string{"tag-a", "tag-b"}
		src.MITREPhases = []string{"execution"}
		src.CalderaAbilities = []string{"ability-1"}
		src.ARTTechniques = []string{"T1059.001"}
		src.SupportedOS = []string{"windows"}
		src.LivePolicy = &scenario.LivePolicy{MaxSprayAttempts: 3, SprayAccountAllowlist: []string{"svc-account"}}
		seedCustomScenario(t, e, src)
		h := New(pool, ws.NewHub(), e, "")

		cloneReq := withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/alias-src/clone", nil), "id", "alias-src")
		cloneRec := httptest.NewRecorder()
		h.CloneScenario(cloneRec, cloneReq)
		if cloneRec.Code != http.StatusCreated {
			t.Fatalf("clone status = %d, body = %s", cloneRec.Code, cloneRec.Body.String())
		}

		clone, ok := e.Get("alias-src-copy")
		if !ok {
			t.Fatalf("clone missing from engine")
		}
		// Mutate every reference-typed field on the clone in place.
		clone.Tags[0] = "MUTATED"
		clone.MITREPhases[0] = "MUTATED"
		clone.CalderaAbilities[0] = "MUTATED"
		clone.ARTTechniques[0] = "MUTATED"
		clone.SupportedOS[0] = "MUTATED"
		clone.LivePolicy.MaxSprayAttempts = 999
		clone.LivePolicy.SprayAccountAllowlist[0] = "MUTATED"

		orig, ok := e.Get("alias-src")
		if !ok {
			t.Fatalf("original scenario missing")
		}
		if orig.Tags[0] != "tag-a" {
			t.Errorf("orig.Tags[0] = %q, want unaffected tag-a (aliasing bug regressed)", orig.Tags[0])
		}
		if orig.MITREPhases[0] != "execution" {
			t.Errorf("orig.MITREPhases[0] = %q, want unaffected execution", orig.MITREPhases[0])
		}
		if orig.CalderaAbilities[0] != "ability-1" {
			t.Errorf("orig.CalderaAbilities[0] = %q, want unaffected ability-1", orig.CalderaAbilities[0])
		}
		if orig.ARTTechniques[0] != "T1059.001" {
			t.Errorf("orig.ARTTechniques[0] = %q, want unaffected T1059.001", orig.ARTTechniques[0])
		}
		if orig.SupportedOS[0] != "windows" {
			t.Errorf("orig.SupportedOS[0] = %q, want unaffected windows", orig.SupportedOS[0])
		}
		if orig.LivePolicy.MaxSprayAttempts != 3 {
			t.Errorf("orig.LivePolicy.MaxSprayAttempts = %d, want unaffected 3", orig.LivePolicy.MaxSprayAttempts)
		}
		if orig.LivePolicy.SprayAccountAllowlist[0] != "svc-account" {
			t.Errorf("orig.LivePolicy.SprayAccountAllowlist[0] = %q, want unaffected svc-account", orig.LivePolicy.SprayAccountAllowlist[0])
		}
	})
}
