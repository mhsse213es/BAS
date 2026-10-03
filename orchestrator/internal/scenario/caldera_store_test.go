package scenario

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewCalderaStore_IndexesAbilitiesByTechnique(t *testing.T) {
	const abilitiesJSON = `[
	  {"ability_id":"a1","name":"whoami","technique_id":"T1033","tactic":"discovery",
	   "executors":[{"platform":"windows","name":"psh","command":"whoami"}]},
	  {"ability_id":"a2","name":"net user","technique_id":"T1033","tactic":"discovery",
	   "executors":[{"platform":"windows","name":"psh","command":"net user"}]},
	  {"ability_id":"a3","name":"systeminfo","technique_id":"T1082","tactic":"discovery",
	   "executors":[{"platform":"windows","name":"psh","command":"systeminfo"}]}
	]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/abilities" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(abilitiesJSON))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	store := NewCalderaStore(srv.URL, "")

	got := store.GetAbilities("T1033")
	if len(got) != 2 {
		t.Fatalf("GetAbilities(T1033) = %d abilities, want 2", len(got))
	}
	names := map[string]bool{}
	for _, s := range got {
		names[s.Name] = true
		if s.Framework != "caldera" {
			t.Errorf("step %q Framework = %q, want caldera", s.Name, s.Framework)
		}
		if s.TechniqueID != "T1033" {
			t.Errorf("step %q TechniqueID = %q, want T1033", s.Name, s.TechniqueID)
		}
	}
	if !names["whoami"] || !names["net user"] {
		t.Errorf("got abilities %v, want whoami and net user", names)
	}

	single := store.GetAbilities("T1082")
	if len(single) != 1 || single[0].Name != "systeminfo" {
		t.Fatalf("GetAbilities(T1082) = %+v, want exactly [systeminfo]", single)
	}

	// Lookup is case-insensitive, mirroring ARTStore.GetSteps.
	if got := store.GetAbilities("t1033"); len(got) != 2 {
		t.Errorf("GetAbilities(t1033) (lowercase) = %d, want 2", len(got))
	}
}

// TestNewCalderaStore_AssignsRealActionKey pins the B5 ART/Caldera audit's
// wiring fix: real dispatch must set ScenarioStep.ActionKey from the
// ability's own Name, using the same derivation cmd/auditcorpus used to
// build execclass_generated.go -- otherwise ResolveExecutionClass always
// falls back to the technique's "enumerate" default regardless of which
// real ability is being classified.
func TestNewCalderaStore_AssignsRealActionKey(t *testing.T) {
	const abilitiesJSON = `[
	  {"ability_id":"a1","name":"systeminfo","technique_id":"T1082","tactic":"discovery",
	   "executors":[{"platform":"windows","name":"psh","command":"systeminfo"}]}
	]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/abilities" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(abilitiesJSON))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	store := NewCalderaStore(srv.URL, "")
	got := store.GetAbilities("T1082")
	if len(got) != 1 {
		t.Fatalf("GetAbilities(T1082) = %d abilities, want 1", len(got))
	}
	if got[0].ActionKey != "systeminfo" {
		t.Errorf("ActionKey = %q, want %q -- real Caldera abilities must get a derived action_key, not be left empty (which falls back to \"enumerate\")", got[0].ActionKey, "systeminfo")
	}
}

func TestNewCalderaStore_UnknownTechniqueReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	store := NewCalderaStore(srv.URL, "")
	if got := store.GetAbilities("T9999"); got != nil {
		t.Errorf("GetAbilities(unknown) = %+v, want nil", got)
	}
}

func TestNewCalderaStore_UnconfiguredURLReturnsEmptyStoreNotError(t *testing.T) {
	store := NewCalderaStore("", "")
	if got := store.GetAbilities("T1033"); got != nil {
		t.Errorf("GetAbilities on unconfigured store = %+v, want nil", got)
	}
}

func TestNewCalderaStore_UnreachableCalderaReturnsEmptyStoreNotPanic(t *testing.T) {
	store := NewCalderaStore("http://127.0.0.1:1", "")
	if got := store.GetAbilities("T1033"); got != nil {
		t.Errorf("GetAbilities on unreachable-Caldera store = %+v, want nil", got)
	}
}

func TestNewCalderaStore_SkipsAbilitiesWithoutTechniqueMapping(t *testing.T) {
	const abilitiesJSON = `[
	  {"ability_id":"a1","name":"no technique","tactic":"discovery",
	   "executors":[{"platform":"windows","name":"psh","command":"whoami"}]}
	]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(abilitiesJSON))
	}))
	defer srv.Close()

	store := NewCalderaStore(srv.URL, "")
	if got := store.GetAbilities(""); got != nil {
		t.Errorf("GetAbilities(\"\") = %+v, want nil (no-technique abilities must not be indexed under the empty key)", got)
	}
}
