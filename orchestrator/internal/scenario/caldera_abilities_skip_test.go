package scenario

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBuildCalderaAbilitiesSteps_ReportsSkippedAbilities proves a
// caldera_abilities scenario surfaces WHICH configured ability IDs never
// became a step and WHY, instead of silently dropping them -- e.g. a
// scenario configured with 8 ids that resolves to only 4 real steps must
// report the other 4 with a reason, not just come back short.
func TestBuildCalderaAbilitiesSteps_ReportsSkippedAbilities(t *testing.T) {
	const okAbilityJSON = `{"ability_id":"%s","name":"%s","technique_id":"T1082","tactic":"discovery",
	  "executors":[{"platform":"windows","name":"psh","command":"systeminfo"}]}`
	// pickExecutorCommand falls back to the FIRST executor's command regardless
	// of platform/name when no preferred/psh/powershell match exists -- so the
	// only way an ability genuinely yields cmd=="" is zero executors at all.
	const noWinExecAbilityJSON = `{"ability_id":"nowin","name":"no executors","technique_id":"T1083",
	  "executors":[]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/abilities/ok1":
			fmt.Fprintf(w, okAbilityJSON, "ok1", "safe recon 1")
		case "/api/v2/abilities/ok2":
			fmt.Fprintf(w, okAbilityJSON, "ok2", "safe recon 2")
		case "/api/v2/abilities/nowin":
			fmt.Fprint(w, noWinExecAbilityJSON)
		default:
			http.NotFound(w, r) // "missing" / "notfound2" — not in this Caldera instance
		}
	}))
	defer srv.Close()

	steps, skipped, err := buildCalderaAbilitiesSteps(
		[]string{"ok1", "ok2", "nowin", "missing", "notfound2"}, srv.URL, "")
	if err != nil {
		t.Fatalf("buildCalderaAbilitiesSteps: %v", err)
	}
	if len(steps) != 2 {
		t.Fatalf("expected 2 dispatched steps, got %d: %+v", len(steps), steps)
	}
	if len(skipped) != 3 {
		t.Fatalf("expected 3 skipped abilities, got %d: %+v", len(skipped), skipped)
	}

	byID := map[string]CalderaSkippedAbility{}
	for _, sk := range skipped {
		byID[sk.AbilityID] = sk
	}
	if sk, ok := byID["nowin"]; !ok || sk.Reason != "no Windows-compatible executor" || sk.Name != "no executors" {
		t.Errorf("nowin skip = %+v, want reason 'no Windows-compatible executor' with Name populated", sk)
	}
	if sk, ok := byID["missing"]; !ok || sk.Reason != "not found in Caldera library" {
		t.Errorf("missing skip = %+v, want reason 'not found in Caldera library'", sk)
	}
	if sk, ok := byID["notfound2"]; !ok || sk.Reason != "not found in Caldera library" {
		t.Errorf("notfound2 skip = %+v, want reason 'not found in Caldera library'", sk)
	}
}

// TestBuildCalderaAbilitiesSteps_AllSkippedStillErrors proves the existing
// hard-fail behavior survives: if every configured id is skipped, callers
// still get an error (nothing to dispatch), not a silent empty success.
func TestBuildCalderaAbilitiesSteps_AllSkippedStillErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	steps, skipped, err := buildCalderaAbilitiesSteps([]string{"a", "b"}, srv.URL, "")
	if err == nil {
		t.Fatal("expected an error when every configured ability id is skipped")
	}
	if len(steps) != 0 {
		t.Errorf("expected no steps, got %d", len(steps))
	}
	if len(skipped) != 2 {
		t.Errorf("expected both ids reported as skipped even on the error path, got %d: %+v", len(skipped), skipped)
	}
}
