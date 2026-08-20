package scenario

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBuildCalderaAdversarySteps_ReportsSkippedAbilities proves
// buildCalderaAdversarySteps has the same "declared vs found" visibility
// buildCalderaAbilitiesSteps already has: an adversary's atomic_ordering
// entry that fails to resolve, or resolves with no Windows-compatible
// executor, must be reported in the skipped list instead of silently
// dropped from the run.
func TestBuildCalderaAdversarySteps_ReportsSkippedAbilities(t *testing.T) {
	const okAbilityJSON = `{"ability_id":"%s","name":"%s","technique_id":"T1082","tactic":"discovery",
	  "executors":[{"platform":"windows","name":"psh","command":"systeminfo"}]}`
	const noWinExecAbilityJSON = `{"ability_id":"nowin","name":"no executors","technique_id":"T1083",
	  "executors":[]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/adversaries/adv1":
			fmt.Fprint(w, `{"adversary_id":"adv1","name":"test adversary","atomic_ordering":["ok1","nowin","missing"]}`)
		case "/api/v2/abilities/ok1":
			fmt.Fprintf(w, okAbilityJSON, "ok1", "safe recon")
		case "/api/v2/abilities/nowin":
			fmt.Fprint(w, noWinExecAbilityJSON)
		default:
			http.NotFound(w, r) // "missing" — not in this Caldera instance
		}
	}))
	defer srv.Close()

	steps, skipped, err := buildCalderaAdversarySteps("adv1", srv.URL, "")
	if err != nil {
		t.Fatalf("buildCalderaAdversarySteps: %v", err)
	}
	if len(steps) != 1 {
		t.Fatalf("expected 1 dispatched step, got %d: %+v", len(steps), steps)
	}
	if len(skipped) != 2 {
		t.Fatalf("expected 2 skipped abilities, got %d: %+v", len(skipped), skipped)
	}
	byID := map[string]CalderaSkippedAbility{}
	for _, sk := range skipped {
		byID[sk.AbilityID] = sk
		if sk.Framework != "caldera" {
			t.Errorf("%s Framework = %q, want \"caldera\"", sk.AbilityID, sk.Framework)
		}
	}
	if sk, ok := byID["nowin"]; !ok || sk.Reason != "no Windows-compatible executor" {
		t.Errorf("nowin skip = %+v, want reason 'no Windows-compatible executor'", sk)
	}
	if sk, ok := byID["missing"]; !ok || sk.Reason != "not found in Caldera library" {
		t.Errorf("missing skip = %+v, want reason 'not found in Caldera library'", sk)
	}
}

// TestBuildCalderaAdversarySteps_AllSkippedStillErrors mirrors the same
// hard-fail-on-total-loss precedent as caldera_abilities and art_techniques.
func TestBuildCalderaAdversarySteps_AllSkippedStillErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v2/adversaries/adv1" {
			fmt.Fprint(w, `{"adversary_id":"adv1","name":"test adversary","atomic_ordering":["missing1","missing2"]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	steps, skipped, err := buildCalderaAdversarySteps("adv1", srv.URL, "")
	if err == nil {
		t.Fatal("expected an error when every ability in the adversary is skipped")
	}
	if len(steps) != 0 {
		t.Errorf("expected no steps, got %d", len(steps))
	}
	if len(skipped) != 2 {
		t.Errorf("expected both abilities reported as skipped even on the error path, got %d: %+v", len(skipped), skipped)
	}
}
