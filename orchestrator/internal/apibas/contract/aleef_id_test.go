package contract

import (
	"strings"
	"testing"
)

func aleefScenario(id, category string) Scenario {
	step := func(id, role string) Step {
		return Step{ID: id, Role: role, Identity: "a", Method: "GET", Path: "/p", Hypothesis: "h"}
	}
	return Scenario{
		ID: id, Name: "n", Category: category, Claim: "cross_identity", AttackObjective: "x",
		ThreatModel:     ThreatModel{Objective: "x"},
		Preconditions:   Preconditions{Fixture: "f", Object: "O"},
		Steps:           []Step{step("b", "baseline"), step("a", "attack")},
		DeniedStatuses:  []int{403},
		ExpectedControl: "x",
		GroundTruth:     GroundTruth{Adapters: []string{"state"}},
		DetectionAssert: DetectionAssertion{Status: "not_evaluated", Reason: "r"},
		SideEffectClass: "READ_ONLY",
	}
}

func TestValidateAcceptsAleefIDs(t *testing.T) {
	for _, id := range []string{"ALEEF-GEN-P-OWN-1-0123abcd", "ALEEF-GEN-P-ROLE-2-ffffffff", "ALEEF-REG-0001"} {
		if err := aleefScenario(id, "ALEEF").Validate(); err != nil {
			t.Errorf("%s: %v", id, err)
		}
	}
}

func TestValidateRejectsMalformedAleefIDs(t *testing.T) {
	for _, id := range []string{
		"ALEEF-GEN-P-OWN-1-0123ABCD", // upper-case hash
		"ALEEF-GEN-P-OWN-1-0123abc",  // short hash
		"ALEEF-GEN-p-own-1-0123abcd", // lower-case property
		"ALEEF-GEN--0123abcd",        // empty property
		"ALEEF-REG-001",              // short serial
		"ALEEF-REG-00001",            // long serial
		"ALEEF-FOO-0001",
		"ALEEF-GEN-P-OWN-1-0123abcd-x",
	} {
		err := aleefScenario(id, "ALEEF").Validate()
		if err == nil || !strings.Contains(err.Error(), "ALEEF") {
			t.Errorf("%s: want ALEEF id rejection, got %v", id, err)
		}
	}
}

func TestAleefIDRequiresAleefCategory(t *testing.T) {
	if err := aleefScenario("ALEEF-REG-0001", "AUTHZ").Validate(); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("want category mismatch, got %v", err)
	}
	if err := aleefScenario("API-BAS-AUTHZ-001", "ALEEF").Validate(); err == nil {
		t.Fatal("a catalogue id must not take category ALEEF")
	}
	if err := aleefScenario("API-BAS-AUTHZ-001", "AUTHZ").Validate(); err != nil {
		t.Fatalf("existing id shape regressed: %v", err)
	}
	if err := aleefScenario("BOGUS", "AUTHZ").Validate(); err == nil || !strings.Contains(err.Error(), "API-BAS") {
		t.Fatalf("existing rejection message changed: %v", err)
	}
}
