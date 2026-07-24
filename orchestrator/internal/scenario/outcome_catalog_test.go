package scenario

import "testing"

func TestResolveOutcomeFamily(t *testing.T) {
	if got := ResolveOutcomeFamily(ExpectedDetection{}); got != "detection" {
		t.Errorf("empty OutcomeFamily: got %q want detection", got)
	}
	if got := ResolveOutcomeFamily(ExpectedDetection{OutcomeFamily: "custom"}); got != "custom" {
		t.Errorf("explicit OutcomeFamily: got %q want custom", got)
	}
}

func TestResolveExpectedOutcome(t *testing.T) {
	if got := ResolveExpectedOutcome(ExpectedDetection{}); got != "Detected" {
		t.Errorf("empty ExpectedOutcome falls back to detection family's implicit default: got %q want Detected", got)
	}
	if got := ResolveExpectedOutcome(ExpectedDetection{ExpectedOutcome: "NotDetected"}); got != "NotDetected" {
		t.Errorf("explicit ExpectedOutcome: got %q want NotDetected", got)
	}
}

func TestValidOutcome(t *testing.T) {
	if !ValidOutcome("detection", "Detected") {
		t.Error("Detected should be valid for the detection family")
	}
	if !ValidOutcome("detection", "NotDetected") {
		t.Error("NotDetected should be valid for the detection family")
	}
	if ValidOutcome("detection", "Warn") {
		t.Error("Warn should not be valid for the detection family")
	}
	if ValidOutcome("nonexistent-family", "anything") {
		t.Error("an unregistered family should never validate any value")
	}
}

func TestRegisterOutcomeCatalog(t *testing.T) {
	RegisterOutcomeCatalog(OutcomeCatalog{Family: "test-only", Values: []string{"A", "B"}, ImplicitExpected: "A"})
	if !ValidOutcome("test-only", "A") {
		t.Error("newly registered family's value should validate")
	}
	if ValidOutcome("test-only", "C") {
		t.Error("value outside the registered catalog should not validate")
	}
}

func TestFamilyKnown(t *testing.T) {
	if !familyKnown("detection") {
		t.Error("detection family should be known — it's registered by this package's own init()")
	}
	if familyKnown("nonexistent-family") {
		t.Error("an unregistered family should not be known")
	}
}

func TestDLPOutcomeCatalogRegistered(t *testing.T) {
	for _, v := range []string{"Allow", "Block", "Warn", "Justify", "Audit", "Quarantine", "Encrypt", "Redact"} {
		if !ValidOutcome("dlp", v) {
			t.Errorf("dlp catalog missing value %q", v)
		}
	}
	if ValidOutcome("dlp", "NotARealValue") {
		t.Error("dlp catalog should not validate an unregistered value")
	}
	if !familyKnown("dlp") {
		t.Error("dlp family should be known once registered")
	}
	if got := ResolveExpectedOutcome(ExpectedDetection{OutcomeFamily: "dlp"}); got != "Block" {
		t.Errorf("dlp family's implicit expected outcome: got %q want Block", got)
	}
}
