package latmove

import (
	"context"
	"errors"
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func TestFakeAccessConditionSource_ReturnsCannedCondition(t *testing.T) {
	tech := WMIRemoteProcessCreation()
	f := &FakeAccessConditionSource{Conditions: map[string]AccessCondition{
		"attacker/ws02/" + tech.ID: AccessGranted,
	}}
	got, err := f.Discover(context.Background(), tech, "attacker", "ws02")
	if err != nil {
		t.Fatal(err)
	}
	if got != AccessGranted {
		t.Fatalf("condition = %q, want granted", got)
	}
}

func TestFakeAccessConditionSource_UncapturedPrincipalIsUnknown(t *testing.T) {
	tech := WMIRemoteProcessCreation()
	f := &FakeAccessConditionSource{Conditions: map[string]AccessCondition{
		"attacker/ws02/" + tech.ID: AccessGranted,
	}}
	got, err := f.Discover(context.Background(), tech, "someone-else", "ws02")
	if err != nil {
		t.Fatal(err)
	}
	if got != AccessUnknown {
		t.Fatalf("condition = %q, want unknown (never guessed from another principal's data)", got)
	}
}

func TestFakeAccessConditionSource_ConfiguredErrorPropagates(t *testing.T) {
	tech := WMIRemoteProcessCreation()
	f := &FakeAccessConditionSource{Err: map[string]error{"boom/ws02/" + tech.ID: errors.New("ldap down")}}
	if _, err := f.Discover(context.Background(), tech, "boom", "ws02"); err == nil {
		t.Fatal("expected the configured error to propagate")
	}
}

func TestExpectationFromDiscovery_GrantedYieldsPositive(t *testing.T) {
	tech := WMIRemoteProcessCreation()
	exp, ok := ExpectationFromDiscovery(AccessGranted, tech)
	if !ok {
		t.Fatal("granted must yield a usable expectation")
	}
	if exp.Expected != controlval.OutcomeAllowed {
		t.Fatalf("expected = %q, want allowed", exp.Expected)
	}
}

func TestExpectationFromDiscovery_DeniedYieldsNegative(t *testing.T) {
	tech := WMIRemoteProcessCreation()
	exp, ok := ExpectationFromDiscovery(AccessDenied, tech)
	if !ok {
		t.Fatal("denied must yield a usable expectation")
	}
	if exp.Expected != controlval.OutcomeBlocked {
		t.Fatalf("expected = %q, want blocked", exp.Expected)
	}
}

func TestExpectationFromDiscovery_UnknownYieldsNoExpectation(t *testing.T) {
	// Discovery independence: an inconclusive discovery must never be guessed
	// into either expectation -- the caller must not evaluate this attempt.
	tech := WMIRemoteProcessCreation()
	if _, ok := ExpectationFromDiscovery(AccessUnknown, tech); ok {
		t.Fatal("unknown access condition must not yield a usable expectation")
	}
}
