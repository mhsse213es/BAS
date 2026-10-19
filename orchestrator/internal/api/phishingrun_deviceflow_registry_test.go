package api

import (
	"context"
	"errors"
	"testing"

	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishscope"
	"github.com/audspect/bas/internal/phishval"
)

type fakeDeviceCodeSignIns struct {
	events []phishidentity.SignInEvent
	err    error
}

func (f fakeDeviceCodeSignIns) SignInsByAuthenticationProtocol(context.Context, string) ([]phishidentity.SignInEvent, error) {
	return f.events, f.err
}

func deviceCodeSignIn(result string) phishidentity.SignInEvent {
	return phishidentity.SignInEvent{
		ID: "s1", AuthenticationProtocol: "deviceCode", ConditionalAccessEvidence: true,
		AppliedConditionalAccessPolicies: []phishidentity.AppliedConditionalAccessPolicy{
			{DisplayName: "Block device code", Result: result},
		},
	}
}

func TestLookupPhishingRunExecutor_PHID003Registered(t *testing.T) {
	if _, ok := LookupPhishingRunExecutor("PH-ID-003"); !ok {
		t.Fatal("PH-ID-003 must be registered as executable")
	}
}

func TestExecutePHID003_PolicyFailureObserved_Pass(t *testing.T) {
	env := PhishingRunExecutorEnv{IdentityScope: phishscope.Scope{Users: []string{"alice@contoso.example"}}, DeviceCodeSignIns: fakeDeviceCodeSignIns{events: []phishidentity.SignInEvent{deviceCodeSignIn("failure")}}}
	outcome, err := executePHID003(context.Background(), env, "run-1", map[string]any{"userIds": []any{"alice@contoso.example"}})
	if err != nil {
		t.Fatalf("executePHID003: %v", err)
	}
	if outcome.Enforcement.Verdict != phishval.VerdictPass {
		t.Errorf("Enforcement.Verdict = %q, want %q (an observed failure on a deviceCode sign-in is a block)", outcome.Enforcement.Verdict, phishval.VerdictPass)
	}
}

func TestExecutePHID003_DeviceCodeAllowed_Fail(t *testing.T) {
	env := PhishingRunExecutorEnv{IdentityScope: phishscope.Scope{Users: []string{"alice@contoso.example"}}, DeviceCodeSignIns: fakeDeviceCodeSignIns{events: []phishidentity.SignInEvent{deviceCodeSignIn("success")}}}
	outcome, err := executePHID003(context.Background(), env, "run-1", map[string]any{"userIds": []any{"alice@contoso.example"}})
	if err != nil {
		t.Fatalf("executePHID003: %v", err)
	}
	if outcome.Enforcement.Verdict != phishval.VerdictFail {
		t.Errorf("Enforcement.Verdict = %q, want %q (an observed deviceCode sign-in that no policy blocked must not pass)", outcome.Enforcement.Verdict, phishval.VerdictFail)
	}
}

func TestExecutePHID003_NilLister_NotTestedNeverPanics(t *testing.T) {
	outcome, err := executePHID003(context.Background(), PhishingRunExecutorEnv{IdentityScope: phishscope.Scope{Users: []string{"alice@contoso.example"}}}, "run-1", map[string]any{"userIds": []any{"alice@contoso.example"}})
	if err != nil {
		t.Fatalf("executePHID003: %v", err)
	}
	if outcome.Enforcement.Verdict != phishval.VerdictNotTested {
		t.Errorf("Enforcement.Verdict = %q, want %q (no configured identity connector must never fabricate a verdict)", outcome.Enforcement.Verdict, phishval.VerdictNotTested)
	}
}

func TestExecutePHID003_SignInReadError_NotTestedNeverPass(t *testing.T) {
	env := PhishingRunExecutorEnv{IdentityScope: phishscope.Scope{Users: []string{"alice@contoso.example"}}, DeviceCodeSignIns: fakeDeviceCodeSignIns{err: errors.New("graph 403")}}
	outcome, err := executePHID003(context.Background(), env, "run-1", map[string]any{"userIds": []any{"alice@contoso.example"}})
	if err != nil {
		t.Fatalf("executePHID003: %v", err)
	}
	if outcome.Enforcement.Verdict != phishval.VerdictNotTested {
		t.Errorf("Enforcement.Verdict = %q, want %q (a failed Graph read is not evidence of either outcome)", outcome.Enforcement.Verdict, phishval.VerdictNotTested)
	}
}

// SignInsForUsersByProtocol returns the same fixture events. Scope filtering is
// asserted at the phishidentity layer, against the actual query.
func (f fakeDeviceCodeSignIns) SignInsForUsersByProtocol(context.Context, string, []string) ([]phishidentity.SignInEvent, error) {
	return f.events, f.err
}
