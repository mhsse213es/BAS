package api

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishscope"
	"github.com/audspect/bas/internal/phishval"
)

// fakeIdentityReader stands in for the read-only Graph identity client. The
// experimental heuristics only read; the fake records no writes because none exist.
type fakeIdentityReader struct {
	mfa       []phishidentity.MFADenialEvent
	risky     []phishidentity.RiskySignInEvent
	validFrom time.Time
	err       error
}

func (f fakeIdentityReader) MFADenialEventsForUser(context.Context, string) ([]phishidentity.MFADenialEvent, error) {
	return f.mfa, f.err
}

func (f fakeIdentityReader) RiskySignInsForUser(context.Context, string) ([]phishidentity.RiskySignInEvent, error) {
	return f.risky, f.err
}

func (f fakeIdentityReader) SignInSessionsValidFromDateTime(context.Context, string) (time.Time, error) {
	return f.validFrom, f.err
}

func burstOfMFADenials(n int, at time.Time) []phishidentity.MFADenialEvent {
	out := make([]phishidentity.MFADenialEvent, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, phishidentity.MFADenialEvent{
			ID: "d", UserID: "user-1", CreatedDateTime: at.Add(time.Duration(i) * time.Second), ErrorCode: 500121,
		})
	}
	return out
}

func TestLookupPhishingRunExecutor_IdentityExperimentalRegistered(t *testing.T) {
	for _, id := range []string{"PH-ID-004", "PH-ID-005"} {
		if _, ok := LookupPhishingRunExecutor(id); !ok {
			t.Errorf("%s must be registered as executable", id)
		}
	}
}

func runIdentity(t *testing.T, id string, env PhishingRunExecutorEnv, params map[string]any) (phishval.Outcome, error) {
	t.Helper()
	exec, ok := LookupPhishingRunExecutor(id)
	if !ok {
		t.Fatalf("%s not registered", id)
	}
	return exec(context.Background(), env, "run-1", params)
}

func TestExecutePHID004_MFAFatigueSuspected_Pass(t *testing.T) {
	env := PhishingRunExecutorEnv{IdentityScope: phishscope.Scope{Users: []string{"user-1"}}, IdentityReader: fakeIdentityReader{mfa: burstOfMFADenials(5, time.Now().Add(-time.Minute))}}
	outcome, err := runIdentity(t, "PH-ID-004", env, map[string]any{"userId": "user-1", "threshold": 3, "windowSeconds": 600})
	if err != nil {
		t.Fatalf("executor: %v", err)
	}
	if outcome.Detection.Verdict != phishval.VerdictPass {
		t.Errorf("Detection.Verdict = %q, want %q for a burst of MFA denials", outcome.Detection.Verdict, phishval.VerdictPass)
	}
}

func TestExecutePHID004_MissingThreshold_Error(t *testing.T) {
	env := PhishingRunExecutorEnv{IdentityScope: phishscope.Scope{Users: []string{"user-1"}}, IdentityReader: fakeIdentityReader{}}
	if _, err := runIdentity(t, "PH-ID-004", env, map[string]any{"userId": "user-1", "windowSeconds": 600}); err == nil {
		t.Fatal("a missing threshold must be an error, never an invented default")
	}
}

func TestExecutePHID004_NilReader_NotTested(t *testing.T) {
	outcome, err := runIdentity(t, "PH-ID-004", PhishingRunExecutorEnv{IdentityScope: phishscope.Scope{Users: []string{"user-1"}}}, map[string]any{"userId": "user-1", "threshold": 3, "windowSeconds": 600})
	if err != nil {
		t.Fatalf("executor: %v", err)
	}
	if outcome.Detection.Verdict != phishval.VerdictNotTested {
		t.Errorf("Detection.Verdict = %q, want %q with no identity connector", outcome.Detection.Verdict, phishval.VerdictNotTested)
	}
}

func TestExecutePHID005_SessionsRevokedAfterRiskyEvent_Pass(t *testing.T) {
	riskyAt := time.Now().Add(-10 * time.Minute)
	env := PhishingRunExecutorEnv{IdentityScope: phishscope.Scope{Users: []string{"user-1"}}, IdentityReader: fakeIdentityReader{
		risky:     []phishidentity.RiskySignInEvent{{ID: "r1", CreatedDateTime: riskyAt, RiskState: "atRisk"}},
		validFrom: riskyAt.Add(time.Minute),
	}}
	outcome, err := runIdentity(t, "PH-ID-005", env, map[string]any{"userId": "user-1", "windowSeconds": 3600})
	if err != nil {
		t.Fatalf("executor: %v", err)
	}
	if outcome.Response.Verdict != phishval.VerdictPass {
		t.Errorf("Response.Verdict = %q, want %q when sessions were revoked after the risky sign-in", outcome.Response.Verdict, phishval.VerdictPass)
	}
}

func TestExecutePHID005_SessionsNotRevoked_Fail(t *testing.T) {
	riskyAt := time.Now().Add(-10 * time.Minute)
	env := PhishingRunExecutorEnv{IdentityScope: phishscope.Scope{Users: []string{"user-1"}}, IdentityReader: fakeIdentityReader{
		risky:     []phishidentity.RiskySignInEvent{{ID: "r1", CreatedDateTime: riskyAt, RiskState: "atRisk"}},
		validFrom: riskyAt.Add(-time.Hour),
	}}
	outcome, err := runIdentity(t, "PH-ID-005", env, map[string]any{"userId": "user-1", "windowSeconds": 3600})
	if err != nil {
		t.Fatalf("executor: %v", err)
	}
	if outcome.Response.Verdict != phishval.VerdictFail {
		t.Errorf("Response.Verdict = %q, want %q when no revocation followed the risky sign-in", outcome.Response.Verdict, phishval.VerdictFail)
	}
}

func TestExecutePHID005_NilReader_NotTested(t *testing.T) {
	outcome, err := runIdentity(t, "PH-ID-005", PhishingRunExecutorEnv{IdentityScope: phishscope.Scope{Users: []string{"user-1"}}}, map[string]any{"userId": "user-1", "windowSeconds": 3600})
	if err != nil {
		t.Fatalf("executor: %v", err)
	}
	if outcome.Response.Verdict != phishval.VerdictNotTested {
		t.Errorf("Response.Verdict = %q, want %q with no identity connector", outcome.Response.Verdict, phishval.VerdictNotTested)
	}
}
