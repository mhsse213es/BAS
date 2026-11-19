package k8sscenario

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/controlval"
)

// fakeReviewer answers each review from a function, and records what it was asked.
type fakeReviewer struct {
	answer func(SARSpec) (SARResult, error)
	seen   []SARSpec
}

func (f *fakeReviewer) Review(_ context.Context, spec SARSpec) (SARResult, error) {
	f.seen = append(f.seen, spec)
	return f.answer(spec)
}

func denyAll(SARSpec) (SARResult, error) {
	return SARResult{StatusCode: 201, Denied: true, Reason: "no RBAC policy matched"}, nil
}

func TestSafeChecks_DeniedIsBlockedAndPasses(t *testing.T) {
	now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	for _, id := range []string{"impersonate-serviceaccounts", "rolebinding-create-foreign-namespace"} {
		check, ok := SafeCheckByID(id)
		if !ok {
			t.Fatalf("%s missing from the catalogue", id)
		}
		rev := &fakeReviewer{answer: denyAll}
		res := RunSafeCheck(context.Background(), rev, check, "system:serviceaccount:bas-probe:probe", "", now)
		if res.Outcome != controlval.OutcomeBlocked || res.Verdict != controlval.VerdictPass {
			t.Errorf("%s: want blocked/PASS, got %s/%s", id, res.Outcome, res.Verdict)
		}
		if res.Profile != "safe" || res.Source != "sar" || res.Confidence != "observed" || res.Remediation == "" {
			t.Errorf("%s: evidence fields missing: %+v", id, res)
		}
		if len(res.Evidence) != len(rev.seen) || len(rev.seen) == 0 {
			t.Errorf("%s: every review must be recorded as evidence", id)
		}
	}
}

func TestSafeChecks_AnyAllowedIsAllowedAndFails(t *testing.T) {
	check, _ := SafeCheckByID("impersonate-serviceaccounts")
	rev := &fakeReviewer{answer: func(spec SARSpec) (SARResult, error) {
		if spec.Resource == "users" {
			return SARResult{StatusCode: 201, Allowed: true, Reason: "granted by binding x"}, nil
		}
		return SARResult{StatusCode: 201, Denied: true}, nil
	}}
	res := RunSafeCheck(context.Background(), rev, check, "system:serviceaccount:bas-probe:probe", "", time.Now())
	if res.Outcome != controlval.OutcomeAllowed || res.Verdict != controlval.VerdictFail {
		t.Errorf("one allowed review must give allowed/FAIL, got %s/%s", res.Outcome, res.Verdict)
	}
}

func TestSafeChecks_ReviewErrorIsUnknownAndError(t *testing.T) {
	check, _ := SafeCheckByID("rolebinding-create-foreign-namespace")
	rev := &fakeReviewer{answer: func(SARSpec) (SARResult, error) {
		return SARResult{StatusCode: 403}, errors.New("refused")
	}}
	res := RunSafeCheck(context.Background(), rev, check, "system:serviceaccount:bas-probe:probe", "", time.Now())
	if res.Outcome != controlval.OutcomeUnknown || res.Verdict != controlval.VerdictError || res.Error == "" {
		t.Errorf("a failed review must be unknown/ERROR, got %s/%s", res.Outcome, res.Verdict)
	}
}

func TestSafeChecks_RoleBindingDefaultsToLabEscalationNamespace(t *testing.T) {
	check, _ := SafeCheckByID("rolebinding-create-foreign-namespace")
	specs := check.Specs("u", "")
	if len(specs) != 1 || specs[0].Namespace != "lab-escalation-test" || specs[0].Verb != "create" ||
		specs[0].Resource != "rolebindings" || specs[0].Group != "rbac.authorization.k8s.io" {
		t.Errorf("unexpected S6 review: %+v", specs)
	}
	if got := check.Specs("u", "other-ns")[0].Namespace; got != "other-ns" {
		t.Errorf("explicit namespace ignored: %q", got)
	}
}

func TestSafeChecks_ImpersonationCoversServiceAccountsAndUsers(t *testing.T) {
	check, _ := SafeCheckByID("impersonate-serviceaccounts")
	specs := check.Specs("u", "")
	if len(specs) != 2 || specs[0].Resource != "serviceaccounts" || specs[1].Resource != "users" {
		t.Errorf("S5 must review serviceaccounts and users: %+v", specs)
	}
	for _, s := range specs {
		if s.Verb != "impersonate" {
			t.Errorf("S5 verb must be impersonate: %+v", s)
		}
	}
}

func TestValidateSubject(t *testing.T) {
	for _, ok := range []string{"system:serviceaccount:bas-probe:probe", "alice"} {
		if err := ValidateSubject(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "   ", "has space", "a\nb", string(make([]byte, 254))} {
		if err := ValidateSubject(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSafeCheckByID_UnknownIsRefused(t *testing.T) {
	if _, ok := SafeCheckByID("delete-everything"); ok {
		t.Error("unknown check must not resolve")
	}
}
