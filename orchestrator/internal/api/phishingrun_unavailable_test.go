package api

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishscope"
	"github.com/audspect/bas/internal/phishval"
)

// PH-ID-003 must say why it has no control result. A missing connector, a missing
// consent, and missing sign-in evidence are each reported as unavailable with the cause,
// never as a verified outcome, and never as a pass or a fail.
func phid003Env(lister DeviceCodeSignInLister) PhishingRunExecutorEnv {
	return PhishingRunExecutorEnv{IdentityScope: phishscope.Scope{Users: []string{"alice@contoso.example"}}, DeviceCodeSignIns: lister}
}

func TestPHID003_Unavailable_ReasonNamesCause(t *testing.T) {
	cases := map[string]struct {
		lister DeviceCodeSignInLister
		want   string
	}{
		"no connector configured": {nil, "not configured"},
		"graph consent missing":   {fakeDeviceCodeSignIns{err: errors.New("graph 403 Forbidden: insufficient privileges")}, "403"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			outcome, err := executePHID003(context.Background(), phid003Env(c.lister), "run-1", map[string]any{"userIds": []any{"alice@contoso.example"}})
			if err != nil {
				t.Fatalf("executePHID003: %v", err)
			}
			if outcome.Enforcement.Verdict == phishval.VerdictPass || outcome.Enforcement.Verdict == phishval.VerdictFail {
				t.Errorf("Enforcement.Verdict = %q, must not be a control outcome", outcome.Enforcement.Verdict)
			}
			if !strings.Contains(outcome.Enforcement.Reason, c.want) {
				t.Errorf("Enforcement.Reason = %q, want it to name the cause (%q)", outcome.Enforcement.Reason, c.want)
			}
		})
	}
}

// Unknown sign-in evidence (the window had no complete CA data) is Inconclusive, with the
// reason kept. It is never reported as a control outcome.
func TestPHID003_UnknownEvidence_InconclusiveWithReason(t *testing.T) {
	ev := phishidentity.SignInEvent{ID: "s1", AuthenticationProtocol: "deviceCode", ConditionalAccessEvidence: false}
	outcome, err := executePHID003(context.Background(), phid003Env(fakeDeviceCodeSignIns{events: []phishidentity.SignInEvent{ev}}), "run-1", map[string]any{"userIds": []any{"alice@contoso.example"}})
	if err != nil {
		t.Fatalf("executePHID003: %v", err)
	}
	if outcome.Enforcement.Verdict != phishval.VerdictInconclusive {
		t.Errorf("Enforcement.Verdict = %q, want inconclusive", outcome.Enforcement.Verdict)
	}
	if outcome.Enforcement.Reason == "" {
		t.Errorf("inconclusive result carries no reason")
	}
}

// PH-ID-002 states the same causes: no connector, or a failed consent read (such as a
// missing Directory.Read.All grant). Neither is a control outcome.
func TestPHID002_Unavailable_ReasonNamesCause(t *testing.T) {
	scope := phishscope.Scope{ClientIDs: []string{"11111111-2222-3333-4444-555555555555"}}
	params := map[string]any{"clientIds": []any{"11111111-2222-3333-4444-555555555555"}}
	cases := map[string]struct {
		lister OAuthConsentGrantLister
		want   string
	}{
		"no connector configured": {nil, "not configured"},
		"consent read refused":    {fakeOAuthConsentLister{err: errors.New("graph 403 Forbidden: Directory.Read.All not granted")}, "403"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			env := PhishingRunExecutorEnv{IdentityScope: scope, OAuthConsentLister: c.lister}
			outcome, err := executePHID002(context.Background(), env, "run-1", params)
			if err != nil {
				t.Fatalf("executePHID002: %v", err)
			}
			if outcome.Enforcement.Verdict == phishval.VerdictPass || outcome.Enforcement.Verdict == phishval.VerdictFail ||
				outcome.Response.Verdict == phishval.VerdictPass || outcome.Response.Verdict == phishval.VerdictFail {
				t.Errorf("a missing read produced a control outcome")
			}
			reasons := outcome.Enforcement.Reason + " " + outcome.Response.Reason + " " + outcome.Detection.Reason
			if !strings.Contains(reasons, c.want) {
				t.Errorf("reasons %q do not name the cause (%q)", reasons, c.want)
			}
		})
	}
}

// PH-ID-004 and PH-ID-005 state the cause of a missing read the same way. Nothing is
// graded from a missing read, and each dimension names what is missing.
func TestIdentityExperimental_Unavailable_ReasonNamesCause(t *testing.T) {
	scope := phishscope.Scope{Users: []string{"user-1"}}
	cases := []struct {
		id     string
		params map[string]any
		env    PhishingRunExecutorEnv
		want   string
	}{
		{"PH-ID-004", map[string]any{"userId": "user-1", "threshold": 5, "windowSeconds": 600},
			PhishingRunExecutorEnv{IdentityScope: scope}, "not configured"},
		{"PH-ID-004", map[string]any{"userId": "user-1", "threshold": 5, "windowSeconds": 600},
			PhishingRunExecutorEnv{IdentityScope: scope, IdentityReader: fakeIdentityReader{err: errors.New("graph 403 Forbidden")}}, "403"},
		{"PH-ID-005", map[string]any{"userId": "user-1", "windowSeconds": 600},
			PhishingRunExecutorEnv{IdentityScope: scope}, "not configured"},
		{"PH-ID-005", map[string]any{"userId": "user-1", "windowSeconds": 600},
			PhishingRunExecutorEnv{IdentityScope: scope, IdentityReader: fakeIdentityReader{err: errors.New("graph 403 Forbidden")}}, "403"},
	}
	for _, c := range cases {
		t.Run(c.id+"/"+c.want, func(t *testing.T) {
			exec, ok := LookupPhishingRunExecutor(c.id)
			if !ok {
				t.Fatalf("%s is not registered", c.id)
			}
			outcome, err := exec(context.Background(), c.env, "run-1", c.params)
			if err != nil {
				t.Fatalf("%s: %v", c.id, err)
			}
			for name, d := range map[string]phishval.DimensionResult{
				"Delivery": outcome.Delivery, "Enforcement": outcome.Enforcement, "Detection": outcome.Detection,
				"UserInteraction": outcome.UserInteraction, "Response": outcome.Response,
			} {
				if d.Verdict == phishval.VerdictPass || d.Verdict == phishval.VerdictFail {
					t.Errorf("%s: %s = %q with no evidence read", c.id, name, d.Verdict)
				}
				if d.Verdict == phishval.VerdictNotTested && !strings.Contains(d.Reason, c.want) {
					t.Errorf("%s: %s reason %q does not name the cause (%q)", c.id, name, d.Reason, c.want)
				}
			}
		})
	}
}
