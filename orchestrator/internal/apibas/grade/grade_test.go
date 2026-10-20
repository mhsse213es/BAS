package grade

import "testing"

func TestAssess_Rules(t *testing.T) {
	ok := Exchange{Status: 200}
	cases := []struct {
		name        string
		ev          Evidence
		wantResult  Result
		wantReason  string
		wantExploit Exploitability
		wantControl Control
	}{
		{
			name:       "transport failure is ERROR, never a block",
			ev:         Evidence{Transport: true},
			wantResult: ERROR, wantReason: ReasonTargetUnreachable,
			wantExploit: ExploitInconclusive, wantControl: ControlInconclusive,
		},
		{
			name:       "attack 5xx is a target fault",
			ev:         Evidence{Baseline: ok, Attack: Exchange{Status: 503}},
			wantResult: ERROR, wantReason: ReasonTargetFault,
			wantExploit: ExploitInconclusive, wantControl: ControlInconclusive,
		},
		{
			name:       "baseline not 200 is a precondition skip",
			ev:         Evidence{Baseline: Exchange{Status: 404}, Attack: Exchange{Status: 403}},
			wantResult: SKIPPED, wantReason: ReasonPreconditionMissing,
			wantExploit: ExploitNotApplicable, wantControl: ControlNotApplicable,
		},
		{
			name:        "state changed by attack is an exploit even on a 403",
			ev:          Evidence{Baseline: ok, Attack: Exchange{Status: 403}, StateChanged: true},
			wantResult:  FAIL,
			wantExploit: Exploited, wantControl: Failed,
		},
		{
			name:        "protected values disclosed is an exploit",
			ev:          Evidence{Baseline: ok, Attack: Exchange{Status: 200, LeakedProtected: 2}},
			wantResult:  FAIL,
			wantExploit: Exploited, wantControl: Failed,
		},
		{
			name:        "403 with no leak and no change is enforced",
			ev:          Evidence{Baseline: ok, Attack: Exchange{Status: 403}},
			wantResult:  PASS,
			wantExploit: NotExploited, wantControl: Enforced,
		},
		{
			name:        "404 with no leak is enforced",
			ev:          Evidence{Baseline: ok, Attack: Exchange{Status: 404}},
			wantResult:  PASS,
			wantExploit: NotExploited, wantControl: Enforced,
		},
		{
			name:       "2xx with no leak is inconclusive, not a pass",
			ev:         Evidence{Baseline: ok, Attack: Exchange{Status: 200}},
			wantResult: SKIPPED, wantReason: ReasonEvidenceInconclusive,
			wantExploit: ExploitInconclusive, wantControl: ControlInconclusive,
		},
		{
			name:       "400 is inconclusive, not a pass",
			ev:         Evidence{Baseline: ok, Attack: Exchange{Status: 400}},
			wantResult: SKIPPED, wantReason: ReasonEvidenceInconclusive,
			wantExploit: ExploitInconclusive, wantControl: ControlInconclusive,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Assess(tc.ev)
			if got.Result != tc.wantResult {
				t.Errorf("Result = %s, want %s", got.Result, tc.wantResult)
			}
			if got.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, tc.wantReason)
			}
			if got.Exploitability != tc.wantExploit {
				t.Errorf("Exploitability = %s, want %s", got.Exploitability, tc.wantExploit)
			}
			if got.Control != tc.wantControl {
				t.Errorf("Control = %s, want %s", got.Control, tc.wantControl)
			}
			if got.Detection != "not_evaluated" {
				t.Errorf("Detection = %s; Phase 1 must not claim a detection result", got.Detection)
			}
		})
	}
}

// A PASS must always carry evidence-backed confidence, and nothing that is
// inconclusive may be graded PASS or FAIL.
func TestAssess_InconclusiveNeverPassesOrFails(t *testing.T) {
	for _, status := range []int{200, 204, 400, 405, 409} {
		out := Assess(Evidence{Baseline: Exchange{Status: 200}, Attack: Exchange{Status: status}})
		if out.Result == PASS || out.Result == FAIL {
			t.Errorf("attack status %d graded %s; expected SKIPPED", status, out.Result)
		}
	}
}
