package grade

import "testing"

var defaultDenied = []int{401, 403, 404}

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
			ev:         Evidence{Transport: true, Denied: defaultDenied},
			wantResult: ERROR, wantReason: ReasonTargetUnreachable,
			wantExploit: ExploitInconclusive, wantControl: ControlInconclusive,
		},
		{
			name:       "attack 5xx is a target fault",
			ev:         Evidence{Baseline: ok, Attack: Exchange{Status: 503}, Denied: defaultDenied},
			wantResult: ERROR, wantReason: ReasonTargetFault,
			wantExploit: ExploitInconclusive, wantControl: ControlInconclusive,
		},
		{
			name:       "baseline not 200 is a precondition skip",
			ev:         Evidence{Baseline: Exchange{Status: 404}, Attack: Exchange{Status: 403}, Denied: defaultDenied},
			wantResult: SKIPPED, wantReason: ReasonPreconditionMissing,
			wantExploit: ExploitNotApplicable, wantControl: ControlNotApplicable,
		},
		{
			name:        "state changed by attack is an exploit even on a 403",
			ev:          Evidence{Baseline: ok, Attack: Exchange{Status: 403}, StateChanged: true, Denied: defaultDenied},
			wantResult:  FAIL,
			wantExploit: Exploited, wantControl: Failed,
		},
		{
			name:        "protected values disclosed is an exploit",
			ev:          Evidence{Baseline: ok, Attack: Exchange{Status: 200, LeakedProtected: 2}, Denied: defaultDenied},
			wantResult:  FAIL,
			wantExploit: Exploited, wantControl: Failed,
		},
		{
			name:        "403 with no leak and no change is enforced",
			ev:          Evidence{Baseline: ok, Attack: Exchange{Status: 403}, Denied: defaultDenied},
			wantResult:  PASS,
			wantExploit: NotExploited, wantControl: Enforced,
		},
		{
			name:        "404 with no leak is enforced",
			ev:          Evidence{Baseline: ok, Attack: Exchange{Status: 404}, Denied: defaultDenied},
			wantResult:  PASS,
			wantExploit: NotExploited, wantControl: Enforced,
		},
		{
			name:        "400 counts as enforced only when the scenario declares it",
			ev:          Evidence{Baseline: ok, Attack: Exchange{Status: 400}, Denied: []int{400, 403}},
			wantResult:  PASS,
			wantExploit: NotExploited, wantControl: Enforced,
		},
		{
			name:       "400 is inconclusive when the scenario does not declare it",
			ev:         Evidence{Baseline: ok, Attack: Exchange{Status: 400}, Denied: defaultDenied},
			wantResult: SKIPPED, wantReason: ReasonEvidenceInconclusive,
			wantExploit: ExploitInconclusive, wantControl: ControlInconclusive,
		},
		{
			name:       "2xx with no leak is inconclusive, not a pass",
			ev:         Evidence{Baseline: ok, Attack: Exchange{Status: 200}, Denied: defaultDenied},
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
				t.Errorf("Detection = %s; no detection claim may be made yet", got.Detection)
			}
		})
	}
}

// Nothing inconclusive may grade PASS or FAIL.
func TestAssess_InconclusiveNeverPassesOrFails(t *testing.T) {
	for _, status := range []int{200, 204, 405, 409} {
		out := Assess(Evidence{Baseline: Exchange{Status: 200}, Attack: Exchange{Status: status}, Denied: defaultDenied})
		if out.Result == PASS || out.Result == FAIL {
			t.Errorf("attack status %d graded %s; expected SKIPPED", status, out.Result)
		}
	}
}

// A projection control: a 2xx with no leak is enforcement only when the
// scenario declares it. Without the declaration the same evidence is
// inconclusive.
func TestAssess_CleanIsEnforcement(t *testing.T) {
	ev := Evidence{Baseline: Exchange{Status: 200}, Attack: Exchange{Status: 200}, Denied: defaultDenied}
	if out := Assess(ev); out.Result != SKIPPED {
		t.Errorf("without declaration: Result = %s, want SKIPPED", out.Result)
	}
	ev.CleanIsEnforcement = true
	if out := Assess(ev); out.Result != PASS || out.Control != Enforced {
		t.Errorf("with declaration: Result = %s control %s, want PASS enforced", out.Result, out.Control)
	}
	// A leak must still FAIL even when the scenario declares a clean projection.
	ev.Attack.LeakedProtected = 1
	if out := Assess(ev); out.Result != FAIL {
		t.Errorf("leak with declaration: Result = %s, want FAIL", out.Result)
	}
	// A state change must still FAIL too.
	ev.Attack.LeakedProtected = 0
	ev.StateChanged = true
	if out := Assess(ev); out.Result != FAIL {
		t.Errorf("state change with declaration: Result = %s, want FAIL", out.Result)
	}
}
