package models

import "testing"

func fraud(v string) *FraudControl { return &FraudControl{Verdict: v} }

func TestEffectiveResultFoldsFraudVerdict(t *testing.T) {
	cases := []struct {
		name   string
		result CheckResult
		fc     *FraudControl
		want   CheckResult
	}{
		{"no fraud record keeps endpoint verdict", ResultPass, nil, ResultPass},
		{"endpoint pass and fraud pass stays pass", ResultPass, fraud("PASS"), ResultPass},
		{"endpoint pass and fraud fail becomes fail", ResultPass, fraud("FAIL"), ResultFail},
		{"endpoint pass and fraud skipped becomes skipped", ResultPass, fraud("SKIPPED"), ResultSkipped},
		{"endpoint fail stands even if fraud skipped", ResultFail, fraud("SKIPPED"), ResultFail},
		{"endpoint error is not overridden", ResultError, fraud("PASS"), ResultError},
		{"blocked endpoint with fraud pass stays blocked", ResultBlocked, fraud("PASS"), ResultBlocked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EffectiveResult(SimulationResult{Result: tc.result, FraudControl: tc.fc})
			if got != tc.want {
				t.Fatalf("EffectiveResult = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestComputeScoreDoesNotCountFraudFailAsPass(t *testing.T) {
	base := SimulationResult{Technique: AttackTechnique{ID: "T1078", Tactic: "Initial Access"}, Severity: "High", Result: ResultPass}
	withFraudFail := base
	withFraudFail.FraudControl = fraud("FAIL")

	s := ComputeScore([]SimulationResult{base, withFraudFail}, nil)
	if s.PassedTechniques != 1 {
		t.Fatalf("PassedTechniques = %d, want 1 (fraud FAIL must not count as passed)", s.PassedTechniques)
	}
	if s.PreventionScore != 50 {
		t.Fatalf("PreventionScore = %v, want 50", s.PreventionScore)
	}
}
