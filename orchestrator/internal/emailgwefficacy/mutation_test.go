package emailgwefficacy

import "testing"

func fixedVerdict(v EmailGWVerdict) func() VerdictDetail {
	return func() VerdictDetail { return VerdictDetail{Verdict: v} }
}

func TestRunMutationTest_ConfirmedSuccessBaselineFlipsToFailureThenRestored_CaughtAndRecovered(t *testing.T) {
	result := RunMutationTest("spf-alignment-policy",
		fixedVerdict(VerdictConfirmedSuccess),
		fixedVerdict(VerdictConfirmedFailure),
		fixedVerdict(VerdictConfirmedSuccess),
	)

	if !result.CaughtRegression {
		t.Error("CaughtRegression = false, want true -- the weakened SPF-alignment policy must be caught")
	}
	if !result.RecoveryConfirmed {
		t.Error("RecoveryConfirmed = false, want true -- reverting the policy must restore the original ConfirmedSuccess verdict")
	}
}

func TestRunMutationTest_BaselineNeverSucceeded_NotCaughtRegression(t *testing.T) {
	result := RunMutationTest("already-broken-scenario",
		fixedVerdict(VerdictInconclusive),
		fixedVerdict(VerdictConfirmedFailure),
		fixedVerdict(VerdictInconclusive),
	)

	if result.CaughtRegression {
		t.Error("CaughtRegression = true, want false -- there was no succeeding baseline to regress from")
	}
}

func TestRunMutationTest_MutationDidNotFlipVerdict_NotCaught(t *testing.T) {
	result := RunMutationTest("policy-unaffected-by-mutation",
		fixedVerdict(VerdictConfirmedSuccess),
		fixedVerdict(VerdictConfirmedSuccess),
		fixedVerdict(VerdictConfirmedSuccess),
	)

	if result.CaughtRegression {
		t.Error("CaughtRegression = true, want false -- the mutated run still succeeded, so no regression was introduced to catch")
	}
}

func TestRunMutationTest_RestoredStillBroken_RecoveryNotConfirmed(t *testing.T) {
	result := RunMutationTest("fix-did-not-take",
		fixedVerdict(VerdictConfirmedSuccess),
		fixedVerdict(VerdictConfirmedFailure),
		fixedVerdict(VerdictConfirmedFailure),
	)

	if result.RecoveryConfirmed {
		t.Error("RecoveryConfirmed = true, want false -- the restored run is still ConfirmedFailure, not back to the original ConfirmedSuccess baseline")
	}
}

func TestMutationResult_Proven_RequiresBothCaughtAndRecovered(t *testing.T) {
	cases := []struct {
		name              string
		caughtRegression  bool
		recoveryConfirmed bool
		wantProven        bool
	}{
		{"both true", true, true, true},
		{"caught only", true, false, false},
		{"recovered only", false, true, false},
		{"neither", false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := MutationResult{CaughtRegression: c.caughtRegression, RecoveryConfirmed: c.recoveryConfirmed}
			if got := result.Proven(); got != c.wantProven {
				t.Errorf("Proven() = %v, want %v -- a half-proof (only one of catch/recovery true) must never report as fully proven", got, c.wantProven)
			}
		})
	}
}

func TestRunMutationTest_NegativeBaselineFailure_RecoveryConfirmedAgainstFailureBaseline(t *testing.T) {
	result := RunMutationTest("negative-case-scenario",
		fixedVerdict(VerdictConfirmedFailure),
		fixedVerdict(VerdictInconclusive),
		fixedVerdict(VerdictConfirmedFailure),
	)

	if result.CaughtRegression {
		t.Error("CaughtRegression = true, want false -- the baseline was never ConfirmedSuccess, so this can never be a caught regression")
	}
	if !result.RecoveryConfirmed {
		t.Error("RecoveryConfirmed = false, want true -- restoring to the same ConfirmedFailure the scenario correctly started at is a confirmed recovery, not forced through a ConfirmedSuccess-only lens")
	}
}
