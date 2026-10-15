package webgwefficacy

import "testing"

func fixedVerdict(v WebGWVerdict) func() VerdictDetail {
	return func() VerdictDetail { return VerdictDetail{Verdict: v} }
}

func TestRunMutationTest_PassBaselineFlipsToFailThenRestored_CaughtAndRecovered(t *testing.T) {
	result := RunMutationTest("malware-category-block-policy",
		fixedVerdict(VerdictPass),
		fixedVerdict(VerdictFail),
		fixedVerdict(VerdictPass),
	)

	if !result.CaughtRegression {
		t.Error("CaughtRegression = false, want true -- a Pass baseline that flipped to Fail is exactly a caught regression")
	}
	if !result.RecoveryConfirmed {
		t.Error("RecoveryConfirmed = false, want true -- restoring to the original Pass baseline is a confirmed recovery")
	}
}

func TestRunMutationTest_BaselineNeverPassed_NotCaughtRegression(t *testing.T) {
	result := RunMutationTest("already-broken-scenario",
		fixedVerdict(VerdictInconclusive),
		fixedVerdict(VerdictFail),
		fixedVerdict(VerdictInconclusive),
	)

	if result.CaughtRegression {
		t.Error("CaughtRegression = true, want false -- there was no passing baseline to regress from")
	}
}

func TestRunMutationTest_MutationDidNotFlipVerdict_NotCaught(t *testing.T) {
	result := RunMutationTest("policy-unaffected-by-mutation",
		fixedVerdict(VerdictPass),
		fixedVerdict(VerdictPass),
		fixedVerdict(VerdictPass),
	)

	if result.CaughtRegression {
		t.Error("CaughtRegression = true, want false -- the mutated run still passed, so no regression was introduced to catch")
	}
}

func TestRunMutationTest_RestoredStillBroken_RecoveryNotConfirmed(t *testing.T) {
	result := RunMutationTest("fix-did-not-take",
		fixedVerdict(VerdictPass),
		fixedVerdict(VerdictFail),
		fixedVerdict(VerdictFail),
	)

	if result.RecoveryConfirmed {
		t.Error("RecoveryConfirmed = true, want false -- the restored run is still Fail, not back to the original Pass baseline")
	}
}

func TestRunMutationTest_NegativeBaselineFail_RecoveryConfirmedAgainstFailBaseline(t *testing.T) {
	result := RunMutationTest("negative-case-scenario",
		fixedVerdict(VerdictFail),
		fixedVerdict(VerdictInconclusive),
		fixedVerdict(VerdictFail),
	)

	if result.CaughtRegression {
		t.Error("CaughtRegression = true, want false -- the baseline was never Pass, so this can never be a caught regression")
	}
	if !result.RecoveryConfirmed {
		t.Error("RecoveryConfirmed = false, want true -- restoring to the same Fail the scenario correctly started at is a confirmed recovery, not forced through a Pass-only lens")
	}
}
