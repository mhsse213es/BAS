package webgwefficacy

import (
	"errors"
	"testing"
	"time"
)

type erroringPolicyConfigProvider struct {
	err     error
	records []PolicyConfigEvidence
}

func (p erroringPolicyConfigProvider) PolicyConfigEvidenceFor(policyRuleID string, window TimeWindow) ([]PolicyConfigEvidence, error) {
	return p.records, p.err
}

func TestFixturePolicyConfigProvider_FiltersByRuleAndWindow(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixturePolicyConfigProvider([]PolicyConfigEvidence{
		{PolicyRuleID: "block-malware-category", ObservedConfigHash: "abc123", Timestamp: now, Source: SourceFixture},
		{PolicyRuleID: "other-rule", ObservedConfigHash: "zzz999", Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.PolicyConfigEvidenceFor("block-malware-category", TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("PolicyConfigEvidenceFor: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v, want exactly one matching record", got)
	}
}

func TestVerifyPolicyBaselineExpectation_HashMatches_Pass(t *testing.T) {
	now := time.Now()
	exp := PolicyBaselineExpectation{PolicyRuleID: "block-malware-category", ExpectedConfigHash: "abc123"}
	provider := NewFixturePolicyConfigProvider([]PolicyConfigEvidence{
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: "abc123", StillActive: true, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyPolicyBaselineExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}, now)

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q -- known-good baseline: configuration matches and the rule is active", result.Verdict, VerdictPass)
	}
}

// TestVerifyPolicyBaselineExpectation_DisabledRuleMatchingHash_Fail
// proves a disabled rule can never verdict Pass just because its
// config hash still matches -- configHashFor only hashes
// action/filters/traffic, never the enabled flag, so a rule disabled
// in the gateway's own console with everything else untouched would
// otherwise produce an identical hash and a false Pass. No exception
// is declared here: this path must be checked independently of the
// exception-expiry branch.
func TestVerifyPolicyBaselineExpectation_DisabledRuleMatchingHash_Fail(t *testing.T) {
	now := time.Now()
	exp := PolicyBaselineExpectation{PolicyRuleID: "block-malware-category", ExpectedConfigHash: "abc123"}
	provider := NewFixturePolicyConfigProvider([]PolicyConfigEvidence{
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: "abc123", StillActive: false, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyPolicyBaselineExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}, now)

	if result.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q -- a disabled rule must never Pass regardless of a matching config hash", result.Verdict, VerdictFail)
	}
}

func TestVerifyPolicyBaselineExpectation_HashMismatch_Fail(t *testing.T) {
	now := time.Now()
	exp := PolicyBaselineExpectation{PolicyRuleID: "block-malware-category", ExpectedConfigHash: "abc123"}
	provider := NewFixturePolicyConfigProvider([]PolicyConfigEvidence{
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: "drifted456", StillActive: true, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyPolicyBaselineExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}, now)

	if result.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q -- negative case: the observed configuration drifted from baseline (rule active, so this isolates the hash-mismatch path from the disabled-rule one)", result.Verdict, VerdictFail)
	}
}

// TestVerifyPolicyBaselineExpectation_ExpiredExceptionStillActive_Fail
// is Phase 3's required policy-drift exit-criterion scenario: a
// temporary exception past its own declared expiry, but still live
// in the gateway's configuration.
func TestVerifyPolicyBaselineExpectation_ExpiredExceptionStillActive_Fail(t *testing.T) {
	now := time.Now()
	expiredAt := now.Add(-24 * time.Hour)
	exp := PolicyBaselineExpectation{PolicyRuleID: "temp-exception-vendor-x", ExpectedConfigHash: "abc123", ExceptionExpiresAt: &expiredAt}
	provider := NewFixturePolicyConfigProvider([]PolicyConfigEvidence{
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: "abc123", StillActive: true, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyPolicyBaselineExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}, now)

	if result.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q -- an expired exception still active in the gateway is configuration drift, even though the config hash matches", result.Verdict, VerdictFail)
	}
}

// TestVerifyPolicyBaselineExpectation_UnexpiredExceptionStillActive_Pass
// confirms the drift check only fires after expiry -- an exception
// that is still within its declared window being active is correct
// behavior, not drift.
func TestVerifyPolicyBaselineExpectation_UnexpiredExceptionStillActive_Pass(t *testing.T) {
	now := time.Now()
	notYetExpired := now.Add(24 * time.Hour)
	exp := PolicyBaselineExpectation{PolicyRuleID: "temp-exception-vendor-x", ExpectedConfigHash: "abc123", ExceptionExpiresAt: &notYetExpired}
	provider := NewFixturePolicyConfigProvider([]PolicyConfigEvidence{
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: "abc123", StillActive: true, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyPolicyBaselineExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}, now)

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q -- the exception has not expired yet, so it being active is correct, not drift", result.Verdict, VerdictPass)
	}
}

func TestVerifyPolicyBaselineExpectation_NoEvidence_Inconclusive(t *testing.T) {
	exp := PolicyBaselineExpectation{PolicyRuleID: "block-malware-category", ExpectedConfigHash: "abc123"}
	provider := NewFixturePolicyConfigProvider(nil)
	now := time.Now()
	result := VerifyPolicyBaselineExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}, now)

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyPolicyBaselineExpectation_ProviderError_Inconclusive(t *testing.T) {
	exp := PolicyBaselineExpectation{PolicyRuleID: "block-malware-category", ExpectedConfigHash: "abc123"}
	provider := erroringPolicyConfigProvider{err: errors.New("configuration API unreachable")}
	result := VerifyPolicyBaselineExpectation(exp, provider, TimeWindow{}, time.Now())

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyPolicyBaselineExpectation_ProviderErrorWithRecords_RecordsIgnored(t *testing.T) {
	exp := PolicyBaselineExpectation{PolicyRuleID: "block-malware-category", ExpectedConfigHash: "abc123"}
	provider := erroringPolicyConfigProvider{
		err:     errors.New("configuration API unreachable"),
		records: []PolicyConfigEvidence{{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: "abc123", Timestamp: time.Now()}},
	}
	result := VerifyPolicyBaselineExpectation(exp, provider, TimeWindow{}, time.Now())

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- a provider error must be checked before its records are ever inspected", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyPolicyBaselineExpectation_MultipleRecords_MostRecentWins(t *testing.T) {
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	exp := PolicyBaselineExpectation{PolicyRuleID: "block-malware-category", ExpectedConfigHash: "abc123"}
	provider := NewFixturePolicyConfigProvider([]PolicyConfigEvidence{
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: "drifted456", StillActive: true, Timestamp: older, Source: SourceFixture},
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: "abc123", StillActive: true, Timestamp: newer, Source: SourceFixture},
	})
	result := VerifyPolicyBaselineExpectation(exp, provider, TimeWindow{Start: older.Add(-time.Minute), End: newer.Add(time.Minute)}, newer)

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q -- the most recent record (matching hash) must win over the stale earlier one (drifted)", result.Verdict, VerdictPass)
	}
}
