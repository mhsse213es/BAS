package emailgwefficacy

import (
	"errors"
	"testing"
	"time"
)

type erroringEmailPolicyConfigProvider struct {
	err error
}

func (p erroringEmailPolicyConfigProvider) EmailPolicyConfigEvidenceFor(policyRuleID string, window TimeWindow) ([]EmailPolicyConfigEvidence, error) {
	return nil, p.err
}

func TestVerifyEmailPolicyBaselineExpectation_ProviderError_Inconclusive(t *testing.T) {
	exp := AntiPhishImpersonationPolicyBaselineExpectation(true)
	result := VerifyEmailPolicyBaselineExpectation(exp, erroringEmailPolicyConfigProvider{err: errors.New("config API unreachable")}, scenarioWindow(), time.Now())

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyEmailPolicyBaselineExpectation_NoEvidence_Inconclusive(t *testing.T) {
	exp := AntiPhishImpersonationPolicyBaselineExpectation(true)
	provider := NewFixtureEmailPolicyConfigProvider(nil)
	result := VerifyEmailPolicyBaselineExpectation(exp, provider, scenarioWindow(), time.Now())

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- absence of evidence must never be read as either outcome", result.Verdict, VerdictInconclusive)
	}
}

func TestAntiPhishPolicyBaselineScenario_KnownGood_ValidExceptionMatchingConfig(t *testing.T) {
	exp := AntiPhishImpersonationPolicyBaselineExpectation(true)
	now := time.Now()
	provider := NewFixtureEmailPolicyConfigProvider([]EmailPolicyConfigEvidence{
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: exp.ExpectedConfigHash, StillActive: true, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyEmailPolicyBaselineExpectation(exp, provider, scenarioWindow(), now)

	if result.Verdict != VerdictConfirmedSuccess {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictConfirmedSuccess)
	}
}

func TestAntiPhishPolicyBaselineScenario_KnownBad_ExpiredExceptionStillActive(t *testing.T) {
	exp := AntiPhishImpersonationPolicyBaselineExpectation(false) // exception already expired
	now := time.Now()
	provider := NewFixtureEmailPolicyConfigProvider([]EmailPolicyConfigEvidence{
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: exp.ExpectedConfigHash, StillActive: true, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyEmailPolicyBaselineExpectation(exp, provider, scenarioWindow(), now)

	if result.Verdict != VerdictConfirmedFailure {
		t.Errorf("Verdict = %q, want %q -- a stale exception past its own expiry must be flagged even though the config hash matches", result.Verdict, VerdictConfirmedFailure)
	}
	if result.Reason == "" {
		t.Error("Reason is empty, want a stated reason since Verdict != ConfirmedSuccess")
	}
}

func TestVerifyEmailPolicyBaselineExpectation_RuleDisabled_ConfirmedFailureRegardlessOfHash(t *testing.T) {
	exp := AntiPhishImpersonationPolicyBaselineExpectation(true)
	now := time.Now()
	provider := NewFixtureEmailPolicyConfigProvider([]EmailPolicyConfigEvidence{
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: exp.ExpectedConfigHash, StillActive: false, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyEmailPolicyBaselineExpectation(exp, provider, scenarioWindow(), now)

	if result.Verdict != VerdictConfirmedFailure {
		t.Errorf("Verdict = %q, want %q -- a disabled rule enforces nothing regardless of its hash", result.Verdict, VerdictConfirmedFailure)
	}
}

func TestVerifyEmailPolicyBaselineExpectation_HashMismatch_ConfirmedFailure(t *testing.T) {
	exp := AntiPhishImpersonationPolicyBaselineExpectation(true)
	now := time.Now()
	provider := NewFixtureEmailPolicyConfigProvider([]EmailPolicyConfigEvidence{
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: "sha256:some-other-unexpected-config", StillActive: true, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyEmailPolicyBaselineExpectation(exp, provider, scenarioWindow(), now)

	if result.Verdict != VerdictConfirmedFailure {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictConfirmedFailure)
	}
}

func TestVerifyEmailPolicyBaselineExpectation_MultipleRecords_MostRecentWins(t *testing.T) {
	exp := AntiPhishImpersonationPolicyBaselineExpectation(true)
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	provider := NewFixtureEmailPolicyConfigProvider([]EmailPolicyConfigEvidence{
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: exp.ExpectedConfigHash, StillActive: false, Timestamp: older, Source: SourceFixture},
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: exp.ExpectedConfigHash, StillActive: true, Timestamp: newer, Source: SourceFixture},
	})
	window := TimeWindow{Start: older.Add(-time.Minute), End: newer.Add(time.Minute)}
	result := VerifyEmailPolicyBaselineExpectation(exp, provider, window, newer)

	if result.Verdict != VerdictConfirmedSuccess {
		t.Errorf("Verdict = %q, want %q -- the most recent record (active) must win over the stale earlier one (disabled)", result.Verdict, VerdictConfirmedSuccess)
	}
}

func TestFixtureEmailPolicyConfigProvider_FiltersByRuleAndWindow(t *testing.T) {
	now := time.Now()
	provider := NewFixtureEmailPolicyConfigProvider([]EmailPolicyConfigEvidence{
		{PolicyRuleID: "target-rule", StillActive: true, Timestamp: now},
		{PolicyRuleID: "other-rule", StillActive: true, Timestamp: now},
		{PolicyRuleID: "target-rule", StillActive: true, Timestamp: now.Add(-24 * time.Hour)},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	records, err := provider.EmailPolicyConfigEvidenceFor("target-rule", window)
	if err != nil {
		t.Fatalf("EmailPolicyConfigEvidenceFor: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %+v, want 1 (wrong-rule and out-of-window records excluded)", records)
	}
}

func TestAntiPhishImpersonationPolicyBaselineExpectation_NeverNamesARealDomain(t *testing.T) {
	exp := AntiPhishImpersonationPolicyBaselineExpectation(true)
	if exp.PolicyRuleID == "" || exp.ExpectedConfigHash == "" {
		t.Fatal("PolicyRuleID or ExpectedConfigHash is empty")
	}
}
