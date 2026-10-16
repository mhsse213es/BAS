package emailgwefficacy

import (
	"errors"
	"testing"
	"time"
)

// ── OAuth consent grant ──────────────────────────────────────────────

type erroringOAuthConsentGrantProvider struct {
	err error
}

func (p erroringOAuthConsentGrantProvider) OAuthConsentGrantEvidenceFor(userPrincipal string, window TimeWindow) ([]OAuthConsentGrantEvidence, error) {
	return nil, p.err
}

func TestVerifyOAuthConsentGrantExpectation_ProviderError_Inconclusive(t *testing.T) {
	exp := SuspiciousOAuthConsentGrantExpectation(true)
	result := VerifyOAuthConsentGrantExpectation(exp, erroringOAuthConsentGrantProvider{err: errors.New("audit log API unreachable")}, scenarioWindow())

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyOAuthConsentGrantExpectation_NoEvidence_Inconclusive(t *testing.T) {
	exp := SuspiciousOAuthConsentGrantExpectation(true)
	provider := NewFixtureOAuthConsentGrantProvider(nil)
	result := VerifyOAuthConsentGrantExpectation(exp, provider, scenarioWindow())

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- absence of evidence must never be read as either outcome", result.Verdict, VerdictInconclusive)
	}
}

func TestSuspiciousOAuthConsentGrantScenario_KnownGood_DetectedAsExpected(t *testing.T) {
	exp := SuspiciousOAuthConsentGrantExpectation(true)
	now := time.Now()
	provider := NewFixtureOAuthConsentGrantProvider([]OAuthConsentGrantEvidence{
		{UserPrincipal: exp.UserPrincipal, AppDisplayName: exp.AppDisplayName, GrantDetected: true, DetectionSource: "Entra ID risk detection", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyOAuthConsentGrantExpectation(exp, provider, scenarioWindow())

	if result.Verdict != VerdictConfirmedSuccess {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictConfirmedSuccess)
	}
}

func TestSuspiciousOAuthConsentGrantScenario_KnownBad_UndetectedMismatch(t *testing.T) {
	exp := SuspiciousOAuthConsentGrantExpectation(true) // expected detected, but evidence says it wasn't
	now := time.Now()
	provider := NewFixtureOAuthConsentGrantProvider([]OAuthConsentGrantEvidence{
		{UserPrincipal: exp.UserPrincipal, GrantDetected: false, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyOAuthConsentGrantExpectation(exp, provider, scenarioWindow())

	if result.Verdict != VerdictConfirmedFailure {
		t.Errorf("Verdict = %q, want %q -- the grant was created but tenant security failed to detect it", result.Verdict, VerdictConfirmedFailure)
	}
	if result.Reason == "" {
		t.Error("Reason is empty, want a stated reason since Verdict != ConfirmedSuccess")
	}
}

func TestVerifyOAuthConsentGrantExpectation_MultipleRecords_MostRecentWins(t *testing.T) {
	exp := SuspiciousOAuthConsentGrantExpectation(true)
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	provider := NewFixtureOAuthConsentGrantProvider([]OAuthConsentGrantEvidence{
		{UserPrincipal: exp.UserPrincipal, GrantDetected: false, Timestamp: older, Source: SourceFixture},
		{UserPrincipal: exp.UserPrincipal, GrantDetected: true, Timestamp: newer, Source: SourceFixture},
	})
	window := TimeWindow{Start: older.Add(-time.Minute), End: newer.Add(time.Minute)}
	result := VerifyOAuthConsentGrantExpectation(exp, provider, window)

	if result.Verdict != VerdictConfirmedSuccess {
		t.Errorf("Verdict = %q, want %q -- the most recent record (detected) must win over the stale earlier one (not detected)", result.Verdict, VerdictConfirmedSuccess)
	}
}

func TestFixtureOAuthConsentGrantProvider_FiltersByUserAndWindow(t *testing.T) {
	now := time.Now()
	provider := NewFixtureOAuthConsentGrantProvider([]OAuthConsentGrantEvidence{
		{UserPrincipal: "target@example-lab.test", GrantDetected: true, Timestamp: now},
		{UserPrincipal: "other@example-lab.test", GrantDetected: true, Timestamp: now},
		{UserPrincipal: "target@example-lab.test", GrantDetected: true, Timestamp: now.Add(-24 * time.Hour)},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	records, err := provider.OAuthConsentGrantEvidenceFor("target@example-lab.test", window)
	if err != nil {
		t.Fatalf("OAuthConsentGrantEvidenceFor: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %+v, want 1 (wrong-user and out-of-window records excluded)", records)
	}
}

func TestSuspiciousOAuthConsentGrantExpectation_NeverNamesARealDomain(t *testing.T) {
	exp := SuspiciousOAuthConsentGrantExpectation(true)
	assertSyntheticTestDomain(t, exp.UserPrincipal)
}

// ── Delegated mailbox access ─────────────────────────────────────────

type erroringDelegatedMailboxAccessProvider struct {
	err error
}

func (p erroringDelegatedMailboxAccessProvider) DelegatedMailboxAccessEvidenceFor(mailbox string, window TimeWindow) ([]DelegatedMailboxAccessEvidence, error) {
	return nil, p.err
}

func TestVerifyDelegatedMailboxAccessExpectation_ProviderError_Inconclusive(t *testing.T) {
	exp := SuspiciousDelegatedMailboxAccessExpectation(true)
	result := VerifyDelegatedMailboxAccessExpectation(exp, erroringDelegatedMailboxAccessProvider{err: errors.New("audit log API unreachable")}, scenarioWindow())

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyDelegatedMailboxAccessExpectation_NoEvidence_Inconclusive(t *testing.T) {
	exp := SuspiciousDelegatedMailboxAccessExpectation(true)
	provider := NewFixtureDelegatedMailboxAccessProvider(nil)
	result := VerifyDelegatedMailboxAccessExpectation(exp, provider, scenarioWindow())

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- absence of evidence must never be read as either outcome", result.Verdict, VerdictInconclusive)
	}
}

func TestSuspiciousDelegatedMailboxAccessScenario_KnownGood_DetectedAsExpected(t *testing.T) {
	exp := SuspiciousDelegatedMailboxAccessExpectation(true)
	now := time.Now()
	provider := NewFixtureDelegatedMailboxAccessProvider([]DelegatedMailboxAccessEvidence{
		{Mailbox: exp.Mailbox, GrantDetected: true, DetectionSource: "audit log", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyDelegatedMailboxAccessExpectation(exp, provider, scenarioWindow())

	if result.Verdict != VerdictConfirmedSuccess {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictConfirmedSuccess)
	}
}

func TestSuspiciousDelegatedMailboxAccessScenario_KnownBad_UndetectedMismatch(t *testing.T) {
	exp := SuspiciousDelegatedMailboxAccessExpectation(true)
	now := time.Now()
	provider := NewFixtureDelegatedMailboxAccessProvider([]DelegatedMailboxAccessEvidence{
		{Mailbox: exp.Mailbox, GrantDetected: false, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyDelegatedMailboxAccessExpectation(exp, provider, scenarioWindow())

	if result.Verdict != VerdictConfirmedFailure {
		t.Errorf("Verdict = %q, want %q -- the delegation was created but tenant security failed to detect it", result.Verdict, VerdictConfirmedFailure)
	}
	if result.Reason == "" {
		t.Error("Reason is empty, want a stated reason since Verdict != ConfirmedSuccess")
	}
}

func TestFixtureDelegatedMailboxAccessProvider_FiltersByMailboxAndWindow(t *testing.T) {
	now := time.Now()
	provider := NewFixtureDelegatedMailboxAccessProvider([]DelegatedMailboxAccessEvidence{
		{Mailbox: "target@example-lab.test", GrantDetected: true, Timestamp: now},
		{Mailbox: "other@example-lab.test", GrantDetected: true, Timestamp: now},
		{Mailbox: "target@example-lab.test", GrantDetected: true, Timestamp: now.Add(-24 * time.Hour)},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	records, err := provider.DelegatedMailboxAccessEvidenceFor("target@example-lab.test", window)
	if err != nil {
		t.Fatalf("DelegatedMailboxAccessEvidenceFor: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %+v, want 1 (wrong-mailbox and out-of-window records excluded)", records)
	}
}

func TestSuspiciousDelegatedMailboxAccessExpectation_NeverNamesARealDomain(t *testing.T) {
	exp := SuspiciousDelegatedMailboxAccessExpectation(true)
	assertSyntheticTestDomain(t, exp.Mailbox)
	assertSyntheticTestDomain(t, exp.DelegateIdentity)
}

// assertSyntheticTestDomain mirrors
// TestSuspiciousAutoForwardExpectation_NeverNamesARealDomain's own
// inline check, factored out since this file asserts it on several
// distinct string fields across two scenario builders.
func assertSyntheticTestDomain(t *testing.T, identity string) {
	t.Helper()
	if identity == "" {
		t.Fatal("identity is empty")
	}
	const suffix = ".test"
	if len(identity) < len(suffix) || identity[len(identity)-len(suffix):] != suffix {
		t.Errorf("identity %q is not in the synthetic .test namespace", identity)
	}
}
