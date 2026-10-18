package dlppolicy

import (
	"strings"
	"testing"
	"time"
)

func TestFixtureDLPPolicyRuleProvider_FiltersByRuleScopeAndWindow(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	events := []DLPPolicyRuleEvidence{
		{RuleID: "lab-dlp-rule-pci-scope", ScopeID: "lab-ou-finance", Timestamp: base, Source: SourceFixture},                      // match
		{RuleID: "lab-dlp-rule-pci-scope", ScopeID: "lab-ou-hr", Timestamp: base, Source: SourceFixture},                           // wrong scope
		{RuleID: "lab-dlp-rule-other", ScopeID: "lab-ou-finance", Timestamp: base, Source: SourceFixture},                          // wrong rule
		{RuleID: "lab-dlp-rule-pci-scope", ScopeID: "lab-ou-finance", Timestamp: base.Add(-48 * time.Hour), Source: SourceFixture}, // out of window
	}
	p := NewFixtureDLPPolicyRuleProvider(events)
	window := TimeWindow{Start: base.Add(-time.Hour), End: base.Add(time.Hour)}

	got, err := p.DLPPolicyRuleEvidenceFor("lab-dlp-rule-pci-scope", "lab-ou-finance", window)
	if err != nil {
		t.Fatalf("DLPPolicyRuleEvidenceFor: %v", err)
	}
	if len(got) != 1 || !got[0].Timestamp.Equal(base) {
		t.Fatalf("got %+v, want exactly the one matching record at %v", got, base)
	}
}

func TestFixtureDLPPolicyRuleProvider_WindowBoundaryInclusive(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	events := []DLPPolicyRuleEvidence{{RuleID: "r1", ScopeID: "s1", Timestamp: base, Source: SourceFixture}}
	p := NewFixtureDLPPolicyRuleProvider(events)

	got, err := p.DLPPolicyRuleEvidenceFor("r1", "s1", TimeWindow{Start: base, End: base})
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v, err %v -- a record exactly at Start==End must still match (inclusive both ends)", got, err)
	}
}

// --- VerifyDLPPolicyRuleExpectation ---

var verifyTestBase = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
var verifyTestWindow = TimeWindow{Start: verifyTestBase.Add(-time.Hour), End: verifyTestBase.Add(time.Hour)}

// baselineExpectation returns a fully-matching DLPPolicyRuleExpectation --
// every test below starts from a copy of this and this.Evidence(), then
// deliberately breaks exactly one aspect to isolate the branch it tests.
func baselineExpectation() DLPPolicyRuleExpectation {
	return DLPPolicyRuleExpectation{
		RuleID:            "lab-dlp-rule-pci-scope",
		ScopeID:           "lab-ou-finance",
		Scope:             DLPPolicyScopeDeclaration{ExcludedUsers: []string{"lab-user-ceo"}},
		ExpectedMode:      ModeEnforce,
		ExpectedEnabled:   true,
		ExpectedPublished: true,
	}
}

func baselineEvidence() DLPPolicyRuleEvidence {
	return DLPPolicyRuleEvidence{
		RuleID:          "lab-dlp-rule-pci-scope",
		ScopeID:         "lab-ou-finance",
		ObservedScope:   DLPPolicyScopeDeclaration{ExcludedUsers: []string{"lab-user-ceo"}},
		ObservedMode:    ModeEnforce,
		Enabled:         true,
		Published:       true,
		ExceptionActive: false,
		ConfigChangedAt: verifyTestBase,
		LastSyncedAt:    verifyTestBase,
		Timestamp:       verifyTestBase,
		Source:          SourceFixture,
	}
}

func verify(exp DLPPolicyRuleExpectation, ev DLPPolicyRuleEvidence) VerdictDetail {
	provider := NewFixtureDLPPolicyRuleProvider([]DLPPolicyRuleEvidence{ev})
	return VerifyDLPPolicyRuleExpectation(exp, provider, verifyTestWindow, verifyTestBase)
}

func verifyMulti(exp DLPPolicyRuleExpectation, evs []DLPPolicyRuleEvidence) VerdictDetail {
	provider := NewFixtureDLPPolicyRuleProvider(evs)
	return VerifyDLPPolicyRuleExpectation(exp, provider, verifyTestWindow, verifyTestBase)
}

func TestVerifyDLPPolicyRuleExpectation_NoEvidence_ReturnsInconclusive(t *testing.T) {
	provider := NewFixtureDLPPolicyRuleProvider(nil)
	got := VerifyDLPPolicyRuleExpectation(baselineExpectation(), provider, verifyTestWindow, verifyTestBase)
	if got.Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictInconclusive)
	}
}

func TestVerifyDLPPolicyRuleExpectation_Disabled_ReturnsConfirmedFailure(t *testing.T) {
	ev := baselineEvidence()
	ev.Enabled = false
	got := verify(baselineExpectation(), ev)
	if got.Verdict != VerdictConfirmedFailure {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictConfirmedFailure)
	}
	if !strings.Contains(got.Reason, "disabled") {
		t.Errorf("Reason = %q, want it to mention \"disabled\"", got.Reason)
	}
}

func TestVerifyDLPPolicyRuleExpectation_NotPublished_ReturnsConfirmedFailure(t *testing.T) {
	ev := baselineEvidence()
	ev.Published = false
	got := verify(baselineExpectation(), ev)
	if got.Verdict != VerdictConfirmedFailure {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictConfirmedFailure)
	}
	if !strings.Contains(got.Reason, "published") {
		t.Errorf("Reason = %q, want it to mention \"published\"", got.Reason)
	}
}

func TestVerifyDLPPolicyRuleExpectation_RuleExpiredButStillActive_ReturnsConfirmedFailure(t *testing.T) {
	exp := baselineExpectation()
	past := verifyTestBase.Add(-time.Hour)
	exp.RuleExpiresAt = &past
	got := verify(exp, baselineEvidence())
	if got.Verdict != VerdictConfirmedFailure {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictConfirmedFailure)
	}
	if !strings.Contains(got.Reason, "expired") {
		t.Errorf("Reason = %q, want it to mention \"expired\"", got.Reason)
	}
}

func TestVerifyDLPPolicyRuleExpectation_RuleExpiresAtNil_SkipsExpiryCheck(t *testing.T) {
	exp := baselineExpectation()
	exp.RuleExpiresAt = nil
	got := verify(exp, baselineEvidence())
	if got.Verdict != VerdictConfirmedSuccess {
		t.Fatalf("Verdict = %q, want %q -- nil RuleExpiresAt must skip the expiry branch entirely", got.Verdict, VerdictConfirmedSuccess)
	}
}

func TestVerifyDLPPolicyRuleExpectation_ExceptionExpiredButStillActive_ReturnsConfirmedFailure(t *testing.T) {
	exp := baselineExpectation()
	past := verifyTestBase.Add(-time.Hour)
	exp.ExceptionExpiresAt = &past
	ev := baselineEvidence()
	ev.ExceptionActive = true
	got := verify(exp, ev)
	if got.Verdict != VerdictConfirmedFailure {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictConfirmedFailure)
	}
	if !strings.Contains(got.Reason, "exception") || !strings.Contains(got.Reason, "expired") {
		t.Errorf("Reason = %q, want it to mention the exception having expired", got.Reason)
	}
}

func TestVerifyDLPPolicyRuleExpectation_ModeMismatch_ReturnsConfirmedFailure(t *testing.T) {
	ev := baselineEvidence()
	ev.ObservedMode = ModeAuditOnly
	got := verify(baselineExpectation(), ev)
	if got.Verdict != VerdictConfirmedFailure {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictConfirmedFailure)
	}
	if !strings.Contains(got.Reason, string(ModeEnforce)) || !strings.Contains(got.Reason, string(ModeAuditOnly)) {
		t.Errorf("Reason = %q, want it to name both %q and %q", got.Reason, ModeEnforce, ModeAuditOnly)
	}
}

func TestVerifyDLPPolicyRuleExpectation_ScopeMismatch_NamesTheField(t *testing.T) {
	exp := baselineExpectation()
	exp.Scope.ExcludedUsers = []string{"lab-user-ceo", "lab-user-cfo"}
	got := verify(exp, baselineEvidence()) // evidence still only excludes lab-user-ceo
	if got.Verdict != VerdictConfirmedFailure {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictConfirmedFailure)
	}
	if !strings.Contains(got.Reason, "ExcludedUsers") {
		t.Errorf("Reason = %q, want it to name the mismatched field ExcludedUsers", got.Reason)
	}
}

func TestVerifyDLPPolicyRuleExpectation_ScopeNilVsEmptySlice_IsNotAMismatch(t *testing.T) {
	exp := baselineExpectation()
	exp.Scope.ExcludedLocations = nil
	ev := baselineEvidence()
	ev.ObservedScope.ExcludedLocations = []string{}
	got := verify(exp, ev)
	if got.Verdict != VerdictConfirmedSuccess {
		t.Fatalf("Verdict = %q, want %q -- nil vs empty slice must not count as a mismatch", got.Verdict, VerdictConfirmedSuccess)
	}
}

func TestVerifyDLPPolicyRuleExpectation_ScopeSetOrderIndependent_IsNotAMismatch(t *testing.T) {
	exp := baselineExpectation()
	exp.Scope.IncludedGroups = []string{"a", "b"}
	ev := baselineEvidence()
	ev.ObservedScope.IncludedGroups = []string{"b", "a"}
	got := verify(exp, ev)
	if got.Verdict != VerdictConfirmedSuccess {
		t.Fatalf("Verdict = %q, want %q -- same set in a different order must not count as a mismatch", got.Verdict, VerdictConfirmedSuccess)
	}
}

func TestVerifyDLPPolicyRuleExpectation_UndeclaredExceptionActive_ReturnsConfirmedFailure(t *testing.T) {
	exp := baselineExpectation() // ExceptionExpiresAt left nil: no exception declared/expected
	ev := baselineEvidence()
	ev.ExceptionActive = true
	got := verify(exp, ev)
	if got.Verdict != VerdictConfirmedFailure {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictConfirmedFailure)
	}
	if !strings.Contains(got.Reason, "not declared") && !strings.Contains(got.Reason, "not expected") {
		t.Errorf("Reason = %q, want it to say the exception was not declared/expected", got.Reason)
	}
}

func TestVerifyDLPPolicyRuleExpectation_PropagationDelayExceeded_ReturnsConfirmedFailure(t *testing.T) {
	exp := baselineExpectation()
	exp.MaxPropagationDelay = 10 * time.Minute
	ev := baselineEvidence()
	ev.ConfigChangedAt = verifyTestBase
	ev.LastSyncedAt = verifyTestBase.Add(-30 * time.Minute) // lag of 30m > 10m allowed
	got := verify(exp, ev)
	if got.Verdict != VerdictConfirmedFailure {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictConfirmedFailure)
	}
	if !strings.Contains(got.Reason, "propagation") && !strings.Contains(got.Reason, "stale") {
		t.Errorf("Reason = %q, want it to mention propagation delay/staleness", got.Reason)
	}
}

func TestVerifyDLPPolicyRuleExpectation_PropagationDelayWithinLimit_ReturnsConfirmedSuccess(t *testing.T) {
	exp := baselineExpectation()
	exp.MaxPropagationDelay = 10 * time.Minute
	ev := baselineEvidence()
	ev.ConfigChangedAt = verifyTestBase
	ev.LastSyncedAt = verifyTestBase.Add(-5 * time.Minute) // lag of 5m <= 10m allowed
	got := verify(exp, ev)
	if got.Verdict != VerdictConfirmedSuccess {
		t.Fatalf("Verdict = %q, want %q -- a lag within the allowed delay must still pass", got.Verdict, VerdictConfirmedSuccess)
	}
}

func TestVerifyDLPPolicyRuleExpectation_AllMatch_ReturnsConfirmedSuccess(t *testing.T) {
	got := verify(baselineExpectation(), baselineEvidence())
	if got.Verdict != VerdictConfirmedSuccess {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictConfirmedSuccess)
	}
	if got.Reason != "" {
		t.Errorf("Reason = %q, want empty on ConfirmedSuccess", got.Reason)
	}
}

func TestVerifyDLPPolicyRuleExpectation_MultipleRecords_PicksLatestByTimestampNotOrder(t *testing.T) {
	older := baselineEvidence() // ConfirmedSuccess-shaped
	older.Timestamp = verifyTestBase.Add(-30 * time.Minute)

	newer := baselineEvidence() // ConfirmedFailure-shaped (disabled)
	newer.Timestamp = verifyTestBase
	newer.Enabled = false

	// newer (the one that should win) appears AFTER older in the slice,
	// so a naive "last element" or "first element" selection would get
	// this wrong in one direction or the other.
	got := verifyMulti(baselineExpectation(), []DLPPolicyRuleEvidence{older, newer})
	if got.Verdict != VerdictConfirmedFailure {
		t.Fatalf("Verdict = %q, want %q -- must select the record with the latest Timestamp, not the last/first in the slice", got.Verdict, VerdictConfirmedFailure)
	}
}
