package dlppolicy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFixtureDLPPolicyPrecedenceProvider_FiltersByScopeContextAndWindow(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	ctx := DLPPolicyEvaluationContext{UserOrGroup: "lab-user-finance-analyst", Location: "lab-site-mumbai", DataType: "pci"}
	otherCtx := DLPPolicyEvaluationContext{UserOrGroup: "lab-user-hr-analyst", Location: "lab-site-mumbai", DataType: "pci"}
	events := []DLPPolicyPrecedenceEvidence{
		{ScopeID: "lab-ou-finance", Context: ctx, Timestamp: base, ObservedWinningRuleID: "r1", Source: SourceFixture},                      // match
		{ScopeID: "lab-ou-hr", Context: ctx, Timestamp: base, ObservedWinningRuleID: "r2", Source: SourceFixture},                           // wrong scope
		{ScopeID: "lab-ou-finance", Context: otherCtx, Timestamp: base, ObservedWinningRuleID: "r3", Source: SourceFixture},                 // wrong context
		{ScopeID: "lab-ou-finance", Context: ctx, Timestamp: base.Add(-48 * time.Hour), ObservedWinningRuleID: "r4", Source: SourceFixture}, // out of window
	}
	p := NewFixtureDLPPolicyPrecedenceProvider(events)
	window := TimeWindow{Start: base.Add(-time.Hour), End: base.Add(time.Hour)}

	got, err := p.DLPPolicyPrecedenceEvidenceFor("lab-ou-finance", ctx, window)
	if err != nil {
		t.Fatalf("DLPPolicyPrecedenceEvidenceFor: %v", err)
	}
	if len(got) != 1 || got[0].ObservedWinningRuleID != "r1" {
		t.Fatalf("got %+v, want exactly the one matching record (r1)", got)
	}
}

func intPtr(v int) *int { return &v }

func TestResolveExpectedWinner_SinglePriorityWins(t *testing.T) {
	candidates := []DLPPolicyRuleRef{
		{RuleID: "r1", Priority: intPtr(2), Eligible: true},
		{RuleID: "r2", Priority: intPtr(1), Eligible: true},
	}
	winnerID, ambiguous, indeterminate := resolveExpectedWinner(candidates)
	if indeterminate || ambiguous || winnerID != "r2" {
		t.Fatalf("got winnerID=%q ambiguous=%v indeterminate=%v, want r2/false/false", winnerID, ambiguous, indeterminate)
	}
}

func TestResolveExpectedWinner_OrderIndependent(t *testing.T) {
	a := []DLPPolicyRuleRef{{RuleID: "r1", Priority: intPtr(2), Eligible: true}, {RuleID: "r2", Priority: intPtr(1), Eligible: true}}
	b := []DLPPolicyRuleRef{{RuleID: "r2", Priority: intPtr(1), Eligible: true}, {RuleID: "r1", Priority: intPtr(2), Eligible: true}}
	w1, _, _ := resolveExpectedWinner(a)
	w2, _, _ := resolveExpectedWinner(b)
	if w1 != "r2" || w2 != "r2" {
		t.Fatalf("winner must not depend on slice order: got %q and %q, want both r2", w1, w2)
	}
}

func TestResolveExpectedWinner_IneligibleSkipped(t *testing.T) {
	candidates := []DLPPolicyRuleRef{
		{RuleID: "r1", Priority: intPtr(1), Eligible: false}, // disabled higher-priority rule
		{RuleID: "r2", Priority: intPtr(2), Eligible: true},
	}
	winnerID, ambiguous, indeterminate := resolveExpectedWinner(candidates)
	if indeterminate || ambiguous || winnerID != "r2" {
		t.Fatalf("got winnerID=%q ambiguous=%v indeterminate=%v, want r2/false/false (ineligible r1 must be skipped)", winnerID, ambiguous, indeterminate)
	}
}

func TestResolveExpectedWinner_TiedPriorityIsAmbiguous(t *testing.T) {
	candidates := []DLPPolicyRuleRef{
		{RuleID: "r1", Priority: intPtr(1), ExpectedAction: "block", Eligible: true},
		{RuleID: "r2", Priority: intPtr(1), ExpectedAction: "quarantine", Eligible: true},
	}
	_, ambiguous, indeterminate := resolveExpectedWinner(candidates)
	if indeterminate || !ambiguous {
		t.Fatalf("got ambiguous=%v indeterminate=%v, want ambiguous=true", ambiguous, indeterminate)
	}
}

func TestResolveExpectedWinner_TiedPrioritySameActionStillAmbiguous(t *testing.T) {
	candidates := []DLPPolicyRuleRef{
		{RuleID: "r1", Priority: intPtr(1), ExpectedAction: "block", Eligible: true},
		{RuleID: "r2", Priority: intPtr(1), ExpectedAction: "block", Eligible: true},
	}
	_, ambiguous, indeterminate := resolveExpectedWinner(candidates)
	if indeterminate || !ambiguous {
		t.Fatalf("got ambiguous=%v indeterminate=%v, want ambiguous=true -- which rule fired is still indeterminate even when the net action matches", ambiguous, indeterminate)
	}
}

func TestResolveExpectedWinner_MissingPriorityIsIndeterminate(t *testing.T) {
	candidates := []DLPPolicyRuleRef{
		{RuleID: "r1", Priority: nil, Eligible: true},
		{RuleID: "r2", Priority: intPtr(1), Eligible: true},
	}
	_, _, indeterminate := resolveExpectedWinner(candidates)
	if !indeterminate {
		t.Fatal("want indeterminate=true when any eligible candidate has a nil Priority")
	}
}

func TestResolveExpectedWinner_NoEligibleCandidatesIsIndeterminate(t *testing.T) {
	candidates := []DLPPolicyRuleRef{{RuleID: "r1", Priority: intPtr(1), Eligible: false}}
	_, _, indeterminate := resolveExpectedWinner(candidates)
	if !indeterminate {
		t.Fatal("want indeterminate=true when no candidate is eligible")
	}
}

// --- VerifyDLPPolicyPrecedenceExpectation ---

var precedenceTestBase = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
var precedenceTestWindow = TimeWindow{Start: precedenceTestBase.Add(-time.Hour), End: precedenceTestBase.Add(time.Hour)}

func baselinePrecedenceExpectation() DLPPolicyPrecedenceExpectation {
	return DLPPolicyPrecedenceExpectation{
		ScopeID: "lab-ou-finance",
		Context: DLPPolicyEvaluationContext{UserOrGroup: "lab-user-finance-analyst", Location: "lab-site-mumbai", DataType: "pci"},
		CandidateRules: []DLPPolicyRuleRef{
			{RuleID: "r-high", Priority: intPtr(1), ExpectedAction: "block", Eligible: true},
			{RuleID: "r-low", Priority: intPtr(2), ExpectedAction: "audit", Eligible: true},
		},
		ExpectedWinningRuleID:   "r-high",
		ExpectedEffectiveAction: "block",
	}
}

func baselinePrecedenceEvidence(exp DLPPolicyPrecedenceExpectation) DLPPolicyPrecedenceEvidence {
	return DLPPolicyPrecedenceEvidence{
		ScopeID: exp.ScopeID, Context: exp.Context,
		ObservedWinningRuleID: exp.ExpectedWinningRuleID, ObservedEffectiveAction: exp.ExpectedEffectiveAction,
		Timestamp: precedenceTestBase, Source: SourceFixture,
	}
}

func verifyPrecedence(exp DLPPolicyPrecedenceExpectation, evs ...DLPPolicyPrecedenceEvidence) VerdictDetail {
	return VerifyDLPPolicyPrecedenceExpectation(exp, NewFixtureDLPPolicyPrecedenceProvider(evs), precedenceTestWindow)
}

func TestVerifyDLPPolicyPrecedenceExpectation_PositiveCase_ReturnsConfirmedSuccess(t *testing.T) {
	exp := baselinePrecedenceExpectation()
	got := verifyPrecedence(exp, baselinePrecedenceEvidence(exp))
	if got.Verdict != VerdictConfirmedSuccess {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictConfirmedSuccess)
	}
}

func TestVerifyDLPPolicyPrecedenceExpectation_ExpectedWinnerNotACandidate_ReturnsInconclusive(t *testing.T) {
	exp := baselinePrecedenceExpectation()
	exp.ExpectedWinningRuleID = "r-nonexistent"
	got := verifyPrecedence(exp, baselinePrecedenceEvidence(exp))
	if got.Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictInconclusive)
	}
}

func TestVerifyDLPPolicyPrecedenceExpectation_ExpectedWinnerIneligible_ReturnsInconclusive(t *testing.T) {
	exp := baselinePrecedenceExpectation()
	exp.CandidateRules[0].Eligible = false // r-high, the declared expected winner
	got := verifyPrecedence(exp, baselinePrecedenceEvidence(exp))
	if got.Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictInconclusive)
	}
}

func TestVerifyDLPPolicyPrecedenceExpectation_DisabledHigherPriorityRule_NextEligibleWinsCorrectly(t *testing.T) {
	exp := baselinePrecedenceExpectation()
	exp.CandidateRules[0].Eligible = false // r-high disabled
	exp.ExpectedWinningRuleID = "r-low"    // correctly expect the next eligible rule
	exp.ExpectedEffectiveAction = "audit"
	ev := baselinePrecedenceEvidence(exp) // ObservedWinningRuleID/Action now follow exp's updated fields
	got := verifyPrecedence(exp, ev)
	if got.Verdict != VerdictConfirmedSuccess {
		t.Fatalf("Verdict = %q, want %q -- disabling the higher-priority rule must correctly let the next eligible one win", got.Verdict, VerdictConfirmedSuccess)
	}
}

func TestVerifyDLPPolicyPrecedenceExpectation_MissingPriority_ReturnsInconclusive(t *testing.T) {
	exp := baselinePrecedenceExpectation()
	exp.CandidateRules[1].Priority = nil // r-low
	got := verifyPrecedence(exp, baselinePrecedenceEvidence(exp))
	if got.Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want %q -- a missing priority must never silently produce a pass", got.Verdict, VerdictInconclusive)
	}
}

func TestVerifyDLPPolicyPrecedenceExpectation_ContradictoryExpectationWithoutOverride_ReturnsInconclusive(t *testing.T) {
	exp := baselinePrecedenceExpectation()
	exp.ExpectedWinningRuleID = "r-low" // contradicts raw priority order (r-high has lower Priority number)
	exp.ExpectedEffectiveAction = "audit"
	got := verifyPrecedence(exp, baselinePrecedenceEvidence(exp))
	if got.Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictInconclusive)
	}
}

func TestVerifyDLPPolicyPrecedenceExpectation_IntentionalOverride_VerifiesCorrectly(t *testing.T) {
	exp := baselinePrecedenceExpectation()
	exp.ExpectedWinningRuleID = "r-low" // contradicts raw priority order, but...
	exp.ExpectedEffectiveAction = "audit"
	exp.OverrideJustification = "r-low is an explicit admin-override rule that always applies regardless of priority"
	got := verifyPrecedence(exp, baselinePrecedenceEvidence(exp))
	if got.Verdict != VerdictConfirmedSuccess {
		t.Fatalf("Verdict = %q, want %q -- a declared, justified override must verify normally against evidence", got.Verdict, VerdictConfirmedSuccess)
	}
}

func TestVerifyDLPPolicyPrecedenceExpectation_WhitespaceOnlyOverrideJustification_StillTreatedAsContradictory(t *testing.T) {
	exp := baselinePrecedenceExpectation()
	exp.ExpectedWinningRuleID = "r-low"
	exp.ExpectedEffectiveAction = "audit"
	exp.OverrideJustification = "   "
	got := verifyPrecedence(exp, baselinePrecedenceEvidence(exp))
	if got.Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want %q -- whitespace-only OverrideJustification must not count as a real justification", got.Verdict, VerdictInconclusive)
	}
}

func TestVerifyDLPPolicyPrecedenceExpectation_GenuineConflict_StillVerifiesAgainstEvidenceWithTieNote(t *testing.T) {
	exp := baselinePrecedenceExpectation()
	exp.CandidateRules[1].Priority = intPtr(1)                    // r-low now tied with r-high at priority 1
	got := verifyPrecedence(exp, baselinePrecedenceEvidence(exp)) // evidence still matches exp's declared winner/action
	if got.Verdict != VerdictConfirmedSuccess {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictConfirmedSuccess)
	}
	if !strings.Contains(got.Reason, "tie") {
		t.Errorf("Reason = %q, want it to note the genuine priority tie even on a successful verdict", got.Reason)
	}
}

func TestVerifyDLPPolicyPrecedenceExpectation_TiedPrioritySameAction_StillFlaggedAsTie(t *testing.T) {
	exp := baselinePrecedenceExpectation()
	exp.CandidateRules[1].Priority = intPtr(1)
	exp.CandidateRules[1].ExpectedAction = exp.CandidateRules[0].ExpectedAction // both "block" now
	got := verifyPrecedence(exp, baselinePrecedenceEvidence(exp))
	if !strings.Contains(got.Reason, "tie") {
		t.Errorf("Reason = %q, want the tie noted even though both candidates share the same action", got.Reason)
	}
}

func TestVerifyDLPPolicyPrecedenceExpectation_IncompleteCandidateInventory_ReturnsInconclusive(t *testing.T) {
	exp := baselinePrecedenceExpectation()
	ev := baselinePrecedenceEvidence(exp)
	ev.ObservedWinningRuleID = "r-unknown" // the vendor matched a rule nobody declared as a candidate
	got := verifyPrecedence(exp, ev)
	if got.Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictInconclusive)
	}
}

func TestVerifyDLPPolicyPrecedenceExpectation_WrongRuleWon_ReturnsConfirmedFailure(t *testing.T) {
	exp := baselinePrecedenceExpectation()
	ev := baselinePrecedenceEvidence(exp)
	ev.ObservedWinningRuleID = "r-low" // the vendor's own candidate, just the wrong one
	got := verifyPrecedence(exp, ev)
	if got.Verdict != VerdictConfirmedFailure {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictConfirmedFailure)
	}
}

func TestVerifyDLPPolicyPrecedenceExpectation_RightRuleWrongAction_ReturnsConfirmedFailure(t *testing.T) {
	exp := baselinePrecedenceExpectation()
	ev := baselinePrecedenceEvidence(exp)
	ev.ObservedEffectiveAction = "warn" // right rule, wrong effective action
	got := verifyPrecedence(exp, ev)
	if got.Verdict != VerdictConfirmedFailure {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictConfirmedFailure)
	}
}

func TestVerifyDLPPolicyPrecedenceExpectation_NoEvidence_ReturnsInconclusive(t *testing.T) {
	exp := baselinePrecedenceExpectation()
	got := VerifyDLPPolicyPrecedenceExpectation(exp, NewFixtureDLPPolicyPrecedenceProvider(nil), precedenceTestWindow)
	if got.Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictInconclusive)
	}
}

func TestDLPPolicyPrecedenceExpectation_JSONUsesCamelCaseKeysThroughoutNestedStructs(t *testing.T) {
	exp := baselinePrecedenceExpectation()
	data, err := json.Marshal(exp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(data)
	for _, want := range []string{
		`"ruleId"`, `"priority"`, `"expectedAction"`, `"eligible"`,
		`"userOrGroup"`, `"location"`, `"dataType"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("marshaled JSON = %s, want it to contain %s (camelCase, matching every other type in this package)", s, want)
		}
	}
	for _, unwanted := range []string{`"RuleID"`, `"Priority"`, `"ExpectedAction"`, `"Eligible"`, `"UserOrGroup"`, `"Location"`, `"DataType"`} {
		if strings.Contains(s, unwanted) {
			t.Errorf("marshaled JSON = %s, must not contain PascalCase key %s", s, unwanted)
		}
	}
}

func TestVerifyDLPPolicyPrecedenceExpectation_MultipleRecords_PicksLatestByTimestampNotOrder(t *testing.T) {
	exp := baselinePrecedenceExpectation()
	older := baselinePrecedenceEvidence(exp) // ConfirmedSuccess-shaped
	older.Timestamp = precedenceTestBase.Add(-30 * time.Minute)
	newer := baselinePrecedenceEvidence(exp) // ConfirmedFailure-shaped
	newer.Timestamp = precedenceTestBase
	newer.ObservedWinningRuleID = "r-low"
	got := verifyPrecedence(exp, older, newer) // newer appears after older in the slice
	if got.Verdict != VerdictConfirmedFailure {
		t.Fatalf("Verdict = %q, want %q -- must select the record with the latest Timestamp", got.Verdict, VerdictConfirmedFailure)
	}
}
