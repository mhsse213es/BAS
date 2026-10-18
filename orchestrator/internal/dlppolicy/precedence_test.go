package dlppolicy

import (
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
