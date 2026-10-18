package dlppolicy

import (
	"strings"
	"testing"
	"time"
)

func scoped(id ScopeID, verdict DLPPOLVerdict, fingerprint string) DLPPolicyScopedVerdict {
	return DLPPolicyScopedVerdict{ScopeID: id, Verdict: VerdictDetail{Verdict: verdict}, Fingerprint: fingerprint}
}

func TestVerifyDLPPolicyVarianceExpectation_IdenticalScopes_ReturnsConfirmedSuccess(t *testing.T) {
	results := map[ScopeID]DLPPolicyScopedVerdict{
		"baseline": scoped("baseline", VerdictConfirmedSuccess, "mode=enforce,enabled=true"),
		"mumbai":   scoped("mumbai", VerdictConfirmedSuccess, "mode=enforce,enabled=true"),
	}
	exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: []ScopeID{"mumbai"}}
	got := VerifyDLPPolicyVarianceExpectation(exp, results)
	if got["mumbai"].Verdict != VerdictConfirmedSuccess {
		t.Fatalf("Verdict = %q, want %q", got["mumbai"].Verdict, VerdictConfirmedSuccess)
	}
}

func TestVerifyDLPPolicyVarianceExpectation_MissingBaseline_ReturnsInconclusive(t *testing.T) {
	results := map[ScopeID]DLPPolicyScopedVerdict{
		"mumbai": scoped("mumbai", VerdictConfirmedSuccess, "x"),
	}
	exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: []ScopeID{"mumbai"}}
	got := VerifyDLPPolicyVarianceExpectation(exp, results)
	if got["mumbai"].Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want %q", got["mumbai"].Verdict, VerdictInconclusive)
	}
}

func TestVerifyDLPPolicyVarianceExpectation_MissingComparisonScope_ReturnsInconclusive(t *testing.T) {
	results := map[ScopeID]DLPPolicyScopedVerdict{
		"baseline": scoped("baseline", VerdictConfirmedSuccess, "x"),
	}
	exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: []ScopeID{"mumbai"}}
	got := VerifyDLPPolicyVarianceExpectation(exp, results)
	if got["mumbai"].Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want %q", got["mumbai"].Verdict, VerdictInconclusive)
	}
}

func TestVerifyDLPPolicyVarianceExpectation_BaselineInconclusive_ReturnsInconclusive(t *testing.T) {
	results := map[ScopeID]DLPPolicyScopedVerdict{
		"baseline": scoped("baseline", VerdictInconclusive, "x"),
		"mumbai":   scoped("mumbai", VerdictConfirmedSuccess, "x"),
	}
	exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: []ScopeID{"mumbai"}}
	got := VerifyDLPPolicyVarianceExpectation(exp, results)
	if got["mumbai"].Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want %q -- an inconclusive side must never produce a comparable claim", got["mumbai"].Verdict, VerdictInconclusive)
	}
}

func TestVerifyDLPPolicyVarianceExpectation_ComparisonNotTested_ReturnsInconclusive(t *testing.T) {
	results := map[ScopeID]DLPPolicyScopedVerdict{
		"baseline": scoped("baseline", VerdictConfirmedSuccess, "x"),
		"mumbai":   scoped("mumbai", VerdictNotTested, "x"),
	}
	exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: []ScopeID{"mumbai"}}
	got := VerifyDLPPolicyVarianceExpectation(exp, results)
	if got["mumbai"].Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want %q -- NotTested must never be treated as a comparable pass/fail", got["mumbai"].Verdict, VerdictInconclusive)
	}
}

func TestVerifyDLPPolicyVarianceExpectation_BaselineNotApplicable_ReturnsInconclusive(t *testing.T) {
	results := map[ScopeID]DLPPolicyScopedVerdict{
		"baseline": scoped("baseline", VerdictNotApplicable, "x"),
		"mumbai":   scoped("mumbai", VerdictConfirmedFailure, "y"),
	}
	exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: []ScopeID{"mumbai"}}
	got := VerifyDLPPolicyVarianceExpectation(exp, results)
	if got["mumbai"].Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want %q -- NotApplicable must never be treated as a comparable pass/fail", got["mumbai"].Verdict, VerdictInconclusive)
	}
}

func TestVerifyDLPPolicyVarianceExpectation_VerdictDiffers_NotPermitted_ReturnsConfirmedFailure(t *testing.T) {
	results := map[ScopeID]DLPPolicyScopedVerdict{
		"baseline": scoped("baseline", VerdictConfirmedSuccess, "mode=enforce"),
		"mumbai":   scoped("mumbai", VerdictConfirmedFailure, "mode=audit-only"),
	}
	exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: []ScopeID{"mumbai"}}
	got := VerifyDLPPolicyVarianceExpectation(exp, results)
	if got["mumbai"].Verdict != VerdictConfirmedFailure {
		t.Fatalf("Verdict = %q, want %q", got["mumbai"].Verdict, VerdictConfirmedFailure)
	}
	if !strings.Contains(got["mumbai"].Reason, "mumbai") {
		t.Errorf("Reason = %q, want it to name the diverging scope", got["mumbai"].Reason)
	}
}

func TestVerifyDLPPolicyVarianceExpectation_VerdictDiffers_Permitted_ReturnsConfirmedSuccessCitingReason(t *testing.T) {
	results := map[ScopeID]DLPPolicyScopedVerdict{
		"baseline": scoped("baseline", VerdictConfirmedSuccess, "mode=enforce"),
		"eu-site":  scoped("eu-site", VerdictConfirmedFailure, "mode=audit-only"),
	}
	exp := DLPPolicyVarianceExpectation{
		BaselineScopeID:    "baseline",
		ComparisonScopeIDs: []ScopeID{"eu-site"},
		PermittedVariance:  map[ScopeID]string{"eu-site": "EU site runs audit-only pending GDPR legal review"},
	}
	got := VerifyDLPPolicyVarianceExpectation(exp, results)
	if got["eu-site"].Verdict != VerdictConfirmedSuccess {
		t.Fatalf("Verdict = %q, want %q -- a declared variance must verify, not fail", got["eu-site"].Verdict, VerdictConfirmedSuccess)
	}
	if !strings.Contains(got["eu-site"].Reason, "GDPR") {
		t.Errorf("Reason = %q, want it to cite the documented PermittedVariance reason", got["eu-site"].Reason)
	}
}

func TestVerifyDLPPolicyVarianceExpectation_SameVerdictDifferentFingerprint_NotPermitted_ReturnsConfirmedFailure(t *testing.T) {
	results := map[ScopeID]DLPPolicyScopedVerdict{
		"baseline": scoped("baseline", VerdictConfirmedSuccess, "action=block"),
		"mumbai":   scoped("mumbai", VerdictConfirmedSuccess, "action=quarantine"),
	}
	exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: []ScopeID{"mumbai"}}
	got := VerifyDLPPolicyVarianceExpectation(exp, results)
	if got["mumbai"].Verdict != VerdictConfirmedFailure {
		t.Fatalf("Verdict = %q, want %q -- both scopes individually passing must not hide a real configuration difference", got["mumbai"].Verdict, VerdictConfirmedFailure)
	}
}

func TestVerifyDLPPolicyVarianceExpectation_SameVerdictDifferentFingerprint_Permitted_ReturnsConfirmedSuccess(t *testing.T) {
	results := map[ScopeID]DLPPolicyScopedVerdict{
		"baseline": scoped("baseline", VerdictConfirmedSuccess, "action=block"),
		"mumbai":   scoped("mumbai", VerdictConfirmedSuccess, "action=quarantine"),
	}
	exp := DLPPolicyVarianceExpectation{
		BaselineScopeID:    "baseline",
		ComparisonScopeIDs: []ScopeID{"mumbai"},
		PermittedVariance:  map[ScopeID]string{"mumbai": "Mumbai site uses quarantine per local incident-response policy"},
	}
	got := VerifyDLPPolicyVarianceExpectation(exp, results)
	if got["mumbai"].Verdict != VerdictConfirmedSuccess {
		t.Fatalf("Verdict = %q, want %q -- the same PermittedVariance gate must cover fingerprint-only drift too", got["mumbai"].Verdict, VerdictConfirmedSuccess)
	}
	if !strings.Contains(got["mumbai"].Reason, "incident-response") {
		t.Errorf("Reason = %q, want it to cite the documented reason", got["mumbai"].Reason)
	}
}

func TestVerifyDLPPolicyVarianceExpectation_MultipleComparisonScopes_ReturnsOneVerdictEach(t *testing.T) {
	results := map[ScopeID]DLPPolicyScopedVerdict{
		"baseline": scoped("baseline", VerdictConfirmedSuccess, "x"),
		"mumbai":   scoped("mumbai", VerdictConfirmedSuccess, "x"),
		"eu-site":  scoped("eu-site", VerdictConfirmedFailure, "y"),
	}
	exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: []ScopeID{"mumbai", "eu-site"}}
	got := VerifyDLPPolicyVarianceExpectation(exp, results)
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	if got["mumbai"].Verdict != VerdictConfirmedSuccess {
		t.Errorf("mumbai Verdict = %q, want %q", got["mumbai"].Verdict, VerdictConfirmedSuccess)
	}
	if got["eu-site"].Verdict != VerdictConfirmedFailure {
		t.Errorf("eu-site Verdict = %q, want %q", got["eu-site"].Verdict, VerdictConfirmedFailure)
	}
}

func TestVerifyDLPPolicyVarianceExpectation_NoComparisonScopes_ReturnsEmptyMap(t *testing.T) {
	exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: nil}
	got := VerifyDLPPolicyVarianceExpectation(exp, map[ScopeID]DLPPolicyScopedVerdict{})
	if len(got) != 0 {
		t.Fatalf("len(got) = %d, want 0", len(got))
	}
}

func TestVerifyDLPPolicyVarianceExpectation_ExceptionInheritance_UndeclaredChildExceptionSurfacesAsDivergence(t *testing.T) {
	window := TimeWindow{Start: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)}
	asOf := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	parentExp := DLPPolicyRuleExpectation{
		RuleID: "r-pci", ScopeID: "parent-ou", ExpectedMode: ModeEnforce,
		ExpectedEnabled: true, ExpectedPublished: true,
		ExceptionExpiresAt: ptrTime(asOf.Add(24 * time.Hour)), // exception IS declared/expected here
	}
	parentEvidence := []DLPPolicyRuleEvidence{{
		RuleID: "r-pci", ScopeID: "parent-ou", ObservedMode: ModeEnforce,
		Enabled: true, Published: true, ExceptionActive: true,
		Timestamp: asOf, Source: SourceFixture,
	}}
	parentVerdict := VerifyDLPPolicyRuleExpectation(parentExp, NewFixtureDLPPolicyRuleProvider(parentEvidence), window, asOf)

	childExp := DLPPolicyRuleExpectation{
		RuleID: "r-pci", ScopeID: "child-ou", ExpectedMode: ModeEnforce,
		ExpectedEnabled: true, ExpectedPublished: true,
		ExceptionExpiresAt: nil, // exception is NOT declared/expected on the child
	}
	childEvidence := []DLPPolicyRuleEvidence{{
		RuleID: "r-pci", ScopeID: "child-ou", ObservedMode: ModeEnforce,
		Enabled: true, Published: true, ExceptionActive: true, // but it inherited one anyway
		Timestamp: asOf, Source: SourceFixture,
	}}
	childVerdict := VerifyDLPPolicyRuleExpectation(childExp, NewFixtureDLPPolicyRuleProvider(childEvidence), window, asOf)

	if childVerdict.Verdict != VerdictConfirmedFailure {
		t.Fatalf("precondition failed: child verdict = %q, want %q (Slice 1 branch 9)", childVerdict.Verdict, VerdictConfirmedFailure)
	}

	results := map[ScopeID]DLPPolicyScopedVerdict{
		"parent-ou": {ScopeID: "parent-ou", Verdict: parentVerdict, Fingerprint: "exceptionActive=true,declared=true"},
		"child-ou":  {ScopeID: "child-ou", Verdict: childVerdict, Fingerprint: "exceptionActive=true,declared=false"},
	}
	exp := DLPPolicyVarianceExpectation{BaselineScopeID: "parent-ou", ComparisonScopeIDs: []ScopeID{"child-ou"}}
	got := VerifyDLPPolicyVarianceExpectation(exp, results)
	if got["child-ou"].Verdict != VerdictConfirmedFailure {
		t.Fatalf("Verdict = %q, want %q -- Slice 2b must surface the inheritance mismatch Slice 1 alone cannot name as a cross-scope concern", got["child-ou"].Verdict, VerdictConfirmedFailure)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
