package wafval

import "testing"

func TestCoverage_Present(t *testing.T) {
	cases := map[Coverage]bool{
		CoverageFound:                true,
		CoverageSearchedVerifiedNone: true,
		CoverageSearchIncomplete:     false,
		CoverageSourceUnavailable:    false,
	}
	for cov, want := range cases {
		if got := cov.Present(); got != want {
			t.Errorf("Coverage(%q).Present() = %v, want %v", cov, got, want)
		}
	}
}

func TestValid(t *testing.T) {
	// VerdictAllowed only from FalsePositive.
	if err := Valid(ClaimPrevention, VerdictAllowed, CompletenessComplete); err == nil {
		t.Error("Prevention+Allowed should be rejected")
	}
	if err := Valid(ClaimFalsePositive, VerdictAllowed, CompletenessComplete); err != nil {
		t.Errorf("FalsePositive+Allowed should be valid, got %v", err)
	}
	// IncorrectlyBlocked only from FalsePositive.
	if err := Valid(ClaimPrevention, VerdictIncorrectlyBlocked, CompletenessComplete); err == nil {
		t.Error("Prevention+IncorrectlyBlocked should be rejected")
	}
	// Non-Inconclusive verdict with Insufficient completeness is rejected.
	if err := Valid(ClaimPrevention, VerdictBlocked, CompletenessInsufficient); err == nil {
		t.Error("Blocked+Insufficient should be rejected")
	}
	// Inconclusive is valid for any claim and any completeness.
	if err := Valid(ClaimPrevention, VerdictInconclusive, CompletenessInsufficient); err != nil {
		t.Errorf("Inconclusive+Insufficient should be valid, got %v", err)
	}
	// Blocked is valid for Prevention at Complete.
	if err := Valid(ClaimPrevention, VerdictBlocked, CompletenessComplete); err != nil {
		t.Errorf("Prevention+Blocked+Complete should be valid, got %v", err)
	}
}
