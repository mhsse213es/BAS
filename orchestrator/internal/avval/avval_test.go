package avval

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
	// Non-Inconclusive finding with Insufficient completeness is rejected.
	if err := Valid(ClaimPrevention, FindingVerifiedProtection, CompletenessInsufficient); err == nil {
		t.Error("VerifiedProtection+Insufficient should be rejected")
	}
	// Inconclusive is valid for any claim and any completeness.
	if err := Valid(ClaimPrevention, FindingInconclusive, CompletenessInsufficient); err != nil {
		t.Errorf("Inconclusive+Insufficient should be valid, got %v", err)
	}
	// VerifiedProtection is valid for Prevention at Complete.
	if err := Valid(ClaimPrevention, FindingVerifiedProtection, CompletenessComplete); err != nil {
		t.Errorf("Prevention+VerifiedProtection+Complete should be valid, got %v", err)
	}
	// ConfirmedGap is valid for FalsePositive at Complete (a legitimate
	// request incorrectly blocked is a confirmed gap under that claim).
	if err := Valid(ClaimFalsePositive, FindingConfirmedGap, CompletenessComplete); err != nil {
		t.Errorf("FalsePositive+ConfirmedGap+Complete should be valid, got %v", err)
	}
	// An unrecognized claim is rejected even at Complete.
	if err := Valid(ClaimType("bogus"), FindingVerifiedProtection, CompletenessComplete); err == nil {
		t.Error("unrecognized claim should be rejected")
	}
}
