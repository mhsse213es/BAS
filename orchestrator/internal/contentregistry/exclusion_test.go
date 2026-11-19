package contentregistry

import (
	"errors"
	"testing"
)

func TestExclusionReasonsAreTheFiveSpecCodes(t *testing.T) {
	want := []string{
		"relevance",
		"insufficient_technical_detail",
		"unsupported_platform",
		"validation_environment_unavailable",
		"third_party_dependency",
	}
	if len(ExclusionReasons) != len(want) {
		t.Fatalf("got %d codes, want %d", len(ExclusionReasons), len(want))
	}
	for i, w := range want {
		if string(ExclusionReasons[i]) != w {
			t.Errorf("code %d = %q, want %q", i, ExclusionReasons[i], w)
		}
	}
}

func TestValidateRejectionRequiresValidCode(t *testing.T) {
	if err := ValidateRejection(LifecycleRejected, ""); !errors.Is(err, ErrRejectionNeedsReason) {
		t.Errorf("empty code: got %v, want ErrRejectionNeedsReason", err)
	}
	if err := ValidateRejection(LifecycleRejected, "not a real reason"); !errors.Is(err, ErrRejectionNeedsReason) {
		t.Errorf("free text: got %v, want ErrRejectionNeedsReason", err)
	}
	if err := ValidateRejection(LifecycleRejected, ExclusionRelevance); err != nil {
		t.Errorf("valid code rejected: %v", err)
	}
}

func TestValidateRejectionIgnoresOtherTransitions(t *testing.T) {
	if err := ValidateRejection(LifecycleApproved, ""); err != nil {
		t.Errorf("non-rejection transition with no code: %v", err)
	}
}
