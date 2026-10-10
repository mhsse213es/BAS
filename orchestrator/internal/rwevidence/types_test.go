package rwevidence

import (
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func TestNotApplicable_IsSkippedWithNotApplicableReason(t *testing.T) {
	cr := NotApplicable(CapabilityRecovery, DataEncryptedForImpact(), "T1486 does not create or destroy recovery mechanisms itself -- that is T1490's domain")
	if cr.Verdict != controlval.VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED", cr.Verdict)
	}
	if cr.SkipReason != controlval.SkipNotApplicable {
		t.Fatalf("skipReason = %q, want not_applicable", cr.SkipReason)
	}
	if cr.Capability != CapabilityRecovery {
		t.Fatalf("capability = %q, want recovery", cr.Capability)
	}
	if cr.TechniqueID != "T1486" {
		t.Fatalf("techniqueID = %q, want T1486", cr.TechniqueID)
	}
	if cr.Reason == "" {
		t.Fatal("not_applicable must always carry a reason explaining why")
	}
}
