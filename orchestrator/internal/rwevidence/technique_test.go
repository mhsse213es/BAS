package rwevidence

import (
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
)

func TestVSSInhibition_StableIdentity(t *testing.T) {
	tech := VSSInhibition()
	if tech.ID != "vss-inhibition" {
		t.Fatalf("id = %q", tech.ID)
	}
	if tech.MitreID != "T1490" {
		t.Fatalf("mitreID = %q, want T1490", tech.MitreID)
	}
	if tech.RiskClass != adprimitive.RiskDestructive {
		t.Fatalf("riskClass = %q, want destructive (a deleted shadow copy cannot be recreated)", tech.RiskClass)
	}
}
