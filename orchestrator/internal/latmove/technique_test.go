package latmove

import (
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
)

func TestWMIRemoteProcessCreation_StableIdentity(t *testing.T) {
	tech := WMIRemoteProcessCreation()
	if tech.ID != "wmi-remote-process-creation" {
		t.Fatalf("id = %q", tech.ID)
	}
	if tech.MitreID != "T1047" {
		t.Fatalf("mitreID = %q, want T1047", tech.MitreID)
	}
	if tech.RiskClass != adprimitive.RiskNonDestructive {
		t.Fatalf("riskClass = %q, want non_destructive", tech.RiskClass)
	}
	if tech.Name == "" {
		t.Fatal("technique must have a human-readable name")
	}
}
