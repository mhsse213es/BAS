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

func TestRemoteServiceCreation_StableIdentity(t *testing.T) {
	tech := RemoteServiceCreation()
	if tech.ID != "remote-service-creation" {
		t.Fatalf("id = %q", tech.ID)
	}
	if tech.MitreID != "T1543.003" {
		t.Fatalf("mitreID = %q, want T1543.003", tech.MitreID)
	}
	if tech.RiskClass != adprimitive.RiskPotentiallyDestructive {
		t.Fatalf("riskClass = %q, want potentially_destructive (leaves a persistent service until cleaned up)", tech.RiskClass)
	}
	if tech.Name == "" {
		t.Fatal("technique must have a human-readable name")
	}
	if tech.ID == WMIRemoteProcessCreation().ID {
		t.Fatal("techniques must have distinct ids")
	}
}
