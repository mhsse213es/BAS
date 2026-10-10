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

func TestScheduledTaskRemote_StableIdentity(t *testing.T) {
	tech := ScheduledTaskRemote()
	if tech.ID != "scheduled-task-remote" {
		t.Fatalf("id = %q", tech.ID)
	}
	if tech.MitreID != "T1053.005" {
		t.Fatalf("mitreID = %q, want T1053.005", tech.MitreID)
	}
	if tech.RiskClass != adprimitive.RiskPotentiallyDestructive {
		t.Fatalf("riskClass = %q, want potentially_destructive (persistent task artifact)", tech.RiskClass)
	}
}

func TestWinRMRemoteExecution_StableIdentity(t *testing.T) {
	tech := WinRMRemoteExecution()
	if tech.ID != "winrm-remote-execution" {
		t.Fatalf("id = %q", tech.ID)
	}
	if tech.MitreID != "T1021.006" {
		t.Fatalf("mitreID = %q, want T1021.006", tech.MitreID)
	}
	if tech.RiskClass != adprimitive.RiskNonDestructive {
		t.Fatalf("riskClass = %q, want non_destructive (one-shot Invoke-Command, no persistence, like WMI)", tech.RiskClass)
	}
}

func TestRDPInteractiveLogon_StableIdentity(t *testing.T) {
	tech := RDPInteractiveLogon()
	if tech.ID != "rdp-interactive-logon" {
		t.Fatalf("id = %q", tech.ID)
	}
	if tech.MitreID != "T1021.001" {
		t.Fatalf("mitreID = %q, want T1021.001", tech.MitreID)
	}
	if tech.RiskClass != adprimitive.RiskNonDestructive {
		t.Fatalf("riskClass = %q, want non_destructive (session establishment alone, no further action)", tech.RiskClass)
	}
}

func TestAllTechniques_HaveDistinctIDs(t *testing.T) {
	seen := map[string]bool{}
	for _, tech := range []Technique{WMIRemoteProcessCreation(), RemoteServiceCreation(), ScheduledTaskRemote(), WinRMRemoteExecution(), RDPInteractiveLogon()} {
		if seen[tech.ID] {
			t.Fatalf("duplicate technique id: %q", tech.ID)
		}
		seen[tech.ID] = true
	}
}
