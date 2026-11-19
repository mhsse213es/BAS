package findings

import (
	"testing"
	"time"
)

// Technique rows show a remediation status only through an explicit check-to-technique
// mapping. The approved mapping for the current catalog is empty: none of the three
// checks directly prevents an ATT&CK technique. A check with no mapping must never
// produce a technique status, however many completed requests it has.

func TestApprovedMappingIsEmpty(t *testing.T) {
	if len(CheckTechniques) != 0 {
		t.Fatalf("CheckTechniques has %d entries; the approved mapping for the catalog is empty", len(CheckTechniques))
	}
}

func TestEmptyMapping_CompletedRequestsDoNotYieldTechniqueStatus(t *testing.T) {
	now := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	reqs := []RemediationRequest{
		{ID: "1", AgentID: "a", CheckID: "windows-smbv1-disabled", Status: "completed", RequestedAt: now},
		{ID: "2", AgentID: "a", CheckID: "windows-firewall-enabled", Status: "completed", RequestedAt: now},
		{ID: "3", AgentID: "a", CheckID: "windows-bitlocker-enabled", Status: "completed", RequestedAt: now},
	}
	for _, tech := range []string{"T1210", "T1021.002", "T1021"} {
		if status, ok := TechniqueRemediationStatus(CheckTechniques, tech, reqs); ok {
			t.Errorf("%s got status %q from an unmapped check; want no status", tech, status)
		}
	}
}

func TestMappedCheck_ReportsLatestStatusForItsTechnique(t *testing.T) {
	old := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	mapping := map[string][]string{"T1": {"check-x"}}
	reqs := []RemediationRequest{
		{ID: "old", AgentID: "a", CheckID: "check-x", Status: "failed", RequestedAt: old},
		{ID: "new", AgentID: "a", CheckID: "check-x", Status: "completed", RequestedAt: newer},
	}
	status, ok := TechniqueRemediationStatus(mapping, "T1", reqs)
	if !ok || status != RequestCompleted {
		t.Fatalf("got (%q, %v), want (Completed, true) from the latest request", status, ok)
	}
}

func TestUnmappedCheckDoesNotLeakIntoAMappedTechnique(t *testing.T) {
	mapping := map[string][]string{"T1": {"check-x"}}
	reqs := []RemediationRequest{{ID: "1", AgentID: "a", CheckID: "check-other", Status: "completed"}}
	if _, ok := TechniqueRemediationStatus(mapping, "T1", reqs); ok {
		t.Fatal("a request for an unmapped check must not give T1 a status")
	}
}

func TestMappedFailureFailsTheTechnique(t *testing.T) {
	mapping := map[string][]string{"T1": {"check-x", "check-y"}}
	reqs := []RemediationRequest{
		{ID: "1", AgentID: "a", CheckID: "check-x", Status: "completed"},
		{ID: "2", AgentID: "a", CheckID: "check-y", Status: "timed_out"},
	}
	status, ok := TechniqueRemediationStatus(mapping, "T1", reqs)
	if !ok || status != RequestFailed {
		t.Fatalf("got (%q, %v), want (Failed, true)", status, ok)
	}
}
