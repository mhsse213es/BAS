package scenario

import (
	"encoding/json"
	"testing"
)

func TestResourceProfileForKnownDiscovery(t *testing.T) {
	p := ResourceProfileFor("T1057")
	if p == nil {
		t.Fatal("T1057 (Process Discovery) should be labelled, got nil")
	}
	if p.Risk != riskObservation || p.Scope != "local" {
		t.Errorf("discovery must be local observation, got scope=%q risk=%q", p.Scope, p.Risk)
	}
	if len(p.Domains) != 1 || p.Domains[0].Domain != domProcess {
		t.Errorf("T1057 should lock the process domain, got %+v", p.Domains)
	}
}

func TestResourceProfileForIsCaseInsensitive(t *testing.T) {
	if ResourceProfileFor("t1012") == nil {
		t.Error("lookup should be case-insensitive; lowercase t1012 returned nil")
	}
}

func TestResourceProfileForSubtechniqueInheritsParent(t *testing.T) {
	// T1087.001 (Local Account) has no exact entry but inherits T1087.
	p := ResourceProfileFor("T1087.001")
	if p == nil {
		t.Fatal("sub-technique T1087.001 should inherit parent T1087, got nil")
	}
	if p.Domains[0].Domain != domSecPolicy {
		t.Errorf("T1087.001 should inherit the wmi-secpolicy domain, got %+v", p.Domains)
	}
}

func TestResourceProfileForUnlabeledIsSerial(t *testing.T) {
	// T1003 (OS Credential Dumping) is a modification — it must NOT be labelled,
	// so the agent runs it serially under the global exclusive lock.
	for _, id := range []string{"T1003", "T1547", "", "not-a-technique"} {
		if p := ResourceProfileFor(id); p != nil {
			t.Errorf("%q must be unlabeled (serial), got %+v", id, p)
		}
	}
}

func TestAttachResourceProfiles(t *testing.T) {
	steps := []ScenarioStep{
		{TechniqueID: "T1057"}, // labelled
		{TechniqueID: "T1003"}, // unlabeled
	}
	AttachResourceProfiles(steps)
	if steps[0].Resource == nil {
		t.Error("T1057 step should have a profile attached")
	}
	if steps[1].Resource != nil {
		t.Error("T1003 step must stay unlabeled (serial)")
	}
}

// TestWireShapeMatchesAgent locks the JSON contract: the orchestrator's profile
// must serialise to exactly the shape the agent's sched.ResourceProfile expects
// (keys: domains[].domain, scope, risk). A drift here silently breaks parallelism.
func TestWireShapeMatchesAgent(t *testing.T) {
	raw, err := json.Marshal(ResourceProfileFor("T1057"))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"domains":[{"domain":"process"}],"scope":"local","risk":"observation"}`
	if string(raw) != want {
		t.Errorf("wire shape drift:\n got %s\nwant %s", raw, want)
	}
}
