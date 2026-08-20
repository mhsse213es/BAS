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

// TestResourceProfileForT1046IsUnlabeled proves T1046 (Network Service
// Discovery) was deliberately removed from the curated discovery set: its
// real ART atomics are active network port scans (a 65535-port sequential
// bash scan, an nmap /24 sweep + telnet + nc, a full-range nmap -sV scan),
// verified against production 2026-08-20 -- not the "sub-second local
// enumeration" this profile's 20s execute-timeout assumes. Must stay
// unlabeled so a step keeps its own declared timeout_sec instead of being
// force-capped at 20s and misclassified as a timeout.
func TestResourceProfileForT1046IsUnlabeled(t *testing.T) {
	if p := ResourceProfileFor("T1046"); p != nil {
		t.Errorf("T1046 must be unlabeled (no curated resource profile), got %+v", p)
	}
	if p := TimeoutProfileFor("T1046"); p != nil {
		t.Errorf("T1046 must not get the curated 20s discovery timeout, got %+v", p)
	}
}

func TestAttachProfiles(t *testing.T) {
	steps := []ScenarioStep{
		{TechniqueID: "T1057"},                  // labelled discovery
		{TechniqueID: "T1003", TimeoutSec: 300}, // unlabeled, custom timeout
	}
	AttachProfiles(steps)
	if steps[0].Resource == nil || steps[0].Timeout == nil {
		t.Error("T1057 should get both resource and timeout profiles")
	}
	if steps[1].Resource != nil || steps[1].Timeout != nil {
		t.Error("T1003 must stay unlabeled so the agent keeps its own 300s timeout")
	}
}

func TestTimeoutProfileForOnlyDiscovery(t *testing.T) {
	if TimeoutProfileFor("T1082") == nil {
		t.Error("discovery technique should get a curated timeout")
	}
	if TimeoutProfileFor("T1003") != nil {
		t.Error("non-discovery technique must not get a curated timeout (keeps its own)")
	}
}

func TestTimeoutWireShapeMatchesAgent(t *testing.T) {
	raw, err := json.Marshal(TimeoutProfileFor("T1057"))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"scheduleSec":30,"executeSec":20,"graceSec":3}`
	if string(raw) != want {
		t.Errorf("timeout wire shape drift:\n got %s\nwant %s", raw, want)
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
