package scenario

import (
	"encoding/json"
	"testing"
)

// TestResourceProfileForKeptDespiteNarrowException proves T1012, T1016, and
// T1049 stay in the curated discovery set even though each has one atomic
// that shares T1046/T1614/T1083's problem (2026-08-20 audit) -- the majority
// of each technique's real atomics are genuinely fast local reads, and this
// map is keyed by technique (not by individual atomic/test_index), so
// removing the whole technique would trade away correct fast/parallel
// treatment for the rest to fix one. See resource.go's inline comments for
// the specific atomic each exception refers to.
func TestResourceProfileForKeptDespiteNarrowException(t *testing.T) {
	for _, id := range []string{"T1012", "T1016", "T1049"} {
		if p := ResourceProfileFor(id); p == nil {
			t.Errorf("%s should still be labelled (kept as a documented narrow exception), got nil", id)
		}
		if p := TimeoutProfileFor(id); p == nil {
			t.Errorf("%s should still get the curated discovery timeout, got nil", id)
		}
	}
}

// TestResourceProfileForT1652AndT1120Added proves the 2026-08-26 expansion
// audit's two additions are labelled: T1652 (Device Driver Discovery, clean --
// kextstat/lsmod/driverquery/a find scoped to a known kernel-modules dir, all
// local and fast) and T1120 (Peripheral Device Discovery, kept with a narrow
// exception -- see resource.go's inline comment for the one atomic that
// downloads and runs a third-party script).
func TestResourceProfileForT1652AndT1120Added(t *testing.T) {
	for _, id := range []string{"T1652", "T1120"} {
		if p := ResourceProfileFor(id); p == nil {
			t.Errorf("%s should be labelled after the 2026-08-26 expansion audit, got nil", id)
		}
		if p := TimeoutProfileFor(id); p == nil {
			t.Errorf("%s should get the curated discovery timeout, got nil", id)
		}
	}
}

// TestResourceProfileForExpansionCandidatesExcluded proves the three
// candidates the 2026-08-26 audit ruled out stay unlabeled: T1201 (3/11
// atomics hit the network/AD -- net accounts /domain, a PowerSploit download,
// get-addefaultdomainpasswordpolicy), T1217 (5/11 atomics do a full
// filesystem `find /` walk, T1083's exact problem), and T1654 (Get-EventLog
// against the Security log is a well-known slow operation, 1/2 atomics).
func TestResourceProfileForExpansionCandidatesExcluded(t *testing.T) {
	for _, id := range []string{"T1201", "T1217", "T1654"} {
		if p := ResourceProfileFor(id); p != nil {
			t.Errorf("%s should stay unlabeled (2026-08-26 audit excluded it), got %+v", id, p)
		}
	}
}

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

// TestResourceProfileForRemovedNetworkHeavyTechniquesAreUnlabeled proves
// T1046 and T1614 were deliberately removed from the curated discovery set
// (2026-08-20 audit, verified against real production ART command text) --
// both must stay unlabeled so a step keeps its own declared timeout_sec
// instead of being force-capped at 20s and misclassified as a timeout.
//   - T1046 (Network Service Discovery): active network port scans (a
//     65535-port sequential bash scan, an nmap /24 sweep + telnet + nc, a
//     full-range nmap -sV scan) -- 3 of 3 atomics.
//   - T1614 (System Location Discovery): `curl -k https://ipinfo.io/` with
//     no --max-time flag, on BOTH platforms (2 of 2 atomics) -- a blocked/
//     dropped egress connection to that external service can hang far past
//     20s, especially on an egress-filtered production endpoint.
func TestResourceProfileForRemovedNetworkHeavyTechniquesAreUnlabeled(t *testing.T) {
	for _, id := range []string{"T1046", "T1614"} {
		if p := ResourceProfileFor(id); p != nil {
			t.Errorf("%s must be unlabeled (no curated resource profile), got %+v", id, p)
		}
		if p := TimeoutProfileFor(id); p != nil {
			t.Errorf("%s must not get the curated 20s discovery timeout, got %+v", id, p)
		}
	}
}

// TestResourceProfileForT1083IsUnlabeled proves T1083 (File and Directory
// Discovery) was deliberately removed: 7 of 9 real Linux/Windows atomics are
// unbounded recursive filesystem walks (`dir /s c:\` -- the entire system
// drive; `find` over the whole $HOME tree; bare `Get-ChildItem -Recurse`),
// not sub-second reads. A large real filesystem can take minutes, not
// seconds, to enumerate -- same failure mode as T1046/T1614 above.
func TestResourceProfileForT1083IsUnlabeled(t *testing.T) {
	if p := ResourceProfileFor("T1083"); p != nil {
		t.Errorf("T1083 must be unlabeled (no curated resource profile), got %+v", p)
	}
	if p := TimeoutProfileFor("T1083"); p != nil {
		t.Errorf("T1083 must not get the curated 20s discovery timeout, got %+v", p)
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

// TestTimeoutProfileForT1018Override is the regression test for the Step C
// evidence-backed override: staging recorded a real T1018 termination at
// 20,011ms with silenceMs=0 (actively producing output, not wedged) against
// the shared 20s discoveryTimeout, then a second termination at 300,268ms
// (again silenceMs=0) against the first 300s budget. See project memory:
// project_timeout_scored_as_pass.md.
func TestTimeoutProfileForT1018Override(t *testing.T) {
	got := TimeoutProfileFor("T1018")
	if got == nil {
		t.Fatal("T1018 should still get a curated timeout")
	}
	if got.ExecuteSec != 600 {
		t.Errorf("T1018 ExecuteSec = %d, want 600 (evidence-backed override, not the shared 20s discovery default)", got.ExecuteSec)
	}
	if got.ScheduleSec <= got.ExecuteSec {
		t.Errorf("T1018 ScheduleSec = %d must exceed ExecuteSec = %d, or a queued sibling's own schedule bound expires before this step can finish", got.ScheduleSec, got.ExecuteSec)
	}
	// Other discovery techniques must be unaffected by the override.
	other := TimeoutProfileFor("T1082")
	if other.ExecuteSec != 20 {
		t.Errorf("T1082 ExecuteSec = %d, want unchanged 20s -- the T1018 override must not leak to other techniques", other.ExecuteSec)
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
	// observesFootprint is present because T1057 reads the process table, which
	// every concurrently running step perturbs. Reads/Writes are absent here
	// (omitempty) since this technique still uses the per-technique form.
	const want = `{"domains":[{"domain":"process"}],"scope":"local","risk":"observation","observesFootprint":true}`
	if string(raw) != want {
		t.Errorf("wire shape drift:\n got %s\nwant %s", raw, want)
	}
}

// Process Discovery observes BAS's own execution footprint: under concurrency
// `ps aux` returns the agent's other in-flight atomics, so its evidence is
// contaminated by the very parallelism that makes it fast. It was shipped as a
// plain observation, i.e. parallel-safe, which is a bug in that model rather
// than a trade-off worth keeping.
//
// The footprint barrier is what expresses this: no other step declares "I write
// the process table", yet every step does simply by running.
func TestResourceProfileFor_ProcessDiscoveryObservesFootprint(t *testing.T) {
	p := ResourceProfileFor("T1057")
	if p == nil {
		t.Fatal("T1057 has no profile")
	}
	if !p.ObservesFootprint {
		t.Error("T1057 (Process Discovery) must be marked ObservesFootprint — its evidence includes BAS's own processes")
	}
}

// Techniques that do NOT read the footprint must stay ordinary observations, or
// marking becomes a blanket serializer and the parallelism is lost.
func TestResourceProfileFor_NonFootprintObserversAreUnmarked(t *testing.T) {
	for _, id := range []string{"T1012", "T1016"} {
		p := ResourceProfileFor(id)
		if p == nil {
			continue // not in the curated set; nothing to assert
		}
		if p.ObservesFootprint {
			t.Errorf("%s must not be marked ObservesFootprint — it does not observe BAS's execution surface", id)
		}
	}
}
