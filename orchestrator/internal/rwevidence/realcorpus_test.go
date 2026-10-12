package rwevidence

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/scenario"
)

var ransomwareScenarioFiles = []string{
	"akira-kill-chain.yaml", "blackcat-kill-chain.yaml", "clop-kill-chain.yaml",
	"lockbit-kill-chain.yaml", "play-kill-chain.yaml", "ransomhub-kill-chain.yaml",
	"ransomware-drill.yaml", "endpoint-mastery/em-07-ransomware-readiness.yaml",
	"linux-ransomware-drill.yaml", "black-basta-kill-chain.yaml", "medusa-kill-chain.yaml",
}

// repoScenariosDir resolves ../../../scenarios relative to this package,
// same relative path adcoverage's real-corpus test already uses
// successfully (internal/adcoverage/index_test.go) -- reused, not
// reinvented.
func repoScenariosDir(t *testing.T) string {
	dir, err := filepath.Abs("../../../scenarios")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("scenarios dir not found at %s: %v", dir, err)
	}
	return dir
}

func loadRealSteps(t *testing.T, filename string) []scenario.Step {
	// scenario.ParseYAML (internal/scenario/engine.go:274) takes raw bytes
	// and returns *Scenario{..., Steps []Step}; confirmed against the real
	// function during planning rather than assumed.
	b, err := os.ReadFile(filepath.Join(repoScenariosDir(t), filename))
	if err != nil {
		t.Fatalf("%s: %v", filename, err)
	}
	sc, err := scenario.ParseYAML(b)
	if err != nil {
		t.Fatalf("%s: %v", filename, err)
	}
	return sc.Steps
}

func TestRealCorpus_EveryTechniqueTaggedStepIsAccountedFor(t *testing.T) {
	for _, file := range ransomwareScenarioFiles {
		steps := loadRealSteps(t, file)
		for _, step := range steps {
			if step.TechniqueID == "" {
				continue // not every step is technique-tagged (e.g. check_id-only posture checks)
			}
			in := StepInput{RunID: "corpus-test", Action: scenario.TaskID(step.TechniqueID, step.Name), TechniqueID: step.TechniqueID, StepName: step.Name, CheckResult: "fail"}
			// &controlval.FakeProvider{} (nil Obs/Err maps) is safe -- nil-map
			// lookups in Go return the zero value with ok=false, so Observe
			// returns Observation{}, nil for any key. Confirmed against
			// controlval/provider.go rather than assumed.
			results := EvaluateStep(in, StepDependencies{Prevention: &controlval.FakeProvider{}, Recovery: &FakeRecoveryObserver{}, Containment: &FakeContainmentObserver{}, Detection: &FakeDetectionLookup{}, DataProtection: &FakeDataProtectionLookup{}})
			if len(results) != 5 {
				t.Errorf("%s / %q (technique %s): got %d results, want 5 -- every technique-tagged step must be fully accounted for", file, step.Name, step.TechniqueID, len(results))
			}
		}
	}
}

func TestRealCorpus_EM07ThreeT1490StepsStayIndependent(t *testing.T) {
	steps := loadRealSteps(t, "endpoint-mastery/em-07-ransomware-readiness.yaml")
	var t1490Steps []scenario.Step
	for _, s := range steps {
		if s.TechniqueID == "T1490" {
			t1490Steps = append(t1490Steps, s)
		}
	}
	if len(t1490Steps) != 3 {
		t.Fatalf("got %d T1490 steps in em-07, want 3 (shadow-copy deletion, wbadmin catalog delete, bcdedit disable)", len(t1490Steps))
	}

	recoveryObs := &FakeRecoveryObserver{Results: map[string]SurvivalResult{}}
	actions := make([]string, 3)
	for i, s := range t1490Steps {
		actions[i] = scenario.TaskID(s.TechniqueID, s.Name)
		recoveryObs.Results[recoveryKey(AttemptKey{RunID: "r1", TechniqueID: "T1490", Action: actions[i]})] = []SurvivalResult{SurvivalConfirmed, SurvivalLost, SurvivalIndeterminate}[i]
	}
	if actions[0] == actions[1] || actions[1] == actions[2] || actions[0] == actions[2] {
		t.Fatalf("em-07's three T1490 steps produced colliding action IDs: %v -- dedupeStepIdentity should have prevented this", actions)
	}

	for i, s := range t1490Steps {
		in := StepInput{RunID: "r1", Action: actions[i], TechniqueID: s.TechniqueID, StepName: s.Name, CheckResult: "fail"}
		deps := StepDependencies{Prevention: &controlval.FakeProvider{}, Recovery: recoveryObs, Containment: &FakeContainmentObserver{}, Detection: &FakeDetectionLookup{}, DataProtection: &FakeDataProtectionLookup{}}
		results := EvaluateStep(in, deps)
		var recovery CapabilityResult
		for _, r := range results {
			if r.Capability == CapabilityRecovery {
				recovery = r
			}
		}
		want := []controlval.Verdict{controlval.VerdictPass, controlval.VerdictFail, controlval.VerdictSkipped}[i]
		if recovery.Verdict != want {
			t.Errorf("step %q: recovery verdict = %q, want %q -- the three actions must not collapse into one shared result", s.Name, recovery.Verdict, want)
		}
	}
}

func TestRealCorpus_AkiraTwoDistinctT1490SkipPatterns(t *testing.T) {
	steps := loadRealSteps(t, "akira-kill-chain.yaml")
	var deletionStep scenario.Step
	for _, s := range steps {
		if s.TechniqueID == "T1490" && s.Name != "" && !reconnaissanceStepNames[s.Name] {
			deletionStep = s
		}
	}
	if deletionStep.Name == "" {
		t.Fatal("expected to find Akira's VSS shadow-copy-deletion step")
	}

	gateIn := StepInput{TechniqueID: "T1490", StepName: deletionStep.Name, CheckResult: "skipped",
		Details: "SKIP: BAS_CONFIRM_VSS_DELETE not set to 'true' - WMI-based VSS deletion skipped (default-disabled per ransomware safety policy)."}
	_, _, gateReason := classifyRansomwareStep(gateIn)
	if gateReason != "gate_not_confirmed" {
		t.Errorf("gate-skip case: specificReason = %q, want gate_not_confirmed", gateReason)
	}

	targetIn := StepInput{TechniqueID: "T1490", StepName: deletionStep.Name, CheckResult: "skipped",
		Details: "SKIP: no C: VSS shadow copies exist - nothing to delete. Create a snapshot first with: vssadmin create shadow /for=C:"}
	_, _, targetReason := classifyRansomwareStep(targetIn)
	if targetReason != "no_target_precondition" {
		t.Errorf("no-target case: specificReason = %q, want no_target_precondition", targetReason)
	}
	if gateReason == targetReason {
		t.Fatal("two genuinely different skip reasons on the same real step must not classify identically")
	}
}
