package rwevidence

import "testing"

func TestClassify_UnmodeledTechnique(t *testing.T) {
	in := StepInput{TechniqueID: "T1059", StepName: "PowerShell Execution", RunID: "r1", Action: "x", CheckResult: "fail"}
	modeled, isAttempt, specificReason := classifyRansomwareStep(in)
	if modeled {
		t.Fatal("T1059 is not one of the 3 modeled techniques")
	}
	if isAttempt {
		t.Fatal("an unmodeled technique is never classified as an attempt")
	}
	if specificReason != "technique_not_mapped" {
		t.Fatalf("specificReason = %q, want technique_not_mapped", specificReason)
	}
}

func TestClassify_ReconnaissanceStep(t *testing.T) {
	in := StepInput{TechniqueID: "T1490", StepName: "VSS Snapshot Enumeration", RunID: "r1", Action: "x", CheckResult: "pass"}
	modeled, isAttempt, specificReason := classifyRansomwareStep(in)
	if !modeled {
		t.Fatal("T1490 is modeled")
	}
	if isAttempt {
		t.Fatal("an enumeration step is not an attempt")
	}
	if specificReason != "not_an_attempt" {
		t.Fatalf("specificReason = %q, want not_an_attempt", specificReason)
	}
}

func TestClassify_GateNotConfirmed(t *testing.T) {
	in := StepInput{
		TechniqueID: "T1490", StepName: "VSS Shadow Copy Deletion via WMI", RunID: "r1", Action: "x",
		CheckResult: "skipped",
		Details:     "SKIP: BAS_CONFIRM_VSS_DELETE not set to 'true' - WMI-based VSS deletion skipped (default-disabled per ransomware safety policy).",
	}
	modeled, isAttempt, specificReason := classifyRansomwareStep(in)
	if !modeled || !isAttempt {
		t.Fatalf("modeled=%v isAttempt=%v, want true/true (this IS the destructive attempt step, it just didn't run)", modeled, isAttempt)
	}
	if specificReason != "gate_not_confirmed" {
		t.Fatalf("specificReason = %q, want gate_not_confirmed", specificReason)
	}
}

func TestClassify_NoTargetPrecondition(t *testing.T) {
	in := StepInput{
		TechniqueID: "T1490", StepName: "VSS Shadow Copy Deletion via WMI", RunID: "r1", Action: "x",
		CheckResult: "skipped",
		Details:     "SKIP: no C: VSS shadow copies exist - nothing to delete. Create a snapshot first with: vssadmin create shadow /for=C:",
	}
	modeled, isAttempt, specificReason := classifyRansomwareStep(in)
	if !modeled || !isAttempt {
		t.Fatalf("modeled=%v isAttempt=%v, want true/true", modeled, isAttempt)
	}
	if specificReason != "no_target_precondition" {
		t.Fatalf("specificReason = %q, want no_target_precondition", specificReason)
	}
}

func TestClassify_UnrecognizedSkipFallsBackConservatively(t *testing.T) {
	in := StepInput{
		TechniqueID: "T1490", StepName: "VSS Shadow Copy Deletion via WMI", RunID: "r1", Action: "x",
		CheckResult: "skipped",
		Details:     "SKIP: some future condition this classifier has never seen before",
	}
	modeled, isAttempt, specificReason := classifyRansomwareStep(in)
	if !modeled || !isAttempt {
		t.Fatalf("modeled=%v isAttempt=%v, want true/true", modeled, isAttempt)
	}
	if specificReason != "skip_unclassified" {
		t.Fatalf("specificReason = %q, want skip_unclassified -- an unrecognized skip must never be guessed into gate_not_confirmed", specificReason)
	}
}

func TestClassify_AttemptThatRan(t *testing.T) {
	in := StepInput{
		TechniqueID: "T1490", StepName: "VSS Shadow Copy Deletion via WMI", RunID: "r1", Action: "x",
		CheckResult: "fail",
		Details:     "FAIL: deleted 1 shadow copy, control did not intervene",
	}
	modeled, isAttempt, specificReason := classifyRansomwareStep(in)
	if !modeled || !isAttempt {
		t.Fatalf("modeled=%v isAttempt=%v, want true/true", modeled, isAttempt)
	}
	if specificReason != "" {
		t.Fatalf("specificReason = %q, want empty -- this attempt ran, there's no coverage-gap reason to record", specificReason)
	}
}
