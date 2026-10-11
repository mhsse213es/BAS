package rwevidence

import (
	"errors"
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

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

func TestEvaluateStep_T1490Attempt_ProducesCompleteCapabilitySet(t *testing.T) {
	in := StepInput{
		RunID: "r1", Action: "aaa11111", TechniqueID: "T1490", StepName: "VSS Shadow Copy Deletion via WMI",
		CheckResult: "fail", Details: "FAIL: deleted 1 shadow copy, control did not intervene",
	}
	deps := StepDependencies{
		Prevention: &controlval.FakeProvider{ProviderName: "microsoft_defender", Obs: map[string]controlval.Observation{
			"aaa11111": {Outcome: controlval.OutcomeAllowed, EvidenceKind: controlval.EvidenceObserved, Confidence: controlval.ConfidenceHigh},
		}},
		Recovery:       &FakeRecoveryObserver{Results: map[string]SurvivalResult{recoveryKey(AttemptKey{RunID: "r1", TechniqueID: "T1490", Action: "aaa11111"}): SurvivalLost}},
		Containment:    &FakeContainmentObserver{},
		Detection:      &FakeDetectionLookup{},
		DataProtection: &FakeDataProtectionLookup{},
	}
	results := EvaluateStep(in, deps)

	byCapability := map[Capability]CapabilityResult{}
	for _, r := range results {
		byCapability[r.Capability] = r
	}
	if len(results) != 5 {
		t.Fatalf("got %d results, want 5 (one per capability, not_applicable/undecided included)", len(results))
	}
	if byCapability[CapabilityPrevention].Verdict != controlval.VerdictFail {
		t.Errorf("prevention = %+v, want FAIL (Defender allowed the attempt)", byCapability[CapabilityPrevention])
	}
	if byCapability[CapabilityRecovery].Verdict != controlval.VerdictFail {
		t.Errorf("recovery = %+v, want FAIL (SurvivalLost)", byCapability[CapabilityRecovery])
	}
	if byCapability[CapabilityContainment].SkipReason != controlval.SkipNotApplicable {
		t.Errorf("containment = %+v, want SKIPPED/not_applicable (T1490 has no Containment dimension)", byCapability[CapabilityContainment])
	}
	if byCapability[CapabilityDataProtection].SkipReason != controlval.SkipNotApplicable {
		t.Errorf("data_protection = %+v, want SKIPPED/not_applicable", byCapability[CapabilityDataProtection])
	}
	for _, r := range results {
		if r.TechniqueID != "T1490" {
			t.Errorf("%s: techniqueID = %q, want T1490", r.Capability, r.TechniqueID)
		}
	}
}

func TestEvaluateStep_T1567002Attempt_UndecidedCapabilitiesAreApplicabilityUndecided(t *testing.T) {
	in := StepInput{
		RunID: "r1", Action: "ccc33333", TechniqueID: "T1567.002", StepName: "Cloud Storage Egress Reachability",
		CheckResult: "fail", Details: "FAIL: reachable",
	}
	deps := StepDependencies{
		Prevention:     &controlval.FakeProvider{},
		Recovery:       &FakeRecoveryObserver{},
		Containment:    &FakeContainmentObserver{},
		Detection:      &FakeDetectionLookup{},
		DataProtection: &FakeDataProtectionLookup{Status: map[string]string{"r1/T1567.002/ccc33333": "NotDetected"}},
	}
	results := EvaluateStep(in, deps)
	byCapability := map[Capability]CapabilityResult{}
	for _, r := range results {
		byCapability[r.Capability] = r
	}
	for _, cap := range []Capability{CapabilityPrevention, CapabilityRecovery, CapabilityDetection} {
		r := byCapability[cap]
		if r.Verdict != controlval.VerdictSkipped || r.SkipReason != controlval.SkipNotTested {
			t.Errorf("%s = %+v, want SKIPPED/not_tested (applicability_undecided)", cap, r)
		}
	}
	if byCapability[CapabilityDataProtection].Verdict != controlval.VerdictFail {
		t.Errorf("data_protection = %+v, want FAIL (NotDetected)", byCapability[CapabilityDataProtection])
	}
}

func TestEvaluateStep_T1486Attempt_DataProtectionIsApplicabilityUndecided(t *testing.T) {
	// The other half of acceptance criterion 11 -- T1567.002's test above
	// covers its 3 undecided capabilities, this covers T1486's 1 (Recovery
	// is a DECIDED not_applicable for T1486, tested separately; DataProtection
	// was never decided either way).
	in := StepInput{
		RunID: "r1", Action: "eee55555", TechniqueID: "T1486", StepName: "Ransomware Payload Simulation",
		CheckResult: "fail", Details: "FAIL: files encrypted",
	}
	deps := StepDependencies{
		Prevention: &controlval.FakeProvider{}, Recovery: &FakeRecoveryObserver{},
		Containment: &FakeContainmentObserver{}, Detection: &FakeDetectionLookup{}, DataProtection: &FakeDataProtectionLookup{},
	}
	results := EvaluateStep(in, deps)
	var dataProtection, recovery CapabilityResult
	for _, r := range results {
		if r.Capability == CapabilityDataProtection {
			dataProtection = r
		}
		if r.Capability == CapabilityRecovery {
			recovery = r
		}
	}
	if dataProtection.Verdict != controlval.VerdictSkipped || dataProtection.SkipReason != controlval.SkipNotTested || dataProtection.SpecificReason != "applicability_undecided" {
		t.Fatalf("data_protection = %+v, want SKIPPED/not_tested/applicability_undecided", dataProtection)
	}
	if recovery.SpecificReason == "applicability_undecided" {
		t.Fatal("recovery is a DECIDED not_applicable for T1486, not an undecided case -- must not share recovery's specificReason with dataProtection's")
	}
}

func TestEvaluateStep_NotAnAttempt_ReturnsNotTestedForAllFiveCapabilities(t *testing.T) {
	in := StepInput{RunID: "r1", Action: "bbb22222", TechniqueID: "T1490", StepName: "VSS Snapshot Enumeration", CheckResult: "pass"}
	results := EvaluateStep(in, StepDependencies{})
	if len(results) != 5 {
		t.Fatalf("got %d results, want 5", len(results))
	}
	for _, r := range results {
		if r.Verdict != controlval.VerdictSkipped || r.SkipReason != controlval.SkipNotTested {
			t.Errorf("%s = %+v, want SKIPPED/not_tested", r.Capability, r)
		}
	}
}

func TestEvaluateStep_EvaluatorErrorIsDistinctFromNotInvoked(t *testing.T) {
	// Acceptance criterion 7: an evaluator that ran and failed operationally
	// (ERROR) must be provably distinct from a capability that was never
	// invoked at all (SKIPPED/not_tested), even within the same result set.
	in := StepInput{
		RunID: "r1", Action: "ddd44444", TechniqueID: "T1486", StepName: "Ransomware Payload Simulation",
		CheckResult: "fail", Details: "FAIL: files encrypted",
	}
	key := recoveryKey(AttemptKey{RunID: "r1", TechniqueID: "T1486", Action: "ddd44444"})
	deps := StepDependencies{
		Prevention:     &controlval.FakeProvider{},
		Recovery:       &FakeRecoveryObserver{}, // T1486: not_applicable, never invoked
		Containment:    &FakeContainmentObserver{},
		Detection:      &FakeDetectionLookup{Err: map[string]error{key: errors.New("detection profile service unreachable")}},
		DataProtection: &FakeDataProtectionLookup{}, // T1486: applicability_undecided, never invoked
	}
	results := EvaluateStep(in, deps)
	byCapability := map[Capability]CapabilityResult{}
	for _, r := range results {
		byCapability[r.Capability] = r
	}

	detection := byCapability[CapabilityDetection]
	if detection.Verdict != controlval.VerdictError {
		t.Fatalf("detection = %+v, want ERROR (the lookup was invoked and failed operationally)", detection)
	}
	recovery := byCapability[CapabilityRecovery]
	if recovery.Verdict != controlval.VerdictSkipped || recovery.SkipReason != controlval.SkipNotApplicable {
		t.Fatalf("recovery = %+v, want SKIPPED/not_applicable (never invoked at all, not an evaluation failure)", recovery)
	}
	if detection.Verdict == recovery.Verdict {
		t.Fatal("an evaluator that ran and errored must not be indistinguishable from one that was never invoked")
	}
}

func TestEvaluateStep_UnmodeledTechnique_ReturnsNotTestedForAllFiveCapabilities(t *testing.T) {
	in := StepInput{RunID: "r1", Action: "zzz99999", TechniqueID: "T1059", StepName: "PowerShell Execution", CheckResult: "fail"}
	results := EvaluateStep(in, StepDependencies{})
	if len(results) != 5 {
		t.Fatalf("got %d results, want 5", len(results))
	}
	for _, r := range results {
		if r.SkipReason != controlval.SkipNotTested {
			t.Errorf("%s = %+v, want not_tested/technique_not_mapped", r.Capability, r)
		}
	}
}

func TestClassify_VetoedStepIsNeverTreatedAsAGenuineAttempt(t *testing.T) {
	// Audspect's own local destructive-action policy can veto a step's
	// execution independently of any scenario-authored safety gate
	// (scenario.Interpret's models.ResultVetoed, interpreter.go:75-89,
	// reachable for any framework). Without a dedicated branch here,
	// classifyRansomwareStep's `CheckResult != "skipped"` check treats a
	// vetoed step as a genuine attempt and routes it through the real
	// Prevention/Recovery/Detection/DataProtection evaluators, fabricating
	// PASS/FAIL findings for a technique Audspect never actually tried --
	// the exact bug class interpreter.go's own C1 fix comment describes.
	in := StepInput{
		TechniqueID: "T1490", StepName: "VSS Shadow Copy Deletion via WMI", RunID: "r1", Action: "x",
		CheckResult: "vetoed",
		Details:     "VETOED — Audspect prevented execution under its local destructive-action policy (action=vssadmin_delete_shadows, class=destructive, source=policy_b5). Customer defensive controls were not tested by this step.",
	}
	modeled, isAttempt, specificReason := classifyRansomwareStep(in)
	if !modeled {
		t.Fatal("T1490 is modeled")
	}
	if isAttempt {
		t.Fatal("a vetoed step was never actually attempted -- it must not be classified as an attempt")
	}
	if specificReason != "vetoed_by_policy" {
		t.Fatalf("specificReason = %q, want vetoed_by_policy", specificReason)
	}
}
