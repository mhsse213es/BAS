package scenario

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Step contract, class-aware.
//
// The action catalog (execclass.go) is the source of truth for whether a step changes anything:
//
//   - non_destructive: no cleanup is required (read-only probes, enumeration). Not a gap.
//   - potentially_destructive, destructive: the step must show one of:
//     1. an undo: a cleanup command in the step, or a catalog-verified undo;
//     2. reversible: true (self-cleaning, verified by the author);
//     3. irreversible: a reason of at least 20 characters explaining why no undo exists.
//     Anything else is a gap.
//
// Provenance matters. A cleanup that lives in the external Atomic Red Team library (framework: art) or in
// Caldera content is NOT verified by this repository. Such a step stays a gap until the library is pinned and
// its cleanup is recorded, so the gap is never hidden. Repository-verified cleanup is what the YAML itself declares.
//
// Detection and telemetry expectations are unchanged from the earlier ratchet. Each file's gap counts may fall but
// must never rise against testdata/step_contract_baseline.json. Regenerate the baselines with
// STEP_CONTRACT_WRITE=1 only to record improvements.
//
// This test changes no runtime behaviour: the loader, the execution path and every score are untouched.

const (
	stepContractBaseline  = "testdata/step_contract_baseline.json"
	stepContractLedger    = "testdata/step_contract_ledger.json"
	minIrreversibleReason = 20
)

// cleanupStatus is the contract's answer for one step.
type cleanupStatus string

const (
	statusNotRequired           cleanupStatus = "not_required_non_destructive"
	statusUndoDeclared          cleanupStatus = "undo_declared_in_yaml"
	statusSelfCleaning          cleanupStatus = "self_cleaning_declared"
	statusIrreversibleDeclared  cleanupStatus = "irreversible_declared"
	statusGapNoUndo             cleanupStatus = "gap_no_undo"
	statusGapIrreversibleNoWhy  cleanupStatus = "gap_irreversible_without_reason"
	statusGapExternalUnverified cleanupStatus = "gap_external_cleanup_unverified"
)

// isGap reports whether a status counts against the contract.
func (c cleanupStatus) isGap() bool {
	switch c {
	case statusGapNoUndo, statusGapIrreversibleNoWhy, statusGapExternalUnverified:
		return true
	}
	return false
}

// stepFramework returns the framework label, treating an empty one as native.
func stepFramework(s Step) string {
	if strings.TrimSpace(s.Framework) == "" {
		return "native"
	}
	return strings.ToLower(strings.TrimSpace(s.Framework))
}

// externalCleanupSource reports whether a step's undo would have to come from outside this repository.
func externalCleanupSource(s Step) bool {
	switch stepFramework(s) {
	case "art", "caldera":
		return true
	}
	return false
}

// classifyCleanup applies the class-aware contract to one step. The class comes from the catalog, never from the
// step's own declarations: an irreversible or reversible declaration cannot make a destructive action look safer.
func classifyCleanup(s Step) (class ExecutionClass, status cleanupStatus) {
	class = ResolveExecutionClass(s.TechniqueID, s.ActionKey).Class
	if class == ClassNonDestructive {
		return class, statusNotRequired
	}
	// A cleanup written in the scenario file is repository-declared, whatever the framework.
	if strings.TrimSpace(s.Cleanup) != "" {
		return class, statusUndoDeclared
	}
	if s.Reversible {
		return class, statusSelfCleaning
	}
	if strings.TrimSpace(s.Irreversible) != "" {
		if len(strings.TrimSpace(s.Irreversible)) >= minIrreversibleReason {
			return class, statusIrreversibleDeclared
		}
		return class, statusGapIrreversibleNoWhy
	}
	if externalCleanupSource(s) {
		return class, statusGapExternalUnverified
	}
	return class, statusGapNoUndo
}

// stepMissingDetection and stepMissingTelemetry keep the earlier, unchanged expectations.
func stepMissingDetection(s Step) bool { return len(s.Detection) == 0 }
func stepMissingTelemetry(s Step) bool { return len(s.Telemetry) == 0 }

// contractGaps is the per-file count of gaps by dimension.
type contractGaps struct {
	Cleanup   int `json:"cleanup"`
	Detection int `json:"detection"`
	Telemetry int `json:"telemetry"`
}

// ledgerEntry records one step's accounting. Every executable step with steps appears exactly once.
type ledgerEntry struct {
	Scenario    string         `json:"scenario"`
	Index       int            `json:"index"`
	TechniqueID string         `json:"technique_id"`
	ActionKey   string         `json:"action_key"`
	Framework   string         `json:"framework"`
	Class       ExecutionClass `json:"class"`
	Status      cleanupStatus  `json:"status"`
}

// contractScenarioDir is orchestrator/internal/scenario -> repo root -> scenarios/.
const contractScenarioDir = "../../../scenarios"

// measureContract walks the executable scenarios and returns per-file gap counts and a step ledger.
func measureContract(t *testing.T) (map[string]contractGaps, []ledgerEntry) {
	t.Helper()
	gaps := map[string]contractGaps{}
	var ledger []ledgerEntry
	err := filepath.Walk(contractScenarioDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var f struct {
			Executable *bool  `yaml:"executable"`
			ID         string `yaml:"id"`
			Steps      []Step `yaml:"steps"`
		}
		if err := yaml.Unmarshal(b, &f); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		if f.Executable == nil || !*f.Executable || len(f.Steps) == 0 {
			return nil
		}
		rel, err := filepath.Rel(contractScenarioDir, path)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		var g contractGaps
		for i, s := range f.Steps {
			class, status := classifyCleanup(s)
			if status.isGap() {
				g.Cleanup++
			}
			if stepMissingDetection(s) {
				g.Detection++
			}
			if stepMissingTelemetry(s) {
				g.Telemetry++
			}
			ledger = append(ledger, ledgerEntry{
				Scenario: key, Index: i, TechniqueID: s.TechniqueID, ActionKey: s.ActionKey,
				Framework: stepFramework(s), Class: class, Status: status,
			})
		}
		gaps[key] = g
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", contractScenarioDir, err)
	}
	sort.Slice(ledger, func(a, b int) bool {
		if ledger[a].Scenario != ledger[b].Scenario {
			return ledger[a].Scenario < ledger[b].Scenario
		}
		return ledger[a].Index < ledger[b].Index
	})
	return gaps, ledger
}

func readJSONFile(t *testing.T, path string, v interface{}) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

func writeJSONFile(t *testing.T, path string, v interface{}) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestStepContract_Ratchet enforces the contract against the real scenarios directory.
func TestStepContract_Ratchet(t *testing.T) {
	gaps, ledger := measureContract(t)
	if len(gaps) < 90 {
		// Guard against a vacuous pass if the directory moved or the walk found nothing.
		t.Fatalf("found only %d executable scenario files with steps; expected about 92", len(gaps))
	}
	if os.Getenv("STEP_CONTRACT_WRITE") == "1" {
		writeJSONFile(t, stepContractBaseline, gaps)
		writeJSONFile(t, stepContractLedger, ledger)
		t.Logf("baseline written with %d files and %d ledger entries", len(gaps), len(ledger))
		return
	}
	var base map[string]contractGaps
	readJSONFile(t, stepContractBaseline, &base)

	keys := make([]string, 0, len(gaps))
	for k := range gaps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		cur := gaps[k]
		old, known := base[k]
		if !known {
			if cur.Cleanup+cur.Detection+cur.Telemetry > 0 {
				t.Errorf("new scenario %s violates the step contract (cleanup %d, detection %d, telemetry %d)",
					k, cur.Cleanup, cur.Detection, cur.Telemetry)
			}
			continue
		}
		if cur.Cleanup > old.Cleanup || cur.Detection > old.Detection || cur.Telemetry > old.Telemetry {
			t.Errorf("%s regressed: cleanup %d->%d, detection %d->%d, telemetry %d->%d",
				k, old.Cleanup, cur.Cleanup, old.Detection, cur.Detection, old.Telemetry, cur.Telemetry)
		}
	}
}

// TestStepContract_LedgerAccountsForEveryStep checks the ledger matches the current scenarios, so a change to a
// scenario cannot silently shift the accounting. Regenerate with STEP_CONTRACT_WRITE=1 after a reviewed change.
func TestStepContract_LedgerAccountsForEveryStep(t *testing.T) {
	_, ledger := measureContract(t)
	var recorded []ledgerEntry
	readJSONFile(t, stepContractLedger, &recorded)
	if len(recorded) != len(ledger) {
		t.Fatalf("ledger has %d entries, scenarios now have %d steps; review and regenerate", len(recorded), len(ledger))
	}
	for i := range ledger {
		if ledger[i] != recorded[i] {
			t.Fatalf("ledger entry %d changed: recorded %+v, now %+v", i, recorded[i], ledger[i])
		}
	}
}

// TestStepContract_ThreeClasses checks the rule for each classification, using real catalog entries.
func TestStepContract_ThreeClasses(t *testing.T) {
	cases := []struct {
		name   string
		step   Step
		class  ExecutionClass
		status cleanupStatus
	}{
		// Non-destructive (T1003/enumerate): no cleanup needed, none declared.
		{"non-destructive", Step{TechniqueID: "T1003", ActionKey: "enumerate", Framework: "custom"},
			ClassNonDestructive, statusNotRequired},
		// Potentially destructive (T1053.005/schtask_create_delete): no undo is a gap.
		{"potentially destructive, no undo", Step{TechniqueID: "T1053.005", ActionKey: "schtask_create_delete", Framework: "custom"},
			ClassPotentiallyDestructive, statusGapNoUndo},
		// Destructive (T1490/vss_delete): an undo clears it; a declared irreversibility also clears it.
		{"destructive, no undo", Step{TechniqueID: "T1490", ActionKey: "vss_delete", Framework: "custom"},
			ClassDestructive, statusGapNoUndo},
		{"destructive, irreversible", Step{TechniqueID: "T1490", ActionKey: "vss_delete", Framework: "custom",
			Irreversible: "deleted shadow copies cannot be restored by any cleanup step"},
			ClassDestructive, statusIrreversibleDeclared},
		// Unknown pair: the catalog fails closed to destructive.
		{"unknown pair fails closed", Step{TechniqueID: "T9999", ActionKey: "no_such_action", Framework: "custom"},
			ClassDestructive, statusGapNoUndo},
	}
	for _, c := range cases {
		cls, st := classifyCleanup(c.step)
		if cls != c.class {
			t.Errorf("%s: class = %s, want %s", c.name, cls, c.class)
		}
		if st != c.status {
			t.Errorf("%s: status = %s, want %s", c.name, st, c.status)
		}
	}
}

// Missing undo is a gap; a cleanup command, self-cleaning declaration or irreversible declaration each clear it.
func TestStepContract_MissingUndoIsFailClosed(t *testing.T) {
	base := Step{TechniqueID: "T9999", ActionKey: "no_such_action", Framework: "custom"}
	if _, st := classifyCleanup(base); !st.isGap() {
		t.Error("destructive step with no undo must be a gap")
	}
	withCleanup := base
	withCleanup.Cleanup = "remove the test file"
	if _, st := classifyCleanup(withCleanup); st.isGap() {
		t.Error("a cleanup command must clear the gap")
	}
	selfClean := base
	selfClean.Reversible = true
	if _, st := classifyCleanup(selfClean); st.isGap() {
		t.Error("a self-cleaning declaration must clear the gap")
	}
}

// A valid irreversible declaration clears the gap; a missing or too-short reason does not.
func TestStepContract_IrreversibleDeclaration(t *testing.T) {
	base := Step{TechniqueID: "T9999", ActionKey: "no_such_action", Framework: "custom"}

	ok := base
	ok.Irreversible = "shadow copies cannot be restored once deleted"
	if _, st := classifyCleanup(ok); st != statusIrreversibleDeclared {
		t.Errorf("valid irreversible declaration status = %s, want %s", st, statusIrreversibleDeclared)
	}

	noReason := base
	noReason.Irreversible = "   "
	if _, st := classifyCleanup(noReason); st != statusGapNoUndo {
		t.Errorf("blank irreversible reason should be treated as no declaration, got %s", st)
	}

	short := base
	short.Irreversible = "n/a"
	if _, st := classifyCleanup(short); st != statusGapIrreversibleNoWhy {
		t.Errorf("too-short irreversible reason status = %s, want %s", st, statusGapIrreversibleNoWhy)
	}
}

// The declaration never changes the catalog class, so it cannot be used to make a destructive action look safer.
func TestStepContract_DeclarationDoesNotChangeClass(t *testing.T) {
	s := Step{TechniqueID: "T9999", ActionKey: "no_such_action", Framework: "custom", Reversible: true,
		Irreversible: "a long enough reason that claims nothing can be undone"}
	cls, _ := classifyCleanup(s)
	if cls != ClassDestructive {
		t.Errorf("class = %s after declarations, want destructive (catalog is the source of truth)", cls)
	}
}

// ART steps: cleanup lives in the external library, which is not verified here, so a missing undo stays a gap.
func TestStepContract_ARTCleanupIsExternallyUnverified(t *testing.T) {
	s := Step{TechniqueID: "T9999", ActionKey: "no_such_action", Framework: "art", TestIndex: 0}
	if _, st := classifyCleanup(s); st != statusGapExternalUnverified {
		t.Errorf("ART step status = %s, want %s (external cleanup must not pass silently)", st, statusGapExternalUnverified)
	}
	// A cleanup written in YAML on an ART step is repository-declared, so it counts.
	s.Cleanup = "rm -f /tmp/atomic-artifact"
	if _, st := classifyCleanup(s); st.isGap() {
		t.Errorf("an ART step with a repository-declared cleanup should not be a gap, got %s", st)
	}
}

// Detection and telemetry expectations: empty is a gap, listed is not.
func TestStepContract_DetectionAndTelemetry(t *testing.T) {
	if !stepMissingDetection(Step{}) || !stepMissingTelemetry(Step{}) {
		t.Error("an empty step should be missing detection and telemetry")
	}
	full := Step{Detection: []string{"EDR: process tree"}, Telemetry: []string{"Sysmon EID 1"}}
	if stepMissingDetection(full) || stepMissingTelemetry(full) {
		t.Error("a step that lists detection and telemetry should not be a gap")
	}
}
