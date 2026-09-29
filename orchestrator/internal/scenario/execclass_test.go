package scenario

import (
	"path/filepath"
	"testing"
)

func TestResolveExecutionClass_ExactMatch(t *testing.T) {
	got := ResolveExecutionClass("T1490", "vss_delete")
	if got.Class != ClassDestructive {
		t.Errorf("T1490:vss_delete class = %q, want %q", got.Class, ClassDestructive)
	}
	if got.DestructiveAction != "vss_delete" {
		t.Errorf("DestructiveAction = %q, want %q", got.DestructiveAction, "vss_delete")
	}
	if got.BlastRadius == "" {
		t.Error("BlastRadius is empty for a destructive action -- must describe the real impact")
	}
}

func TestResolveExecutionClass_NoActionKeyFallsBackToDefault(t *testing.T) {
	// Seed a technique with only a "default" entry, via a technique known to
	// have exactly one behavior. T1082 (System Information Discovery) is
	// already proven read-only in resource.go's discoveryProfiles.
	got := ResolveExecutionClass("T1082", "")
	if got.Class != ClassNonDestructive {
		t.Errorf("T1082 (no action_key) class = %q, want %q", got.Class, ClassNonDestructive)
	}
}

func TestResolveExecutionClass_UnknownActionKeyFailsClosed(t *testing.T) {
	// T1490 has curated entries, but not this action_key -- must NOT fall
	// back to a technique-wide default. This is the exact ambiguity the
	// catalog exists to eliminate.
	got := ResolveExecutionClass("T1490", "totally_unreviewed_action")
	if got.Class != ClassDestructive {
		t.Errorf("unknown action_key under a partially-catalogued technique = %q, want %q (fail closed)", got.Class, ClassDestructive)
	}
}

func TestResolveExecutionClass_UnknownTechniqueFailsClosed(t *testing.T) {
	got := ResolveExecutionClass("T9999", "anything")
	if got.Class != ClassDestructive {
		t.Errorf("wholly unknown technique class = %q, want %q (fail closed)", got.Class, ClassDestructive)
	}
}

func TestResolveExecutionClass_CaseNormalization(t *testing.T) {
	// Mirrors ResourceProfileFor's existing strings.ToUpper/TrimSpace handling
	// for technique IDs (resource.go) -- action_key normalization is new here.
	got := ResolveExecutionClass("t1490", "VSS_DELETE")
	if got.Class != ClassDestructive {
		t.Errorf("case-insensitive lookup failed: class = %q, want %q", got.Class, ClassDestructive)
	}
}

// resource.go's discoveryProfiles map is 15 ATT&CK discovery techniques
// already audited against real production ART command text and proven
// read-only/non-mutating (see that map's own doc comment -- the
// "2026-08-20 audit" and "2026-08-26 expansion audit" entries). Final
// whole-branch review finding C2: the plan's own Task 10 Step 2 intended
// to reuse this proven-safe set as "default" ClassNonDestructive catalog
// entries (so a step with no hand-authored action_key annotation for one
// of these techniques doesn't fail closed to destructive), but this step
// was skipped. T1120 is deliberately excluded here even though it
// remains in discoveryProfiles: discoveryProfiles labels it read-only
// for RESOURCE/concurrency purposes only (ResourceProfile's Risk field),
// but one of its four real atomics (the "WinPwn - printercheck" test)
// downloads and executes an arbitrary third-party script
// (iex(new-object net.webclient).downloadstring(...)) -- genuinely
// unverifiable destructiveness, the exact ambiguity this whole catalog
// exists to fail closed on. T1082 already has its own "default" entry
// (Task 1's seed), so it's checked here too rather than skipped, to
// confirm this task doesn't accidentally duplicate/conflict with it.
func TestExecutionClassifications_DiscoveryProfilesDefaultToNonDestructive(t *testing.T) {
	for _, tid := range []string{
		"T1012", "T1057", "T1007", "T1518", "T1010", "T1082", "T1033",
		"T1124", "T1016", "T1049", "T1018", "T1087", "T1069", "T1652",
	} {
		got := ResolveExecutionClass(tid, "")
		if got.Class != ClassNonDestructive {
			t.Errorf("%s (no action_key, discoveryProfiles-derived default) class = %q, want %q", tid, got.Class, ClassNonDestructive)
		}
	}
}

// T1120 must NOT inherit a blanket non_destructive default despite being
// in discoveryProfiles -- see the doc comment above.
func TestExecutionClassifications_T1120DoesNotDefaultToNonDestructive(t *testing.T) {
	got := ResolveExecutionClass("T1120", "")
	if got.Class == ClassNonDestructive {
		t.Error("T1120 (no action_key) must not default to non_destructive -- one of its real atomics downloads and executes an arbitrary third-party script, unverifiable destructiveness")
	}
}

func TestAttachExecutionClassifications(t *testing.T) {
	steps := []ScenarioStep{
		{TechniqueID: "T1490", ActionKey: "vss_delete"},
		{TechniqueID: "T1082"}, // no action_key -> "default"
		{TechniqueID: "T9999"}, // wholly unknown -> fail closed
	}
	AttachExecutionClassifications(steps)

	if steps[0].ExecutionClass != ClassDestructive {
		t.Errorf("steps[0].ExecutionClass = %q, want %q", steps[0].ExecutionClass, ClassDestructive)
	}
	if steps[0].DestructiveAction != "vss_delete" {
		t.Errorf("steps[0].DestructiveAction = %q, want %q", steps[0].DestructiveAction, "vss_delete")
	}
	if steps[1].ExecutionClass != ClassNonDestructive {
		t.Errorf("steps[1].ExecutionClass = %q, want %q", steps[1].ExecutionClass, ClassNonDestructive)
	}
	if steps[2].ExecutionClass != ClassDestructive {
		t.Errorf("steps[2].ExecutionClass = %q, want %q (fail closed)", steps[2].ExecutionClass, ClassDestructive)
	}
}

// TestExecutionClassifications_HandAuthoredCorpusIsNotUnderclassified is the
// Task 10 completeness check for the hand-authored scenario corpus (the
// only part of the full technique library reachable in this session --
// see the plan's Task 10 for why the ART/Caldera corpora remain
// unaudited pending live infrastructure access). Loads every real,
// shipped scenario YAML file and asserts that every step whose
// action_key was set during this audit resolves to the specific,
// intended classification -- not silently falling back to the
// fail-closed "unclassified" default because of a YAML typo or a
// resign that didn't take.
func TestExecutionClassifications_HandAuthoredCorpusIsNotUnderclassified(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "scenarios"))
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(dir)
	if err := e.Load(); err != nil {
		t.Fatalf("engine load: %v", err)
	}

	type want struct {
		class  ExecutionClass
		action string
	}
	// Every (technique_id, action_key) pair this audit annotated in real
	// scenario YAML, and the classification each MUST resolve to.
	expected := map[string]map[string]want{
		"T1490": {
			"enumerate":                   {ClassNonDestructive, ""},
			"backup_readiness_check":      {ClassNonDestructive, ""},
			"vss_delete":                  {ClassDestructive, "vss_delete"},
			"wbadmin_delete_catalog":      {ClassDestructive, "wbadmin_delete_catalog"},
			"bootloader_recovery_disable": {ClassDestructive, "bootloader_recovery_disable"},
		},
		"T1489":     {"backup_service_stop": {ClassDestructive, "backup_service_stop"}},
		"T1562.001": {"stop_auditd": {ClassPotentiallyDestructive, ""}},
		"T1569.002": {"service_create_start_stop_delete": {ClassPotentiallyDestructive, ""}},
		"T1003.003": {"enumerate": {ClassNonDestructive, ""}},
	}

	found := map[string]map[string]bool{}
	for _, sc := range e.List() {
		for _, step := range sc.Steps {
			techByAction, ok := expected[step.TechniqueID]
			if !ok || step.ActionKey == "" {
				continue
			}
			w, ok := techByAction[step.ActionKey]
			if !ok {
				continue
			}
			if found[step.TechniqueID] == nil {
				found[step.TechniqueID] = map[string]bool{}
			}
			found[step.TechniqueID][step.ActionKey] = true

			got := ResolveExecutionClass(step.TechniqueID, step.ActionKey)
			if got.Class != w.class {
				t.Errorf("%s (%s, action_key=%s): Class = %q, want %q",
					sc.ID, step.TechniqueID, step.ActionKey, got.Class, w.class)
			}
			if got.DestructiveAction != w.action {
				t.Errorf("%s (%s, action_key=%s): DestructiveAction = %q, want %q",
					sc.ID, step.TechniqueID, step.ActionKey, got.DestructiveAction, w.action)
			}
		}
	}

	// Every expected pair must have actually been found in at least one
	// real scenario -- otherwise this test would pass vacuously if a
	// scenario file failed to load (signature drift) or a sed edit landed
	// in the wrong place.
	for tid, actions := range expected {
		for action := range actions {
			if !found[tid][action] {
				t.Errorf("expected to find a real scenario step with technique_id=%s action_key=%s, found none -- scenario load may have silently failed, or the action_key edit didn't land", tid, action)
			}
		}
	}
}
