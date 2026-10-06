package corpusaudit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestCommandHash_SameCommandSameHash(t *testing.T) {
	first, second := CommandHash("vssadmin delete shadows /all"), CommandHash("vssadmin delete shadows /all")
	if first != second {
		t.Error("expected identical commands to hash identically")
	}
	if CommandHash("vssadmin delete shadows /all") == CommandHash("vssadmin delete shadows /quiet") {
		t.Error("expected different commands to hash differently")
	}
}

func TestLoadReviewedDecisions_MissingFileReturnsEmpty(t *testing.T) {
	decisions, err := LoadReviewedDecisions(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(decisions) != 0 {
		t.Errorf("expected empty, got %d", len(decisions))
	}
}

func TestLoadReviewedDecisions_ParsesRealFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reviewed.yaml")
	content := `- technique_id: T1490
  action_key: vss_delete_akira_style
  class: destructive
  command_hash: ` + CommandHash("Win32_ShadowCopy.Delete()") + `
  reviewer: test-reviewer
  reviewed_at: "2026-10-03"
  note: "WMI-based VSS deletion, same family as the hand-authored vss_delete entry"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	decisions, err := LoadReviewedDecisions(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(decisions))
	}
	d := decisions[0]
	if d.TechniqueID != "T1490" || d.ActionKey != "vss_delete_akira_style" || d.Class != scenario.ClassDestructive {
		t.Errorf("parsed decision wrong: %+v", d)
	}
}

func TestTriage_SkipsAlreadyHandAuthored(t *testing.T) {
	items := []KeyedItem{
		{DiscoveredItem: DiscoveredItem{Source: "art", TechniqueID: "", Command: "irrelevant"}, ActionKey: "default"},
	}
	result := Triage(items, nil)
	if len(result) != 1 || result[0].Status != StatusAlreadyHandAuthored {
		t.Errorf("expected the hand-authored \"\"/\"default\" pair to be skipped as already covered, got %+v", result)
	}
}

func TestTriage_PromotesNonDestructiveWithNoHumanDecisionNeeded(t *testing.T) {
	items := []KeyedItem{
		{DiscoveredItem: DiscoveredItem{Source: "art", TechniqueID: "T1082", Command: "whoami /all"}, ActionKey: "whoami_fresh_unclassified_test"},
	}
	result := Triage(items, nil)
	if len(result) != 1 || result[0].Status != StatusClassified || result[0].Class != scenario.ClassNonDestructive {
		t.Errorf("expected auto-promotion to non_destructive with no reviewed-decisions entry, got %+v", result)
	}
}

func TestTriage_DestructiveWithNoReviewedDecisionIsUnresolved(t *testing.T) {
	items := []KeyedItem{
		{DiscoveredItem: DiscoveredItem{Source: "art", TechniqueID: "T1490", Command: "vssadmin delete shadows /all /quiet"}, ActionKey: "vss_delete_fresh_unclassified_test"},
	}
	result := Triage(items, nil)
	if len(result) != 1 || result[0].Status != StatusUnresolved {
		t.Errorf("expected unresolved with no matching reviewed decision, got %+v", result)
	}
}

func TestTriage_DestructiveWithMatchingReviewedDecisionIsClassified(t *testing.T) {
	cmd := "vssadmin delete shadows /all /quiet"
	items := []KeyedItem{
		{DiscoveredItem: DiscoveredItem{Source: "art", TechniqueID: "T1490", Command: cmd}, ActionKey: "vss_delete_fresh_unclassified_test"},
	}
	reviewed := []ReviewedDecision{
		{TechniqueID: "T1490", ActionKey: "vss_delete_fresh_unclassified_test", Class: scenario.ClassDestructive, CommandHash: CommandHash(cmd), Note: "matches hand-authored vss_delete family"},
	}
	result := Triage(items, reviewed)
	if len(result) != 1 || result[0].Status != StatusClassified || result[0].Class != scenario.ClassDestructive {
		t.Errorf("expected classified destructive from the reviewed decision, got %+v", result)
	}
}

func TestTriage_StaleReviewedDecision_CommandChanged_IsUnresolved(t *testing.T) {
	items := []KeyedItem{
		{DiscoveredItem: DiscoveredItem{Source: "art", TechniqueID: "T1490", Command: "vssadmin delete shadows /all /quiet /new-flag-nobody-reviewed"}, ActionKey: "vss_delete_fresh_unclassified_test"},
	}
	reviewed := []ReviewedDecision{
		// reviewed against the OLD command text -- hash won't match the live item above
		{TechniqueID: "T1490", ActionKey: "vss_delete_fresh_unclassified_test", Class: scenario.ClassDestructive, CommandHash: CommandHash("vssadmin delete shadows /all /quiet")},
	}
	result := Triage(items, reviewed)
	if len(result) != 1 || result[0].Status != StatusUnresolved {
		t.Errorf("expected a stale reviewed decision (command text changed) to be treated as unresolved, not silently trusted, got %+v", result)
	}
}
