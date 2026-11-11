package scenario

import "testing"

// wbadmin_delete_catalog is no longer used by any scenario step: the em-07
// steps that used it were replaced with read-only telemetry checks. The
// catalog entry is kept on purpose so that any future step using this action
// is still classified destructive (fail-closed), rather than falling through
// to the unknown-pair default. This test pins that classification directly,
// because the corpus test can only check pairs that a scenario actually uses.
func TestExecClass_WbadminDeleteCatalogStaysDestructive(t *testing.T) {
	got := ResolveExecutionClass("T1490", "wbadmin_delete_catalog")
	if got.Class != ClassDestructive {
		t.Fatalf("Class = %q, want %q", got.Class, ClassDestructive)
	}
	if got.DestructiveAction != "wbadmin_delete_catalog" {
		t.Fatalf("DestructiveAction = %q, want %q", got.DestructiveAction, "wbadmin_delete_catalog")
	}
}
