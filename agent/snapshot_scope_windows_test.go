package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The revert must never remove an entry outside the snapshot's scope, even one
// created during the window. Another process's temp file is not this run's residue.
func TestRevertTmpScopeLeavesEntriesOutsideTheScopeAlone(t *testing.T) {
	scope := t.TempDir()
	outside := filepath.Join(os.TempDir(), "bas-scope-test-outside-"+t.Name())
	if err := os.WriteFile(outside, []byte("other process"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })

	s := newSnapshot("r")
	s.setTmpScope(scope)
	inside := filepath.Join(scope, "step-residue.tmp")
	if err := os.WriteFile(inside, []byte("step"), 0o600); err != nil {
		t.Fatal(err)
	}

	reverted := revertTmpScope(s)

	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("file outside the scope was deleted: %v", err)
	}
	if _, err := os.Stat(inside); !os.IsNotExist(err) {
		t.Errorf("step residue inside the scope was not reverted")
	}
	if len(reverted) != 1 {
		t.Errorf("reverted = %v, want exactly the one in-scope entry", reverted)
	}
}

func TestRevertTmpScopeWithNoScopeTouchesNothing(t *testing.T) {
	s := newSnapshot("r")
	s.setTmpScope("")
	if got := revertTmpScope(s); len(got) != 0 {
		t.Errorf("no scope must revert nothing, got %v", got)
	}
}
