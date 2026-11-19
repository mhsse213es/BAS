package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTmpScopeNeverIsTheMachineTempDirectory(t *testing.T) {
	if got := tmpScopeFor(""); got != "" {
		t.Errorf("empty dir -> %q, want no scope", got)
	}
	if got := tmpScopeFor(os.TempDir()); got != "" {
		t.Errorf("machine temp dir -> %q, want no scope", got)
	}
	if got := tmpScopeFor(os.TempDir() + string(filepath.Separator)); got != "" {
		t.Errorf("machine temp dir with trailing separator -> %q, want no scope", got)
	}
	run := t.TempDir()
	if got := tmpScopeFor(run); got != run {
		t.Errorf("run dir -> %q, want %q", got, run)
	}
}

func TestSetTmpScopeListsOnlyEntriesInsideTheScope(t *testing.T) {
	scope := t.TempDir()
	if err := os.WriteFile(filepath.Join(scope, "inside.tmp"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newSnapshot("r")
	s.setTmpScope(scope)
	if len(s.Lists["tmp_files"]) != 1 || filepath.Base(s.Lists["tmp_files"][0]) != "inside.tmp" {
		t.Errorf("tmp_files = %v, want only the entry inside the scope", s.Lists["tmp_files"])
	}
	none := newSnapshot("r")
	none.setTmpScope("")
	if len(none.Lists["tmp_files"]) != 0 || none.TmpScope != "" {
		t.Errorf("no scope must record nothing, got %+v", none.Lists["tmp_files"])
	}
}

func TestWithTempDirReplacesTempVariablesCaseInsensitively(t *testing.T) {
	scope := t.TempDir()
	env := withTempDir([]string{"PATH=/bin", "temp=C:\\old", "Tmp=C:\\old", "TMPDIR=/old"}, scope)
	counts := map[string]int{}
	for _, kv := range env {
		name, val, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(name) {
		case "TEMP", "TMP", "TMPDIR":
			counts[strings.ToUpper(name)]++
			if val != scope {
				t.Errorf("%s = %q, want the step scope", name, val)
			}
		}
	}
	for _, k := range []string{"TEMP", "TMP", "TMPDIR"} {
		if counts[k] != 1 {
			t.Errorf("%s set %d times, want once", k, counts[k])
		}
	}
	found := false
	for _, kv := range env {
		if kv == "PATH=/bin" {
			found = true
		}
	}
	if !found {
		t.Error("unrelated variables must be kept")
	}
	unchanged := withTempDir([]string{"TEMP=keep"}, os.TempDir())
	if len(unchanged) != 1 || unchanged[0] != "TEMP=keep" {
		t.Errorf("machine temp dir must leave the environment alone, got %v", unchanged)
	}
}
