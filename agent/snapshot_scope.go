package main

import (
	"os"
	"path/filepath"
	"strings"
)

// tmpScopeFor returns the directory a run or step may snapshot and revert, or ""
// when it has none. The machine temp directory is never a scope: other processes
// write there, so counting its entries would report their files as this run's
// residue, and reverting it would delete them.
func tmpScopeFor(dir string) string {
	if dir == "" {
		return ""
	}
	if filepath.Clean(dir) == filepath.Clean(os.TempDir()) {
		return ""
	}
	return dir
}

// setTmpScope records scope on the snapshot and lists the entries directly inside
// it. An empty scope records nothing, so the snapshot has no temp component.
func (s *SystemSnapshot) setTmpScope(scope string) {
	s.TmpScope = scope
	if scope == "" {
		return
	}
	entries, err := os.ReadDir(scope)
	if err != nil {
		return
	}
	for _, e := range entries {
		s.Lists["tmp_files"] = append(s.Lists["tmp_files"], filepath.Join(scope, e.Name()))
	}
}

// withTempDir points a step's child process at its own temp directory, so the
// files a step writes land inside the directory its snapshot covers. Existing
// TEMP/TMP/TMPDIR entries are replaced (Windows environment names are
// case-insensitive).
func withTempDir(env []string, dir string) []string {
	scope := tmpScopeFor(dir)
	if scope == "" {
		return env
	}
	out := make([]string, 0, len(env)+3)
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(name) {
		case "TEMP", "TMP", "TMPDIR":
			continue
		}
		out = append(out, kv)
	}
	return append(out, "TEMP="+scope, "TMP="+scope, "TMPDIR="+scope)
}
