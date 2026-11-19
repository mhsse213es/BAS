package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

// ACLGEN_DUMP=<dir> writes each step command to <dir>/NN.ps1 for external checks.
func TestDumpCommands(t *testing.T) {
	dir := os.Getenv("ACLGEN_DUMP")
	if dir == "" {
		t.Skip("ACLGEN_DUMP not set")
	}
	sc, err := scenario.ParseYAML(gen(t))
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range sc.Steps {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%02d.ps1", i)), []byte(s.Command), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
