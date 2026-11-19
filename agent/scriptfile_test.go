package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteStepScriptWritesUniquePrivateFile(t *testing.T) {
	dir := t.TempDir()
	p1, c1, err := writeStepScript(dir, ".sh", "echo one\n", false)
	if err != nil {
		t.Fatal(err)
	}
	p2, c2, err := writeStepScript(dir, ".sh", "echo two\n", false)
	if err != nil {
		t.Fatal(err)
	}
	if p1 == p2 {
		t.Fatal("two scripts shared one path")
	}
	if filepath.Dir(p1) != dir {
		t.Errorf("script written outside the requested dir: %s", p1)
	}
	if !strings.HasSuffix(p1, ".sh") {
		t.Errorf("extension not kept: %s", p1)
	}
	if b, _ := os.ReadFile(p1); string(b) != "echo one\n" {
		t.Errorf("content = %q", b)
	}
	c1()
	c2()
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Errorf("cleanup left %d file(s)", len(left))
	}
	c1() // cleanup is safe to call twice
}

func TestWriteStepScriptBOMForPowerShell(t *testing.T) {
	dir := t.TempDir()
	p, cleanup, err := writeStepScript(dir, ".ps1", "Write-Output 'é'\n", true)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	b, _ := os.ReadFile(p)
	if len(b) < 3 || b[0] != 0xEF || b[1] != 0xBB || b[2] != 0xBF {
		t.Errorf("missing UTF-8 BOM: % x", b[:min(len(b), 4)])
	}
}

func TestWriteStepScriptNeverUsesCallerSuppliedName(t *testing.T) {
	// The name is generated; a hostile "name" in the extension argument must
	// not walk out of the directory.
	dir := t.TempDir()
	if _, _, err := writeStepScript(dir, `\..\..\evil.ps1`, "x", false); err == nil {
		t.Error("an extension containing a path separator must be rejected")
	}
	if _, _, err := writeStepScript(dir, "/evil", "x", false); err == nil {
		t.Error("an extension containing a path separator must be rejected")
	}
}
