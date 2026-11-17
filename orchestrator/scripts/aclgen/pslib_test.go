package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func ps(t *testing.T, args ...string) string {
	t.Helper()
	p, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("powershell.exe not available")
	}
	full := append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"}, args...)
	out, err := exec.Command(p, full...).CombinedOutput()
	if err != nil {
		t.Fatalf("powershell failed: %v\n%s", err, out)
	}
	return string(out)
}

// The offline library tests build in-memory security descriptors; no domain is needed.
func TestPowerShellLibraryOffline(t *testing.T) {
	lib, _ := filepath.Abs(filepath.Join(srcDir, "lib.ps1"))
	tests, _ := filepath.Abs(filepath.Join(srcDir, "tests", "lib.Tests.ps1"))
	out := ps(t, "-File", tests, "-Lib", lib)
	if !strings.Contains(out, "ALL TESTS PASSED") {
		t.Fatalf("library tests did not pass:\n%s", out)
	}
}

// Every generated step command must parse as PowerShell 5.1.
func TestGeneratedCommandsParse(t *testing.T) {
	sc, err := scenario.ParseYAML(gen(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for i, s := range sc.Steps {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%02d.ps1", i)), []byte(s.Command), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res := ps(t, "-Command", `$bad=0; Get-ChildItem '`+dir+`' -Filter *.ps1 | ForEach-Object { $e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$t,[ref]$e); if($e.Count){$bad++; $_.Name+': '+$e[0].Message+' @'+$e[0].Extent.StartLineNumber} }; if($bad){exit 1}; 'PARSEOK'`)
	if !strings.Contains(res, "PARSEOK") {
		t.Fatalf("generated commands do not parse:\n%s", res)
	}
}
