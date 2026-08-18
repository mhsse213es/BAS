package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestBuildToolchain_IsExactlyGo1_20_14 is the load-bearing check for this
// entire module: a bare `go 1.20` line in go.mod only enforces minimum
// LANGUAGE compatibility -- if a newer `go` binary is on PATH it will still
// build against it, producing a binary linked against a newer runtime than
// the one Windows 7/8/Server 2008R2-2012 compatibility actually depends on.
// This test fails loudly if GOTOOLCHAIN isn't pinned correctly in whatever
// environment runs it.
func TestBuildToolchain_IsExactlyGo1_20_14(t *testing.T) {
	out, err := exec.Command("go", "version").CombinedOutput()
	if err != nil {
		t.Fatalf("go version failed: %v (%s)", err, out)
	}
	got := strings.TrimSpace(string(out))
	if !strings.Contains(got, "go1.20.14") {
		t.Fatalf("resolved toolchain = %q, want it to contain \"go1.20.14\" -- set GOTOOLCHAIN=go1.20.14 in the environment running this build/test", got)
	}
}
