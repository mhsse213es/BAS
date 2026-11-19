package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

const srcDir = "../../../scenarios-src/acl-privilege-exposure-audit"

func gen(t *testing.T) []byte {
	t.Helper()
	b, err := Generate(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGenerateDeterministic(t *testing.T) {
	if !bytes.Equal(gen(t), gen(t)) {
		t.Fatal("two generator runs differ")
	}
}

func TestEveryStepHasContractFields(t *testing.T) {
	sc, err := scenario.ParseYAML(gen(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sc.Steps {
		if len(s.Detection) == 0 && !strings.Contains(s.Name, "Stage 0") {
			t.Errorf("%s: no detection", s.Name)
		}
		if len(s.Telemetry) == 0 {
			t.Errorf("%s: no telemetry", s.Name)
		}
		if s.Command == "" {
			t.Errorf("%s: empty command", s.Name)
		}
	}
}

var forbidden = regexp.MustCompile(`(?i)CommitChanges|SetAccessRule|AddAccessRule\(|SetOwner\(|Set-ADObject|Set-ADUser|Add-ADGroupMember|Set-ADAccountPassword|\.(SetPassword|ChangePassword)\(|Set-Acl|\.Put\(|\.SetInfo\(`)

// Library functions may build in-memory rules in tests, never in stage commands:
// the lib itself must not contain a mutating call.
func TestNoMutatingCalls(t *testing.T) {
	sc, err := scenario.ParseYAML(gen(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sc.Steps {
		if m := forbidden.FindString(s.Command); m != "" {
			t.Errorf("%s contains mutating token %q", s.Name, m)
		}
	}
}

// internal/admatrix pins this stage name and its telemetry string.
func TestStage1NamePinned(t *testing.T) {
	sc, err := scenario.ParseYAML(gen(t))
	if err != nil {
		t.Fatal(err)
	}
	const want = "ACL Stage 1 — Privileged Group DACL Exposure (Domain/Enterprise/Schema Admins)"
	for _, s := range sc.Steps {
		if s.Name == want {
			return
		}
	}
	t.Fatalf("stage %q missing", want)
}

// Tree-shaking must keep every function a stage calls.
func TestEveryCalledFunctionIsDefined(t *testing.T) {
	lib, err := os.ReadFile(filepath.Join(srcDir, "lib.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	_, fns := splitLib(string(lib))
	if len(fns) < 15 {
		t.Fatalf("splitLib found only %d functions", len(fns))
	}
	sc, err := scenario.ParseYAML(gen(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sc.Steps {
		for _, f := range fns {
			used := regexp.MustCompile(`(?i)(^|[^\w-])` + regexp.QuoteMeta(f.name) + `([^\w-]|$)`)
			defd := regexp.MustCompile(`(?im)^function\s+` + regexp.QuoteMeta(f.name) + `\b`)
			body := defd.ReplaceAllString(s.Command, "")
			if used.MatchString(body) && !defd.MatchString(s.Command) {
				t.Errorf("%s calls %s but does not define it", s.Name, f.name)
			}
		}
	}
}

func TestStepCommandsAreCompact(t *testing.T) {
	sc, err := scenario.ParseYAML(gen(t))
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, s := range sc.Steps {
		total += len(s.Command)
	}
	t.Logf("total command bytes: %d across %d steps", total, len(sc.Steps))
	// Steps are self-contained (no shared-prelude field in the schema), so the
	// shared library is embedded per step. The agent runs commands over 8000 bytes
	// from a temp file (-File), so per-step length is safe. Budget guards growth.
	if total > 800000 {
		t.Errorf("scenario commands total %d bytes; keep under 800000", total)
	}
}
