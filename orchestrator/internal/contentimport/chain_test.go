package contentimport

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestChain_Validation(t *testing.T) {
	ok := Stage{Name: "a", TechniqueID: "T1059", Executor: "powershell", Command: "exit 0"}
	cases := []struct {
		name   string
		stages []Stage
		want   string
	}{
		{"one stage", []Stage{ok}, "between 2 and"},
		{"mixed families", []Stage{ok, {Name: "b", TechniqueID: "T1059", Executor: "bash", Command: "true"}}, "cannot run in the same chain"},
		{"first stage depends", []Stage{{Name: "a", TechniqueID: "T1", Executor: "cmd", Command: "x", RunIf: RunPrevAllowed}, ok}, "no previous stage"},
		{"bad run_if", []Stage{ok, {Name: "b", TechniqueID: "T1", Executor: "cmd", Command: "x", RunIf: "sometimes"}}, "run_if"},
		{"empty command", []Stage{ok, {Name: "b", TechniqueID: "T1", Executor: "cmd", Command: "  "}}, "no command"},
	}
	for _, c := range cases {
		if _, err := CompileChain("n", c.stages); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err=%v, want %q", c.name, err, c.want)
		}
	}
}

func TestChain_RiskIsTheHighestStageAndUnstatedIsNotAssumedLow(t *testing.T) {
	mk := func(r string) Stage {
		return Stage{Name: "s", TechniqueID: "T1059", Executor: "bash", Command: "true", Risk: r, Reversible: true, SafeForProd: true}
	}
	st, _ := CompileChain("c", []Stage{mk("low"), mk("low")})
	if st.Risk != "low" || !st.ProductionSafe {
		t.Errorf("%s %v", st.Risk, st.ProductionSafe)
	}
	st, _ = CompileChain("c", []Stage{mk("low"), mk("high")})
	if st.Risk != "high" {
		t.Errorf("%s", st.Risk)
	}
	st, _ = CompileChain("c", []Stage{mk("low"), mk("")})
	if st.Risk != "medium" {
		t.Errorf("unstated risk must not be treated as low: %s", st.Risk)
	}
}

func TestChain_StepPassesScenarioValidation(t *testing.T) {
	st, err := CompileChain("c", []Stage{
		{Name: "a", TechniqueID: "T1059", Executor: "bash", Command: "true"},
		{Name: "b", TechniqueID: "T1105", Executor: "bash", Command: "true", RunIf: RunPrevAllowed}})
	if err != nil {
		t.Fatal(err)
	}
	sc := &scenario.Scenario{ID: "imp-chain", Name: "t", Steps: []scenario.Step{*st}}
	if err := sc.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := sc.ValidateMarkers(); err != nil {
		t.Fatal(err)
	}
}

// ── execution: the compiled script is run for real, not just inspected ──────────────────────────────────────────────

func runScript(t *testing.T, shell string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(shell, args...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run %s: %v", shell, err)
	}
	return string(out), code
}

func outcomes(out string) []string {
	var r []string
	for _, ln := range strings.Split(out, "\n") {
		if i := strings.Index(ln, "outcome="); i >= 0 && strings.Contains(ln, "AUDSPECT_CHAIN") {
			r = append(r, strings.TrimSpace(ln[i+len("outcome="):]))
		}
	}
	return r
}

func joined(s []string) string { return strings.Join(s, ",") }

func TestChain_Bash_Executes(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	stage := func(name, cmd, runIf string) Stage {
		return Stage{Name: name, TechniqueID: "T1059", Executor: "bash", Command: cmd, RunIf: runIf}
	}
	run := func(stages []Stage) (string, int, *scenario.Step) {
		st, err := CompileChain("demo", stages)
		if err != nil {
			t.Fatal(err)
		}
		out, code := runScript(t, bash, "-c", st.Command)
		return out, code, st
	}

	out, code, _ := run([]Stage{stage("one", "echo hi; exit 0", ""), stage("two", "exit 0", RunPrevAllowed)})
	if joined(outcomes(out)) != "allowed,allowed" || code != 0 {
		t.Errorf("all allowed: %s code=%d\n%s", joined(outcomes(out)), code, out)
	}
	if !strings.Contains(out, "| hi") {
		t.Errorf("stage output should be shown: %s", out)
	}

	out, code, _ = run([]Stage{stage("one", "exit 3", ""), stage("two", "exit 0", RunPrevAllowed), stage("three", "exit 0", RunPrevAllowed)})
	if joined(outcomes(out)) != "blocked,skipped,skipped" || code != 1 {
		t.Errorf("a blocked first stage stops an attack chain: %s code=%d", joined(outcomes(out)), code)
	}

	out, code, _ = run([]Stage{stage("one", "exit 2", ""), stage("fallback", "exit 0", RunPrevBlocked)})
	if joined(outcomes(out)) != "blocked,allowed" || code != 0 {
		t.Errorf("a fallback technique runs when the first is blocked: %s code=%d", joined(outcomes(out)), code)
	}

	out, _, _ = run([]Stage{stage("one", "exit 0", ""), stage("fallback", "exit 0", RunPrevBlocked)})
	if joined(outcomes(out)) != "allowed,skipped" {
		t.Errorf("a fallback is skipped when the first succeeds: %s", joined(outcomes(out)))
	}
}

func TestChain_Bash_CleanupRunsEveryStageCleanupAndRemovesTheFolder(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	flag := filepath.ToSlash(filepath.Join(t.TempDir(), "cleaned"))
	st, _ := CompileChain("demo", []Stage{
		{Name: "a", TechniqueID: "T1059", Executor: "bash", Command: "exit 0", Cleanup: "echo a >> '" + flag + "'"},
		{Name: "b", TechniqueID: "T1059", Executor: "bash", Command: "exit 0", Cleanup: "echo b >> '" + flag + "'"},
	})
	runScript(t, bash, "-c", st.Command)
	out, code := runScript(t, bash, "-c", st.Cleanup)
	if code != 0 {
		t.Fatalf("cleanup failed: %s", out)
	}
	b, _ := os.ReadFile(strings.ReplaceAll(flag, "/", string(os.PathSeparator)))
	if string(b) != "b\na\n" {
		t.Errorf("cleanups run in reverse order: %q", b)
	}
}

func TestChain_PowerShell_Executes(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows only")
	}
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("no powershell")
	}
	stage := func(name, ex, cmd, runIf string) Stage {
		return Stage{Name: name, TechniqueID: "T1059", Executor: ex, Command: cmd, RunIf: runIf}
	}
	run := func(stages []Stage) (string, int) {
		st, err := CompileChain("demo", stages)
		if err != nil {
			t.Fatal(err)
		}
		return runScript(t, ps, "-NoProfile", "-Command", st.Command)
	}

	out, code := run([]Stage{stage("one", "powershell", "Write-Output hello; exit 0", ""), stage("two", "cmd", "@echo off\r\nexit /b 0", RunPrevAllowed)})
	if joined(outcomes(out)) != "allowed,allowed" || code != 0 || !strings.Contains(out, "| hello") {
		t.Errorf("all allowed: %s code=%d\n%s", joined(outcomes(out)), code, out)
	}

	out, code = run([]Stage{stage("one", "powershell", "exit 5", ""), stage("two", "powershell", "exit 0", RunPrevAllowed)})
	if joined(outcomes(out)) != "blocked,skipped" || code != 1 {
		t.Errorf("blocked then skipped: %s code=%d\n%s", joined(outcomes(out)), code, out)
	}

	out, code = run([]Stage{stage("one", "cmd", "@echo off\r\nexit /b 7", ""), stage("fallback", "powershell", "exit 0", RunPrevBlocked)})
	if joined(outcomes(out)) != "blocked,allowed" || code != 0 {
		t.Errorf("fallback: %s code=%d\n%s", joined(outcomes(out)), code, out)
	}
}

func TestChain_PowerShell_CleanupRemovesTheWorkFolder(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows only")
	}
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("no powershell")
	}
	flag := filepath.Join(t.TempDir(), "cleaned.txt")
	st, _ := CompileChain("demo", []Stage{
		{Name: "a", TechniqueID: "T1059", Executor: "powershell", Command: "exit 0", Cleanup: "Add-Content -Path '" + flag + "' -Value a"},
		{Name: "b", TechniqueID: "T1059", Executor: "powershell", Command: "exit 0"},
	})
	runScript(t, ps, "-NoProfile", "-Command", st.Command)
	dir := filepath.Join(os.TempDir(), "audspect-"+st.Marker)
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("the chain should have created its work folder: %v", err)
	}
	if out, code := runScript(t, ps, "-NoProfile", "-Command", st.Cleanup); code != 0 {
		t.Fatalf("cleanup failed: %s", out)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("the work folder must be removed")
	}
	if b, _ := os.ReadFile(flag); !strings.Contains(string(b), "a") {
		t.Errorf("stage cleanup did not run: %q", b)
	}
}

func TestChain_IsGatedLikeItsMostDestructiveStage(t *testing.T) {
	benign := Stage{Name: "benign", TechniqueID: "T1033", Executor: "bash", Command: "true"}
	if c := scenario.ResolveExecutionClass(benign.TechniqueID, benign.ActionKey); c.Class != scenario.ClassNonDestructive {
		t.Skipf("T1033 is %s in this catalog; pick another benign technique", c.Class)
	}
	destructive := Stage{Name: "dcsync", TechniqueID: "T1003.006", ActionKey: "negative", Executor: "bash", Command: "true"}
	if scenario.ResolveExecutionClass(destructive.TechniqueID, destructive.ActionKey).Class != scenario.ClassDestructive {
		t.Fatal("test premise: T1003.006/negative must be destructive")
	}
	st, err := CompileChain("c", []Stage{benign, destructive})
	if err != nil {
		t.Fatal(err)
	}
	if st.TechniqueID != "T1003.006" || st.ActionKey != "negative" {
		t.Errorf("the chain must take the destructive stage's classification key, got %s/%s", st.TechniqueID, st.ActionKey)
	}
	st, _ = CompileChain("c", []Stage{benign, {Name: "b2", TechniqueID: "T1033", Executor: "bash", Command: "true"}})
	if st.TechniqueID != "T1033" {
		t.Errorf("an all-benign chain keeps the first stage's technique: %s", st.TechniqueID)
	}
	st, _ = CompileChain("c", []Stage{benign, {Name: "unknown", TechniqueID: "T9999", Executor: "bash", Command: "true"}})
	if st.TechniqueID != "T9999" {
		t.Errorf("an unrecognised technique is treated as destructive and must win: %s", st.TechniqueID)
	}
}
