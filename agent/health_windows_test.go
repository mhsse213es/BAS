//go:build windows

package main

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// The health check asks Windows itself what a file type or folder opens with (the same lookup Explorer and the Run
// dialog use), so it catches a hijack however it was written. These tests use a scratch file type, never a real one.

const healthScratchExt = ".audspecthealthtest"

func setScratchHandler(t *testing.T, cmd string) {
	t.Helper()
	k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Classes\`+healthScratchExt+`\shell\open\command`, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if err := k.SetStringValue("", cmd); err != nil {
		t.Fatal(err)
	}
}

func removeScratch(t *testing.T) {
	t.Helper()
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\`+healthScratchExt+`\shell\open\command`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\`+healthScratchExt+`\shell\open`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\`+healthScratchExt+`\shell`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\`+healthScratchExt)
}

func withScratchAssoc(t *testing.T) {
	t.Helper()
	old := healthAssocs
	healthAssocs = []string{healthScratchExt}
	removeScratch(t)
	t.Cleanup(func() { healthAssocs = old; removeScratch(t) })
}

func TestAssocCommand_ReadsWhatWindowsWouldRun(t *testing.T) {
	if got := assocCommand(".exe"); !strings.Contains(got, "%1") {
		t.Errorf(`.exe opens with %q, want a command containing "%%1"`, got)
	}
	// an unknown type resolves to Windows's "Open with" fallback, which is a stable answer, not an error
	if a, b := assocCommand(".audspect-no-such-type"), assocCommand(".audspect-other-type"); a != b {
		t.Errorf("two unknown types resolved differently: %q vs %q", a, b)
	}
}

func TestHealth_ReportsAHandlerThatChangedAndNothingWhenItDidNot(t *testing.T) {
	withScratchAssoc(t)
	setScratchHandler(t, `C:\Windows\notepad.exe "%1"`)
	pre := captureHealth()
	if got := pre.verify(); len(got) != 0 {
		t.Fatalf("nothing changed but health reports %v", got)
	}
	setScratchHandler(t, `C:\Windows\explorer.exe`)
	got := pre.verify()
	if len(got) != 1 || !strings.Contains(got[0], healthScratchExt) || !strings.Contains(got[0], "explorer.exe") {
		t.Fatalf("a changed handler must be named with its new command, got %v", got)
	}
	setScratchHandler(t, `C:\Windows\notepad.exe "%1"`)
	if got := pre.verify(); len(got) != 0 {
		t.Fatalf("handler put back but health still reports %v", got)
	}
}

func TestHealth_ReportsAHandlerCreatedDuringTheRun(t *testing.T) {
	withScratchAssoc(t)
	pre := captureHealth() // the scratch type has no handler yet
	setScratchHandler(t, `C:\Windows\explorer.exe`)
	got := pre.verify()
	if len(got) == 0 {
		t.Fatal("a handler that appeared during the run must be reported")
	}
}

func TestHealth_ShellOverridesListsAUserLevelHandlerAndTheStockStateListsNone(t *testing.T) {
	withScratchAssoc(t)
	if got := hkcuShellOverrides(healthAssocs); len(got) != 0 {
		t.Fatalf("no override yet, got %v", got)
	}
	setScratchHandler(t, `C:\x.exe`)
	got := hkcuShellOverrides(healthAssocs)
	if len(got) != 1 || !strings.HasSuffix(got[0], `\shell\open`) {
		t.Fatalf("want the user-level open verb listed, got %v", got)
	}
}

func TestHealth_AnOverrideAlreadyPresentAtStartIsFlaggedNotSilentlyAccepted(t *testing.T) {
	withScratchAssoc(t)
	setScratchHandler(t, `C:\x.exe`) // left behind by an earlier run
	pre := captureHealth()
	notes := pre.baselineProblems()
	if len(notes) != 1 || !strings.Contains(notes[0], "already present") {
		t.Fatalf("a pre-existing override must be reported as such, got %v", notes)
	}
}

func TestHealth_ExplorerStoppingIsReported(t *testing.T) {
	pre := captureHealth()
	pre.ExplorerUp = true
	orig := explorerRunning
	explorerRunning = func() bool { return false }
	defer func() { explorerRunning = orig }()
	got := pre.verify()
	if len(got) != 1 || !strings.Contains(got[0], "Explorer") {
		t.Fatalf("want an Explorer problem, got %v", got)
	}
	pre.ExplorerUp = false // it was not running at the start (service session): nothing to compare
	if got := pre.verify(); len(got) != 0 {
		t.Fatalf("Explorer was not running before, so its absence is not a regression: %v", got)
	}
}

func TestHealth_RunsThroughSnapshotAndRevertAndReportsWhatTheRestoreMissed(t *testing.T) {
	withScratchAssoc(t)
	setScratchHandler(t, `C:\Windows\notepad.exe "%1"`)
	snap := captureSnapshot("health-test")
	setScratchHandler(t, `C:\Windows\explorer.exe`) // outside the guard's roots: only the health check can notice
	reverted := revertFromSnapshot(snap)
	found := false
	for _, r := range reverted {
		if strings.HasPrefix(r, "restore incomplete: health:") && strings.Contains(r, healthScratchExt) {
			found = true
		}
	}
	if !found {
		t.Fatalf("a handler still changed after the restore must be reported as an incomplete restore, got %v", reverted)
	}
}

func TestHealth_APreExistingOverrideIsReportedInTheRunResult(t *testing.T) {
	withScratchAssoc(t)
	setScratchHandler(t, `C:\x.exe`)
	snap := captureSnapshot("health-test2")
	reverted := revertFromSnapshot(snap)
	found := false
	for _, r := range reverted {
		if strings.Contains(r, "already present before this run") {
			found = true
		}
	}
	if !found {
		t.Fatalf("an override left by an earlier run must be named in the result, got %v", reverted)
	}
}

func TestHealth_AnExtraContextMenuVerbIsNotAnOverride(t *testing.T) {
	withScratchAssoc(t)
	k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Classes\`+healthScratchExt+`\shell\DiskUsageTool\command`, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	k.SetStringValue("", `C:\tools\du.exe "%1"`)
	k.Close()
	defer registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\`+healthScratchExt+`\shell\DiskUsageTool\command`)
	defer registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\`+healthScratchExt+`\shell\DiskUsageTool`)
	if got := hkcuShellOverrides(healthAssocs); len(got) != 0 {
		t.Fatalf("an added verb must not count as an override, got %v", got)
	}
}
