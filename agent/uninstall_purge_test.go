package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mkfile(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestAgentDataTargets_NamesEveryPlaceTheAgentWrites(t *testing.T) {
	pd, exeDir, cfg, tmp := `C:\ProgramData`, `C:\Program Files\BASAgent`, `C:\Windows\System32\config\systemprofile\AppData\Roaming`, `C:\Windows\Temp`
	glob := func(pattern string) []string {
		if strings.HasSuffix(pattern, "certs.replaced-*") {
			return []string{filepath.Join(pd, "Audspect", "certs.replaced-20261024T082304Z")}
		}
		return nil
	}
	trees, parents := agentDataTargets(pd, []string{exeDir}, cfg, tmp, glob)
	want := []string{
		filepath.Join(pd, "BASAgent"),
		filepath.Join(pd, "Audspect", "certs"),
		filepath.Join(pd, "Audspect", "certs.replaced-20261024T082304Z"),
		filepath.Join(exeDir, "logs"),
		filepath.Join(cfg, "BASAgent"),
		filepath.Join(tmp, "BASAgent"),
	}
	for _, w := range want {
		found := false
		for _, g := range trees {
			if g == w {
				found = true
			}
		}
		if !found {
			t.Errorf("target %q missing from %v", w, trees)
		}
	}
	if len(parents) != 1 || parents[0] != filepath.Join(pd, "Audspect") {
		t.Errorf("parents = %v, want only the Audspect folder", parents)
	}
}

func TestPurge_RemovesEverythingTheAgentCreatedAndNothingElse(t *testing.T) {
	root := t.TempDir()
	mkfile(t, filepath.Join(root, "BASAgent", "api.token"))
	mkfile(t, filepath.Join(root, "BASAgent", "logs", "op_log.log"))
	mkfile(t, filepath.Join(root, "BASAgent", "spool", "q1.json"))
	mkfile(t, filepath.Join(root, "Audspect", "certs", "agent-key.pem"))
	mkfile(t, filepath.Join(root, "Audspect", "certs", "agent-cert.pem"))
	mkfile(t, filepath.Join(root, "Audspect", "certs.replaced-1", "agent-key.pem"))
	mkfile(t, filepath.Join(root, "Audspect", "certs-old-by-an-admin", "agent-key.pem")) // not created by the agent
	mkfile(t, filepath.Join(root, "Unrelated", "keep.txt"))

	trees := []string{filepath.Join(root, "BASAgent"), filepath.Join(root, "Audspect", "certs"), filepath.Join(root, "Audspect", "certs.replaced-1")}
	rep := purgeAgentFiles(trees, []string{filepath.Join(root, "Audspect")}, osPurgeOps(nil))

	for _, gone := range trees {
		if exists(gone) {
			t.Errorf("%s should have been removed", gone)
		}
	}
	if !exists(filepath.Join(root, "Audspect", "certs-old-by-an-admin", "agent-key.pem")) {
		t.Error("a folder the agent did not create must never be deleted")
	}
	if !exists(filepath.Join(root, "Unrelated", "keep.txt")) {
		t.Error("unrelated data must never be deleted")
	}
	if len(rep.Removed) != 3 || len(rep.Failed) != 0 || len(rep.Deferred) != 0 {
		t.Errorf("report = %+v, want 3 removed and nothing failed", rep)
	}
	if len(rep.Kept) != 1 || !strings.Contains(rep.Kept[0], "Audspect") {
		t.Errorf("Kept = %v, want the Audspect folder reported as left in place", rep.Kept)
	}
}

func TestPurge_AnEmptyParentFolderIsRemovedToo(t *testing.T) {
	root := t.TempDir()
	mkfile(t, filepath.Join(root, "Audspect", "certs", "agent-key.pem"))
	rep := purgeAgentFiles([]string{filepath.Join(root, "Audspect", "certs")}, []string{filepath.Join(root, "Audspect")}, osPurgeOps(nil))
	if exists(filepath.Join(root, "Audspect")) {
		t.Error("the Audspect folder is empty after the purge and must go too")
	}
	if len(rep.Kept) != 0 {
		t.Errorf("Kept = %v, want none", rep.Kept)
	}
}

func TestPurge_NothingToRemoveIsNotAnError(t *testing.T) {
	root := t.TempDir()
	rep := purgeAgentFiles([]string{filepath.Join(root, "BASAgent")}, []string{filepath.Join(root, "Audspect")}, osPurgeOps(nil))
	if len(rep.Removed)+len(rep.Deferred)+len(rep.Failed)+len(rep.Kept) != 0 {
		t.Errorf("report = %+v, want empty", rep)
	}
}

func TestPurge_AFolderThatCannotBeRemovedNowIsScheduledForTheNextBoot(t *testing.T) {
	root := t.TempDir()
	mkfile(t, filepath.Join(root, "BASAgent", "logs", "agent.log"))
	var scheduled []string
	ops := osPurgeOps(func(p string) error { scheduled = append(scheduled, p); return nil })
	ops.removeAll = func(string) error { return errors.New("file in use") }
	rep := purgeAgentFiles([]string{filepath.Join(root, "BASAgent")}, nil, ops)
	if len(rep.Deferred) != 1 || len(rep.Failed) != 0 {
		t.Fatalf("report = %+v, want one deferred", rep)
	}
	if len(scheduled) == 0 {
		t.Error("nothing was scheduled for deletion at boot")
	}
	// files first, then folders, deepest first, so the boot-time delete can empty each folder
	last := scheduled[len(scheduled)-1]
	if last != filepath.Join(root, "BASAgent") {
		t.Errorf("the root folder must be scheduled last, got %q", last)
	}
}

func TestPurge_AFailureThatCannotBeScheduledEitherIsReportedNotHidden(t *testing.T) {
	root := t.TempDir()
	mkfile(t, filepath.Join(root, "BASAgent", "x"))
	ops := osPurgeOps(func(string) error { return errors.New("no rights") })
	ops.removeAll = func(string) error { return errors.New("file in use") }
	rep := purgeAgentFiles([]string{filepath.Join(root, "BASAgent")}, nil, ops)
	if len(rep.Failed) != 1 {
		t.Errorf("report = %+v, want one failure that the operator can see", rep)
	}
	if rep.Clean() {
		t.Error("a purge with a failure must not claim to be clean")
	}
}

func TestPurgeReport_CleanOnlyWhenNothingIsDeferredFailedOrKept(t *testing.T) {
	if !(purgeReport{Removed: []string{"a"}}).Clean() {
		t.Error("removed-only is clean")
	}
	for _, r := range []purgeReport{{Deferred: []string{"a"}}, {Failed: []string{"a"}}, {Kept: []string{"a"}}} {
		if r.Clean() {
			t.Errorf("%+v must not be clean", r)
		}
	}
}

// A missing base path must never turn into a relative target such as "logs", which would be resolved against
// whatever folder the uninstall happens to run from (for example Downloads).
func TestAgentDataTargets_NeverProducesARelativeTarget(t *testing.T) {
	trees, parents := agentDataTargets("", []string{"", `C:\Program Files\BASAgent`}, "", "", nil)
	for _, p := range append(append([]string{}, trees...), parents...) {
		if !filepath.IsAbs(p) && !strings.HasPrefix(p, `C:`) {
			t.Errorf("relative target %q", p)
		}
	}
	if len(trees) != 1 || trees[0] != filepath.Join(`C:\Program Files\BASAgent`, "logs") {
		t.Errorf("trees = %v, want only the logs folder of the one real install folder", trees)
	}
	if len(parents) != 0 {
		t.Errorf("parents = %v, want none without a ProgramData path", parents)
	}
}

// The agent's diagnostic log folder survives an uninstall unless the operator asks for it to be purged.
func TestAgentLogPurge_KeptByDefaultRemovedOnRequest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Audspect")
	mkfile(t, filepath.Join(dir, logFileName))
	mkfile(t, filepath.Join(dir, logFileName+".1"))

	if got := logPurgeTrees(false, dir); len(got) != 0 {
		t.Fatalf("without the purge request nothing may be targeted, got %v", got)
	}
	purgeAgentFiles(logPurgeTrees(false, dir), nil, osPurgeOps(nil))
	if !exists(filepath.Join(dir, logFileName)) {
		t.Error("agent.log must survive a normal uninstall")
	}

	purgeAgentFiles(logPurgeTrees(true, dir), nil, osPurgeOps(nil))
	if exists(dir) {
		t.Error("with the purge request the log folder must be removed")
	}
	if got := logPurgeTrees(true, ""); len(got) != 0 {
		t.Errorf("an empty folder name must never become a target (it would resolve against the current folder), got %v", got)
	}
}
