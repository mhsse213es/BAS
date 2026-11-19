//go:build windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

// scratch returns an empty HKCU scratch key for one test and points the guard at it. Nothing outside it is touched.
func scratch(t *testing.T) guardRoot {
	t.Helper()
	base := `Software\AudspectGuardTest\` + safeFileName(t.Name())
	_ = deleteTree(guardRoot{"HKCU", base}, "")
	t.Cleanup(func() { _ = deleteTree(guardRoot{"HKCU", base}, "") })
	k, _, err := registry.CreateKey(registry.CURRENT_USER, base, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	k.Close()
	root := guardRoot{"HKCU", base}
	guardRootsFn = func() []guardRoot { return []guardRoot{root} }
	stateDir := filepath.Join(t.TempDir(), "restore")
	guardStateDir = func() string { return stateDir }
	t.Cleanup(func() { guardRootsFn = defaultGuardRoots })
	return root
}

func mkKey(t *testing.T, r guardRoot, rel string) registry.Key {
	t.Helper()
	k, _, err := registry.CreateKey(registry.CURRENT_USER, joinKey(r.Path, rel), registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func setStr(t *testing.T, r guardRoot, rel, name, v string) {
	t.Helper()
	k := mkKey(t, r, rel)
	defer k.Close()
	if err := k.SetStringValue(name, v); err != nil {
		t.Fatal(err)
	}
}

func getStr(r guardRoot, rel, name string) (string, bool) {
	k, err := registry.OpenKey(registry.CURRENT_USER, joinKey(r.Path, rel), registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	return v, err == nil
}

func keyExists(r guardRoot, rel string) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, joinKey(r.Path, rel), registry.READ)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

// The reported fault: a technique rewrites what a folder opens with. After the run it must be what it was.
func TestRegGuard_RestoresAHijackedFolderHandler(t *testing.T) {
	r := scratch(t)
	const cmdPath = `Classes\Folder\shell\open\command`
	setStr(t, r, cmdPath, "", `C:\Windows\explorer.exe /idlist,%I,%L`)
	g := captureRegGuard("run-folder")

	setStr(t, r, cmdPath, "", `C:\Users\Public\evil.exe`)          // handler hijacked
	setStr(t, r, cmdPath, "DelegateExecute", "")                   // UAC-bypass style value
	setStr(t, r, `Classes\cplfile\shell\cplopen\command`, "", "x") // a handler that did not exist

	changed, residual := g.restore()
	if len(residual) != 0 {
		t.Fatalf("residual after restore: %v", residual)
	}
	if v, _ := getStr(r, cmdPath, ""); v != `C:\Windows\explorer.exe /idlist,%I,%L` {
		t.Errorf("folder handler = %q, want the original", v)
	}
	if _, ok := getStr(r, cmdPath, "DelegateExecute"); ok {
		t.Error("the added DelegateExecute value is still there")
	}
	if keyExists(r, `Classes\cplfile`) {
		t.Error("the handler key created during the run is still there")
	}
	if len(changed) == 0 {
		t.Error("restore changed things but reported nothing")
	}
}

func TestRegGuard_RestoresEveryKindOfChange(t *testing.T) {
	r := scratch(t)
	k := mkKey(t, r, `A\B`)
	k.SetDWordValue("dw", 7)
	k.SetStringValue("gone", "x")
	k.SetStringValue("retyped", "text")
	k.SetBinaryValue("bin", []byte{1, 2, 3})
	k.SetExpandStringValue("exp", `%SystemRoot%\x`)
	k.SetStringsValue("multi", []string{"a", "b"})
	k.Close()
	setStr(t, r, `A\Deleted\Deeper`, "v", "keep me")
	g := captureRegGuard("run-kinds")

	k = mkKey(t, r, `A\B`)
	k.SetDWordValue("dw", 9)         // changed
	k.DeleteValue("gone")            // deleted
	k.SetDWordValue("retyped", 1)    // type changed, REG_SZ to REG_DWORD
	k.SetStringValue("added", "new") // added
	k.Close()
	deleteTree(r, `A\Deleted`)            // key and subtree deleted
	mkKey(t, r, `A\Created\Deep`).Close() // key tree added

	_, residual := g.restore()
	if len(residual) != 0 {
		t.Fatalf("residual: %v", residual)
	}
	after := captureRoot(r)
	if d := diffRootState(g.Roots[0], after); !d.empty() {
		t.Fatalf("root still differs from before the run: %+v", d)
	}
	if v, _ := getStr(r, `A\Deleted\Deeper`, "v"); v != "keep me" {
		t.Errorf("deleted subtree not recreated with its value: %q", v)
	}
}

func TestRegGuard_RemovesARootCreatedDuringTheRun(t *testing.T) {
	r := scratch(t)
	missing := guardRoot{"HKCU", r.Path + `\NotThereYet`}
	guardRootsFn = func() []guardRoot { return []guardRoot{missing} }
	g := captureRegGuard("run-missing")
	setStr(t, missing, `x\y`, "v", "1")
	_, residual := g.restore()
	if len(residual) != 0 || keyExists(missing, "") {
		t.Fatalf("root created during the run was not removed (residual %v)", residual)
	}
}

func TestRegGuard_NothingChangedMeansNothingTouched(t *testing.T) {
	r := scratch(t)
	setStr(t, r, "k", "v", "1")
	g := captureRegGuard("run-clean")
	changed, residual := g.restore()
	if len(changed) != 0 || len(residual) != 0 {
		t.Fatalf("an untouched root reported changed=%v residual=%v", changed, residual)
	}
}

// The agent can be killed mid-run. The next start must put the registry back from the record on disk.
func TestRegGuard_RecoversAfterACrash(t *testing.T) {
	r := scratch(t)
	setStr(t, r, `Classes\Folder`, "", "original")
	g := captureRegGuard("run-crash")
	if g.file == "" {
		t.Fatal("the pre-run record was not saved")
	}
	setStr(t, r, `Classes\Folder`, "", "hijacked")
	// The agent dies here; restore() is never called.

	n := len(recoverPendingRestores())
	if v, _ := getStr(r, `Classes\Folder`, ""); v != "original" || n == 0 {
		t.Fatalf("not recovered after restart: value %q, %d change(s)", v, n)
	}
	if _, err := os.Stat(g.file); !os.IsNotExist(err) {
		t.Error("the record is still on disk after a clean recovery")
	}
}

func TestRegGuard_DropsAStaleRecordInsteadOfRestoringIt(t *testing.T) {
	r := scratch(t)
	setStr(t, r, "k", "v", "original")
	g := captureRegGuard("run-stale")
	setStr(t, r, "k", "v", "changed by a person later")
	g.TakenAt = time.Now().Add(-2 * maxRecoveryAge)
	b, _ := json.Marshal(g)
	if err := os.WriteFile(g.file, b, 0o600); err != nil {
		t.Fatal(err)
	}
	recoverPendingRestores()
	if v, _ := getStr(r, "k", "v"); v != "changed by a person later" {
		t.Errorf("a stale record overwrote a later change: %q", v)
	}
	if _, err := os.Stat(g.file); !os.IsNotExist(err) {
		t.Error("the stale record was kept")
	}
}

func TestRegGuard_LeavesATooLargeRootAloneAndSaysSo(t *testing.T) {
	r := scratch(t)
	for _, n := range []string{"a", "b", "c", "d"} {
		setStr(t, r, n, "v", "1")
	}
	old := maxGuardKeys
	maxGuardKeys = 2
	t.Cleanup(func() { maxGuardKeys = old })
	g := captureRegGuard("run-big")
	setStr(t, r, "a", "v", "changed")
	changed, residual := g.restore()
	if v, _ := getStr(r, "a", "v"); v != "changed" || len(changed) != 0 {
		t.Errorf("a root too large to record exactly was modified: %q %v", v, changed)
	}
	if len(residual) == 0 || !strings.Contains(residual[0], "too large") {
		t.Errorf("the guard did not report the root it could not protect: %v", residual)
	}
}

// The protected set is the point of the guard: losing one of these quietly would reopen the fault.
func TestDefaultGuardRoots_CoverTheKnownHijackPoints(t *testing.T) {
	have := map[string]bool{}
	for _, r := range defaultGuardRoots() {
		have[strings.ToLower(r.String())] = true
	}
	for _, want := range []string{
		`HKCU\Software\Classes\Folder`, `HKCU\Software\Classes\Directory`, `HKCU\Software\Classes\cplfile`,
		`HKCU\Software\Classes\mscfile`, `HKCU\Software\Classes\ms-settings`, `HKCU\Software\Classes\exefile`,
		`HKCU\Software\Classes\.cpl`, `HKCU\Software\Classes\CLSID`,
		`HKLM\Software\Classes\Folder`, `HKLM\Software\Classes\cplfile`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths`,
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies`, // includes the UAC settings under Policies\System
		`HKLM\SOFTWARE\Policies\Microsoft`, // includes Windows Defender, Firewall, BitLocker (FVE), Windows Update
	} {
		if !have[strings.ToLower(want)] {
			t.Errorf("not protected: %s", want)
		}
	}
}

// Through the same entry points a run uses: snapshot at the start, revert at the end.
func TestRegGuard_RunsThroughSnapshotAndRevert(t *testing.T) {
	r := scratch(t)
	setStr(t, r, `Classes\cplfile\shell\cplopen\command`, "", "original")
	snap := captureSnapshot("run-through")
	if snap.Guard == nil {
		t.Fatal("captureSnapshot did not take the registry guard")
	}
	setStr(t, r, `Classes\cplfile\shell\cplopen\command`, "", `C:\evil.exe`)
	reverted := revertFromSnapshot(snap)
	if v, _ := getStr(r, `Classes\cplfile\shell\cplopen\command`, ""); v != "original" {
		t.Errorf("cplfile handler = %q after revert", v)
	}
	found := false
	for _, line := range reverted {
		if strings.HasPrefix(line, "registry value restored:") {
			found = true
		}
		if strings.HasPrefix(line, "restore incomplete:") {
			t.Errorf("revert reported an incomplete restore: %s", line)
		}
	}
	if !found {
		t.Errorf("revert did not report the restored value: %v", reverted)
	}
}
