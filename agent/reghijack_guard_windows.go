//go:build windows

package main

// Registry restore guard: the "Restore" stage of every assessment.
//
// Some simulated techniques change how Windows launches things: a UAC bypass rewrites
// HKCU\Software\Classes\Folder\shell\open\command, a hijack points appwiz.cpl at another program, IFEO or App Paths
// redirects an executable. A test's own cleanup does not always undo that (or never runs if the agent dies), and the
// customer is left with folders that will not open. This guard records the registry locations that decide what runs and
// how Windows behaves BEFORE a run, writes that record to disk, and after the run puts every difference back and checks
// that it worked. Because the record is on disk, an agent that was killed mid-run restores it the next time it starts.
//
// It restores only the locations in guardRoots, and only back to what they held at the start of the run. It never
// touches anything else, and a root too large to record exactly is left alone and reported rather than half-restored.

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Variables so tests can shrink them. A root over either limit is not recorded exactly, so it is never restored.
var (
	maxGuardKeys   = 4000
	maxGuardValues = 40000
)

// A record older than this is dropped, not restored: after this long the machine has legitimately changed.
const maxRecoveryAge = 12 * time.Hour

// guardRoot is one registry subtree the guard protects.
type guardRoot struct {
	Hive string `json:"hive"` // "HKCU" or "HKLM"
	Path string `json:"path"`
}

func (r guardRoot) String() string { return r.Hive + `\` + r.Path }

func (r guardRoot) base() registry.Key {
	if r.Hive == "HKLM" {
		return registry.LOCAL_MACHINE
	}
	return userHiveKey() // the logged-in user's hive: the service's own HKCU is SYSTEM's, not the customer's
}

// classesHijackKeys are the file-type and shell-verb keys a technique rewrites to change what a file, folder or
// Run-dialog command opens.
var classesHijackKeys = []string{
	"Folder", "Directory", "Drive", "*", "AllFilesystemObjects", "Applications",
	"exefile", "batfile", "cmdfile", "comfile", "scrfile", "lnkfile", "cplfile", "mscfile", "htafile", "ms-settings",
	".exe", ".bat", ".cmd", ".com", ".scr", ".lnk", ".cpl", ".msc", ".hta", ".ps1", ".vbs", ".js",
}

// guardRootsFn returns the protected locations. A variable so tests can point the guard at a scratch key.
var guardRootsFn = defaultGuardRoots

func defaultGuardRoots() []guardRoot {
	var roots []guardRoot
	for _, hive := range []string{"HKCU", "HKLM"} {
		for _, k := range classesHijackKeys {
			roots = append(roots, guardRoot{hive, `Software\Classes\` + k})
		}
	}
	// Per-user COM registration (COM hijacking). Not guarded under HKLM: far too large and managed by installers.
	roots = append(roots, guardRoot{"HKCU", `Software\Classes\CLSID`})
	roots = append(roots,
		// Where Windows looks up an executable by name.
		guardRoot{"HKCU", `Software\Microsoft\Windows\CurrentVersion\App Paths`},
		guardRoot{"HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths`},
		// Redirection and hooks: debugger redirects, process-exit monitors, shell hooks, load-time DLLs.
		guardRoot{"HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`},
		guardRoot{"HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`},
		guardRoot{"HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks`},
		guardRoot{"HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`},
		guardRoot{"HKCU", `Software\Microsoft\Windows NT\CurrentVersion\Windows`},
		// What starts at logon and when a command prompt opens.
		guardRoot{"HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`},
		guardRoot{"HKLM", `SOFTWARE\Microsoft\Command Processor`},
		guardRoot{"HKCU", `Software\Microsoft\Command Processor`},
		guardRoot{"HKCU", `Environment`},
		// Security configuration a test must not leave changed: UAC and shell policies (NoRun, DisableTaskMgr,
		// DisableRegistryTools), every Microsoft policy (Defender, Firewall, BitLocker, Windows Update), LSA, WDigest.
		guardRoot{"HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies`},
		guardRoot{"HKCU", `Software\Microsoft\Windows\CurrentVersion\Policies`},
		guardRoot{"HKLM", `SOFTWARE\Policies\Microsoft`},
		guardRoot{"HKCU", `Software\Policies\Microsoft`},
		guardRoot{"HKLM", `SYSTEM\CurrentControlSet\Control\Lsa`},
		guardRoot{"HKLM", `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`},
		// Found by the static scan of the shipped Windows atomics (scripts/scenario-scan): other places a test
		// writes that change how the machine behaves. Each is small; a root too large to record is reported, not guessed.
		guardRoot{"HKLM", `SYSTEM\CurrentControlSet\Control\Terminal Server`}, // RDP on or off
		guardRoot{"HKLM", `SYSTEM\CurrentControlSet\Control\Session Manager`},
		guardRoot{"HKLM", `SYSTEM\CurrentControlSet\Control\SafeBoot`},
		guardRoot{"HKLM", `SYSTEM\CurrentControlSet\Control\NetworkProvider`},
		guardRoot{"HKLM", `SYSTEM\CurrentControlSet\Control\FileSystem`},
		guardRoot{"HKLM", `SYSTEM\CurrentControlSet\Control\WMI\Autologger`}, // ETW sessions switched off
		guardRoot{"HKLM", `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`},
		guardRoot{"HKLM", `SYSTEM\CurrentControlSet\Services\W32Time`},
		guardRoot{"HKLM", `SYSTEM\CurrentControlSet\Services\TermService\Parameters`},
		guardRoot{"HKCU", `Software\Microsoft\Windows\CurrentVersion\Internet Settings`}, // proxy and security zones
		guardRoot{"HKCU", `Software\Microsoft\Windows\CurrentVersion\Winlogon`},
		guardRoot{"HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels`}, // event log channels switched off
		guardRoot{"HKLM", `SOFTWARE\Microsoft\Active Setup\Installed Components`},
		guardRoot{"HKCU", `Software\Microsoft\Active Setup\Installed Components`},
		guardRoot{"HKLM", `SOFTWARE\Microsoft\.NETFramework`},
		guardRoot{"HKLM", `SOFTWARE\Microsoft\Provisioning\Commands`},
		guardRoot{"HKCU", `Software\Microsoft\Office\16.0\Excel\Security`}, // macro security
		guardRoot{"HKCU", `Software\Microsoft\Office\16.0\Word\Security`},
		guardRoot{"HKCU", `Software\Microsoft\Office\16.0\Outlook\Security`},
		guardRoot{"HKCU", `Software\Microsoft\Office\16.0\PowerPoint\Security`},
	)
	return roots
}

// regEntry is one registry value, kept raw (type and bytes) so a restore writes back exactly what was there.
type regEntry struct {
	Key  string `json:"key"` // path relative to the root; "" is the root itself
	Name string `json:"name"`
	Kind uint32 `json:"kind"`
	Data []byte `json:"data"`
}

func (e regEntry) id() string { return e.Key + "\x00" + e.Name }

// rootState is the recorded content of one root.
type rootState struct {
	Root      guardRoot  `json:"root"`
	Exists    bool       `json:"exists"`
	Truncated bool       `json:"truncated"` // too large to record exactly: never restored
	Keys      []string   `json:"keys"`      // relative paths of every key, including "" for the root
	Values    []regEntry `json:"values"`
}

func joinKey(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + `\` + b
}

func readRawValue(k registry.Key, name string) (uint32, []byte, bool) {
	n, kind, err := k.GetValue(name, nil)
	if err != nil {
		return 0, nil, false
	}
	buf := make([]byte, n)
	n, kind, err = k.GetValue(name, buf)
	if err != nil {
		return 0, nil, false
	}
	return kind, buf[:n], true
}

func captureRoot(r guardRoot) rootState {
	st := rootState{Root: r}
	k, err := registry.OpenKey(r.base(), r.Path, registry.READ)
	if err != nil {
		return st // the root does not exist
	}
	k.Close()
	st.Exists = true
	walkRoot(r, "", &st)
	return st
}

func walkRoot(r guardRoot, rel string, st *rootState) {
	if st.Truncated {
		return
	}
	k, err := registry.OpenKey(r.base(), joinKey(r.Path, rel), registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	if len(st.Keys) >= maxGuardKeys {
		st.Truncated = true
		return
	}
	st.Keys = append(st.Keys, rel)
	names, _ := k.ReadValueNames(-1)
	for _, n := range names {
		kind, data, ok := readRawValue(k, n)
		if !ok {
			continue
		}
		if len(st.Values) >= maxGuardValues {
			st.Truncated = true
			return
		}
		st.Values = append(st.Values, regEntry{Key: rel, Name: n, Kind: kind, Data: data})
	}
	subs, _ := k.ReadSubKeyNames(-1)
	sort.Strings(subs)
	for _, s := range subs {
		walkRoot(r, joinKey(rel, s), st)
	}
}

// rootDiff is what changed in one root between two recordings.
type rootDiff struct {
	AddedKeys   []string   // exist now, did not before
	MissingKeys []string   // existed before, gone now
	AddedVals   []regEntry // exist now, did not before
	MissingVals []regEntry // existed before, gone now (the earlier value)
	ChangedVals []regEntry // value or type differs (the earlier value)
}

func (d rootDiff) empty() bool {
	return len(d.AddedKeys)+len(d.MissingKeys)+len(d.AddedVals)+len(d.MissingVals)+len(d.ChangedVals) == 0
}

func (d rootDiff) count() int {
	return len(d.AddedKeys) + len(d.MissingKeys) + len(d.AddedVals) + len(d.MissingVals) + len(d.ChangedVals)
}

func diffRootState(pre, post rootState) rootDiff {
	var d rootDiff
	preKeys := map[string]bool{}
	for _, k := range pre.Keys {
		preKeys[k] = true
	}
	postKeys := map[string]bool{}
	for _, k := range post.Keys {
		postKeys[k] = true
		if !preKeys[k] {
			d.AddedKeys = append(d.AddedKeys, k)
		}
	}
	for _, k := range pre.Keys {
		if !postKeys[k] {
			d.MissingKeys = append(d.MissingKeys, k)
		}
	}
	preVals := map[string]regEntry{}
	for _, v := range pre.Values {
		preVals[v.id()] = v
	}
	postVals := map[string]regEntry{}
	for _, v := range post.Values {
		postVals[v.id()] = v
		p, ok := preVals[v.id()]
		switch {
		case !ok:
			d.AddedVals = append(d.AddedVals, v)
		case p.Kind != v.Kind || string(p.Data) != string(v.Data):
			d.ChangedVals = append(d.ChangedVals, p)
		}
	}
	for _, v := range pre.Values {
		if _, ok := postVals[v.id()]; !ok {
			d.MissingVals = append(d.MissingVals, v)
		}
	}
	return d
}

func depth(rel string) int {
	if rel == "" {
		return 0
	}
	return strings.Count(rel, `\`) + 1
}

func setRaw(r guardRoot, rel string, e regEntry) error {
	k, err := registry.OpenKey(r.base(), joinKey(r.Path, rel), registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	name, err := windows.UTF16PtrFromString(e.Name)
	if err != nil {
		return err
	}
	var p *byte
	if len(e.Data) > 0 {
		p = &e.Data[0]
	}
	// x/sys exposes no raw setter, and the typed ones would change a value's type. RegSetValueExW writes it back
	// byte for byte with the type it had.
	status, _, _ := procRegSetValueEx.Call(uintptr(k), uintptr(unsafe.Pointer(name)), 0, uintptr(e.Kind),
		uintptr(unsafe.Pointer(p)), uintptr(len(e.Data)))
	if status != 0 {
		return windows.Errno(status)
	}
	return nil
}

var procRegSetValueEx = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegSetValueExW")

// restoreRoot puts one root back to its recorded state and returns what it changed.
func restoreRoot(pre, post rootState) []string {
	var out []string
	r := pre.Root
	if !pre.Exists {
		if post.Exists {
			// The whole root was created during the run.
			if err := deleteTree(r, ""); err == nil {
				out = append(out, "registry key removed: "+r.String())
			}
		}
		return out
	}
	d := diffRootState(pre, post)
	// 1. Keys created during the run, deepest first so a parent is empty when it goes.
	sort.Slice(d.AddedKeys, func(i, j int) bool { return depth(d.AddedKeys[i]) > depth(d.AddedKeys[j]) })
	for _, rel := range d.AddedKeys {
		if err := registry.DeleteKey(r.base(), joinKey(r.Path, rel)); err == nil {
			out = append(out, "registry key removed: "+joinKey(r.String(), rel))
		}
	}
	// 2. Keys that existed and were deleted, shallowest first.
	sort.Slice(d.MissingKeys, func(i, j int) bool { return depth(d.MissingKeys[i]) < depth(d.MissingKeys[j]) })
	for _, rel := range d.MissingKeys {
		if k, _, err := registry.CreateKey(r.base(), joinKey(r.Path, rel), registry.ALL_ACCESS); err == nil {
			k.Close()
			out = append(out, "registry key recreated: "+joinKey(r.String(), rel))
		}
	}
	// 3. Values that were changed or deleted go back; values that were added come out.
	for _, e := range append(append([]regEntry{}, d.ChangedVals...), d.MissingVals...) {
		if err := setRaw(r, e.Key, e); err == nil {
			out = append(out, "registry value restored: "+joinKey(r.String(), e.Key)+` [`+valueLabel(e.Name)+`]`)
		}
	}
	for _, e := range d.AddedVals {
		k, err := registry.OpenKey(r.base(), joinKey(r.Path, e.Key), registry.SET_VALUE)
		if err != nil {
			continue
		}
		if k.DeleteValue(e.Name) == nil {
			out = append(out, "registry value removed: "+joinKey(r.String(), e.Key)+` [`+valueLabel(e.Name)+`]`)
		}
		k.Close()
	}
	return out
}

func valueLabel(name string) string {
	if name == "" {
		return "(Default)"
	}
	return name
}

// deleteTree removes a key and everything under it, deepest first.
func deleteTree(r guardRoot, rel string) error {
	full := joinKey(r.Path, rel)
	k, err := registry.OpenKey(r.base(), full, registry.READ)
	if err != nil {
		return err
	}
	subs, _ := k.ReadSubKeyNames(-1)
	k.Close()
	for _, s := range subs {
		if err := deleteTree(r, joinKey(rel, s)); err != nil {
			return err
		}
	}
	return registry.DeleteKey(r.base(), full)
}

// regGuard is the record of every protected root taken at the start of one run.
type regGuard struct {
	RunID   string      `json:"runId"`
	TakenAt time.Time   `json:"takenAt"`
	Roots   []rootState `json:"roots"`
	file    string
}

// guardStateDir is where records are kept so a killed agent can restore on its next start. A variable for tests.
var guardStateDir = func() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "BASAgent", "restore")
}

// captureRegGuard records every protected root and saves the record to disk (best effort: a failure to save only
// loses the crash-recovery path, not the normal restore at the end of the run).
func captureRegGuard(runID string) *regGuard {
	g := &regGuard{RunID: runID, TakenAt: time.Now()}
	for _, r := range guardRootsFn() {
		g.Roots = append(g.Roots, captureRoot(r))
	}
	dir := guardStateDir()
	if err := os.MkdirAll(dir, 0o700); err == nil && runID != "" {
		g.file = filepath.Join(dir, safeFileName(runID)+".json")
		if b, err := json.Marshal(g); err == nil {
			if err := os.WriteFile(g.file, b, 0o600); err != nil {
				log.Printf("[!] restore guard: could not save the pre-run record: %v", err)
				g.file = ""
			}
		}
	}
	return g
}

func safeFileName(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// restore puts every root back, then records the root again to prove it. It returns what it changed and anything that
// is still different afterwards. The on-disk record is removed only when nothing is left different.
func (g *regGuard) restore() (changed []string, residual []string) {
	for _, pre := range g.Roots {
		if pre.Truncated {
			residual = append(residual, "not guarded (too large to record exactly): "+pre.Root.String())
			continue
		}
		post := captureRoot(pre.Root)
		if post.Truncated {
			residual = append(residual, "not restored (grew too large to compare): "+pre.Root.String())
			continue
		}
		if diffRootState(pre, post).empty() {
			continue
		}
		changed = append(changed, restoreRoot(pre, post)...)
		// Prove it: the root must now match what it held before the run.
		after := captureRoot(pre.Root)
		if d := diffRootState(pre, after); !d.empty() {
			residual = append(residual, fmt.Sprintf("%s still differs in %d place(s) after restore", pre.Root, d.count()))
		}
	}
	clean := true
	for _, r := range residual {
		if !strings.HasPrefix(r, "not guarded") {
			clean = false
		}
	}
	if clean && g.file != "" {
		_ = os.Remove(g.file)
	}
	return changed, residual
}

// recoverPendingRestores runs when the agent starts: a record still on disk means a run never finished restoring
// (the agent or the machine went down mid-run). Restore it now, unless it is too old to trust.
func recoverPendingRestores() []string {
	dir := guardStateDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var all []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var g regGuard
		if json.Unmarshal(b, &g) != nil {
			_ = os.Remove(path)
			continue
		}
		g.file = path
		if time.Since(g.TakenAt) > maxRecoveryAge {
			log.Printf("[restore] dropping a stale pre-run record from %s (run %s): too old to restore safely", g.TakenAt.Format(time.RFC3339), g.RunID)
			_ = os.Remove(path)
			continue
		}
		changed, residual := g.restore()
		for _, c := range changed {
			log.Printf("[restore] recovered after interrupted run %s: %s", g.RunID, c)
		}
		for _, r := range residual {
			log.Printf("[!] restore: run %s: %s", g.RunID, r)
		}
		all = append(all, changed...)
	}
	return all
}
