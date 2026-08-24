# Environment Restoration Accuracy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a run report's "Environment Restoration" panel internally consistent — its headline Cleanup Rate / leaked count must never contradict the "Agent-Confirmed Rollbacks" list shown in the same panel.

**Architecture:** Every cleanup-bearing step gets a lightweight before/after snapshot bracket around its action+cleanup, giving it real evidence (`CleanupResidual`) instead of trusting a single exit code. `buildEnvRestoration` then cross-references any step still showing residue against what the whole-run safety net (`reverted[]`) actually removed afterward, introducing a third state — `rescued` — for steps a later sweep cleaned up even though their own script failed.

**Tech Stack:** Go (agent + orchestrator), vanilla JS (wwwroot/index.html), Postgres (JSONB `results`/`reverted` columns — no migration needed).

**Spec:** `orchestrator/docs/superpowers/specs/2026-08-24-environment-restoration-accuracy-design.md`

## Global Constraints

- No new API endpoint and no DB migration — `CleanupVerdict` and the new `CleanupResidual` both travel inside the existing JSONB `results` column; nothing here is a first-class SQL column.
- Cleanup-bearing steps are already fully serial under the agent's resource-lock scheduler (`orchestrator/internal/scenario/resource.go`'s `discoveryProfiles` is exclusively `riskObservation`, and read-only discovery techniques never declare `cleanup:`). No scheduler/locking change is needed or in scope.
- `captureSnapshotLite` must never add the netsh firewall dump or the hosts-file read that `captureSnapshot` does on Windows — those are the two slow calls the design explicitly trims per cleanup-bearing step.
- Snapshot capture failures must fail soft exactly like today's `captureSnapshot`/`revertFromSnapshot` (independent `err == nil` guards per category) — a step's cleanup must never block or fail because a snapshot category couldn't be read.
- Historical rows with no `CleanupResidual` (nil — every row recorded before this change) must fall back to today's exact exit-code-only classification, never be reinterpreted.
- Every new Go field uses the JSON tag `cleanupResidual,omitempty` for `CleanupResidual []string`, matching the spec exactly.

---

## Task 1: `diffSnapshots` + `diffRegistry` — the shared snapshot-diffing primitive

**Files:**
- Modify: `agent/snapshot.go`
- Modify: `agent/snapshot_windows.go`
- Modify: `agent/snapshot_posix.go`
- Test: `agent/snapshot_test.go` (new)
- Test: `agent/snapshot_windows_test.go` (new)

**Interfaces:**
- Produces: `diffSnapshots(before, after *SystemSnapshot) []string` (agent/snapshot.go) — normalized-key diff, used by Task 2's per-step bracket. `diffRegistry(before, after *SystemSnapshot) []string` (build-tag-selected: real impl in snapshot_windows.go, no-op stub in snapshot_posix.go) — called internally by `diffSnapshots`.

`agent/snapshot.go`'s existing `SystemSnapshot.Lists` map uses these category keys today: `"schtasks"`, `"services"`, `"tmp_files"`, `"startup"` (Windows, in `snapshot_windows.go`) and `"cron_dirs"`, `"services"`, `"tmp_files"` (POSIX, in `snapshot_posix.go`). `"services"` and `"tmp_files"` are literally the same key name on both platforms, so one shared prefix map covering all five names is safe on both OSes — a platform's snapshot simply never populates the categories its own `captureSnapshot` doesn't capture, so those map entries are harmless no-ops.

- [ ] **Step 1: Write the failing test for list-category diffing**

Create `agent/snapshot_test.go`:

```go
package main

import (
	"reflect"
	"sort"
	"testing"
)

func snap(lists map[string][]string, files map[string][]byte) *SystemSnapshot {
	s := newSnapshot("test-run")
	if lists != nil {
		s.Lists = lists
	}
	if files != nil {
		s.Files = files
	}
	return s
}

func sortedDiff(before, after *SystemSnapshot) []string {
	d := diffSnapshots(before, after)
	sort.Strings(d)
	return d
}

func TestDiffSnapshots_EmptyWhenUnchanged(t *testing.T) {
	before := snap(map[string][]string{"tmp_files": {"/tmp/a"}}, nil)
	after := snap(map[string][]string{"tmp_files": {"/tmp/a"}}, nil)
	if d := diffSnapshots(before, after); len(d) != 0 {
		t.Errorf("diffSnapshots = %v, want empty", d)
	}
}

func TestDiffSnapshots_NewTmpFile(t *testing.T) {
	before := snap(map[string][]string{"tmp_files": {"/tmp/a"}}, nil)
	after := snap(map[string][]string{"tmp_files": {"/tmp/a", "/tmp/evil.ps1"}}, nil)
	want := []string{"tmp:/tmp/evil.ps1"}
	if d := sortedDiff(before, after); !reflect.DeepEqual(d, want) {
		t.Errorf("diffSnapshots = %v, want %v", d, want)
	}
}

func TestDiffSnapshots_PreExistingItemsNeverFlagged(t *testing.T) {
	before := snap(map[string][]string{
		"tmp_files": {"/tmp/a", "/tmp/b"},
		"services":  {"Spooler"},
		"schtasks":  {"\\Microsoft\\Windows\\Defrag"},
		"startup":   {"C:\\Startup\\ok.lnk"},
		"cron_dirs": {"/etc/cron.d/logrotate"},
	}, nil)
	after := snap(map[string][]string{
		"tmp_files": {"/tmp/a", "/tmp/b"},
		"services":  {"Spooler"},
		"schtasks":  {"\\Microsoft\\Windows\\Defrag"},
		"startup":   {"C:\\Startup\\ok.lnk"},
		"cron_dirs": {"/etc/cron.d/logrotate"},
	}, nil)
	if d := diffSnapshots(before, after); len(d) != 0 {
		t.Errorf("diffSnapshots = %v, want empty (nothing new)", d)
	}
}

func TestDiffSnapshots_NewServiceSchtaskStartupCron(t *testing.T) {
	before := snap(map[string][]string{}, nil)
	after := snap(map[string][]string{
		"services":  {"EvilSvc"},
		"schtasks":  {"\\Evil\\Task"},
		"startup":   {"C:\\Startup\\evil.lnk"},
		"cron_dirs": {"/etc/cron.d/evil"},
	}, nil)
	want := []string{"cron:/etc/cron.d/evil", "schtask:\\Evil\\Task", "service:EvilSvc", "startup:C:\\Startup\\evil.lnk"}
	if d := sortedDiff(before, after); !reflect.DeepEqual(d, want) {
		t.Errorf("diffSnapshots = %v, want %v", d, want)
	}
}

func TestDiffSnapshots_WholeFileChanged(t *testing.T) {
	before := snap(nil, map[string][]byte{"crontab:user": []byte("0 * * * * old\n")})
	after := snap(nil, map[string][]byte{"crontab:user": []byte("0 * * * * old\n* * * * * evil\n")})
	want := []string{"crontab:user"}
	if d := diffSnapshots(before, after); !reflect.DeepEqual(d, want) {
		t.Errorf("diffSnapshots = %v, want %v", d, want)
	}
}

func TestDiffSnapshots_WholeFileUnchanged(t *testing.T) {
	before := snap(nil, map[string][]byte{"/etc/hosts": []byte("127.0.0.1 localhost\n")})
	after := snap(nil, map[string][]byte{"/etc/hosts": []byte("127.0.0.1 localhost\n")})
	if d := diffSnapshots(before, after); len(d) != 0 {
		t.Errorf("diffSnapshots = %v, want empty", d)
	}
}

func TestDiffSnapshots_UnrecognizedCategoryIgnored(t *testing.T) {
	before := snap(map[string][]string{"future_category": {}}, nil)
	after := snap(map[string][]string{"future_category": {"new-item"}}, nil)
	if d := diffSnapshots(before, after); len(d) != 0 {
		t.Errorf("diffSnapshots = %v, want empty (unrecognized category must be ignored, not panic)", d)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./agent/... -run TestDiffSnapshots -v` (from repo root, or `cd agent && go test ./... -run TestDiffSnapshots -v`)
Expected: FAIL — `diffSnapshots` (and `diffRegistry`, transitively) undefined.

- [ ] **Step 3: Implement `diffSnapshots` in `agent/snapshot.go`**

Add `"bytes"` and `"strings"` to the existing import block, then append below `snapCmd`:

```go
// listCategoryPrefixes maps each SystemSnapshot.Lists category key to the
// normalized key prefix diffSnapshots emits. A given platform's snapshot only
// ever populates the categories its own captureSnapshot captures — entries
// for the other platform's categories are harmless no-ops here.
var listCategoryPrefixes = map[string]string{
	"tmp_files": "tmp:",
	"services":  "service:",
	"schtasks":  "schtask:",
	"startup":   "startup:",
	"cron_dirs": "cron:",
}

// diffSnapshots returns normalized keys for every item present in after but
// absent (or changed) from before, across every category both snapshots
// share: "tmp:<path>", "service:<name>", "schtask:<name>", "startup:<path>",
// "cron:<path>" (list categories, via listCategoryPrefixes), plus
// "registry:<key>\<value>" (Windows Run/RunOnce values, via diffRegistry) and
// whole-file keys unchanged from SystemSnapshot.Files (e.g. "crontab:user",
// "iptables", "/etc/hosts") whenever their content differs. Order is not
// significant to callers.
func diffSnapshots(before, after *SystemSnapshot) []string {
	var diff []string

	for category, items := range after.Lists {
		prefix, ok := listCategoryPrefixes[category]
		if !ok {
			continue
		}
		beforeSet := toSet(before.Lists[category])
		for _, item := range items {
			if !beforeSet[item] {
				diff = append(diff, prefix+item)
			}
		}
	}

	diff = append(diff, diffRegistry(before, after)...)

	for key, afterBlob := range after.Files {
		if strings.HasPrefix(key, "reg:") {
			continue // handled by diffRegistry above
		}
		beforeBlob, ok := before.Files[key]
		if !ok || bytes.Equal(beforeBlob, afterBlob) {
			continue
		}
		diff = append(diff, key)
	}

	return diff
}
```

- [ ] **Step 4: Add the `diffRegistry` build-tag-selected pair**

In `agent/snapshot_windows.go`, append below `revertFromSnapshot` (before `parseRegValues`):

```go
// diffRegistry returns "registry:<key>\<value>" for every Run/RunOnce value
// present in after but absent from before. Registry values need per-value
// diffing (not whole-blob comparison) because a single "reg:<key>" capture
// covers every value under that key — see parseRegValues.
func diffRegistry(before, after *SystemSnapshot) []string {
	var diff []string
	for key, afterBlob := range after.Files {
		if !strings.HasPrefix(key, "reg:") {
			continue
		}
		beforeBlob, ok := before.Files[key]
		if !ok {
			continue
		}
		beforeValues := parseRegValues(beforeBlob)
		afterValues := parseRegValues(afterBlob)
		regKey := strings.TrimPrefix(key, "reg:")
		for name := range afterValues {
			if !beforeValues[name] {
				diff = append(diff, "registry:"+regKey+`\`+name)
			}
		}
	}
	return diff
}
```

In `agent/snapshot_posix.go`, append at the end of the file:

```go
// diffRegistry is a no-op on POSIX — there is no registry to diff.
func diffRegistry(_, _ *SystemSnapshot) []string { return nil }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd agent && go test ./... -run TestDiffSnapshots -v`
Expected: PASS (all 7 subtests). This runs on Windows (the build host), so `diffRegistry`'s real Windows implementation compiles in — it's simply never exercised by these OS-independent fixtures since none of them use a `"reg:"`-prefixed key.

- [ ] **Step 6: Write the failing registry-diff test**

Create `agent/snapshot_windows_test.go`:

```go
//go:build windows

package main

import (
	"reflect"
	"sort"
	"testing"
)

func TestDiffRegistry_NewValue(t *testing.T) {
	key := `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	before := &SystemSnapshot{Files: map[string][]byte{
		"reg:" + key: []byte("    OneDrive    REG_SZ    C:\\OneDrive.exe\n"),
	}}
	after := &SystemSnapshot{Files: map[string][]byte{
		"reg:" + key: []byte("    OneDrive    REG_SZ    C:\\OneDrive.exe\n    Evil    REG_SZ    C:\\evil.exe\n"),
	}}
	want := []string{"registry:" + key + `\Evil`}
	got := diffRegistry(before, after)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("diffRegistry = %v, want %v", got, want)
	}
}

func TestDiffRegistry_KeyMissingFromBeforeSkipped(t *testing.T) {
	key := `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	before := &SystemSnapshot{Files: map[string][]byte{}}
	after := &SystemSnapshot{Files: map[string][]byte{
		"reg:" + key: []byte("    Evil    REG_SZ    C:\\evil.exe\n"),
	}}
	if got := diffRegistry(before, after); len(got) != 0 {
		t.Errorf("diffRegistry = %v, want empty (key absent from before is not a diffable pair)", got)
	}
}
```

- [ ] **Step 7: Run the registry test to verify it fails, then passes**

Run: `cd agent && go test ./... -run TestDiffRegistry -v`
Expected: first run FAILs if `diffRegistry` were not yet implemented — since Step 4 already implemented it in this same task, run this once and expect PASS directly. If it fails, re-check Step 4's code against `parseRegValues`' exact behavior in `agent/snapshot_windows.go`.

- [ ] **Step 8: Commit**

```bash
git add agent/snapshot.go agent/snapshot_windows.go agent/snapshot_posix.go agent/snapshot_test.go agent/snapshot_windows_test.go
git commit -m "feat(agent): add diffSnapshots/diffRegistry snapshot-diffing primitive"
git push
```

---

## Task 2: `captureSnapshotLite`

**Files:**
- Modify: `agent/snapshot_windows.go`
- Modify: `agent/snapshot_posix.go`
- Test: `agent/snapshot_windows_test.go`

**Interfaces:**
- Consumes: nothing new (uses existing `snapCmd`, `newSnapshot` from `agent/snapshot.go`).
- Produces: `captureSnapshotLite(runID string) *SystemSnapshot` (build-tag-selected pair), consumed by Task 4's per-step bracket.

- [ ] **Step 1: Write the failing subset test**

Add to `agent/snapshot_windows_test.go`:

```go
func TestCaptureSnapshotLite_ExcludesFirewallAndHosts(t *testing.T) {
	lite := captureSnapshotLite("test-run")
	if _, ok := lite.Files["firewall"]; ok {
		t.Error("captureSnapshotLite must not capture the firewall dump")
	}
	hostsPath := `C:\Windows\System32\drivers\etc\hosts`
	if _, ok := lite.Files[hostsPath]; ok {
		t.Error("captureSnapshotLite must not capture the hosts file")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd agent && go test ./... -run TestCaptureSnapshotLite -v`
Expected: FAIL — `captureSnapshotLite` undefined.

- [ ] **Step 3: Implement `captureSnapshotLite` in `agent/snapshot_windows.go`**

Append after `captureSnapshot` (before `revertFromSnapshot`):

```go
// captureSnapshotLite captures the same categories as captureSnapshot minus
// the netsh firewall dump and the hosts-file read — the two slowest calls,
// and essentially never what a step's own cleanup: script targets. Used for
// the per-step before/after bracket (see agent/executor.go), where the cost
// is paid twice per cleanup-bearing step rather than once per run.
func captureSnapshotLite(runID string) *SystemSnapshot {
	s := newSnapshot(runID)

	if out, err := snapCmd("schtasks", "/query", "/fo", "CSV", "/nh"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			fields := strings.SplitN(line, ",", 2)
			if len(fields) > 0 {
				name := strings.Trim(fields[0], `"`)
				s.Lists["schtasks"] = append(s.Lists["schtasks"], name)
			}
		}
	}

	if out, err := snapCmd("sc", "query", "type=", "all", "state=", "all"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "SERVICE_NAME:") {
				name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "SERVICE_NAME:"))
				if name != "" {
					s.Lists["services"] = append(s.Lists["services"], name)
				}
			}
		}
	}

	regKeys := []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
	}
	for _, key := range regKeys {
		if out, err := snapCmd("reg", "query", key); err == nil {
			s.Files["reg:"+key] = out
		}
	}

	tmpDirs := []string{os.TempDir(), `C:\Windows\Temp`}
	for _, dir := range tmpDirs {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				s.Lists["tmp_files"] = append(s.Lists["tmp_files"], filepath.Join(dir, e.Name()))
			}
		}
	}

	startupDirs := []string{
		filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`),
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`,
	}
	for _, dir := range startupDirs {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				s.Lists["startup"] = append(s.Lists["startup"], filepath.Join(dir, e.Name()))
			}
		}
	}

	return s
}
```

In `agent/snapshot_posix.go`, append at the end:

```go
// captureSnapshotLite is identical to captureSnapshot on POSIX — none of its
// calls are expensive enough to warrant a trimmed variant (unlike Windows'
// netsh firewall dump).
func captureSnapshotLite(runID string) *SystemSnapshot {
	return captureSnapshot(runID)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd agent && go test ./... -run TestCaptureSnapshotLite -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agent/snapshot_windows.go agent/snapshot_posix.go agent/snapshot_windows_test.go
git commit -m "feat(agent): add captureSnapshotLite for per-step snapshot brackets"
git push
```

---

## Task 3: `CleanupResidual` field + `reconcileCleanupVerdict`

**Files:**
- Modify: `agent/types.go`
- Modify: `agent/executor.go`
- Test: `agent/executor_test.go`

**Interfaces:**
- Consumes: `diffSnapshots` (Task 1), `captureSnapshotLite` (Task 2), `SystemSnapshot` (`agent/snapshot.go`).
- Produces: `ExecResult.CleanupResidual []string` (agent/types.go); `reconcileCleanupVerdict(pre, post *SystemSnapshot, verdict string) (residual []string, newVerdict string)` (agent/executor.go), consumed by Task 4.

- [ ] **Step 1: Add `CleanupResidual` to `ExecResult`**

In `agent/types.go`, immediately after the existing `CleanupVerdict` field (line 227):

```go
	// CleanupResidual lists the normalized snapshot-diff keys (see
	// diffSnapshots) still present after this step's own cleanup command ran.
	// Populated only for steps with a non-empty Cleanup script; nil means
	// either no cleanup was defined or the before/after snapshot pair could
	// not be captured (fails soft — never blocks the step).
	CleanupResidual []string `json:"cleanupResidual,omitempty"`
```

- [ ] **Step 2: Write the failing test for `reconcileCleanupVerdict`**

Add to `agent/executor_test.go`:

```go
func TestReconcileCleanupVerdict(t *testing.T) {
	clean := &SystemSnapshot{Lists: map[string][]string{"tmp_files": {"/tmp/a"}}}
	dirty := &SystemSnapshot{Lists: map[string][]string{"tmp_files": {"/tmp/a", "/tmp/evil"}}}

	cases := []struct {
		name         string
		pre, post    *SystemSnapshot
		verdict      string
		wantVerdict  string
		wantResidual int // len(residual) — 0 or 1 for these fixtures
	}{
		{"reverted downgrades when residue found", clean, dirty, "reverted", "partial", 1},
		{"leaked upgrades when no residue found", clean, clean, "leaked", "reverted", 0},
		{"partial stays partial regardless of residue", clean, dirty, "partial", "partial", 1},
		{"reverted stays reverted when no residue", clean, clean, "reverted", "reverted", 0},
		{"nil pre skips reconciliation", nil, clean, "leaked", "leaked", 0},
		{"nil post skips reconciliation", clean, nil, "leaked", "leaked", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			residual, verdict := reconcileCleanupVerdict(c.pre, c.post, c.verdict)
			if verdict != c.wantVerdict {
				t.Errorf("verdict = %q, want %q", verdict, c.wantVerdict)
			}
			if len(residual) != c.wantResidual {
				t.Errorf("len(residual) = %d, want %d (residual=%v)", len(residual), c.wantResidual, residual)
			}
		})
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd agent && go test ./... -run TestReconcileCleanupVerdict -v`
Expected: FAIL — `reconcileCleanupVerdict` undefined.

- [ ] **Step 4: Implement `reconcileCleanupVerdict` in `agent/executor.go`**

Add after `execStep` (before `trimOutput`):

```go
// reconcileCleanupVerdict lets snapshot-diff evidence override the raw
// exit-code verdict from runCleanup when they disagree: an exit-0 "reverted"
// verdict downgrades to "partial" if evidence shows residue left behind; a
// timed-out "leaked" verdict upgrades to "reverted" if evidence shows nothing
// left behind. "partial" is left unchanged either way — the spec calls out
// only these two specific overrides. A nil pre or post (snapshot capture
// unavailable) skips reconciliation entirely and returns the raw verdict
// unchanged with a nil residual — this never blocks or fails the step.
func reconcileCleanupVerdict(pre, post *SystemSnapshot, verdict string) ([]string, string) {
	if pre == nil || post == nil {
		return nil, verdict
	}
	residual := diffSnapshots(pre, post)
	switch {
	case verdict == "reverted" && len(residual) > 0:
		return residual, "partial"
	case verdict == "leaked" && len(residual) == 0:
		return residual, "reverted"
	default:
		return residual, verdict
	}
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd agent && go test ./... -run TestReconcileCleanupVerdict -v`
Expected: PASS (all 6 subtests).

- [ ] **Step 6: Commit**

```bash
git add agent/types.go agent/executor.go agent/executor_test.go
git commit -m "feat(agent): add CleanupResidual field and reconcileCleanupVerdict"
git push
```

---

## Task 4: Wire the pre/post snapshot bracket into `execStep`

**Files:**
- Modify: `agent/executor.go`
- Test: `agent/executor_test.go`

**Interfaces:**
- Consumes: `captureSnapshotLite` (Task 2), `reconcileCleanupVerdict` (Task 3).
- Produces: `execStep` now populates `ExecResult.CleanupResidual` for every cleanup-bearing step, on both the pooled and non-pooled paths.

**Note on caveat:** if every snapshot category fails to capture on both the pre and post side (e.g. every subprocess call is blocked), `diffSnapshots` returns an empty diff indistinguishable from "genuinely nothing left behind" — this is the same fail-soft blind spot `revertFromSnapshot`'s whole-run sweep already has today (a category that never succeeds simply reports nothing), not a new risk this task introduces. No `SystemSnapshot` capture-success flag is added — that would be new scope beyond the approved spec.

- [ ] **Step 1: Read current `execStep` call sites to confirm anchors**

Run: `grep -n "step.Cleanup != \"\"" agent/executor.go`
Expected output: two matches, one inside the pooled branch (`if pool != nil && pooledCandidate(step) {`), one after the non-pooled `cmd.Wait()` block. These are the two sites this step modifies.

- [ ] **Step 2: Capture the pre-snapshot once, before the pooled/non-pooled branch**

In `agent/executor.go`, immediately after `before := time.Now()` (top of `execStep`), add:

```go

	var preCleanupSnap *SystemSnapshot
	if step.Cleanup != "" {
		preCleanupSnap = captureSnapshotLite(step.TaskID)
	}
```

- [ ] **Step 3: Wrap the pooled-path cleanup call**

Replace:

```go
			if step.Cleanup != "" {
				r.CleanupVerdict = runCleanup(step)
			}
```

with:

```go
			if step.Cleanup != "" {
				r.CleanupVerdict = runCleanup(step)
				r.CleanupResidual, r.CleanupVerdict = reconcileCleanupVerdict(
					preCleanupSnap, captureSnapshotLite(step.TaskID), r.CleanupVerdict)
			}
```

- [ ] **Step 4: Wrap the non-pooled-path cleanup call**

Replace:

```go
	if step.Cleanup != "" {
		result.CleanupVerdict = runCleanup(step)
	}
```

with:

```go
	if step.Cleanup != "" {
		result.CleanupVerdict = runCleanup(step)
		result.CleanupResidual, result.CleanupVerdict = reconcileCleanupVerdict(
			preCleanupSnap, captureSnapshotLite(step.TaskID), result.CleanupVerdict)
	}
```

- [ ] **Step 5: Write a regression test confirming a cleanup-less step is untouched**

Add to `agent/executor_test.go` (this test needs no real subprocess execution — it only asserts the pre-snapshot short-circuit, which is cheap to verify structurally by reading the source guard rather than invoking `execStep`, since `execStep` requires a real host process and pool wiring beyond this task's scope):

```go
// TestExecStep_NoCleanupNeverSnapshots documents the invariant that
// preCleanupSnap (and therefore both captureSnapshotLite calls) are gated
// behind step.Cleanup != "" — a step with no cleanup script must never pay
// the snapshot cost. Enforced by code inspection here rather than an
// integration run of execStep, which needs a real process/pool.
func TestExecStep_NoCleanupNeverSnapshots(t *testing.T) {
	src, err := os.ReadFile("executor.go")
	if err != nil {
		t.Fatalf("read executor.go: %v", err)
	}
	if !strings.Contains(string(src), `if step.Cleanup != "" {\n\t\tpreCleanupSnap = captureSnapshotLite`) &&
		!strings.Contains(string(src), "if step.Cleanup != \"\" {\n\t\tpreCleanupSnap = captureSnapshotLite") {
		t.Error("preCleanupSnap must only be captured when step.Cleanup != \"\"")
	}
}
```

Add `"os"` and `"strings"` to `agent/executor_test.go`'s import block if not already present (check first — `executor_test.go` already imports `"strings"` per Task 3's additions; confirm `"os"` is present, add it if not).

- [ ] **Step 6: Run the full agent test suite**

Run: `cd agent && go build ./... && go test ./... -v`
Expected: PASS, zero `--- FAIL` lines, build succeeds (this compiles both the changed executor.go and confirms no platform-specific breakage).

- [ ] **Step 7: Commit**

```bash
git add agent/executor.go agent/executor_test.go
git commit -m "feat(agent): bracket cleanup-bearing steps with before/after snapshots"
git push
```

---

## Task 5: Thread `CleanupResidual` through the wire format and reporting structs

**Files:**
- Modify: `orchestrator/internal/scenario/types.go`
- Modify: `orchestrator/internal/scenario/interpreter.go`
- Modify: `orchestrator/internal/models/schema.go`
- Modify: `orchestrator/internal/reporting/engine.go`
- Test: `orchestrator/internal/scenario/interpreter_test.go` (check if it exists first — see Step 3)
- Test: `orchestrator/internal/reporting/engine_test.go`

**Interfaces:**
- Consumes: the agent's `cleanupResidual` JSON field (Task 3), now present on posted `ExecResult`s.
- Produces: `models.SimulationResult.CleanupResidual []string`; `reporting.TechniqueRow.CleanupResidual []string`, consumed by Task 6's `buildEnvRestoration` reconciliation.

- [ ] **Step 1: Add `CleanupResidual` to `scenario.ExecResult`**

In `orchestrator/internal/scenario/types.go`, immediately after the existing `CleanupVerdict` field (line 366):

```go
	// CleanupResidual lists the normalized snapshot-diff keys the agent found
	// still present after this step's own cleanup command ran (see
	// agent/executor.go's reconcileCleanupVerdict). Nil when no cleanup was
	// defined or the agent's before/after snapshot pair wasn't captured.
	CleanupResidual []string `json:"cleanupResidual,omitempty"`
```

- [ ] **Step 2: Add `CleanupResidual` to `models.SimulationResult`**

In `orchestrator/internal/models/schema.go`, immediately after the existing `CleanupVerdict` field (line 70):

```go
	CleanupResidual []string `json:"cleanupResidual,omitempty"` // normalized snapshot-diff keys still present after the step's own cleanup ran
```

- [ ] **Step 3: Wire the pass-through in `Interpret`**

In `orchestrator/internal/scenario/interpreter.go`, immediately after the existing `CleanupVerdict: result.CleanupVerdict,` line (line 84):

```go
		CleanupResidual:     result.CleanupResidual,
```

Check for an existing test file first: run `ls orchestrator/internal/scenario/*_test.go | grep -i interpret` (or the PowerShell equivalent `Get-ChildItem orchestrator/internal/scenario/*interpret*test*`). If `TestInterpret*`-style tests exist that construct a full `models.SimulationResult` and compare it field-by-field (e.g. via `reflect.DeepEqual` or an exhaustive struct literal), extend the existing fixture with a `CleanupResidual` value and assert it passes through unchanged. If no such test exists, skip to Step 4 — this is a one-line mechanical pass-through identical in shape to `CleanupVerdict`'s existing pass-through, and Task 8's end-to-end test already exercises it live.

- [ ] **Step 4: Add `CleanupResidual` to `TechniqueRow` and wire `buildTechniqueMatrix`**

In `orchestrator/internal/reporting/engine.go`, add to the `TechniqueRow` struct immediately after the existing `CleanupVerdict` field (line 464):

```go
	// CleanupResidual mirrors models.SimulationResult.CleanupResidual — see
	// buildEnvRestoration for how it's cross-referenced against reverted[] to
	// produce the "rescued" verdict.
	CleanupResidual []string `json:"cleanupResidual,omitempty"`
```

In `buildTechniqueMatrix`, immediately after the existing `CleanupVerdict: r.CleanupVerdict,` line (line 931):

```go
			CleanupResidual:   r.CleanupResidual,
```

- [ ] **Step 5: Write a failing test asserting the pass-through**

Add to `orchestrator/internal/reporting/engine_test.go`:

```go
func TestBuildTechniqueMatrix_PassesThroughCleanupResidual(t *testing.T) {
	results := []models.SimulationResult{
		{
			Technique:        models.AttackTechnique{ID: "T1053.005", Tactic: "persistence"},
			Result:           models.ResultFail,
			Severity:         "High",
			CleanupVerdict:   "partial",
			CleanupResidual:  []string{"schtask:\\Evil\\Task"},
		},
	}
	rows := buildTechniqueMatrix(results, nil)
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	want := []string{"schtask:\\Evil\\Task"}
	if !reflect.DeepEqual(rows[0].CleanupResidual, want) {
		t.Errorf("CleanupResidual = %v, want %v", rows[0].CleanupResidual, want)
	}
}
```

Add `"reflect"` to `engine_test.go`'s import block.

- [ ] **Step 6: Run the test to verify it fails, then implement, then verify it passes**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestBuildTechniqueMatrix_PassesThroughCleanupResidual -v`
Expected before Step 4's edit: FAIL (unknown field `CleanupResidual` in struct literal). After Step 4's edit: PASS.

- [ ] **Step 7: Run the full scenario + reporting + models package suites**

Run: `cd orchestrator && go build ./... && go test ./internal/scenario/... ./internal/models/... ./internal/reporting/... -v`
Expected: PASS, zero `--- FAIL` lines.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/scenario/types.go orchestrator/internal/scenario/interpreter.go orchestrator/internal/models/schema.go orchestrator/internal/reporting/engine.go orchestrator/internal/reporting/engine_test.go
git commit -m "feat(reporting): thread CleanupResidual through the report pipeline"
git push
```

---

## Task 6: `buildEnvRestoration` reconciliation — the `rescued` state

**Files:**
- Modify: `orchestrator/internal/reporting/engine.go`
- Test: `orchestrator/internal/reporting/engine_test.go`

**Interfaces:**
- Consumes: `TechniqueRow.CleanupResidual` (Task 5), the existing `reverted []string` parameter `buildEnvRestoration` already receives from all three call sites.
- Produces: `EnvRestoration.StepsRescued int`; `buildEnvRestoration`'s signature stays `(matrix []TechniqueRow, reverted []string) EnvRestoration` exactly as before, but its body now mutates matched rows' `CleanupVerdict` in place from `"leaked"`/`"partial"` to `"rescued"` — visible to the caller since `matrix` is a slice sharing the caller's backing array, and therefore visible in the JSON response's `technique matrix` table too, not just the aggregate.

**Design note carried forward from planning:** the spec's "extend the CleanupVerdict doc comment with the new 'rescued' value" is applied to `TechniqueRow.CleanupVerdict` (engine.go), not `models.SimulationResult.CleanupVerdict` (schema.go) — `"rescued"` is a report-rendering-time enrichment computed fresh on every request; the persisted per-run raw verdict in `models.SimulationResult` (and the DB's `results` JSONB column) is never mutated or reinterpreted. This was confirmed safe by checking all three `buildEnvRestoration` call sites: each already computes `report.CleanupFailed`/`CleanupFailedCount` from the raw per-row verdict *before* calling `buildEnvRestoration`, and the frontend (Task 7) only reads `report.CleanupFailed` as a fallback when `envRestoration.hasData` is false — so leaving that counter based on the raw verdict does not reintroduce any contradiction.

- [ ] **Step 1: Write the failing reconciliation tests**

Add to `orchestrator/internal/reporting/engine_test.go`:

```go
func TestBuildEnvRestoration_RescuedWhenResidualMatchesReverted(t *testing.T) {
	matrix := []TechniqueRow{
		{TechniqueID: "T1053.005", CleanupVerdict: "leaked", CleanupResidual: []string{"schtask:\\Evil\\Task"}},
	}
	reverted := []string{"schtask deleted: \\Evil\\Task"}

	e := buildEnvRestoration(matrix, reverted)

	if e.StepsRescued != 1 {
		t.Errorf("StepsRescued = %d, want 1", e.StepsRescued)
	}
	if e.StepsCleaned != 1 {
		t.Errorf("StepsCleaned = %d, want 1 (rescued counts toward cleaned)", e.StepsCleaned)
	}
	if e.StepsLeaked != 0 {
		t.Errorf("StepsLeaked = %d, want 0", e.StepsLeaked)
	}
	if matrix[0].CleanupVerdict != "rescued" {
		t.Errorf("matrix[0].CleanupVerdict = %q, want %q (mutated in place)", matrix[0].CleanupVerdict, "rescued")
	}
}

func TestBuildEnvRestoration_LeakedWhenResidualHasNoMatch(t *testing.T) {
	matrix := []TechniqueRow{
		{TechniqueID: "T1053.005", CleanupVerdict: "leaked", CleanupResidual: []string{"tmp:/tmp/evil"}},
	}
	reverted := []string{"schtask deleted: \\Unrelated\\Task"}

	e := buildEnvRestoration(matrix, reverted)

	if e.StepsRescued != 0 {
		t.Errorf("StepsRescued = %d, want 0", e.StepsRescued)
	}
	if e.StepsLeaked != 1 {
		t.Errorf("StepsLeaked = %d, want 1", e.StepsLeaked)
	}
	if matrix[0].CleanupVerdict != "leaked" {
		t.Errorf("matrix[0].CleanupVerdict = %q, want unchanged %q", matrix[0].CleanupVerdict, "leaked")
	}
}

func TestBuildEnvRestoration_NilResidualFallsBackToLegacyMath(t *testing.T) {
	// Historical row recorded before this change: CleanupVerdict set, CleanupResidual nil.
	matrix := []TechniqueRow{
		{TechniqueID: "T1053.005", CleanupVerdict: "leaked", CleanupResidual: nil},
	}
	reverted := []string{"schtask deleted: \\Evil\\Task"}

	e := buildEnvRestoration(matrix, reverted)

	if e.StepsRescued != 0 {
		t.Errorf("StepsRescued = %d, want 0 (nil residual must never match)", e.StepsRescued)
	}
	if e.StepsLeaked != 1 {
		t.Errorf("StepsLeaked = %d, want 1 (unchanged legacy classification)", e.StepsLeaked)
	}
}

func TestNormalizeReverted(t *testing.T) {
	cases := []struct {
		entry   string
		wantKey string
		wantOK  bool
	}{
		{"tmp removed: /tmp/evil", "tmp:/tmp/evil", true},
		{"registry removed: HKCU\\Run\\Evil", "registry:HKCU\\Run\\Evil", true},
		{"schtask deleted: \\Evil\\Task", "schtask:\\Evil\\Task", true},
		{"service stopped: EvilSvc", "service:EvilSvc", true},
		{"startup removed: C:\\Startup\\evil.lnk", "startup:C:\\Startup\\evil.lnk", true},
		{"cron removed: /etc/cron.d/evil", "cron:/etc/cron.d/evil", true},
		{"file restored: /etc/hosts", "/etc/hosts", true},
		{"crontab: user crontab restored", "crontab:user", true},
		{"iptables: rules restored", "iptables", true},
		{"something unrecognized", "", false},
	}
	for _, c := range cases {
		key, ok := normalizeReverted(c.entry)
		if ok != c.wantOK || key != c.wantKey {
			t.Errorf("normalizeReverted(%q) = (%q, %v), want (%q, %v)", c.entry, key, ok, c.wantKey, c.wantOK)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/reporting/... -run "TestBuildEnvRestoration_|TestNormalizeReverted" -v`
Expected: FAIL — `normalizeReverted` undefined; `StepsRescued` unknown field; rescued mutation not yet implemented (all failures are compile/assertion errors, not panics).

- [ ] **Step 3: Add `StepsRescued` to `EnvRestoration`**

In `orchestrator/internal/reporting/engine.go`, add to the `EnvRestoration` struct immediately after `StepsLeaked` (line 3195):

```go
	StepsRescued     int     `json:"stepsRescued,omitempty"` // subset of StepsCleaned that a step's own script failed to clean, later confirmed removed by the whole-run safety net
```

- [ ] **Step 4: Extend `TechniqueRow.CleanupVerdict`'s doc comment**

Change (line 464):

```go
	CleanupVerdict   string `json:"cleanupVerdict,omitempty"` // reverted|partial|leaked
```

to:

```go
	CleanupVerdict   string `json:"cleanupVerdict,omitempty"` // reverted|partial|leaked|rescued ("rescued" is set only by buildEnvRestoration, at report-build time — never the raw agent verdict)
```

- [ ] **Step 5: Implement `normalizeReverted` and the reconciliation pass**

Add above `buildEnvRestoration` (after the `EnvRestoration` struct, before the function's existing doc comment):

```go
// revertedKeyPrefixes maps each human-readable prefix revertFromSnapshot
// writes into a run's reverted[] log (agent/snapshot_windows.go,
// agent/snapshot_posix.go) back to the normalized key format diffSnapshots
// uses for CleanupResidual, so a step's residual keys can be cross-referenced
// against what the whole-run safety net actually confirmed removing.
var revertedKeyPrefixes = []struct{ from, to string }{
	{"tmp removed: ", "tmp:"},
	{"registry removed: ", "registry:"},
	{"schtask deleted: ", "schtask:"},
	{"service stopped: ", "service:"},
	{"startup removed: ", "startup:"},
	{"cron removed: ", "cron:"},
	{"file restored: ", ""},
}

// normalizeReverted maps one reverted[] log entry to its normalized
// CleanupResidual-format key. ok is false for an entry with no known mapping
// ("crontab: user crontab restored", "iptables: rules restored" — fixed
// literal log lines handled as exact-match special cases below, and anything
// else unrecognized) — those never match a residual key, so the step they
// might relate to is conservatively left at its raw verdict rather than
// guessed as rescued.
func normalizeReverted(entry string) (key string, ok bool) {
	switch entry {
	case "crontab: user crontab restored":
		return "crontab:user", true
	case "iptables: rules restored":
		return "iptables", true
	}
	for _, p := range revertedKeyPrefixes {
		if strings.HasPrefix(entry, p.from) {
			return p.to + strings.TrimPrefix(entry, p.from), true
		}
	}
	return "", false
}

// normalizeRevertedSet builds a lookup set of every reverted[] entry this
// run's whole-run safety net logged, in normalized-key form.
func normalizeRevertedSet(reverted []string) map[string]bool {
	set := make(map[string]bool, len(reverted))
	for _, entry := range reverted {
		if key, ok := normalizeReverted(entry); ok {
			set[key] = true
		}
	}
	return set
}
```

Check whether `orchestrator/internal/reporting/engine.go` already imports `"strings"` (run `grep -n '"strings"' orchestrator/internal/reporting/engine.go`); add it to the import block if missing.

Then, at the top of `buildEnvRestoration` (before the existing `e := EnvRestoration{...}` line), add the reconciliation pass:

```go
func buildEnvRestoration(matrix []TechniqueRow, reverted []string) EnvRestoration {
	revertedSet := normalizeRevertedSet(reverted)
	for i := range matrix {
		if matrix[i].CleanupVerdict != "leaked" && matrix[i].CleanupVerdict != "partial" {
			continue
		}
		for _, key := range matrix[i].CleanupResidual {
			if revertedSet[key] {
				matrix[i].CleanupVerdict = "rescued"
				break
			}
		}
	}

	e := EnvRestoration{
		StepsTotal:    len(matrix),
		RevertedCount: len(reverted),
	}
	for _, r := range matrix {
		switch r.CleanupVerdict {
		case "reverted":
			e.StepsWithCleanup++
			e.StepsCleaned++
		case "rescued":
			e.StepsWithCleanup++
			e.StepsCleaned++
			e.StepsRescued++
		case "partial", "leaked":
			e.StepsWithCleanup++
			e.StepsLeaked++
		default:
			e.StepsNoCleanup++
		}
	}
```

(The rest of `buildEnvRestoration` — cleanup rate, coverage rate, the `ImpactLevel`/`ImpactLabel`/`StatusLabel`/`ExecSummary` switch, and `e.HasData` — stays exactly as it is today; do not duplicate it.)

- [ ] **Step 6: Append the rescued-count sentence to `ExecSummary`**

Immediately before the existing `e.HasData = e.StepsTotal > 0` line (end of the function), add:

```go
	if e.StepsRescued > 0 {
		e.ExecSummary += fmt.Sprintf(" %d of these were cleaned by the safety-net sweep, not by their own script.", e.StepsRescued)
	}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/reporting/... -run "TestBuildEnvRestoration_|TestNormalizeReverted" -v`
Expected: PASS (all 4 tests).

- [ ] **Step 8: Run the full reporting package suite**

Run: `cd orchestrator && go build ./... && go test ./internal/reporting/... -v`
Expected: PASS, zero `--- FAIL` lines — this also catches any other test in the package that constructs an `EnvRestoration` or `TechniqueRow` literal and would need updating for the new field (unlikely given `omitempty`, but confirm).

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/reporting/engine.go orchestrator/internal/reporting/engine_test.go
git commit -m "feat(reporting): reconcile leaked-but-rescued steps in buildEnvRestoration"
git push
```

---

## Task 7: Frontend — "rescued" badge on the Environment Restoration panel

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: `rep.envRestoration.stepsRescued` (Task 6) — already present on the same `envR` object the panel's existing rendering code reads `stepsLeaked`/`stepsCleaned`/`execSummary` from.

- [ ] **Step 1: Locate the exact insertion point**

Run: `grep -n "step(s) leaked" orchestrator/wwwroot/index.html`
Expected: one match, the line building `erLeaked > 0 ? '...step(s) leaked...' : ''` (currently line 14719).

- [ ] **Step 2: Add the rescued badge line**

Immediately after that line (still inside the same `html += '<div ...>' + ... +` chain, before `erItemsHtml +`), add:

```javascript
      (envR && envR.stepsRescued > 0 ? '<div style="font-size:0.72rem;color:var(--warning);margin-bottom:4px">&#9888; ' + envR.stepsRescued + ' step(s) cleaned by the safety-net sweep, not by their own script</div>' : '') +
```

The full block (lines 14719-14720 today) becomes:

```javascript
      (erLeaked > 0 ? '<div style="font-size:0.72rem;color:var(--danger);margin-bottom:4px">&#9888; ' + erLeaked + ' step(s) leaked &nbsp;&#8226;&nbsp; ' + erCleaned + ' cleaned</div>' : '') +
      (envR && envR.stepsRescued > 0 ? '<div style="font-size:0.72rem;color:var(--warning);margin-bottom:4px">&#9888; ' + envR.stepsRescued + ' step(s) cleaned by the safety-net sweep, not by their own script</div>' : '') +
      erItemsHtml +
```

- [ ] **Step 3: Verify JS syntax**

Extract the inline `<script>` block and check it, following this session's established method:

```bash
python3 -c "
import re
html = open('orchestrator/wwwroot/index.html', encoding='utf-8').read()
scripts = re.findall(r'<script(?:\s[^>]*)?>(.*?)</script>', html, re.S)
open('/tmp/index_scripts.js', 'w', encoding='utf-8').write('\n'.join(scripts))
"
node --check /tmp/index_scripts.js
```

Expected: no output from `node --check` (success).

- [ ] **Step 4: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): show a rescued-by-safety-net badge on the Environment Restoration panel"
git push
```

---

## Task 8: End-to-end test through `GetRunReportData`

**Files:**
- Modify: `orchestrator/internal/api/report_fixtures_test.go`
- Test: `orchestrator/internal/api/run_report_api_test.go`

**Interfaces:**
- Consumes: `seedReportableRun` (existing fixture helper), `reportRunOpts` (existing struct, gains one field), the full pipeline from Tasks 5-6.

- [ ] **Step 1: Add a `Reverted` field to `reportRunOpts` and thread it into the INSERT**

In `orchestrator/internal/api/report_fixtures_test.go`, add to `reportRunOpts` (after `TechniqueOverride`, line 125):

```go
	Reverted          []string
```

In `seedReportableRun`, after the existing `resultsJSON, err := json.Marshal(results)` block (after line 165), add:

```go
	revertedJSON, err := json.Marshal(opts.Reverted)
	if err != nil {
		t.Fatalf("marshal reverted: %v", err)
	}
```

Then change the INSERT statement (lines 185-194) from:

```go
	if _, err := pool.Exec(ctx,
		`INSERT INTO scenario_runs
		   (id, scenario_id, agent_id, name, status, results, started_at, campaign_id,
		    alerts_total, alerts_high_fidelity, noise_score,
		    perf_cpu_before, perf_cpu_after, perf_ram_before, perf_ram_after, perf_disk_before, perf_disk_after)
		 VALUES ($1,'sc-report',$2,$3,$4,$5, COALESCE($6::timestamptz, NOW()), $7,
		    42, 7, 3.5, 10, 25, 30, 55, 1, 2)`,
		runID, agentID, name, status, resultsJSON, startedAt, campaignID); err != nil {
		t.Fatalf("seed reportable run: %v", err)
	}
```

to:

```go
	if _, err := pool.Exec(ctx,
		`INSERT INTO scenario_runs
		   (id, scenario_id, agent_id, name, status, results, started_at, campaign_id, reverted,
		    alerts_total, alerts_high_fidelity, noise_score,
		    perf_cpu_before, perf_cpu_after, perf_ram_before, perf_ram_after, perf_disk_before, perf_disk_after)
		 VALUES ($1,'sc-report',$2,$3,$4,$5, COALESCE($6::timestamptz, NOW()), $7, $8,
		    42, 7, 3.5, 10, 25, 30, 55, 1, 2)`,
		runID, agentID, name, status, resultsJSON, startedAt, campaignID, revertedJSON); err != nil {
		t.Fatalf("seed reportable run: %v", err)
	}
```

This is additive and backward-compatible: every existing caller that doesn't set `opts.Reverted` now passes `json.Marshal(nil)` → `"null"` for the `reverted` column, which `json.Unmarshal(revertedRaw, &report.Reverted)` in `BuildFromRun` already handles today exactly as it handles a genuinely-absent value (`report.Reverted` stays nil) — no existing test's behavior changes.

- [ ] **Step 2: Write the failing end-to-end test**

Add to `orchestrator/internal/api/run_report_api_test.go`:

```go
// TestGetRunReportData_EnvRestoration_RescuedNotContradictory is the direct
// regression test for the bug this plan fixes: a step whose own cleanup
// script failed (CleanupVerdict "leaked") but whose artifact the whole-run
// safety net later removed (present in reverted[]) must be counted as
// cleaned in the envRestoration headline, not as leaked — so the panel's
// stepsLeaked figure never contradicts the reverted[] rollback list shown
// alongside it.
func TestGetRunReportData_EnvRestoration_RescuedNotContradictory(t *testing.T) {
	pool := testPool(t) // matches this file's existing pool-acquisition helper; adjust name if run_report_api_test.go uses a different helper — check with: grep -n "func testPool\|pool :=" orchestrator/internal/api/run_report_api_test.go
	h := newReportingHandler(t, pool, nil)

	runID := "run-rescued-1"
	agentID := "agent-rescued-1"
	rescuedStep := models.SimulationResult{
		ID:              "res-rescued",
		Technique:       models.AttackTechnique{ID: "T1053.005", Name: "Scheduled Task", Tactic: "persistence"},
		Result:          models.ResultFail,
		Severity:        "High",
		CleanupVerdict:  "leaked",
		CleanupResidual: []string{"schtask:\\Evil\\RescueMe"},
		ExecutedAt:      time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
		StartedAt:       time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
	}
	genuinelyLeakedStep := models.SimulationResult{
		ID:             "res-leaked",
		Technique:      models.AttackTechnique{ID: "T1543.003", Name: "Windows Service", Tactic: "persistence"},
		Result:         models.ResultFail,
		Severity:       "High",
		CleanupVerdict: "leaked",
		ExecutedAt:     time.Date(2026, 7, 1, 12, 1, 0, 0, time.UTC),
		StartedAt:      time.Date(2026, 7, 1, 12, 1, 0, 0, time.UTC),
	}

	seedReportableRun(t, pool, runID, agentID, reportRunOpts{
		Results:  []models.SimulationResult{rescuedStep, genuinelyLeakedStep},
		Reverted: []string{"schtask deleted: \\Evil\\RescueMe"},
	})

	rr := httptest.NewRequest("GET", "/api/scenarios/runs/"+runID+"/report.json", nil)
	rr.SetPathValue("runId", runID) // adjust to this file's actual routing helper — check with: grep -n "GetRunReportData\|mux.SetURLVars\|chi.RouteContext" orchestrator/internal/api/run_report_api_test.go for the established pattern
	w := httptest.NewRecorder()
	h.GetRunReportData(w, rr)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	er, ok := resp["envRestoration"].(map[string]any)
	if !ok {
		t.Fatalf("envRestoration missing or wrong shape: %v", resp["envRestoration"])
	}
	if got := er["stepsRescued"]; got != float64(1) {
		t.Errorf("envRestoration.stepsRescued = %v, want 1", got)
	}
	if got := er["stepsLeaked"]; got != float64(1) {
		t.Errorf("envRestoration.stepsLeaked = %v, want 1 (only the genuinely-leaked step)", got)
	}
	if got := er["stepsCleaned"]; got != float64(1) {
		t.Errorf("envRestoration.stepsCleaned = %v, want 1 (the rescued step counts as cleaned)", got)
	}

	reverted, _ := resp["reverted"].([]any)
	if len(reverted) != 1 {
		t.Fatalf("reverted = %v, want 1 entry", reverted)
	}
}
```

**Before running:** this file's exact test-request/routing pattern (how existing tests in `run_report_api_test.go` construct the request and invoke the handler — `httptest.NewRequest` + a router, or a direct handler call with path params set some other way) must match what's already established in that file. Run `grep -n "func TestGetRunReportData" -A 25 orchestrator/internal/api/run_report_api_test.go` first and copy the exact request-construction pattern from `TestGetRunReportData_Shape` (referenced in this plan's grounding — already confirmed to exist and pass) instead of the placeholder `httptest`/`SetPathValue` lines above, which are illustrative only.

- [ ] **Step 3: Run the test to verify it fails, then passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetRunReportData_EnvRestoration_RescuedNotContradictory -v`
Expected before Task 6 lands (it already has by this point in the plan, so this should PASS on first real run once the request-construction pattern is corrected per Step 2's note) — if it fails, the failure must be a genuine mismatch to debug via `superpowers:systematic-debugging`, not a placeholder-pattern issue silently ignored.

- [ ] **Step 4: Run the full API package suite**

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -v`
Expected: PASS, zero `--- FAIL` lines.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/report_fixtures_test.go orchestrator/internal/api/run_report_api_test.go
git commit -m "test(api): add end-to-end regression test for rescued-step reconciliation"
git push
```

---

## Task 9: Full verification and cost measurement

**Files:** none (verification only, plus a short note if cost measurement surfaces something worth documenting).

- [ ] **Step 1: Run the complete agent test suite**

Run: `cd agent && go build ./... && go test ./... -v`
Expected: PASS, zero `--- FAIL` lines.

- [ ] **Step 2: Run the complete orchestrator test suite**

Run: `cd orchestrator && go build ./... && go test ./... -v`
Expected: PASS, zero `--- FAIL` lines. (This is a large suite — run with a generous timeout, e.g. `go test ./... -v -timeout 20m`.)

- [ ] **Step 3: Measure the real per-step snapshot cost against a live sweep**

The spec's Cost section explicitly asks for this to be measured, not assumed: "This should be measured against a real sweep during implementation and reported, not assumed away." If a live Windows agent + orchestrator can be brought up in this environment, run a scenario with several `cleanup:`-bearing steps (e.g. one of the ART Full Sweep scenarios) before and after this change, and compare total wall-clock run duration. If no live environment is reasonably available in this session, say so explicitly rather than claiming this was measured — matching the spec's own "Real hardware verification... is out of scope for this session — flagged honestly as unverified rather than claimed complete."

- [ ] **Step 4: Use the finishing-a-development-branch skill**

Announce: "I'm using the finishing-a-development-branch skill to complete this work." Follow that skill: verify the full test suite is green (Steps 1-2 above already did this), detect the git environment, and present the standard merge/PR/keep-as-is options to the user rather than deciding unilaterally.

---

## Self-Review

- **Spec coverage:** Design §1 (per-step evidence-based verdict) → Tasks 1-4. Design §2 (server-side reconciliation) → Task 6. Data model changes → Tasks 3, 5, 6 (every listed file touched: `agent/types.go`, `agent/snapshot*.go`, `agent/executor.go`, `internal/models/schema.go`, `internal/reporting/engine.go`, `wwwroot/index.html`). Error handling → Task 4's caveat note, Task 3's nil-snapshot branch, Task 6's nil-residual test. Cost → Task 9 Step 3. Testing → every task's own test steps plus Task 8's end-to-end fixture. Out of scope (no per-step attribution for cleanup-less steps, no scheduler changes, no Windows-only scoping) → none of the nine tasks touch the scheduler, `AttachProfiles`, or add any attribution for steps without a `cleanup:` script.
- **Placeholder scan:** the only intentionally-illustrative (not literal) code is in Task 8 Step 2, explicitly flagged as such with an instruction to replace it with the file's real established pattern before running — this is not a "TBD", it's a concrete unblocking instruction for a fact this plan could not observe without reading a file whose content was already summarized as "219 lines, seen before compaction" but not re-verified fresh in this session.
- **Type consistency:** `CleanupResidual []string` with JSON tag `cleanupResidual,omitempty` is identical across all four struct additions (`agent/types.go`, `orchestrator/internal/scenario/types.go`, `orchestrator/internal/models/schema.go`, `orchestrator/internal/reporting/engine.go`). `reconcileCleanupVerdict(pre, post *SystemSnapshot, verdict string) ([]string, string)` in Task 3 is called with exactly that signature in Task 4. `diffSnapshots(before, after *SystemSnapshot) []string` and `diffRegistry(before, after *SystemSnapshot) []string` in Task 1 match their Task 3 (`reconcileCleanupVerdict`) and Task 6 (`buildEnvRestoration`, indirectly via `TechniqueRow.CleanupResidual`) call sites.

## Execution Handoff

Plan complete and saved to `orchestrator/docs/superpowers/plans/2026-08-24-environment-restoration-accuracy.md`. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

This session's established pattern throughout today's work has been inline execution — but the choice is yours either way.

**Which approach?**
