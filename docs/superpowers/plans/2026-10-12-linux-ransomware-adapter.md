# Linux Ransomware Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the existing Windows-only ransomware evidence pipeline (T1490/T1486 via `rwevidence`) to recognize a Linux-flavored procedure for each technique, add one new Linux scenario exercising them, and register that scenario everywhere the existing 8-scenario corpus is tracked.

**Architecture:** Additive-only changes to one already-shipped dispatch file, one new scenario YAML, and six separate registration edits across existing files that each maintain their own copy of "the ransomware scenario list." No new Go package, no new DB schema, no new HTTP endpoint, no `Platform` field anywhere.

**Tech Stack:** Go (existing `rwevidence`/`rwdetect`/`rwtaxonomy`/`api` packages), YAML scenario content, bash (new scenario's steps; existing scenarios use `powershell`).

**Spec:** `docs/superpowers/specs/2026-10-12-linux-ransomware-adapter-design.md`

## Global Constraints

- No new `TechniqueID`, no new `Capability`, no new `SkipReason` value, no `Platform` field anywhere. Reuse `T1490` and `T1486` exactly as `rwevidence` already models them.
- `backupassurance` gets zero changes this pass.
- `T1486`'s dispatch classification path is unchanged — the new Linux `T1486` steps are not in `reconnaissanceStepNames` and hit no skip pattern, so they classify as genuine attempts via the existing default path, exactly like their Windows siblings. Only `T1490`'s recon-name recognition and skip-text patterns get new, additive entries.
- The LVM snapshot deletion step acts on a real snapshot when explicitly confirmed — same risk profile as the already-accepted Windows VSS deletion step, not a weaker synthetic stand-in.
- Every one of the six registration touchpoints (Task 3) must be updated; this plan's own self-review must point to the task that updates each one.
- A Linux-run result must never be confusable with Windows coverage: the new scenario's `detection_profiles` use only `linux_*`-prefixed names, never a `windows_*`-prefixed one.
- This pass covers Linux only. No macOS, no ESXi/vSphere, no VM storage/datastores, no NAS, no cloud object storage, no hypervisor/storage identities — those are each their own later pass.

## Review Focus

- The new scenario's `detection_profiles` must never reuse a `windows_*`-prefixed name — Task 2 pins this with a dedicated assertion, not just "the YAML parses."
- The existing Windows `dispatch_test.go` cases must still pass unchanged after the additive edit — Task 1 runs the whole file, not just the new cases, as its own completion gate.
- `internal/api`'s `ransomwareScenarioIDs` map has no existing fail-closed test tying it to the real scenario corpus (confirmed: `rwevidence_dispatch_test.go` has no such test today) — this is the single most consequential gap in this plan, since a missed entry here means a run is silently never evaluated, with no test anywhere currently positioned to catch it. Task 3 adds a new real-corpus two-way test for it, modeled on the pattern `rwdetect`/`rwevidence`/`rwtaxonomy` already use, not just the one map entry.
- The YAML smoke test must assert `supported_os` is exactly `["linux"]`, catching a copy-paste of `windows` into the new file.
- The `.sig` file must actually verify via the repo's own `verify-all` mechanism, not merely exist as a file.

---

### Task 1: `dispatch.go` — recognize Linux LVM step name and skip-text

**Files:**
- Modify: `orchestrator/internal/rwevidence/dispatch.go:26-29` (add one `reconnaissanceStepNames` entry), `dispatch.go:66-74` (add two skip-text `switch` cases)
- Modify: `orchestrator/internal/rwevidence/dispatch_test.go` (add 3 new test functions)

**Interfaces:**
- Consumes: nothing new — this task only extends `classifyRansomwareStep`'s existing recognition tables. Signature unchanged: `classifyRansomwareStep(in StepInput) (modeled bool, isAttempt bool, specificReason string)`.
- Produces: nothing new for later tasks to consume directly — Task 2's scenario content is written to match these exact recognized strings (`"LVM Snapshot Enumeration"`, `"bas_confirm_lvm_delete not set"`, `"no lvm snapshots exist"`), so this task's recognized text is the contract Task 2 must match verbatim (case-insensitively, since `classifyRansomwareStep` lowercases `in.Details` before matching).

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/rwevidence/dispatch_test.go` (after `TestClassify_ReconnaissanceStep`, mirroring its exact style):

```go
func TestClassify_LinuxLVMReconnaissanceStep(t *testing.T) {
	in := StepInput{TechniqueID: "T1490", StepName: "LVM Snapshot Enumeration", RunID: "r1", Action: "x", CheckResult: "pass"}
	modeled, isAttempt, specificReason := classifyRansomwareStep(in)
	if !modeled {
		t.Fatal("T1490 is modeled")
	}
	if isAttempt {
		t.Fatal("an LVM enumeration step is not an attempt")
	}
	if specificReason != "not_an_attempt" {
		t.Fatalf("specificReason = %q, want not_an_attempt", specificReason)
	}
}

func TestClassify_LinuxLVMGateNotConfirmed(t *testing.T) {
	in := StepInput{
		TechniqueID: "T1490", StepName: "LVM Snapshot Removal", RunID: "r1", Action: "x",
		CheckResult: "skipped",
		Details:     "SKIP: BAS_CONFIRM_LVM_DELETE not set to 'true' - LVM snapshot deletion skipped (default-disabled per ransomware safety policy).",
	}
	modeled, isAttempt, specificReason := classifyRansomwareStep(in)
	if !modeled || !isAttempt {
		t.Fatalf("modeled=%v isAttempt=%v, want true/true (this IS the destructive attempt step, it just didn't run)", modeled, isAttempt)
	}
	if specificReason != "gate_not_confirmed" {
		t.Fatalf("specificReason = %q, want gate_not_confirmed", specificReason)
	}
}

func TestClassify_LinuxLVMNoTargetPrecondition(t *testing.T) {
	in := StepInput{
		TechniqueID: "T1490", StepName: "LVM Snapshot Removal", RunID: "r1", Action: "x",
		CheckResult: "skipped",
		Details:     "SKIP: no LVM snapshots exist - nothing to delete. Create a snapshot first with: lvcreate -s.",
	}
	modeled, isAttempt, specificReason := classifyRansomwareStep(in)
	if !modeled || !isAttempt {
		t.Fatalf("modeled=%v isAttempt=%v, want true/true", modeled, isAttempt)
	}
	if specificReason != "no_target_precondition" {
		t.Fatalf("specificReason = %q, want no_target_precondition", specificReason)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/rwevidence/ -run "TestClassify_LinuxLVM" -v`
Expected: all 3 FAIL. `TestClassify_LinuxLVMReconnaissanceStep` fails because `isAttempt` comes back `true` (the step name isn't recognized yet). The other two fail because `specificReason` comes back `"skip_unclassified"` (the text isn't recognized yet).

- [ ] **Step 3: Write the minimal implementation**

In `orchestrator/internal/rwevidence/dispatch.go`, change:

```go
var reconnaissanceStepNames = map[string]bool{
	"VSS Snapshot Enumeration":         true,
	"VSS + Backup Catalog Enumeration": true,
}
```

to:

```go
var reconnaissanceStepNames = map[string]bool{
	"VSS Snapshot Enumeration":         true,
	"VSS + Backup Catalog Enumeration": true,
	"LVM Snapshot Enumeration":         true,
}
```

And change:

```go
	lower := strings.ToLower(in.Details)
	switch {
	case strings.Contains(lower, "bas_confirm_vss_delete not set"):
		return true, true, "gate_not_confirmed"
	case strings.Contains(lower, "no c: vss shadow copies exist"):
		return true, true, "no_target_precondition"
	default:
		return true, true, "skip_unclassified"
	}
```

to:

```go
	lower := strings.ToLower(in.Details)
	switch {
	case strings.Contains(lower, "bas_confirm_vss_delete not set"):
		return true, true, "gate_not_confirmed"
	case strings.Contains(lower, "bas_confirm_lvm_delete not set"):
		return true, true, "gate_not_confirmed"
	case strings.Contains(lower, "no c: vss shadow copies exist"):
		return true, true, "no_target_precondition"
	case strings.Contains(lower, "no lvm snapshots exist"):
		return true, true, "no_target_precondition"
	default:
		return true, true, "skip_unclassified"
	}
```

- [ ] **Step 4: Run tests to verify they pass, including the existing suite**

Run: `cd orchestrator && go test ./internal/rwevidence/ -v`
Expected: PASS — all existing tests in the package (including `TestClassify_ReconnaissanceStep`, `TestClassify_GateNotConfirmed`, `TestClassify_NoTargetPrecondition`, `TestClassify_UnrecognizedSkipFallsBackConservatively`, every `TestEvaluateStep_*`) plus the 3 new ones, 0 FAIL. This full-package run (not just `-run TestClassify_LinuxLVM`) is the proof the additive edit didn't disturb the existing Windows recognition.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/rwevidence/dispatch.go orchestrator/internal/rwevidence/dispatch_test.go
git commit -m "feat(rwevidence): recognize Linux LVM snapshot step name and skip-text

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: New scenario `scenarios/linux-ransomware-drill.yaml`

**Files:**
- Create: `scenarios/linux-ransomware-drill.yaml`
- Create: `orchestrator/internal/scenario/linux_ransomware_drill_test.go`

**Interfaces:**
- Consumes: the exact recognized strings from Task 1 (`"LVM Snapshot Enumeration"` as a step `name`, `"BAS_CONFIRM_LVM_DELETE"` as the gate env var referenced in that step's skip output, `"no LVM snapshots exist"` as the no-target skip output) — Task 1's dispatch.go matches these case-insensitively via `strings.Contains(lower, ...)`, so this task's YAML text only needs to contain those substrings somewhere in its `SKIP:` output lines, matching the existing Windows convention exactly.
- Produces: `scenarios/linux-ransomware-drill.yaml` on disk — every task from here on (Task 3's six registration edits, Task 4's signing) depends on this file existing with scenario `id: linux-ransomware-drill` and exactly 4 steps.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/scenario/linux_ransomware_drill_test.go`:

```go
package scenario

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxRansomwareDrill_ParsesWithFourStepsLinuxOnly(t *testing.T) {
	path := filepath.Join("..", "..", "..", "scenarios", "linux-ransomware-drill.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(sc.SupportedOS) != 1 || sc.SupportedOS[0] != "linux" {
		t.Fatalf("SupportedOS = %v, want exactly [\"linux\"]", sc.SupportedOS)
	}
	if len(sc.Steps) != 4 {
		t.Fatalf("len(Steps) = %d, want 4", len(sc.Steps))
	}
	wantTechniques := []string{"T1490", "T1490", "T1486", "T1486"}
	for i, want := range wantTechniques {
		if sc.Steps[i].TechniqueID != want {
			t.Errorf("Steps[%d].TechniqueID = %q, want %q", i, sc.Steps[i].TechniqueID, want)
		}
	}
	for _, step := range sc.Steps {
		for _, p := range step.DetectionProfiles {
			if len(p) >= 8 && p[:8] == "windows_" {
				t.Errorf("step %q uses a windows_-prefixed detection profile %q -- a Linux scenario must never report Windows coverage", step.Name, p)
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/scenario/ -run TestLinuxRansomwareDrill_ParsesWithFourStepsLinuxOnly -v`
Expected: FAIL — `read ../../../scenarios/linux-ransomware-drill.yaml: ... no such file or directory` (the file doesn't exist yet).

- [ ] **Step 3: Write the scenario file**

Create `scenarios/linux-ransomware-drill.yaml`:

```yaml
id: linux-ransomware-drill
name: Linux Ransomware Drill — LVM Snapshot and File-Encryption Validation
description: >
  Linux analog of ransomware-drill.yaml's T1490/T1486 validation. MITRE's own
  definitions of T1490 (Inhibit System Recovery) and T1486 (Data Encrypted for
  Impact) explicitly cover Linux procedures -- LVM snapshot deletion and
  shell-based file encryption -- so this reuses the same two techniques
  rwevidence already evaluates, with Linux-native commands in place of
  PowerShell/vssadmin. A distinct execution and evidence adapter, not a
  cosmetic command-swap: Linux-specific safety constraints (lvremove's real
  deletion semantics, bash file permissions) are validated on their own
  terms, never assumed equivalent to the Windows steps' behavior just
  because the TechniqueID matches.

  STEPS:
    1. Discovery          — LVM Snapshot Enumeration (T1490, safe, read-only)
    2. Recovery Inhibition — LVM Snapshot Removal, lab-only, gated behind BAS_CONFIRM_LVM_DELETE=true
    3. Encryption probe    — File Rename Probe .bas_locked (T1486, safe, reversible)
    4. Encryption          — XOR Encryption Simulation, lab-only, isolated scratch dir

  SAFETY: Step 2 deletes a real LVM snapshot only when explicitly confirmed
  via env var, after verifying one exists -- same risk profile as
  ransomware-drill.yaml's VSS deletion step, default-disabled. Steps 3-4 use
  synthetic decoy data only, scoped to an isolated /tmp directory, with
  forced cleanup and byte-for-byte XOR restoration (XOR is its own inverse).
  All steps are [BAS-SIM] tagged. Linux only.
author: Audspect Research
executable: true
local_check: false
supported_os: [linux]
tags:
  - ransomware
  - linux
  - lvm
  - t1486
  - t1490
  - mitre
mitre_phases:
  - discovery
  - impact

live_policy:
  block_on_domain_controller: false
  require_dc_reachable: false
  max_spray_attempts: 0
  spray_account_allowlist: []
  execution_window: ""

steps:

  # ---------------------------------------------------------------------------
  # Step 1 — Discovery: LVM Snapshot Enumeration (T1490)
  # ---------------------------------------------------------------------------
  - name: "LVM Snapshot Enumeration"
    technique_id: T1490
    action_key: enumerate
    detection_profiles:
      - linux_lvm_snapshot_inhibition
    framework: custom
    executor: bash
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Read-only enumeration of LVM snapshots via lvs. No snapshots deleted; no backup jobs modified."
    reversible: true
    telemetry:
      - "auditd: execve of lvs"
    detection:
      - "SIEM: lvs invocation from a non-backup process  -  ransomware pre-deletion recon"
      - "EDR: repeated lvs/lvdisplay calls preceding an lvremove  -  backup-destruction staging"
    command: |
      set +e
      snapshot_count=$(lvs --noheadings -o lv_attr 2>/dev/null | awk '$1 ~ /^s/' | wc -l)
      echo "EXEC: LVM snapshot enumeration - ${snapshot_count} snapshot(s) found. Ransomware operators enumerate these before deletion. No snapshots removed. [BAS-SIM]"
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Step 2 — Recovery Inhibition: LVM Snapshot Removal (T1490, lab-only)
  # ---------------------------------------------------------------------------
  - name: "LVM Snapshot Removal (lab  -  requires BAS_CONFIRM_LVM_DELETE=true)"
    technique_id: T1490
    action_key: lvm_delete
    detection_profiles:
      - linux_lvm_snapshot_inhibition
    framework: custom
    executor: bash
    requires_priv: admin
    timeout_sec: 60
    fidelity: lab-only
    production_safe: false
    risk: high
    blast_radius: "Deletes ONE oldest LVM snapshot. Requires explicit BAS_CONFIRM_LVM_DELETE=true env var and verifies a snapshot exists first. Default-disabled without the flag."
    reversible: false
    telemetry:
      - "auditd: execve of lvremove with -f"
    detection:
      - "EDR: lvremove with -f argument  -  ransomware pre-encryption technique"
      - "SIEM: LVM snapshot count decrease; alert if count drops to 0"
    command: |
      set +e
      if [ "${BAS_CONFIRM_LVM_DELETE}" != "true" ]; then
        echo "SKIP: BAS_CONFIRM_LVM_DELETE not set to 'true' - LVM snapshot deletion skipped (default-disabled per ransomware safety policy). Set env var explicitly in isolated lab to enable. [BAS-SIM]"
        exit 0
      fi
      target=$(lvs --noheadings -o vg_name,lv_name,lv_time,lv_attr --sort lv_time 2>/dev/null | awk '$4 ~ /^s/' | head -n1)
      if [ -z "${target}" ]; then
        echo "SKIP: no LVM snapshots exist - nothing to delete. Create a snapshot first with: lvcreate -s. [BAS-SIM]"
        exit 0
      fi
      vg=$(echo "${target}" | awk '{print $1}')
      lv=$(echo "${target}" | awk '{print $2}')
      lvremove -f "/dev/${vg}/${lv}" >/dev/null 2>&1
      remaining=$(lvs --noheadings -o lv_attr 2>/dev/null | awk '$1 ~ /^s/' | wc -l)
      echo "FAIL: LVM snapshot ${vg}/${lv} deleted - expect auditd lvremove event. ${remaining} snapshot(s) remaining. Create a new snapshot to restore recovery capability. [BAS-SIM]"
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Step 3 — Encryption probe: File Rename Probe (.bas_locked extension) (T1486)
  # ---------------------------------------------------------------------------
  - name: "File Rename Probe (.bas_locked extension)"
    technique_id: T1486
    detection_profiles:
      - linux_ransomware_encryption
    framework: custom
    executor: bash
    requires_priv: user
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Creates a single marker file in /tmp, renames to .bas_locked, renames back, then deletes. No real data files touched."
    reversible: true
    telemetry:
      - "auditd: rename of bas_ransom_probe_<id>.txt in /tmp to .bas_locked"
    detection:
      - "EDR: file renamed to known ransomware extension (.bas_locked)  -  extension-change detection rule"
      - "SIEM: rapid file rename to uncommon extension"
    command: |
      set +e
      run_id="${BAS_RUN_ID:-$(od -An -N4 -tx1 /dev/urandom | tr -d ' ')}"
      run_id="${run_id:0:8}"
      orig="/tmp/bas_ransom_probe_${run_id}.txt"
      locked="/tmp/bas_ransom_probe_${run_id}.bas_locked"
      echo "BAS-SIM T1486 rename probe run-id=${run_id}" > "${orig}"
      mv "${orig}" "${locked}" 2>/dev/null
      if [ -f "${locked}" ]; then renamed=1; else renamed=0; fi
      mv "${locked}" "${orig}" 2>/dev/null
      rm -f "${orig}" "${locked}"
      if [ "${renamed}" = "1" ]; then
        echo "EXEC: file renamed to .bas_locked extension (run-id=${run_id})  -  expect auditd rename event. [BAS-SIM]"
      else
        echo "PASS: file rename blocked  -  a mandatory access control policy prevented the .bas_locked extension rename."
      fi
    cleanup: |
      rm -f /tmp/bas_ransom_probe_*.txt /tmp/bas_ransom_probe_*.bas_locked

  # ---------------------------------------------------------------------------
  # Step 4 — Encryption: XOR Encryption Simulation (T1486, lab-only)
  # ---------------------------------------------------------------------------
  - name: "XOR Encryption Simulation (lab  -  isolated temp dir, forced cleanup)"
    technique_id: T1486
    detection_profiles:
      - linux_ransomware_encryption
    framework: custom
    executor: bash
    requires_priv: user
    timeout_sec: 60
    fidelity: lab-only
    production_safe: false
    risk: high
    blast_radius: "Creates isolated /tmp/bas_range_<id>/ with <=3 benign dummy files, XOR-encrypts in-place, drops marker ransom note, XOR-decrypts to restore, deletes entire directory. File cap + size cap + cleanup verification enforced."
    reversible: true
    telemetry:
      - "auditd: file create/modify under /tmp/bas_range_<id>/"
    detection:
      - "EDR: rapid sequential file modification pattern across multiple files  -  encryption behaviour"
      - "SIEM: high file-modify rate on /tmp path  -  ransomware staging signal"
    command: |
      set +e
      run_id="${BAS_RUN_ID:-$(od -An -N4 -tx1 /dev/urandom | tr -d ' ')}"
      run_id="${run_id:0:8}"
      range_dir="/tmp/bas_range_${run_id}"
      mkdir -p "${range_dir}"
      for f in finance_q4.txt customer_export.txt swift_ops.txt; do
        printf 'BAS-SIM DUMMY DATA run-id=%s file=%s' "${run_id}" "${f}" > "${range_dir}/${f}"
      done
      enc_count=0
      for f in "${range_dir}"/*; do
        python3 -c "
import sys
data = open('${f}', 'rb').read()
xored = bytes(b ^ 0xAB for b in data)
open('${f}.bas_locked', 'wb').write(xored)
"
        rm -f "${f}"
        enc_count=$((enc_count + 1))
      done
      note_file="${range_dir}/README_RESTORE_BAS_SIM.txt"
      echo "BAS-SIM RANSOM NOTE  -  run-id=${run_id}  -  THIS IS A CONTROLLED DRILL" > "${note_file}"
      echo "EXEC: ${enc_count} file(s) XOR-encrypted in ${range_dir}  -  expect EDR encryption-behaviour alert. Restoring now. [BAS-SIM]"
      for f in "${range_dir}"/*.bas_locked; do
        python3 -c "
data = open('${f}', 'rb').read()
plain = bytes(b ^ 0xAB for b in data)
orig = '${f}'[:-len('.bas_locked')]
open(orig, 'wb').write(plain)
"
        rm -f "${f}"
      done
      rm -f "${note_file}"
      rm -rf "${range_dir}"
      if [ -d "${range_dir}" ]; then cleaned=0; else cleaned=1; fi
      echo "CLEANUP: range directory removed=${cleaned}. No encrypted data remains. [BAS-SIM]"
    cleanup: |
      rm -rf /tmp/bas_range_*
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/scenario/ -run TestLinuxRansomwareDrill_ParsesWithFourStepsLinuxOnly -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scenarios/linux-ransomware-drill.yaml orchestrator/internal/scenario/linux_ransomware_drill_test.go
git commit -m "feat(scenarios): Linux ransomware drill -- LVM snapshot + file-encryption validation

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: Register the new scenario in all six existing tracking lists

**Files:**
- Modify: `orchestrator/internal/api/rwevidence_dispatch.go:22-31` (add map entry)
- Create: `orchestrator/internal/api/rwevidence_dispatch_corpus_test.go` (new fail-closed test — this list has no existing one)
- Modify: `orchestrator/internal/rwdetect/profiles.go` (append 2 detection-profile names)
- Modify: `orchestrator/internal/rwdetect/profiles_test.go:15-19` (append filename)
- Modify: `orchestrator/internal/rwevidence/realcorpus_test.go:12` (append filename)
- Modify: `orchestrator/internal/rwtaxonomy/mapping_corpus_test.go:14-18` (append filename)
- Modify: `orchestrator/web/src/features/ransomware.js:19-22` (append scenario id)

**Interfaces:**
- Consumes: `scenarios/linux-ransomware-drill.yaml` from Task 2 (its exact `id: linux-ransomware-drill`, its 4 `technique_id`s, and its `linux_lvm_snapshot_inhibition`/`linux_ransomware_encryption` detection profile names).
- Produces: nothing new for later tasks — Task 4 depends only on the file existing (from Task 2), not on this task's registration edits.

- [ ] **Step 1: Confirm the real-corpus-test gap, then write the failing test for `ransomwareScenarioIDs`**

Create `orchestrator/internal/api/rwevidence_dispatch_corpus_test.go`, modeled on `internal/rwtaxonomy/mapping_corpus_test.go`'s pattern:

```go
package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func repoScenariosDirForRWDispatch(t *testing.T) string {
	dir, err := filepath.Abs("../../../scenarios")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("scenarios dir not found at %s: %v", dir, err)
	}
	return dir
}

// TestRansomwareScenarioIDs_MatchesRealCorpus is the fail-closed test
// ransomwareScenarioIDs never had: a scenario missing from this map is
// never evaluated by rwevidence at all, with no error anywhere -- this
// proves every ransomware-tagged scenario file on disk has a matching
// entry, and every entry still has a matching file.
func TestRansomwareScenarioIDs_MatchesRealCorpus(t *testing.T) {
	files := []string{
		"akira-kill-chain.yaml", "blackcat-kill-chain.yaml", "clop-kill-chain.yaml",
		"lockbit-kill-chain.yaml", "play-kill-chain.yaml", "ransomhub-kill-chain.yaml",
		"ransomware-drill.yaml", "endpoint-mastery/em-07-ransomware-readiness.yaml",
		"linux-ransomware-drill.yaml",
	}
	dir := repoScenariosDirForRWDispatch(t)
	seen := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		sc, err := scenario.ParseYAML(b)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		seen[sc.ID] = true
	}
	for id := range seen {
		if !ransomwareScenarioIDs[id] {
			t.Errorf("real corpus file for scenario %q exists, but ransomwareScenarioIDs is missing it -- this run would silently never be evaluated by rwevidence", id)
		}
	}
	for id := range ransomwareScenarioIDs {
		if !seen[id] {
			t.Errorf("ransomwareScenarioIDs lists %q, but no real scenario file declares that id -- stale entry", id)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/ -run TestRansomwareScenarioIDs_MatchesRealCorpus -v`
Expected: FAIL — `real corpus file for scenario "linux-ransomware-drill" exists, but ransomwareScenarioIDs is missing it`.

- [ ] **Step 3: Add the map entry**

In `orchestrator/internal/api/rwevidence_dispatch.go`, change:

```go
var ransomwareScenarioIDs = map[string]bool{
	"akira-kill-chain":           true,
	"blackcat-kill-chain":        true,
	"clop-kill-chain":            true,
	"lockbit-kill-chain":         true,
	"play-kill-chain":            true,
	"ransomhub-kill-chain":       true,
	"ransomware-drill":           true,
	"em-07-ransomware-readiness": true,
}
```

to:

```go
var ransomwareScenarioIDs = map[string]bool{
	"akira-kill-chain":           true,
	"blackcat-kill-chain":        true,
	"clop-kill-chain":            true,
	"lockbit-kill-chain":         true,
	"play-kill-chain":            true,
	"ransomhub-kill-chain":       true,
	"ransomware-drill":           true,
	"em-07-ransomware-readiness": true,
	"linux-ransomware-drill":     true,
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/ -run TestRansomwareScenarioIDs_MatchesRealCorpus -v`
Expected: PASS.

- [ ] **Step 5: Update the remaining four Go-side registration lists, running each one's existing test after every edit**

Append `"linux_lvm_snapshot_inhibition"` and `"linux_ransomware_encryption"` to `RansomwareRelevantProfiles` in `orchestrator/internal/rwdetect/profiles.go` (keep the existing alphabetical-ish ordering convention — add them after `"windows_vulnerable_driver_load"`, the list's last entry).

Append `"linux-ransomware-drill.yaml"` to the `ransomwareScenarioFiles` literal in each of these three files (same append, same position — after `"endpoint-mastery/em-07-ransomware-readiness.yaml"`):
- `orchestrator/internal/rwdetect/profiles_test.go`
- `orchestrator/internal/rwevidence/realcorpus_test.go`
- `orchestrator/internal/rwtaxonomy/mapping_corpus_test.go`

Run: `cd orchestrator && go test ./internal/rwdetect/ ./internal/rwevidence/ ./internal/rwtaxonomy/ -v`
Expected: PASS, every real-corpus test in all 3 packages green (each one now sees the new file and its 2 new Linux detection-profile names via `RansomwareRelevantProfiles`, and finds `T1490`/`T1486` already in `rwtaxonomy.TechniqueDomain` from sub-project #8, so no new domain-mapping entries are needed).

- [ ] **Step 6: Update the frontend list**

In `orchestrator/web/src/features/ransomware.js`, change:

```js
var RR_SCENARIO_IDS = [
  'akira-kill-chain', 'blackcat-kill-chain', 'clop-kill-chain', 'lockbit-kill-chain',
  'play-kill-chain', 'ransomhub-kill-chain', 'ransomware-drill', 'em-07-ransomware-readiness'
];
```

to:

```js
var RR_SCENARIO_IDS = [
  'akira-kill-chain', 'blackcat-kill-chain', 'clop-kill-chain', 'lockbit-kill-chain',
  'play-kill-chain', 'ransomhub-kill-chain', 'ransomware-drill', 'em-07-ransomware-readiness',
  'linux-ransomware-drill'
];
```

No test command for this file: confirmed via `find web -iname "*ransomware*test*" -o -iname "*ransomware*spec*"` (excluding `node_modules`/`dist`) that `ransomware.js` has no existing test harness anywhere in this codebase's frontend. Verification for this step is manual: re-open the file and confirm the array literal now has exactly 9 entries, comma-separated, with `'linux-ransomware-drill'` last.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/rwevidence_dispatch.go orchestrator/internal/api/rwevidence_dispatch_corpus_test.go orchestrator/internal/rwdetect/profiles.go orchestrator/internal/rwdetect/profiles_test.go orchestrator/internal/rwevidence/realcorpus_test.go orchestrator/internal/rwtaxonomy/mapping_corpus_test.go orchestrator/web/src/features/ransomware.js
git commit -m "feat(rwevidence): register linux-ransomware-drill across all 6 scenario-list touchpoints

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 4: Sign the new scenario file

**Files:**
- Create: `scenarios/linux-ransomware-drill.yaml.sig`

**Interfaces:**
- Consumes: `scenarios/linux-ransomware-drill.yaml` from Task 2, `orchestrator/private_key.pem` (the repo's existing scenario-signing private key).
- Produces: `scenarios/linux-ransomware-drill.yaml.sig`, which the existing `verify-all` gate (used in build/pack per the standing scenario-signature-gate convention) checks alongside every other `scenarios/*.yaml.sig`.

- [ ] **Step 1: Sign the file**

Run: `cd orchestrator && go run scripts/signer.go sign private_key.pem ../scenarios/linux-ransomware-drill.yaml`
Expected: a `linux-ransomware-drill.yaml.sig` file is created in `scenarios/`.

- [ ] **Step 2: Verify it alongside every other scenario's signature**

Run: `cd orchestrator && go run scripts/signer.go verify-all ../scenarios`
Expected: every `.sig` in `scenarios/` (including the new one and all pre-existing ones) verifies successfully — 0 failures reported.

- [ ] **Step 3: Commit**

```bash
git add scenarios/linux-ransomware-drill.yaml.sig
git commit -m "chore(scenarios): sign linux-ransomware-drill.yaml

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 5: Final regression across every touched package

**Files:**
- None (verification-only task; no new code).

**Interfaces:**
- Consumes: everything from Tasks 1-4.
- Produces: nothing — this is the plan's terminal verification layer.

- [ ] **Step 1: Run the pure-Go packages together (no testcontainers needed for any of these)**

`internal/scenario` (Task 2's smoke test), `internal/rwdetect`, `internal/rwtaxonomy` are plain Go with no DB dependency — confirm this is still true by checking none of their test files import `sharedDB`/`pgxpool` before running (grep for `sharedDB` in each package's `*_test.go`; none should match).

Run: `cd orchestrator && go test ./internal/scenario/ ./internal/rwdetect/ ./internal/rwtaxonomy/ -v`
Expected: `ok` for all three, 0 FAIL.

- [ ] **Step 2: Run `internal/rwevidence` on its own (pure Go, but run separately from Step 3 for a clean signal)**

Run: `cd orchestrator && go test ./internal/rwevidence/ -v`
Expected: `ok`, 0 FAIL — including all of Task 1's new tests and the full pre-existing suite.

- [ ] **Step 3: Run `internal/api` alone, with `-p 1`**

`internal/api` is heavily testcontainers-backed (confirmed: most of its test files use `sharedDB`/`pgxpool`), even though Task 3's new `TestRansomwareScenarioIDs_MatchesRealCorpus` itself needs no container. Per this session's standing host-memory rule (`project_docker_windows.md`): any `go test` invocation touching 2+ testcontainer-backed packages in one call risks spinning up multiple Postgres containers simultaneously on this ~7.8GB host. Since this step runs `internal/api` by itself (not alongside `internal/db` or another container-backed package in the same invocation), a bare run is sufficient — no `-p 1` is strictly required for a single package, but pass it anyway as a zero-cost safety margin given this package's size.

Run: `cd orchestrator && go test ./internal/api/ -p 1 -timeout 20m -v`
Expected: `ok`, 0 FAIL.

- [ ] **Step 2 (no commit for this task):** If every step above is green, there is nothing to commit — this task exists only to confirm the whole touched surface together, one final time.
