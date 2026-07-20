# OS Patch Vulnerability Posture Scenario Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new standalone scenario, `os-patch-posture`, selectable on its own in the scenario library, reports whether an endpoint's OS has current security patches — Windows (reusing existing logic) and Linux (two new checks).

**Architecture:** `local_check` scenarios execute entirely agent-side — the scenario YAML's `id` is dispatched, per platform, through a `knownPostureScenarios()`/`RunScenarioChecks()` table in `agent/simulate_<os>.go` to a grouping function that returns `[]SimCategory` of deferred-execution `SimCheck`s. This plan adds one new dispatch entry to each of `simulate_windows.go` (reusing the existing `checkPatchCurrency()`) and `simulate_linux.go` (two new checks), plus one new scenario YAML file. No orchestrator/server code changes.

**Tech Stack:** Go (agent binaries, `//go:build windows` / `//go:build linux` file-suffix compilation), YAML (scenario definition).

## Global Constraints

- Reuse `checkPatchCurrency()` on Windows unchanged — no new Windows check, no Windows Update Agent COM API (air-gap/hang risk).
- New Linux checks (`checkPendingSecurityUpdates`, `checkLastPatchAge`) must mirror `checkPatchCurrency()`'s exact day-bucket thresholds: ≤15 days pass ("well within"), ≤30 days pass ("within"), ≤60 days fail ("exceeds"), >60 days fail ("significantly overdue").
- Package-manager detection: apt first, then dnf, matching this codebase's supported-OS floor (Ubuntu 20.04+, Rocky/RHEL/CentOS 9+ — same floor `install.sh`'s `_check_os` already enforces).
- No macOS changes — `supported_os: [windows, linux]` in the YAML is the only gate needed.
- No orchestrator/server-side changes — everything here is agent-side plus one new YAML file.

---

### Task 1: Linux — `checkPendingSecurityUpdates`, `checkLastPatchAge`, dispatch wiring

**Files:**
- Modify: `agent/simulate_linux.go:1-11` (imports)
- Modify: `agent/simulate_linux.go:130-137` (`knownPostureScenarios`)
- Modify: `agent/simulate_linux.go:189-190` (`RunScenarioChecks` switch)
- Modify: `agent/simulate_linux.go` — new functions appended near the end of the file

**Interfaces:**
- Consumes: `SimCheck`, `SimCategory`, `check(techID, name, tactic, severity, threat, fix string, fn func() (string, string)) SimCheck` — all defined in `agent/simulate.go` (unchanged, pre-existing).
- Produces: `packageManager() string` (returns `"apt"`, `"dnf"`, or `""`), `checkPendingSecurityUpdates() SimCheck`, `checkLastPatchAge() SimCheck`, `osPatchPostureChecks() []SimCategory` — consumed by Task 3's live verification and by the `"os-patch-posture"` dispatch case added in this same task.

- [ ] **Step 1: Add the `"time"` import**

Current (`agent/simulate_linux.go:5-11`):

```go
import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)
```

Becomes:

```go
import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)
```

- [ ] **Step 2: Register the new scenario ID**

Current (`agent/simulate_linux.go:130-137`):

```go
func knownPostureScenarios() []string {
	return []string{
		"safe-simulation", "cis-ubuntu-l1", "apt36-spearphish", "apt36-kill-chain",
		"ransomware-drill", "ad-credential-access", "upi-fraud-killchain",
		"cscrf-mii-drill", "purplesharp-ad-drill", "lolbin-execution",
		"lolbin-execution-coverage",
	}
}
```

Becomes:

```go
func knownPostureScenarios() []string {
	return []string{
		"safe-simulation", "cis-ubuntu-l1", "apt36-spearphish", "apt36-kill-chain",
		"ransomware-drill", "ad-credential-access", "upi-fraud-killchain",
		"cscrf-mii-drill", "purplesharp-ad-drill", "lolbin-execution",
		"lolbin-execution-coverage", "os-patch-posture",
	}
}
```

- [ ] **Step 3: Add the dispatch case**

Current (`agent/simulate_linux.go:189-193`):

```go
func RunScenarioChecks(scenarioID string) []SimCategory {
	switch scenarioID {
	case "safe-simulation":
		return safeSimChecks()
	case "cis-ubuntu-l1":
```

Becomes:

```go
func RunScenarioChecks(scenarioID string) []SimCategory {
	switch scenarioID {
	case "safe-simulation":
		return safeSimChecks()
	case "os-patch-posture":
		return osPatchPostureChecks()
	case "cis-ubuntu-l1":
```

- [ ] **Step 4: Append the new functions**

Add at the end of `agent/simulate_linux.go`:

```go
// ── OS Patch Vulnerability Posture ─────────────────────────────────────────────

// packageManager returns "apt", "dnf", or "" if neither is found on PATH.
func packageManager() string {
	if _, err := exec.LookPath("apt-get"); err == nil {
		return "apt"
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		return "dnf"
	}
	return ""
}

func osPatchPostureChecks() []SimCategory {
	return []SimCategory{
		{Phase: "initial-access", Checks: []SimCheck{
			checkPendingSecurityUpdates(),
			checkLastPatchAge(),
		}},
	}
}

func checkPendingSecurityUpdates() SimCheck {
	return check("T1082", "Pending Security Updates (CSCRF-5.1)", "cscrf-business-continuity", "High",
		"Unpatched packages with known CVEs are a primary ransomware and worm entry point.",
		"Apply pending security updates via apt/dnf, or enable unattended-upgrades / dnf-automatic.",
		func() (string, string) {
			switch packageManager() {
			case "apt":
				out, err := exec.Command("apt", "list", "--upgradable").Output()
				if err != nil {
					return "skipped", "Could not enumerate upgradable packages via apt — verify manually."
				}
				n := 0
				for _, line := range strings.Split(string(out), "\n") {
					if strings.Contains(strings.ToLower(line), "-security") {
						n++
					}
				}
				if n == 0 {
					return "pass", "No pending security updates (apt)."
				}
				return "fail", fmt.Sprintf("%d pending security update(s) found (apt) — apply promptly.", n)
			case "dnf":
				out, err := exec.Command("dnf", "updateinfo", "list", "security").Output()
				if err != nil {
					return "skipped", "Could not enumerate security updates via dnf — verify manually."
				}
				n := 0
				for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
					if strings.TrimSpace(line) != "" {
						n++
					}
				}
				if n == 0 {
					return "pass", "No pending security updates (dnf)."
				}
				return "fail", fmt.Sprintf("%d pending security update(s) found (dnf) — apply promptly.", n)
			default:
				return "skipped", "Neither apt nor dnf found — cannot determine pending security updates."
			}
		})
}

func checkLastPatchAge() SimCheck {
	return check("T1082", "Patch Currency — Last Update Age (CSCRF-5.1)", "cscrf-business-continuity", "High",
		"SEBI CSCRF mandates critical patches within 30 days of release. Unpatched endpoints are primary ransomware entry.",
		"Enforce patch deployment via unattended-upgrades/dnf-automatic or a patch management tool. Set 30-day SLA for critical patches per CSCRF schedule.",
		func() (string, string) {
			var path string
			switch packageManager() {
			case "apt":
				path = "/var/log/apt/history.log"
			case "dnf":
				path = "/var/lib/rpm/rpmdb.sqlite"
			default:
				return "skipped", "Neither apt nor dnf found — cannot determine last patch date."
			}
			info, err := os.Stat(path)
			if err != nil {
				return "skipped", fmt.Sprintf("Could not read %s — verify patch history manually.", path)
			}
			days := int(time.Since(info.ModTime()).Hours() / 24)
			switch {
			case days <= 15:
				return "pass", fmt.Sprintf("Last patch installed %d days ago — well within SEBI CSCRF 30-day critical patch window.", days)
			case days <= 30:
				return "pass", fmt.Sprintf("Last patch installed %d days ago — within CSCRF 30-day threshold.", days)
			case days <= 60:
				return "fail", fmt.Sprintf("Last patch installed %d days ago — exceeds SEBI CSCRF 30-day critical patch deadline.", days)
			default:
				return "fail", fmt.Sprintf("Last patch installed %d days ago — significantly overdue, high vulnerability exposure, CSCRF non-compliant.", days)
			}
		})
}
```

- [ ] **Step 5: Cross-compile for Linux**

```bash
cd agent && GOOS=linux GOARCH=amd64 go build -o /tmp/agent-linux-check .
```

Expected: exits 0, no output, `/tmp/agent-linux-check` created.

- [ ] **Step 6: `go vet` for Linux**

```bash
cd agent && GOOS=linux GOARCH=amd64 go vet .
```

Expected: no output, exit 0.

- [ ] **Step 7: Live-verify the parsing logic against real apt/dnf output**

The Go binary itself can't be run directly from this Windows host against a Linux package manager, so verify the exact same command + parsing logic (security-line substring match, mtime-based day count) directly in throwaway containers — the same technique already used for `install.sh`.

Ubuntu (apt) — confirm the exact `apt list --upgradable` security-line detection:

```bash
MSYS_NO_PATHCONV=1 docker run --rm ubuntu:22.04 bash -c '
  apt-get update -qq
  apt list --upgradable 2>/dev/null | grep -ic security || echo 0
  stat -c %Y /var/log/apt/history.log 2>&1 || echo "no history.log yet (fresh image)"
'
```

Expected: a numeric count (0 or more) for the security-update line count; `stat` either prints a Unix timestamp or reports the file doesn't exist yet on a brand-new container (expected — `checkLastPatchAge` correctly reports `skipped` via the `os.Stat` error path in that case, matching a host that's never run `apt upgrade`).

Rocky Linux (dnf):

```bash
MSYS_NO_PATHCONV=1 docker run --rm rockylinux:9 bash -c '
  dnf updateinfo list security 2>/dev/null | grep -c . || echo 0
  stat -c %Y /var/lib/rpm/rpmdb.sqlite 2>&1
'
```

Expected: a numeric line count; `stat` prints a Unix timestamp for `/var/lib/rpm/rpmdb.sqlite` (present by default on a Rocky 9 base image, since rpm itself needs it).

- [ ] **Step 8: Commit**

```bash
git add agent/simulate_linux.go
git commit -m "$(cat <<'EOF'
feat(agent): add Linux OS patch posture checks

checkPendingSecurityUpdates() and checkLastPatchAge() -- apt/dnf pending
security-update count and last-patch-age, mirroring the existing Windows
checkPatchCurrency()'s exact 30-day SEBI CSCRF threshold buckets. Wired
into knownPostureScenarios/RunScenarioChecks under a new os-patch-posture
scenario ID (not yet backed by a scenario YAML -- lands in a later commit).
EOF
)"
```

---

### Task 2: Windows — dispatch wiring (reuses existing check, no new logic)

**Files:**
- Modify: `agent/simulate_windows.go:58-65` (`knownPostureScenarios`)
- Modify: `agent/simulate_windows.go:67-70` (`RunScenarioChecks` switch)
- Modify: `agent/simulate_windows.go` — new function near `checkPatchCurrency()`

**Interfaces:**
- Consumes: `checkPatchCurrency() SimCheck` — pre-existing, unchanged (`agent/simulate_windows.go:2201-2224` as of this plan's writing; exact line numbers will drift after Task 1/2's edits to earlier parts of other files, but this function itself is untouched).
- Produces: `osPatchPostureChecks() []SimCategory` (Windows build) — same name as Task 1's Linux function; safe, since `//go:build windows` / `//go:build linux` mean only one file compiles per target, so there's no symbol collision.

- [ ] **Step 1: Register the new scenario ID**

Current (`agent/simulate_windows.go:58-65`):

```go
func knownPostureScenarios() []string {
	return []string{
		"safe-simulation", "apt36-spearphish", "apt36-kill-chain",
		"ransomware-drill", "ad-credential-access", "upi-fraud-killchain",
		"cscrf-mii-drill", "purplesharp-ad-drill", "lolbin-execution",
		"lolbin-execution-coverage",
	}
}
```

Becomes:

```go
func knownPostureScenarios() []string {
	return []string{
		"safe-simulation", "apt36-spearphish", "apt36-kill-chain",
		"ransomware-drill", "ad-credential-access", "upi-fraud-killchain",
		"cscrf-mii-drill", "purplesharp-ad-drill", "lolbin-execution",
		"lolbin-execution-coverage", "os-patch-posture",
	}
}
```

- [ ] **Step 2: Add the dispatch case**

Current (`agent/simulate_windows.go:67-71`):

```go
func RunScenarioChecks(scenarioID string) []SimCategory {
	switch scenarioID {
	case "safe-simulation":
		return safeSimChecks()
	case "apt36-spearphish":
```

Becomes:

```go
func RunScenarioChecks(scenarioID string) []SimCategory {
	switch scenarioID {
	case "safe-simulation":
		return safeSimChecks()
	case "os-patch-posture":
		return osPatchPostureChecks()
	case "apt36-spearphish":
```

- [ ] **Step 3: Add the grouping function next to `checkPatchCurrency()`**

Find `func checkPatchCurrency() SimCheck {` in `agent/simulate_windows.go` and insert immediately before it:

```go
func osPatchPostureChecks() []SimCategory {
	return []SimCategory{
		{Phase: "initial-access", Checks: []SimCheck{
			checkPatchCurrency(),
		}},
	}
}

func checkPatchCurrency() SimCheck {
```

(Only the new function and the blank line before the pre-existing `func checkPatchCurrency() SimCheck {` line are added — `checkPatchCurrency`'s own body is untouched.)

- [ ] **Step 4: Cross-compile for Windows**

```bash
cd agent && GOOS=windows GOARCH=amd64 go build -o /tmp/agent-windows-check.exe .
```

Expected: exits 0, no output, `/tmp/agent-windows-check.exe` created. (Since this dev host is Windows, this is also effectively a native build — no cross-compilation risk here.)

- [ ] **Step 5: `go vet` for Windows**

```bash
cd agent && GOOS=windows GOARCH=amd64 go vet .
```

Expected: no output, exit 0.

- [ ] **Step 6: Commit**

```bash
git add agent/simulate_windows.go
git commit -m "$(cat <<'EOF'
feat(agent): wire os-patch-posture scenario on Windows

Reuses the existing checkPatchCurrency() unchanged -- no new Windows
check logic. Deliberately does not add a pending-updates count via the
Windows Update Agent COM API, since that can call out to WU/WSUS and
risks hanging on air-gapped hosts.
EOF
)"
```

---

### Task 3: New scenario YAML

**Files:**
- Create: `scenarios/os-patch-posture.yaml`

**Interfaces:**
- Consumes: scenario `id: os-patch-posture` must exactly match the string used in Task 1's and Task 2's `knownPostureScenarios()`/`RunScenarioChecks()` dispatch tables.

- [ ] **Step 1: Write the scenario file**

```yaml
id: os-patch-posture
name: OS Patch Vulnerability Posture Check
local_check: true
description: >
  Checks whether the endpoint's operating system has current security
  patches applied. Unpatched OS vulnerabilities are among the most common
  ransomware and worm entry points; SEBI CSCRF mandates critical patches
  within 30 days of release.

  Windows: last Windows Update installation age (Get-HotFix).
  Linux: count of pending security updates (apt/dnf) and last patch age.

  Expected verdicts:
    PASS = patches current (within 30 days) and/or zero pending security updates
    FAIL = patches overdue (beyond 30 days) or pending security updates found
    SKIP = patch status could not be determined (e.g. unsupported package manager)
author: Audspect Research
supported_os: [windows, linux]
tags:
  - patch-management
  - vulnerability
  - cscrf
  - t1082
  - t1190

steps:
  - name: "Patch Currency — Last Update Age (CSCRF-5.1)"
    technique_id: T1082
    framework: custom
    executor: local
    command: "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1"
    timeout_sec: 15

  - name: "Pending Security Updates (apt/dnf)"
    technique_id: T1082
    framework: custom
    executor: local
    command: "apt list --upgradable 2>/dev/null | grep -ic security  # or: dnf updateinfo list security"
    timeout_sec: 20

  - name: "Last Patch Age (apt/dnf)"
    technique_id: T1082
    framework: custom
    executor: local
    command: "stat -c %Y /var/log/apt/history.log  # or rpm DB mtime on dnf systems"
    timeout_sec: 10
```

- [ ] **Step 2: Validate the YAML parses via the Go loader**

```bash
cd orchestrator && cat > /tmp/parse_test.go <<'EOF'
package main

import (
	"fmt"
	"os"

	"github.com/audspect/bas/internal/scenario"
)

func main() {
	data, err := os.ReadFile("../scenarios/os-patch-posture.yaml")
	if err != nil {
		panic(err)
	}
	s, err := scenario.ParseYAML(data)
	if err != nil {
		fmt.Println("PARSE ERROR:", err)
		os.Exit(1)
	}
	fmt.Printf("OK: id=%s localCheck=%v supportedOS=%v steps=%d\n", s.ID, s.LocalCheck, s.SupportedOS, len(s.Steps))
}
EOF
go run /tmp/parse_test.go
```

Expected: `OK: id=os-patch-posture localCheck=true supportedOS=[windows linux] steps=3`

(If `scenario.ParseYAML` isn't the exact exported function name, check `orchestrator/internal/scenario/engine.go`'s `Load()` for whatever function it calls to parse a single file, and use that instead — the goal is just confirming the YAML round-trips through the real parser without error before it ever reaches the signing pipeline.)

- [ ] **Step 3: Clean up the throwaway parse-test file**

```bash
rm /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator/parse_test.go 2>/dev/null; true
```

(It was written to `orchestrator/` — a sibling of `go.mod` — so `go run` could resolve the `github.com/audspect/bas/...` import; it's a throwaway verification script, not part of the deliverable, so it must not be committed.)

- [ ] **Step 4: Commit**

```bash
git add scenarios/os-patch-posture.yaml
git commit -m "$(cat <<'EOF'
feat(scenarios): add os-patch-posture standalone scenario

New selectable scenario surfacing OS patch currency for both platforms
-- previously only available buried inside cscrf-mii-drill/safe-simulation/
ransomware-drill. Unsigned as a new builtin file; picked up by the
integrity-signing pipeline on the next windows-build.ps1 run.
EOF
)"
```

---

### Task 4: Final verification and push

**Files:** none (verification only)

- [ ] **Step 1: Full build across both platforms one more time, from a clean tree**

```bash
cd agent
GOOS=linux GOARCH=amd64 go build -o /tmp/agent-linux-final . && echo "LINUX_BUILD_OK"
GOOS=windows GOARCH=amd64 go build -o /tmp/agent-windows-final.exe . && echo "WINDOWS_BUILD_OK"
GOOS=linux GOARCH=amd64 go vet . && echo "LINUX_VET_OK"
GOOS=windows GOARCH=amd64 go vet . && echo "WINDOWS_VET_OK"
```

Expected: all four `_OK` lines print, no errors.

- [ ] **Step 2: Confirm the three new/changed files are exactly what's expected**

```bash
git log --oneline -4
git show --stat HEAD~2..HEAD
```

Expected: three commits from Tasks 1-3 (Linux checks, Windows wiring, scenario YAML), touching exactly `agent/simulate_linux.go`, `agent/simulate_windows.go`, `scenarios/os-patch-posture.yaml`.

- [ ] **Step 3: Push**

```bash
git push
```

- [ ] **Step 4: Clean up temp build artifacts**

```bash
rm -f /tmp/agent-linux-check /tmp/agent-windows-check.exe /tmp/agent-linux-final /tmp/agent-windows-final.exe
```
