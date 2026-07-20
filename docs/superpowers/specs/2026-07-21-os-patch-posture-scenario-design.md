# OS Patch Vulnerability Posture Scenario — Design

## Context

The user asked for a "BAS scenario/technique for unpatched OS" — coverage for whether an endpoint is exposed via missing OS security patches. Real weaponized exploits for specific unpatched CVEs are out of scope for this platform (too risky/legally sensitive for a BAS tool, and Atomic Red Team deliberately avoids them too); the safe, buildable framing is a **posture check**: does this host have current security patches, yes or no.

Investigating the existing `local_check` architecture (used by `cis-ubuntu-l1.yaml` and others) turned up two things:

1. **Windows already has this**, twice over — `checkPatchCurrency()` and `safecheckPatchAge()` (`agent/simulate_windows.go:2201`, `:2347`) both check the last `Get-HotFix` install date against a 30-day SEBI CSCRF threshold. Neither is exposed as its own selectable scenario; both are buried inside `cscrf-mii-drill`, `safe-simulation`, and `ransomware-drill`.
2. **Linux has zero patch-posture checks.** No occurrence of `apt`, `dnf`, `yum`, `unattended-upgrade`, or similar in `agent/simulate_linux.go`.

This plan closes the Linux gap and surfaces both platforms as one dedicated, standalone scenario — rather than adding real exploit code for any specific CVE.

## How `local_check` scenarios actually work

This matters because it shapes the whole plan: for `local_check: true` scenarios, the actual pass/fail logic lives in **agent Go source**, not in the scenario YAML. The YAML's `steps:` list (as seen in `cis-ubuntu-l1.yaml`) is purely informational/UI-display — `orchestrator/internal/scenario/types.go`'s `Step` struct has no code path that executes a `command:` field for `local_check` scenarios, and the engine only requires `local_check: true` OR a `steps`/ART/Caldera execution mode to accept a scenario (`internal/scenario/engine.go:162`).

The real dispatch is entirely agent-side, per platform:
- `agent/simulate.go` — shared `SimCheck` type, `check(techID, name, tactic, severity, threat, fix, fn)` constructor (deferred execution — `fn` runs later via `.run()`), and `BuildPostureCatalog()`, which harvests check metadata (for the enrollment-time picker) by calling `RunScenarioChecks(scenarioID)` for every ID in `knownPostureScenarios()`.
- `agent/simulate_linux.go` / `agent/simulate_windows.go` / `agent/simulate_darwin.go` — each defines its own `knownPostureScenarios() []string` and `RunScenarioChecks(scenarioID string) []SimCategory`, switching on scenario ID to a grouping function (e.g. `cisUbuntuL1()`, `safeSimChecks()`) that returns categorized `SimCheck`s built via individual `checkXxx() SimCheck` functions.

Adding a new posture scenario therefore means: register the scenario ID in the per-platform dispatch tables, write the `checkXxx()` functions, and add a YAML file whose `id` matches — no server/orchestrator changes.

## Goal

A new scenario, `os-patch-posture`, selectable on its own in the scenario library, that reports whether an endpoint's OS has current security patches — for both Windows and Linux agents.

## Architecture

### 1. New scenario YAML — `scenarios/os-patch-posture.yaml`

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

`steps:` mirrors `cis-ubuntu-l1.yaml`'s convention (documentation for the scenario-library browser); the first step only ever executes on Windows agents, the other two only on Linux — governed entirely by which platform's `RunScenarioChecks("os-patch-posture")` runs, not by anything in this file.

Since this is a **new** scenario file, it lands in `scenarios/` unsigned; per the existing integrity pipeline (see `[[project_integrity_system]]` in memory) the server won't load it until `windows-build.ps1`'s signing step runs on the next build — same as every other new builtin scenario.

### 2. Windows — pure reuse, zero new check logic

`agent/simulate_windows.go`: add `"os-patch-posture"` to `knownPostureScenarios()` (near line 58-65) and a new case in `RunScenarioChecks()` (near line 67-87):

```go
case "os-patch-posture":
	return osPatchPostureChecks()
```

New grouping function, placed near `checkPatchCurrency()`:

```go
func osPatchPostureChecks() []SimCategory {
	return []SimCategory{
		{Phase: "initial-access", Checks: []SimCheck{
			checkPatchCurrency(),
		}},
	}
}
```

`checkPatchCurrency()` itself (`agent/simulate_windows.go:2201-2224`) is unchanged — reused exactly as-is. No new Windows check is added: a *pending*-updates count would need the Windows Update Agent COM API (`Microsoft.Update.Session`), which can call out to WU/WSUS and risks hanging on air-gapped BFSI hosts (per `[[project_onprem_sqlserver]]`/`[[project_machines]]` — this platform targets fully on-prem, no-internet-assumed environments). The existing `Get-HotFix`-based check has no such risk and is already proven in production via `cscrf-mii-drill`/`safe-simulation`/`ransomware-drill`.

### 3. Linux — two new checks

`agent/simulate_linux.go`: add `"os-patch-posture"` to `knownPostureScenarios()` (line 130-136) and a new case in `RunScenarioChecks()` (line 189+):

```go
case "os-patch-posture":
	return osPatchPostureChecks()
```

New grouping function and two new checks, placed near the other `checkXxx()` functions:

```go
func osPatchPostureChecks() []SimCategory {
	return []SimCategory{
		{Phase: "initial-access", Checks: []SimCheck{
			checkPendingSecurityUpdates(),
			checkLastPatchAge(),
		}},
	}
}

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

`checkLastPatchAge()` deliberately mirrors `checkPatchCurrency()`'s exact day-bucket thresholds (≤15/≤30/≤60/>60) and wording style, for direct comparability in reports that show both OS families side by side. Both checks share `packageManager()` for detection, following the same `command -v`-style precedent `install.sh:_install_docker` already established for OS-family branching.

`/var/lib/rpm/rpmdb.sqlite` is the modern (RPM 4.16+, matches Rocky/RHEL 9's baseline per `_check_os` in `install.sh`) BerkeleyDB-successor path. Older rpm layouts use `/var/lib/rpm/Packages` instead; this plan targets Rocky/RHEL/CentOS 9+ only (matching this codebase's existing supported-OS floor), so the sqlite path is the correct, unconditional choice — no fallback needed.

### 4. New imports

`agent/simulate_linux.go`'s current import block is `fmt`, `os`, `os/exec`, `strconv`, `strings` — only `"time"` (for `time.Since`) needs adding for `checkLastPatchAge()`. `fmt`, `os`, `os/exec`, and `strings` are already present and cover everything else used above.

## Non-goals

- **No real exploit code for any specific CVE.** This is a posture check (are patches current), not an exploitation scenario. ART technique-coverage for `T1068`/`T1210`/`T1203` (benign Atomic Red Team atomics tagged under those techniques) was explicitly deferred as a separate, later follow-up during brainstorming — not part of this plan.
- **No macOS coverage.** `supported_os: [windows, linux]` in the YAML keeps the scenario from ever being dispatched to a macOS agent by the server-side filter, so `agent/simulate_darwin.go` needs no changes.
- **No Windows Update Agent COM API / pending-updates count for Windows.** Deliberately avoided due to air-gap/hang risk (see Architecture §2). If ever wanted, that's a separate follow-up with its own risk analysis.
- **No changes to the three existing scenarios** (`cscrf-mii-drill`, `safe-simulation`, `ransomware-drill`) that already embed `checkPatchCurrency()`/`safecheckPatchAge()` — they keep working exactly as today; this plan only adds a new, additional, standalone scenario alongside them.
- **No orchestrator/server-side code changes.** Everything for `local_check` scenarios is agent-side; the server only needs the new YAML file (which it picks up like any other scenario, once signed).

## Rollout note

Per existing project convention (`[[project_posture_picker]]` in memory), the enrollment-time picker catalog (`BuildPostureCatalog()`) is harvested once at agent enrollment. Already-enrolled agents won't show `os-patch-posture` in their picker until they re-enroll after the next agent binary upgrade — this is pre-existing platform behavior, not something this plan needs to change.

## Testing

No automated test harness currently covers `simulate_linux.go`/`simulate_windows.go`'s `checkXxx()` functions directly (they call real OS commands). Verification, matching the style already used elsewhere in this codebase (`agent/simulate_test.go`, `agent/cancel_test.go` exist but test different concerns):

1. `go build ./...` in `agent/` for both `GOOS=linux` and `GOOS=windows` cross-compiles cleanly.
2. `go vet ./...` clean.
3. Live verification of `checkPendingSecurityUpdates()`/`checkLastPatchAge()` logic against the exact apt/dnf commands, using the same throwaway-container technique already used for `install.sh` (Ubuntu 22.04 and Rocky Linux 9 containers) — run the shell commands directly (not through the compiled agent, which isn't practical to cross-run in a Linux container from this Windows dev host) to confirm the parsing logic (security-line counting, mtime-based day counts) against real `apt list --upgradable` / `dnf updateinfo list security` / file mtimes on hosts with and without pending updates.
4. `BuildPostureCatalog()` returns a `"os-patch-posture"` entry with the expected check metadata (technique IDs, names) for both platforms — verified by reading the dispatch table wiring, since running the actual enrollment flow requires a live orchestrator + agent pair beyond what a unit-style check can prove.
