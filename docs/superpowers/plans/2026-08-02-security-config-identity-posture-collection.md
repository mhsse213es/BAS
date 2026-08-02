# Security Configuration & Identity Posture Collection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fill in Sub-project 1's "Security Configuration" and "Identity" placeholder categories in `internal/endpointrisk` with real evidence, sourced from a new Windows posture-check scenario plus the existing `cis-ubuntu-l1.yaml` Linux scenario, classified via a stable `check_id` (not overloaded ATT&CK technique IDs).

**Architecture:** A new optional `check_id` field threads from `scenario.Step` through `scenario.Interpret` into `models.SimulationResult`. A new, separate taxonomy package (`internal/endpointrisk`'s own `categories.yaml`/`taxonomy.go`, structurally parallel to `internal/controlhealth`'s but not shared with it) maps `check_id` → `{category, weight}`. A new shared `PostureCheckInput` aggregation (one function, two thin wrappers) feeds both categories into a refactored `ComputeHealth`, which also gains a richer `TrendDetail` (direction + new/resolved findings) computed across all four evidence-row-backed categories (Compliance, BAS Readiness, Security Configuration, Identity).

**Tech Stack:** Go 1.x, PostgreSQL (via `pgxpool`), YAML scenario definitions, vanilla JS frontend (`wwwroot/index.html`), `gopkg.in/yaml.v3`, `testcontainers-go` for DB-backed tests.

## Global Constraints

- No new agent code — every check runs through the agent's existing generic `executor: local` (default PowerShell path on Windows per `agent/executor_windows.go:106-110`, raw shell on Linux).
- No auto-run/scheduling — the new scenario is executed manually like any other. No Campaign framework, no enroll-triggered dispatch.
- `internal/controlhealth`'s `categories.yaml`/`mapper.go` are not modified — the new taxonomy is a separate file/package.
- ATT&CK `technique_id` is optional metadata on posture-check steps, never the primary classification key — `check_id` is.
- Every existing finding-builder / category / test in `internal/endpointrisk` and `internal/api` that isn't explicitly changed by a task below must keep passing unmodified.
- Full spec: `docs/superpowers/specs/2026-08-02-security-config-identity-posture-collection-design.md`.

---

### Task 1: Thread `check_id` through Step → Interpret → SimulationResult

**Files:**
- Modify: `orchestrator/internal/scenario/types.go:120-131` (`Step` struct)
- Modify: `orchestrator/internal/models/schema.go:36-78` (`SimulationResult` struct)
- Modify: `orchestrator/internal/scenario/interpreter.go:56-84` (`Interpret`)
- Test: `orchestrator/internal/scenario/interpret_test.go`

**Interfaces:**
- Produces: `scenario.Step.CheckID string` (yaml `check_id`), `models.SimulationResult.CheckID string` (json `checkId`) — consumed by Task 5's aggregation.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/scenario/interpret_test.go`:

```go
func TestInterpretCopiesCheckIDThrough(t *testing.T) {
	step := Step{TechniqueID: "T1562.004", Name: "Firewall Enabled", Framework: "custom", CheckID: "windows-firewall-enabled"}
	res := Interpret(step, ExecResult{ExitCode: 0, Stdout: "PASS: firewall enabled"})
	if res.CheckID != "windows-firewall-enabled" {
		t.Errorf("CheckID = %q, want windows-firewall-enabled", res.CheckID)
	}
}

func TestInterpretCheckIDEmptyWhenUnset(t *testing.T) {
	step := Step{TechniqueID: "T1055", Name: "ASLR Enabled", Framework: "custom"}
	res := Interpret(step, ExecResult{ExitCode: 0})
	if res.CheckID != "" {
		t.Errorf("CheckID = %q, want empty for a step with no check_id (e.g. cis-ubuntu-l1 kernel checks)", res.CheckID)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestInterpretCopiesCheckIDThrough -v`
Expected: FAIL — `Step` has no field `CheckID` (compile error).

- [ ] **Step 3: Add `CheckID` to `Step`**

In `orchestrator/internal/scenario/types.go`, in the `Step` struct (right after `TechniqueID`):

```go
type Step struct {
	Name        string        `yaml:"name"                  json:"name"`
	TechniqueID string        `yaml:"technique_id"          json:"techniqueId"`
	// CheckID is a stable, ATT&CK-independent identifier for configuration/
	// posture checks (e.g. "windows-firewall-enabled"). technique_id stays
	// optional metadata for checks that genuinely map to a technique;
	// CheckID is what internal/endpointrisk's taxonomy classifies on, so a
	// check like BitLocker (no honest ATT&CK fit) doesn't need a forced
	// technique_id at all.
	CheckID     string        `yaml:"check_id,omitempty"    json:"checkId,omitempty"`
	Framework   string        `yaml:"framework"             json:"framework"`
	Command     string        `yaml:"command,omitempty"     json:"command,omitempty"`
	AbilityID   string        `yaml:"ability_id,omitempty"  json:"abilityId,omitempty"`
	TestIndex   int           `yaml:"test_index"            json:"testIndex"`
	Executor    string        `yaml:"executor,omitempty"    json:"executor,omitempty"`
	TimeoutSec  int           `yaml:"timeout_sec,omitempty" json:"timeoutSec,omitempty"`
	Payloads    []YAMLPayload `yaml:"payloads,omitempty"   json:"payloads,omitempty"`
	Cleanup     string        `yaml:"cleanup,omitempty"    json:"cleanup,omitempty"`
	// ... rest of struct unchanged
```

- [ ] **Step 4: Add `CheckID` to `models.SimulationResult`**

In `orchestrator/internal/models/schema.go`, in `SimulationResult` (right after `ID`):

```go
type SimulationResult struct {
	ID               string           `json:"id"`
	// CheckID mirrors scenario.Step.CheckID -- present only for
	// configuration/posture-check steps (empty for ordinary ATT&CK technique
	// steps), used by internal/endpointrisk's taxonomy to classify Security
	// Configuration / Identity findings without overloading technique_id.
	CheckID          string           `json:"checkId,omitempty"`
	Technique        AttackTechnique  `json:"technique"`
	Result           CheckResult      `json:"result"`
	// ... rest of struct unchanged
```

- [ ] **Step 5: Copy it through in `Interpret`**

In `orchestrator/internal/scenario/interpreter.go`, in the `SimulationResult{...}` literal returned by `Interpret` (around line 56), add:

```go
	return models.SimulationResult{
		ID:      TaskID(step.TechniqueID, step.Name),
		CheckID: step.CheckID,
		Technique: models.AttackTechnique{
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/scenario/... -v`
Expected: PASS, including the two new tests and every pre-existing test in the package.

- [ ] **Step 7: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds (confirms no other code does an exhaustive/positional struct literal on `Step` or `SimulationResult` that the new field breaks — Go struct literals with field names are unaffected either way, but this catches any positional literal).

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/scenario/types.go orchestrator/internal/models/schema.go orchestrator/internal/scenario/interpreter.go orchestrator/internal/scenario/interpret_test.go
git commit -m "feat(scenario): thread stable check_id through Step -> SimulationResult"
git push
```

---

### Task 2: New Windows posture-check scenario + `cis-ubuntu-l1.yaml` backfill

**Files:**
- Create: `scenarios/windows-security-config.yaml`
- Modify: `scenarios/cis-ubuntu-l1.yaml` (backfill `check_id` on 7 existing steps — additive, no other field touched)

**Interfaces:**
- Produces: the `check_id` vocabulary Task 3's taxonomy classifies (`windows-firewall-enabled`, `windows-defender-realtime`, `windows-bitlocker-enabled`, `windows-rdp-nla-required`, `windows-smbv1-disabled`, `windows-guest-account-disabled`, `windows-local-admin-count`, `windows-password-min-length`, `windows-password-max-age`, `windows-account-lockout-threshold`, `linux-firewall-enabled`, `linux-apparmor-enabled`, `linux-ssh-root-login-disabled`, `linux-ssh-empty-passwords-forbidden`, `linux-password-min-length`, `linux-password-max-age`, `linux-no-empty-password-accounts`).

- [ ] **Step 1: Create `scenarios/windows-security-config.yaml`**

The agent's Windows executor (`agent/executor_windows.go:106-110`) runs any `executor: local` step's `command` as the body of `powershell -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command <command>` — so `command` must be a raw PowerShell expression, not itself wrapped in a `powershell -Command` call. Verdicts follow `interpretCustom`'s `PASS:`/`FAIL:` first-line convention (`orchestrator/internal/scenario/interpreter.go:182-208`).

```yaml
id: windows-security-config
name: Windows Security Configuration & Identity Baseline
local_check: true
description: >
  Validates core Windows security-configuration and identity posture
  controls relevant to BFSI environments: firewall, endpoint protection,
  disk encryption, remote access hardening, and account/password policy.
  All checks run on the Windows agent as built-in posture assessments --
  no external commands are sent.
supported_os: [windows]
tags:
  - security-configuration
  - identity
  - windows
  - hardening

steps:
  # -- Security Configuration ---------------------------------------------
  - name: "Windows Firewall Enabled (All Profiles)"
    check_id: windows-firewall-enabled
    technique_id: T1562.004
    framework: custom
    executor: local
    command: >-
      $p = Get-NetFirewallProfile;
      if (($p | Where-Object { $_.Enabled -eq $false }).Count -eq 0) { Write-Output 'PASS: All firewall profiles enabled' }
      else { Write-Output 'FAIL: One or more firewall profiles disabled' }
    timeout_sec: 15

  - name: "Windows Defender Real-Time Protection Enabled"
    check_id: windows-defender-realtime
    technique_id: T1562.001
    framework: custom
    executor: local
    command: >-
      $s = Get-MpComputerStatus -ErrorAction SilentlyContinue;
      if ($s -and $s.RealTimeProtectionEnabled) { Write-Output 'PASS: Defender real-time protection enabled' }
      else { Write-Output 'FAIL: Defender real-time protection disabled or unavailable' }
    timeout_sec: 15

  - name: "BitLocker Enabled on System Volume"
    check_id: windows-bitlocker-enabled
    framework: custom
    executor: local
    command: >-
      $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue;
      if ($v -and $v.ProtectionStatus -eq 'On') { Write-Output 'PASS: BitLocker enabled on system volume' }
      else { Write-Output 'FAIL: BitLocker not enabled on system volume' }
    timeout_sec: 15

  - name: "RDP Disabled or NLA Required"
    check_id: windows-rdp-nla-required
    technique_id: T1021.001
    framework: custom
    executor: local
    command: >-
      $deny = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections;
      $nla = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication;
      if ($deny -eq 1) { Write-Output 'PASS: RDP disabled' }
      elseif ($nla -eq 1) { Write-Output 'PASS: RDP enabled with NLA required' }
      else { Write-Output 'FAIL: RDP enabled without NLA' }
    timeout_sec: 15

  - name: "SMBv1 Disabled"
    check_id: windows-smbv1-disabled
    technique_id: T1021.002
    framework: custom
    executor: local
    command: >-
      $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue;
      if (-not $f -or $f.State -eq 'Disabled') { Write-Output 'PASS: SMBv1 disabled' }
      else { Write-Output 'FAIL: SMBv1 enabled' }
    timeout_sec: 20

  # -- Identity -------------------------------------------------------------
  - name: "Guest Account Disabled"
    check_id: windows-guest-account-disabled
    technique_id: T1078
    framework: custom
    executor: local
    command: >-
      $g = Get-LocalUser -Name Guest -ErrorAction SilentlyContinue;
      if (-not $g -or -not $g.Enabled) { Write-Output 'PASS: Guest account disabled' }
      else { Write-Output 'FAIL: Guest account enabled' }
    timeout_sec: 15

  - name: "Local Administrators Group Size"
    check_id: windows-local-admin-count
    technique_id: T1078.003
    framework: custom
    executor: local
    command: >-
      $c = (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue).Count;
      if ($c -le 2) { Write-Output ('PASS: ' + $c + ' local administrators') }
      else { Write-Output ('FAIL: ' + $c + ' local administrators (expected <= 2)') }
    timeout_sec: 15

  - name: "Minimum Password Length >= 12"
    check_id: windows-password-min-length
    technique_id: T1110
    framework: custom
    executor: local
    command: >-
      $o = (net accounts) -join "`n";
      if ($o -match 'Minimum password length\s+(\d+)') {
        if ([int]$Matches[1] -ge 12) { Write-Output 'PASS: Minimum password length >= 12' }
        else { Write-Output 'FAIL: Minimum password length below 12' }
      } else { Write-Output 'FAIL: Could not determine password policy' }
    timeout_sec: 15

  - name: "Maximum Password Age Within Policy"
    check_id: windows-password-max-age
    technique_id: T1110
    framework: custom
    executor: local
    command: >-
      $o = (net accounts) -join "`n";
      if ($o -match 'Maximum password age.*?(\d+)') {
        if ([int]$Matches[1] -gt 0 -and [int]$Matches[1] -le 90) { Write-Output 'PASS: Maximum password age <= 90 days' }
        else { Write-Output 'FAIL: Maximum password age not within policy' }
      } else { Write-Output 'FAIL: Could not determine password policy' }
    timeout_sec: 15

  - name: "Account Lockout Threshold Configured"
    check_id: windows-account-lockout-threshold
    technique_id: T1110
    framework: custom
    executor: local
    command: >-
      $o = (net accounts) -join "`n";
      if ($o -match 'Lockout threshold\s+(\d+)') {
        if ([int]$Matches[1] -ge 1 -and [int]$Matches[1] -le 10) { Write-Output 'PASS: Account lockout threshold configured' }
        else { Write-Output 'FAIL: Account lockout threshold not within policy' }
      } else { Write-Output 'FAIL: Could not determine lockout policy' }
    timeout_sec: 15
```

- [ ] **Step 2: Backfill `check_id` onto 7 `cis-ubuntu-l1.yaml` steps**

In `scenarios/cis-ubuntu-l1.yaml`, add a `check_id:` line to these existing steps (identified by their `name:`), leaving every other field untouched:

| Existing step `name` | Insert `check_id:` |
|---|---|
| `"UFW Firewall Enabled"` | `linux-firewall-enabled` |
| `"AppArmor Enabled and Enforcing"` | `linux-apparmor-enabled` |
| `"SSH Root Login Disabled (PermitRootLogin no)"` | `linux-ssh-root-login-disabled` |
| `"SSH Empty Passwords Forbidden (PermitEmptyPasswords no)"` | `linux-ssh-empty-passwords-forbidden` |
| `"Password Minimum Length >= 12 (PASS_MIN_LEN)"` | `linux-password-min-length` |
| `"Password Maximum Age <= 365 Days (PASS_MAX_DAYS)"` | `linux-password-max-age` |
| `"No Accounts with Empty Passwords (/etc/shadow)"` | `linux-no-empty-password-accounts` |

Example (one of the seven — same pattern for the rest):

```yaml
  - name: "UFW Firewall Enabled"
    check_id: linux-firewall-enabled
    technique_id: T1046
    framework: custom
    executor: local
    command: "ufw status 2>&1"
    timeout_sec: 10
```

- [ ] **Step 3: Verify both scenarios load cleanly**

Write a throwaway verification (not a permanent test file — this checks YAML syntax + the engine's own parsing, which Task 3/5's real tests will exercise functionally):

```bash
cd orchestrator && cat <<'EOF' > /tmp/loadcheck_test.go
package main

import (
	"fmt"
	"github.com/audspect/bas/internal/scenario"
)

func main() {
	e := scenario.NewEngine("../scenarios")
	if err := e.Load(); err != nil {
		panic(err)
	}
	if _, ok := e.Get("windows-security-config"); !ok {
		panic("windows-security-config not loaded")
	}
	if _, ok := e.Get("cis-ubuntu-l1"); !ok {
		panic("cis-ubuntu-l1 not loaded")
	}
	fmt.Println("both scenarios loaded OK")
}
EOF
go run /tmp/loadcheck_test.go
rm /tmp/loadcheck_test.go
```

Expected: prints `both scenarios loaded OK` — confirms both YAML files parse and the engine accepts the new `check_id` field without error (unknown-to-a-strict-decoder fields would fail; `yaml.v3`'s default `Unmarshal` into a struct ignores nothing it doesn't recognize as long as the field exists on `Step`, which Task 1 added).

- [ ] **Step 4: Commit**

```bash
git add scenarios/windows-security-config.yaml scenarios/cis-ubuntu-l1.yaml
git commit -m "feat(scenarios): add Windows security-config/identity checks, backfill check_id on cis-ubuntu-l1"
git push
```

(Scenario signing is automatic — `windows-build.ps1` step 0b regenerates `.sig` files at build time. No manual signing step here.)

---

### Task 3: New taxonomy package — `internal/endpointrisk/categories.yaml` + `taxonomy.go`

**Files:**
- Create: `orchestrator/internal/endpointrisk/categories.yaml`
- Create: `orchestrator/internal/endpointrisk/taxonomy.go`
- Test: `orchestrator/internal/endpointrisk/taxonomy_test.go`

**Interfaces:**
- Produces: `endpointrisk.Taxonomy`, `endpointrisk.NewTaxonomy() (*Taxonomy, error)`, `(*Taxonomy).CategoryForCheck(checkID string) (category string, weight float64, ok bool)` — consumed by Task 5's aggregation.

- [ ] **Step 1: Write `categories.yaml`**

```yaml
checks:
  # -- Windows (scenarios/windows-security-config.yaml) --------------------
  - check_id: windows-firewall-enabled
    category: security-configuration
    weight: 1.0
  - check_id: windows-defender-realtime
    category: security-configuration
    weight: 1.0
  - check_id: windows-bitlocker-enabled
    category: security-configuration
    weight: 1.0
  - check_id: windows-rdp-nla-required
    category: security-configuration
    weight: 1.0
  - check_id: windows-smbv1-disabled
    category: security-configuration
    weight: 1.0
  - check_id: windows-guest-account-disabled
    category: identity
    weight: 1.0
  - check_id: windows-local-admin-count
    category: identity
    weight: 1.0
  - check_id: windows-password-min-length
    category: identity
    weight: 1.0
  - check_id: windows-password-max-age
    category: identity
    weight: 1.0
  - check_id: windows-account-lockout-threshold
    category: identity
    weight: 1.0

  # -- Linux (scenarios/cis-ubuntu-l1.yaml, backfilled subset) -------------
  - check_id: linux-firewall-enabled
    category: security-configuration
    weight: 1.0
  - check_id: linux-apparmor-enabled
    category: security-configuration
    weight: 1.0
  - check_id: linux-ssh-root-login-disabled
    category: identity
    weight: 1.0
  - check_id: linux-ssh-empty-passwords-forbidden
    category: identity
    weight: 1.0
  - check_id: linux-password-min-length
    category: identity
    weight: 1.0
  - check_id: linux-password-max-age
    category: identity
    weight: 1.0
  - check_id: linux-no-empty-password-accounts
    category: identity
    weight: 1.0
```

- [ ] **Step 2: Write the failing test**

```go
// orchestrator/internal/endpointrisk/taxonomy_test.go
package endpointrisk

import "testing"

func TestNewTaxonomy_LoadsEmbeddedFile(t *testing.T) {
	tx, err := NewTaxonomy()
	if err != nil {
		t.Fatalf("NewTaxonomy: %v", err)
	}
	cat, weight, ok := tx.CategoryForCheck("windows-firewall-enabled")
	if !ok {
		t.Fatal("expected windows-firewall-enabled to be mapped")
	}
	if cat != "security-configuration" {
		t.Errorf("category = %q, want security-configuration", cat)
	}
	if weight != 1.0 {
		t.Errorf("weight = %v, want 1.0", weight)
	}
}

func TestCategoryForCheck_UnknownCheckID_NotOK(t *testing.T) {
	tx, err := NewTaxonomy()
	if err != nil {
		t.Fatalf("NewTaxonomy: %v", err)
	}
	_, _, ok := tx.CategoryForCheck("no-such-check")
	if ok {
		t.Error("expected ok=false for an unmapped check_id")
	}
}

func TestNewTaxonomy_LinuxChecksMapped(t *testing.T) {
	tx, err := NewTaxonomy()
	if err != nil {
		t.Fatalf("NewTaxonomy: %v", err)
	}
	cat, _, ok := tx.CategoryForCheck("linux-ssh-root-login-disabled")
	if !ok || cat != "identity" {
		t.Errorf("linux-ssh-root-login-disabled: cat=%q ok=%v, want identity/true", cat, ok)
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/endpointrisk/... -run TestNewTaxonomy -v`
Expected: FAIL — `NewTaxonomy` undefined (compile error).

- [ ] **Step 4: Write `taxonomy.go`**

```go
package endpointrisk

import (
	"embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed categories.yaml
var taxonomyFS embed.FS

type checkEntry struct {
	CheckID  string  `yaml:"check_id"`
	Category string  `yaml:"category"`
	Weight   float64 `yaml:"weight"`
}

type taxonomyFile struct {
	Checks []checkEntry `yaml:"checks"`
}

// Taxonomy maps a posture-check step's check_id to the endpointrisk
// category it belongs to and its scoring weight. This is a separate,
// structurally parallel file/package from internal/controlhealth's
// technique-keyed taxonomy -- not shared with it, so that already-shipped
// package stays untouched (per design spec §"Taxonomy ownership").
type Taxonomy struct {
	category map[string]string
	weight   map[string]float64
}

// NewTaxonomy loads and indexes the embedded categories.yaml.
func NewTaxonomy() (*Taxonomy, error) {
	data, err := taxonomyFS.ReadFile("categories.yaml")
	if err != nil {
		return nil, fmt.Errorf("endpointrisk: read categories.yaml: %w", err)
	}
	var tf taxonomyFile
	if err := yaml.Unmarshal(data, &tf); err != nil {
		return nil, fmt.Errorf("endpointrisk: parse categories.yaml: %w", err)
	}
	t := &Taxonomy{category: make(map[string]string), weight: make(map[string]float64)}
	for _, c := range tf.Checks {
		id := strings.TrimSpace(c.CheckID)
		if id == "" || c.Category == "" {
			return nil, fmt.Errorf("endpointrisk: check entry missing check_id or category: %+v", c)
		}
		w := c.Weight
		if w <= 0 {
			w = 1.0
		}
		t.category[id] = c.Category
		t.weight[id] = w
	}
	if len(t.category) == 0 {
		return nil, fmt.Errorf("endpointrisk: no checks loaded")
	}
	return t, nil
}

// CategoryForCheck returns checkID's category and weight. ok=false means
// checkID has no taxonomy entry -- callers must skip it, not error, since a
// scenario step can exist before its taxonomy entry is added.
func (t *Taxonomy) CategoryForCheck(checkID string) (category string, weight float64, ok bool) {
	c, ok := t.category[checkID]
	if !ok {
		return "", 0, false
	}
	return c, t.weight[checkID], true
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/endpointrisk/... -v`
Expected: PASS — all 3 new tests plus every pre-existing `internal/endpointrisk` test (which Task 4 has not yet touched, so they still use the old `ComputeHealth` signature at this point).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/endpointrisk/categories.yaml orchestrator/internal/endpointrisk/taxonomy.go orchestrator/internal/endpointrisk/taxonomy_test.go
git commit -m "feat(endpointrisk): add check_id-keyed taxonomy for Security Config/Identity"
git push
```

---

### Task 4: `types.go` + `health.go` — `PostureCheckInput`, extended `Finding`, `TrendDetail`, refactored `ComputeHealth`

**Files:**
- Modify: `orchestrator/internal/endpointrisk/types.go`
- Modify: `orchestrator/internal/endpointrisk/health.go`
- Modify: `orchestrator/internal/endpointrisk/health_test.go`

**Interfaces:**
- Consumes: nothing new from Tasks 1-3 directly (this task's Go code doesn't import `Taxonomy` — that's Task 5's job in `internal/api`).
- Produces: `endpointrisk.PostureCheckInput{Score, Passed, Failed, Total, Findings, Collected}`, `endpointrisk.HealthInputs{Compliance, BAS, SecurityConfig, Identity}`, `endpointrisk.TrendDetail{Direction, NewFindings, ResolvedFindings}`, extended `endpointrisk.Finding` (adds `ID`, `Description`, `Reference`, `Expected`, `Observed`, `Passed`, `LastObserved`, `LastPassed`), `endpointrisk.ComputeHealth(agentID string, profile exposure.AssetExposureProfile, now, past HealthInputs) EndpointHealth` (signature change from the old 6-positional-arg form) — consumed by Task 6's handlers.

- [ ] **Step 1: Extend `types.go`**

Replace the `Finding` struct and add the new types in `orchestrator/internal/endpointrisk/types.go`:

```go
package endpointrisk

import "time"

// Finding is one evidence-backed issue shown on a category card.
// EstimatedTime/RequiresReboot/CanAudspectFix are deliberately absent --
// this sub-project ships no remediation-execution mechanism, so there is
// nothing honest to say about how a fix would be applied yet.
// ID/Description/Reference/Expected/Observed/Passed/LastObserved/LastPassed
// are populated by posture-check findings (Security Configuration,
// Identity); every other finding builder (attack-path, detection,
// vulnerability, compliance, BAS-readiness) leaves them zero-valued --
// purely additive, no behavior change for those categories.
type Finding struct {
	ID               string     `json:"id,omitempty"` // check_id, for posture-check findings
	Title            string     `json:"title"`
	Description      string     `json:"description,omitempty"`
	Severity         string     `json:"severity"` // Critical | High | Medium | Low
	Risk             string     `json:"risk"`
	AffectedStandard string     `json:"affectedStandard,omitempty"`
	Remediation      string     `json:"remediation"`
	Reference        string     `json:"reference,omitempty"`
	Expected         string     `json:"expected,omitempty"`
	Observed         string     `json:"observed,omitempty"`
	Passed           bool       `json:"passed"`
	LastObserved     *time.Time `json:"lastObserved,omitempty"`
	LastPassed       *time.Time `json:"lastPassed,omitempty"`
}

// CategoryScore is one category's contribution to the Health Score.
// Collected=false means no data source exists for this category yet
// (Patch Management, Application Risk in V1) -- Score/Deficit/Findings are
// meaningless in that case and the frontend must render a "Not yet
// collected" placeholder instead of a 0.
type CategoryScore struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Collected bool      `json:"collected"`
	Score     int       `json:"score,omitempty"`   // 0-100, higher = safer
	Deficit   int       `json:"deficit,omitempty"` // 100 - Score
	Findings  []Finding `json:"findings,omitempty"`
}

// ActionItem is one row of the Recommended Action Plan: the worst finding
// in the category with the biggest deficit, not a fabricated per-finding
// risk-reduction percentage.
type ActionItem struct {
	CategoryID   string  `json:"categoryId"`
	CategoryName string  `json:"categoryName"`
	Deficit      int     `json:"deficit"`
	Finding      Finding `json:"finding"`
}

// AttackPathStep is one edge in the endpoint's attack-path chain narrative,
// rendered directly from exposure.Recommendations -- no new correlation
// logic.
type AttackPathStep struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

// TrendDetail is now-vs-7-days-ago: a coarse band comparison (Direction,
// averaged across whichever of Compliance/BAS/SecurityConfig/Identity are
// Collected) plus a real new/resolved-findings diff computed only from
// Security Configuration + Identity, since those are the only categories
// with a stable per-finding ID (check_id) that survives across two points
// in time. Compliance/BAS-Readiness findings aren't stably keyed the same
// way, so they stay covered by Direction only.
type TrendDetail struct {
	Direction        string    `json:"direction"` // Improving | Stable | Declining | InsufficientData
	NewFindings      []Finding `json:"newFindings,omitempty"`
	ResolvedFindings []Finding `json:"resolvedFindings,omitempty"`
}

// EndpointHealth is the full computed result for one agent.
type EndpointHealth struct {
	AgentID         string           `json:"agentId"`
	HealthScore     int              `json:"healthScore"`
	CriticalityRisk int              `json:"criticalityRisk"` // exposure.Scores.CriticalityRisk, sort/priority signal only -- never part of HealthScore
	Categories      []CategoryScore  `json:"categories"`
	ActionPlan      []ActionItem     `json:"actionPlan"`
	AttackPathChain []AttackPathStep `json:"attackPathChain"`
	Trend           TrendDetail      `json:"trend"`
}

// ComplianceInput is the compliance rollup output: one CompliancePercent
// per loaded framework, plus the real failed-control findings with their
// existing remediation text.
type ComplianceInput struct {
	PercentByFramework map[string]float64
	FailedFindings     []Finding
	Collected          bool
}

// BASReadinessInput is the BAS readiness aggregation output.
type BASReadinessInput struct {
	TechniquesTested int
	PassRate         float64 // 0-100
	LastExecutedAt   *time.Time
	Collected        bool
}

// PostureCheckInput is the shared aggregation output for BOTH Security
// Configuration and Identity -- deliberately one generic type, not
// SecurityConfigInput/IdentityInput, since the two categories are
// structurally identical (a set of check_id-keyed pass/fail results).
type PostureCheckInput struct {
	Score     int       // 0-100, weighted pass rate (see aggregation)
	Passed    int        // unweighted count of currently-passing checks
	Failed    int        // unweighted count of currently-failing checks
	Total     int        // Passed + Failed
	Findings  []Finding  // one per currently-failing check_id, ID = check_id
	Collected bool
}

// HealthInputs bundles the four evidence-row-backed category inputs so
// ComputeHealth takes two params (now, past) instead of eight positional
// ones -- every call site needed updating anyway to add SecurityConfig/
// Identity, so this is the natural point to fix the signature's ergonomics.
type HealthInputs struct {
	Compliance     ComplianceInput
	BAS            BASReadinessInput
	SecurityConfig PostureCheckInput
	Identity       PostureCheckInput
}
```

- [ ] **Step 2: Rewrite `health.go`**

Replace the full contents of `orchestrator/internal/endpointrisk/health.go`:

```go
package endpointrisk

import (
	"github.com/audspect/bas/internal/exposure"
)

// Category IDs -- used both for the 7 collected categories (real score) and
// the 2 not-yet-collected placeholders, in the fixed display order the
// design spec's category table lists. Security Configuration and Identity
// moved from placeholder to real in this sub-project.
const (
	CategoryExposureAttackPath = "exposure-attackpath"
	CategoryDetectionHealth    = "detection-health"
	CategoryVulnerabilities    = "vulnerabilities"
	CategoryCompliance         = "compliance"
	CategoryBASReadiness       = "bas-readiness"
	CategorySecurityConfig     = "security-configuration"
	CategoryIdentity           = "identity"
	CategoryPatchManagement    = "patch-management"
	CategoryApplicationRisk    = "application-risk"
)

var notYetCollectedCategories = []struct{ ID, Name string }{
	{CategoryPatchManagement, "Patch Management"},
	{CategoryApplicationRisk, "Application Risk"},
}

// ComputeHealth is pure -- no I/O -- so every combination is unit-testable
// without a database. past is the same four inputs recomputed with
// evidence filtered to 7 days ago by the caller; exposure-derived
// categories have no past counterpart, per spec §6, so Trend.Direction
// only ever reflects Compliance/BAS/SecurityConfig/Identity.
func ComputeHealth(agentID string, profile exposure.AssetExposureProfile, now, past HealthInputs) EndpointHealth {
	exposureAttackPath := CategoryScore{
		ID: CategoryExposureAttackPath, Name: "Exposure / Attack Path", Collected: true,
		Score: mean2(profile.Scores.ExposureScore, profile.Scores.AttackPathScore),
	}
	exposureAttackPath.Deficit = 100 - exposureAttackPath.Score
	exposureAttackPath.Findings = attackPathFindings(profile)

	detection := CategoryScore{
		ID: CategoryDetectionHealth, Name: "Detection Health", Collected: true,
		Score: profile.Scores.DetectionCoverageScore,
	}
	detection.Deficit = 100 - detection.Score
	detection.Findings = detectionFindings(profile)

	vulns := CategoryScore{
		ID: CategoryVulnerabilities, Name: "Vulnerabilities", Collected: true,
		Score: profile.Scores.VulnerabilityScore,
	}
	vulns.Deficit = 100 - vulns.Score
	vulns.Findings = vulnerabilityFindings(profile)

	compCat := CategoryScore{ID: CategoryCompliance, Name: "Compliance", Collected: now.Compliance.Collected}
	if now.Compliance.Collected {
		compCat.Score = round(meanOf(now.Compliance.PercentByFramework))
		compCat.Deficit = 100 - compCat.Score
		compCat.Findings = now.Compliance.FailedFindings
	}

	basCat := CategoryScore{ID: CategoryBASReadiness, Name: "BAS Readiness", Collected: now.BAS.Collected}
	if now.BAS.Collected {
		basCat.Score = round(now.BAS.PassRate)
		basCat.Deficit = 100 - basCat.Score
		basCat.Findings = basReadinessFindings(now.BAS)
	}

	secCat := CategoryScore{ID: CategorySecurityConfig, Name: "Security Configuration", Collected: now.SecurityConfig.Collected}
	if now.SecurityConfig.Collected {
		secCat.Score = now.SecurityConfig.Score
		secCat.Deficit = 100 - secCat.Score
		secCat.Findings = now.SecurityConfig.Findings
	}

	idCat := CategoryScore{ID: CategoryIdentity, Name: "Identity", Collected: now.Identity.Collected}
	if now.Identity.Collected {
		idCat.Score = now.Identity.Score
		idCat.Deficit = 100 - idCat.Score
		idCat.Findings = now.Identity.Findings
	}

	categories := []CategoryScore{exposureAttackPath, detection, vulns, compCat, basCat, secCat, idCat}
	for _, c := range notYetCollectedCategories {
		categories = append(categories, CategoryScore{ID: c.ID, Name: c.Name, Collected: false})
	}

	collectedScores := []int{}
	for _, c := range categories {
		if c.Collected {
			collectedScores = append(collectedScores, c.Score)
		}
	}

	return EndpointHealth{
		AgentID:         agentID,
		HealthScore:     round(meanInts(collectedScores)),
		CriticalityRisk: profile.Scores.CriticalityRisk,
		Categories:      categories,
		ActionPlan:      buildActionPlan(categories),
		AttackPathChain: buildAttackPathChain(profile),
		Trend:           computeTrend(now, past),
	}
}

func mean2(a, b int) int { return (a + b) / 2 }

func round(f float64) int {
	if f < 0 {
		return 0
	}
	return int(f + 0.5)
}

func meanOf(m map[string]float64) float64 {
	if len(m) == 0 {
		return 0
	}
	var sum float64
	for _, v := range m {
		sum += v
	}
	return sum / float64(len(m))
}

func meanInts(vs []int) float64 {
	if len(vs) == 0 {
		return 0
	}
	var sum int
	for _, v := range vs {
		sum += v
	}
	return float64(sum) / float64(len(vs))
}

// buildActionPlan ranks the collected categories by deficit, worst first,
// and surfaces each one's single worst finding (first in its Findings
// slice -- callers are responsible for ordering Findings worst-first when
// they build them, matching how exposure/pathcorrelation already rank
// their own output).
func buildActionPlan(categories []CategoryScore) []ActionItem {
	var out []ActionItem
	for _, c := range categories {
		if !c.Collected || c.Deficit <= 0 || len(c.Findings) == 0 {
			continue
		}
		out = append(out, ActionItem{
			CategoryID: c.ID, CategoryName: c.Name, Deficit: c.Deficit, Finding: c.Findings[0],
		})
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Deficit > out[i].Deficit {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

func buildAttackPathChain(profile exposure.AssetExposureProfile) []AttackPathStep {
	var out []AttackPathStep
	for _, g := range profile.Recommendations {
		out = append(out, AttackPathStep{From: g.Edge.From, To: g.Edge.To, Kind: string(g.Edge.Kind), Reason: g.Reason})
	}
	return out
}

func attackPathFindings(profile exposure.AssetExposureProfile) []Finding {
	var out []Finding
	for _, g := range profile.Recommendations {
		out = append(out, Finding{
			Title:       string(g.Priority) + ": " + g.Edge.From + " -> " + g.Edge.To,
			Severity:    string(g.Priority),
			Risk:        g.Reason,
			Remediation: g.Remediation,
		})
	}
	return out
}

func detectionFindings(profile exposure.AssetExposureProfile) []Finding {
	var out []Finding
	if profile.Detection.Gap > 0 {
		out = append(out, Finding{
			Title: "Detection gap on this endpoint", Severity: "High",
			Risk:        "No detection rule fired for a technique known to threaten this asset.",
			Remediation: "Add or tune a detection rule for the affected technique(s).",
		})
	}
	if profile.Detection.Unknown > 0 {
		out = append(out, Finding{
			Title: "Unverified detection coverage", Severity: "Medium",
			Risk:        "No verification evidence exists either way for a technique threatening this asset.",
			Remediation: "Run a verification pass (Detection Validation) against the affected technique(s).",
		})
	}
	return out
}

func vulnerabilityFindings(profile exposure.AssetExposureProfile) []Finding {
	var out []Finding
	for _, v := range profile.Vulnerabilities {
		sev := "Medium"
		switch {
		case v.KEV || v.CVSS >= 9:
			sev = "Critical"
		case v.CVSS >= 7:
			sev = "High"
		}
		out = append(out, Finding{
			Title:       v.CVEID,
			Severity:    sev,
			Risk:        cveRiskNarrative(v),
			Remediation: "Update the affected software to a patched version.",
		})
	}
	// worst-first, so buildActionPlan's Findings[0] is the worst CVE
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if severityRank(out[j].Severity) > severityRank(out[i].Severity) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func severityRank(s string) int {
	switch s {
	case "Critical":
		return 3
	case "High":
		return 2
	case "Medium":
		return 1
	default:
		return 0
	}
}

func cveRiskNarrative(v exposure.CVEExposure) string {
	if v.KEV {
		return v.CVEID + " is listed in CISA's Known Exploited Vulnerabilities catalog -- active exploitation confirmed in the wild."
	}
	return v.CVEID + " (CVSS " + ftoa1(v.CVSS) + ") threatens this asset via a technique in its attack surface."
}

func ftoa1(f float64) string {
	// avoids importing strconv/fmt for one call site's simple 1-decimal format
	i := int(f*10 + 0.5)
	return itoa(i/10) + "." + itoa(i%10)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func basReadinessFindings(bas BASReadinessInput) []Finding {
	if bas.PassRate >= 90 {
		return nil
	}
	return []Finding{{
		Title: "Low BAS pass rate on this endpoint", Severity: "Medium",
		Risk:        "Simulations against this endpoint have been failing more than expected.",
		Remediation: "Review recent failed simulation results and address the underlying control gaps.",
	}}
}

// healthBand is a coarse Good/Fair/Poor grouping used only for trend
// comparison -- a 1-point wobble inside "Poor" must not read as Improving.
func healthBand(score float64) int {
	switch {
	case score >= 80:
		return 2
	case score >= 50:
		return 1
	default:
		return 0
	}
}

// computeTrend reflects Compliance + BAS Readiness + Security
// Configuration + Identity (all four are asOf-filterable evidence rows);
// Exposure/Attack-Path/Detection Health have no past counterpart to
// compare, per spec §6. NewFindings/ResolvedFindings are computed only
// from Security Configuration + Identity's Findings (ID-set diff) -- see
// TrendDetail's doc comment for why Compliance/BAS don't get the same
// per-finding diff.
func computeTrend(now, past HealthInputs) TrendDetail {
	anyNow := now.Compliance.Collected || now.BAS.Collected || now.SecurityConfig.Collected || now.Identity.Collected
	anyPast := past.Compliance.Collected || past.BAS.Collected || past.SecurityConfig.Collected || past.Identity.Collected
	if !anyNow || !anyPast {
		return TrendDetail{Direction: "InsufficientData"}
	}

	current := trendInputScore(now)
	prior := trendInputScore(past)
	cb, pb := healthBand(current), healthBand(prior)
	direction := "Stable"
	switch {
	case cb > pb:
		direction = "Improving"
	case cb < pb:
		direction = "Declining"
	}

	nowFindings := append(append([]Finding{}, now.SecurityConfig.Findings...), now.Identity.Findings...)
	pastFindings := append(append([]Finding{}, past.SecurityConfig.Findings...), past.Identity.Findings...)

	return TrendDetail{
		Direction:        direction,
		NewFindings:      diffFindings(pastFindings, nowFindings),
		ResolvedFindings: diffFindings(nowFindings, pastFindings),
	}
}

// diffFindings returns the findings in compare whose ID doesn't appear in
// baseline. Findings without an ID (non-posture-check categories) never
// match here, which is correct -- they aren't part of this diff.
func diffFindings(baseline, compare []Finding) []Finding {
	seen := map[string]bool{}
	for _, f := range baseline {
		if f.ID != "" {
			seen[f.ID] = true
		}
	}
	var out []Finding
	for _, f := range compare {
		if f.ID != "" && !seen[f.ID] {
			out = append(out, f)
		}
	}
	return out
}

func trendInputScore(in HealthInputs) float64 {
	var sum, n float64
	if in.Compliance.Collected {
		sum += meanOf(in.Compliance.PercentByFramework)
		n++
	}
	if in.BAS.Collected {
		sum += in.BAS.PassRate
		n++
	}
	if in.SecurityConfig.Collected {
		sum += float64(in.SecurityConfig.Score)
		n++
	}
	if in.Identity.Collected {
		sum += float64(in.Identity.Score)
		n++
	}
	if n == 0 {
		return 0
	}
	return sum / n
}
```

- [ ] **Step 3: Rewrite `health_test.go`**

Replace the full contents of `orchestrator/internal/endpointrisk/health_test.go`:

```go
package endpointrisk

import (
	"testing"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/exposure"
	"github.com/audspect/bas/internal/pathcorrelation"
)

func TestComputeHealth_ScoresOnlyCollectedCategories(t *testing.T) {
	profile := exposure.AssetExposureProfile{
		Scores: exposure.ScoreBreakdown{ExposureScore: 80, AttackPathScore: 60, DetectionCoverageScore: 90, VulnerabilityScore: 70, CriticalityRisk: 40},
	}
	got := ComputeHealth("agent-1", profile, HealthInputs{}, HealthInputs{})

	// exposureAttackPath = mean(80,60) = 70; detection=90; vulns=70 -> mean(70,90,70) = 76.67 -> round 77
	if got.HealthScore != 77 {
		t.Errorf("HealthScore = %d, want 77", got.HealthScore)
	}
	if got.CriticalityRisk != 40 {
		t.Errorf("CriticalityRisk = %d, want 40 (not folded into HealthScore)", got.CriticalityRisk)
	}
	want := map[string]bool{CategoryCompliance: false, CategoryBASReadiness: false, CategorySecurityConfig: false, CategoryIdentity: false}
	for _, c := range got.Categories {
		if _, ok := want[c.ID]; ok {
			if c.Collected {
				t.Errorf("category %s should be Collected=false", c.ID)
			}
			delete(want, c.ID)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing categories present-but-uncollected: %v", want)
	}
}

func TestComputeHealth_NotYetCollectedCategoriesAlwaysPresent(t *testing.T) {
	got := ComputeHealth("agent-1", exposure.AssetExposureProfile{}, HealthInputs{}, HealthInputs{})
	want := map[string]bool{CategoryPatchManagement: false, CategoryApplicationRisk: false}
	for _, c := range got.Categories {
		if _, ok := want[c.ID]; ok {
			if c.Collected {
				t.Errorf("category %s should be Collected=false", c.ID)
			}
			delete(want, c.ID)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing not-yet-collected categories: %v", want)
	}
}

func TestComputeHealth_SecurityConfigAndIdentity_CollectedWhenPresent(t *testing.T) {
	now := HealthInputs{
		SecurityConfig: PostureCheckInput{Collected: true, Score: 80, Passed: 4, Failed: 1, Total: 5, Findings: []Finding{{ID: "windows-bitlocker-enabled", Title: "BitLocker disabled"}}},
		Identity:       PostureCheckInput{Collected: true, Score: 100, Passed: 5, Failed: 0, Total: 5},
	}
	got := ComputeHealth("agent-1", exposure.AssetExposureProfile{}, now, HealthInputs{})
	var secCat, idCat *CategoryScore
	for i := range got.Categories {
		switch got.Categories[i].ID {
		case CategorySecurityConfig:
			secCat = &got.Categories[i]
		case CategoryIdentity:
			idCat = &got.Categories[i]
		}
	}
	if secCat == nil || !secCat.Collected || secCat.Score != 80 || secCat.Deficit != 20 || len(secCat.Findings) != 1 {
		t.Errorf("Security Configuration category = %+v, want Collected=true Score=80 Deficit=20 1 finding", secCat)
	}
	if idCat == nil || !idCat.Collected || idCat.Score != 100 || idCat.Deficit != 0 {
		t.Errorf("Identity category = %+v, want Collected=true Score=100 Deficit=0", idCat)
	}
}

func TestComputeHealth_ActionPlanRankedByDeficit(t *testing.T) {
	profile := exposure.AssetExposureProfile{
		Scores:    exposure.ScoreBreakdown{ExposureScore: 90, AttackPathScore: 90, DetectionCoverageScore: 40, VulnerabilityScore: 95},
		Detection: exposure.DetectionContext{Gap: 1},
	}
	got := ComputeHealth("agent-1", profile, HealthInputs{}, HealthInputs{})
	if len(got.ActionPlan) == 0 {
		t.Fatal("expected at least one action item")
	}
	if got.ActionPlan[0].CategoryID != CategoryDetectionHealth {
		t.Errorf("top action = %s, want %s (biggest deficit: detection health at 60)", got.ActionPlan[0].CategoryID, CategoryDetectionHealth)
	}
}

func TestComputeHealth_AttackPathChainFromRecommendations(t *testing.T) {
	profile := exposure.AssetExposureProfile{
		Recommendations: []pathcorrelation.PrioritizedGap{
			{Edge: attackpath.Edge{From: "HOST-A", To: "HOST-B", Kind: "rdp"}, Priority: "Critical", Reason: "RDP reachable", Remediation: "Disable RDP or require MFA"},
		},
	}
	got := ComputeHealth("agent-1", profile, HealthInputs{}, HealthInputs{})
	if len(got.AttackPathChain) != 1 {
		t.Fatalf("got %d chain steps, want 1", len(got.AttackPathChain))
	}
	if got.AttackPathChain[0].From != "HOST-A" || got.AttackPathChain[0].To != "HOST-B" {
		t.Errorf("chain step = %+v, want From=HOST-A To=HOST-B", got.AttackPathChain[0])
	}
}

func TestComputeTrend_BothCollected_BandComparison(t *testing.T) {
	now := HealthInputs{
		Compliance: ComplianceInput{Collected: true, PercentByFramework: map[string]float64{"ISO": 90}},
		BAS:        BASReadinessInput{Collected: true, PassRate: 90},
	}
	past := HealthInputs{
		Compliance: ComplianceInput{Collected: true, PercentByFramework: map[string]float64{"ISO": 40}},
		BAS:        BASReadinessInput{Collected: true, PassRate: 40},
	}
	got := computeTrend(now, past)
	if got.Direction != "Improving" {
		t.Errorf("Direction = %q, want Improving (band moved from Poor to Good)", got.Direction)
	}
}

func TestComputeTrend_NeitherCollected_InsufficientData(t *testing.T) {
	got := computeTrend(HealthInputs{}, HealthInputs{})
	if got.Direction != "InsufficientData" {
		t.Errorf("Direction = %q, want InsufficientData", got.Direction)
	}
}

func TestComputeTrend_NewAndResolvedFindings(t *testing.T) {
	now := HealthInputs{
		SecurityConfig: PostureCheckInput{Collected: true, Score: 80, Findings: []Finding{{ID: "windows-bitlocker-enabled", Title: "BitLocker disabled"}}},
	}
	past := HealthInputs{
		SecurityConfig: PostureCheckInput{Collected: true, Score: 80, Findings: []Finding{{ID: "windows-firewall-enabled", Title: "Firewall disabled"}}},
	}
	got := computeTrend(now, past)
	if len(got.NewFindings) != 1 || got.NewFindings[0].ID != "windows-bitlocker-enabled" {
		t.Errorf("NewFindings = %+v, want exactly windows-bitlocker-enabled", got.NewFindings)
	}
	if len(got.ResolvedFindings) != 1 || got.ResolvedFindings[0].ID != "windows-firewall-enabled" {
		t.Errorf("ResolvedFindings = %+v, want exactly windows-firewall-enabled", got.ResolvedFindings)
	}
}

func TestComputeTrend_SameFindingsBothSides_NoNewNoResolved(t *testing.T) {
	shared := PostureCheckInput{Collected: true, Score: 80, Findings: []Finding{{ID: "windows-bitlocker-enabled", Title: "BitLocker disabled"}}}
	got := computeTrend(HealthInputs{SecurityConfig: shared}, HealthInputs{SecurityConfig: shared})
	if len(got.NewFindings) != 0 || len(got.ResolvedFindings) != 0 {
		t.Errorf("expected no new/resolved findings when both sides match, got new=%+v resolved=%+v", got.NewFindings, got.ResolvedFindings)
	}
}
```

- [ ] **Step 4: Run tests**

Run: `cd orchestrator && go test ./internal/endpointrisk/... -v`
Expected: PASS — every test in the package (Task 3's taxonomy tests plus this task's rewritten `health_test.go`).

- [ ] **Step 5: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: FAILS at this point — `internal/api/endpointrisk_handlers.go` and `internal/api/endpointrisk_aggregations.go` still call the old `ComputeHealth`/`complianceInput`/`basReadinessInput` shapes. This is expected; Tasks 5-6 fix it. Confirm the *only* build errors are in those two files (nothing else references the changed types), then proceed.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/endpointrisk/types.go orchestrator/internal/endpointrisk/health.go orchestrator/internal/endpointrisk/health_test.go
git commit -m "feat(endpointrisk): add PostureCheckInput/TrendDetail, refactor ComputeHealth to HealthInputs"
git push
```

(This intentionally leaves `internal/api` non-building for one commit — Tasks 5-6 fix it immediately after. If subagent-driven execution reviews between tasks, flag this explicitly so the reviewer doesn't treat the broken build as this task's defect.)

---

### Task 5: `postureCheckInput` aggregation in `internal/api`

**Files:**
- Modify: `orchestrator/internal/api/endpointrisk_aggregations.go`
- Modify: `orchestrator/internal/api/endpointrisk_aggregations_test.go`

**Interfaces:**
- Consumes: `endpointrisk.Taxonomy.CategoryForCheck` (Task 3), `endpointrisk.PostureCheckInput` (Task 4), `h.aggregateAgentResults` (existing, `handlers.go:3763`), `filterByAsOf` (existing, same file).
- Produces: `(h *Handler) postureCheckInput(ctx, agentID, asOf, allResults, category, findingText) endpointrisk.PostureCheckInput`, `(h *Handler) securityConfigInput(...)`, `(h *Handler) identityInput(...)` — consumed by Task 6's handlers.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/api/endpointrisk_aggregations_test.go`:

```go
func TestPostureCheckInput_WeightedScoreAndCounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-pc-a1', 'ER-PC-HOST')`)
		now := time.Now().UTC()
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-pc-run', 'windows-security-config', 'Posture Run', 'er-pc-a1', 'completed', $1::jsonb, NOW())`,
			`[
				{"checkId":"windows-firewall-enabled","technique":{"id":"T1562.004"},"result":"pass","executedAt":"`+now.Format(time.RFC3339)+`"},
				{"checkId":"windows-bitlocker-enabled","technique":{"id":""},"result":"fail","executedAt":"`+now.Format(time.RFC3339)+`"},
				{"checkId":"windows-guest-account-disabled","technique":{"id":"T1078"},"result":"pass","executedAt":"`+now.Format(time.RFC3339)+`"}
			]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		all := h.aggregateAgentResults(context.Background(), "er-pc-a1")
		got := h.securityConfigInput(context.Background(), "er-pc-a1", now.Add(time.Hour), all)
		if !got.Collected {
			t.Fatal("expected Collected=true")
		}
		if got.Total != 2 || got.Passed != 1 || got.Failed != 1 {
			t.Errorf("Total/Passed/Failed = %d/%d/%d, want 2/1/1", got.Total, got.Passed, got.Failed)
		}
		if got.Score != 50 {
			t.Errorf("Score = %d, want 50 (equal weight, 1 of 2 passed)", got.Score)
		}
		if len(got.Findings) != 1 || got.Findings[0].ID != "windows-bitlocker-enabled" {
			t.Errorf("Findings = %+v, want exactly windows-bitlocker-enabled", got.Findings)
		}

		gotIdentity := h.identityInput(context.Background(), "er-pc-a1", now.Add(time.Hour), all)
		if !gotIdentity.Collected || gotIdentity.Total != 1 || gotIdentity.Passed != 1 {
			t.Errorf("identity input = %+v, want Collected=true Total=1 Passed=1", gotIdentity)
		}
	})
}

func TestPostureCheckInput_UnmappedCheckID_Skipped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-pc-a2', 'ER-PC-HOST-2')`)
		now := time.Now().UTC()
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-pc-run-2', 'custom', 'Unmapped Run', 'er-pc-a2', 'completed', $1::jsonb, NOW())`,
			`[{"checkId":"no-such-check","result":"fail","executedAt":"`+now.Format(time.RFC3339)+`"}]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		all := h.aggregateAgentResults(context.Background(), "er-pc-a2")
		got := h.securityConfigInput(context.Background(), "er-pc-a2", now.Add(time.Hour), all)
		if got.Collected {
			t.Error("expected Collected=false -- the only result has an unmapped check_id")
		}
	})
}

func TestPostureCheckInput_NoResults_NotCollected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		all := h.aggregateAgentResults(context.Background(), "no-such-agent-ever-pc")
		got := h.securityConfigInput(context.Background(), "no-such-agent-ever-pc", time.Now().UTC(), all)
		if got.Collected {
			t.Error("expected Collected=false for an agent with no results")
		}
	})
}

func TestPostureCheckInput_HistoricalAsOf_LatestPerCheckBeforeCutoff(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-pc-a3', 'ER-PC-HOST-3')`)
		early := time.Now().UTC().Add(-48 * time.Hour)
		late := time.Now().UTC()
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-pc-run-3', 'windows-security-config', 'Regression Run', 'er-pc-a3', 'completed', $1::jsonb, NOW())`,
			`[
				{"checkId":"windows-firewall-enabled","result":"pass","executedAt":"`+early.Format(time.RFC3339)+`"},
				{"checkId":"windows-firewall-enabled","result":"fail","executedAt":"`+late.Format(time.RFC3339)+`"}
			]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		all := h.aggregateAgentResults(context.Background(), "er-pc-a3")

		asOfEarly := early.Add(time.Minute)
		gotEarly := h.securityConfigInput(context.Background(), "er-pc-a3", asOfEarly, all)
		if gotEarly.Failed != 0 || gotEarly.Passed != 1 {
			t.Errorf("as-of just after the early pass: Passed/Failed = %d/%d, want 1/0", gotEarly.Passed, gotEarly.Failed)
		}

		asOfLate := late.Add(time.Minute)
		gotLate := h.securityConfigInput(context.Background(), "er-pc-a3", asOfLate, all)
		if gotLate.Failed != 1 || gotLate.Passed != 0 {
			t.Errorf("as-of after the later fail: Passed/Failed = %d/%d, want 0/1", gotLate.Passed, gotLate.Failed)
		}
		if gotLate.Findings[0].LastPassed == nil {
			t.Error("LastPassed should be set to the early pass's timestamp, not nil")
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestPostureCheckInput -v`
Expected: FAIL — `h.securityConfigInput`/`h.identityInput` undefined (compile error). (This also still fails to build overall per Task 4 Step 5's expected state; that's fine, this task fixes it.)

- [ ] **Step 3: Add `postureCheckInput` and wrappers to `endpointrisk_aggregations.go`**

Add to `orchestrator/internal/api/endpointrisk_aggregations.go` (after the existing `basReadinessInput` function):

```go
// postureCheckFindingText holds the static per-check_id copy (description,
// expected/observed values, remediation, reference) used to build a
// Finding without inventing anything from raw command output. Keyed by
// check_id; shared across Security Configuration and Identity since a
// check_id is unique across both categories.
var postureCheckFindingText = map[string]struct {
	Title, Description, Expected, Observed, Remediation, Reference string
}{
	"windows-firewall-enabled":          {"Windows Firewall disabled", "Windows Firewall must be enabled for the Domain, Private, and Public profiles.", "Enabled", "Disabled", "Enable Windows Firewall for all profiles.", "Microsoft Security Baseline"},
	"windows-defender-realtime":         {"Defender real-time protection disabled", "Windows Defender's real-time protection must be active.", "Enabled", "Disabled", "Enable Windows Defender real-time protection.", "Microsoft Security Baseline"},
	"windows-bitlocker-enabled":         {"BitLocker not enabled", "The system volume should be encrypted with BitLocker.", "On", "Off", "Enable BitLocker on the system volume.", "CIS Microsoft Windows Benchmark"},
	"windows-rdp-nla-required":          {"RDP exposed without NLA", "RDP, if enabled, must require Network Level Authentication.", "Disabled or NLA required", "Enabled without NLA", "Disable RDP or require NLA.", "CIS Microsoft Windows Benchmark"},
	"windows-smbv1-disabled":            {"SMBv1 enabled", "The legacy, vulnerable SMBv1 protocol must be disabled.", "Disabled", "Enabled", "Disable the SMB1Protocol Windows feature.", "Microsoft Security Baseline"},
	"windows-guest-account-disabled":    {"Guest account enabled", "The built-in Guest account must be disabled.", "Disabled", "Enabled", "Disable the local Guest account.", "CIS Microsoft Windows Benchmark"},
	"windows-local-admin-count":         {"Excess local administrators", "Local Administrators group membership should be minimal.", "<= 2 members", "> 2 members", "Review and remove unnecessary local administrator accounts.", "CIS Microsoft Windows Benchmark"},
	"windows-password-min-length":       {"Weak minimum password length", "Minimum password length should be at least 12 characters.", ">= 12", "< 12", "Increase the minimum password length to 12+.", "CIS Microsoft Windows Benchmark"},
	"windows-password-max-age":          {"Password max age out of policy", "Maximum password age should be 90 days or fewer.", "1-90 days", "Out of range", "Set maximum password age to 90 days or fewer.", "CIS Microsoft Windows Benchmark"},
	"windows-account-lockout-threshold": {"Account lockout threshold not configured", "Account lockout threshold should be between 1 and 10 attempts.", "1-10", "Not configured", "Configure an account lockout threshold.", "CIS Microsoft Windows Benchmark"},
	"linux-firewall-enabled":            {"UFW firewall not confirmed active", "The UFW firewall should be active.", "active", "inactive", "Enable UFW (ufw enable).", "CIS Ubuntu Benchmark"},
	"linux-apparmor-enabled":            {"AppArmor not enforcing", "AppArmor should be enabled and enforcing.", "enforcing", "not enforcing", "Enable and enforce AppArmor profiles.", "CIS Ubuntu Benchmark"},
	"linux-ssh-root-login-disabled":     {"SSH root login permitted", "SSH root login should be disabled.", "PermitRootLogin no", "permitted", "Set PermitRootLogin no in sshd_config.", "CIS Ubuntu Benchmark"},
	"linux-ssh-empty-passwords-forbidden": {"SSH empty passwords permitted", "SSH must not allow empty passwords.", "PermitEmptyPasswords no", "permitted", "Set PermitEmptyPasswords no in sshd_config.", "CIS Ubuntu Benchmark"},
	"linux-password-min-length":         {"Weak minimum password length", "Minimum password length should be at least 12 characters.", ">= 12", "< 12", "Set PASS_MIN_LEN 12 in /etc/login.defs.", "CIS Ubuntu Benchmark"},
	"linux-password-max-age":            {"Password max age out of policy", "Maximum password age should be 365 days or fewer.", "<= 365", "> 365", "Set PASS_MAX_DAYS 365 in /etc/login.defs.", "CIS Ubuntu Benchmark"},
	"linux-no-empty-password-accounts":  {"Accounts with empty passwords found", "No account should have an empty password.", "none", "one or more found", "Set a password or lock the affected account(s).", "CIS Ubuntu Benchmark"},
}

// postureCheckInput aggregates Security Configuration or Identity evidence
// (selected by category, a taxonomy category string) from allResults: the
// most recent result per check_id (asOf-filtered) determines that check's
// current pass/fail state; Score is a weighted pass rate using each
// check's taxonomy weight; LastPassed scans full history (still asOf-
// filtered) for that check_id's most recent pass, independent of what the
// latest result is.
func (h *Handler) postureCheckInput(ctx context.Context, agentID string, asOf time.Time, allResults []models.SimulationResult, category string) endpointrisk.PostureCheckInput {
	if h.endpointRiskTaxonomy == nil {
		return endpointrisk.PostureCheckInput{}
	}
	results := filterByAsOf(allResults, asOf)

	type latest struct {
		result     models.SimulationResult
		lastPassed *time.Time
	}
	byCheck := map[string]*latest{}
	for _, r := range results {
		if r.CheckID == "" {
			continue
		}
		cat, _, ok := h.endpointRiskTaxonomy.CategoryForCheck(r.CheckID)
		if !ok || cat != category {
			continue
		}
		l, exists := byCheck[r.CheckID]
		if !exists {
			l = &latest{}
			byCheck[r.CheckID] = l
		}
		if r.Result == models.ResultPass {
			t := r.ExecutedAt
			if l.lastPassed == nil || t.After(*l.lastPassed) {
				l.lastPassed = &t
			}
		}
		if l.result.ID == "" || r.ExecutedAt.After(l.result.ExecutedAt) {
			l.result = r
		}
	}

	if len(byCheck) == 0 {
		return endpointrisk.PostureCheckInput{}
	}

	var passed, failed int
	var weightedPassed, weightedTotal float64
	var findings []endpointrisk.Finding
	for checkID, l := range byCheck {
		_, weight, _ := h.endpointRiskTaxonomy.CategoryForCheck(checkID)
		weightedTotal += weight
		if l.result.Result == models.ResultPass {
			passed++
			weightedPassed += weight
			continue
		}
		failed++
		text := postureCheckFindingText[checkID]
		observedAt := l.result.ExecutedAt
		findings = append(findings, endpointrisk.Finding{
			ID: checkID, Title: text.Title, Description: text.Description,
			Severity: "Medium", Risk: text.Description,
			Remediation: text.Remediation, Reference: text.Reference,
			Expected: text.Expected, Observed: text.Observed,
			Passed: false, LastObserved: &observedAt, LastPassed: l.lastPassed,
		})
	}

	score := 0
	if weightedTotal > 0 {
		score = int(weightedPassed/weightedTotal*100 + 0.5)
	}
	return endpointrisk.PostureCheckInput{
		Score: score, Passed: passed, Failed: failed, Total: passed + failed,
		Findings: findings, Collected: true,
	}
}

func (h *Handler) securityConfigInput(ctx context.Context, agentID string, asOf time.Time, allResults []models.SimulationResult) endpointrisk.PostureCheckInput {
	return h.postureCheckInput(ctx, agentID, asOf, allResults, "security-configuration")
}

func (h *Handler) identityInput(ctx context.Context, agentID string, asOf time.Time, allResults []models.SimulationResult) endpointrisk.PostureCheckInput {
	return h.postureCheckInput(ctx, agentID, asOf, allResults, "identity")
}
```

- [ ] **Step 4: Add the `endpointRiskTaxonomy` field to `Handler` (needed for Step 3 to compile)**

In `orchestrator/internal/api/handlers.go`, add the field next to `controlHealthMapper` (around line 86):

```go
	complianceMapper      *compliance.Mapper    // nil when not loaded
	controlHealthMapper   *controlhealth.Mapper // nil when not loaded
	endpointRiskTaxonomy  *endpointrisk.Taxonomy // nil when not loaded
```

And add a `With` method next to `WithControlHealth` (around line 119):

```go
// WithEndpointRiskTaxonomy attaches the Security Config/Identity check_id taxonomy.
func (h *Handler) WithEndpointRiskTaxonomy(t *endpointrisk.Taxonomy) *Handler {
	h.endpointRiskTaxonomy = t
	return h
}
```

Add the import `"github.com/audspect/bas/internal/endpointrisk"` to `handlers.go`'s import block if not already present (it is — `endpointrisk_handlers.go` already imports it in the same package, but each file needs its own import; check `handlers.go`'s existing import block and add it if missing).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestPostureCheckInput -v`
Expected: PASS for all 4 new tests. (Full package build still fails until Task 6 updates `endpointrisk_handlers.go`'s calls to the old `ComputeHealth`/`complianceInput` shapes — expected at this point.)

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/endpointrisk_aggregations.go orchestrator/internal/api/endpointrisk_aggregations_test.go orchestrator/internal/api/handlers.go
git commit -m "feat(api): add postureCheckInput aggregation for Security Config/Identity"
git push
```

---

### Task 6: Wire `HealthInputs` into handlers + `main.go`

**Files:**
- Modify: `orchestrator/internal/api/endpointrisk_handlers.go`
- Modify: `orchestrator/internal/api/endpointrisk_handlers_test.go`
- Modify: `orchestrator/cmd/server/main.go`

**Interfaces:**
- Consumes: `endpointrisk.HealthInputs`, `endpointrisk.NewTaxonomy()` (Task 3/4), `h.securityConfigInput`/`h.identityInput` (Task 5), `h.WithEndpointRiskTaxonomy` (Task 5).

- [ ] **Step 1: Update `GetAgentRisk` and `GetAgentRiskSummary`**

In `orchestrator/internal/api/endpointrisk_handlers.go`, replace the body of `GetAgentRisk` from the `allResults :=` line onward:

```go
	allResults := h.aggregateAgentResults(r.Context(), agentID)
	now := time.Now().UTC()
	weekAgo := now.AddDate(0, 0, -7)

	nowInputs := endpointrisk.HealthInputs{
		Compliance:     h.complianceInput(r.Context(), agentID, now, allResults),
		BAS:            h.basReadinessInput(now, allResults),
		SecurityConfig: h.securityConfigInput(r.Context(), agentID, now, allResults),
		Identity:       h.identityInput(r.Context(), agentID, now, allResults),
	}
	pastInputs := endpointrisk.HealthInputs{
		Compliance:     h.complianceInput(r.Context(), agentID, weekAgo, allResults),
		BAS:            h.basReadinessInput(weekAgo, allResults),
		SecurityConfig: h.securityConfigInput(r.Context(), agentID, weekAgo, allResults),
		Identity:       h.identityInput(r.Context(), agentID, weekAgo, allResults),
	}

	health := endpointrisk.ComputeHealth(agentID, profile, nowInputs, pastInputs)
	respond(w, health)
```

And in `GetAgentRiskSummary`, replace the per-agent block inside the `for _, s := range ag.Summaries()` loop from `allResults :=` onward:

```go
		allResults := h.aggregateAgentResults(r.Context(), s.Asset.AgentID)
		nowInputs := endpointrisk.HealthInputs{
			Compliance:     h.complianceInput(r.Context(), s.Asset.AgentID, now, allResults),
			BAS:            h.basReadinessInput(now, allResults),
			SecurityConfig: h.securityConfigInput(r.Context(), s.Asset.AgentID, now, allResults),
			Identity:       h.identityInput(r.Context(), s.Asset.AgentID, now, allResults),
		}
		pastInputs := endpointrisk.HealthInputs{
			Compliance:     h.complianceInput(r.Context(), s.Asset.AgentID, weekAgo, allResults),
			BAS:            h.basReadinessInput(weekAgo, allResults),
			SecurityConfig: h.securityConfigInput(r.Context(), s.Asset.AgentID, weekAgo, allResults),
			Identity:       h.identityInput(r.Context(), s.Asset.AgentID, weekAgo, allResults),
		}
		health := endpointrisk.ComputeHealth(s.Asset.AgentID, profile, nowInputs, pastInputs)

		row := AgentRiskRow{
			AgentID: s.Asset.AgentID, Hostname: s.Asset.Label,
			HealthScore: health.HealthScore, CriticalityRisk: health.CriticalityRisk, Trend: health.Trend.Direction,
		}
```

(The rest of `GetAgentRiskSummary` — `TopDeficitCategory`/`OpenFindingsCount` population and `append(out, row)` — is unchanged.)

- [ ] **Step 2: Update `endpointrisk_handlers_test.go`**

In `TestGetAgentRisk_KnownAgent_ReturnsAllCategories` (`orchestrator/internal/api/endpointrisk_handlers_test.go`), change the expected category count comment/assertion:

```go
		if len(got.Categories) != 9 {
			t.Errorf("got %d categories, want 9 (7 real-or-uncollected + 2 not-yet-collected)", len(got.Categories))
		}
```

(Total stays 9 -- composition changes from 5+4 to 7+2: Exposure/Attack-Path, Detection Health, Vulnerabilities, Compliance, BAS Readiness, Security Configuration, Identity are all always-present-collected-or-not; only Patch Management and Application Risk remain placeholders.)

Add one new test confirming a mixed Windows/Linux fleet works through `GetAgentRiskSummary` without error:

```go
func TestGetAgentRiskSummary_MixedOSFleet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os) VALUES ('er-mix-win', 'ER-MIX-WIN', 'windows')`)
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os) VALUES ('er-mix-lin', 'ER-MIX-LIN', 'linux')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/agents/risk-summary", nil)
		w := httptest.NewRecorder()
		h.GetAgentRiskSummary(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var body struct {
			Agents []AgentRiskRow `json:"agents"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		seen := map[string]bool{}
		for _, a := range body.Agents {
			seen[a.AgentID] = true
		}
		if !seen["er-mix-win"] || !seen["er-mix-lin"] {
			t.Error("expected both Windows and Linux agents in the fleet risk summary")
		}
	})
}
```

(If `agents` has no `os` column, check `internal/db` schema first — if absent, drop the `os` column from the two `INSERT`s above; the test's point is just "two agents of any kind both compute cleanly", not literal OS filtering, since `GetAgentRiskSummary` doesn't branch on OS today.)

- [ ] **Step 3: Wire the taxonomy in `main.go`**

Add the import in `orchestrator/cmd/server/main.go`'s import block (alphabetical, next to `"github.com/audspect/bas/internal/detect"`):

```go
	"github.com/audspect/bas/internal/endpointrisk"
```

Add construction after the Control Health Mapper block (around line 196):

```go
	// ── Endpoint Risk Taxonomy (Security Config & Identity Posture) ───────
	endpointRiskTaxonomy, erErr := endpointrisk.NewTaxonomy()
	if erErr != nil {
		log.Printf("[!] endpoint risk taxonomy: %v — Security Configuration/Identity categories unavailable", erErr)
	} else {
		log.Printf("[+] Endpoint risk taxonomy loaded")
	}
```

Add `.WithEndpointRiskTaxonomy(endpointRiskTaxonomy).` to the handler chain right after `.WithControlHealth(controlHealthMapper).` (around line 401).

- [ ] **Step 4: Run the full test suite**

Run: `cd orchestrator && go build ./... && go test ./... -short`
Expected: builds cleanly; all `-short` tests pass (container-backed tests skip in `-short` mode, matching this session's established convention).

Run: `cd orchestrator && go test ./internal/api/... ./internal/endpointrisk/... ./internal/scenario/... -v`
Expected: full pass, including every container-backed test (requires Docker running — check `docker info` first per project convention).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/endpointrisk_handlers.go orchestrator/internal/api/endpointrisk_handlers_test.go orchestrator/cmd/server/main.go
git commit -m "feat(api): wire Security Config/Identity into GetAgentRisk via HealthInputs"
git push
```

---

### Task 7: Frontend — richer trend + finding rendering

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: `EndpointHealth.trend` (now `{direction, newFindings, resolvedFindings}` instead of a plain string), extended `Finding` fields (`expected`, `observed`, `lastObserved`, `reference`).

- [ ] **Step 1: Update `renderAgtRisk`'s trend badge call**

In `orchestrator/wwwroot/index.html`, find the `renderAgtRisk` function (currently ~line 13856). Change the Health Score card's trend line:

```js
'<div class="tiny muted">' + _riskTrendBadge(health.trend.direction) + '</div></div>' +
```

(was `_riskTrendBadge(health.trend)` — `health.trend` is now an object, `_riskTrendBadge` still expects a plain string.)

- [ ] **Step 2: Add a new/resolved findings summary line**

Immediately after the `kpi-row` div in `renderAgtRisk` (right after the closing `'</div>';` of the `h` variable's first assignment, before the Recommended Action Plan block), add:

```js
  if ((health.trend.newFindings || []).length || (health.trend.resolvedFindings || []).length) {
    h += '<div class="tiny muted" style="margin-bottom:1rem">' +
      (health.trend.newFindings.length ? '<span style="color:var(--danger)">' + health.trend.newFindings.length + ' new</span>' : '') +
      (health.trend.newFindings.length && health.trend.resolvedFindings.length ? ', ' : '') +
      (health.trend.resolvedFindings.length ? '<span style="color:var(--success)">' + health.trend.resolvedFindings.length + ' resolved</span>' : '') +
      ' since 7 days ago</div>';
  }
```

- [ ] **Step 3: Render the new `Finding` fields in `_riskCategoryCard`**

In `_riskCategoryCard` (currently ~line 13838), extend the `findingsHtml` mapping to show expected/observed and last-observed when present:

```js
  var findingsHtml = (c.findings || []).map(function(f) {
    return '<li><strong>' + x(f.title) + '</strong> (' + x(f.severity) + ') — ' + x(f.risk) +
      (f.expected || f.observed ? '<div class="tiny muted">Expected: ' + x(f.expected || '—') + ' · Observed: ' + x(f.observed || '—') + '</div>' : '') +
      (f.affectedStandard ? '<div class="tiny muted">Affected standard: ' + x(f.affectedStandard) + '</div>' : '') +
      (f.reference ? '<div class="tiny muted">Reference: ' + x(f.reference) + '</div>' : '') +
      (f.lastObserved ? '<div class="tiny muted">Last observed: ' + new Date(f.lastObserved).toLocaleString() + '</div>' : '') +
      '<div class="tiny" style="color:var(--accent)">Remediation: ' + x(f.remediation) + '</div></li>';
  }).join('');
```

- [ ] **Step 4: Verify with `node --check`**

Extract the inline `<script>` block and check syntax, following this session's established convention:

```bash
cd "C:/Users/Administrator/Downloads/Audspect_Cloud/orchestrator/wwwroot"
START=$(grep -n '<script>' index.html | tail -1 | cut -d: -f1)
END=$(grep -n '</script>' index.html | tail -1 | cut -d: -f1)
sed -n "${START},$((END-1))p" index.html | tail -n +2 > /tmp/extracted.js
node --check /tmp/extracted.js
rm /tmp/extracted.js
```

Expected: no output (syntax OK).

- [ ] **Step 5: Manual review note**

No automated frontend test suite exists for `wwwroot/index.html` (established convention). Manual browser QA for this rendering change goes on the existing deferred-QA backlog alongside the rest of Sub-project 1's frontend — do not attempt to click through it now unless explicitly asked.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): render TrendDetail (new/resolved findings) and richer Finding fields in Risk & Remediation"
git push
```

---

## Self-Review Notes

- **Spec coverage**: §1 (check_id schema) → Task 1. §2 (Windows scenario) → Task 2. §3 (taxonomy) → Task 3. §4 (Finding/PostureCheckInput) → Task 4. §5 (aggregation) → Task 5. §6 (ComputeHealth/weighting/trend) → Tasks 4-5. §7 (explicit already-shipped changes list) → Tasks 1, 4, 5, 6, 7 collectively. §8 (testing) → every task's own test step plus Task 6 Step 4's full-suite run.
- **Type consistency checked**: `PostureCheckInput`, `HealthInputs`, `TrendDetail`, `Taxonomy.CategoryForCheck` signatures match verbatim between their defining task (3/4) and every consuming task (5/6).
- **Build-breaks-mid-plan called out explicitly**: Tasks 4 and 5 each end with a known, temporary `internal/api` build failure fixed by the next task — flagged in both tasks' steps so a reviewer (human or subagent-driven-development's review stage) doesn't mistake it for a defect in that task.
