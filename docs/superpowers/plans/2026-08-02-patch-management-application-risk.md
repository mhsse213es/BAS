# Patch Management & Application Risk Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fill in Sub-project 1's last two placeholder categories in `internal/endpointrisk` — Patch Management (fix + extend the existing broken `os-patch-posture.yaml`) and Application Risk (build from scratch: inventory scenario, server-side parsing, curated EOL catalog, severity-weighted scoring).

**Architecture:** Patch Management reuses Sub-project 2's exact `check_id`/taxonomy/`PostureCheckInput` pattern — it's a fixed pass/fail checklist. Application Risk is new territory: a schema fix for oversized evidence (`MaxOutputBytes`), two new inventory scenarios, a new embedded EOL/high-risk software catalog (`internal/endpointrisk/eol_catalog.yaml`), and a distinct `ApplicationRiskInput` type with severity-weighted deduction scoring (not a pass rate — an open-ended scan, not a checklist).

**Tech Stack:** Go 1.x, PostgreSQL (via `pgxpool`), YAML scenario definitions, `gopkg.in/yaml.v3`, `testcontainers-go` for DB-backed tests.

## Global Constraints

- No new agent code — every check runs through the existing `executor: local` primitive.
- No auto-run/scheduling — both new scenarios are manually executed, matching every other scenario.
- The EOL catalog is a small, hand-curated, embedded V1 list (~18 entries) — explicitly not exhaustive, no external feed.
- `PostureCheckInput` (fixed checklist) and `ApplicationRiskInput` (open-ended scan) stay distinct types — do not merge them.
- Every existing finding-builder / category / test in `internal/endpointrisk` and `internal/api` that isn't explicitly changed by a task below must keep passing unmodified.
- Full spec: `docs/superpowers/specs/2026-08-02-patch-management-application-risk-design.md`.

---

### Task 1: Evidence-size schema fix — `MaxOutputBytes` + truncation metadata

**Files:**
- Modify: `orchestrator/internal/scenario/types.go` (`Step` struct)
- Modify: `orchestrator/internal/models/schema.go` (`SimulationResult` struct)
- Modify: `orchestrator/internal/scenario/interpreter.go` (`Interpret`)
- Test: `orchestrator/internal/scenario/interpret_test.go`

**Interfaces:**
- Produces: `scenario.Step.MaxOutputBytes int` (yaml `max_output_bytes`), `models.SimulationResult.Truncated bool` + `OriginalOutputBytes int` (json `truncated`/`originalOutputBytes`) — consumed by Task 4's installed-software scenarios and available to any future evidence-heavy check.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/scenario/interpret_test.go`:

```go
func TestInterpretUsesDefaultOutputLimitWhenUnset(t *testing.T) {
	step := Step{TechniqueID: "T1082", Name: "test", Framework: "custom"}
	longOutput := strings.Repeat("x", 4000)
	res := Interpret(step, ExecResult{ExitCode: 0, Stdout: longOutput})
	if len(res.RawOutput) > 3001 { // 3000 + the "…" truncation marker
		t.Errorf("RawOutput len = %d, want capped near 3000 (default limit)", len(res.RawOutput))
	}
	if !res.Truncated {
		t.Error("expected Truncated=true when output exceeds the default 3000-byte limit")
	}
	if res.OriginalOutputBytes != len(longOutput) {
		t.Errorf("OriginalOutputBytes = %d, want %d", res.OriginalOutputBytes, len(longOutput))
	}
}

func TestInterpretUsesStepOverrideOutputLimit(t *testing.T) {
	step := Step{TechniqueID: "T1082", Name: "test", Framework: "custom", MaxOutputBytes: 20000}
	longOutput := strings.Repeat("x", 4000)
	res := Interpret(step, ExecResult{ExitCode: 0, Stdout: longOutput})
	if res.Truncated {
		t.Error("expected Truncated=false -- 4000 bytes is under the step's 20000-byte override")
	}
	if len(res.RawOutput) != len(longOutput) {
		t.Errorf("RawOutput len = %d, want %d (untruncated)", len(res.RawOutput), len(longOutput))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestInterpretUsesDefault -v`
Expected: FAIL — `Step.MaxOutputBytes` / `SimulationResult.Truncated` undefined (compile error).

- [ ] **Step 3: Add `MaxOutputBytes` to `Step`**

In `orchestrator/internal/scenario/types.go`, in the `Step` struct (right after `CheckID`):

```go
	CheckID     string        `yaml:"check_id,omitempty"    json:"checkId,omitempty"`
	// MaxOutputBytes overrides the default 3000-byte RawOutput truncation
	// limit for checks whose evidence is legitimately large (e.g. a full
	// installed-software inventory). 0 means "use the default".
	MaxOutputBytes int        `yaml:"max_output_bytes,omitempty" json:"maxOutputBytes,omitempty"`
	Framework   string        `yaml:"framework"             json:"framework"`
```

- [ ] **Step 4: Add `Truncated`/`OriginalOutputBytes` to `models.SimulationResult`**

In `orchestrator/internal/models/schema.go`, in `SimulationResult` (right after `RawOutput`):

```go
	RawOutput        string           `json:"rawOutput,omitempty"`
	// Truncated/OriginalOutputBytes make evidence truncation visible instead
	// of silent -- a parser (e.g. Application Risk's installed-software
	// parser) can detect incomplete evidence rather than unknowingly working
	// with a partial list.
	Truncated            bool `json:"truncated,omitempty"`
	OriginalOutputBytes  int  `json:"originalOutputBytes,omitempty"`
	DurationMs       int64            `json:"durationMs"`
```

- [ ] **Step 5: Use the override and record truncation metadata in `Interpret`**

In `orchestrator/internal/scenario/interpreter.go`, replace the single `RawOutput: truncate(combined, 3000),` line's surrounding logic. First, before the `return models.SimulationResult{...}` block (after the `combined := ...` line around line 32), add:

```go
	combined := strings.TrimSpace(result.Stdout + "\n" + result.Stderr)

	outputLimit := 3000
	if step.MaxOutputBytes > 0 {
		outputLimit = step.MaxOutputBytes
	}
	truncated := len(combined) > outputLimit
```

Then in the `SimulationResult{...}` literal, replace `RawOutput: truncate(combined, 3000),` with:

```go
		RawOutput:            truncate(combined, outputLimit),
		Truncated:            truncated,
		OriginalOutputBytes:  len(combined),
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/scenario/... -v`
Expected: PASS, including the two new tests and every pre-existing test in the package.

- [ ] **Step 7: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly (purely additive struct fields).

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/scenario/types.go orchestrator/internal/models/schema.go orchestrator/internal/scenario/interpreter.go orchestrator/internal/scenario/interpret_test.go
git commit -m "feat(scenario): add per-step MaxOutputBytes override + truncation metadata"
git push
```

---

### Task 2: Patch Management scenarios — split and retire

**Files:**
- Create: `scenarios/windows-patch-posture.yaml`
- Create: `scenarios/linux-patch-posture.yaml`
- Delete: `scenarios/os-patch-posture.yaml`
- Modify: `orchestrator/internal/endpointrisk/categories.yaml` (add 3 patch-management entries)

**Interfaces:**
- Produces: `check_id`s `windows-last-patch-age`, `linux-pending-security-updates`, `linux-last-patch-age`, each mapped to `category: patch-management` — consumed by Task 3's `patchManagementInput`.

- [ ] **Step 1: Check for a stale signature file and remove it if present**

```bash
ls scenarios/os-patch-posture.yaml.sig 2>/dev/null && rm scenarios/os-patch-posture.yaml.sig
```

- [ ] **Step 2: Delete the old scenario**

```bash
rm scenarios/os-patch-posture.yaml
```

- [ ] **Step 3: Create `scenarios/windows-patch-posture.yaml`**

```yaml
id: windows-patch-posture
name: Windows Patch Currency Check
local_check: true
description: >
  Checks whether the endpoint has installed a security update within the
  last 30 days. Unpatched OS vulnerabilities are among the most common
  ransomware and worm entry points; SEBI CSCRF mandates critical patches
  within 30 days of release.
author: Audspect Research
supported_os: [windows]
tags:
  - patch-management
  - cscrf
  - windows

steps:
  - name: "Patch Currency — Last Update Age (CSCRF-5.1)"
    check_id: windows-last-patch-age
    technique_id: T1082
    framework: custom
    executor: local
    command: >-
      $h = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1;
      if ($h -and $h.InstalledOn -and ((Get-Date) - $h.InstalledOn).Days -le 30) { Write-Output 'PASS: Last patch installed within 30 days' }
      else { Write-Output 'FAIL: Last patch installed more than 30 days ago (or unknown)' }
    timeout_sec: 15
```

- [ ] **Step 4: Create `scenarios/linux-patch-posture.yaml`**

```yaml
id: linux-patch-posture
name: Linux Patch Currency Check
local_check: true
description: >
  Checks pending security updates and last-patch age. Unpatched OS
  vulnerabilities are among the most common ransomware and worm entry
  points; SEBI CSCRF mandates critical patches within 30 days of release.
author: Audspect Research
supported_os: [linux]
tags:
  - patch-management
  - cscrf
  - linux

steps:
  - name: "Pending Security Updates (apt)"
    check_id: linux-pending-security-updates
    technique_id: T1082
    framework: custom
    executor: local
    command: >-
      count=$(apt list --upgradable 2>/dev/null | grep -ic security || echo 0);
      if [ "$count" -eq 0 ]; then echo "PASS: No pending security updates"; else echo "FAIL: $count pending security update(s)"; fi
    timeout_sec: 20

  - name: "Last Patch Age (apt history)"
    check_id: linux-last-patch-age
    technique_id: T1082
    framework: custom
    executor: local
    command: >-
      if [ -f /var/log/apt/history.log ]; then
        age=$(( ( $(date +%s) - $(stat -c %Y /var/log/apt/history.log) ) / 86400 ));
        if [ "$age" -le 30 ]; then echo "PASS: Last patch $age days ago"; else echo "FAIL: Last patch $age days ago (overdue)"; fi
      else
        echo "SKIP: apt history log not found";
      fi
    timeout_sec: 10
```

- [ ] **Step 5: Add taxonomy entries**

In `orchestrator/internal/endpointrisk/categories.yaml`, append:

```yaml

  # -- Windows (scenarios/windows-patch-posture.yaml) ----------------------
  - check_id: windows-last-patch-age
    category: patch-management
    weight: 1.0

  # -- Linux (scenarios/linux-patch-posture.yaml) ---------------------------
  - check_id: linux-pending-security-updates
    category: patch-management
    weight: 1.0
  - check_id: linux-last-patch-age
    category: patch-management
    weight: 1.0
```

- [ ] **Step 6: Verify both new scenarios parse and the old one is gone**

```bash
cd orchestrator && mkdir -p cmd/loadcheck_tmp && cat <<'EOF' > cmd/loadcheck_tmp/main.go
package main

import (
	"fmt"
	"os"

	"github.com/audspect/bas/internal/scenario"
	"gopkg.in/yaml.v3"
)

func check(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var s scenario.Scenario
	if err := yaml.Unmarshal(b, &s); err != nil {
		panic(fmt.Sprintf("%s: parse error: %v", path, err))
	}
	if s.ID == "" {
		panic(fmt.Sprintf("%s: missing id", path))
	}
	fmt.Printf("%s: OK id=%s steps=%d\n", path, s.ID, len(s.Steps))
}

func main() {
	check("../scenarios/windows-patch-posture.yaml")
	check("../scenarios/linux-patch-posture.yaml")
	if _, err := os.Stat("../scenarios/os-patch-posture.yaml"); err == nil {
		panic("os-patch-posture.yaml should have been deleted")
	}
	fmt.Println("all checks passed")
}
EOF
go run ./cmd/loadcheck_tmp
rm -rf cmd/loadcheck_tmp
```

Expected: both scenarios print `OK id=... steps=N`, then `all checks passed`.

- [ ] **Step 7: Confirm the taxonomy still loads (categories.yaml is unembedded YAML data, but a quick unit-test run catches any indentation error)**

Run: `cd orchestrator && go test ./internal/endpointrisk/... -run TestNewTaxonomy -v`
Expected: PASS (existing tests still pass against the extended file).

- [ ] **Step 8: Commit**

```bash
git add scenarios/windows-patch-posture.yaml scenarios/linux-patch-posture.yaml orchestrator/internal/endpointrisk/categories.yaml
git rm scenarios/os-patch-posture.yaml
git commit -m "feat(scenarios): split os-patch-posture.yaml into OS-specific scenarios with check_id"
git push
```

---

### Task 3: `patchManagementInput` wrapper + finding text

**Files:**
- Modify: `orchestrator/internal/api/endpointrisk_aggregations.go`
- Modify: `orchestrator/internal/api/endpointrisk_aggregations_test.go`

**Interfaces:**
- Produces: `(h *Handler) patchManagementInput(ctx, agentID, asOf, allResults) endpointrisk.PostureCheckInput` — consumed by Task 8's handlers.

- [ ] **Step 1: Add the 3 new check_ids to `postureCheckFindingText`**

In `orchestrator/internal/api/endpointrisk_aggregations.go`, add entries to the existing `postureCheckFindingText` map:

```go
	"windows-last-patch-age":           {"Last patch overdue", "The last installed security update should be within 30 days.", "<= 30 days", "> 30 days or unknown", "Install pending Windows Updates.", "SEBI CSCRF"},
	"linux-pending-security-updates":   {"Pending security updates", "No pending security updates should be outstanding.", "0 pending", "1 or more pending", "Run apt upgrade to install pending security updates.", "SEBI CSCRF"},
	"linux-last-patch-age":             {"Last patch overdue", "The last installed patch should be within 30 days.", "<= 30 days", "> 30 days", "Run apt upgrade regularly to keep patches current.", "SEBI CSCRF"},
```

- [ ] **Step 2: Add the wrapper**

Right after `identityInput`:

```go
func (h *Handler) patchManagementInput(ctx context.Context, agentID string, asOf time.Time, allResults []models.SimulationResult) endpointrisk.PostureCheckInput {
	return h.postureCheckInput(ctx, agentID, asOf, allResults, "patch-management")
}
```

- [ ] **Step 3: Write the failing test**

Add to `orchestrator/internal/api/endpointrisk_aggregations_test.go`:

```go
func TestPatchManagementInput_ComputesFromWindowsAndLinuxChecks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-pm-a1', 'ER-PM-HOST')`)
		now := time.Now().UTC()
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-pm-run', 'windows-patch-posture', 'Patch Run', 'er-pm-a1', 'completed', $1::jsonb, NOW())`,
			`[{"checkId":"windows-last-patch-age","result":"fail","executedAt":"`+now.Format(time.RFC3339)+`"}]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		tx, err := endpointrisk.NewTaxonomy()
		if err != nil {
			t.Fatalf("NewTaxonomy: %v", err)
		}
		h.endpointRiskTaxonomy = tx

		all := h.aggregateAgentResults(context.Background(), "er-pm-a1")
		got := h.patchManagementInput(context.Background(), "er-pm-a1", now.Add(time.Hour), all)
		if !got.Collected || got.Total != 1 || got.Failed != 1 {
			t.Errorf("patch management input = %+v, want Collected=true Total=1 Failed=1", got)
		}
		if len(got.Findings) != 1 || got.Findings[0].ID != "windows-last-patch-age" {
			t.Errorf("Findings = %+v, want exactly windows-last-patch-age", got.Findings)
		}
	})
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestPatchManagementInput -v`
Expected: PASS.

- [ ] **Step 5: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/endpointrisk_aggregations.go orchestrator/internal/api/endpointrisk_aggregations_test.go
git commit -m "feat(api): add patchManagementInput wrapper and finding text"
git push
```

---

### Task 4: Installed-software inventory scenarios

**Files:**
- Create: `scenarios/windows-installed-software.yaml`
- Create: `scenarios/linux-installed-software.yaml`

**Interfaces:**
- Produces: `check_id`s `windows-installed-software`/`linux-installed-software`, each a single `Name|Version`-per-line inventory dump (`max_output_bytes: 20000`, from Task 1) — consumed by Task 6's `applicationRiskInput`.

- [ ] **Step 1: Create `scenarios/windows-installed-software.yaml`**

```yaml
id: windows-installed-software
name: Windows Installed Software Inventory
local_check: true
description: >
  Enumerates installed applications (both 64-bit and 32-bit-on-64-bit
  Uninstall registry hives) as Name|Version pairs, consumed server-side by
  the Application Risk category to flag known EOL/high-risk software.
supported_os: [windows]
tags:
  - application-risk
  - windows
  - inventory

steps:
  - name: "Installed Software Inventory"
    check_id: windows-installed-software
    technique_id: T1082
    framework: custom
    executor: local
    max_output_bytes: 20000
    command: >-
      $apps = @();
      $apps += Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue;
      $apps += Get-ItemProperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue;
      $apps | Where-Object { $_.DisplayName } | Sort-Object DisplayName -Unique |
        ForEach-Object { "$($_.DisplayName)|$($_.DisplayVersion)" }
    timeout_sec: 30
```

- [ ] **Step 2: Create `scenarios/linux-installed-software.yaml`**

```yaml
id: linux-installed-software
name: Linux Installed Software Inventory
local_check: true
description: >
  Enumerates installed Debian packages as Name|Version pairs, consumed
  server-side by the Application Risk category to flag known EOL/high-risk
  software.
supported_os: [linux]
tags:
  - application-risk
  - linux
  - inventory

steps:
  - name: "Installed Software Inventory"
    check_id: linux-installed-software
    technique_id: T1082
    framework: custom
    executor: local
    max_output_bytes: 20000
    command: "dpkg-query -W -f='${Package}|${Version}\\n' 2>/dev/null"
    timeout_sec: 30
```

- [ ] **Step 3: Verify both scenarios parse**

```bash
cd orchestrator && mkdir -p cmd/loadcheck_tmp && cat <<'EOF' > cmd/loadcheck_tmp/main.go
package main

import (
	"fmt"
	"os"

	"github.com/audspect/bas/internal/scenario"
	"gopkg.in/yaml.v3"
)

func check(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var s scenario.Scenario
	if err := yaml.Unmarshal(b, &s); err != nil {
		panic(fmt.Sprintf("%s: parse error: %v", path, err))
	}
	if s.ID == "" || len(s.Steps) == 0 {
		panic(fmt.Sprintf("%s: missing id or steps", path))
	}
	if s.Steps[0].MaxOutputBytes != 20000 {
		panic(fmt.Sprintf("%s: MaxOutputBytes = %d, want 20000", path, s.Steps[0].MaxOutputBytes))
	}
	fmt.Printf("%s: OK id=%s steps=%d maxOutputBytes=%d\n", path, s.ID, len(s.Steps), s.Steps[0].MaxOutputBytes)
}

func main() {
	check("../scenarios/windows-installed-software.yaml")
	check("../scenarios/linux-installed-software.yaml")
}
EOF
go run ./cmd/loadcheck_tmp
rm -rf cmd/loadcheck_tmp
```

Expected: both print `OK ... maxOutputBytes=20000`.

- [ ] **Step 4: Commit**

```bash
git add scenarios/windows-installed-software.yaml scenarios/linux-installed-software.yaml
git commit -m "feat(scenarios): add Windows/Linux installed-software inventory checks"
git push
```

---

### Task 5: EOL/high-risk software catalog

**Files:**
- Create: `orchestrator/internal/endpointrisk/eol_catalog.yaml`
- Create: `orchestrator/internal/endpointrisk/eol.go`
- Test: `orchestrator/internal/endpointrisk/eol_test.go`

**Interfaces:**
- Produces: `endpointrisk.Catalog`, `endpointrisk.NewCatalog() (*Catalog, error)`, `(*Catalog).Lookup(appName, appVersion string) (entry eolEntry-shaped fields exposed via accessor, ok bool)` — consumed by Task 6's `applicationRiskInput`. (Exact returned type is `endpointrisk.CatalogEntry`, exported — see Step 3.)

- [ ] **Step 1: Write `eol_catalog.yaml`**

```yaml
software:
  - id: flash
    vendor: Adobe
    product: Flash Player
    match: ["Adobe Flash Player"]
    risk: critical
    reason: End of life -- no longer receives security updates.
    recommendation: Remove Adobe Flash Player immediately.
    reference: "https://www.adobe.com/products/flashplayer/end-of-life.html"

  - id: ie
    vendor: Microsoft
    product: Internet Explorer
    match: ["Internet Explorer"]
    risk: critical
    reason: Retired -- no longer receives security updates.
    recommendation: Remove Internet Explorer; use Microsoft Edge instead.

  - id: java6
    vendor: Oracle
    product: Java 6
    match: ["Java 6", "JRE 6", "JDK 6", "Java(TM) 6"]
    risk: critical
    reason: End of public support.
    recommendation: Upgrade to a supported Java LTS release (17 or newer).

  - id: java7
    vendor: Oracle
    product: Java 7
    match: ["Java 7", "JRE 7", "JDK 7", "Java(TM) 7"]
    risk: high
    reason: End of public support.
    recommendation: Upgrade to a supported Java LTS release (17 or newer).

  - id: java8
    vendor: Oracle
    product: Java 8
    match: ["Java 8", "JRE 8", "JDK 8", "Java(TM) 8"]
    version_max: "8"
    risk: high
    reason: End of public support for Java 8.
    recommendation: Upgrade to a supported Java LTS release (17 or newer).

  - id: python2
    vendor: Python Software Foundation
    product: Python 2
    match: ["Python 2"]
    version_max: "2"
    risk: high
    reason: End of life -- Python 2 no longer receives security updates.
    recommendation: Upgrade to Python 3.

  - id: office2007
    vendor: Microsoft
    product: Office 2007
    match: ["Microsoft Office 2007", "Office 2007"]
    risk: high
    reason: End of extended support.
    recommendation: Upgrade to a supported Microsoft Office / Microsoft 365 release.

  - id: office2010
    vendor: Microsoft
    product: Office 2010
    match: ["Microsoft Office 2010", "Office 2010"]
    risk: high
    reason: End of extended support.
    recommendation: Upgrade to a supported Microsoft Office / Microsoft 365 release.

  - id: office2013
    vendor: Microsoft
    product: Office 2013
    match: ["Microsoft Office 2013", "Office 2013"]
    risk: medium
    reason: End of extended support.
    recommendation: Upgrade to a supported Microsoft Office / Microsoft 365 release.

  - id: silverlight
    vendor: Microsoft
    product: Silverlight
    match: ["Microsoft Silverlight", "Silverlight"]
    risk: critical
    reason: End of life -- no longer receives security updates.
    recommendation: Remove Microsoft Silverlight.

  - id: dotnet35
    vendor: Microsoft
    product: .NET Framework 3.5
    match: [".NET Framework 3.5", "Microsoft .NET Framework 3.5"]
    risk: medium
    reason: Legacy runtime -- superseded by current .NET releases.
    recommendation: Migrate applications to a currently supported .NET runtime.

  - id: dotnet40
    vendor: Microsoft
    product: .NET Framework 4.0
    match: [".NET Framework 4.0", "Microsoft .NET Framework 4.0"]
    risk: medium
    reason: Legacy runtime -- superseded by current .NET releases.
    recommendation: Migrate applications to a currently supported .NET runtime.

  - id: quicktime
    vendor: Apple
    product: QuickTime
    match: ["QuickTime", "Apple QuickTime"]
    risk: critical
    reason: End of life on Windows -- Apple no longer issues security patches.
    recommendation: Remove Apple QuickTime for Windows.

  - id: shockwave
    vendor: Adobe
    product: Shockwave Player
    match: ["Adobe Shockwave Player", "Shockwave Player"]
    risk: critical
    reason: End of life -- no longer receives security updates.
    recommendation: Remove Adobe Shockwave Player.

  - id: sqlserver2008
    vendor: Microsoft
    product: SQL Server 2008
    match: ["Microsoft SQL Server 2008", "SQL Server 2008"]
    risk: high
    reason: End of extended support.
    recommendation: Upgrade to a currently supported SQL Server release.

  - id: sqlserver2012
    vendor: Microsoft
    product: SQL Server 2012
    match: ["Microsoft SQL Server 2012", "SQL Server 2012"]
    risk: medium
    reason: End of extended support.
    recommendation: Upgrade to a currently supported SQL Server release.

  - id: realplayer
    vendor: RealNetworks
    product: RealPlayer
    match: ["RealPlayer"]
    risk: medium
    reason: Historically vulnerable, infrequently updated media player.
    recommendation: Remove RealPlayer or replace with a maintained alternative.

  - id: acrobat9
    vendor: Adobe
    product: Acrobat/Reader 9
    match: ["Adobe Acrobat 9", "Adobe Reader 9"]
    risk: high
    reason: End of life -- no longer receives security updates.
    recommendation: Upgrade to a currently supported Adobe Acrobat/Reader release.
```

- [ ] **Step 2: Write the failing test**

```go
// orchestrator/internal/endpointrisk/eol_test.go
package endpointrisk

import "testing"

func TestNewCatalog_LoadsEmbeddedFile(t *testing.T) {
	c, err := NewCatalog()
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	entry, ok := c.Lookup("Adobe Flash Player 32.0.0.465", "32.0.0.465")
	if !ok {
		t.Fatal("expected Adobe Flash Player to match")
	}
	if entry.Risk != "critical" {
		t.Errorf("Risk = %q, want critical", entry.Risk)
	}
}

func TestCatalogLookup_CaseInsensitiveAndNormalized(t *testing.T) {
	c, err := NewCatalog()
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	_, ok := c.Lookup("java(tm) 8 update 451", "8.0.451")
	if !ok {
		t.Error("expected normalized lowercase match with (TM) stripped")
	}
}

func TestCatalogLookup_VersionMaxGating(t *testing.T) {
	c, err := NewCatalog()
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	// Java 8 has version_max "8" -- a hypothetical "Java 8" name with a
	// version that doesn't parse should still match (never blocks on
	// ambiguous versions).
	_, ok := c.Lookup("Java 8 Update 451", "8u451")
	if !ok {
		t.Error("expected match when version doesn't parse as a leading integer (never blocks on ambiguity)")
	}
}

func TestCatalogLookup_NoMatch(t *testing.T) {
	c, err := NewCatalog()
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	_, ok := c.Lookup("Google Chrome", "120.0.0.0")
	if ok {
		t.Error("expected no match for software not in the catalog")
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/endpointrisk/... -run TestNewCatalog -v`
Expected: FAIL — `NewCatalog` undefined (compile error).

- [ ] **Step 4: Write `eol.go`**

```go
package endpointrisk

import (
	"embed"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed eol_catalog.yaml
var eolFS embed.FS

// CatalogEntry is one EOL/high-risk software record. Exported so callers
// (internal/api's applicationRiskInput) can read its fields directly.
type CatalogEntry struct {
	ID             string   `yaml:"id"`
	Vendor         string   `yaml:"vendor"`
	Product        string   `yaml:"product"`
	Match          []string `yaml:"match"`
	VersionMax     string   `yaml:"version_max,omitempty"`
	Risk           string   `yaml:"risk"` // critical | high | medium | low
	Reason         string   `yaml:"reason"`
	Recommendation string   `yaml:"recommendation"`
	Reference      string   `yaml:"reference,omitempty"`
}

type eolCatalogFile struct {
	Software []CatalogEntry `yaml:"software"`
}

// Catalog is a small, hand-curated, embedded list of well-known EOL/
// high-risk software (Flash, Java 6/7/8, Python 2, ...), matched against
// installed-software inventory by normalized-name substring. Deliberately
// not exhaustive -- see design spec §2d.
type Catalog struct {
	entries []CatalogEntry
}

// NewCatalog loads and validates the embedded eol_catalog.yaml.
func NewCatalog() (*Catalog, error) {
	data, err := eolFS.ReadFile("eol_catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("endpointrisk: read eol_catalog.yaml: %w", err)
	}
	var cf eolCatalogFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("endpointrisk: parse eol_catalog.yaml: %w", err)
	}
	seen := map[string]bool{}
	for _, e := range cf.Software {
		if e.ID == "" || len(e.Match) == 0 || e.Risk == "" {
			return nil, fmt.Errorf("endpointrisk: eol entry missing id/match/risk: %+v", e)
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("endpointrisk: duplicate eol catalog id %q", e.ID)
		}
		seen[e.ID] = true
	}
	if len(cf.Software) == 0 {
		return nil, fmt.Errorf("endpointrisk: no eol catalog entries loaded")
	}
	return &Catalog{entries: cf.Software}, nil
}

// normalizeAppName lowercases and strips common marketing/vendor noise so
// "Java(TM) 8 Update 451" and "JRE 8" normalize close enough to match the
// same catalog entry's patterns.
func normalizeAppName(name string) string {
	n := strings.ToLower(name)
	for _, noise := range []string{"(tm)", "(r)", "®", "™"} {
		n = strings.ReplaceAll(n, noise, "")
	}
	return strings.Join(strings.Fields(n), " ")
}

// Lookup finds the first catalog entry whose match pattern is a
// case-insensitive substring of appName. When the entry declares
// version_max and appVersion parses as a leading integer, versions above
// version_max don't match (already-upgraded software isn't flagged) -- an
// unparseable version never blocks a match, it only sometimes prevents a
// false positive.
func (c *Catalog) Lookup(appName, appVersion string) (CatalogEntry, bool) {
	normalized := normalizeAppName(appName)
	for _, e := range c.entries {
		for _, m := range e.Match {
			if !strings.Contains(normalized, normalizeAppName(m)) {
				continue
			}
			if e.VersionMax != "" && !versionAtOrBelow(appVersion, e.VersionMax) {
				continue
			}
			return e, true
		}
	}
	return CatalogEntry{}, false
}

// versionAtOrBelow does simple leading-integer comparison only -- "8.0.451"
// vs version_max "8" compares 8 <= 8 -> true.
func versionAtOrBelow(installed, max string) bool {
	iv, iok := leadingInt(installed)
	mv, mok := leadingInt(max)
	if !iok || !mok {
		return true
	}
	return iv <= mv
}

func leadingInt(s string) (int, bool) {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	v, err := strconv.Atoi(s[:end])
	return v, err == nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/endpointrisk/... -v`
Expected: PASS -- all 4 new tests plus every pre-existing `internal/endpointrisk` test.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/endpointrisk/eol_catalog.yaml orchestrator/internal/endpointrisk/eol.go orchestrator/internal/endpointrisk/eol_test.go
git commit -m "feat(endpointrisk): add embedded EOL/high-risk software catalog"
git push
```

---

### Task 6: Application Risk types, parsing, aggregation, and wiring

**Files:**
- Modify: `orchestrator/internal/endpointrisk/types.go` (add `InstalledApp`, `ApplicationRiskInput`)
- Modify: `orchestrator/internal/api/endpointrisk_aggregations.go` (add `parseInstalledSoftware`, `applicationRiskInput`)
- Modify: `orchestrator/internal/api/endpointrisk_aggregations_test.go`
- Modify: `orchestrator/internal/api/handlers.go` (add `eolCatalog` field + `WithEOLCatalog`)
- Modify: `orchestrator/cmd/server/main.go` (construct and wire the catalog)

**Interfaces:**
- Consumes: `endpointrisk.Catalog.Lookup` (Task 5), `h.aggregateAgentResults`/`filterByAsOf` (existing).
- Produces: `endpointrisk.InstalledApp{Name, Version}`, `endpointrisk.ApplicationRiskInput{Score, AppsScanned, Findings, Collected}`, `(h *Handler) applicationRiskInput(ctx, agentID, asOf, allResults) endpointrisk.ApplicationRiskInput` — consumed by Task 7's `HealthInputs` and Task 8's handlers.

- [ ] **Step 1: Add the two new types to `types.go`**

Append to `orchestrator/internal/endpointrisk/types.go`:

```go

// InstalledApp is one parsed row from an installed-software inventory
// check's raw "Name|Version" output.
type InstalledApp struct {
	Name    string
	Version string
}

// ApplicationRiskInput is deliberately a distinct type from
// PostureCheckInput -- Application Risk is an open-ended scan (zero or
// more risky apps found), not a fixed pass/fail checklist, so its score is
// a severity-weighted deduction, not a pass rate.
type ApplicationRiskInput struct {
	Score       int       // 0-100, 100 minus severity-weighted deductions, floored at 0
	AppsScanned int
	Findings    []Finding // one per unique matched catalog id
	Collected   bool
}
```

- [ ] **Step 2: Write the failing tests for parsing and aggregation**

Add to `orchestrator/internal/api/endpointrisk_aggregations_test.go`:

```go
func TestParseInstalledSoftware_ParsesValidLinesSkipsMalformed(t *testing.T) {
	raw := "Adobe Flash Player|32.0.0.465\nmalformed line\nGoogle Chrome|120.0.0.0\n|no name\n"
	got := parseInstalledSoftware(raw)
	if len(got) != 2 {
		t.Fatalf("got %d apps, want 2 (malformed lines skipped): %+v", len(got), got)
	}
	if got[0].Name != "Adobe Flash Player" || got[0].Version != "32.0.0.465" {
		t.Errorf("apps[0] = %+v, want Adobe Flash Player/32.0.0.465", got[0])
	}
}

func TestParseInstalledSoftware_EmptyInput(t *testing.T) {
	if got := parseInstalledSoftware(""); len(got) != 0 {
		t.Errorf("got %d apps, want 0", len(got))
	}
}

func TestApplicationRiskInput_MatchesCatalogAndScores(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-ar-a1', 'ER-AR-HOST')`)
		now := time.Now().UTC()
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-ar-run', 'windows-installed-software', 'Inventory Run', 'er-ar-a1', 'completed', $1::jsonb, NOW())`,
			`[{"checkId":"windows-installed-software","result":"pass","rawOutput":"Adobe Flash Player|32.0.0.465\nGoogle Chrome|120.0.0.0\nJava 8 Update 451|8.0.451","executedAt":"`+now.Format(time.RFC3339)+`"}]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, err := endpointrisk.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h.eolCatalog = cat

		all := h.aggregateAgentResults(context.Background(), "er-ar-a1")
		got := h.applicationRiskInput(context.Background(), "er-ar-a1", now.Add(time.Hour), all)
		if !got.Collected {
			t.Fatal("expected Collected=true")
		}
		if got.AppsScanned != 3 {
			t.Errorf("AppsScanned = %d, want 3", got.AppsScanned)
		}
		// Flash (critical, -25) + Java 8 (high, -15) = 2 findings, Chrome not in catalog.
		if len(got.Findings) != 2 {
			t.Errorf("got %d findings, want 2 (Flash + Java 8, Chrome not in catalog): %+v", len(got.Findings), got.Findings)
		}
		if got.Score != 60 {
			t.Errorf("Score = %d, want 60 (100 - 25 - 15)", got.Score)
		}
	})
}

func TestApplicationRiskInput_NoInventoryResult_NotCollected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, err := endpointrisk.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h.eolCatalog = cat

		all := h.aggregateAgentResults(context.Background(), "no-such-agent-ar")
		got := h.applicationRiskInput(context.Background(), "no-such-agent-ar", time.Now().UTC(), all)
		if got.Collected {
			t.Error("expected Collected=false for an agent with no inventory result")
		}
	})
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestParseInstalledSoftware|TestApplicationRiskInput" -v`
Expected: FAIL — `parseInstalledSoftware`/`h.applicationRiskInput`/`h.eolCatalog` undefined (compile error).

- [ ] **Step 4: Add `parseInstalledSoftware` and `applicationRiskInput` to `endpointrisk_aggregations.go`**

Add near the end of `orchestrator/internal/api/endpointrisk_aggregations.go`:

```go
// parseInstalledSoftware splits an installed-software check's raw
// "Name|Version" output into structured rows. Malformed lines are skipped
// rather than erroring -- evidence from a real machine is messy, and a
// handful of bad lines shouldn't lose the rest.
func parseInstalledSoftware(raw string) []endpointrisk.InstalledApp {
	var out []endpointrisk.InstalledApp
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		version := strings.TrimSpace(parts[1])
		if name == "" {
			continue
		}
		out = append(out, endpointrisk.InstalledApp{Name: name, Version: version})
	}
	return out
}

// eolSeverityWeight is the shared deduction table for Application Risk
// scoring -- one weight per risk tier, not per catalog entry (see design
// spec §2e).
var eolSeverityWeight = map[string]int{
	"critical": 25,
	"high":     15,
	"medium":   5,
	"low":      2,
}

// applicationRiskInput finds the agent's most recent installed-software
// inventory result (asOf-filtered, whichever OS-specific check_id is
// present), parses it, matches every installed app against the EOL
// catalog, deduplicates by catalog id (a product with multiple matching
// components -- e.g. three Java 8 pieces -- deducts once, not three
// times), and computes a severity-weighted score.
func (h *Handler) applicationRiskInput(ctx context.Context, agentID string, asOf time.Time, allResults []models.SimulationResult) endpointrisk.ApplicationRiskInput {
	if h.eolCatalog == nil {
		return endpointrisk.ApplicationRiskInput{}
	}
	results := filterByAsOf(allResults, asOf)

	var latest *models.SimulationResult
	for i := range results {
		r := &results[i]
		if r.CheckID != "windows-installed-software" && r.CheckID != "linux-installed-software" {
			continue
		}
		if latest == nil || r.ExecutedAt.After(latest.ExecutedAt) {
			latest = r
		}
	}
	if latest == nil {
		return endpointrisk.ApplicationRiskInput{}
	}

	apps := parseInstalledSoftware(latest.RawOutput)
	seen := map[string]bool{}
	var findings []endpointrisk.Finding
	score := 100
	for _, app := range apps {
		entry, ok := h.eolCatalog.Lookup(app.Name, app.Version)
		if !ok || seen[entry.ID] {
			continue
		}
		seen[entry.ID] = true
		observedAt := latest.ExecutedAt
		findings = append(findings, endpointrisk.Finding{
			ID: entry.ID, Title: entry.Product, Description: entry.Reason,
			Severity: titleCase(entry.Risk), Risk: entry.Reason,
			Remediation: entry.Recommendation, Reference: entry.Reference,
			Observed: strings.TrimSpace(app.Name + " " + app.Version), LastObserved: &observedAt,
		})
		score -= eolSeverityWeight[entry.Risk]
	}
	if score < 0 {
		score = 0
	}
	return endpointrisk.ApplicationRiskInput{
		Score: score, AppsScanned: len(apps), Findings: findings, Collected: true,
	}
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
```

Add `"strings"` to this file's import block (it currently imports only `"context"`, `"time"`, `endpointrisk`, `models`).

- [ ] **Step 5: Add the `eolCatalog` field and `WithEOLCatalog` method**

In `orchestrator/internal/api/handlers.go`, add the field next to `endpointRiskTaxonomy`:

```go
	endpointRiskTaxonomy  *endpointrisk.Taxonomy // nil when not loaded
	eolCatalog            *endpointrisk.Catalog  // nil when not loaded
```

And a `With` method next to `WithEndpointRiskTaxonomy`:

```go
// WithEOLCatalog attaches the Application Risk EOL/high-risk software catalog.
func (h *Handler) WithEOLCatalog(c *endpointrisk.Catalog) *Handler {
	h.eolCatalog = c
	return h
}
```

- [ ] **Step 6: Wire construction in `main.go`**

In `orchestrator/cmd/server/main.go`, right after the Endpoint Risk Taxonomy block:

```go
	// ── Application Risk EOL/High-Risk Software Catalog ────────────────────
	eolCatalog, eolErr := endpointrisk.NewCatalog()
	if eolErr != nil {
		log.Printf("[!] EOL software catalog: %v — Application Risk category unavailable", eolErr)
	} else {
		log.Printf("[+] EOL software catalog loaded")
	}
```

And add `.WithEOLCatalog(eolCatalog).` to the handler chain right after `.WithEndpointRiskTaxonomy(endpointRiskTaxonomy).`.

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestParseInstalledSoftware|TestApplicationRiskInput" -v`
Expected: PASS for all 4 new tests.

- [ ] **Step 8: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/endpointrisk/types.go orchestrator/internal/api/endpointrisk_aggregations.go orchestrator/internal/api/endpointrisk_aggregations_test.go orchestrator/internal/api/handlers.go orchestrator/cmd/server/main.go
git commit -m "feat(api): add applicationRiskInput aggregation with severity-weighted scoring"
git push
```

---

### Task 7: Wire both categories into `ComputeHealth`

**Files:**
- Modify: `orchestrator/internal/endpointrisk/types.go` (extend `HealthInputs`)
- Modify: `orchestrator/internal/endpointrisk/health.go`
- Modify: `orchestrator/internal/endpointrisk/health_test.go`

**Interfaces:**
- Consumes: `endpointrisk.PostureCheckInput` (Sub-project 2), `endpointrisk.ApplicationRiskInput` (Task 6).
- Produces: `HealthInputs{..., PatchManagement PostureCheckInput, ApplicationRisk ApplicationRiskInput}` — every existing `HealthInputs{}` struct literal in `internal/api` (Sub-project 2's handlers) keeps compiling unchanged, since these are named-field additions with zero-value defaults; Task 8 is what actually populates them.

- [ ] **Step 1: Extend `HealthInputs` in `types.go`**

```go
// HealthInputs bundles the six evidence-row-backed category inputs so
// ComputeHealth takes two params (now, past) instead of many positional
// ones.
type HealthInputs struct {
	Compliance      ComplianceInput
	BAS             BASReadinessInput
	SecurityConfig  PostureCheckInput
	Identity        PostureCheckInput
	PatchManagement PostureCheckInput
	ApplicationRisk ApplicationRiskInput
}
```

- [ ] **Step 2: Rewrite `health.go`**

Replace the full contents of `orchestrator/internal/endpointrisk/health.go`:

```go
package endpointrisk

import (
	"github.com/audspect/bas/internal/exposure"
)

// Category IDs -- every one of the 9 categories the design spec's category
// table lists is now real-or-uncollected; there are no more permanent
// placeholders (Patch Management and Application Risk were the last two).
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

// ComputeHealth is pure -- no I/O -- so every combination is unit-testable
// without a database. past is the same six inputs recomputed with evidence
// filtered to 7 days ago by the caller; exposure-derived categories have no
// past counterpart, per spec §6, so Trend.Direction never reflects them.
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

	patchCat := CategoryScore{ID: CategoryPatchManagement, Name: "Patch Management", Collected: now.PatchManagement.Collected}
	if now.PatchManagement.Collected {
		patchCat.Score = now.PatchManagement.Score
		patchCat.Deficit = 100 - patchCat.Score
		patchCat.Findings = now.PatchManagement.Findings
	}

	appRiskCat := CategoryScore{ID: CategoryApplicationRisk, Name: "Application Risk", Collected: now.ApplicationRisk.Collected}
	if now.ApplicationRisk.Collected {
		appRiskCat.Score = now.ApplicationRisk.Score
		appRiskCat.Deficit = 100 - appRiskCat.Score
		appRiskCat.Findings = now.ApplicationRisk.Findings
	}

	categories := []CategoryScore{exposureAttackPath, detection, vulns, compCat, basCat, secCat, idCat, patchCat, appRiskCat}

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
// Configuration + Identity + Patch Management + Application Risk (all six
// are asOf-filterable evidence rows); Exposure/Attack-Path/Detection
// Health have no past counterpart to compare, per spec §6.
// NewFindings/ResolvedFindings are computed from Security Configuration +
// Identity + Patch Management + Application Risk's Findings (ID-set diff)
// -- all four are stably keyed (check_id or catalog id). Compliance/
// BAS-Readiness findings aren't stably keyed the same way, so they stay
// covered by Direction only.
func computeTrend(now, past HealthInputs) TrendDetail {
	anyNow := now.Compliance.Collected || now.BAS.Collected || now.SecurityConfig.Collected ||
		now.Identity.Collected || now.PatchManagement.Collected || now.ApplicationRisk.Collected
	anyPast := past.Compliance.Collected || past.BAS.Collected || past.SecurityConfig.Collected ||
		past.Identity.Collected || past.PatchManagement.Collected || past.ApplicationRisk.Collected
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

	nowFindings := pooledStableFindings(now)
	pastFindings := pooledStableFindings(past)

	return TrendDetail{
		Direction:        direction,
		NewFindings:      diffFindings(pastFindings, nowFindings),
		ResolvedFindings: diffFindings(nowFindings, pastFindings),
	}
}

// pooledStableFindings collects Findings from every category whose
// Finding.ID is stable across a 7-day window (check_id or catalog id).
func pooledStableFindings(in HealthInputs) []Finding {
	var out []Finding
	out = append(out, in.SecurityConfig.Findings...)
	out = append(out, in.Identity.Findings...)
	out = append(out, in.PatchManagement.Findings...)
	out = append(out, in.ApplicationRisk.Findings...)
	return out
}

// diffFindings returns the findings in compare whose ID doesn't appear in
// baseline. Findings without an ID (non-stably-keyed categories) never
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
	if in.PatchManagement.Collected {
		sum += float64(in.PatchManagement.Score)
		n++
	}
	if in.ApplicationRisk.Collected {
		sum += float64(in.ApplicationRisk.Score)
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
	want := map[string]bool{
		CategoryCompliance: false, CategoryBASReadiness: false, CategorySecurityConfig: false,
		CategoryIdentity: false, CategoryPatchManagement: false, CategoryApplicationRisk: false,
	}
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

func TestComputeHealth_AllNineCategoriesAlwaysPresent(t *testing.T) {
	got := ComputeHealth("agent-1", exposure.AssetExposureProfile{}, HealthInputs{}, HealthInputs{})
	if len(got.Categories) != 9 {
		t.Errorf("got %d categories, want 9 (every category is now real-or-uncollected)", len(got.Categories))
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

func TestComputeHealth_PatchManagementAndApplicationRisk_CollectedWhenPresent(t *testing.T) {
	now := HealthInputs{
		PatchManagement: PostureCheckInput{Collected: true, Score: 100, Passed: 1, Total: 1},
		ApplicationRisk: ApplicationRiskInput{Collected: true, Score: 60, AppsScanned: 3, Findings: []Finding{{ID: "flash", Title: "Flash Player"}, {ID: "java8", Title: "Java 8"}}},
	}
	got := ComputeHealth("agent-1", exposure.AssetExposureProfile{}, now, HealthInputs{})
	var patchCat, appRiskCat *CategoryScore
	for i := range got.Categories {
		switch got.Categories[i].ID {
		case CategoryPatchManagement:
			patchCat = &got.Categories[i]
		case CategoryApplicationRisk:
			appRiskCat = &got.Categories[i]
		}
	}
	if patchCat == nil || !patchCat.Collected || patchCat.Score != 100 || patchCat.Deficit != 0 {
		t.Errorf("Patch Management category = %+v, want Collected=true Score=100 Deficit=0", patchCat)
	}
	if appRiskCat == nil || !appRiskCat.Collected || appRiskCat.Score != 60 || appRiskCat.Deficit != 40 || len(appRiskCat.Findings) != 2 {
		t.Errorf("Application Risk category = %+v, want Collected=true Score=60 Deficit=40 2 findings", appRiskCat)
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

func TestComputeTrend_NewAndResolvedFindings_AcrossFourStableCategories(t *testing.T) {
	now := HealthInputs{
		SecurityConfig:  PostureCheckInput{Collected: true, Score: 80, Findings: []Finding{{ID: "windows-bitlocker-enabled", Title: "BitLocker disabled"}}},
		PatchManagement: PostureCheckInput{Collected: true, Score: 100, Findings: []Finding{{ID: "windows-last-patch-age", Title: "Patch overdue"}}},
	}
	past := HealthInputs{
		SecurityConfig:  PostureCheckInput{Collected: true, Score: 80, Findings: []Finding{{ID: "windows-firewall-enabled", Title: "Firewall disabled"}}},
		ApplicationRisk: ApplicationRiskInput{Collected: true, Score: 75, Findings: []Finding{{ID: "flash", Title: "Flash Player"}}},
	}
	got := computeTrend(now, past)
	newIDs := map[string]bool{}
	for _, f := range got.NewFindings {
		newIDs[f.ID] = true
	}
	if !newIDs["windows-bitlocker-enabled"] || !newIDs["windows-last-patch-age"] || len(got.NewFindings) != 2 {
		t.Errorf("NewFindings = %+v, want exactly windows-bitlocker-enabled + windows-last-patch-age", got.NewFindings)
	}
	resolvedIDs := map[string]bool{}
	for _, f := range got.ResolvedFindings {
		resolvedIDs[f.ID] = true
	}
	if !resolvedIDs["windows-firewall-enabled"] || !resolvedIDs["flash"] || len(got.ResolvedFindings) != 2 {
		t.Errorf("ResolvedFindings = %+v, want exactly windows-firewall-enabled + flash", got.ResolvedFindings)
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
Expected: PASS -- every test in the package.

- [ ] **Step 5: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly -- `HealthInputs`'s two new fields are named, so every existing `HealthInputs{...}` literal in `internal/api` (Sub-project 2's handlers) still compiles; those two categories simply read as `Collected: false` until Task 8 wires real values in.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/endpointrisk/types.go orchestrator/internal/endpointrisk/health.go orchestrator/internal/endpointrisk/health_test.go
git commit -m "feat(endpointrisk): wire Patch Management and Application Risk into ComputeHealth"
git push
```

---

### Task 8: Wire both categories into the handlers

**Files:**
- Modify: `orchestrator/internal/api/endpointrisk_handlers.go`
- Modify: `orchestrator/internal/api/endpointrisk_handlers_test.go`

**Interfaces:**
- Consumes: `h.patchManagementInput` (Task 3), `h.applicationRiskInput` (Task 6).

- [ ] **Step 1: Update `GetAgentRisk`**

In `orchestrator/internal/api/endpointrisk_handlers.go`, extend both `HealthInputs` literals:

```go
	nowInputs := endpointrisk.HealthInputs{
		Compliance:      h.complianceInput(r.Context(), agentID, now, allResults),
		BAS:             h.basReadinessInput(now, allResults),
		SecurityConfig:  h.securityConfigInput(r.Context(), agentID, now, allResults),
		Identity:        h.identityInput(r.Context(), agentID, now, allResults),
		PatchManagement: h.patchManagementInput(r.Context(), agentID, now, allResults),
		ApplicationRisk: h.applicationRiskInput(r.Context(), agentID, now, allResults),
	}
	pastInputs := endpointrisk.HealthInputs{
		Compliance:      h.complianceInput(r.Context(), agentID, weekAgo, allResults),
		BAS:             h.basReadinessInput(weekAgo, allResults),
		SecurityConfig:  h.securityConfigInput(r.Context(), agentID, weekAgo, allResults),
		Identity:        h.identityInput(r.Context(), agentID, weekAgo, allResults),
		PatchManagement: h.patchManagementInput(r.Context(), agentID, weekAgo, allResults),
		ApplicationRisk: h.applicationRiskInput(r.Context(), agentID, weekAgo, allResults),
	}
```

- [ ] **Step 2: Update `GetAgentRiskSummary`**

Apply the identical extension to both `HealthInputs` literals inside the `for _, s := range ag.Summaries()` loop (same fields, `s.Asset.AgentID` in place of `agentID`).

- [ ] **Step 3: Write the failing integration test**

Add to `orchestrator/internal/api/endpointrisk_handlers_test.go`:

```go
func TestGetAgentRisk_PatchAndApplicationRisk_CollectedFromRealChecks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-h3-a1', 'ER-H3-HOST')`)
		now := time.Now().UTC()
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-h3-run', 'windows-patch-posture', 'H3 Run', 'er-h3-a1', 'completed', $1::jsonb, NOW())`,
			`[
				{"checkId":"windows-last-patch-age","result":"pass","executedAt":"`+now.Format(time.RFC3339)+`"},
				{"checkId":"windows-installed-software","result":"pass","rawOutput":"Adobe Flash Player|32.0.0.465","executedAt":"`+now.Format(time.RFC3339)+`"}
			]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		tx, err := endpointrisk.NewTaxonomy()
		if err != nil {
			t.Fatalf("NewTaxonomy: %v", err)
		}
		h.endpointRiskTaxonomy = tx
		cat, err := endpointrisk.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h.eolCatalog = cat

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "er-h3-a1")
		w := httptest.NewRecorder()
		h.GetAgentRisk(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var got endpointrisk.EndpointHealth
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		var patchCat, appRiskCat *endpointrisk.CategoryScore
		for i := range got.Categories {
			switch got.Categories[i].ID {
			case endpointrisk.CategoryPatchManagement:
				patchCat = &got.Categories[i]
			case endpointrisk.CategoryApplicationRisk:
				appRiskCat = &got.Categories[i]
			}
		}
		if patchCat == nil || !patchCat.Collected {
			t.Errorf("Patch Management = %+v, want Collected=true", patchCat)
		}
		if appRiskCat == nil || !appRiskCat.Collected || len(appRiskCat.Findings) != 1 {
			t.Errorf("Application Risk = %+v, want Collected=true with 1 finding (Flash)", appRiskCat)
		}
	})
}
```

Note: `TestGetAgentRisk_KnownAgent_ReturnsAllCategories`'s existing `!= 9` assertion needs no change -- the category count was already 9 and stays 9 (composition changes, total doesn't).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestGetAgentRisk" -v`
Expected: PASS for all `GetAgentRisk*` tests including the new one.

- [ ] **Step 5: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/endpointrisk_handlers.go orchestrator/internal/api/endpointrisk_handlers_test.go
git commit -m "feat(api): wire Patch Management and Application Risk into GetAgentRisk handlers"
git push
```

---

### Task 9: Full verification pass

**Files:** none (verification only).

- [ ] **Step 1: Confirm Docker is available for container-backed tests**

```bash
docker info >/dev/null 2>&1 && echo "docker running" || echo "docker not running"
```

- [ ] **Step 2: Full build**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 3: Full test suite for every touched package**

Run: `cd orchestrator && go test ./internal/api/... ./internal/endpointrisk/... ./internal/scenario/... -v`
Expected: PASS, zero failures.

- [ ] **Step 4: Confirm no stray scenario signature files reference the deleted scenario**

```bash
ls scenarios/os-patch-posture.yaml* 2>/dev/null || echo "clean -- no os-patch-posture.yaml artifacts remain"
```

- [ ] **Step 5: Frontend sanity check**

No new frontend code is expected -- `_riskCategoryCard`/`renderAgtRisk` (Sub-project 1/2) already render any `CategoryScore` generically, and Patch Management/Application Risk are now ordinary real categories. Confirm the inline script still parses:

```bash
cd orchestrator/wwwroot
START=$(grep -n '<script>' index.html | tail -1 | cut -d: -f1)
END=$(grep -n '</script>' index.html | tail -1 | cut -d: -f1)
sed -n "${START},$((END-1))p" index.html | tail -n +2 > /tmp/extracted.js
node --check /tmp/extracted.js && echo "SYNTAX OK"
rm /tmp/extracted.js
```

- [ ] **Step 6: No commit needed** (verification-only task).

---

## Self-Review Notes

- **Spec coverage**: §1 (Patch Management split) → Tasks 2-3. §2a (schema fix) → Task 1. §2b (inventory scenarios) → Task 4. §2c (parsing) → Task 6. §2d (EOL catalog) → Task 5. §2e (scoring) → Task 6. §2f (aggregation) → Task 6. §3 (`ComputeHealth`/trend wiring) → Tasks 7-8. §4 (UI) → Task 9 (verification only, no new code needed, as the spec itself states). §5 (testing) → every task's own test step plus Task 9's full-suite run.
- **Type consistency checked**: `CatalogEntry`, `ApplicationRiskInput`, `InstalledApp`, `HealthInputs` field names match verbatim between their defining task and every consuming task.
- **No temporary build breaks this time**: unlike Sub-project 2, every task here keeps `go build ./...` green throughout, because `HealthInputs`'s new fields are additive named fields with safe zero-value defaults -- Task 7 wires the categories into `ComputeHealth` (reading as `Collected: false` until real data arrives), and Task 8 supplies that real data, with no window where the package fails to compile.
