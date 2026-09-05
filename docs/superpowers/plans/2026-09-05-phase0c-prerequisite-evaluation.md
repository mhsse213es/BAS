# Phase 0C: Environmental Prerequisite Evaluation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `domain_joined` as the first environmental prerequisite fact, flowing end-to-end: the agent collects it, the orchestrator stores it, and both execution engines (ART/Caldera and `internal/exercise`) gate on it through their existing skip mechanisms.

**Architecture:** No new subsystem. Extends two mechanisms already in production: ART/Caldera's pre-dispatch `synthesize*SkipResult` filters in `dispatchRun`, and `internal/exercise`'s `evalCondition` predicate grammar. Zero changes to `execution_attempts`'s schema or granularity.

**Tech Stack:** Go (orchestrator + agent), PostgreSQL, `golang.org/x/sys/windows` for the Win32 domain-join query.

**Spec:** [docs/superpowers/specs/2026-09-05-phase0c-prerequisite-evaluation-design.md](../specs/2026-09-05-phase0c-prerequisite-evaluation-design.md) — read it alongside this plan; it explains WHY each piece is shaped this way. This plan corrects two implementation details the spec's illustrative code got wrong (see Task 1's and Task 4's notes) after verifying against the real current source.

## Global Constraints

- `DomainJoined` is `*bool` everywhere (agent identity, protocol, orchestrator model, `agents` column) — `nil` means "not evaluated on this platform," never coerce to `false`. A curated technique's requirement is checked ONLY when the value is non-nil; nil always dispatches normally.
- No generic facts bag, no fact-comparison DSL, no fact beyond `domain_joined` in this phase.
- No changes to `execution_attempts`'s schema, columns, or the two existing ART/Caldera skip families' (`SkipReasonPolicyPrivilege`, `SkipReasonPlatformUnavailable`) behavior.
- POSIX agents report `nil` for `DomainJoined` in this phase — no real POSIX collection.

---

### Task 1: Agent — Windows domain-join collection and heartbeat wiring

**Files:**
- Modify: `agent/sysinfo_windows.go` — add `getDomainJoined() *bool`
- Modify: `agent/sysinfo_linux.go` — add `getDomainJoined() *bool` stub (returns `nil`)
- Modify: `agent/sysinfo_darwin.go` — add `getDomainJoined() *bool` stub (returns `nil`)
- Modify: `agent/identity.go` — `Identity` struct gains `DomainJoined *bool`; `collectIdentity()` calls `getDomainJoined()`
- Modify: `agent/protocol/heartbeat.go` — `Heartbeat` struct gains `DomainJoined *bool`
- Modify: `agent/agent.go` — `sendHeartbeat`'s `hb := protocol.Heartbeat{...}` literal gains `DomainJoined: a.id.DomainJoined,`
- Create: `agent/sysinfo_windows_test.go`

**Interfaces:**
- Produces: `getDomainJoined() *bool` (one per platform file), `Identity.DomainJoined *bool`, `protocol.Heartbeat.DomainJoined *bool` (JSON tag `domainJoined,omitempty`)

**Correction from the spec:** the spec's Collection section names `NetGetJoinInformation` but doesn't give exact code. `golang.org/x/sys/windows` does not wrap this API (verified — grepped the vendored package, no match), so it needs a raw syscall binding via `windows.NewLazySystemDLL`/`NewProc`, the exact same pattern `agent/job_windows.go` already uses for `SetInformationJobObject`. The real Win32 signature (stable since Windows 2000, unchanged) is:
```c
NET_API_STATUS NetGetJoinInformation(LPCWSTR lpServer, LPWSTR *lpNameBuffer, PNETSETUP_JOIN_STATUS BufferType);
```
`BufferType` out-value: `0`=Unknown, `1`=Unjoined (workgroup), `2`=WorkgroupName, `3`=DomainName. `domain_joined` is true only for `3`. The name buffer must be freed via `NetApiBufferFree` regardless of outcome.

- [ ] **Step 1: Write the failing test**

```go
// agent/sysinfo_windows_test.go
//go:build windows

package main

import "testing"

// TestGetDomainJoined_ReturnsNonNilAndDoesNotPanic proves the Win32 call
// succeeds on this real Windows build host and returns a real answer, not a
// silently-swallowed nil. Whether this specific machine is domain-joined is
// not asserted -- that depends on the host running the test -- only that the
// mechanism itself works.
func TestGetDomainJoined_ReturnsNonNilAndDoesNotPanic(t *testing.T) {
	got := getDomainJoined()
	if got == nil {
		t.Fatal("getDomainJoined() = nil, want a real answer on a live Windows host (NetGetJoinInformation should succeed here)")
	}
	t.Logf("this build host reports domain_joined=%v", *got)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agent && GOWORK=off go test . -run TestGetDomainJoined_ReturnsNonNilAndDoesNotPanic -v`
Expected: FAIL with `undefined: getDomainJoined`

- [ ] **Step 3: Implement `getDomainJoined` in `agent/sysinfo_windows.go`**

Add to the existing file (which already imports `"golang.org/x/sys/windows"` — no new import needed beyond `"unsafe"` and `"syscall"`):

```go
import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Separate lazy-DLL var name to avoid conflict with jobKernel32 in job_windows.go.
var (
	netapi32                  = windows.NewLazySystemDLL("netapi32.dll")
	procNetGetJoinInformation = netapi32.NewProc("NetGetJoinInformation")
	procNetApiBufferFree      = netapi32.NewProc("NetApiBufferFree")
)

// NetSetupDomainName is the BufferType value NetGetJoinInformation reports
// when the machine is joined to an Active Directory domain (as opposed to
// NetSetupUnjoined=1 or NetSetupWorkgroupName=2 for a workgroup machine).
const netSetupDomainName = 3

// getDomainJoined reports whether this Windows machine is domain-joined, via
// the standard NetGetJoinInformation Win32 API -- not wrapped by
// golang.org/x/sys/windows, so bound directly here, same pattern as
// SetInformationJobObject in job_windows.go. Returns nil only if the API call
// itself fails (rare — access-denied under unusual security policy, or a
// non-standard Windows edition); a genuine "not joined" answer is a real,
// non-nil false, not nil.
func getDomainJoined() *bool {
	var nameBuffer *uint16
	var bufferType uint32
	ret, _, _ := procNetGetJoinInformation.Call(
		0, // lpServer: nil = local computer
		uintptr(unsafe.Pointer(&nameBuffer)),
		uintptr(unsafe.Pointer(&bufferType)),
	)
	if nameBuffer != nil {
		defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(nameBuffer)))
	}
	if ret != 0 { // non-zero = NET_API_STATUS error code, not NERR_Success
		return nil
	}
	joined := bufferType == netSetupDomainName
	return &joined
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd agent && GOWORK=off go test . -run TestGetDomainJoined_ReturnsNonNilAndDoesNotPanic -v`
Expected: PASS, with a log line reporting this machine's real domain-join status

- [ ] **Step 5: Add POSIX stubs**

`agent/sysinfo_linux.go`, add:
```go
// getDomainJoined: no POSIX collection in this phase (see Phase 0C spec's
// "Explicitly out of scope" -- one fact, Windows-only, to start). nil means
// "not evaluated," which the orchestrator's gate treats as "never skip."
func getDomainJoined() *bool { return nil }
```

`agent/sysinfo_darwin.go`, add the identical function and comment.

- [ ] **Step 6: Wire into `Identity` and `collectIdentity`**

`agent/identity.go`:
```go
type Identity struct {
	AgentID      string
	Hostname     string
	IPAddress    string
	OSVersion    string
	Username     string
	DomainJoined *bool
}
```
In `collectIdentity()`, add `DomainJoined: getDomainJoined(),` to the returned `Identity{...}` literal (alongside the existing `OSVersion: getOSVersion(),`).

- [ ] **Step 7: Wire into `protocol.Heartbeat`**

`agent/protocol/heartbeat.go`, add to the `Heartbeat` struct (after `OSVersion`):
```go
	DomainJoined *bool `json:"domainJoined,omitempty"`
```

- [ ] **Step 8: Wire into `sendHeartbeat`**

`agent/agent.go`, in `sendHeartbeat`'s `hb := protocol.Heartbeat{...}` literal, add:
```go
		DomainJoined:  a.id.DomainJoined,
```
right after the existing `OSVersion: a.id.OSVersion,` line.

- [ ] **Step 9: Build and run the full agent suite**

Run: `cd agent && GOWORK=off go build ./... && GOWORK=off go test ./... -timeout 10m`
Expected: build clean, all packages `ok`

- [ ] **Step 10: Commit**

```bash
git add agent/sysinfo_windows.go agent/sysinfo_windows_test.go agent/sysinfo_linux.go agent/sysinfo_darwin.go agent/identity.go agent/protocol/heartbeat.go agent/agent.go
git commit -m "feat(phase0c): agent collects and reports domain-joined status"
```

---

### Task 2: Orchestrator — store `domain_joined` from heartbeat

**Files:**
- Modify: `orchestrator/internal/models/schema.go` — `Heartbeat` struct gains `DomainJoined *bool`
- Modify: `orchestrator/internal/db/postgres.go` — `agents` table gains `domain_joined` column
- Modify: `orchestrator/internal/api/handlers.go` — `Heartbeat` handler persists it
- Test: `orchestrator/internal/api/agent_lifecycle_test.go` (append)

**Interfaces:**
- Consumes: nothing from Task 1 (this task's own JSON decode target is independent of the agent's struct — they just need matching field names, already true: `domainJoined`)
- Produces: `agents.domain_joined boolean` column, readable via `SELECT domain_joined FROM agents WHERE agent_id = $1` (the exact query Tasks 4 and 5 will use)

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/api/agent_lifecycle_test.go`:

```go
func TestHeartbeat_PersistsDomainJoined(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-domain-joined-hb"

		body, _ := json.Marshal(map[string]any{
			"agentId": agentID, "hostname": "h", "status": "idle", "domainJoined": true,
		})
		rec := httptest.NewRecorder()
		h.Heartbeat(rec, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var domainJoined *bool
		if err := pool.QueryRow(context.Background(),
			`SELECT domain_joined FROM agents WHERE agent_id = $1`, agentID,
		).Scan(&domainJoined); err != nil {
			t.Fatalf("read domain_joined: %v", err)
		}
		if domainJoined == nil || !*domainJoined {
			t.Fatalf("domain_joined = %v, want true", domainJoined)
		}

		// A heartbeat that omits the field must NOT clobber the known value
		// back to NULL -- an agent's later heartbeat that doesn't resend a
		// fact isn't a signal that the fact became unknown again. (This
		// mirrors the existing security_products guard at handlers.go:1251.)
		body2, _ := json.Marshal(map[string]any{"agentId": agentID, "hostname": "h", "status": "idle"})
		rec2 := httptest.NewRecorder()
		h.Heartbeat(rec2, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(body2)))
		if rec2.Code != http.StatusOK {
			t.Fatalf("second heartbeat: status = %d", rec2.Code)
		}
		var stillDomainJoined *bool
		if err := pool.QueryRow(context.Background(),
			`SELECT domain_joined FROM agents WHERE agent_id = $1`, agentID,
		).Scan(&stillDomainJoined); err != nil {
			t.Fatalf("read domain_joined after omitted-field heartbeat: %v", err)
		}
		if stillDomainJoined == nil || !*stillDomainJoined {
			t.Fatalf("domain_joined after omitted-field heartbeat = %v, want still true (must not be clobbered to NULL)", stillDomainJoined)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestHeartbeat_PersistsDomainJoined -v`
Expected: FAIL — `models.Heartbeat` has no `DomainJoined` field (JSON decode silently drops it, so the column read returns NULL) or the column doesn't exist yet (query error)

- [ ] **Step 3: Add the schema column**

`orchestrator/internal/db/postgres.go`, add right after the existing line `ALTER TABLE agents ADD COLUMN IF NOT EXISTS stop_reason text` (immediately before `CREATE TABLE IF NOT EXISTS scenario_runs`):

```go
		// Phase 0C: domain-joined is the first environmental prerequisite fact.
		// NULL = agent has never reported it (POSIX in this phase, or a
		// pre-upgrade Windows agent) -- the dispatch-time gate treats NULL as
		// "unknown, never skip on it." See
		// docs/superpowers/specs/2026-09-05-phase0c-prerequisite-evaluation-design.md.
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS domain_joined boolean`,
```

- [ ] **Step 4: Add the field to `models.Heartbeat`**

`orchestrator/internal/models/schema.go`, add to the `Heartbeat` struct right after `OSVer`:
```go
	DomainJoined *bool `json:"domainJoined,omitempty"`
```

- [ ] **Step 5: Persist it in the `Heartbeat` handler**

`orchestrator/internal/api/handlers.go`, the main upsert (`handlers.go:1225-1242`) intentionally excludes `domain_joined` — adding it there would clobber a known value to NULL on every heartbeat that omits the field (the test above pins this). Instead, add a conditional update mirroring the existing `security_products` guard right after it (`handlers.go:1251-1257`):

```go
	// Persist domain-joined status only when the heartbeat reports it (nil
	// omitted, per omitempty) -- an agent's later heartbeat that doesn't
	// resend the fact must not clobber a known value back to unknown.
	if hb.DomainJoined != nil {
		_, _ = h.db.Exec(r.Context(),
			`UPDATE agents SET domain_joined = $2 WHERE agent_id = $1`,
			hb.AgentID, *hb.DomainJoined)
	}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestHeartbeat_PersistsDomainJoined -v`
Expected: PASS

- [ ] **Step 7: Run the full api and models regression to confirm no breakage**

Run: `cd orchestrator && go test ./internal/api/... ./internal/models/... -timeout 25m`
Expected: `ok` for both packages, zero FAIL lines. (`internal/api` alone can take 15-20 minutes on this host's resource-constrained Docker VM under the default timeout — this is a known, pre-existing environment characteristic documented in the Phase 0B ledger, not a regression; use `-p 1` if the default parallelism causes container contention.)

- [ ] **Step 8: Commit**

```bash
git add internal/models/schema.go internal/db/postgres.go internal/api/handlers.go internal/api/agent_lifecycle_test.go
git commit -m "feat(phase0c): orchestrator stores domain-joined status from heartbeat"
```

---

### Task 3: `internal/scenario` — curated prerequisite map

**Files:**
- Modify: `orchestrator/internal/scenario/resource.go` — add `PrerequisiteSpec`, `prerequisiteOverrides`, `PrerequisiteFor`
- Test: `orchestrator/internal/scenario/resource_test.go` (append)

**Interfaces:**
- Consumes: nothing from Tasks 1-2
- Produces: `scenario.PrerequisiteSpec{Fact string, Required bool}`, `scenario.PrerequisiteFor(techniqueID string) (PrerequisiteSpec, bool)` — Task 4 calls this directly.

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/scenario/resource_test.go`:

```go
// TestPrerequisiteForT1087002 is the regression test for the first
// evidence-backed prerequisite entry: T1087.002 (Account Discovery: Domain
// Account) is meaningless against a non-domain-joined host, confirmed
// present in real staging traffic 2026-09-05. Mirrors
// TestTimeoutProfileForT1018Override's shape. See project memory /
// docs/superpowers/specs/2026-09-05-phase0c-prerequisite-evaluation-design.md.
func TestPrerequisiteForT1087002(t *testing.T) {
	got, ok := PrerequisiteFor("T1087.002")
	if !ok {
		t.Fatal("T1087.002 should have a curated prerequisite")
	}
	if got.Fact != "domain_joined" {
		t.Errorf("Fact = %q, want %q", got.Fact, "domain_joined")
	}
	if !got.Required {
		t.Error("Required = false, want true (T1087.002 needs domain_joined=true)")
	}
	// Other techniques must be unaffected by the override.
	if _, ok := PrerequisiteFor("T1082"); ok {
		t.Error("T1082 should have no curated prerequisite -- the T1087.002 entry must not leak")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestPrerequisiteForT1087002 -v`
Expected: FAIL with `undefined: PrerequisiteFor`

- [ ] **Step 3: Implement in `resource.go`**

Add right after the existing `timeoutOverrides` block (`resource.go:78-80`, i.e. after the closing `}` of `timeoutOverrides` and before `TimeoutProfileFor`):

```go
// PrerequisiteSpec names a static fact a technique requires to be true (or
// false) about the target agent before it is worth dispatching. See
// docs/superpowers/specs/2026-09-05-phase0c-prerequisite-evaluation-design.md.
type PrerequisiteSpec struct {
	Fact     string // "domain_joined" is the only fact that exists in this phase
	Required bool   // the value Fact must equal for the step to be eligible
}

// prerequisiteOverrides holds curated, evidence-backed per-technique
// prerequisites -- same discipline as timeoutOverrides above: one
// evidence-backed entry at a time, never guessed.
//
// T1087.002 (Account Discovery: Domain Account): confirmed present in real
// staging traffic (2026-09-05) -- genuinely meaningless against a
// non-domain-joined host, since there is no domain account list to enumerate.
var prerequisiteOverrides = map[string]PrerequisiteSpec{
	"T1087.002": {Fact: "domain_joined", Required: true},
}

// PrerequisiteFor returns the curated prerequisite for a technique, or
// (zero, false) if none is curated -- the technique dispatches unconditionally.
func PrerequisiteFor(techniqueID string) (PrerequisiteSpec, bool) {
	spec, ok := prerequisiteOverrides[techniqueID]
	return spec, ok
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestPrerequisiteForT1087002 -v`
Expected: PASS

- [ ] **Step 5: Run the package suite to confirm no breakage**

Run: `cd orchestrator && go test ./internal/scenario/... -v`
Expected: `ok`, all tests pass

- [ ] **Step 6: Commit**

```bash
git add internal/scenario/resource.go internal/scenario/resource_test.go
git commit -m "feat(phase0c): curated per-technique environmental prerequisites"
```

---

### Task 4: ART/Caldera — the third pre-dispatch skip filter

**Files:**
- Modify: `orchestrator/internal/models/schema.go` — add `SkipReasonPrerequisiteMissing` constant
- Modify: `orchestrator/internal/api/handlers.go` — `synthesizePrerequisiteSkipResult` + the filter in `dispatchRun`
- Test: `orchestrator/internal/api/run_scenario_integration_test.go` (append)

**Interfaces:**
- Consumes: `scenario.PrerequisiteFor` (Task 3), `agents.domain_joined` column (Task 2)
- Produces: nothing further downstream consumes — this is the terminal write for the ART/Caldera side

**Correction from the spec:** the spec's illustrative code has `sim.SkipReason = models.SkipReasonPrerequisiteUnsatisfied`. That constant is real but is the WRONG one for this struct — it's `models.SkipReason`, a *typed* enum (`SkipReason` type, value `"prerequisite_unsatisfied"`, underscored) used only for `ExecutionAttempt.SkipReason` (schema.go:205). `SimulationResult.SkipReason` (schema.go:98, the field `synthesizePolicySkipResult`/`synthesizeSkippedContentResult` actually write to) is a plain `string`, populated from a *different*, untyped, hyphenated constant family (`SkipReasonPolicyPrivilege = "policy-privilege"`, schema.go:220). Assigning the typed enum here would not compile without an explicit conversion, and semantically it belongs to the other table's vocabulary. A new constant is needed in the correct (untyped, hyphenated) family — named distinctly from the existing typed one to avoid the exact naming collision Phase 0B's final whole-branch review already flagged (Minor finding #15) between these two families.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/api/run_scenario_integration_test.go`:

```go
// TestRunScenarioIntegration_SkipsStepMissingPrerequisite mirrors
// TestRunScenarioIntegration_MaxPrivilegeFiltersStep's shape for the new
// environmental-prerequisite filter: T1087.002 requires domain_joined=true
// (see scenario.PrerequisiteFor); against a non-domain-joined agent it must
// be skipped while an unrelated step in the same run dispatches normally.
func TestRunScenarioIntegration_SkipsStepMissingPrerequisite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "unrelated-step", TechniqueID: "T1082", Framework: "custom", Command: "echo hi",
				RequiresPriv: scenario.PrivSpec{Minimum: "user"}},
			{Name: "domain-step", TechniqueID: "T1087.002", Framework: "custom", Command: "echo domain",
				RequiresPriv: scenario.PrivSpec{Minimum: "user"}},
		}
		sc, engine := minimalLiveScenario(t, "int-prereq-missing", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-prereq-missing"
		seedActiveAgent(t, pool, agentID, "Windows")
		if _, err := pool.Exec(context.Background(),
			`UPDATE agents SET domain_joined = false WHERE agent_id = $1`, agentID); err != nil {
			t.Fatalf("seed domain_joined=false: %v", err)
		}
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true,
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		runID, _ := resp["runId"].(string)
		if runID == "" {
			t.Fatalf("resp = %+v, want a non-empty runId", resp)
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(cmd.Steps) != 1 || cmd.Steps[0].Name != "unrelated-step" {
			t.Fatalf("cmd.Steps = %+v, want exactly [unrelated-step] (domain-step must be filtered)", cmd.Steps)
		}

		var skippedJSON []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT policy_skipped_results FROM scenario_runs WHERE id = $1`, runID,
		).Scan(&skippedJSON); err != nil {
			t.Fatalf("read policy_skipped_results: %v", err)
		}
		var skipped []models.SimulationResult
		if err := json.Unmarshal(skippedJSON, &skipped); err != nil {
			t.Fatalf("unmarshal policy_skipped_results: %v", err)
		}
		if len(skipped) != 1 {
			t.Fatalf("policy_skipped_results = %d entries, want 1", len(skipped))
		}
		if skipped[0].Result != models.ResultSkipped {
			t.Errorf("skipped[0].Result = %q, want %q", skipped[0].Result, models.ResultSkipped)
		}
		if skipped[0].SkipReason != models.SkipReasonPrerequisiteMissing {
			t.Errorf("skipped[0].SkipReason = %q, want %q", skipped[0].SkipReason, models.SkipReasonPrerequisiteMissing)
		}
		if skipped[0].Technique.ID != "T1087.002" {
			t.Errorf("skipped[0].Technique.ID = %q, want T1087.002", skipped[0].Technique.ID)
		}
	})
}

// TestRunScenarioIntegration_UnknownDomainJoinedNeverGates confirms the
// Error-handling contract: an agent that has never reported domain_joined
// (NULL) must never have a curated technique skipped on its account.
func TestRunScenarioIntegration_UnknownDomainJoinedNeverGates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "domain-step", TechniqueID: "T1087.002", Framework: "custom", Command: "echo domain",
				RequiresPriv: scenario.PrivSpec{Minimum: "user"}},
		}
		sc, engine := minimalLiveScenario(t, "int-prereq-unknown", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-prereq-unknown"
		seedActiveAgent(t, pool, agentID, "Windows") // domain_joined left NULL -- never set
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true,
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(cmd.Steps) != 1 || cmd.Steps[0].Name != "domain-step" {
			t.Fatalf("cmd.Steps = %+v, want [domain-step] dispatched normally (domain_joined unknown must never gate)", cmd.Steps)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestRunScenarioIntegration_SkipsStepMissingPrerequisite|TestRunScenarioIntegration_UnknownDomainJoinedNeverGates" -v`
Expected: FAIL — `models.SkipReasonPrerequisiteMissing` undefined, and even once that's added, both steps still dispatch (no filter exists yet)

- [ ] **Step 3: Add the constant**

`orchestrator/internal/models/schema.go`, add right after the existing `SkipReasonPlatformUnavailable` constant (schema.go:227-231):

```go
// SkipReasonPrerequisiteMissing marks a SimulationResult synthesized
// server-side because a curated technique's required environmental fact
// (e.g. domain_joined) did not match the target agent's known value. Do not
// confuse with the differently-typed, differently-spelled SkipReason enum
// value SkipReasonPrerequisiteUnsatisfied ("prerequisite_unsatisfied",
// underscored) above -- that one is ExecutionAttempt.SkipReason's vocabulary
// (a typed SkipReason), this one is SimulationResult.SkipReason's (a plain
// string, hyphenated like its siblings on this line). The two fields belong
// to different tables and must never be assigned each other's constants.
const SkipReasonPrerequisiteMissing = "prerequisite-missing"
```

- [ ] **Step 4: Add `synthesizePrerequisiteSkipResult`**

`orchestrator/internal/api/handlers.go`, add right after `synthesizeSkippedContentResult` (handlers.go:1636-1658):

```go
// synthesizePrerequisiteSkipResult mirrors synthesizePolicySkipResult for a
// step whose curated environmental prerequisite (scenario.PrerequisiteFor)
// does not match the target agent's known fact value.
func synthesizePrerequisiteSkipResult(st scenario.ScenarioStep, spec scenario.PrerequisiteSpec) models.SimulationResult {
	step := scenario.Step{TechniqueID: st.TechniqueID, Name: st.Name, Framework: st.Framework}
	result := scenario.ExecResult{
		TaskID: st.TaskID,
		Stdout: fmt.Sprintf("SKIP: requires %s=%v, agent reports otherwise", spec.Fact, spec.Required),
	}
	sim := scenario.Interpret(step, result)
	sim.SkipReason = models.SkipReasonPrerequisiteMissing
	return sim
}
```

- [ ] **Step 5: Add the filter in `dispatchRun`**

`orchestrator/internal/api/handlers.go`, add right after the existing privilege filter block (handlers.go:1968-1978), before the `if len(skippedResults) > 0 {` persistence check:

```go
	// Environmental prerequisite filter: a curated technique whose required
	// fact doesn't match the agent's known value is skipped, never dispatched.
	// domainJoined == nil (agent has never reported it) means "unknown, do
	// not gate" -- see the Error-handling section of the Phase 0C spec.
	var domainJoined *bool
	h.db.QueryRow(ctx,
		`SELECT domain_joined FROM agents WHERE agent_id = $1`, agentID,
	).Scan(&domainJoined)
	if domainJoined != nil {
		kept := make([]scenario.ScenarioStep, 0, len(steps))
		for _, st := range steps {
			if spec, ok := scenario.PrerequisiteFor(st.TechniqueID); ok && spec.Fact == "domain_joined" {
				if *domainJoined != spec.Required {
					skippedResults = append(skippedResults, synthesizePrerequisiteSkipResult(st, spec))
					continue
				}
			}
			kept = append(kept, st)
		}
		steps = kept
	}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestRunScenarioIntegration_SkipsStepMissingPrerequisite|TestRunScenarioIntegration_UnknownDomainJoinedNeverGates|TestRunScenarioIntegration_MaxPrivilegeFiltersStep" -v`
Expected: PASS for all three (the third confirms the new filter didn't disturb the existing privilege filter it sits beside)

- [ ] **Step 7: Full regression**

Run: `cd orchestrator && go test ./internal/api/... ./internal/models/... ./internal/scenario/... -timeout 25m`
Expected: `ok` for all three packages, zero FAIL lines (same resource-constrained-host caveat as Task 2 — use `-p 1` if needed).

- [ ] **Step 8: Commit**

```bash
git add internal/models/schema.go internal/api/handlers.go internal/api/run_scenario_integration_test.go
git commit -m "feat(phase0c): ART/Caldera dispatch gates on domain-joined prerequisite"
```

---

### Task 5: `internal/exercise` — `agent:` predicate in `evalCondition`

**Files:**
- Modify: `orchestrator/internal/exercise/store.go` — add `Store.AgentDomainJoined`
- Modify: `orchestrator/internal/exercise/executor.go` — `evalCondition` signature + new predicate case + `agentFact`; update the one call site (executor.go:252)
- Test: `orchestrator/internal/exercise/executor_test.go` (extend `TestEvalCondition_PredicateMatrix`, update its other 10 call sites for the new signature)

**Interfaces:**
- Consumes: `agents.domain_joined` column (Task 2)
- Produces: nothing further downstream consumes

**Note on scope:** `evalCondition`'s signature gains one parameter (`agentID string`). It has exactly one production call site (`executor.go:252`) and eleven call sites in `TestEvalCondition_PredicateMatrix` (`executor_test.go:150,153,157,160,163,167,170,175,178,182,185`) — all eleven must be updated in this same task for the package to compile. This is mechanical (append `, ""` to each, since none of those existing scenarios involve an `agent_task` step) but must be done at every site; a partial update leaves the package broken.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/exercise/executor_test.go`, as a new test (do not yet touch `TestEvalCondition_PredicateMatrix`'s existing eleven calls — that happens in Step 4):

```go
// TestEvalCondition_AgentDomainJoinedPredicate covers the new agent: predicate
// namespace, sibling to the existing step: namespace. true/false/unknown-agent
// mirror the existing step: predicate tests' coverage shape.
func TestEvalCondition_AgentDomainJoinedPredicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _ := newTestExecutor(pool)
		ctx := context.Background()

		joinedAgent := "exercise-agent-domain-joined"
		notJoinedAgent := "exercise-agent-domain-not-joined"
		unknownAgent := "exercise-agent-domain-unknown"
		if _, err := pool.Exec(ctx,
			`INSERT INTO agents (agent_id, hostname, state, domain_joined) VALUES ($1,'h','active',true)`, joinedAgent); err != nil {
			t.Fatalf("seed joined agent: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO agents (agent_id, hostname, state, domain_joined) VALUES ($1,'h','active',false)`, notJoinedAgent); err != nil {
			t.Fatalf("seed not-joined agent: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO agents (agent_id, hostname, state) VALUES ($1,'h','active')`, unknownAgent); err != nil {
			t.Fatalf("seed unknown agent: %v", err)
		}

		byID := map[string]*StepExecution{}
		if !e.evalCondition(ctx, "agent:domain_joined:true", "exec-x", byID, joinedAgent) {
			t.Error("joined agent should satisfy agent:domain_joined:true")
		}
		if e.evalCondition(ctx, "agent:domain_joined:true", "exec-x", byID, notJoinedAgent) {
			t.Error("not-joined agent should fail agent:domain_joined:true")
		}
		if !e.evalCondition(ctx, "agent:domain_joined:false", "exec-x", byID, notJoinedAgent) {
			t.Error("not-joined agent should satisfy agent:domain_joined:false")
		}
		// Unknown (NULL) or no agent at all: fail open (true), same philosophy
		// as an unrecognised predicate defaulting to true.
		if !e.evalCondition(ctx, "agent:domain_joined:true", "exec-x", byID, unknownAgent) {
			t.Error("agent with unknown domain_joined should fail open (true)")
		}
		if !e.evalCondition(ctx, "agent:domain_joined:true", "exec-x", byID, "") {
			t.Error("no agent (empty agentID) should fail open (true)")
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/exercise/... -run TestEvalCondition_AgentDomainJoinedPredicate -v`
Expected: FAIL with a compile error — `evalCondition` takes 4 arguments, 5 supplied — since the new parameter doesn't exist yet

- [ ] **Step 3: Add `Store.AgentDomainJoined`**

`orchestrator/internal/exercise/store.go`, add near the other simple scalar-lookup methods:

```go
// AgentDomainJoined returns the agent's known domain-joined status, or nil if
// the agent has never reported it (or doesn't exist). Same nil-means-unknown
// contract as the ART/Caldera side's equivalent lookup in dispatchRun.
func (s *Store) AgentDomainJoined(ctx context.Context, agentID string) (*bool, error) {
	var domainJoined *bool
	err := s.db.QueryRow(ctx,
		`SELECT domain_joined FROM agents WHERE agent_id = $1`, agentID,
	).Scan(&domainJoined)
	if err != nil {
		return nil, err
	}
	return domainJoined, nil
}
```

- [ ] **Step 4: Update `evalCondition`'s signature and add the new predicate case**

`orchestrator/internal/exercise/executor.go`, replace the function signature and add the new branch (executor.go:733-746):

```go
func (e *Executor) evalCondition(ctx context.Context, cond, execID string, byID map[string]*StepExecution, agentID string) bool {
	cond = strings.TrimSpace(cond)
	if cond == "" || cond == "always" || cond == "true" {
		return true
	}
	if cond == "false" || cond == "never" {
		return false
	}
	parts := strings.SplitN(cond, ":", 3)
	if len(parts) == 3 && parts[0] == "agent" {
		return e.agentFact(ctx, agentID, parts[1], parts[2])
	}
	if len(parts) != 3 || parts[0] != "step" {
		log.Printf("[exercise] unknown condition: %q", cond)
		return true
	}
	stepID, predicate := parts[1], parts[2]
	se := byID[stepID]
```

(Everything from `switch predicate {` through the closing `}` of the function is unchanged.)

Add `agentFact` right after `evalCondition`:

```go
// agentFact evaluates an "agent:<fact>:<expected>" condition against the
// current step's target agent. agentID == "" (a step type with no
// AgentTaskConfig, e.g. send_email/wait/approval) or an unrecognised fact
// name fails open (true) -- structurally inapplicable is not "unsatisfied,"
// same philosophy as evalCondition's own unknown-predicate default. A nil
// (never-reported) domain_joined value also fails open, per the Phase 0C
// spec's Error-handling contract: unknown facts never gate.
func (e *Executor) agentFact(ctx context.Context, agentID, fact, expected string) bool {
	if agentID == "" {
		log.Printf("[exercise] agent: condition on a step with no target agent")
		return true
	}
	if fact != "domain_joined" {
		log.Printf("[exercise] unknown agent fact %q", fact)
		return true
	}
	domainJoined, err := e.store.AgentDomainJoined(ctx, agentID)
	if err != nil || domainJoined == nil {
		return true
	}
	want := expected == "true"
	return *domainJoined == want
}
```

- [ ] **Step 5: Update the production call site**

`orchestrator/internal/exercise/executor.go:252`, replace:
```go
		if !e.evalCondition(ctx, ps.Condition, ex.ID, byID) {
```
with:
```go
		stepAgentID := ""
		if ps.Config.AgentTask != nil {
			stepAgentID = ps.Config.AgentTask.AgentID
		}
		if !e.evalCondition(ctx, ps.Condition, ex.ID, byID, stepAgentID) {
```

- [ ] **Step 6: Update the eleven existing test call sites**

`orchestrator/internal/exercise/executor_test.go`, in `TestEvalCondition_PredicateMatrix`, append `, ""` as the fifth argument to every one of these eleven calls (lines as of this plan's writing — search for `e.evalCondition(ctx,` in this function if line numbers have drifted): the two lines at 150 (which call it three times each — `e.evalCondition(ctx, "", ...)`, `"always"`, `"true"` — all three need the new argument) and 153 (two more calls), plus the single calls at 157, 160, 163, 167, 170, 175, 178, 182, 185. Every occurrence of `e.evalCondition(ctx, <cond>, execID, byID)` in this test function becomes `e.evalCondition(ctx, <cond>, execID, byID, "")`.

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/exercise/... -run "TestEvalCondition_AgentDomainJoinedPredicate|TestEvalCondition_PredicateMatrix|TestAdvance_ConditionFalseSkips" -v`
Expected: PASS for all three

- [ ] **Step 8: Full package regression**

Run: `cd orchestrator && go build ./... && go test ./internal/exercise/... -timeout 15m`
Expected: build clean, `ok`, zero FAIL lines

- [ ] **Step 9: Commit**

```bash
git add internal/exercise/store.go internal/exercise/executor.go internal/exercise/executor_test.go
git commit -m "feat(phase0c): exercise engine gates on agent:domain_joined condition"
```

---

## Final verification

After all 5 tasks: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/api/... ./internal/exercise/... ./internal/scenario/... ./internal/models/... -timeout 30m` and `cd agent && GOWORK=off go build ./... && GOWORK=off go test ./... -timeout 10m`. Confirm all 6 success criteria from the spec are demonstrated by the tests written across these 5 tasks (they map 1:1: criterion 1 → Task 1+2's tests, criteria 2-4 → Task 4's tests, criterion 5 → Task 5's test, criterion 6 → no `execution_attempts`-touching file appears in any task's diff).
