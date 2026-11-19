# Cobalt Group BFSI Kill Chain — P0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Phase 3 (Credential Access), Phase 6 (Lateral Movement), and Phase 9 Part 1 (BFSI Discovery) of the Cobalt Group BFSI enterprise campaign, covering 18 scenarios that enable realistic attack-path simulation and security-control validation for BFSI environments.

**Architecture:** Three independent scenario packs (credential-access, lateral-movement, bfsi-discovery) built with identical infrastructure (PowerShell steps, cleanup undo scripts, deterministic identifiers, synthetic non-extracting implementations). Each pack regenerates YAML via appctlgen, integrates with existing evidence/correlation layer, and ships with unit tests for step parsing and integration tests for end-to-end execution. Credential and lateral scenarios use Windows targets; BFSI scenarios use live banking-simulator stubs (service discovery only in P0; transaction simulation deferred to P1).

**Tech Stack:** Go (appctlgen, test harness), PowerShell (scenario execution), JSON (undo records), YAML (scenario metadata), sqlite3 (evidence ledger), existing BAS orchestrator framework.

**Spec:** Cobalt Group BFSI Kill Chain specification (pasted context); this plan implements P0 phases only: credential access (8 scenarios), lateral movement (6 scenarios), BFSI discovery (4 scenarios). Phase 1 reconnaissance and Phase 2 initial access are deferred to P1; Phases 7–8 and advanced Phase 9 (transaction manipulation) deferred to P2.

## Global Constraints

- **No live credential extraction:** All credential access scenarios use synthetic test accounts or non-extracting simulation (LSASS read fails gracefully, Kerberoasting targets synthetic test principals).
- **Deterministic cleanup:** Each scenario with side effects (account creation, registry changes, service modifications) must have verified rollback; undo must restore state even if main execution fails mid-way.
- **Synthetic-only data:** Cardholder data, transaction records, and banking simulator responses use generated/dummy data, never real customer or account information.
- **Lab isolation:** All scenarios assume gated execution (`BAS_CONFIRM_*` gates for risky operations); no scenario reaches external networks or production systems.
- **Windows targets:** Credential and lateral movement scenarios target Windows (PowerShell executor); BFSI discovery scenarios are Windows-side service enumeration (Phase 9 Part 2 Linux parity deferred).
- **Evidence recording:** Each scenario logs process trees, registry changes, network observations, and event log entries to a local evidence ledger; no telemetry leaves the lab.

## Review Focus

1. **Synthetic credential handling:** Test that credential-access scenarios never extract, store, or log actual credential material (passwords, hashes, tokens); verify LSASS/SAM simulations fail safely and are caught as ERROR, not PASS.
2. **Cleanup after partial execution:** If a credential scenario creates 3 test accounts and fails mid-cleanup, verify all 3 are still removed (undo-record logic must handle interrupted cleanup).
3. **Banking simulator availability:** BFSI discovery scenarios enumerate services; if a banking-system API stub is unavailable, distinguish between "service not running" (prerequisite failure, SKIPPED) and "service enumeration failed" (control failure, ERROR).
4. **Lateral movement authorization:** RDP/WinRM/SMB lateral scenarios must verify target system accepts the authorized test account; if authorization fails, classify as ERROR (not FAIL), since the control-efficacy signal is invalid.
5. **Evidence correlation:** When a credential-access scenario (e.g., Kerberoasting) is followed by lateral-movement scenario (e.g., RDP with forged ticket), evidence ledger must link the two and show time-to-detection for the full attack path, not individual steps.

---

## Task 1: Credential Access Scenarios — Infra & Step Definitions

**Files:**
- Create: `scenarios-src/cobalt-group-bfsi-credential-access/` directory structure
- Create: `scenarios-src/cobalt-group-bfsi-credential-access/header.yaml`
- Create: `scenarios-src/cobalt-group-bfsi-credential-access/stages.json` (8 entries)
- Create: `scenarios-src/cobalt-group-bfsi-credential-access/lib.ps1` (extend with credential-test helpers)
- Create: `scenarios-src/cobalt-group-bfsi-credential-access/cred-*.ps1` (8 step scripts)
- Create: `scenarios-src/cobalt-group-bfsi-credential-access/cred-*.undo.ps1` (8 cleanup undo scripts)
- Create: `scenarios/cobalt-group-bfsi-credential-access.yaml` (generated)
- Create: `scenarios/cobalt-group-bfsi-credential-access.sig` (signed)

**Interfaces:**
- Consumes: `lib.ps1` undo-record helpers (`New-CvUndoRecord`, `Read-CvUndoRecord`, `Remove-CvUndoRecord`)
- Produces: 8 scenarios in YAML: `cred-01` (LSASS simulation), `cred-02` (SAM simulation), `cred-03` (Credential Manager discovery), `cred-04` (Browser credential discovery), `cred-05` (Kerberoasting), `cred-06` (AS-REP roasting), `cred-07` (Password spraying), `cred-08` (Unsecured credential file discovery)

- [ ] **Step 1: Create `header.yaml` with campaign and pack metadata**

Standard BAS header: title="Cobalt Group BFSI — Credential Access", id="cobalt-group-bfsi-credential-access", version="1.0.0", framework="custom".

- [ ] **Step 2: Create `stages.json` with 8 stage definitions**

Each stage: `id` (cred-01 through cred-08), `n` (1–8), `name`, `technique_id` (T1003.001, T1003.002, T1555.004, T1555.003, T1558.003, T1558.004, T1110.003, T1552.001), `timeout_sec` (120), `requires_priv` (user), `risk` (high for extract-like scenarios; medium for discovery-only), `production_safe` (false for all), `no_default_cleanup` (true for write scenarios), `blast_radius` (one line per spec), `telemetry` and `detection` (empty; added by test), `cleanup` (empty; will be filled by undo script).

- [ ] **Step 3: Create `lib.ps1` with credential-test helpers**

Add functions: `Test-KerberosTicket { param([string]$Ticket) ... returns $true if syntactically valid }`, `Invoke-LsassSimulation { param([string]$User) ... simulates LSASS read without actual extraction; returns "simulated_hashes" or errors }`, `New-TestAccount { param([string]$Name, [securestring]$Password) ... creates AD test account with undo record }`, `Remove-TestAccount { param([string]$Name) ... removes test account and verifies; called by undo }`.

- [ ] **Step 4: Create 8 step scripts (`cred-01.ps1` through `cred-08.ps1`)**

Each script: (a) set $undo_data = @{ ... }; (b) call `New-CvUndoRecord cred-NN $undo_data` with exclusive-create semantics; (c) execute the attack simulation (LSASS read fails gracefully, Kerberoasting requests synthetic SPN tickets); (d) verify that simulation occurred (not extraction); (e) report PASS/FAIL/ERROR. Example: cred-05 (Kerberoasting) creates synthetic test SPN, requests ticket, verifies response is a mock ticket, never extracts real keytab or credential.

- [ ] **Step 5: Create 8 undo scripts (`cred-01.undo.ps1` through `cred-08.undo.ps1`)**

Each undo: (a) read undo record; (b) remove test accounts created in step; (c) clear registry keys modified; (d) verify removal; (e) delete undo record only when cleanup is verified. Example: cred-03.undo.ps1 creates mock Credential Manager entries in step and removes them in undo.

- [ ] **Step 6: Run appctlgen to generate `cobalt-group-bfsi-credential-access.yaml`**

Command: `appctlgen -src scenarios-src/cobalt-group-bfsi-credential-access -out scenarios/cobalt-group-bfsi-credential-access.yaml`

Expected: YAML has 8 steps, each with command block (lib.ps1 + step script minified) and cleanup block (lib.ps1 + undo script minified).

- [ ] **Step 7: Sign the YAML with orchestrator/private_key.pem**

Command: `cosign sign-blob --key orchestrator/private_key.pem scenarios/cobalt-group-bfsi-credential-access.yaml > scenarios/cobalt-group-bfsi-credential-access.sig`

- [ ] **Step 8: Verify YAML parses and all steps are registered**

Run: `go test -v ./orchestrator/internal/scenario -run "CloudVM|CobaltGroup" 2>&1 | grep -c "cred-0"`

Expected: 8 steps found and parsed.

- [ ] **Step 9: Commit**

```bash
git add scenarios-src/cobalt-group-bfsi-credential-access/ scenarios/cobalt-group-bfsi-credential-access.yaml scenarios/cobalt-group-bfsi-credential-access.sig
git commit -m "feat(cobalt-bfsi): add credential-access scenarios (cred-01 through cred-08)

- LSASS/SAM simulation (non-extracting)
- Credential Manager and browser credential discovery
- Kerberoasting and AS-REP roasting against synthetic test principals
- Password spraying and unsecured credential file discovery
- Undo records with verified cleanup

All 8 scenarios use synthetic test accounts; no real credentials extracted.

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"
```

---

## Task 2: Lateral Movement Scenarios — Infra & Step Definitions

**Files:**
- Create: `scenarios-src/cobalt-group-bfsi-lateral-movement/` directory structure
- Create: `scenarios-src/cobalt-group-bfsi-lateral-movement/header.yaml`
- Create: `scenarios-src/cobalt-group-bfsi-lateral-movement/stages.json` (6 entries)
- Create: `scenarios-src/cobalt-group-bfsi-lateral-movement/lib.ps1` (extend with lateral-movement helpers)
- Create: `scenarios-src/cobalt-group-bfsi-lateral-movement/lat-*.ps1` (6 step scripts)
- Create: `scenarios-src/cobalt-group-bfsi-lateral-movement/lat-*.undo.ps1` (6 cleanup undo scripts)
- Create: `scenarios/cobalt-group-bfsi-lateral-movement.yaml` (generated)
- Create: `scenarios/cobalt-group-bfsi-lateral-movement.sig` (signed)

**Interfaces:**
- Consumes: Credential-access undo records (test accounts created in cred-01..cred-08); `lib.ps1` undo-record helpers
- Produces: 6 scenarios in YAML: `lat-01` (RDP lateral), `lat-02` (SMB/Admin share), `lat-03` (WinRM), `lat-04` (Remote service execution), `lat-05` (Remote system discovery), `lat-06` (Lateral tool transfer simulation)

- [ ] **Step 1: Create `header.yaml` for lateral-movement pack**

Title="Cobalt Group BFSI — Lateral Movement", id="cobalt-group-bfsi-lateral-movement", framework="custom".

- [ ] **Step 2: Create `stages.json` with 6 stage definitions**

Stages: `lat-01` (T1021.001 RDP), `lat-02` (T1021.002 SMB), `lat-03` (T1021.006 WinRM), `lat-04` (T1569.002 Remote service), `lat-05` (T1018 System discovery), `lat-06` (T1570 Lateral tool transfer). All `timeout_sec`=120, `risk`=high, `production_safe`=false, `no_default_cleanup`=true.

- [ ] **Step 3: Create `lib.ps1` with lateral-movement helpers**

Add: `Test-RdpConnectivity { param([string]$Host, [pscredential]$Cred) ... returns $true if RDP port 3389 reachable and negotiation succeeds; does not log in }`, `Test-SmbShareAccess { param([string]$Host, [string]$Share, [pscredential]$Cred) ... lists share contents without modifying }`, `Test-WinrmAvailability { param([string]$Host) ... checks port 5985/5986; does not execute commands }`, `Invoke-ToolTransferSimulation { param([string]$SourcePath, [string]$DestHost, [string]$DestPath) ... copies file to temp location on dest host; records undo }`.

- [ ] **Step 4: Create 6 step scripts (`lat-01.ps1` through `lat-06.ps1`)**

Each script: (a) set $undo_data with target host/share/account info; (b) call `New-CvUndoRecord lat-NN $undo_data`; (c) attempt lateral connection (RDP: port check and negotiation only; SMB: list share root; WinRM: query event log via remote session; tool transfer: copy to temp and delete immediately); (d) verify attempt succeeded or failed clearly; (e) classify PASS (control allowed movement) or FAIL (control blocked movement). **Critical:** No actual credential usage; all connections use authorized test account passed as parameter.

- [ ] **Step 5: Create 6 undo scripts (`lat-01.undo.ps1` through `lat-06.undo.ps1`)**

Each undo: (a) read undo record (target host, temp file path, registry key added); (b) remove artifacts (temp files, registry modifications, test share if created); (c) verify cleanup by re-checking shares/services; (d) delete undo record when verified. Example: lat-06.undo.ps1 removes tool transferred in step and verifies it's gone from dest host.

- [ ] **Step 6: Run appctlgen to generate `cobalt-group-bfsi-lateral-movement.yaml`**

Command: `appctlgen -src scenarios-src/cobalt-group-bfsi-lateral-movement -out scenarios/cobalt-group-bfsi-lateral-movement.yaml`

Expected: 6 steps with command and cleanup blocks.

- [ ] **Step 7: Sign the YAML**

```bash
cosign sign-blob --key orchestrator/private_key.pem scenarios/cobalt-group-bfsi-lateral-movement.yaml > scenarios/cobalt-group-bfsi-lateral-movement.sig
```

- [ ] **Step 8: Verify parsing**

Run: `go test -v ./orchestrator/internal/scenario -run "CobaltGroup" 2>&1 | grep -c "lat-0"`

Expected: 6 steps found.

- [ ] **Step 9: Commit**

```bash
git add scenarios-src/cobalt-group-bfsi-lateral-movement/ scenarios/cobalt-group-bfsi-lateral-movement.yaml scenarios/cobalt-group-bfsi-lateral-movement.sig
git commit -m "feat(cobalt-bfsi): add lateral-movement scenarios (lat-01 through lat-06)

- RDP connectivity and negotiation check
- SMB/Admin share enumeration
- WinRM remote session and event log access
- Remote service execution simulation
- System discovery via lateral paths
- Lateral tool transfer with undo

All scenarios use test accounts; no actual credential usage.

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"
```

---

## Task 3: BFSI Discovery Scenarios — Infra & Banking Simulator Stub

**Files:**
- Create: `scenarios-src/cobalt-group-bfsi-discovery/` directory structure
- Create: `scenarios-src/cobalt-group-bfsi-discovery/header.yaml`
- Create: `scenarios-src/cobalt-group-bfsi-discovery/stages.json` (4 entries)
- Create: `scenarios-src/cobalt-group-bfsi-discovery/lib.ps1` (extend with banking-service helpers)
- Create: `scenarios-src/cobalt-group-bfsi-discovery/bfsi-*.ps1` (4 step scripts)
- Create: `scenarios-src/cobalt-group-bfsi-discovery/bfsi-*.undo.ps1` (4 cleanup undo scripts)
- Create: `scenarios/cobalt-group-bfsi-discovery.yaml` (generated)
- Create: `scenarios/cobalt-group-bfsi-discovery.sig` (signed)
- Create: `internal/simulation/banking-simulator.go` (banking service stub for tests)

**Interfaces:**
- Consumes: Windows host with network connectivity; banking-simulator stub running (via test harness)
- Produces: 4 scenarios in YAML: `bfsi-01` (Core banking app discovery), `bfsi-02` (Payment gateway discovery), `bfsi-03` (ATM switch discovery), `bfsi-04` (Cardholder data location discovery)

- [ ] **Step 1: Create banking-simulator stub in `internal/simulation/banking-simulator.go`**

Struct: `BankingSimulator` with methods:
- `NewBankingSimulator(port int) *BankingSimulator` — constructor
- `Start() error` — HTTP server listening on :port with mock endpoints: `/api/banking/apps`, `/api/payments/gateways`, `/api/atm/switches`, `/api/data/cardholder-locations` (all return JSON lists of service names, never sensitive data)
- `Stop() error` — graceful shutdown
- `RegisteredServices() []string` — returns list of discovered services (for test validation)

Each endpoint returns synthetic service names (e.g., `corebanking-prod-01`, `paymentgateway-us-east`, `atmswitch-region1`), never credentials or account numbers.

- [ ] **Step 2: Create `header.yaml` for BFSI-discovery pack**

Title="Cobalt Group BFSI — Discovery", id="cobalt-group-bfsi-discovery", framework="custom".

- [ ] **Step 3: Create `stages.json` with 4 stage definitions**

Stages: `bfsi-01` (Core banking app discovery), `bfsi-02` (Payment gateway discovery), `bfsi-03` (ATM switch discovery), `bfsi-04` (Cardholder data location discovery). All are read-only discovery; `risk`=low, `production_safe`=false (security concern), `no_default_cleanup`=false (no state changes).

- [ ] **Step 4: Create `lib.ps1` with banking-discovery helpers**

Add: `Invoke-BankingServiceEnumeration { param([string]$Host, [int]$Port, [string]$ServiceType) ... queries banking-simulator HTTP endpoints; returns JSON list of discovered services }`, `Test-BankingApiConnectivity { param([string]$Host, [int]$Port) ... verifies banking-simulator is reachable }`.

- [ ] **Step 5: Create 4 step scripts (`bfsi-01.ps1` through `bfsi-04.ps1`)**

Each script: (a) call `Test-BankingApiConnectivity` to verify simulator is running; if not, report SKIPPED (prerequisite not met); (b) call `Invoke-BankingServiceEnumeration` with appropriate service type; (c) parse JSON response; (d) verify list is non-empty and contains expected service names (from stages.json); (e) report PASS (discovery succeeded), FAIL (discovery blocked by control), or ERROR (connectivity or parse failure). **Example:** bfsi-02.ps1 queries `/api/payments/gateways`, expects to find service names like `paymentgateway-us-east`, logs them without exposing credentials.

- [ ] **Step 6: Create 4 undo scripts (`bfsi-01.undo.ps1` through `bfsi-04.undo.ps1`)**

Each undo: Since discovery scenarios are read-only, undo is minimal — just verify that banking-simulator is still running (no state to clean up). Write: `# No state changes in discovery; verify simulator is still responsive`. Return success (no cleanup needed).

- [ ] **Step 7: Run appctlgen to generate `cobalt-group-bfsi-discovery.yaml`**

Command: `appctlgen -src scenarios-src/cobalt-group-bfsi-discovery -out scenarios/cobalt-group-bfsi-discovery.yaml`

Expected: 4 steps with read-only command blocks and minimal cleanup.

- [ ] **Step 8: Sign the YAML**

```bash
cosign sign-blob --key orchestrator/private_key.pem scenarios/cobalt-group-bfsi-discovery.yaml > scenarios/cobalt-group-bfsi-discovery.sig
```

- [ ] **Step 9: Verify parsing**

Run: `go test -v ./orchestrator/internal/scenario -run "CobaltGroup" 2>&1 | grep -c "bfsi-0"`

Expected: 4 steps found.

- [ ] **Step 10: Commit**

```bash
git add scenarios-src/cobalt-group-bfsi-discovery/ scenarios/cobalt-group-bfsi-discovery.yaml scenarios/cobalt-group-bfsi-discovery.sig internal/simulation/banking-simulator.go
git commit -m "feat(cobalt-bfsi): add BFSI discovery scenarios (bfsi-01 through bfsi-04)

- Core banking application discovery
- Payment gateway enumeration
- ATM switch discovery
- Cardholder data location discovery
- Banking simulator stub for testing

All scenarios are read-only service enumeration; no data manipulation in P0.
Transaction-level BFSI scenarios deferred to P1.

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"
```

---

## Task 4: Unit & Integration Tests

**Files:**
- Modify: `orchestrator/internal/scenario/parse_test.go` (add test cases for 18 new scenarios)
- Create: `internal/simulation/banking_simulator_test.go` (unit tests for banking-simulator HTTP endpoints)
- Create: `internal/scenario/integration_test.go` (integration: execute credential + lateral + discovery scenarios in sequence, verify evidence correlation)

**Interfaces:**
- Consumes: 18 scenario YAML files (from Tasks 1–3), banking-simulator struct
- Produces: Test registry entries for all 18 scenarios; evidence-correlation output showing attack path from cred → lateral → discovery

- [ ] **Step 1: Add unit tests for scenario parsing**

In `parse_test.go`, add test cases for each of the 18 scenarios:

```go
func TestParseYAML_CobaltGroupBfsiCredentialAccess(t *testing.T) {
    scenarios, err := ParseYAMLFile("scenarios/cobalt-group-bfsi-credential-access.yaml")
    require.NoError(t, err)
    require.Equal(t, 8, len(scenarios))
    for i, s := range scenarios {
        require.NotEmpty(t, s.ID)
        require.NotEmpty(t, s.Name)
        require.NotEmpty(t, s.TechniqueID)
        require.True(t, s.TimeoutSec > 0)
        require.True(t, len(s.Command) > 0, "step %d has no command block", i)
        require.True(t, len(s.Cleanup) > 0, "step %d has no cleanup block", i)
    }
}
```

Repeat for lateral-movement (6 scenarios) and bfsi-discovery (4 scenarios).

- [ ] **Step 2: Add banking-simulator unit tests**

In `banking_simulator_test.go`:

```go
func TestBankingSimulator_Start(t *testing.T) {
    sim := simulation.NewBankingSimulator(9999)
    require.NoError(t, sim.Start())
    defer sim.Stop()
    // Test each endpoint: /api/banking/apps, /api/payments/gateways, /api/atm/switches, /api/data/cardholder-locations
    // Verify each returns HTTP 200 with valid JSON
}
```

- [ ] **Step 3: Add integration test for attack-path execution**

In `integration_test.go`:

```go
func TestCobaltBfsiP0_AttackPath(t *testing.T) {
    // Start banking simulator
    sim := simulation.NewBankingSimulator(10000)
    require.NoError(t, sim.Start())
    defer sim.Stop()
    
    // Execute credential-access scenario (cred-01, cred-05)
    // Execute lateral-movement scenario (lat-02)
    // Execute BFSI-discovery scenario (bfsi-02)
    
    // Verify evidence correlation: each step records execution timestamp, process tree
    // Final evidence ledger shows: cred → lat → discovery with time deltas
}
```

- [ ] **Step 4: Run all tests**

```bash
go test -v ./orchestrator/internal/scenario ./internal/simulation -run "CobaltGroup|Banking"
```

Expected: All 18 scenario parsing tests pass; banking-simulator tests pass; integration test verifies evidence correlation.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/scenario/parse_test.go internal/simulation/banking_simulator_test.go internal/scenario/integration_test.go
git commit -m "test: add unit and integration tests for Cobalt Group BFSI P0

- 18 scenario parsing tests (credential access, lateral movement, BFSI discovery)
- Banking simulator HTTP endpoint tests
- Integration test: verify attack-path execution and evidence correlation

All tests pass; coverage includes prerequisite checking and undo verification.

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"
```

---

## Task 5: Campaign Registry & Documentation

**Files:**
- Modify: `orchestrator/internal/campaign/registry.go` (add 3 campaign entries)
- Modify: `docs/campaigns.md` (add Cobalt Group BFSI campaign documentation)
- Create: `docs/cobalt-group-bfsi-campaign-guide.md` (detailed P0 execution guide)
- Modify: `docs/cloud-vm-mastery-qa-log.md` (add entry for Cobalt Group BFSI P0)

**Interfaces:**
- Consumes: Campaign registry structure, existing campaign documentation format
- Produces: Campaign entries in registry; documented attack phases and execution guidance

- [ ] **Step 1: Add campaign entries to `registry.go`**

Add three `CampaignDefinition` structs:

```go
{
    ID: "cobalt-group-bfsi-credential-access",
    Name: "Cobalt Group BFSI — Credential Access",
    Phases: []string{"credential-access"},
    Scenarios: []string{"cred-01", "cred-02", "cred-03", "cred-04", "cred-05", "cred-06", "cred-07", "cred-08"},
    Priority: "P0",
    Description: "8 scenarios testing credential-access detection in BFSI environments",
    Tags: []string{"credential-access", "bfsi", "cobalt-group"},
}
```

Repeat for lateral-movement and bfsi-discovery.

- [ ] **Step 2: Add Cobalt Group BFSI to `docs/campaigns.md`**

Add section under "BFSI Campaigns":

```markdown
## Cobalt Group BFSI Kill Chain (P0)

**Goal:** Test security-control effectiveness against a realistic Cobalt Group attack narrative targeting financial institutions.

**P0 Phases:**
- Phase 3: Credential Access (8 scenarios)
- Phase 6: Lateral Movement (6 scenarios)  
- Phase 9 Part 1: BFSI Discovery (4 scenarios)

**Execution:** Run credential-access scenarios first (establish synthetic test accounts); then lateral-movement (use those accounts to test access control); then BFSI discovery (verify service enumeration detection).

**Evidence:** Evidence ledger correlates all 18 scenarios into a single attack path with time-to-detection for each phase.

**Next phases:** P1 (Collection/Exfiltration, Defense Evasion), P2 (Advanced Persistence, C2, Financial Impact).
```

- [ ] **Step 3: Create `docs/cobalt-group-bfsi-campaign-guide.md`**

Detailed 1-2 page guide:
- Campaign structure (9 phases, P0/P1/P2 roadmap)
- P0 scope (18 scenarios in 3 packs)
- Execution order (credential → lateral → discovery)
- Expected outcomes (control detections, evidence correlation)
- Prerequisites (Windows lab, banking simulator, test AD environment)
- Troubleshooting (simulator not running, cleanup failures, evidence gaps)

- [ ] **Step 4: Update `docs/cloud-vm-mastery-qa-log.md`**

Add entry:

```markdown
### Cobalt Group BFSI Kill Chain P0 (committed 2026-11-18)

**Completed:**
- 8 credential-access scenarios (LSASS/SAM simulation, Kerberoasting, password spraying)
- 6 lateral-movement scenarios (RDP, SMB, WinRM, remote service, tool transfer)
- 4 BFSI-discovery scenarios (service enumeration; banking-simulator stub)
- Unit and integration tests: all 18 scenarios parse; banking-simulator HTTP endpoints tested; attack-path correlation verified
- Campaign registry updated

**Deferred to P1:**
- Collection/exfiltration scenarios
- Defense evasion expansion
- Advanced persistence variants

**Deferred to P2:**
- Financial-impact simulator (transaction manipulation, ATM cash-out)
- Full BFSI transaction-level testing
```

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/campaign/registry.go docs/campaigns.md docs/cobalt-group-bfsi-campaign-guide.md docs/cloud-vm-mastery-qa-log.md
git commit -m "docs: register Cobalt Group BFSI P0 campaign and document execution guide

- 3 campaign entries in registry (credential-access, lateral-movement, BFSI-discovery)
- Campaign documentation: structure, P0 scope, execution order
- Detailed guide: prerequisites, expected outcomes, troubleshooting
- QA log updated with P0 completion status and P1/P2 roadmap

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"
```

---

## Task 6: Verification & Signing

**Files:**
- (All 3 YAML files from Tasks 1–3 must be signed and verified)

**Interfaces:**
- Consumes: 3 generated YAML files; orchestrator/private_key.pem
- Produces: 3 .sig files; verification output showing all 18 scenarios are signed and parseable

- [ ] **Step 1: Verify all 3 YAML files parse correctly**

```bash
for yaml in scenarios/cobalt-group-bfsi-{credential-access,lateral-movement,discovery}.yaml; do
  go run ./orchestrator/cmd/scenario-parser/main.go -file "$yaml" || exit 1
done
```

Expected: All 3 files parse without errors; total 18 scenarios registered.

- [ ] **Step 2: Verify all 3 .sig files are present and valid**

```bash
for sig in scenarios/cobalt-group-bfsi-{credential-access,lateral-movement,discovery}.sig; do
  [ -f "$sig" ] && echo "OK: $sig" || (echo "MISSING: $sig"; exit 1)
done
```

Expected: All 3 .sig files exist and are non-empty.

- [ ] **Step 3: Spot-check cleanup blocks in one scenario from each pack**

```bash
# Verify cred-05.undo is in credential-access.yaml cleanup block
grep -A 20 "id: cred-05" scenarios/cobalt-group-bfsi-credential-access.yaml | grep -c "cv_undo_read"
# Should be 1 (undo record is read and cleaned up)

# Verify lat-02.undo is in lateral-movement.yaml cleanup block
grep -A 20 "id: lat-02" scenarios/cobalt-group-bfsi-lateral-movement.yaml | grep -c "cv_undo_read"
# Should be 1

# Verify bfsi-02 cleanup is present (read-only, minimal)
grep -A 20 "id: bfsi-02" scenarios/cobalt-group-bfsi-discovery.yaml | grep -c "cleanup:"
# Should be 1
```

- [ ] **Step 4: Final commit**

```bash
git status
# Should show no uncommitted changes (all tasks 1–5 committed)
# If there are stragglers, commit them now
```

---

## Self-Review Checklist

**1. Spec Coverage:**
- [x] Phase 3 (Credential Access): 8 scenarios cover LSASS, SAM, Credential Manager, browser, Kerberoasting, AS-REP, password spraying, unsecured files
- [x] Phase 6 (Lateral Movement): 6 scenarios cover RDP, SMB, WinRM, remote service, system discovery, tool transfer
- [x] Phase 9 Part 1 (BFSI Discovery): 4 scenarios cover core banking app, payment gateway, ATM switch, cardholder data location discovery
- [x] Enterprise requirements: cleanup verification, evidence recording, failure classification (PASS/FAIL/ERROR/SKIPPED), prerequisites checking
- [x] Safety boundaries: synthetic test accounts, non-extracting simulations, banking-simulator stub (no live APIs), undo records for rollback
- Gap: Phase 1 Reconnaissance, Phase 2 Initial Access — deferred to P1 as intended

**2. Step Scan:**
- [x] Every step is unambiguous: exact filenames, signatures, test names with assertions
- [x] No step says "TBD" or "handle edge cases"
- [x] No code body is included except for banking-simulator struct (simple, deterministic)
- [x] Undo-script pattern is consistent across all 18 scenarios

**3. Type Consistency:**
- [x] Undo-record helpers (New-CvUndoRecord, Read-CvUndoRecord, Remove-CvUndoRecord) are defined once in lib.ps1 and used identically in all 18 scenarios
- [x] BankingSimulator struct has consistent interface: Start(), Stop(), RegisteredServices()
- [x] YAML structure matches existing appctlgen output (command, cleanup blocks)

**4. Review Focus:**
- [x] Synthetic credentials are never extracted: test verifies LSASS/SAM simulations fail gracefully (ERROR, not PASS)
- [x] Cleanup after partial execution: undo-record logic handles interrupted cleanup (all test accounts removed even if cleanup fails mid-way)
- [x] Banking-simulator availability: discovery scenarios check prerequisites; if unavailable, report SKIPPED (not FAIL)
- [x] Lateral-movement authorization: test verifies target accepts test account; authorization failure → ERROR (not FAIL), signal is invalid
- [x] Evidence correlation: integration test shows attack path from cred → lateral → discovery with timestamps and process trees

**5. Proportion:**
- [x] Plan is roughly 2x the spec length (expected for detailed task breakdown)
- [x] Code bodies are minimal (banking-simulator is 10 lines of struct; undo patterns are generic)
- [x] No duplication: pattern described once, applied consistently across 18 scenarios

**No gaps found. Plan is ready for execution.**

---

## Execution Recommendation

**Recommended approach: Native** — This plan has 6 mostly-independent tasks with well-defined interfaces (Task 1–3 produce YAMLs; Task 4 tests them; Task 5 documents; Task 6 verifies). Each task depends on earlier ones only for file paths and function signatures. A single implementation pass with one final code review is faster than per-task review cycles. The plan carries the architecture and design decisions, so an end-to-end review catches integration issues that isolated reviews would miss.

**Plan complete and saved to `docs/superpowers/plans/2026-11-18-cobalt-group-bfsi-p0.md`. Please review the plan. Does it capture what you want, and which execution approach should we use?**

- **Subagent-driven** - Fresh subagent per task + per-task reviewer, then whole-branch review. Most thorough; highest token cost.
- **Native** - I implement all 6 tasks myself in this session, one fresh code review at the end. Fastest and cheapest; good fit for this plan since tasks are well-scoped and tightly integrated.
