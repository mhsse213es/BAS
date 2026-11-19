# Cobalt Group BFSI Kill Chain — P1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Phase 8 (Collection/Exfiltration), the remainder of Phase 4 (Defense Evasion), and Phase 9 Part 2 (Financial-Impact Simulator) of the Cobalt Group BFSI campaign — 20 scenarios across 3 packs — extending the P0 credential-access/lateral-movement/discovery work already on main.

**Architecture:** Two scenario packs follow the exact P0 pattern (own `lib.ps1` with undo-record helpers, PowerShell steps + undo scripts, generated via `appctlgen`). The financial-impact pack is different: it needs a stateful target, not a stateless discovery stub, so `internal/bfsisim` (the P0 discovery simulator) gains a transaction ledger with GET/POST endpoints the scenarios mutate and verify against — same process, same package, no new simulator.

**Tech Stack:** Go (appctlgen, bfsisim), PowerShell (scenario execution), JSON (undo records, ledger state), YAML (scenario metadata).

**Spec:** Cobalt Group BFSI Kill Chain specification (pasted into conversation 2026-11-18); P0 implementation at `docs/superpowers/plans/2026-11-18-cobalt-group-bfsi-p0.md` and `docs/cobalt-group-bfsi-mastery-qa-log.md` (bugs found there must not recur here — see Global Constraints).

## Global Constraints

- **`appctlgen -common` must always be passed explicitly**, pointed at the pack's own source directory. P0's worst bug was relying on the flag's default (a different library), which silently embedded the wrong lib.ps1 in every one of 18 scenarios.
- **`product_line: killchain`** on every header.yaml (the value `internal/license.ValidProductLine` accepts for this family; P0 shipped `bfsi`, which is invalid and causes "refusing to load").
- **Never use `$Host` or `$host` as a PowerShell variable or parameter name** — it is a read-only automatic variable; binding or assigning it throws at runtime. Use `$TargetHost`/a non-colliding name instead.
- **Every scenario `id:` in header.yaml must be unique project-wide** — grep `scenarios-src/*/header.yaml` for the chosen id before generating; P0's Linux-pack bug (copied id, silently shadowed by dedup) must not recur.
- **No real credential extraction, no real transaction execution against any live payment/ATM system.** All financial-impact scenarios mutate only the in-process bfsisim ledger.
- **Deterministic cleanup**: every write scenario gets an undo record (`New-CgUndoRecord`/`Read-CgUndoRecord`/`Remove-CgUndoRecord`, reused from P0's lib.ps1 pattern) and a `.undo.ps1` cleanup script; `no_default_cleanup: true` for all of them.
- **Sign with the project's real signer** (`go run orchestrator/scripts/signer.go sign orchestrator/private_key.pem <file>`), never `cosign` (this repo does not use cosign; P0 wasted a cycle on this).
- **Verify with the full suite before declaring done**: `go run orchestrator/scripts/signer.go verify-all scenarios` and `go test ./internal/scenario -count=1` (not just a targeted `-run`) — P0's two most severe bugs (invalid product_line, duplicate Linux ids) were only caught by the full, unfiltered run.

## Review Focus

1. **Ledger state leaking between scenario runs**: two runs of financial-impact scenarios (or a killed run) must not accumulate fake transactions in the bfsisim ledger forever — each write scenario's undo must remove exactly what it added, by a recorded deterministic key, not a wildcard sweep.
2. **Concurrent ledger writers**: the bfsisim ledger will be read and written by multiple steps in sequence (and potentially a kill-safe-undo cleanup running concurrently with a later step); state must be guarded (mutex) so a torn read/write never corrupts the ledger JSON.
3. **Reconciliation-mismatch detection must distinguish "no simulator running" (SKIP) from "reconciliation actually balanced" (PASS/FAIL)** — a step that can't reach the ledger must never report the same verdict as one that reached it and found no discrepancy.
4. **Defense-evasion steps that are inherently destructive-sounding (event log clearing, security tool impairment) must verify they only simulate, never actually clear real logs or disable real services** — test that the "clearing" step only creates/deletes synthetic BAS-tagged log entries in a dedicated test log, never calls `wevtutil cl` or `Set-MpPreference -DisableRealtimeMonitoring` for real.
5. **Collection/exfiltration steps that stage synthetic PII/financial data must never write it anywhere persistent beyond the run** — verify staged files are deleted in the same step or by undo, mirroring the existing `collection-pii-financial-exfil.yaml` convention already on main (synthetic `[BAS-SIM]` data, `.invalid` destinations).

---

## Task 1: Collection and Exfiltration Pack

**Files:**
- Create: `scenarios-src/cobalt-group-bfsi-collection-exfil/{header.yaml,stages.json,lib.ps1}`
- Create: `scenarios-src/cobalt-group-bfsi-collection-exfil/coll-{01..06}.ps1` and `.undo.ps1`
- Create: `scenarios/cobalt-group-bfsi-collection-exfil.yaml` + `.yaml.sig`

**Interfaces:**
- Consumes: P0's undo-record pattern (reuse verbatim: `Get-CgUndoPath`/`New-CgUndoRecord`/`Read-CgUndoRecord`/`Remove-CgUndoRecord`, `Write-CgVerdict`/`Complete-CgStep` with tag prefix `BAS-COLL-`)
- Produces: 6 scenarios `coll-01`..`coll-06`, technique ids T1005, T1039, T1114.001, T1560.001, T1041, T1048.003

- [ ] **Step 1: Write `header.yaml`**

`id: "cobalt-group-bfsi-collection-exfil"`, `product_line: killchain`, `supported_os: [windows]`, name "Cobalt Group BFSI - Collection and Exfiltration (P1)", tags including `cobalt-group`, `bfsi`, `collection`, `exfiltration`, `p1`.

- [ ] **Step 2: Write `stages.json`** with 6 entries matching the existing P0 stages.json schema (`id`, `n`, `name`, `technique_id`, `timeout_sec: 120`, `requires_priv: user`, `fidelity: telemetry-safe`, `production_safe: false`, `risk`, `blast_radius`, `telemetry`, `detection`, `cleanup: ""`, `action_key`, `no_default_cleanup: true`, `reversible: false`):
  - `coll-01` T1005 "Local Data Collection from Test Directories" — searches an operator-designated test directory for files matching a synthetic pattern (`bas_sim_*`), counts them, never reads contents of files it did not create itself.
  - `coll-02` T1039 "Network Share Collection" — lists files on a share reachable via `$env:BAS_TEST_HOST` (reuse the P0 lateral-movement convention: SKIP if unset), read-only.
  - `coll-03` T1114.001 "Email Collection Simulation" — reads local Outlook/mail-client profile presence only (e.g. checks for `Outlook.exe` process or a profile registry key); never opens a real mailbox or reads real email content.
  - `coll-04` T1560.001 "Archive Collected Data" — creates one synthetic test file, archives it with `Compress-Archive`, verifies the archive exists, deletes both (step is self-cleaning; undo is a no-op safety net).
  - `coll-05` T1041 "Exfiltration Over C2 Channel Simulation" — attempts a POST of a small synthetic payload to the bfsisim ledger's exfil-sink endpoint (added in Task 3's simulator extension — this task's step script can be written now but will SKIP until Task 3 lands; do not block Task 1 on Task 3).
  - `coll-06` T1048.003 "DNS Exfiltration Simulation" — resolves a synthetic subdomain (`bas-sim-<tag>.invalid`) via `Resolve-DnsName`, expects NXDOMAIN/failure (the `.invalid` TLD per RFC 6761 never resolves), classifies success-to-resolve (shouldn't happen) as FAIL, resolution failure as PASS.

- [ ] **Step 3: Write `lib.ps1`** — copy the undo-record block verbatim from `scenarios-src/cobalt-group-bfsi-credential-access/lib.ps1`, with tag prefix changed to `BAS-COLL-`. Add one helper: `Invoke-DnsExfilProbe { param([string]$Subdomain) ... wraps Resolve-DnsName in try/catch, returns @{Resolved=bool} }`.

- [ ] **Step 4: Write the 6 step scripts and 6 undo scripts**, following the exact structure of P0's `cred-*.ps1`/`cred-*.undo.ps1` (undo record created before any write, `Complete-CgStep` at the end, undo script reads record and removes only what it created).

- [ ] **Step 5: Generate, sign, verify**

```bash
go run ./orchestrator/scripts/appctlgen -src scenarios-src/cobalt-group-bfsi-collection-exfil -common scenarios-src/cobalt-group-bfsi-collection-exfil -out scenarios/cobalt-group-bfsi-collection-exfil.yaml
go run orchestrator/scripts/signer.go sign orchestrator/private_key.pem scenarios/cobalt-group-bfsi-collection-exfil.yaml
```
(appctlgen is built via `go build -o appctlgen.exe ./orchestrator/scripts/appctlgen` first if the binary isn't already present from P0.)

- [ ] **Step 6: Parse-check and syntax-check**

PowerShell: `[System.Management.Automation.Language.Parser]::ParseFile` on all 12 new .ps1 files, 0 failures expected (same check used in P0).
Go: add to `orchestrator/internal/scenario/cobalt_bfsi_test.go`'s `want` map: `"cobalt-group-bfsi-collection-exfil": 6`. Run `go test ./internal/scenario -run TestCobaltBFSIPacks_ParseWithCommandAndCleanup -v`.

- [ ] **Step 7: Commit**

```bash
git add scenarios-src/cobalt-group-bfsi-collection-exfil scenarios/cobalt-group-bfsi-collection-exfil.yaml scenarios/cobalt-group-bfsi-collection-exfil.yaml.sig orchestrator/internal/scenario/cobalt_bfsi_test.go
git commit -m "feat(cobalt-bfsi): add P1 collection and exfiltration pack (coll-01..06)"
```

---

## Task 2: Defense Evasion Pack

**Files:**
- Create: `scenarios-src/cobalt-group-bfsi-defense-evasion/{header.yaml,stages.json,lib.ps1}`
- Create: `scenarios-src/cobalt-group-bfsi-defense-evasion/eva-{01..07}.ps1` and `.undo.ps1`
- Create: `scenarios/cobalt-group-bfsi-defense-evasion.yaml` + `.yaml.sig`

**Interfaces:**
- Consumes: same undo-record pattern, tag prefix `BAS-EVA-`
- Produces: 7 scenarios `eva-01`..`eva-07`, technique ids T1518.001, T1562.001, T1027, T1036, T1112, T1070.001, T1055

- [ ] **Step 1: Write `header.yaml`** — `id: "cobalt-group-bfsi-defense-evasion"`, `product_line: killchain`, `supported_os: [windows]`.

- [ ] **Step 2: Write `stages.json`** with 7 entries:
  - `eva-01` T1518.001 "Security Software Discovery" — enumerates running AV/EDR process names (read-only), no `risk: low`/`production_safe: true` since it's reconnaissance against security tooling.
  - `eva-02` T1562.001 "Security Tool Impairment Simulation (gated, read-only probe)" — **never actually disables a real security product**; checks (does not change) whether Defender real-time protection registry/service state could be modified by the current user (permission probe only — e.g. attempt `Get-MpPreference`, never `Set-MpPreference`). `requires_priv: user`, gated behind `BAS_CONFIRM_DEFENSE_EVASION_PROBE`.
  - `eva-03` T1027 "PowerShell Obfuscation Detection Test" — runs one base64-encoded synthetic benign command (`[Convert]::ToBase64String(...)` of `Write-Output 'bas-sim-obfuscation-test'`) via `-EncodedCommand`, checks whether it executed (FAIL, since an obfuscation-detection control should flag/block it) or was blocked (PASS).
  - `eva-04` T1036 "Masquerading Executable Detection Test" — copies `cmd.exe` (or a synthetic benign binary) to a test directory under a misleading name (e.g. `svchost_test.exe`, tagged clearly as BAS-SIM in content/metadata) and checks whether execution is flagged, then deletes it.
  - `eva-05` T1112 "Registry Modification Detection Test" — writes one synthetic value under `HKCU:\Software\BAS-SIM-Test` (never a real security-relevant key), verifies write succeeded, deletes it; undo removes the key if the step didn't.
  - `eva-06` T1070.001 "Event Log Clearing Attempt (non-destructive)" — creates a **dedicated synthetic test event log/source** (e.g. `New-EventLog -LogName 'BAS-SIM-Test'`), writes a synthetic entry, attempts to clear only that dedicated log (`Clear-EventLog -LogName 'BAS-SIM-Test'`, never Security/System/Application), verifies, removes the test log via undo. Must never call `wevtutil cl Security` or similar against a real log — this is the Review Focus #4 item; the test for this step must assert the command string contains only the synthetic log name.
  - `eva-07` T1055 "Process Injection Detection Test" — spawns one benign synthetic child process (e.g. `notepad.exe` or a short-lived `powershell.exe -Command Start-Sleep 2`) tagged with a recognizable command-line marker, and checks whether security tooling flagged it (read-only probe of Defender/EDR logs for the marker, no actual injection technique is performed — this step tests detection-readiness, not an injection primitive).

- [ ] **Step 3: Write `lib.ps1`** — undo-record block (tag `BAS-EVA-`) plus `Invoke-EncodedCommandProbe { param([string]$PlainText) ... }` (base64-encodes and runs via `-EncodedCommand`, returns whether it ran).

- [ ] **Step 4: Write the 7 step scripts and 7 undo scripts.**

- [ ] **Step 5: Generate, sign, verify** (same commands as Task 1, substituting `defense-evasion`).

- [ ] **Step 6: Parse-check and syntax-check** — add `"cobalt-group-bfsi-defense-evasion": 7` to the test's `want` map.

- [ ] **Step 7: Commit.**

---

## Task 3: Financial-Impact Ledger — Simulator Extension

**Files:**
- Modify: `orchestrator/internal/bfsisim/simulator.go`
- Modify: `orchestrator/internal/bfsisim/simulator_test.go`

**Interfaces:**
- Consumes: existing `Simulator` struct and `NewSimulator(addr string) *Simulator` from P0
- Produces: new exported methods `Simulator.Ledger() *Ledger` (for test assertions) and 5 new HTTP endpoints under `/api/ledger/...`; a `Transaction` type with fields `ID, Amount, Account, Status string/float64`

- [ ] **Step 1: Write the failing test**

```go
func TestSimulator_LedgerCreateAndReconcile(t *testing.T) {
    s := NewSimulator("127.0.0.1:0")
    require.NoError(t, s.Start())
    defer func() { _ = s.Stop(context.Background()) }()
    base := "http://" + s.Addr()

    // POST a synthetic transaction
    body := `{"id":"bas-sim-tx-1","amount":100.00,"account":"test-acct-1"}`
    resp, err := http.Post(base+"/api/ledger/transactions", "application/json", strings.NewReader(body))
    require.NoError(t, err)
    require.Equal(t, http.StatusCreated, resp.StatusCode)

    // GET it back
    resp2, err := http.Get(base + "/api/ledger/transactions/bas-sim-tx-1")
    require.NoError(t, err)
    require.Equal(t, http.StatusOK, resp2.StatusCode)

    // DELETE (undo path)
    req, _ := http.NewRequest(http.MethodDelete, base+"/api/ledger/transactions/bas-sim-tx-1", nil)
    resp3, err := http.DefaultClient.Do(req)
    require.NoError(t, err)
    require.Equal(t, http.StatusOK, resp3.StatusCode)

    // GET again -> 404
    resp4, err := http.Get(base + "/api/ledger/transactions/bas-sim-tx-1")
    require.NoError(t, err)
    require.Equal(t, http.StatusNotFound, resp4.StatusCode)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/bfsisim -run TestSimulator_LedgerCreateAndReconcile -v`
Expected: FAIL (404 on POST, route not registered)

- [ ] **Step 3: Implement the ledger in `simulator.go`**

Add:
```go
type Transaction struct {
    ID      string  `json:"id"`
    Amount  float64 `json:"amount"`
    Account string  `json:"account"`
    Status  string  `json:"status,omitempty"` // "", "flagged", "reconciled"
}

type Ledger struct {
    mu           sync.Mutex
    transactions map[string]Transaction
    reconciled   bool // toggled by /api/ledger/reconcile for FAIL/PASS testing
}
```
Routes on the existing `mux` in `NewSimulator`:
- `POST /api/ledger/transactions` — decode body into `Transaction`, store by ID (mutex-guarded), 409 if ID already exists (idempotent-safe undo), 201 on success.
- `GET /api/ledger/transactions/{id}` — 200 + JSON body, or 404.
- `DELETE /api/ledger/transactions/{id}` — removes it, 200, or 404 if absent (undo calls this and tolerates 404 as "already gone").
- `GET /api/ledger/transactions` — lists all (for the reconciliation steps to diff against an expected set).
- `POST /api/ledger/reconcile` — body `{"expectedTotal": <float>}`; sums stored transactions' amounts, compares to `expectedTotal`, returns `{"balanced": bool, "actualTotal": <float>}`.

Add `func (s *Simulator) Ledger() map[string]Transaction` returning a copy (mutex-guarded) for test assertions.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/bfsisim -run TestSimulator_LedgerCreateAndReconcile -v`
Expected: PASS

- [ ] **Step 5: Add a concurrency test (Review Focus #2)**

```go
func TestSimulator_LedgerConcurrentWritesDoNotCorrupt(t *testing.T) {
    s := NewSimulator("127.0.0.1:0")
    require.NoError(t, s.Start())
    defer func() { _ = s.Stop(context.Background()) }()
    base := "http://" + s.Addr()
    var wg sync.WaitGroup
    for i := 0; i < 20; i++ {
        wg.Add(1)
        go func(i int) {
            defer wg.Done()
            body := fmt.Sprintf(`{"id":"bas-sim-tx-%d","amount":1.0,"account":"a"}`, i)
            _, _ = http.Post(base+"/api/ledger/transactions", "application/json", strings.NewReader(body))
        }(i)
    }
    wg.Wait()
    resp, err := http.Get(base + "/api/ledger/transactions")
    require.NoError(t, err)
    var list []Transaction
    require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
    require.Len(t, list, 20) // every write landed, none lost or corrupted
}
```

- [ ] **Step 6: Run full bfsisim test suite**

Run: `go test ./internal/bfsisim -v -count=1`
Expected: all tests (P0's 3 + this task's 2) PASS

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/bfsisim/simulator.go orchestrator/internal/bfsisim/simulator_test.go
git commit -m "feat(bfsisim): add transaction ledger with reconciliation endpoint for P1 financial-impact scenarios"
```

---

## Task 4: Financial-Impact Scenario Pack

**Files:**
- Create: `scenarios-src/cobalt-group-bfsi-financial-impact/{header.yaml,stages.json,lib.ps1}`
- Create: `scenarios-src/cobalt-group-bfsi-financial-impact/fin-{01..07}.ps1` and `.undo.ps1`
- Create: `scenarios/cobalt-group-bfsi-financial-impact.yaml` + `.yaml.sig`

**Interfaces:**
- Consumes: Task 3's ledger endpoints (`POST/GET/DELETE /api/ledger/transactions[/{id}]`, `POST /api/ledger/reconcile`), `BFSI_SIMULATOR_HOST`/`BFSI_SIMULATOR_PORT` env vars (same convention as P0's discovery pack)
- Produces: 7 scenarios `fin-01`..`fin-07`, all `action_key` prefixed `bfsi_financial_`

- [ ] **Step 1: Write `header.yaml`** — `id: "cobalt-group-bfsi-financial-impact"`, `product_line: killchain`, `supported_os: [windows]`, description noting this validates custom BFSI-specific controls, not all MITRE-mapped.

- [ ] **Step 2: Write `stages.json`** with 7 entries (all `requires_priv: user`, `production_safe: false`, `no_default_cleanup: true`, `reversible: false`, SKIP when the simulator is unreachable — reuse `Test-BankingSimulatorConnectivity` from the P0 discovery lib):
  - `fin-01` "Transaction Record Manipulation Attempt" — POSTs a transaction with a tampered amount field for an ID that already exists in a pre-seeded baseline (the step first creates the baseline record, then attempts to overwrite it), checks whether the overwrite was accepted (FAIL, since transaction integrity controls should reject in-place amount changes) — since the stub ledger's current `POST` returns 409 on duplicate ID, this step's "attempt" is itself the control test: 409 = PASS (control rejected), 200/201 = FAIL.
  - `fin-02` "Payment Instruction Manipulation Attempt" — same pattern against a payment-instruction-shaped transaction (`account` field holding a synthetic beneficiary ID), checks for unauthorized field mutation rejection.
  - `fin-03` "ATM Dispense Workflow Manipulation Attempt" — POSTs a transaction tagged as an ATM dispense request with an amount above a synthetic configured limit (e.g. 100000), then calls `/api/ledger/reconcile` with the correct expected total excluding it, and checks that reconciliation flags the mismatch (`balanced: false` = PASS, the control noticed; `balanced: true` = FAIL, it didn't).
  - `fin-04` "Fraudulent Transaction Pattern Simulation" — POSTs several small transactions in rapid succession (structuring pattern) under one synthetic account, then checks reconciliation for the account's running total against expectation.
  - `fin-05` "Transaction Limit Bypass Attempt" — POSTs one transaction with `amount` far exceeding a synthetic per-transaction limit constant (defined in lib.ps1, e.g. `$FinTxLimit = 50000`), checks whether the ledger accepted it unconditionally (the stub always accepts within its own rules, so this step's real job is to prove the *test itself* can detect a limit violation — compares `$tx.amount -gt $FinTxLimit` after a successful POST, FAIL if accepted and over limit, PASS if rejected).
  - `fin-06` "Financial Reconciliation Manipulation Attempt" — POSTs a transaction, then calls `/api/ledger/reconcile` with a deliberately wrong `expectedTotal`, verifies the endpoint reports `balanced: false` rather than silently accepting the wrong figure (PASS = correctly flagged false; FAIL = endpoint wrongly reported balanced).
  - `fin-07` "Recovery and Service Disruption Check" — calls `GET /api/ledger/transactions` before and after a burst of writes from fin-01..06, confirms the simulator stayed reachable throughout (SKIP-safe: if any call times out, ERROR, not FAIL) — a resilience smoke check, not a disruption attempt against a real system.

- [ ] **Step 3: Write `lib.ps1`** — reuse P0 discovery lib's `Test-BankingSimulatorConnectivity`/`Get-BankingSimulatorHost`/`Get-BankingSimulatorPort` verbatim (same env var names so one simulator instance serves both packs), add:
```
$FinTxLimit = 50000
function New-CgLedgerTransaction { param([string]$Id, [double]$Amount, [string]$Account) ... POSTs via Invoke-RestMethod, returns @{Code=int} }
function Remove-CgLedgerTransaction { param([string]$Id) ... DELETEs, tolerates 404 }
function Invoke-CgLedgerReconcile { param([double]$ExpectedTotal) ... POSTs to /api/ledger/reconcile, returns parsed JSON }
```
Plus the undo-record block (tag `BAS-FIN-`).

- [ ] **Step 4: Write the 7 step scripts and 7 undo scripts** — each undo calls `Remove-CgLedgerTransaction` for every transaction ID the step created (read from the undo record), not a wildcard sweep (Review Focus #1).

- [ ] **Step 5: Generate, sign, verify** (same commands as Task 1, substituting `financial-impact`).

- [ ] **Step 6: Parse-check, syntax-check, and a real end-to-end run**

Add `"cobalt-group-bfsi-financial-impact": 7` to the test's `want` map.
Then, exactly as P0's discovery pack was verified: build `cmd/bfsisim-lab`, run it, set `BFSI_SIMULATOR_HOST`/`PORT`, run each `fin-*` step's assembled command (lib + step) via PowerShell against the live ledger, confirm each produces a verdict reflecting the ledger's actual response (not a hardcoded expectation) — mirroring `TestCobaltBFSIAttackPath_CredentialToDiscoveryCorrelation`'s approach. Add one Go integration test, `TestCobaltBFSIFinancialImpact_LedgerManipulationDetected`, that runs `fin-01`'s real command against a live `bfsisim.Simulator` and asserts the verdict is `PASS` (409 rejection) given the stub's actual duplicate-ID behavior.

- [ ] **Step 7: Commit.**

---

## Task 5: Full-Suite Verification and QA Log

**Files:**
- Modify: `docs/cobalt-group-bfsi-mastery-qa-log.md` (append a P1 section; do not rewrite the P0 section)

**Interfaces:**
- Consumes: all prior tasks' committed YAMLs and Go code

- [ ] **Step 1: Run the full signer verification**

Run: `go run orchestrator/scripts/signer.go verify-all scenarios`
Expected: the 3 new packs appear in the `ok` set; failure count unchanged from before this plan started (any existing unrelated failures are not this plan's responsibility — confirm by name against the pre-plan baseline).

- [ ] **Step 2: Run the full, unfiltered scenario test suite**

Run: `go test ./internal/scenario -count=1 -timeout 420s`
Expected: no new failures beyond the known pre-existing one(s); specifically, no "refusing to load" or "duplicate id" log lines mentioning any `cobalt-group-bfsi-*` path. If `TestBuiltinScenarios_AllHaveValidProductLine`'s count pin is now stale, re-measure and bump it (same procedure as P0's fix), noting the new count in the QA log.

- [ ] **Step 3: Append the P1 section to the QA log**, following the existing P0 section's format exactly (What was built / What was verified for real / Bugs found and fixed / Honest limits), including explicit confirmation that none of P0's bug classes (wrong `-common`, `$Host` misuse, invalid `product_line`, duplicate ids) recurred, or documenting any that did and how they were fixed.

- [ ] **Step 4: Commit and push.**

---

## Self-Review Checklist

**1. Spec coverage:** Phase 8 (6/6 scenarios) ✓, Phase 4 remainder (7/7 scenarios) ✓, Phase 9 Part 2 financial-impact (7/7 scenarios) ✓. Phase 1 (reconnaissance) and Phase 2 (initial access) remain out of scope for P1 as agreed. P2 (additional persistence/C2 variants) is a separate plan.

**2. Step scan:** every step names exact file paths, exact function signatures where new code is introduced, and exact test assertions; no step says "handle appropriately."

**3. Type consistency:** `Transaction` and `Ledger` types defined once in Task 3, referenced by name (not redefined) in Task 4's lib.ps1 description; undo-record function names (`New-CgUndoRecord` etc.) match P0's existing lib.ps1 verbatim across Tasks 1, 2, 4.

**4. Review Focus:** all 5 items have an owning task and test (ledger leak -> Task 4's per-ID undo; concurrency -> Task 3 Step 5; SKIP-vs-balanced distinction -> Task 4 fin-06/fin-07; destructive-sounding evasion steps -> Task 2's eva-02/eva-06 constraints; persistent staged PII -> Task 1's coll-01/coll-04 self-cleaning requirement).

**5. Proportion:** this plan is roughly 2-3x the relevant spec excerpt's length, consistent with P0's accepted ratio; code blocks are limited to the one genuinely new algorithm (the ledger's concurrency-safe map) and test bodies, not scenario step bodies (those are described by behavior, matching how P0's plan described cred-01..08).

## Execution Recommendation

**Recommended approach: Native.** P0 used Native successfully; this plan's tasks have the same shape (independent packs sharing a proven lib pattern, one genuinely new piece of Go code in Task 3) and the same person who executed and fully verified P0 — including catching two critical, non-obvious bugs via live execution rather than inspection — is continuing directly. A fresh per-task reviewer would re-litigate decisions (undo-record pattern, `-common` flag discipline, killchain product_line) already proven correct in P0's QA log.

**Plan complete and saved to `docs/superpowers/plans/2026-11-18-cobalt-group-bfsi-p1.md`.**
