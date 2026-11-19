# Carbanak BFSI Pack Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **DO NOT EXECUTE** until the user approves this plan and its acceptance criteria.

**Goal:** Expand the Carbanak kill chain into a BFSI pack in which endpoint compromise is validated against a simulated banking ledger, with separate endpoint and fraud-control verdicts per step.

**Architecture:** A new lab-only Go service `carbanak-ledger-sim` enforces banking control rules on its own HTTP API and writes a hash-chained audit log. The Carbanak chain file keeps stages 1-7, replaces stage 8 with a 7-step fraud sequence (8a-8g) that shares ledger state, and adds lateral, discovery, credential, and collection stages. Items 9 and 23-28 are separate scenario files, each with fresh ledger state. A new `fraud_control` verdict is parsed from a structured marker line emitted by each fraud step and is scored independently of the endpoint verdict.

**Tech Stack:** Go (orchestrator module, `net/http`, `httptest`), PowerShell step commands, YAML scenarios signed via `orchestrator/scripts/signer.go`.

**Spec:** `docs/superpowers/specs/2026-11-17-carbanak-bfsi-expansion-design.md` (approved). The spec is authoritative; conflicts resolve against it.

## Global Constraints

- Ledger binds `127.0.0.1` by default. Non-loopback requires an env override AND a host label ending `.test`, `.invalid`, or `.lab`. A production hostname is refused.
- Operating window: Asia/Kolkata (IST); normal hours Monday-Friday 09:00-18:00 IST; outside = before 09:00, after 18:00, weekends. Configurable per test environment.
- Deterministic clock: env `BAS_CARBANAK_FIXED_TIME` (RFC3339). With it set, results are identical across runs.
- LSASS uses query-only `0x1000` only. Credential Manager and browser stores are enumerated or probed for existence only; never read.
- Lateral-movement stages require `BAS_CARBANAK_TARGET_HOST`; unset -> SKIP with reason.
- Items 23 and 28 have an empty `technique_id` with `attack_gap: no_clean_attack_technique`. They are excluded from ATT&CK coverage percentages and included in execution and fraud-control reporting.
- Proposed ATT&CK IDs are not shipped as validated. Every technique in a new scenario must have a validated row in the mapping register (Task 2) before that scenario's task starts.
- Every scenario edit requires re-signing its `.sig`.

## Review Focus

1. **Endpoint block with ledger never called.** The fraud step must not report PASS. Expected: fraud verdict SKIPPED with reason "ledger not called"; overall SKIPPED, not PASS. Pinned by Task 7.
2. **Ledger down or port in use.** Expected: SKIP (unset) or ERROR (port conflict) with the reason, never PASS. Pinned by Task 6 and Task 8.
3. **Shared sequence leakage.** Items 23-28 must not see 8a-8g transactions or approvals. Expected: fresh run_id, empty audit for a new run. Pinned by Task 12.
4. **Non-loopback ledger host.** A production hostname must be refused, even with the override set. Pinned by Task 6.
5. **Fixed clock determinism.** Two runs with the same `BAS_CARBANAK_FIXED_TIME` must produce byte-identical audit rows apart from the random run_id. Pinned by Task 5.

---

### Task 1: Step attack_gap field and relaxed validation

**Files:**
- Modify: `orchestrator/internal/scenario/types.go:127` (the `Step` struct, add field after `TechniqueID`)
- Modify: `orchestrator/internal/scenario/engine.go:356-380` (`Scenario.Validate`)
- Test: `orchestrator/internal/scenario/attack_gap_test.go` (create)

**Interfaces:**
- Produces: `Step.AttackGap string` with yaml `attack_gap,omitempty`, json `attackGap,omitempty`. Const `AttackGapNoCleanTechnique = "no_clean_attack_technique"`.
- Validate rule: a step may have empty `TechniqueID` only if `AttackGap == AttackGapNoCleanTechnique`. Any other empty technique is rejected with the existing message. Any non-empty `AttackGap` other than the const is rejected.

- [ ] **Step 1: Write the failing tests**

```go
func TestParseYAML_AttackGapAllowsEmptyTechnique(t *testing.T) {
	src := []byte("id: t\nproduct_line: killchain\nname: t\nexecutable: true\nsupported_os: [windows]\nsteps:\n  - name: s\n    attack_gap: no_clean_attack_technique\n    executor: powershell\n    command: 'x'\n")
	if _, err := ParseYAML(src); err != nil {
		t.Fatalf("empty technique with attack_gap rejected: %v", err)
	}
}
// TestParseYAML_EmptyTechniqueWithoutGapRejected: same YAML without attack_gap -> error contains "missing a technique_id".
// TestParseYAML_AttackGapUnknownValueRejected: attack_gap: "whatever" -> error.
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `cd orchestrator && go test ./internal/scenario/ -run TestParseYAML_AttackGap -v`
Expected: FAIL (empty technique rejected even with attack_gap; unknown field).

- [ ] **Step 3: Implement the field and the relaxed rule** in `types.go` and `engine.go:376`.

- [ ] **Step 4: Run the tests and verify they pass**

Run: `go test ./internal/scenario/ -run TestParseYAML_ -v`
Expected: PASS for the three new tests, and the existing `TestParseYAML_*` suite unchanged.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/scenario/types.go orchestrator/internal/scenario/engine.go orchestrator/internal/scenario/attack_gap_test.go
git commit -m "feat(scenario): allow a step without ATT&CK technique when attack_gap names it"
```

---

### Task 2: ATT&CK mapping register

**Files:**
- Create: `docs/carbanak-mapping-register.md`

**Interfaces:**
- Produces: one row per new technique with `status` (`validated`, `validated-with-caveat`, `no_clean_attack_technique`, `pending`), confidence, and source URL. Later tasks check their row before starting.

- [ ] **Step 1: Record already-validated rows** (from the design doc, with sources): item 9 T1057 validated; items 23 and 28 `no_clean_attack_technique`; item 24 T1565.002 validated-with-caveat; item 25 and 27 T1078 validated-with-caveat; item 26 T1078 validated; Stage 3 T1686.003 validated (attack.mitre.org/techniques/T1686/003/).

- [ ] **Step 2: Validate each `pending` row** on attack.mitre.org (items 10-22, 29-32 and the Stage 2/8 subtechniques) before its task. Record the URL and confidence per row. A row that does not fit becomes `no_clean_attack_technique`.

- [ ] **Step 3: Commit**

```bash
git add docs/carbanak-mapping-register.md
git commit -m "docs(carbanak): ATT&CK mapping register for the BFSI pack"
```

---

### Task 3: Correct existing stages 3 and 4

**Files:**
- Modify: `scenarios/carbanak-kill-chain.yaml` (Stage 3 `technique_id` line 198 and tags; Stage 4 command line 280)
- Test: `orchestrator/internal/scenario/carbanak_kill_chain_test.go` (create)

**Interfaces:**
- Consumes: none new.

- [ ] **Step 1: Write the failing tests**

```go
func TestCarbanakStage3UsesHostFirewallSubTechnique(t *testing.T) {
	// load scenarios/carbanak-kill-chain.yaml via ParseYAML; find step named "...Stage 3..."
	// assert TechniqueID == "T1686.003"
}
func TestCarbanakStage4UsesQueryOnlyLSASSAccess(t *testing.T) {
	// assert step.Command contains "0x1000" and does not contain "0x1010"
}
```

- [ ] **Step 2: Run and verify they fail**

Run: `go test ./internal/scenario/ -run TestCarbanakStage -v`
Expected: FAIL (T1686, 0x1010).

- [ ] **Step 3: Edit Stage 3 to `T1686.003`, and Stage 4 `OpenProcess(0x1010, ...)` to `0x1000`.** Update the Stage 4 blast_radius text to match ("PROCESS_QUERY_LIMITED_INFORMATION").

- [ ] **Step 4: Run and verify pass; re-sign the file** (`go run scripts/signer.go sign private_key.pem ../scenarios/carbanak-kill-chain.yaml`).

- [ ] **Step 5: Commit**

```bash
git add scenarios/carbanak-kill-chain.yaml scenarios/carbanak-kill-chain.yaml.sig orchestrator/internal/scenario/carbanak_kill_chain_test.go
git commit -m "fix(carbanak): host-firewall sub-technique for stage 3, query-only LSASS for stage 4"
```

---

### Task 4: Ledger rules engine

**Files:**
- Create: `orchestrator/internal/carbanakledger/rules.go`
- Test: `orchestrator/internal/carbanakledger/rules_test.go`

**Interfaces:**
- Produces:
  - `type Decision string` with consts `Approved`, `Rejected`, `Flagged`.
  - `type Action struct { Kind string; Actor string; Approver string; Amount int64; Hour time.Time; Limit int64; PrivilegedRole bool; ApproverRole bool; SecondApproverPresent bool; SameHostAsSession bool; SessionExpired bool }`.
  - `func Evaluate(a Action, w Window) (Decision, string)` returns decision and `rule_fired` (empty when approved).
  - `type Window struct { Location *time.Location; Start, End int /* hour */; }` with `func (w Window) Inside(t time.Time) bool`.
- Behavior per spec table: self-approval -> Rejected (`maker_checker_self_approval`); approver without approver role -> Rejected (`approver_role_missing`); beneficiary change without second approver -> Rejected (`beneficiary_second_approver_missing`); amount over limit -> Flagged (`amount_over_limit`); limit change without privileged role -> Rejected (`limit_change_unprivileged`); outside window -> Flagged (`outside_operating_window`); session reuse other host or expired -> Flagged (`session_anomaly`); else Approved.

- [ ] **Step 1: Write table-driven tests** covering every rule above, plus window boundaries: 08:59:59 IST outside, 09:00:00 inside, 17:59:59 inside, 18:00:00 outside, Saturday 10:00 outside, Monday 09:00 inside. Use `time.LoadLocation("Asia/Kolkata")`.

- [ ] **Step 2: Run and verify they fail**

Run: `go test ./internal/carbanakledger/ -run TestEvaluate -v`
Expected: FAIL (package does not exist).

- [ ] **Step 3: Implement `rules.go`** with the rules in the order listed in the spec table. First matching rule wins.

- [ ] **Step 4: Run and verify pass.**

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/carbanakledger/rules.go orchestrator/internal/carbanakledger/rules_test.go
git commit -m "feat(carbanak-ledger): banking control rules with IST operating window"
```

---

### Task 5: Hash-chained audit log

**Files:**
- Create: `orchestrator/internal/carbanakledger/audit.go`
- Test: `orchestrator/internal/carbanakledger/audit_test.go`

**Interfaces:**
- Consumes: `Decision` and `rule_fired` from Task 4.
- Produces:
  - `type Row struct { RunID, Step, Actor, Action, Decision, RuleFired, PrevHash, Hash string; At time.Time }`
  - `type Log struct` with `func Open(path string) (*Log, error)` (reloads existing rows from the file), `func (l *Log) Append(runID, step, actor, action string, d Decision, rule string, at time.Time) (Row, error)`, `func (l *Log) Rows(runID string) []Row`, `func (l *Log) Verify(runID string) (intact bool, badIndex int)`.
- Hash: SHA-256 over `PrevHash|RunID|Step|Actor|Action|Decision|RuleFired|At.UTC().Format(RFC3339Nano)`, hex-encoded. The genesis `PrevHash` is `"0"` repeated 64 times.

- [ ] **Step 1: Write the failing tests:** append three rows, `Verify` intact; mutate one row's `Decision` in the file, reopen, `Verify` returns intact=false with the mutated index; reopen after appends returns the same rows (restart survival); two runs with the same fixed `at` produce identical hashes except RunID-dependent fields.

- [ ] **Step 2: Run and verify fail.**

- [ ] **Step 3: Implement** with one JSON object per line in the file, append-only writes with `O_APPEND`.

- [ ] **Step 4: Run and verify pass.**

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/carbanakledger/audit.go orchestrator/internal/carbanakledger/audit_test.go
git commit -m "feat(carbanak-ledger): hash-chained append-only audit log"
```

---

### Task 6: Ledger HTTP API, identity config, and the command entry point

**Files:**
- Create: `orchestrator/internal/carbanakledger/server.go`, `orchestrator/internal/carbanakledger/config.go`, `orchestrator/internal/carbanakledger/server_test.go`, `orchestrator/cmd/carbanak-ledger-sim/main.go`

**Interfaces:**
- Consumes: `Evaluate` (Task 4), `Log` (Task 5).
- Produces:
  - `type Identity struct { ID string; Roles []string; Host string }` (`Host` is the expected host label, checked against the connection source).
  - `func LoadConfig(path string) (Config, error)`; `Config` holds identities, window, limits, and `ListenAddr`.
  - `func NewServer(cfg Config, log *Log, now func() time.Time) http.Handler`.
  - Endpoints: `POST /session`, `POST /beneficiary`, `POST /transfer`, `POST /approve`, `PUT /limit`, `GET /audit?run_id=`, `GET /audit/verify?run_id=`, `GET /alerts?run_id=`.
  - Each mutating call returns `{decision, rule_fired, audit_hash}`.
- Trust model: the caller host is read from `r.RemoteAddr`, not the request body. Identity comes from the synthetic credential in the config.
- Listen rule: if `ListenAddr` host is not loopback, refuse unless env `BAS_CARBANAK_ALLOW_NONLOCAL=1` AND the configured hostname label ends `.test`, `.invalid`, or `.lab`. Otherwise return an error from `main`.
- Port in use: `main` exits non-zero with the message `ERROR: port <n> in use`.

- [ ] **Step 1: Write the failing `httptest` tests:** `POST /transfer` by a synthetic operator returns `{decision: "approved"}` when inside window and under limit; the same call with `now` at 20:00 IST returns `flagged` with `rule_fired: outside_operating_window`; `POST /approve` where approver == initiator returns `rejected` `maker_checker_self_approval`; a request body with a spoofed `host` field is ignored (decision unchanged); `LoadConfig` plus `ListenAddr: "10.0.0.5:8745"` without the override and without a `.lab` label returns an error (refusal test).

- [ ] **Step 2: Run and verify fail.**

- [ ] **Step 3: Implement the server, config loader, and `main.go`.**

- [ ] **Step 4: Run and verify pass.** Manual check: `go run ./cmd/carbanak-ledger-sim --config testdata/ledger.yaml` binds `127.0.0.1:8745`.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/carbanakledger/ orchestrator/cmd/carbanak-ledger-sim/
git commit -m "feat(carbanak-ledger): HTTP control API with loopback-only binding"
```

---

### Task 7: fraud_control verdict model and marker parsing

**Files:**
- Modify: `orchestrator/internal/scenario/outcome.go` (add `FraudControlRecord` and parsing) and the `SimulationResult` model that carries it (confirm exact file at task start; the spec defers the field mapping to this task)
- Test: `orchestrator/internal/scenario/fraud_control_test.go` (create)

**Interfaces:**
- Marker format: one line in step stdout, `BAS-FRAUD-CONTROL {json}`, with fields `step` (string), `expected_control` (`prevent` | `detect` | `verify`), `ledger_called` (bool), `ledger_decision` (`approved` | `rejected` | `flagged` | ""), `rule_fired` (string), `alert_present` (bool), `audit_intact` (bool, only for verify), `audit_hash` (string).
- Produces: `type FraudControlRecord struct { Verdict string; Reason string; Decision string; RuleFired string; AuditHash string }` with `Verdict` one of `PASS`, `FAIL`, `SKIPPED`.
- Verdict table:
  - `ledger_called == false` -> `SKIPPED`, reason `ledger not called`.
  - `prevent`: PASS if decision `rejected`; else FAIL.
  - `detect`: PASS if decision `flagged` or `alert_present`; else FAIL.
  - `verify`: PASS if `audit_intact`; else FAIL.
- Overall verdict (new): PASS iff endpoint PASS and fraud PASS; FAIL if either is FAIL; otherwise SKIPPED.

- [ ] **Step 1: Write the table tests** covering every row of the verdict table, plus the four overall combinations from the spec (PASS/PASS=PASS, PASS/FAIL=FAIL, FAIL/PASS=FAIL, FAIL/FAIL=FAIL) and the endpoint-blocked-ledger-not-called case (endpoint PASS, fraud SKIPPED, overall SKIPPED, not PASS).

- [ ] **Step 2: Run and verify fail.**

- [ ] **Step 3: Implement the parser and verdict functions.**

- [ ] **Step 4: Run and verify pass.**

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/scenario/outcome.go orchestrator/internal/scenario/fraud_control_test.go
git commit -m "feat(scenario): independent fraud-control verdict from BAS-FRAUD-CONTROL marker"
```

---

### Task 8: Replace stage 8 with the 7-step fraud sequence

**Files:**
- Modify: `scenarios/carbanak-kill-chain.yaml` (replace the Stage 8 step with steps 8a-8g)
- Test: `orchestrator/internal/scenario/carbanak_kill_chain_test.go` (extend)

**Interfaces:**
- Consumes: ledger HTTP API (Task 6), marker format (Task 7).
- Each step's command: read the shared run id from `%TEMP%\bas_carbanak_run.txt` (written by 8a, `Set-Content`), call the ledger at `http://127.0.0.1:8745` (or `BAS_CARBANAK_LEDGER_URL`), print the `BAS-FRAUD-CONTROL {json}` line. If the ledger is unreachable, print the marker with `ledger_called: false` and a SKIP line. If `BAS_CARBANAK_LEDGER_URL` points to a non-loopback host without a test label, refuse.
- Steps and `expected_control`: 8a `verify`-free (auth, reported as `detect`=not applicable; use `prevent` only where a rejection is the expected control, otherwise omit the marker's control and record auth result as endpoint-side evidence); 8b `prevent`; 8c `detect`; 8d `prevent`; 8e `prevent`; 8f `verify`; 8g `detect`.
- Cleanup for 8a: delete the run file. The chain never writes a decoy file.
- Note on 8a: the marker for auth carries `expected_control: prevent` only if the ledger is expected to reject a bad session; the auth step uses the synthetic valid credential, so its expected outcome is `approved` and its fraud verdict is recorded as evidence with verdict `SKIPPED` (not a control test). This is a Ruling, recorded in the QA log.

- [ ] **Step 1: Write the failing tests:** the chain has stages 1-7 plus 8a-8g in order; each of 8b-8g carries a `BAS-FRAUD-CONTROL` marker in its command; no step command contains `bas_carbanak_fraud_` (the decoy path is gone).

- [ ] **Step 2: Run and verify fail.**

- [ ] **Step 3: Write the 8a-8g steps** and update Stage 8's blast_radius and detection text.

- [ ] **Step 4: Run and verify pass; re-sign** `carbanak-kill-chain.yaml`.

- [ ] **Step 5: Commit**

```bash
git add scenarios/carbanak-kill-chain.yaml scenarios/carbanak-kill-chain.yaml.sig orchestrator/internal/scenario/carbanak_kill_chain_test.go
git commit -m "feat(carbanak): replace decoy stage with 7-step fraud sequence against the ledger"
```

---

### Task 9: Discovery and credential stages (items 10-15, 17-18)

**Files:**
- Modify: `scenarios/carbanak-kill-chain.yaml` (append stages)
- Test: `orchestrator/internal/scenario/carbanak_kill_chain_test.go` (extend)

**Interfaces:** each stage has `technique_id` from Task 2's register (`pending` rows must be validated first), `fidelity`, `production_safe`, `telemetry`, `detection`, `threat_intel_sources`, `command`, `cleanup`, with `[BAS-SIM-CARBANAK-Sn]` markers.

Stages: 10 payment gateway configuration discovery (T1083, read config file existence and paths only); 11 database server and service discovery (T1046, list service names and TCP listeners, no connection attempt); 12 domain privileged account enumeration (T1069.002, query group membership names); 13 network share discovery (T1135, `net view` names only); 14 Credential Manager access attempt (T1555.004, `cmdkey /list` target names only, never retrieve); 15 browser credential-store access probe (T1555.003, check file existence and metadata only, never open the DB); 17 Kerberos service account enumeration (T1558.003, `setspn -Q` only, no ticket request); 18 synthetic operator credential discovery (T1552, a file search for a synthetic marker file the scenario itself creates and deletes).

- [ ] **Step 1: Write the failing tests:** the eight stages exist with the register's technique IDs; each stage command contains no `ReadProcessMemory`, `CredRead`, `CryptUnprotectData`, `MiniDump`, or `VM_READ`; each has a `threat_intel_sources` entry.

- [ ] **Step 2: Run and verify fail.**

- [ ] **Step 3: Append the eight stages.**

- [ ] **Step 4: Run and verify pass; re-sign.**

- [ ] **Step 5: Commit**

```bash
git add scenarios/carbanak-kill-chain.yaml scenarios/carbanak-kill-chain.yaml.sig orchestrator/internal/scenario/carbanak_kill_chain_test.go
git commit -m "feat(carbanak): discovery and credential-access stages, safe tier"
```

---

### Task 10: Lateral movement and collection stages (items 19-22, 29-32)

**Files:**
- Modify: `scenarios/carbanak-kill-chain.yaml` (append stages)
- Test: `orchestrator/internal/scenario/carbanak_kill_chain_test.go` (extend)

**Interfaces:** same stage shape as Task 9.

Stages 19 SMB administrative share access (T1021.002, needs `BAS_CARBANAK_TARGET_HOST`, otherwise SKIP); 20 WinRM remote execution simulation (T1021.006, target host, SKIP otherwise); 21 remote service creation (T1569.002, target host, SKIP otherwise, service name prefixed `BAS-SIM-`, created then deleted); 22 remote scheduled task creation (T1053.005, target host, SKIP otherwise, task name prefixed `BAS-SIM-`, created then deleted); 29 financial document collection (T1005, synthetic documents created under `%TEMP%` by the scenario, then listed); 30 payment database staging simulation (T1074.001, synthetic data only, staged under `%TEMP%`, then removed); 31 archive financial records (T1560.001, archive the synthetic staging dir, then remove the archive); 32 HTTPS exfiltration simulation (T1041, `.invalid` domain, same pattern as APT29 stage 30).

- [ ] **Step 1: Write the failing tests:** the eight stages exist with register IDs; stages 19-22 print a SKIP line containing `BAS_CARBANAK_TARGET_HOST` when the variable is unset (test the guard by running the PowerShell guard logic, as the APT29 SKIP test does); stage 32's domain ends in `.invalid`.

- [ ] **Step 2: Run and verify fail.**

- [ ] **Step 3: Append the eight stages.**

- [ ] **Step 4: Run and verify pass; re-sign.**

- [ ] **Step 5: Commit**

```bash
git add scenarios/carbanak-kill-chain.yaml scenarios/carbanak-kill-chain.yaml.sig orchestrator/internal/scenario/carbanak_kill_chain_test.go
git commit -m "feat(carbanak): lateral movement and collection stages with SKIP gating"
```

---

### Task 11: Item 9 as a separate scenario

**Files:**
- Create: `scenarios/carbanak-bfsi-app-discovery.yaml` and `.sig`
- Test: `orchestrator/internal/scenario/carbanak_bfsi_app_discovery_test.go` (create)

**Interfaces:** one step, technique T1057, `attack_gap` unset. Separate from Stage 5, which is not modified.

- [ ] **Step 1: Write the failing test:** the file parses, has one step, technique `T1057`, `product_line: killchain`, and its command enumerates banking application names and prints the `EXEC` and `FAIL`/`PASS` lines in the Stage 5 style.

- [ ] **Step 2: Run and verify fail.**

- [ ] **Step 3: Create the file.**

- [ ] **Step 4: Run and verify pass; sign it** (`signer.go sign`).

- [ ] **Step 5: Commit**

```bash
git add scenarios/carbanak-bfsi-app-discovery.yaml scenarios/carbanak-bfsi-app-discovery.yaml.sig orchestrator/internal/scenario/carbanak_bfsi_app_discovery_test.go
git commit -m "feat(carbanak): banking application discovery as a separate scenario"
```

---

### Task 12: Items 23-28 as separate scenarios with fresh state

**Files:**
- Create: six files `scenarios/carbanak-bfsi-<slug>.yaml` and `.sig` for: `beneficiary-creation`, `amount-manipulation`, `unauthorized-approval`, `session-misuse`, `off-hours-transfer`, `limit-modification`
- Test: `orchestrator/internal/scenario/carbanak_bfsi_fraud_test.go` (create)

**Interfaces:**
- Each file: one step, `technique_id: ""`, `attack_gap: no_clean_attack_technique` for beneficiary-creation and limit-modification; validated IDs from the register for the other four. Each step starts a fresh run id and calls the ledger, emitting `BAS-FRAUD-CONTROL`.
- Ledger state is per run_id. The command's run id is generated fresh (never read from the shared chain file).

- [ ] **Step 1: Write the failing tests:** six files parse; the two gap files have empty technique and the gap reason; each command generates a fresh run id (contains `Get-Random` or a GUID, and does not read `bas_carbanak_run.txt`); each emits a `BAS-FRAUD-CONTROL` marker.

- [ ] **Step 2: Run and verify fail.**

- [ ] **Step 3: Create the six files.**

- [ ] **Step 4: Run and verify pass; sign each.**

- [ ] **Step 5: Commit**

```bash
git add scenarios/carbanak-bfsi-*.yaml scenarios/carbanak-bfsi-*.yaml.sig orchestrator/internal/scenario/carbanak_bfsi_fraud_test.go
git commit -m "feat(carbanak): six fraud-control scenarios with fresh ledger state"
```

---

### Task 13: Coverage exclusion

**Files:**
- Test: `orchestrator/internal/scenario/validation_profile_test.go` (extend, or create `carbanak_coverage_test.go`)

**Interfaces:** consumes the existing coverage function in `validation_profile.go` (it already skips empty `TechniqueID` from technique counts).

- [ ] **Step 1: Write the failing test:** load the Carbanak chain and the six gap-free and gap scenarios; the coverage technique total excludes the two `no_clean_attack_technique` steps (items 23 and 28); `proposed` rows are absent from the coverage input.

- [ ] **Step 2: Run and verify.** If it already passes because the existing code skips empty IDs, record that in the QA log and keep the test as a regression guard.

- [ ] **Step 3: Implement any missing exclusion** only if the test fails.

- [ ] **Step 4: Run and verify pass.**

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/scenario/carbanak_coverage_test.go
git commit -m "test(carbanak): gap steps excluded from ATT&CK coverage"
```

---

### Task 14: Registration, detection wiring, signing, step contract

**Files:**
- Modify: `orchestrator/internal/scenario/product_line_test.go` (scenario count constant)
- Modify: `orchestrator/internal/scenario/testdata/step_contract_ledger.json`, `step_contract_baseline.json` (regenerate)
- Modify: `orchestrator/internal/scenario/engine_test.go` (detection-profile wiring table for new stages, same pattern as the APT29 wiring test)

**Interfaces:** consumes all earlier tasks.

- [ ] **Step 1: Bump the count constant.** The current value at branch HEAD `88a6cd8d` is **152**. Add 7 for the new files: `carbanak-bfsi-app-discovery.yaml` plus six fraud-control files. Target: **159**, if no other scenarios are added before this task. Re-read the constant at task start.

- [ ] **Step 2: Add detection-profile wiring rows** for every new stage that names a profile.

- [ ] **Step 3: Regenerate the step contract:** `STEP_CONTRACT_WRITE=1 go test ./internal/scenario/... -run TestStepContract`. Confirm via `git diff` that only Carbanak entries changed.

- [ ] **Step 4: Run `go run scripts/signer.go verify-all ../scenarios`** and confirm `fail=0`.

- [ ] **Step 5: Run the full package:** `go test ./internal/scenario/... ./internal/carbanakledger/...`. Expected: green.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/scenario/product_line_test.go orchestrator/internal/scenario/engine_test.go orchestrator/internal/scenario/testdata/
git commit -m "chore(carbanak): register pack, detection wiring, step contract"
```

---

### Task 15: QA log and lab runbook

**Files:**
- Create: `docs/carbanak-bfsi-mastery-qa-log.md`, `docs/carbanak-bfsi-lab-runbook.md`

**Interfaces:** documents what was verified structurally and what awaits a lab run. Follows the convention in `docs/apt29-phase7-mastery-qa-log.md`.

- [ ] **Step 1: Write the runbook** covering: starting the ledger (command, port, `BAS_CARBANAK_FIXED_TIME` for determinism), setting `BAS_CARBANAK_TARGET_HOST`, the per-stage evidence checklist, and the endpoint-vs-fraud reporting check.

- [ ] **Step 2: Write the QA log** with the structural results, the Rulings made during the build (8a verdict treatment; any Task 4 window boundary choice), and blank lab result tables.

- [ ] **Step 3: Commit**

```bash
git add docs/carbanak-bfsi-mastery-qa-log.md docs/carbanak-bfsi-lab-runbook.md
git commit -m "docs(carbanak): BFSI pack lab runbook and QA log"
```

---

## Self-Review

1. **Spec coverage:** goals 1-5 map to Tasks 3, 8, 6-7 (two verdicts), 5 (audit), and the 23-item expansion across Tasks 9-12. Corrections (T1686.003, 0x1000) are Task 3. Operating window and fixed clock are Task 4 and Global Constraints. Acceptance criteria 1-15 map to Tasks 4-14.
2. **Step scan:** Tasks 9, 10, and 12 list stage contents as one line each, not full scripts. Implementers write the bodies from the register and the APT29 patterns.
3. **Type consistency:** `Decision`, `Action`, `Window`, `Row`, `Log`, `Identity`, `Config`, `FraudControlRecord`, and the `AttackGap` const are named once and referenced by the same names.
4. **Review Focus:** each of the five lines is pinned to a task (Tasks 7, 6/8, 12, 6, 5).

## Rulings (recorded for review)

- **8a verdict:** the auth step is evidence, not a control test, so its fraud verdict is SKIPPED.
- **Overall when ledger not called:** SKIPPED, not PASS (Review Focus 1).
- **Scenario granularity:** the chain file holds stages 1-7 plus 8a-8g and the 16 new stages. Items 9 and 23-28 are separate files, because item 9 is approved as separate and 23-28 need fresh state. This makes the scenario-unit count differ from the spec's "31"; the spec's count is in stage terms.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-11-17-carbanak-bfsi-expansion.md`. Nothing is executed yet.

**Before execution:** the plan has 15 tasks, and the later tasks depend on the Task 7 outcome-model seam. Tasks 1-6 can run first, independently of the scenario files.

Which execution approach do you prefer?
- **Subagent-driven:** a fresh subagent per task with a reviewer after each. Most thorough; more cost.
- **Native:** I implement each task here, then one fresh reviewer checks the whole branch. Cheaper; less per-task review.

I'd recommend **Subagent-driven**, because Task 7 is the riskiest seam and the fraud-control verdicts are the core of the requirement. Does the plan capture what you want, and which approach should we use?
