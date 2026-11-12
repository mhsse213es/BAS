# Scenario step contract: QA log

Initiative: enterprise scenario plan, step 1 (the cleanup contract). Stop point: remediation proposed, nothing applied.

## 2026-11-11: class-aware contract and measurement correction

**Scope of this entry.** The contract test and one additive schema field only. No scenario YAML was edited, no `.sig` was re-signed, and no execution path changed.

### Changes

- `orchestrator/internal/scenario/types.go`: added `Irreversible string` (yaml/json `irreversible`, omitempty). It is documentation for the contract. It never changes a step's execution class and never bypasses lab-gating. `gofmt` re-aligned two neighbouring lines.
- `orchestrator/internal/scenario/step_contract_test.go`: replaced the YAML-only ratchet with the class-aware contract.
  - Class comes from `ResolveExecutionClass(technique_id, action_key)`, which is the action catalog.
  - Non-destructive: no cleanup required.
  - Potentially destructive and destructive: an explicit undo (`cleanup` in the YAML), or `reversible: true`, or `irreversible` with a reason of at least 20 characters.
  - ART and Caldera steps: a cleanup in the YAML counts as repository-declared. Anything else is `gap_external_cleanup_unverified`, because the external library is not pinned and not in this repo.
  - Missing undo is fail-closed: `gap_no_undo`.
  - A per-step ledger (`testdata/step_contract_ledger.json`) accounts for every step, so a scenario change cannot shift the numbers silently.
- `orchestrator/internal/scenario/testdata/step_contract_baseline.json`: regenerated per file with the new cleanup counts.

### Tests

All in package `scenario`, run with `go test -run TestStepContract -v`:

| Test | Checks |
|---|---|
| `Ratchet` | Per-file counts may not rise against the baseline. A new file must have zero gaps. |
| `LedgerAccountsForEveryStep` | The ledger matches the current scenarios exactly (count and content). |
| `ThreeClasses` | Non-destructive (`T1003/enumerate`) is not required. Potentially destructive (`T1053.005/schtask_create_delete`) with no undo is a gap. Destructive (`T1490/vss_delete`) is a gap with no undo, and clears with a declared irreversibility. Unknown pairs fail closed. |
| `MissingUndoIsFailClosed` | A missing undo is a gap. A cleanup command, or self-cleaning, clears it. |
| `IrreversibleDeclaration` | A valid reason clears it. A blank reason counts as no declaration. A short reason (`n/a`) is `gap_irreversible_without_reason`. |
| `DeclarationDoesNotChangeClass` | Declarations do not change the catalog class. |
| `ARTCleanupIsExternallyUnverified` | An ART step with no YAML cleanup stays a gap. An ART step with a repository-declared cleanup does not. |
| `DetectionAndTelemetry` | Unchanged expectations from the earlier ratchet. |

Result: all eight tests pass on `step-contract-ratchet` in a worktree from `origin/main` (286cc09a). Before the baseline was regenerated, the ledger test failed as intended.

### Recalculated figures (517 steps in executable scenarios)

| Class | Status | Steps |
|---|---|---:|
| non-destructive | not required (no cleanup needed) | 446 |
| destructive | gap: external cleanup unverified (ART) | 25 |
| destructive | gap: no undo | 18 |
| destructive | self-cleaning declared | 12 |
| destructive | undo declared in YAML | 11 |
| potentially destructive | undo declared in YAML | 5 |

- **Acceptance 1, non-destructive steps not counted as gaps:** the 42 non-destructive steps that lacked a cleanup under the earlier measurement are now `not_required_non_destructive`. No non-destructive step is a gap.
- **Acceptance 2, destructive steps individually accounted for:** 43 gaps (25 + 18), each in the remediation table with its own row.
- **Acceptance 3, ART provenance explicit:** the 25 ART gaps are labelled `gap_external_cleanup_unverified`, and the table states that the library is not pinned.
- **Acceptance 4, fail-closed:** a missing undo is `gap_no_undo` for both the native and custom paths. Unknown action pairs classify as destructive.
- **Acceptance 5, no execution change:** the only production change is the additive field above.

The earlier figure of 85 was the sum of 42 non-destructive and 43 destructive steps measured with a YAML-only rule. The 43 is unchanged; the 42 is now correctly not a gap.

### Findings that need review before any remediation

1. **Ungated destructive commands.** `endpoint-mastery/em-07-ransomware-readiness.yaml` steps #6 and #7 run `vssadmin delete shadows /all /quiet` and `wbadmin delete catalog -quiet` with no `BAS_CONFIRM` environment gate. The other VSS and LVM steps do have gates. The step is intended to check whether EDR blocks the process, but if EDR does not block it, the step deletes shadow copies or the backup catalog on the host. This needs an urgent decision, separate from the cleanup work.
2. **Framework-less steps with no command (12 steps).** The kill-chain files `hunters-international-kill-chain`, `medusa-kill-chain` and `rhysida-kill-chain` have steps with no framework and no command in the YAML. Their action keys are either missing from the catalog (so they fail closed to destructive) or are present. I have not confirmed whether the runner executes them at all. Until that is confirmed, their classification and their cleanup status are not reliable.
3. **ART library is not pinned.** `docs/SBOM-CBOM-v1.7.3.md` records the Atomic Red Team YAMLs as `master` HEAD at build time. Pinning needs a commit hash and a change to the build input. This is not done here.

### Pending decisions

- Pin the ART library to a specific commit (changes the build input; needs your go-ahead, and the commit to pin).
- Approve each row of `reports/step-contract-remediation.md` before any scenario YAML is edited or re-signed.
- Decide on finding 1 (the ungated VSS and wbadmin steps) separately and first.

### Not verified

- Whether any step's cleanup actually reverses its effect on a real host.
- Whether the framework-less steps run at all.
- Whether any ART test's cleanup exists in the pinned library.

Each of these needs a lab host.


## 2026-11-11 (execution): approved remediation applied

Authorised by the approval with conditions. Nothing here is lab-verified. Every lab item is NOT VERIFIED.

### Changes applied

| File | Change | Re-signed |
|---|---|---|
| `scenarios/akira-kill-chain.yaml` | `irreversible` declared on step #11 (Stage 8). Lab gate `BAS_CONFIRM_VSS_DELETE` unchanged. | yes |
| `scenarios/black-basta-kill-chain.yaml` | `irreversible` declared on step #9. Gate unchanged. | yes |
| `scenarios/ransomware-drill.yaml` | `irreversible` declared on step #6. Gate unchanged. | yes |
| `scenarios/linux-ransomware-drill.yaml` | `irreversible` declared on step #1 (LVM). Gate `BAS_CONFIRM_LVM_DELETE` unchanged. | yes |
| `scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml` | Steps #6 and #7 changed from `vss_delete` / `wbadmin_delete_catalog` to `backup_readiness_check` (non-destructive). The `vssadmin delete` and `wbadmin delete` commands are removed. Each step now reads state only and prints PASS/FAIL/SKIP. Stage description updated. | yes |
| `orchestrator/Dockerfile` | ART fetch pinned to `a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6` via `ARG ART_COMMIT`. The build fails if the resolved HEAD differs. | n/a |
| `orchestrator/internal/scenario/execclass_test.go` | Removed `wbadmin_delete_catalog` from the corpus expectations. It no longer appears in any scenario, so the corpus guard could not find it. | n/a |
| `orchestrator/internal/scenario/execclass_wbadmin_test.go` (new) | Pins `wbadmin_delete_catalog` as destructive, fail-closed, directly. | n/a |
| `testdata/step_contract_baseline.json`, `step_contract_ledger.json` | Regenerated (`STEP_CONTRACT_WRITE=1`). | n/a |

Signatures: all 156 scenario `.sig` files pass `verify-all` (`ok=156 fail=0`). The five re-signed files used the release key from the main checkout. The key was not copied into the worktree. Verification was not weakened, and `--allow-dev` was not used.

### em-07 replacement: what it does and does not test

- Step #6 reads the VSS service, counts existing shadow copies (`Win32_ShadowCopy`) and checks Sysmon telemetry. It prints PASS if telemetry is enabled, FAIL if not, and SKIP if the state cannot be read.
- Step #7 reads the Windows Backup service state and checks Sysmon telemetry, with the same verdicts.
- **Neither step tests whether EDR blocks `vssadmin` or `wbadmin`.** The PASS line says so. This is a proxy for visibility, not a control test. Calling it "EDR validated" would overstate it.
- The telemetry and detection lists still describe the behaviour the detection rule targets. They do not describe what the step generates now.

### Measured after the change (517 steps)

| Status | Count |
|---|---:|
| not_required_non_destructive | 448 |
| gap_external_cleanup_unverified (ART) | 25 |
| gap_no_undo (framework-less, unchanged) | 12 |
| undo_declared_in_yaml | 16 |
| self_cleaning_declared | 12 |
| irreversible_declared | 4 |

Destructive gaps: 37 (from 43). Two left the gap list by reclassification, because they are now read-only. Four left by declaration. Neither reduction came from an undo or from weakening the rule.

### ART pin: per-step check (against `a0e3f9bc`)

The library was fetched at the exact commit and every destructive ART step was checked individually. The check looks for a `cleanup_command` in the test's executor at that commit.

- **16 of 25 steps** have a `cleanup_command` at the pin.
- **9 of 25 steps** have none. These stay gaps.

**"Present at pin" is not "verified".** It means a cleanup string exists. It does not show that the cleanup reverses the action, that it runs cleanly, or that it works on a real host. The contract still counts all 25 as gaps, which matches your instruction: no manifest, and no marking all 25 as verified because the library is pinned. Recording the 16 present-at-pin steps as externally verified needs a decision on where that record lives.

| Scenario | # | Technique | Test | Atomic name (at pin) | cleanup_command at pin |
|---|---:|---|---:|---|---|
| `dll-hijack-execution.yaml` | 3 | T1574.011 | 0 | Service Registry Permissions Weakness | NO |
| `dll-hijack-execution.yaml` | 4 | T1574.011 | 1 | Service ImagePath Change with reg.exe | yes |
| `dll-hijack-execution.yaml` | 5 | T1574.012 | 2 | Registry-free process scope COR_PROFILER | yes |
| `outlook-rules-bec.yaml` | 0 | T1137.005 | 3 | Outlook Rules - Enumerate Existing Rules via PowerShell COM Object | yes |
| `outlook-rules-bec.yaml` | 1 | T1137.005 | 0 | Outlook Rule - Subject Trigger with DeletePermanently Action via COM Object | yes |
| `outlook-rules-bec.yaml` | 2 | T1137.005 | 1 | Outlook Rule - Sender Address Trigger with DeletePermanently Action via COM Object | yes |
| `outlook-rules-bec.yaml` | 3 | T1137.005 | 2 | Outlook Rule - Auto-Forward Emails to External Address via COM Object | yes |
| `outlook-rules-bec.yaml` | 4 | T1137.005 | 4 | Outlook Rule - Create Rule with Obfuscated Blank Name (MAPI Evasion) | yes |
| `ubuntu-hardening-validation.yaml` | 3 | T1547.006 | 0 | Linux - Load Kernel Module via insmod | yes |
| `ubuntu-hardening-validation.yaml` | 4 | T1548.001 | 0 | Make and modify binary from C source | yes |
| `ubuntu-hardening-validation.yaml` | 5 | T1548.001 | 1 | Make and modify binary from C source (freebsd) | yes |
| `ubuntu-hardening-validation.yaml` | 6 | T1548.001 | 2 | Set a SetUID flag on file | yes |
| `ubuntu-hardening-validation.yaml` | 7 | T1548.001 | 3 | Set a SetUID flag on file (freebsd) | yes |
| `ubuntu-hardening-validation.yaml` | 8 | T1548.001 | 4 | Set a SetGID flag on file | yes |
| `ubuntu-hardening-validation.yaml` | 9 | T1548.001 | 5 | Set a SetGID flag on file (freebsd) | yes |
| `ubuntu-hardening-validation.yaml` | 10 | T1548.001 | 6 | Make and modify capabilities of a binary | yes |
| `ubuntu-hardening-validation.yaml` | 11 | T1548.001 | 7 | Provide the SetUID capability to a file | yes |
| `ubuntu-hardening-validation.yaml` | 12 | T1548.001 | 8 | Do reconnaissance for files that have the setuid bit set | NO |
| `ubuntu-hardening-validation.yaml` | 13 | T1548.001 | 9 | Do reconnaissance for files that have the setgid bit set | NO |
| `ubuntu-hardening-validation.yaml` | 14 | T1548.003 | 0 | Sudo usage | NO |
| `ubuntu-hardening-validation.yaml` | 15 | T1548.003 | 1 | Sudo usage (freebsd) | NO |
| `ubuntu-hardening-validation.yaml` | 16 | T1548.003 | 2 | Unlimited sudo cache timeout | NO |
| `ubuntu-hardening-validation.yaml` | 17 | T1548.003 | 3 | Unlimited sudo cache timeout (freebsd) | NO |
| `ubuntu-hardening-validation.yaml` | 18 | T1548.003 | 4 | Disable tty_tickets for sudo caching | NO |
| `ubuntu-hardening-validation.yaml` | 19 | T1548.003 | 5 | Disable tty_tickets for sudo caching (freebsd) | NO |

### NOT VERIFIED (lab items)

- Running any of the four irreversible steps, and the em-07 replacements, on a lab host.
- That any ART cleanup actually reverses its test.
- The Docker build with the pinned `ARG ART_COMMIT`. The fetch by commit was checked by hand. The full image build was not run.
- `TestExecutionClassifications_ARTCalderaCorpusFullyResolved` is **skipped**. It needs `DATABASE_URL` and `CALDERA_URL` (the live stack), so the ART/Caldera corpus gate has not run here.
- Whether the 12 framework-less kill-chain steps (hunters-international, medusa, rhysida) execute at all. Left unchanged, as you directed. They stay explicitly unresolved.

### Test results

- `go build ./...` (orchestrator): OK
- `go vet ./internal/scenario/`: OK
- `go test ./internal/scenario/`: **ok** (one live-stack test skipped, listed above)
- `TestStepContract_*`: all 6 pass.

### Not committed

The changes are in the worktree `.claude/worktrees/step-contract` on `step-contract-ratchet`, uncommitted, pending your go-ahead.

## 2026-11-12: Akira kill chain, three approved changes (akira-kill-chain.yaml)

Branch `step-contract-ratchet` (worktree). NOT committed. Nothing here is lab-verified.

### Behavioural changes

- **Stage 3, SAM and SYSTEM hive copy (`akira-s3-sam-theft`).** The verdict logic is unchanged: a saved hive prints FAIL, a blocked save prints PASS. Changed: `fidelity: lab-only`, `production_safe: false`. The blast radius now says SAM and SYSTEM together give the material for offline password-hash extraction, since the bootkey is in SYSTEM. It says that deleting the copies does NOT undo the exposure. The earlier text claimed the SAM hive was unusable without the bootkey, which was wrong.
- **Stage 3b, LSASS handle probe (`akira-s3b-lsass-probe`).** Was: `PROCESS_QUERY_LIMITED_INFORMATION` (0x1000), with EXEC and INFO lines and no verdict token, so it always scored PASS. Now: `PROCESS_VM_READ` (0x10), opened and closed at once, with no memory read. Granted prints FAIL. Denied prints PASS. Missing LSASS or a helper-compile failure prints SKIP. The EXEC and INFO lines are removed. Changed: `fidelity: lab-only`, `production_safe: false`.
- **Stage 4, Defender exclusion (`akira-s4-defender-exclusion`).** Was: a stub that built `$cmdLine` but never ran it, and claimed EID 4104/4688 telemetry. Now: a read-only `Get-MpPreference` check. TEMP excluded prints FAIL. Not excluded prints PASS. Unreadable preferences print SKIP. Telemetry expectation is now none (`expected_telemetry_count: 0`). The step is renamed to "Configuration Check".

### What the changes do NOT claim

- Stage 3b shows only whether a handle with PROCESS_VM_READ can be obtained. It does NOT show that credentials could be dumped.
- Opening a VM_READ handle to LSASS triggers EDR alerts by design. The step is lab-only and requires explicit lab authorization.
- A denied handle can have causes other than a control: a PPL or Credential Guard block, or some other access failure. The PASS text states only that the handle-access control was in effect.
- The Stage 4 check reads configuration. It does not test whether Defender logs an exclusion change.
- Stage 3 keeps its existing verdict logic as approved. A reg.exe failure that is not a block will also print PASS. That is a known limitation of the approved design, not a fixed defect.

### Verification

- Re-signed with the release key. `verify-all` ok=156 fail=0.
- Each of the three commands parses as PowerShell (`Parser.ParseFile`).
- The orchestrator builds. The contract tests and the scenario package pass.
- Test pin updated in `engine_test.go` for the renamed Stage 4 step.
- The 14 API tests that reference Akira pass. The full API suite was not rerun for this change; it previously showed two environmental failures under shared-database contention.
- NOT VERIFIED: all three steps need lab execution. Lab execution of Stage 3b must be authorised explicitly.

### Left unchanged, per approval

Other Akira stages, including the exfiltration POST (5b), the ransomware simulation (6, 6b), the VSS enumeration and deletion (7, 8), the survival and recovery probes (8b, 8c), and the log clear (9). These need separate review before any change.

## 2026-11-12: Akira Stages 5b, 6 and 9 (akira-kill-chain.yaml)

Branch `step-contract-ratchet` (worktree). NOT committed. NOT VERIFIED on a lab host.

### Verdict semantics, changed

A blocked operation is PASS only with positive evidence of a control denial. An arbitrary failure is never evidence of protection.

| Step | Outcome | Verdict (before, as written) | Verdict (now) |
|---|---|---|---|
| 5b exfil POST | Successful POST | FAIL | FAIL |
| 5b | Explicit HTTP 403 | PASS (any exception was PASS) | PASS |
| 5b | Unfilled `{{SINK_URL}}` / token | sent to a literal placeholder, PASS | SKIP, nothing sent |
| 5b | DNS, TLS, timeout, sink down, other error | PASS "blocked or failed" | SKIP |
| 6 ransom sim | Write succeeds | FAIL | FAIL |
| 6 | Explicit access denied | PASS (any failure was PASS) | PASS |
| 6 | Any other error | PASS | SKIP |
| 9 log clear | Exit 0 and log confirmed empty | FAIL (based on text match only) | FAIL |
| 9 | Explicit access denied | PASS (text match only) | PASS |
| 9 | Other failure, or channel not created | PASS or SKIP (text match) | SKIP |

### Stage 5b, exfiltration POST

- The `{{SINK_URL}}` and `{{SINK_TOKEN}}` placeholders are filled only for sink-wired runs (`internal/api/dlp_sink.go`). An unfilled placeholder now SKIPs and sends nothing.
- Nothing is sent unless the sink host is in the `BAS_SINK_ALLOWED_HOSTS` environment variable (comma-separated). The variable must be set explicitly for each lab run. Without it the step SKIPs.
- The reachability probe is removed. It was a second send with no verdict. The `abort_on` text now matches the behaviour.
- `production_safe: false`, `fidelity: lab-only`.

### Stage 6, ransomware simulation

- Writes now go to a dedicated, freshly named workspace (`bas_akira_ws_<runId>`) under `%TEMP%`. An existing workspace is refused. The finally block removes only that workspace, so cleanup runs after errors too.
- Only synthetic content is used.
- `production_safe` stays `true`. The approval allowed this only if these conditions are verified in the implementation. They are verified by reading the code. They are not verified by running it.
- Cleanup in the YAML also removes the new workspace pattern.

### Stage 9, log clear

- The temporary channel `BAS-Sim-Akira` is removed in a finally block, including after errors and after the exception path.
- If the channel still exists after removal, the step prints `CLEANUP FAILED: ... Manual removal required`. The step never leaves the channel behind silently.
- Clear success is decided by the exit code and by a record count of 0. The text match is gone.
- `production_safe: false`, `fidelity: lab-only`.
- Limitation: if the PowerShell process is killed mid-run, the finally block does not run. The YAML cleanup then runs, but it cannot report a failure.

### Verification

- Re-signed with the release key. `verify-all` ok=156 fail=0.
- All three commands parse as PowerShell (`Parser.ParseFile`).
- The contract tests, the scenario package, the orchestrator build and the 14 related API tests pass.
- Not run on any host. All lab status is NOT VERIFIED.

### Noticed, not changed

- Stage 8c (`akira-s8c-recovery-probe`) has INFO-only branches that print no verdict token, so they score PASS on exit 0. It is outside this approval and needs its own review.
- Stage 6b (mass rename) and the Stage 5c and 7 probes are still unreviewed.

## 2026-11-12: Akira Stages 6b and 8c, plus Stage 7 hold (akira-kill-chain.yaml)

Branch `step-contract-ratchet` (worktree). NOT committed. NOT VERIFIED on a lab host.

### Stage 6b, mass-rename fan-out

| Outcome | Verdict (before) | Verdict (now) |
|---|---|---|
| One or more files written or renamed | FAIL only if both written and renamed | FAIL |
| Explicit access denied, nothing written or renamed | PASS (any failure was PASS) | PASS |
| Any other error or ambiguous result | PASS | SKIP |
| Existing workspace found | not checked | SKIP, nothing reused |

- Renames now run with `-ErrorAction Stop`. Before, their errors were suppressed, so denied renames looked like successes.
- The workspace is fresh and uniquely named. It is removed in a finally block, and only if this run created it.
- `production_safe: true` kept. Content is synthetic, writes are confined to the new workspace, and existing files cannot be overwritten. Verified by reading the code, not by running it.

### Stage 8c, recovery-config probe

| Outcome | Verdict (before) | Verdict (now) |
|---|---|---|
| bcdedit recovery state unreadable | INFO, no token, PASS on exit 0 | SKIP |
| recoveryenabled = No | FAIL | FAIL |
| backup catalog unreadable | INFO, no token, PASS on exit 0 | SKIP |
| backup catalog visible | INFO, no token, PASS on exit 0 | FAIL |
| recovery enabled and no catalog visible | PASS | PASS (positive read) |

- Read-only throughout. Still `production_safe: true`.
- The FAIL on a visible catalog is a posture decision. It matches the convention of Stage 7. It is not an attack success.

### Stage 7, VSS enumeration: HELD

Unchanged. Its PASS branch also covers a failed `vssadmin` call, which is the same false-pass class. It joins the separate scoring-correction change, together with the held VSS enumeration step in `ransomware-drill.yaml`.

### Verification

- Re-signed with the release key. `verify-all` ok=156 fail=0.
- Both commands parse as PowerShell.
- The contract tests, the scenario package, the build and the 14 related API tests pass.
- Not run on any host.
