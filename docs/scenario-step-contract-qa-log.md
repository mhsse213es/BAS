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

## 2026-11-12: Remediation batch (worktree, NOT committed, NOT VERIFIED on a lab host)

Each change was re-signed with the release key; `verify-all` ok=156 fail=0. Score impact is listed per change, since these steps' customer-facing verdicts move.

1. **cscrf-mii-drill step 8 (Security log clear).** Now `action_key: clear_real_security_log_gated` (already destructive in the catalog). `reversible: false` with an `irreversible` reason. Flag unset: SKIP and runs nothing (the old output claimed telemetry that was never generated). Flag set: FAIL only if exit 0 and an EID 1102 is confirmed; explicit denial PASS; otherwise SKIP. Score impact: previously PASS-by-default; now FAIL when the clear actually happens.
   - Ledger regenerated with STEP_CONTRACT_WRITE=1. Baseline also changed for outlook-rules-bec (detection/telemetry 5 to 0), a recorded improvement from the earlier approved detection/telemetry change.
2. **full-scan steps 15-17.** Previously always PASS. Run key: FAIL if a value points into a user-writable path (AppData, Temp, Downloads, Public). Startup folder: FAIL if any item is present (review). Non-system services: FAIL if any are running (review). Score impact: these can now fail. Decision: conservative FAIL-for-review, my recommendation.
3. **Verdict-token form (21 lines, 4 files).** `SKIP T...:`, `FAIL [CSCRF-x]:` and `FAIL (CRITICAL):` do not match the interpreter's `WORD:` form, so with exit 0 they scored PASS. Rewritten to `WORD: ID ...`. Affects dcsync (8 SKIP lines, now SKIP instead of PASS), cscrf-mii-drill (6 lines, now FAIL/PASS as written), exposure-validation (4 FAIL lines, now FAIL instead of PASS), akira (3 SKIP lines). Regression test `TestVerdictTokens_ExactForm` added.
4. **ubuntu-hardening-validation.** Step 21 (/proc/1/mem): read at offset 0 normally fails with I/O error, so any failure was PASS. Now FAIL on success, PASS only on explicit Permission denied / Operation not permitted, else SKIP. Scope note: PID 1 is root-owned, so the denial may come from file ownership rather than Yama ptrace_scope; the verdict does not claim which control. Step 23 (auditd stop): PASS only on an explicit denial message; the old PASS claimed specific controls with no evidence. Step 26 (mount): same rule. Cleanup previously ran `losetup -D` (every loop device on the host); now detaches only devices backed by bas_usbsim_ images.
5. **cis-ubuntu-l1, six checks** (SSH Protocol, telnetd, rsh-server, tftpd-hpa, sudo logfile, empty passwords). Each had no verdict logic: its `|| echo` fallback guaranteed exit 0, so every one scored PASS. Each now decides PASS/FAIL from the state; unreadable or missing tools SKIP. Score impact: these can now FAIL. Sudo logfile FAIL follows the CIS definition (Ubuntu sudo otherwise logs to syslog).
6. **Command-less steps.** hunters-international (9), medusa (10), rhysida (11) have no command, so each SKIPs with "No command defined". Left `executable: true`: setting it false would remove 30 gaps from the step-contract measurement without any coverage change. Open gap: build real commands or retire these steps.
7. **VSS enumeration (held item, resolved).** akira Stage 7 and ransomware-drill "VSS + Backup Catalog Enumeration": shadows present with exit 0 = FAIL (posture finding); none = PASS; explicit denial = PASS; other = SKIP. The ransomware-drill step previously printed no verdict at all and always scored PASS. Medusa and rhysida VSS steps are command-less (see 6).

### Still open
- Ransomware group: blackcat, ransomhub, volt, black-basta, fin8, apt29, clop (not reviewed in this batch).
- AV/NGAV (22 files), common/cloud (24), endpoint-mastery (14), detection profiles.
- dlp-exfiltration-multichannel archive/shared/HTTPS/DNS/SFTP/SMTP steps.
- Thin scenarios (34) and detection/telemetry backfill (40/39 files), which needs per-file approval.
- Lab verification of every changed step.

## 2026-11-12: Tokenless verdict sweep (worktree, NOT committed, NOT VERIFIED on a lab host)

Method: every executable or local_check step whose command prints no PASS/FAIL/SKIP/ERROR token scores PASS on exit 0. Each was given a verdict or an explicit SKIP reason. Re-signed; verify-all ok=156 fail=0; scenario tests pass.

- **av-ngav-assessment (15 steps).** Primary steps: FAIL if the test artifact is retained; PASS only on an explicit block or a Defender detection record for that path; otherwise SKIP. Counterpart steps: FAIL on a false positive (benign artifact blocked or removed), PASS when not blocked. Run-key, scheduled-task and high-I/O steps follow the same rules.
- **Telemetry-only probes (apt36, evasion, insider, lolbin-coverage, upi, windows-discovery, acl context).** SKIP with a reason. No control outcome exists to score.
- **cscrf-mii-drill steps 1 and 4.** Real posture verdicts: management ports reachable on localhost is FAIL; no audit subcategory enabled is FAIL.
- **cis-ubuntu-l1 (32 checks).** Each compares the live value to the CIS value (sysctl, mount options, sshd -T, services, login.defs, cron.allow, journald, /var/log permissions, UFW, AppArmor). Unreadable values SKIP.
- **Inventory (linux/windows-installed-software).** SKIP: inventory only.

Score impact: many steps that previously PASSed on exit 0 can now FAIL or SKIP. This is intentional and must be reviewed before the next build.

### Not changed, with reasons
- **DLP sink-verified steps (about 61).** Their grade is server-side: `dlpVerifier` (internal/reporting/dlp.go) uses `SinkTokenObserved` as authoritative. Their missing token is by design, not a false PASS. Their `production_safe: true` label is a separate question: they POST synthetic regulated-shaped data to the registered sink. Akira 5b was made lab-only with an allow-list guard. Decide whether the same applies here.
- **lolbin-execution-coverage #12 and lolbin-execution #1 (wmi executor), lolbin-execution #2 (mshta).** Their executor is not PowerShell, so the verdict path is unconfirmed. The mshta payload `vbscript:window.close` looks malformed. Left as open.
- **30 command-less steps (hunters-international, medusa, rhysida).** Still open: building real commands needs design.
- **Thin scenarios (34) and detection/telemetry backfill.** Still open: these add content and need your approval per file.
- **Platform-wide default (tokenless exit-0 = PASS).** Still open: a scoring-model decision for you.

## 2026-11-12: Open decisions, taken

1. **Platform default (interpreter.go `interpretCustom`). REVERTED, not shipped.** I tried changing an exit-0 step with no verdict token from PASS to SKIP. The full internal/api run showed three ransomware-evidence tests failing (TestRWContainment_ContainedVendorStatusPasses, TestRWDetection_ConfiguredConnectorVerifiesWithProvenance, TestRWDetection_FallbackTimestampIsNeverQueriedAsEventTime). The detection capability only verifies steps that reach a verdict, so telemetry-only probes would stop being checked by the connector. That is a real regression. The default is restored to HEAD. Tokenless steps are handled per step in the scenario files instead. Open: decide how telemetry-only probes should reach the detection verifier without scoring as PASS.
2. **DLP sink steps (production_safe true).** Kept. The destination is the platform's own sink from the server-side target registry, which is the operator-configured allow-list. Akira 5b was made lab-only because its step text carried an unfilled URL, not a registry sink. Revisit if the registry can point at an external host.
3. **Non-PowerShell steps.** The wmi steps run their command inside an inner PowerShell (agent/executor_windows.go), so they fall under decision 1 and SKIP. The mshta step (`vbscript:window.close`) runs the string as an mshta argument; it now SKIPs by default. Its payload looks like a placeholder and needs a content review.
4. **30 command-less steps (hunters-international, medusa, rhysida).** Left as recorded gaps. Each SKIPs with "No command defined". Building real commands is attack-simulation design work that should be lab-validated, so it is not done here.
5. **Thin scenarios and detection/telemetry backfill.** Not done. Detection and telemetry expectations describe what a SOC should see. Writing them without a source would be invented evidence, so they need a sourced reference per technique first.
6. **Lab verification.** Not possible from this environment. Pending lab access.

## 2026-11-12: AD read-only vertical slice (worktree, NOT committed, NOT VERIFIED on a domain)

Scope: the five read-only AD audits. DCSync audit unchanged. DCSync live verification untouched (lab approval required, deferred). ADCS ESC classes were confirmed from `orchestrator/internal/adenv/adcs_predicates.go` and the scenario's own PowerShell before splitting. Nothing was added that the code does not already evaluate.

### Steps split (existing logic, no new evaluation)

| File | Steps before | Steps after | Split |
|---|---:|---:|---|
| adcs-esc-template-exposure-audit | 1 | 10 | ESC1, ESC2, ESC3, ESC4, ESC5, ESC7, ESC9, ESC11, ESC13, ESC15 |
| kerberos-delegation-exposure-audit | 1 | 3 | A unconstrained (non-DC), B constrained targets, C RBCD attribute set |
| rbcd-configure-exposure-audit | 1 | 2 | A MachineAccountQuota above 0, B computer objects writable by non-tier-0 |
| gpo-writable-linked-exposure-audit | 1 | 2 | A linked at domain root, B linked to OU or site |
| trust-sid-history-exposure-audit | 1 | 2 | A forest-transitive trust without quarantine bit, B populated sIDHistory |

Total steps in these five files: 5 to 19. Step-contract ledger 517 to 531. Contract gap counts unchanged (`step_contract_baseline.json` identical): every new step is an enumeration with no action key, so no undo is required.

### Verdict changes (the score-delta record, step level)

These are the verdict-level differences from the original single-step files. Customer-facing scores have NOT been measured; they change only in a real run.

1. **ADCS ESC5 and ESC7, failed query: PASS to SKIP.** The original ESC7 block was inside `catch {}`, so an unreadable CA object set produced no finding and therefore PASS. Each now sets an explicit ok flag and SKIPs when the read fails or no CA objects exist.
2. **ADCS ESC13: never FAIL.** The original counted template-level issuance-policy preconditions and OID objects toward the aggregate FAIL, but its own comment says group linkage is "verified below" when it is not. The step now SKIPs with the evidence listed and "manual correlation required".
3. **ADCS ESC9: flag value corrected, 0x400000 to 0x80000.** CT_FLAG_NO_SECURITY_EXTENSION is 0x00080000 in msPKI-Enrollment-Flag. Source: [MS-CRTD section 2.26 msPKI-Enrollment-Flag](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1), the [MS-CRTD errata](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-winerrata/6898053e-8726-4209-ade2-37f8b0474c99), and the Locksmith check of 0x80000 in [Set-NoSecurityExtension.ps1](https://www.powershellgallery.com/packages/Locksmith2/2026.3.26.1044/Content/Private%5CSet%5CSet-NoSecurityExtension.ps1). This can change ESC9 verdicts on a real domain in either direction, so it needs a lab run.
4. **RBCD quota unreadable: PASS to SKIP.** The original defaulted the quota to 0 when the attribute was unreadable, and then reported PASS. The step now SKIPs and says "not treated as 0".
5. **RBCD A (new FAIL-capable step): quota above 0.** A domain whose quota is above 0 with no writable computers was PASS before and is FAIL now. The quota is the same attribute the original already used, but its FAIL on its own is a new verdict. Flagged for your review.
6. **GPO: "populated scope" removed from the wording.** The original PASS text said "linked to a populated scope", but the code only checks that a link exists. The text now says only what is checked.
7. **ADCS ESC7: ManageCA and ManageCertificates NOT evaluated.** The original comment said these were control rights, and the code checks only standard write bits. The description and PASS text now state this.
8. **Trust A: "SID filtering" wording narrowed.** The check is the quarantine bit in trustAttributes. Its meaning for forest trusts is NOT VERIFIED in a lab.

Kerberos and trust splits carry the same underlying checks as before, so the verdict on a domain is unchanged in both directions apart from the way the findings are grouped.

### Verification done here

- All 19 new PowerShell commands parse with the PowerShell parser (0 errors). Two parse errors found during the work (unbraced `$cn:` and `$caDN:` in double quotes) were fixed before signing.
- All five files re-signed with `orchestrator/private_key.pem` (read from the main checkout; no key copied into the worktree). `verify-all ../scenarios`: ok=156 fail=0.
- `go test ./internal/scenario/`: ok, including `TestVerdictTokens_ExactForm`, `TestStepContract_*` (after ledger regeneration with `STEP_CONTRACT_WRITE=1`) and `TestBuiltinScenarios_AllHaveValidProductLine`.
- **Fail-closed on a non-domain host:** each of the 19 commands was run on this machine (not domain-joined). All 19 printed a SKIP with a reason and no PASS or FAIL.

### NOT VERIFIED (requires a domain or an isolated lab)

- Any FAIL or PASS on a real domain. Positive evidence (a planted misconfiguration that the step reports) has not been produced.
- ESC9 verdicts after the flag correction (item 3).
- Trust quarantine bit meaning for forest trusts (item 8).
- Whether the PowerShell ADSI calls return the expected objects on a real AD CS deployment (for example `$tmpl.Properties` value types).
- The score impact of items 1 to 5 on customer-facing scores.

### Deferred within this slice (not implemented, needs a decision)

- DCSync: checking non-default principals holding DS-Replication rights needs a lab-confirmed allow-list of default holders. Not added.
- Kerberos: privileged-account, service-account, stale and cross-domain delegation (no evaluation exists).
- GPO: ownership, security filtering, enforcement and inheritance (no evaluation exists).
- Trust: per-trust direction and type analysis (no evaluation exists).
- ADCS: ESC6 and ESC8 (CA host and network properties, out of scope), ESC10 (comment only, never implemented), ESC12 and ESC14 (not present in code).

### Not committed

The five scenario files, their `.sig` files, the regenerated ledger and this log entry are uncommitted in the worktree. Commit only when asked.

### Addendum: RBCD A wording (accepted by the user)

RBCD A keeps its FAIL on the quota above 0, but the title and evidence now say what was measured: a machine-account quota exposure (ms-DS-MachineAccountQuota above 0). The step reads the domain attribute only. It does not show that RBCD is configured or exploitable, and that is assessed by step B. The ESC9 flag change (0x80000, MS-CRTD §2.26) is accepted by the user.

## 2026-11-12: hygiene and DLP simulated-upload label (worktree, NOT committed)

### Hygiene
- gofmt: 65 committed Go files were not gofmt-clean. The other flags were CRLF working copies (`core.autocrlf=true`), not committed content. 64 files were formatted with `gofmt -w` (262 insertions, 253 deletions ignoring line endings). `orchestrator/cmd/server/main.go` was deliberately left alone because another session has uncommitted work in it on the main checkout.
- go.mod: `go mod tidy` moved three modules that the code imports directly from indirect to direct (`github.com/aws/aws-sdk-go-v2/service/organizations`, `github.com/aws/smithy-go`, `go.opentelemetry.io/otel/trace`). go.sum unchanged.

### DLP simulated upload (dlp-exfiltration-browser-upload)
- The step name now carries `[simulated_upload]`, and the description states that this is a scripted HTTP multipart request, not a drag-and-drop or any other user gesture.
- Both EXEC output lines carry `simulated_upload` and state that no user gesture or browser interaction occurred. The `[BAS-SIM-DLP-BROWSER-UPLOAD]` tag is kept because the fixture test requires it.
- The sink's `channel` field still sends `browser-upload`. It is a correlation key used by `internal/dlpcorrelate` tests and the sink, so changing it is a contract change and was not done here. Reports built from that channel value may still read as a browser upload. This is recorded as an open item.
- The fixture catalogue (`internal/dlpfixture/catalog.go`) was updated to the new step name.
- Re-signed; verify-all ok=156 fail=0.

### Tests
- `go build ./...`, `go vet` on internal/scenario and internal/api: clean.
- `go test` on internal/dlpfixture, internal/dlpcorrelate, internal/scenario: ok. The internal/api subset matching DLP, sink and browser: ok.
- Full internal/api suite NOT rerun for these two batches (gofmt and labels only).

### NOT VERIFIED
- The reporting path that renders the `browser-upload` channel value (see open item above).

### Addendum: DLP sink channel renamed (option 2, approved)

- The scenario now sends `channel=simulated-upload` instead of `browser-upload`. The step name, description and output already say simulated upload.
- Updated: the sink-parse test (`internal/api/dlp_sink_parse_test.go`), the correlation tests and comment (`internal/dlpcorrelate/channelconsistency*.go`). The token string `tok-browser-upload` is a test token and is unchanged.
- Existing rows in `dlp_sink_receipts` keep `browser-upload`. The table is append-only, and no rows were rewritten. Any report built from them still shows the old value.
- The sink does not validate the channel value, so old and new values are both accepted.
- Targeted tests (DLP fixture, correlation, scenario, sink) pass; signatures verify 156/0. The full internal/api suite is rerun after this change.

## 2026-11-13: AD check hotfix from the lab baseline (worktree, NOT verified on a domain)

Found by running the AD checks on the lab DC (`lab.local`, baseline with nothing planted). Fixes are in the generator and the scenario files.

### Defects fixed

| # | Defect | Effect before | Fix |
|---|---|---|---|
| 1 | The write mask included read bits (ReadControl), so any read ACE matched | False FAILs: ESC4 (33 templates), ESC5 (5 PKS objects), ESC7 (Authenticated Users), GPO-A, GPO-B | Mask set to write bits only: 0x500C0020 (GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty) |
| 2 | RBCD-B matched every write ACE, including default SELF ACEs on other attributes | False FAILs on WS01 and the DC computer object | Counted only when the ACE covers all attributes or msDS-AllowedToActOnBehalfOfOtherIdentity |
| 3 | ESC4 finding named no principal | Could not be checked against the evidence rule | Finding now lists the write-holding SIDs (`write-by=`) |
| 4 | ESC11 FAILed on the template RA-signature count, which is not the ESC11 weakness (that is the CA-level RPC enforcement state) | False FAILs on 8 default templates | Now SKIP when the template precondition is present; never FAIL. Not scored |
| 5 | ESC13 EXEC line said "precondition present" when only OID objects were found | Overstated wording | Wording changed to "review" |
| 6 | DCSync audit command did not parse (em-dash inside a double-quoted string, which PowerShell 5.1 reads as a smart quote) | Step could not run | Em-dashes in the command replaced with hyphens |
| 7 | exposure-validation step 0 had `\"` inside a double-quoted string, which ended the string early | Step could not run | Changed to `""` (PowerShell escape). Pre-existing, not from this branch |

### Verdict changes (step level)

- ESC4, ESC5, ESC7, GPO-A, GPO-B, RBCD-B: FAIL to PASS on the lab baseline. Real exposures are still reported as FAIL, with the principal named.
- ESC11: FAIL to SKIP when the template precondition is present.
- DCSync: no verdict (parse error) to a verdict.
- exposure-validation step 0: no verdict (parse error) to a verdict.

### Verification

- Write mask checked with a harness on synthetic ACE rights: GenericRead, ReadProperty+ReadControl and ExtendedRight do not match; WriteProperty, WriteDacl, GenericWrite and GenericAll do. Note: the first harness run was invalid, because `[ActiveDirectoryRights]0x500C0020` throws in PowerShell 5.1 and the variable came back empty. Fixed by using a plain integer.
- Parse check of all 436 PowerShell steps in the scenarios, with a UTF-8 BOM (matching the Windows agent, which writes BOM for steps): 435 parse. The one exception, exposure-validation step 0, is now fixed.
- Without a BOM, 41 steps fail to parse. That is an artifact of writing the files without one. The agent writes BOM for Windows steps, so those are not customer-facing defects.
- Signatures: 7 changed files re-signed; verify-all ok=156 fail=0. Ledger regenerated. Scenario and DLP fixture tests pass.
- Lab rerun of the fixed checks: NOT YET DONE. Needs the rebuilt kit copied to AD-DC-01 (`C:\bas\ad-lab-kit`).

### Still open

- ESC7 orphaned ACE on the CA object (SID ...-1000 does not resolve to an account). It is a real FAIL, pending cleanup decision.
- ESC7 does not evaluate ManageCA or ManageCertificates.
- ESC9 flag change (0x80000) still needs a domain-side check.

### ESC4 follow-up (lab run 2)

- Defect: an ExtendedRight ACE scoped to the Enroll GUID also carried WriteProperty (rights 304). The write test counted it, so Domain Users was reported on 8 templates.
- Fix: a write bit on an ACE that grants an extended right to a specific right GUID is not counted. Whole-object writes and property writes still count.
- Checked on the lab's exact ACE values: Enroll-scoped grant not a write; plain WriteProperty is a write.
- Expected lab change: ESC4 FAIL to PASS. Not yet re-run on the domain.

### GPO CREATOR OWNER rule (decision recorded 2026-11-13)

- CREATOR OWNER (S-1-3-0) is no longer counted by itself. The ACE is evaluated against the GPO's actual owner (GetOwner). If the owner is tier-0, the ACE is not exposure. If the owner is not tier-0 and holds write, it is a FAIL.
- Expected lab change: GPO-A and GPO-B FAIL to PASS, since the owner is Domain Admins.
- ESC7 orphaned SID (...-1000) unchanged: FAIL until an administrator approves removal and the CA ACL is re-validated.
- RBCD-B Account Operators: NOT changed. Conditional tier-0 classification requires a lab tier-model setting that is not built yet. Current result remains FAIL.

### ESC7 finding corrected and decision recorded (2026-11-13)

- The earlier note calling SID `...-3848455713-1000` an orphaned, non-resolving SID was WRONG.
- Confirmed on AD-DC-01: that SID is the domain controller's own computer account, `LAB\WIN-TQ70FGLETIU$` (`Get-ADComputer` SID check).
- The CA object ACE is `Allow`, `983295` (CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, GenericRead, WriteDacl, WriteOwner), not inherited.
- Decision: ESC7 stays FAIL. No ACE removed. An administrator decides whether a DC machine account should hold these rights on a DC-hosted CA.
- Not chosen: adding domain controller machine accounts to the tier-0 list in the shipped check (would change customer scores; needs separate approval).
- RBCD-B lab kit: Account Operators treated as tier-0 in the lab kit only (`S-1-5-32-548`). Shipped scenario unchanged. Lab rerun pending.

### RBCD-B: SELF exempted (decision 2026-11-13)

- Principal rule, same as CREATOR OWNER: SELF (S-1-5-10) is the object's own account, which already controls that object. A SELF write is not a grant to another principal, so it is not counted.
- Lab run before this change: WIN-TQ70FGLETIU$ and WS01$ FAILed because of SELF on msDS-AllowedToActOnBehalfOfOtherIdentity. Account Operators dropped out after the lab tier-model change.
- Shipped scenario change: SELF exempted. Customer-visible score effect: computer objects whose only non-tier-0 write is SELF now PASS.
- Lab-only: Account Operators as tier-0 (lab kit file, not shipped).
- Expected lab result after rerun: RBCD-B PASS.

### ADCS: ESC6, ESC10 (partial), ESC12 (posture) added (2026-11-13)

- Added three steps to the ADCS scenario (10 to 13). Existing steps unchanged.
- Customer-visible: these can add FAILs where present.
  - ESC6: a CA with EDITF_ATTRIBUTESUBJECTALTNAME2 (0x40000) set in policy\EditFlags.
  - ESC10: a DC with StrongCertificateBindingEnforcement=0 (Kdc key). Value 1 or unset is SKIP, not PASS.
  - ESC12: a CA whose key provider is a software provider. Posture only; ESC12 exploit path not tested.
- Coverage gaps, stated plainly:
  - ESC10 certificate-mapping methods not checked (registry path not confirmed).
  - ESC12 does not verify HSM assurance for non-software providers.
  - ESC6, ESC10, ESC12 exploitation not tested.
- Baseline unchanged; ledger gained three entries. Scenario tests pass; 156 signatures verify.
- NOT VERIFIED on a domain. Lab probe required before a kit run is trusted.

### ESC10 corrected to SKIP-only (2026-11-13, approved)

- Reason: Microsoft KB5014754 (https://support.microsoft.com/help/5014754) states the StrongCertificateBindingEnforcement registry value is no longer supported after the September 9, 2025 update. The earlier PASS on value 2 and FAIL on value 0 rested on a key the DC no longer reads.
- Change: ESC10 step now always SKIP, stating the reason. No PASS path. No FAIL path.
- Customer-visible score delta: DCs that previously PASSed on value 2 move to SKIP. Any FAIL on value 0 is removed.
- Not changed: certificate-mapping methods (CertificateMappingMethods, Schannel key, bit 0x4 UPN) remain unassessed. The KB does not state the KDC reads it.
- Lab: ESC10 result was already SKIP (value unset). No lab change made; setting value 2 was rejected because it has no effect after the 2025 update.
- Tests: scenario tests pass; 156 signatures verify.

### Atomic Red Team pin: hard-coded check and step resolution (2026-11-13)

- Pin: `orchestrator/Dockerfile` fetches redcanaryco/atomic-red-team at `a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6`. The commit exists upstream (GitHub API, 200; committed 2026-11-06).
- Gap found: the post-fetch check compared HEAD to `ART_COMMIT`, which is the same build argument that picked the commit. `--build-arg ART_COMMIT=<any>` passed. Fixed: the RUN step now also hard-codes the expected commit and refuses an override.
- Verified by hand: the sparse fetch of the pinned commit succeeds; 353 T*.yaml files; the pin check passes; an override is refused. The full Docker image build was NOT run.
- Step resolution: 39 `framework: art` steps. Runtime rule (builder.go): 0-based `test_index` into the platform-filtered test list; out-of-range silently falls back to index 0.
  - 37 resolve.
  - UNRESOLVED, runs the wrong test silently:
    - entra-hybrid-identity-attack.yaml T1539 index 3: only 5 Windows tests exist.
    - ubuntu-hardening-validation.yaml T1046 index 11: only 13 Linux tests exist, but the platform filter leaves fewer.
- Not changed: scenario test indexes; the runtime silent fallback in builder.go (a change to execution behaviour, needs approval).
