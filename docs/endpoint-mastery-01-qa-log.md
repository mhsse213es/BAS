# Endpoint Mastery 01: Control Validation — QA log

Scenario: `scenarios/endpoint-mastery/em-01-control-validation.yaml` (signed by `em-01-control-validation.yaml.sig`).
Scope: 7 → 69 read-only posture checks, grouped by control area in the file.

## Status

Technically on track, **not yet enterprise-ready**. Every FAIL has been classified below. The
classification found two wrong verdicts (fixed), one open root cause that needs the owner, and
one coverage gap (Windows Server not exercised). The results are evidence of this endpoint's
state, not a score for the organisation.

## Changes

- The seven original step names are kept. The Go test that loads a step by name still finds them.
- 62 new steps follow the original seven. Each is independent and has its own verdict.
- Overrides come from agent environment variables, read with `$env:` inside the command, as existing scenarios read `BAS_*` gates:
  - `BAS_EM01_OUTBOUND_BASELINE` — `none` (default) | `block`
  - `BAS_EM01_FW_LOG_MB` — default 16 (Audspect recommended default)
  - `BAS_EM01_SECLOG_MB` — default 192 (Audspect recommended default)
  - `BAS_EM01_AV_DEF_HOURS` — default 24 (Audspect recommended default)
  - Invalid override values produce ERROR, never a silent default.
- Thresholds are Audspect recommended defaults, not Microsoft or CIS requirements. Each PASS/FAIL reports the observed value and the threshold with its source.
- Fixes made during this classification pass (both were wrong verdicts, not strictness):
  1. **ASR composite (step 04).** `@($null).Count` is 1, so a host with no ASR configuration reported "1 ASR rule(s) present". Nulls are now filtered. The verdict stays FAIL, with the correct message.
  2. **Sense (step 53).** Presence of the service was treated as an expectation. Sense ships with Windows and is only expected to run when the endpoint is onboarded or set to start automatically. The result is now SKIP when neither holds (reason given) and FAIL when either holds and the sensor is stopped.
  3. **HVCI (step 67).** The FAIL evidence now records the Secure Boot prerequisite, which was the likely root cause on this host. The verdict is unchanged.
- Earlier fixes (previous passes) are unchanged: EDR fallback no longer treats Defender as a 3rd-party AV; WDAC enforced = PASS, audit = FAIL.
- `[BAS-SIM]` is not applied to new steps. Original tags are preserved (see Decisions).

## Verdict counts

| Run | PASS | FAIL | SKIP | ERROR |
|---|---|---|---|---|
| Before classification fixes (run 4) | 23 | 40 | 6 | 0 |
| **Final (run 5, after fixes)** | **23** | **39** | **7** | **0** |

The SKIP count went up because of fix 2 (Sense).

## Failure classification (39 FAIL, final run)

Categories:
- **Genuine misconfiguration:** a security control is absent or off on this endpoint and nothing else explains it. Owner action is needed.
- **Environment-specific:** the result depends on hardware or firmware this OS cannot see.
- **Policy-dependent:** an opt-in control. It is a FAIL only if the selected baseline requires it.
- **Expected Windows configuration:** the value is the out-of-box Windows state. The check is correct against an enterprise baseline, and no defect is involved. The defaults are believed out-of-box and were **not verified against a fresh image** in this pass.
- **Incorrect detection or test logic:** the verdict was wrong. These are fixed.

All 39 FAILs were produced on a **Windows Client** SKU (ProductType 1, Dell Inspiron 7373, physical, not a VM).

| Class | Count | Checks (step number) |
|---|---|---|
| Genuine misconfiguration | 12 | 00, 19, 07, 08 (RTP root cause, see below); 25, 68 (RDP exposure, NLA); 06, 44, 45, 46 (BitLocker off, no method, no recovery protector); 65 (Secure Boot off); 67 (HVCI, prerequisite Secure Boot) |
| Environment-specific | 1 | 48 (TPM not present/ready on a physical device: absent vs disabled in firmware cannot be told from the OS) |
| Policy-dependent | 5 | 02 (Tamper Protection off), 11 (cloud protection not Advanced), 12 (PUA not block), 13 (network protection not block), 14 (controlled folder access not block) |
| Expected Windows configuration | 20 | 26, 27 (firewall logging off, 4 MB log); 28–37 (no ASR rules); 39, 40 (AppLocker MSI/Appx not configured); 57 (Security log 20 MB); 60 (LSA protection not set); 61 (script-block logging not set); 62 (no process-creation auditing); 63 (no command-line capture); 64 (LLMNR not disabled) |
| Incorrect logic (fixed) | 1 | 04 (ASR composite phantom rule; verdict remains FAIL for the real reason, no rules) |

### Open root cause: real-time protection disabled (steps 00, 19, 07, 08)

- Evidence: `DisableRealtimeMonitoring=True` in Defender preferences; `RealTimeProtectionEnabled=False`; Defender event 5001 (RTP disabled), most recent at **2026-10-11 10:38**. Steps 07 and 08 follow from the same master disable.
- The Defender configuration-change events (5007) from today are service-startup housekeeping (`WdConfigHash`, `IsServiceRunning`). They do not show a preference change.
- Candidate cause, **not confirmed**: `scenarios/blackcat-kill-chain.yaml` (line ~203) and `scenarios/ransomware-drill.yaml` (line ~395) set `DisableRealtimeMonitoring $true` and restore it in cleanup. An interrupted run would leave RTP disabled. Nothing in the logs attributes the 2026-10-11 change to them.
- **Owner action:** confirm whether this host ran those scenarios on or after 2026-10-11, and decide whether to re-enable RTP. The QA run did not change any host state.

### Windows Server versus Client

- This run covered **Client only**. Windows Server was not exercised, so server behaviour is **NOT_ASSESSED**.
- Expected server differences, not verified here:
  - Windows Security Center (`SecurityCenter2`) may be absent, which turns steps 49–51 into SKIP.
  - Remote Desktop is often intentionally enabled on servers, so the RDP rules (step 25) will be expected rather than a defect on those hosts.
  - Default ASR, Tamper Protection and logging postures on servers may differ.
- A Server run is needed before any Server verdict is claimed.

## SKIP semantics (7 SKIP)

Every SKIP line has an explicit reason. None is scored.

| Step | Reason (from the output) | Verified against |
|---|---|---|
| 15 NIS signature freshness | Network Inspection System is disabled | `NISEnabled=False` |
| 22 Outbound policy | `NOT_ASSESSED` — no outbound baseline configured | `BAS_EM01_OUTBOUND_BASELINE` unset; observed Allow on all profiles is reported as evidence, not failed |
| 41 AppLocker AppIDSvc | No AppLocker collection is enforcing | `Get-AppLockerPolicy -Effective` shows NotConfigured |
| 43 User-mode WDAC | No user-mode WDAC policy deployed | `UsermodeCodeIntegrityPolicyEnforcementStatus=0` |
| 53 Sense (MDE sensor) | Present but not onboarded; StartType Manual | `OnboardingState` absent; `StartType=Manual` |
| 54 WdNisSvc | NIS disabled, so the service is not required | Same as step 15 |
| 56 Sysmon | Not deployed (optional telemetry) | No `Sysmon`/`Sysmon64` service |

**Scoring verification.** `internal/models/score.go` excludes `ResultSkipped` from `weightedTotal` (`case ResultSkipped: skipped++; continue`). A temporary test (not committed, removed after running) fed the seven live SKIP lines through `scenario.Interpret`:
- All seven mapped to `ResultSkipped`.
- Adding them to a score with one PASS and one FAIL left prevention = 50, exposure = 50, coverage = 0 unchanged.

**Caveat on step 53.** The SKIP rests on `OnboardingState=1` meaning "onboarded". That value was not confirmed on an onboarded device. If an onboarded sensor is stopped and its StartType is not Automatic, the step would report SKIP. This is an open item.

## Evidence quality (PASS checks)

Each PASS was checked against a second source or the raw property where one existed:

- **Step 00 vs 19 vs 07/08:** the RTP FAIL agrees across the runtime property, the configuration flag and the event log.
- **Steps 49–51 (Security Center):** `productState 397568` = `0x61000`. The enabled bit (`0x1000`) is set and the definitions bit (`0x0010`) is clear. This agrees with signature age 0 from `Get-MpComputerStatus`.
- **Step 66 (VBS):** status 2 and no running security services. This is consistent with VBS running without Credential Guard or HVCI.
- **Step 21 (inbound default Block) and step 23 (mpssvc Running):** read directly from the ActiveStore and the service.
- **Step 24 (no allow-all rule):** a first draft of this check flagged 32 rules. They were packaged (UWP) app rules, scoped by a Package SID on the application filter. The check now excludes them, and the rule count is reported. This false positive was found by the run, not assumed away.
- **Step 59 (SMBv1 disabled):** `Get-SmbServerConfiguration EnableSMB1Protocol=False`.
- **Step 16 (definitions 12.8 hours old):** matches `AntivirusSignatureLastUpdated`.
- **Step 20 (exclusions):** reviewed the seven paths and one process manually. None is a drive root, system or user root, Temp, wildcard, extension or LOLBin.

## Other verification

- Signature: `signer.go verify-all scenarios/endpoint-mastery` → ok=14, fail=0, after the final edit. The `.sig` must be verified again on the branch copy of the YAML.
- Step-contract tests (`TestStepContract_*`) and `TestAppControlPosture_EmitsEffectiveCoverageNotPresence` pass on the working branch.
- Live: all 69 commands run locally, read-only, on this endpoint. 0 ERROR and 0 NO-VERDICT in the final run.
- The ERROR path was exercised by invalid override values (`BAS_EM01_FW_LOG_MB=abc`, `BAS_EM01_AV_DEF_HOURS=0`, `BAS_EM01_OUTBOUND_BASELINE=bogus`).

## Decisions applied

1. **Outbound firewall check is baseline-driven.** Windows default Allow is never a FAIL. With no baseline the result is NOT_ASSESSED (SKIP). With `block` it is PASS only if outbound Deny is in force on all profiles, and FAIL names the violated profiles.
2. **Thresholds are configurable and labelled** as Audspect recommended defaults (table above).
3. **`[BAS-SIM]` tag.** The tag is a naming prefix for synthetic artifacts BAS creates or simulates: fixture rows (`agent/dbprobe/fixtures/catalog.go`), decoy files and temporary accounts (`orchestrator/internal/scenario/execclass.go`), and DLP placeholder records. On em-01 it is a text suffix on some PASS lines. No non-test Go code, web UI or reporting code parses it: `scenario/interpreter.go` reads only the leading verdict prefix. The only tag-parsing family is `adcsaudit`'s `BAS-SIM-ADCS-*`. em-01 creates no synthetic artifacts, so the meaning does not apply to its checks. New steps carry no tag. Existing tags are unchanged. **Open for the owner:** whether the suffix was meant as a simulation-mode marker for reporting. Nothing in the code confirms it.

## Repository state and isolation

- The work started on `feat/db04-pg-sensitive-table`, which is 14 commits ahead of `main` and carries unrelated uncommitted work. The EM-01 change must not ride on that branch.
- `main` is 2c3b521d. Its ledger differs from this branch's ledger by three `dbsim-db04` rows. The EM-01 ledger must therefore be regenerated on a `main` base, not copied.
- The EM-01 branch is created from `main` in a separate worktree. Only these files are committed: the YAML, its `.sig`, the 62 em-01 ledger rows, and this QA log.
- The baseline file (`step_contract_baseline.json`) is not changed by this work: em-01 has zero gaps.

## Open items: status (2026-11-20)

Built here, with instructions in `docs/endpoint-mastery-01-owner-runbook.md`:

- **Read-only runner:** `scripts/em01_readonly_run.py` runs all 69 checks with the engine's verdict rules and writes CSV, JSON and a summary that records the host and the YAML sha256. Tested on this host: it reproduces the live results. The one difference from the earlier run is step 16, which FAILs because the definitions are now 28.6 h old. That is the 24 h check working as intended.

Needs the owner (steps are in the runbook):

1. **Real-time protection cause.** Still open. Investigated what could be checked from this host:
   - Defender logged RTP-disabled events on 2026-10-10 11:11, 2026-10-10 16:48 and 2026-10-11 10:38.
   - Agent operation logs for 2026-10-10 and 2026-10-11 do not exist.
   - Retained operation logs contain test agent IDs (`test-agent`, `a1`, `abc123deadbeef01`), which suggests harness runs on this host. This is an observation, not proof.
   - Nothing in the retained logs names the RTP-disabling scenarios. No host state was changed.
2. **`OnboardingState=1` signal.** Needs an onboarded device. Not confirmed.
3. **Windows Server run.** Needs a Server host. Not done.
4. **Out-of-box defaults.** Needs a fresh image. Windows Sandbox is disabled on this host; enabling it is a state change the owner must approve.
5. **`[BAS-SIM]` meaning.** Repo docs define the tag as marking synthetic or simulated data. EM-01 reads real state, so its PASS tags may mislabel real evidence. Options A/B/C are in the runbook. Decision pending.
6. **Also found:** TPM (step 48) and Secure Boot (step 65) are firmware settings and need a person at the device. Defender definitions are 28.6 h old, which fails step 16 today.
