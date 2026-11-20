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

## Decisions implemented (2026-11-20)

Driven by the Windows Server 2019 test run, which surfaced three SKIP/FAIL questions that needed a decision and not a guess.

1. **BitLocker is baseline-driven (steps 06, 44–47).** Controlled by `BAS_EM01_ENCRYPTION_BASELINE` (`none` default | `required`).
   - `required`: a missing BitLocker feature, or an unencrypted volume, is a FAIL.
   - `none`: both are NOT_ASSESSED (SKIP), not PASS. A missing feature is never a successful check.
   - Any other value is an ERROR.
   - **Effect on the client run:** the laptop's BitLocker FAILs (steps 06, 44, 45, 46) become NOT_ASSESSED under the default `none`. They are unchanged when `required` is set. Step 47 (no fixed data volumes) still PASSes, because the BitLocker feature is present and enumerates no data volumes. This is the only case where PASS is valid without encryption.
2. **Approved exceptions (steps 08, 19).** Controlled by `BAS_EM01_APPROVED_EXCEPTIONS` (for example `DisableIOAVProtection:CHG-1234`, comma-separated).
   - An approved disable is reported as SKIP with its reference. It is not scored, and it names the exception so it is visible in the report.
   - An unapproved disable still FAILs, even when another flag is approved.
   - Nothing is restored or weakened automatically. The owner decides whether each exception is intentional. The default remains "restore the expected configuration".
   - Verified: `DisableRealtimeMonitoring` approved → step 19 SKIP with ref; `DisableIOAVProtection` approved alone → step 19 still FAILs on the unapproved flag; step 08 approved → SKIP with ref.
3. **Defender update-source connectivity (step 16).** Controlled by `BAS_EM01_DEF_UPDATE_HOST` (default `definitionupdates.microsoft.com`, TCP 443, 5 s timeout).
   - Definitions fresh → PASS. Connectivity is not needed.
   - Definitions stale and source reachable → FAIL: the endpoint is not taking updates.
   - Definitions stale and source unreachable → NOT_ASSESSED (SKIP), with the reason. This is an environmental limitation and is not reported as an endpoint failure.
   - Connectivity probe error → treated as unreachable and reported with the message. It is not reported as an endpoint failure.
   - The default host is an assumption: it is the Defender definitions host commonly documented for TCP 443 access. The owner should confirm it, or set `BAS_EM01_DEF_UPDATE_HOST` to the approved internal source (for example WSUS or a local mirror).
   - Verified on the client: default host reachable; stale threshold with reachable source → FAIL; stale threshold with an unresolvable host → NOT_ASSESSED with the reason.

### Environmental limitations versus security-control failures

The runner now writes a `category` field for every step, and the summary groups results by it:

- **control_failure** — the control is not in the required state. Scored. Owner action needed.
- **not_assessed_environmental_or_policy** — baseline does not require it, an approved exception covers it, or the source is unreachable from this host. Not scored, and the reason is printed.
- **not_applicable** — the component is absent by design or out of scope (for example, Sense not onboarded, Sysmon not deployed, WDAC not deployed). Not scored.
- **probe_error** — the check could not run. Not scored, but it must be investigated; it is never a PASS.

The earlier client result of 39 FAIL / 7 SKIP is superseded by this run: 35 control_failure, 5 not_assessed, 6 not_applicable, 0 probe_error, 23 PASS (on this client, with step 16 PASS because definitions are fresh).

### Server re-run needed

The 2019 server result predates these decisions. To re-run it, the owner must choose the baseline for the server:
- If the server's baseline requires BitLocker, set `BAS_EM01_ENCRYPTION_BASELINE=required`. The five not-installed BitLocker checks then become FAILs, which is the intended outcome.
- Decide whether `DisableIOAVProtection` is an approved exception. If it is not, restore the expected Defender configuration on the server and re-run. The steps are in the runbook.
- Run the step-16 connectivity probe from the server. Its result decides between FAIL and NOT_ASSESSED.

### Open item not changed by these decisions

- **TPM (step 48)** still FAILs when no TPM is present, regardless of the BitLocker baseline. The TPM is a BitLocker prerequisite, but it was not one of the three decisions. Owner should decide whether TPM should follow the same baseline gate.

## Windows Server 2019 test run (WIN-2IP8FNO4MAD, lab.local member server, VMware, 2026-11-19/20)

Server is a lab test VM, not production. It also hosts the Trellix ePolicy Orchestrator 5.10 server role and the Trellix Agent, so it manages the lab Trellix fleet.

### Latest run

Run 22:34 PST (package `8f880097…918f14c`): **PASS 38, FAIL 17, SKIP 14, ERROR 0, probe errors 0.** Every verdict has an evidence line.

Remaining control failures and their status:

| Step | Finding | Status |
|---|---|---|
| 02 | Defender Tamper Protection OFF | **FAIL, not recorded as an exception.** No local toggle on this build. Needs Defender for Endpoint or Intune. |
| 04, 28–37 | ASR rules not configured | Open. Audit-mode commands recommended, not applied. |
| 05, 39, 40 | AppLocker not enforced | Open. Audit-mode policy via GPO recommended, not applied. |
| 13 | Network protection not in block mode | **Open, unexplained.** Set to Enabled, but evidence showed `EnableNetworkProtection=2` (audit). Check for a policy source. |
| 60 | LSA protection (RunAsPPL) | Open. See the LSA section below. |

Changes applied by the owner and confirmed by the run: Private firewall enabled (03); RDP removed from Public (25); PUA, cloud protection (Advanced), firewall logging and log sizes, security log size, LLMNR off, process-creation auditing and command lines (11, 12, 26, 27, 57, 62–64).

Other results: Defender on-access, behaviour monitoring and real-time protection PASS after the owner re-enabled real-time protection; step 19 PASS once the disable flags were cleared. Step 16 (definitions) PASS. HVCI (67) PASS after the owner enabled Memory integrity (configured and running, no driver blocks). VBS, Secure Boot and NLA PASS. Step 53 (Sense) SKIP: not onboarded. Steps 06, 22, 44–48 NOT_ASSESSED under baseline `none`.

### Decisions applied

- **BitLocker and TPM (06, 44–48):** baseline-gated. `none` = NOT_ASSESSED; `required` = FAIL. Not yet set to `required` for this server. The baseline owner must decide.
- **Defender Tamper Protection (02):** the scenario has an approved-exception branch (`BAS_EM01_APPROVED_EXCEPTIONS=TamperProtection:<ref>`). No reference exists, so no exception is recorded and step 02 stays a FAIL. The branch is inactive without the variable.
- **Defender real-time protection:** restored (owner decision). The earlier unexplained disable was not traced to a PowerShell change in the 21:20–21:40 window. Logs show Trellix services running.

### LSA protection (step 60): attempted, rolled back, not applied

- `RunAsPPL` was set to 1 by registry, with no UEFI lock, and the server was rebooted.
- After the reboot the domain was unavailable: the DHCP-provided DNS server list had lost `192.168.11.200` (the DC), and domain discovery and the secure channel failed.
- Cause: the DNS change at the reboot, not LSA protection. A rollback to `RunAsPPL=0` with a reboot still failed, which isolated LSA as not the cause.
- Fix: static DNS on the adapter to `192.168.11.200` and the DC's IPv6 address; `ipconfig /registerdns`; Netlogon restart; `Test-ComputerSecureChannel -Repair`; `gpupdate /force`. A reboot test with LSA off then passed: DNS persisted, DC found, secure channel `Status = 0`.
- **Current state:** `RunAsPPL = 0`. Step 60 remains a FAIL.
- **Not yet confirmed:** Trellix compatibility with LSA protection on. The first LSA-on boot never reached a clean state, so LSA behaviour on this server is unverified. Retry only after Trellix confirms compatibility in writing, with a snapshot and a reboot window.
- **Separate open item:** the DHCP scope still hands out the old DNS server to other machines. This server is now static, so it's unaffected. The DHCP option needs fixing at the DHCP server or router.

### Trellix (open decision)

- Trellix ENS is running and is registered with ePO on this host. Windows Security Center shows no registered AV product, so Defender stays active in normal mode.
- Recommendation: Trellix as the single primary engine, with Defender passive. The owner has not yet confirmed this.
- Scenario step 00 would need a change to accept a registered, enabled third-party product. Not made; needs owner approval.

### TPM (step 48)

Resolved as a decision: follows the BitLocker baseline gate. Under `none` it is NOT_ASSESSED, under `required` it is FAIL. The open item in the previous section is closed.

### Open items

1. Confirm the server baseline: `BAS_EM01_ENCRYPTION_BASELINE` `none` or `required`.
2. Step 02: onboard the server to Defender for Endpoint or Intune, or accept the gap in writing with a change reference.
3. Step 13: find out why network protection reads audit mode after being set to block.
4. Trellix: confirm the primary engine and whether step 00 should accept a registered third-party product.
5. Step 60: wait for Trellix's written compatibility confirmation before any further LSA change.
6. DHCP scope: fix the DNS server option.
7. ASR and AppLocker: audit-mode rollout, then review.

## Decisions and signal semantics (2026-11-20, latest)

**`[BAS-SIM]` tag: option A.** The tag stays on the existing PASS lines it was already on. No new step carries it. The docs' meaning (synthetic or simulated data) does not match EM-01, which reads real endpoint state. That mismatch is recorded here and is not resolved.

**Trellix signal (steps 00, 07, 08).** Approved and implemented in `8d9991df`.
- An attached on-access driver (`mfehidk`) with Trellix services running is **presence only**. It never produces a PASS.
- When the driver and services are present but Trellix's on-access state cannot be verified locally, the result is `SKIP: NOT_ASSESSED`. It is not scored and it is not a PASS.
- Services stopped, or no engine at all, with Defender real-time off: FAIL.
- A PASS needs a verified engine: Defender real-time on (step 00), or a Windows Security Center registration with the enabled bit set (step 00, and 08 as before).
- The on-access state is verified in the ePO console. The check cannot read it locally.

**Step 07 judgment.** The on-access driver proves on-access is attached, not that behaviour monitoring is on. Step 07 therefore never reports PASS from the Trellix signal. It reports NOT_ASSESSED when Defender behaviour and real-time are both off and Trellix is present, and FAIL when nothing is present.

**Baselines (approved).** Server and client: `BAS_EM01_ENCRYPTION_BASELINE=required`. This covers BitLocker (06, 44–47) and TPM (48).
- A missing BitLocker capability, an unencrypted system volume, or a missing or unavailable TPM is FAIL against this baseline.
- A virtual machine without a supported virtual TPM is FAIL. Passing needs the vTPM added to the VM, which is an infrastructure change.
- Any approved hardware or platform exception must be documented separately with a reference. None is recorded.

**Defender real-time disable (step 19).** Not approved. The disable source is not established, and Trellix primary is not confirmed. Step 19 stays FAIL until both are established.

**Trellix primary engine.** Not confirmed. Windows Security Center does not register Trellix on this Server SKU, so there is no Windows-side evidence. Confirmation needs Windows Security Center plus the Trellix console. Until then, no step treats Trellix as the primary engine.

**Tamper Protection (step 02).** Decision: onboard to Defender for Endpoint or Intune and use centralised enforcement. Until onboarding, it stays FAIL. No exception is recorded.

**ASR and AppLocker.** Remain in audit mode. Enforcement waits for audit review, documented exclusions, and a successful controlled pilot. Not every ASR rule is enabled blindly.

**Open items for the next run:** the Trellix on-access fix, the server and client `required` runs, and the `[BAS-SIM]` decision (now recorded as A). The client's TPM state is still unknown.

## Client run (DESKTOP-5TVEBSI, Windows 10 Pro, Dell Inspiron 7373, 2026-11-20)

Package `a5865a1d…a8c81`, `BAS_EM01_ENCRYPTION_BASELINE=required`, run on the client itself (read-only). Output: `C:\Users\Administrator\Downloads\em01-client-local-final`.

**Result: PASS 23, FAIL 39, SKIP 7, ERROR 0, NO_VERDICT 0.**

An earlier attempt that appeared to be a client run was executed on the server (its host line showed `WIN-2IP8FNO4MAD`). It is not client evidence and is not used here.

### Client findings

- **Real-time protection is off (00, 07, 08, 19).** Defender real-time protection is disabled by a preference flag, and no verified real-time engine is present on this laptop. Real-time protection on this client is not running. This needs an owner decision: re-enable Defender real-time protection (a state change, needs approval), or establish and approve another engine.
- **BitLocker and TPM (06, 44–46, 48) FAIL under `required`.** The system drive is not encrypted and the TPM is not present or ready. These are genuine gaps against this baseline.
- **Secure Boot is off (65).** This is a firmware setting, and the BIOS change needs a person at the device.
- **HVCI (67) FAILs while VBS runs (66 PASS).** Same pattern as the server before it was fixed: VBS is running but Memory integrity is not configured. The configuration needs checking.
- **RDP is enabled without Network Level Authentication (68).** Genuine misconfiguration.
- **Firewall logging and log sizes (26, 27, 57), script block logging (61), process-creation auditing and command lines (62, 63), LLMNR (64), LSA protection (60), ASR and AppLocker (04, 05, 28–40), network protection (13), controlled folder access (14), PUA (12), cloud protection (11), Tamper Protection (02).** Hardening gaps, same as the server.
- **Sense (53) SKIP:** not onboarded, not applicable by design.
- **WDAC kernel policy (42) PASS** (`CodeIntegrityPolicyEnforcementStatus=2`). This wasn't PASS on the previous client run, so a WDAC policy has been deployed since. Check which policy it is before relying on it.
- **Security Center (49–51) PASS** because Defender is registered there.

### Flag: step 50 may overstate protection

Step 50 PASSes with "Security Center reports an enabled AV provider: Windows Defender", while Defender's real-time protection is off (step 00 FAIL). The Security Center enabled bit can stay set when real-time is off. Step 50 may therefore be reporting registration rather than active protection. This needs a decision on whether to tighten it. I haven't changed it, because changing a verdict needs approval.

### Decisions needed for the client

1. Re-enable Defender real-time protection on this laptop, or approve another engine. Until then the laptop has no working real-time protection.
2. Whether step 50 should require real-time protection to be on, in addition to the enabled bit.
3. BIOS: Secure Boot and TPM, if the owner wants those to pass.
4. HVCI configuration on the client, matching the server's fix.

## Changes since the server and client runs (2026-11-20)

- **Step 50 (Security Center enabled provider):** now requires Defender real-time protection to be ON before PASS. Registered but real-time off is FAIL. Real-time not readable locally is NOT_ASSESSED. Commit `74127234`. Effect: on the client, step 50 becomes FAIL because real-time protection is off there.
- **Client RDP Network Level Authentication:** set `UserAuthentication` from `0` to `1` on DESKTOP-5TVEBSI, so step 68 now PASSes. Original value `0`. Revert: `Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 0 -Type DWord`. RDP stays enabled.
- **Not changed on the client:** Defender real-time protection (left alone at the owner's request), HVCI (needs a reboot, awaiting approval), BitLocker (decryption time), Secure Boot and TPM (BIOS only).

## Release gate status

- Merge to `main`: **not yet.** Blockers: the Trellix on-access issue on the server, and the final server re-run on the frozen package.
- Frozen package: the scenario sha256 is `a65bf7e1baf6c7a780bdec67fd1055c435108830b3b6f786d48f3a73111110be` on commit `74127234`.

## Client HVCI change (DESKTOP-5TVEBSI, 2026-11-20)

- **Change:** `HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity` created with `Enabled=1` (Memory integrity on). Applied before a reboot.
- **Original state:** the key did not exist (step 67 FAIL). VBS was running (`VirtualizationBasedSecurityStatus=2`).
- **Revert:** `Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Recurse -Force`, then reboot.
- **Verify after reboot:** `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object SecurityServicesConfigured, SecurityServicesRunning` should show `2` in both. Check `Microsoft-Windows-CodeIntegrity/Operational` for events 3033 or 3077, which mean a driver blocked HVCI.
