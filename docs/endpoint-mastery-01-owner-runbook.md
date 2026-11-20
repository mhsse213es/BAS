# Endpoint Mastery 01: owner runbook for open items

These are the open items from `docs/endpoint-mastery-01-qa-log.md` that need a person or a machine
the build host does not have. Each has the exact commands. All commands are read-only unless marked
**CHANGES STATE**, and none of them should be run without the decision noted.

## Tool: the read-only runner

`scripts/em01_readonly_run.py` runs all 69 EM-01 checks on the current host using the same verdict
rules as the engine, and writes `results.csv`, `results.json` and `summary.txt`. The summary records
the host (ProductType, edition, admin status), the YAML sha256, and every non-PASS result.

Requirements: Python 3.8+, `pip install pyyaml`, Windows PowerShell 5.1, an elevated shell for the
admin-only checks.

```powershell
git clone -b feat/em01-control-validation <repo-url> em01
cd em01
python scripts\em01_readonly_run.py --scenario scenarios\endpoint-mastery\em-01-control-validation.yaml --out C:\em01-results\<host-label>
```

Check that `YAML sha256` in `summary.txt` matches the commit you ran from. Send back
`summary.txt` and `results.json`.

Overrides (set in the same shell before running, optional):
`BAS_EM01_OUTBOUND_BASELINE` (`none` | `block`), `BAS_EM01_FW_LOG_MB`, `BAS_EM01_SECLOG_MB`,
`BAS_EM01_AV_DEF_HOURS`.

---

## 1. Confirm why real-time protection is disabled on this host (owner decision)

**Why it matters:** four FAILs (steps 00, 19, 07, 08) depend on it. The cause is not confirmed.

Evidence so far:
- Defender logged RTP-disabled events (EID 5001) on 2026-10-10 11:11, 2026-10-10 16:48 and
  2026-10-11 10:38.
- Agent operation logs for 2026-10-10 and 2026-10-11 are missing.
- `blackcat-kill-chain.yaml` and `ransomware-drill.yaml` disable RTP and restore it in cleanup. An
  interrupted run would leave it off. This is a candidate, not a finding.
- Operation logs that do exist carry test agent IDs (`test-agent`, `a1`, `abc123deadbeef01`).

Steps:
1. Read the Defender timeline (read-only):
   ```powershell
   Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=5001,5010} |
     Select-Object TimeCreated, Id | Sort-Object TimeCreated
   ```
2. Check whether a BAS scenario or test harness ran on this host on or after 2026-10-10. Use the
   orchestrator's run history for host `DESKTOP-5TVEBSI`, and the agent's scheduled tasks and logs.
3. Decide, and record the decision in the QA log:
   - **Re-enable:** **CHANGES STATE** (admin). Confirm first that no run is in progress.
     ```powershell
     Set-MpPreference -DisableRealtimeMonitoring $false
     ```
     Then re-run the runner. Steps 00, 19, 07 and 08 should PASS.
   - **Keep disabled as a documented exception:** record who approved it and why. The FAILs stay.

## 2. Confirm the Sense onboarding signal (needs a Defender-for-Endpoint onboarded device)

**Why it matters:** step 53 treats `OnboardingState=1` as "onboarded". That value is assumed, not
confirmed.

On an **onboarded** device, in an elevated shell:
```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection' -Name OnboardingState
Get-Service Sense | Select-Object Name, Status, StartType
```
Send back both outputs. If `OnboardingState` is not `1` on an onboarded device, step 53's logic is
wrong and needs a change. The same check on a non-onboarded device should show the value absent or
not 1.

## 3. Windows Server run (needs a Windows Server host)

**Why it matters:** every result so far is from a Windows Client. Server behaviour is unverified.

1. Run the runner on the server (steps above). Use an elevated shell.
2. Expected differences to look for, not assumed:
   - Steps 49–51 (Security Center): may SKIP if `SecurityCenter2` is absent on the server.
   - Step 25 (RDP on Public/Any profile): RDP is often intentionally enabled on servers. A FAIL
     there may be expected for that server's role. Record the role; do not waive it silently.
   - Steps 04 and 28–37 (ASR): check which rules the server actually has. Server support differs
     from the client.
   - Steps 53 and 54 (Sense, WdNisSvc): may differ depending on how the server is managed.
3. Send back `summary.txt` and `results.json`, and note the server role.

## 4. Confirm the "expected Windows configuration" defaults (needs a fresh image)

**Why it matters:** the 20 failures classed as "expected Windows configuration" were classified from
their current values. Whether those values are the true out-of-box state has not been verified on a
fresh install.

Option A (quickest): **Windows Sandbox**. It is currently **disabled** on this host.
```powershell
# CHANGES STATE (admin, then a reboot). Needs owner approval.
Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All
```
Open Windows Sandbox, copy the repo's `scripts` and `scenarios` folders in, install Python and
PyYAML inside it, run the runner. Sandbox is disposable, so nothing persists.

Option B: a fresh Windows 10 or 11 VM from the install media, with no domain or policy applied.

Then compare each step in the "Expected Windows configuration" group of the QA log
(steps 26, 27, 28–37, 39, 40, 57, 60–64) against the fresh-image result. If a value differs from the
out-of-box state, move that step to a different class in the QA log.

## 5. TPM and Secure Boot (firmware, needs a person at the device)

**Why it matters:** step 48 (TPM) and step 65 (Secure Boot) are firmware settings. The OS cannot tell
"absent" from "disabled".

1. Restart into BIOS/UEFI setup. Check for a TPM setting (usually "Security" or "TPM 2.0"). Note
   whether it is enabled, and whether the firmware reports a TPM at all.
2. Check the boot mode (UEFI vs Legacy) and whether Secure Boot is available and enabled.
3. Record what you found. If you enable a setting, **CHANGES STATE** (firmware). Then run the runner
   again. Step 67 (HVCI) depends on Secure Boot, so it should be re-checked after step 65 changes.

## 6. Decide the `[BAS-SIM]` tag on posture PASS lines (owner decision)

**Why it matters:** the repo's docs use `[BAS-SIM]` for **synthetic or simulated** data and actions
(for example `docs/collection-exfil-expansion-qa-log.md`: "All data is synthetic (`[BAS-SIM]`)").
EM-01 reads **real** endpoint state. Its PASS lines tagged `[BAS-SIM]` may therefore mislabel real
evidence as simulated. No code consumes the suffix today, so nothing breaks either way.

Options:
- **A. Keep as is.** Preserves current output. The label stays inconsistent with the docs.
- **B. Remove the tag from the existing EM-01 PASS lines.** Changes the signed YAML: this needs a
  re-sign and a new ledger check. Recommended if the docs' meaning is the intended one.
- **C. Keep, and document it as "checked by the BAS posture pack".** Requires a doc change
  describing a new meaning.

Reply with A, B or C. Until then, no new step carries the tag.

## 7. Stale Defender definitions (optional, needs your go-ahead)

On this host the definitions were 28.6 hours old at the last run. Step 16 (24-hour window) now FAILs.
That is correct behaviour, not a runner error.

To refresh the definitions (**CHANGES STATE**, a signature update only, not a configuration change):
```powershell
Update-MpSignature
```
Check whether this host should update within 24 hours at all. That depends on how its updates are
managed.

## Environment variables added (2026-11-20)

- `BAS_EM01_ENCRYPTION_BASELINE` — `none` (default) | `required`. Set `required` if the selected baseline requires BitLocker. A missing feature or an unencrypted volume then FAILs. Under `none` both are NOT_ASSESSED.
- `BAS_EM01_APPROVED_EXCEPTIONS` — e.g. `DisableIOAVProtection:CHG-1234`. Use only for a documented, approved exception. Each entry is reported as SKIP with its reference and is not scored. Unapproved disables still FAIL.
- `BAS_EM01_DEF_UPDATE_HOST` — the update source probed for step 16 when definitions are stale. Default `definitionupdates.microsoft.com`. Set it to an approved internal source if the endpoint uses one.

The runner now writes a `category` column and groups the summary into control failures, not-assessed (environmental or policy), not-applicable, and probe errors.
