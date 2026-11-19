# CSCRF-MII live run runbook (lab VM only)

These steps change state, so they run on the lab VM, never on the build host. Each one is gated by an environment variable. Run each step, then its undo, then check for residue. Record every verdict in `docs/cscrf-mii-qa-log.md`, including FAIL and ERROR.

How to run a step (elevated PowerShell on the lab VM, from the pack folder):

```powershell
Get-Content .\lib.ps1,.\<step>.ps1 | Set-Content .\run.ps1 -Encoding utf8
powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1
Get-Content .\lib.ps1,.\<step>.undo.ps1 | Set-Content .\undo.ps1 -Encoding utf8
powershell -NoProfile -ExecutionPolicy Bypass -File .\undo.ps1
```

## 1. Malware detection with the EICAR test file (ir-01)
- Pack: `cscrf-mii-incident-response`. Gate: `BAS_CONFIRM_IR_TEST=true`.
- Expected: PASS if endpoint protection removes or flags the file; FAIL if it stays and real-time protection is on, or if real-time protection is off.
- Undo: PASS. Residue check: no `%TEMP%\bas-ir-*` folder.

## 2. Compromised account disablement (ir-04)
- Pack: `cscrf-mii-incident-response`. Gate: `BAS_CONFIRM_IR_TEST=true`.
- Expected: PASS when the synthetic account is created and disabled.
- Undo: PASS. Residue check: `Get-LocalUser | Where-Object Name -like 'bas-ir-*'` returns nothing.

## 3. Marker egress to a named share (dp-05)
- Pack: `cscrf-mii-data-protection`. Gate: `BAS_CONFIRM_DP_TEST=true`, `BAS_DP_SHARE=<a share you control, e.g. \<host>\<share>>`.
- Expected: PASS when the marker is written and read back. This does not test DLP blocking, which is deferred.
- Undo: PASS. Residue check: no `bas-dp-marker-*` file in the share.

## 4. Synthetic file copy and verify (fc-02)
- Pack: `cscrf-mii-filecopy-recovery`. Gate: `BAS_CONFIRM_FC_TEST=true`, `BAS_FC_TARGET=<a target you control>`.
- Expected: PASS when the copies match by hash.
- Undo: PASS. Residue check: no `bas-fc-*` folder at the target or in `%TEMP%`.

## 5. Off-host copy check (fc-01), against a real copy
- Pack: `cscrf-mii-filecopy-recovery`. Input: `BAS_FC_TARGET` pointing to a folder that holds a real `SHA256SUMS`.
- Expected: PASS when every file matches; FAIL after you change one file. This is read only, so no undo is needed.

## 6. Named MII services (mii-03)
- Pack: `cscrf-mii-mii-controls`. Input: `BAS_MII_SERVICES=<names of real services on the VM>`.
- Expected: PASS when all are running; FAIL if any is missing or stopped. Read only.

## Not live-testable here (leave as deferred)
- DLP detection and blocking of the marker.
- DR SOC monitoring and recovery.
- Backup checks bdr-01 and bdr-02, which need a working VSS on the lab VM.
