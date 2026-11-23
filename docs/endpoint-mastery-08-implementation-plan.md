# Endpoint Mastery 08 — Exploit Mitigation & Posture Check: implementation plan

Status: PLAN ONLY. No scenario change until the decisions in section 8 are approved.
Current file: scenarios/endpoint-mastery/em-08-exploit-mitigation.yaml (2 steps, on main).

## 1. Defects in the current EM-08 (fix in the expansion)

1. **DEP step** maps `Win32_OperatingSystem.DataExecutionPrevention_SupportPolicy` straight to PASS. That property is an OS policy code. It doesn't show that any process is actually protected, so it proves configuration only. The OptIn branch (1) is also PASS, though OptIn covers only OS components.
2. **ASLR step** passes if `MitigationOptions` exists under the kernel key. The value's presence doesn't show that ASLR is enforced. This is the registry-equals-enforcement error the spec rules out.
3. Both steps tag output `[BAS-SIM]` and the description contains `[cite: 4, 5]`. Both are removed, as in EM-05 and EM-06.
4. Both steps are mapped to T1562 (Impair Defenses). That fits poorly: an exploit mitigation is a defence, and what it defeats is exploitation. The mapping needs review (decision 8.6).
5. The verdict uses PASS/FAIL only. There is no ERROR, SKIP or evidence field, so an unsupported mitigation would look like a failure.

## 2. Three questions per control

Every mitigation family answers, in its own test rows:
- **CONFIGURED**: what policy or registry state says it should be.
- **ENFORCED**: what the OS reports as the effective state, from Get-ProcessMitigation or the kernel-reported policy.
- **APPLIED**: which running processes actually get it, from per-process inspection of a fixed target list.

A test PASSes only on the question it asks. Configured alone is not PASS for an enforcement test.

## 3. Verdict and output contract

Each test returns one line, in the same shape as EM-05 and EM-06:
- Verdict: PASS, FAIL, ERROR or SKIP. The spec's "SKIPPED" is written as SKIP so the runner's counts match. (Decision 8.1.)
- Observed: the actual value read.
- Expected: the baseline for this host.
- Evidence source: the cmdlet, registry key or bcdedit field read.
- Skip reason: required when SKIP.

Rules:
- **Unsupported is not FAIL.** A mitigation the OS build or SKU doesn't expose returns SKIP with the reason, e.g. "not exposed on Windows Server 2019 build 17763."
- **Unconfigured is FAIL** only when the baseline requires it.
- **Read-only.** No write probes and no exploit execution. Nothing is launched beyond the cmdlets and reads listed here.

## 4. Evidence sources (all read-only)

- `Get-ProcessMitigation -System`: the system-wide policy for DEP, ASLR, CFG, SEHOP, heap, extension point, child process, image load, binary signature, dynamic code.
- `Get-ProcessMitigation -Name <image>`: the configured policy for an application image.
- `Get-ProcessMitigation -Running` plus per-process lookup: which running processes get which mitigation. Used for APPLIED.
- `bcdedit /enum {current}`: the `nx` boot value (OptIn / OptOut / AlwaysOn / AlwaysOff). Needs admin; on a non-admin run it returns SKIP.
- `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel`: kernel-side values, read only where a value is documented as effective.
- `Get-CimInstance Win32_OperatingSystem`: OS build and SKU, for the SKIP decision.

Assumption to verify before coding: the exact field names of Get-ProcessMitigation (e.g. `Dep`, `Aslr`, `Cfg`, `SEHOP`, `Heap`, `ExtensionPoint`, `ChildProcess`, `ImageLoad`, `BinarySignature`, `DynamicCode`) and which of them are returned on Server 2019 vs Windows 10. The lab output will settle this; the plan does not claim it.

## 5. Target process list

APPLIED tests need a fixed target list, so the counts don't change between hosts:
- `explorer.exe`, `powershell.exe`, `svchost.exe` (system), and one application image from a configured list.
- LSASS is **not** a target. Reading its mitigation state is not needed, and touching a protected process isn't worth the risk.
- Application tests read only the image names in a config list. With no list, they SKIP with "no application list configured."

## 6. Test list (about 50)

| Family | IDs | Tests |
|---|---|---|
| DEP | 01–06 | System DEP policy (CIM code and bcdedit nx, both reported); system DEP per Get-ProcessMitigation; per-process DEP on each target (APPLIED); DEP compatibility exceptions for targets; DEP on the Windows Defender process (or SKIP if not running); OptIn-only systems: FAIL unless per-process DEP is confirmed |
| ASLR | 07–12 | Force ASLR (system); bottom-up ASLR (system); high-entropy ASLR (system); per-process ForceRelocateImages on each target; per-process bottom-up/high-entropy on each target; image relocation support (count of target images with relocation data, read from the PE header) |
| CFG | 13–18 | System CFG; CFG strict mode (if exposed); per-process CFG on each target; CFG export suppression; CFG compatibility exceptions; CFG on a Microsoft-signed system binary |
| ACG | 19–22 | ACG (DynamicCode) per target; ACG allowed-opt-out list read; ACG on system-wide policy; ACG on the application list |
| CIG | 23–26 | Microsoft-signed-only binary policy (system); per-process BinarySignature on each target; CIG on the application list; CIG enforcement state from the policy |
| SEHOP | 27–29 | SEHOP system state (exception-chain validation; read-only); SEHOP per target; SEHOP for the application list |
| Heap | 30–32 | Heap termination on corruption (system); heap per target; heap on the application list |
| Image load | 33–36 | NoRemoteImages (system); NoLowMandatoryLabelImages (system); PreferSystem32 (system); image-load on the application list |
| Extension / child process | 37–40 | Extension-point restriction (system and per target); child-process restriction (system and per target) |
| Exploit Protection policy | 41–46 | System mitigation policy present; application-specific policies read per target; effective policy vs configured policy (compare, report mismatch); Group Policy source (read only); Defender Exploit Protection configuration (read only, SKIP if not exposed); reported as FAIL only when the baseline requires it |
| Application-specific | 47–50 | Four tests against the configured application list (per-app DEP, ASLR, CFG and ACG status); SKIP with reason when the list is empty |

Count: 50. The spec's 43–54 range is met.

## 7. Validation

- Syntax check of every step with the PowerShell parser before any run.
- Read-only run on the client (SKIP on mitigations a client SKU doesn't expose).
- Lab run on WIN-2IP8FNO4MAD (Server 2019). Expected: several tests SKIP on server-only exposure; the rest should show real observed values.
- Expected-baseline check: each baseline is written down before the run, so the lab result can't tune it.

## 8. Decisions needed

1. **Verdict word.** Use SKIP (matches the runner and EM-05/EM-06) or SKIPPED as in the spec?
2. **OptIn DEP.** On OptIn systems, FAIL unless per-process DEP is confirmed for the targets (my recommendation), or PASS with a note?
3. **Target list.** Accept explorer.exe, powershell.exe, svchost.exe, plus one application image? LSASS excluded.
4. **Application list.** Who supplies the application image list? Without it, tests 47–50 SKIP.
5. **Test count.** Accept about 50 (the spec's range is 43–54)?
6. **ATT&CK mapping.** T1562 is a poor fit. Options: keep it; map each mitigation to the exploitation technique it defeats (e.g. T1203 Exploitation for Client Execution); or leave technique_id blank for these checks. Which?
7. **Old steps.** Replace the two existing steps with the new rows (my recommendation), or keep the existing two untouched as step 01 and 02 and add the rest?

## 9. Sequence after approval

1. Verify the Get-ProcessMitigation field names on the lab server (read-only), and correct section 4's assumption.
2. Write the 50 steps and the baseline file.
3. Syntax check, sign, step-contract ratchet, ledger rows for em-08 only.
4. Client read-only run, then lab server run.
5. QA log, PR.
