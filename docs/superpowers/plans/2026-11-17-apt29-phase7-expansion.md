# APT29 Kill Chain Phase 7 Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand `scenarios/apt29-kill-chain.yaml` from 5 to 30 Windows stages and add a
separate `scenarios/apt29-cloud-identity.yaml` (5 stages), each a real OS/API operation
with execution outcome, detection outcome and cleanup outcome recorded as three
independent fields, never collapsed into one self-reported line.

**Architecture:** Every new stage is hand-authored YAML in the existing `Step` shape
(`executor: powershell`, `technique_id`, `blast_radius`, `telemetry`, `detection`,
`detection_profiles`, `command`, `cleanup`), the same shape the current 5 APT29 stages
and every other kill-chain scenario already use — no new scenario schema. The
`detection_profiles` reference (`orchestrator/internal/scenario/detection.go`) already
carries the detection-outcome axis; `classifyExecution`
(`orchestrator/internal/scenario/outcome.go`) already carries the execution-outcome
axis; `step_contract_test.go` already carries the cleanup-outcome axis. The work is
authoring 30 real stages against that existing model, classifying each correctly in
`execclass.go`, and regenerating the ledger/baseline/signature once. The 4 real cloud
mutations use the existing `login.microsoftonline.com` OAuth2 client-credentials grant
called directly from PowerShell (`Invoke-RestMethod`) against Microsoft Graph — the
same flow `internal/platform/msauth.EntraTokenSource` already implements in Go for
other connectors — rather than a new Go connector/executor type, since PowerShell can
perform the grant and the Graph call natively with zero new orchestrator code. This is
a deviation from the design doc's "extend secretstore/msauth" sketch; see the Ruling
in Task 8.

**Tech Stack:** Go 1.x (`orchestrator` module), hand-authored scenario YAML, PowerShell
5.1/7, Microsoft Graph REST API, the repo's existing `scripts/signer.go` sign/verify-all
tooling.

**Spec:** `docs/superpowers/specs/2026-11-17-apt29-kill-chain-phase7-expansion-design.md`

## Global Constraints

- Every step is a real, reversible OS/API operation — never a printed claim of one.
- Credential-access-themed steps (LSASS, Credential Manager, browser stores, DPAPI,
  Kerberos) use only the approved real access-attempt tier: LSASS `OpenProcess` with
  query-only access (never reads process memory); Credential Manager enumeration APIs
  that never retrieve secret blobs; browser-store checks that validate
  location/metadata only, never extract a credential; DPAPI protect/unprotect on
  synthetic test data with disposable test keys only; Kerberos SPN/service-account
  enumeration that never requests or extracts a ticket.
- The 4 multi-host-dependent stages (T1018 remote-system-discovery, T1021.002,
  T1021.006, T1569.002) SKIP with an explicit reason when `$env:BAS_APT29_TARGET_HOST`
  is unset — never silently pass.
- A missing precondition (no target host, no cloud tenant, denied API) is ERROR or
  SKIPPED with an explicit reason — never read as PASS or FAIL.
- The cloud branch is code-complete but execution-unverified until a real tenant
  exists; it must never report PASS for a scenario that has not actually run against
  one.
- Every new/changed `.yaml` is re-signed; `signer.go verify-all` must stay 0 fail.
- `go test ./internal/scenario/...` must stay green, including the ratcheted
  `step_contract_test.go` baseline (gap counts may fall, never rise).
- No new scenario schema fields, no new Step executor type.

## Review Focus

1. **A credential-access step exposes real secret material.** The approved tier is
   query/enumerate/metadata-only; a wrong implementation choice (e.g. calling an API
   that returns a password blob, or `ReadProcessMemory` on LSASS) would silently
   build the exact capability this plan explicitly excludes. Pinned in Task 4's tests:
   assert the command text never calls a memory-read or secret-retrieval API.
2. **A multi-host-dependent stage reports PASS/FAIL instead of SKIP when no target is
   configured.** The most likely way this plan's own SKIP-gate requirement gets
   silently dropped. Pinned in Task 5: run each of the 3 stages with
   `BAS_APT29_TARGET_HOST` unset and assert the output contains `SKIP` and an explicit
   reason, never `PASS:` or `FAIL:`.
3. **A cloud stage reports PASS before a tenant exists.** The core anti-goal of the
   whole cloud branch. Pinned in Task 8: run each of the 4 real-mutation stages with
   the tenant env vars unset and assert `ERROR`/`SKIP`, never `PASS:`.
4. **A new technique ID silently becomes a step-contract gap.** Every new stage
   defaults to `ClassDestructive` in `execclass.go` unless reclassified; an
   unclassified discovery-only stage with no cleanup declared becomes a ratchet
   regression and fails CI, not a silent miss — but a stage that *should* be
   non-destructive and gets a fabricated no-op cleanup instead would hide the real
   risk tier. Pinned in Task 9: `TestStepContract_Ratchet` must show 0 new gaps and
   the per-stage class recorded in the ledger must match the stage's real behavior
   (read-only discovery → non_destructive; anything that creates/writes something →
   cleanup declared, not just marked non-destructive to dodge the requirement).
5. **Stage 15 (startup-folder persistence) collides with existing stage 3 (run-key
   persistence) on technique ID T1547.001.** A report or dedup path keyed only on
   `technique_id` could merge or hide one finding. Pinned in Task 3: assert both
   steps keep distinct names and distinct ledger entries (`Index` values), and that
   `go test ./internal/scenario/...` treats them as two steps, not one.

---

**Ruling (adapts the plan to a real convention found at execution time):** there is no
generic "every scenarios/*.yaml loads" test in this repo. Kill-chain scenarios are each
verified by their own dedicated `<scenario>_test.go` (see
`internal/scenario/black_basta_kill_chain_test.go`: `ParseYAML`, assert
`len(sc.Steps)`, assert the `TechniqueID` list in order). `apt29-kill-chain.yaml` has
no such file yet. Task 1 Step 1 below creates
`internal/scenario/apt29_kill_chain_test.go` with that shape; every later task's
"verify" step updates its expected step count and technique list instead of running a
nonexistent generic loader test. This replaces every "(same loader test as Task 1 Step
6)" reference below with "update and run
`go test ./internal/scenario/... -run TestAPT29KillChain -v`". Cost if wrong: none —
this is strictly additive test coverage this scenario was missing.

## Task 1: Discovery cluster — stages 6-10

**Files:**
- Modify: `scenarios/apt29-kill-chain.yaml` (append stages 6-10 after stage 5, before
  the file's closing newline)
- Create: `internal/scenario/apt29_kill_chain_test.go`

**Interfaces:**
- Consumes: existing `Step` YAML shape (`scenarios/apt29-kill-chain.yaml:56-84` as the
  template for a discovery-only stage — read-only command, no cleanup needed since
  non-destructive).
- Produces: 5 new stages other tasks don't depend on.

- [ ] **Step 0: Write the failing test**

  Create `internal/scenario/apt29_kill_chain_test.go`, following
  `black_basta_kill_chain_test.go`'s shape: `ParseYAML` the file from
  `../../../scenarios/apt29-kill-chain.yaml`, assert `len(sc.Steps) == 10`, assert
  `sc.Steps[i].TechniqueID` for i=0..9 equals
  `["T1482","T1059.001","T1547.001","T1053.005","T1071.004","T1069.002","T1018","T1018","T1518.001","T1016"]`
  (the first 5 are the existing stages; do not change their order).

  Run: `go test ./internal/scenario/... -run TestAPT29KillChain -v`
  Expected: FAIL — `got 5 steps, want 10` (the file still has only 5 stages).

- [ ] **Step 1: Append stage 6 — Domain privileged group enumeration (T1069.002)**

  Name: `"APT29 Stage 6 — Domain Privileged Group Enumeration (T1069.002)"`.
  Read-only: enumerate membership of Domain Admins/Enterprise Admins via
  `Get-ADGroupMember` or `net group "Domain Admins" /domain`. `requires_priv: user`,
  `risk: low`, no `cleanup` needed (read-only). Telemetry: Sysmon EID 1
  (`net.exe`/PowerShell `Get-ADGroupMember`), Security EID 4661/4662 if object-access
  auditing is on. Detection: Sigma rule for privileged-group enumeration. Output ends
  with an `EXEC T1069.002:` line and a `FAIL:`/`PASS:` line in the file's existing
  style (FAIL when the enumeration ran unimpeded, matching stage 1's convention).

- [ ] **Step 2: Append stage 7 — Domain controller discovery (T1018)**

  Name: `"APT29 Stage 7 — Domain Controller Discovery (T1018)"`. Read-only:
  `nltest /dclist:<domain>` or `Get-ADDomainController -Filter *`. Same
  non-destructive shape as Step 1.

- [ ] **Step 3: Append stage 8 — Remote system discovery (T1018), SKIP-gated**

  Name: `"APT29 Stage 8 — Remote System Discovery (T1018)"`. Reads
  `$env:BAS_APT29_TARGET_HOST` first. If unset: `Write-Output "SKIP: ... no remote
  target host configured ($env:BAS_APT29_TARGET_HOST unset). [BAS-SIM-APT29-S8]"` and
  stop — this is the pattern Task 5's stages 24-26 reuse verbatim, so get the exact
  wording right here once. If set: `Test-Connection`/`Resolve-DnsName` against that
  host only (read-only, no admin share or remote exec — that's stages 24-26).

- [ ] **Step 4: Append stage 9 — Security product discovery (T1518.001)**

  Name: `"APT29 Stage 9 — Security Product Discovery (T1518.001)"`. Read-only:
  enumerate AV/EDR via `Get-CimInstance -Namespace root/SecurityCenter2 -ClassName
  AntiVirusProduct` and running-process check for common EDR process names (read-only
  comparison against a literal list, never kills or tampers with any process — that
  is explicitly stage 14's different technique).

- [ ] **Step 5: Append stage 10 — Network configuration discovery (T1016)**

  Name: `"APT29 Stage 10 — Network Configuration Discovery (T1016)"`. Read-only:
  `ipconfig /all`, `Get-NetRoute`, `arp -a`.

- [ ] **Step 6: Run the test to verify it passes**

  Run: `cd orchestrator && go test ./internal/scenario/... -run TestAPT29KillChain -v`
  Expected: PASS — 10 steps, technique IDs match.

- [ ] **Step 7: Commit**

```bash
git add scenarios/apt29-kill-chain.yaml internal/scenario/apt29_kill_chain_test.go
git commit -m "feat(apt29): add discovery cluster stages 6-10 (T1069.002, T1018 x2, T1518.001, T1016)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

## Task 2: Execution / defense-evasion cluster — stages 11-14

**Files:**
- Modify: `scenarios/apt29-kill-chain.yaml` (append stages 11-14 after stage 10)

**Interfaces:**
- Consumes: stage 2's encoded-PS-loader step (`scenarios/apt29-kill-chain.yaml:89-127`)
  as the template for a benign-payload execution stage with real cleanup.
- Produces: 4 new stages other tasks don't depend on.

- [ ] **Step 1: Append stage 11 — WMI-based process execution simulation (T1047)**

  Name: `"APT29 Stage 11 — WMI-Based Process Execution Simulation (T1047)"`. Spawns a
  benign child process via `Invoke-CimMethod -ClassName Win32_Process -MethodName
  Create` with a command line that only writes a `[BAS-SIM]` string to a temp file
  (same benign-payload convention as stage 2), then deletes the temp file.
  `cleanup:` removes the temp file (belt-and-suspenders with the in-command delete).
  Telemetry: Sysmon EID 1 (wmiprvse.exe spawning the child) + EID 19/20/21 (WMI
  consumer/filter events do not apply here — only EID 1 is expected; don't claim 19-21
  since no permanent WMI subscription is created by this stage — that's stage 16).

- [ ] **Step 2: Append stage 12 — Rundll32 proxy execution (T1218.011)**

  Name: `"APT29 Stage 12 — Rundll32 Proxy Execution (T1218.011)"`. Runs
  `rundll32.exe` against a benign, already-present Windows DLL export that performs no
  harmful action (e.g. `rundll32.exe shell32.dll,Control_RunDLL` with no arguments, or
  an equivalent no-op export) — never a custom/downloaded DLL. `cleanup: ""` (no
  state changed). Telemetry: Sysmon EID 1 (`rundll32.exe` child of `powershell.exe`).

- [ ] **Step 3: Append stage 13 — PowerShell obfuscation detection (T1027)**

  Name: `"APT29 Stage 13 — PowerShell Obfuscation Detection (T1027)"`. Builds a
  benign command string obfuscated with string concatenation / backtick insertion /
  case randomization (same `[BAS-SIM]` benign payload as stage 2) and runs it via
  `Invoke-Expression`, then checks whether PowerShell ScriptBlock logging (EID 4104)
  captured the de-obfuscated form. `cleanup: ""`.

- [ ] **Step 4: Append stage 14 — Windows event logging impairment attempt (T1685.001)**

  Name: `"APT29 Stage 14 — Windows Event Logging Impairment Attempt (T1685.001)"`.
  Attempts `wevtutil sl Security /e:false` (disable the Security log) — a real,
  reversible OS operation — then immediately `wevtutil sl Security /e:true` to
  restore it, and reads back `wevtutil gl Security` to confirm the enabled state was
  restored. `cleanup:` re-enables the log as a second safety net in case the main
  command's restore step fails. `requires_priv: admin` (this needs local admin; stage
  must `ERROR` with an explicit reason if access is denied, not silently report
  PASS/FAIL — this is the "missing permission must never read as clean" rule applied
  here).

- [ ] **Step 5: Update the test and verify**

  Edit `internal/scenario/apt29_kill_chain_test.go`: extend the expected count to 14
  and append `"T1047","T1218.011","T1027","T1685.001"` to the technique-ID list.
  Run: `go test ./internal/scenario/... -run TestAPT29KillChain -v`. Expected: PASS,
  14 steps.

- [ ] **Step 6: Commit**

```bash
git add scenarios/apt29-kill-chain.yaml
git commit -m "feat(apt29): add execution/defense-evasion cluster stages 11-14 (T1047, T1218.011, T1027, T1685.001)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

## Task 3: Persistence cluster — stages 15-18

**Files:**
- Modify: `scenarios/apt29-kill-chain.yaml` (append stages 15-18 after stage 14)

**Interfaces:**
- Consumes: stage 3's HKCU Run-key stage (`scenarios/apt29-kill-chain.yaml:132-169`) as
  the write-then-delete template.
- Produces: stage 15 reuses technique_id `T1547.001` (same as existing stage 3) — see
  Review Focus item 5. Keep the two stages' `name` fields and ledger `Index` distinct;
  do not merge them.

- [ ] **Step 1: Append stage 15 — Startup folder persistence (T1547.001)**

  Name: `"APT29 Stage 15 — Startup Folder Persistence Write + Delete (T1547.001)"`
  (note: deliberately distinct name from stage 3's, even though both carry
  `T1547.001` — they test different mechanisms, per the design doc). Writes a
  `.lnk`/`.cmd` file into
  `$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup` containing a benign
  `[BAS-SIM]` echo, confirms it exists, deletes it, confirms deletion. `cleanup:`
  removes the file as a second safety net. Telemetry: Sysmon EID 11 (file create) +
  EID 23/26 (file delete).

- [ ] **Step 2: Append stage 16 — WMI event subscription persistence (T1546.003)**

  Name: `"APT29 Stage 16 — WMI Event Subscription Persistence (T1546.003)"`. Creates
  a real `__EventFilter` + `CommandLineEventConsumer` + `__FilterToConsumerBinding`
  triple via `Set-WmiInstance` whose consumer action is the benign `[BAS-SIM]` echo,
  confirms all three objects exist via `Get-WmiObject`, then removes all three via
  `Remove-WmiObject`, confirms removal. `cleanup:` removes all three WMI objects by
  name as a second safety net. Telemetry: Sysmon EID 19 (`__EventFilter` created), 20
  (`__FilterToConsumerBinding` created), 21 (`CommandLineEventConsumer` created).

- [ ] **Step 3: Append stage 17 — Windows service persistence (T1543.003)**

  Name: `"APT29 Stage 17 — Windows Service Persistence (T1543.003)"`. `requires_priv:
  admin`. Creates a real service via `New-Service -Name 'ZZ-BAS-APT29-Svc' -BinaryPathName
  'cmd.exe /c echo [BAS-SIM]' -StartupType Manual` (Manual, never auto-start — never
  actually `Start-Service`), confirms it exists via `Get-Service`, deletes it via
  `sc.exe delete` (per `feedback_agent_manual_cleanup_footgun` memory: use the
  equivalent clean removal, not a half-measure), confirms removal. `cleanup:` deletes
  the service by name as a second safety net. `ERROR` with explicit reason if service
  creation is denied (no admin), never PASS/FAIL. Telemetry: Security EID 4697
  (service installed) + EID 7045 (System log) + EID 4697-paired-deletion event.

- [ ] **Step 4: Append stage 18 — COM hijacking detection simulation (T1546.015)**

  Name: `"APT29 Stage 18 — COM Hijacking Detection Simulation (T1546.015)"`. Writes a
  benign override under
  `HKCU:\Software\Classes\CLSID\{<a harmless, well-known, non-critical CLSID>}\InprocServer32`
  pointing at a benign DLL path string (never a real hijack — the value is written and
  read back, never loaded/executed), confirms the write, deletes the key, confirms
  deletion. `cleanup:` removes the key as a second safety net. Telemetry: Sysmon EID
  13 (registry value set) + EID 14 (deleted).

- [ ] **Step 5: Update the test and verify**

  Edit `internal/scenario/apt29_kill_chain_test.go`: extend the expected count to 18
  and append `"T1547.001","T1546.003","T1543.003","T1546.015"` to the technique-ID
  list (note index 2 and the new entry for stage 15 both read `T1547.001` — assert
  both positions explicitly, this is the Review Focus item 5 check at author time;
  Task 9's ledger regeneration re-checks it at the ledger level).
  Run: `go test ./internal/scenario/... -run TestAPT29KillChain -v`. Expected: PASS,
  18 steps.

- [ ] **Step 6: Commit**

```bash
git add scenarios/apt29-kill-chain.yaml
git commit -m "feat(apt29): add persistence cluster stages 15-18 (T1547.001, T1546.003, T1543.003, T1546.015)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

## Task 4: Credential-access cluster — stages 19-23

**Files:**
- Modify: `scenarios/apt29-kill-chain.yaml` (append stages 19-23 after stage 18)

**Interfaces:**
- Consumes: none from earlier tasks.
- Produces: 5 new stages. This task is the one Review Focus item 1 is pinned to —
  every step's `command` text must be checkable against the approved tier below.

- [ ] **Step 1: Append stage 19 — LSASS access attempt (T1003.001)**

  Name: `"APT29 Stage 19 — LSASS Access Attempt (T1003.001)"`. `requires_priv: admin`
  (opening any handle to lsass.exe needs it). Command: a real
  `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, $false, $lsassPid)` call (via
  P/Invoke or `Get-Process lsass | Select-Object -ExpandProperty Handle`-equivalent
  query-only access — **never** `PROCESS_VM_READ`, never `MiniDumpWriteDump`, never
  any call that can return process memory), records whether the handle open
  succeeded or was denied, closes the handle. `cleanup: ""` (no state changed — this
  is why it's `ClassNonDestructive`, see Task 9). Output must state explicitly that
  only a query-only handle was requested and no memory was read. Telemetry: Sysmon
  EID 10 (ProcessAccess) *if* process-access auditing/Sysmon config captures
  query-only access rights — flag in the `detection` field that this depends on the
  endpoint's Sysmon config granularity (ties to Review Focus item 1's "don't assume
  every API call generates the expected EDR event").

- [ ] **Step 2: Append stage 20 — Windows Credential Manager access attempt (T1555.004)**

  Name: `"APT29 Stage 20 — Windows Credential Manager Access Attempt (T1555.004)"`.
  Command: enumerate stored credential *names/targets* only via
  `cmdkey /list` or the `CredEnumerate` Win32 API called with a filter, printing only
  the `TargetName`/`UserName` fields returned by the enumeration call — **never**
  `CredRead` on a specific target, which is the call that would return the secret
  blob. `cleanup: ""`.

- [ ] **Step 3: Append stage 21 — Browser credential store access attempt (T1555.003)**

  Name: `"APT29 Stage 21 — Browser Credential Store Access Attempt (T1555.003)"`.
  Command: checks for the *existence and file metadata* (path, size, last-write time)
  of the Chrome/Edge `Login Data` SQLite file and the Firefox `logins.json`/`key4.db`
  files under the current user's profile — **never** opens/queries the SQLite
  database, never calls `CryptUnprotectData` against any blob found there (that
  combination is DPAPI-unprotecting a real credential, explicitly excluded).
  `cleanup: ""`.

- [ ] **Step 4: Append stage 22 — Kerberos service account enumeration (T1558.003)**

  Name: `"APT29 Stage 22 — Kerberos Service Account Enumeration (T1558.003)"`.
  Command: `Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties
  ServicePrincipalName` (or `setspn -T <domain> -Q */*`) to list SPN-bearing
  accounts — **never** calls `Add-Type -AssemblyName System.IdentityModel` /
  `KerberosRequestorSecurityToken` or any API that requests a service ticket.
  `cleanup: ""`.

- [ ] **Step 5: Append stage 23 — DPAPI credential access simulation (T1555)**

  Name: `"APT29 Stage 23 — DPAPI Credential Access Simulation (T1555)"`. Command:
  generates a synthetic byte array (not derived from any real credential), calls
  `[System.Security.Cryptography.ProtectedData]::Protect` with
  `DataProtectionScope.CurrentUser` to produce a disposable protected blob, then
  `Unprotect` to recover the original synthetic bytes, confirms round-trip equality,
  and discards both buffers — **never** calls `Unprotect` against any file found on
  disk (that would be unprotecting a real stored secret, explicitly excluded).
  `cleanup: ""`.

- [ ] **Step 6: Verify — Review Focus item 1 check**

  Run: `grep -niE "ReadProcessMemory|VM_READ|MiniDumpWriteDump|CredRead\b|key4\.db.*Unprotect|CryptUnprotectData" scenarios/apt29-kill-chain.yaml`
  on just the lines added in this task (stages 19-23).
  Expected: no match. Any match is a Review Focus item 1 failure — fix the command
  before proceeding.

- [ ] **Step 7: Update the test and verify**

  Edit `internal/scenario/apt29_kill_chain_test.go`: extend the expected count to 23
  and append `"T1003.001","T1555.004","T1555.003","T1558.003","T1555"`.
  Run: `go test ./internal/scenario/... -run TestAPT29KillChain -v`. Expected: PASS,
  23 steps.

- [ ] **Step 8: Commit**

```bash
git add scenarios/apt29-kill-chain.yaml
git commit -m "feat(apt29): add credential-access cluster stages 19-23, real access-attempt tier only (T1003.001, T1555.004, T1555.003, T1558.003, T1555)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

## Task 5: Lateral-movement cluster — stages 24-26 (SKIP-gated)

**Files:**
- Modify: `scenarios/apt29-kill-chain.yaml` (append stages 24-26 after stage 23)

**Interfaces:**
- Consumes: Task 1 Step 3's exact SKIP-gate wording and `$env:BAS_APT29_TARGET_HOST`
  convention — reuse it verbatim in all 3 stages here.
- Produces: 3 new stages. This task is the one Review Focus item 2 is pinned to.

- [ ] **Step 1: Append stage 24 — SMB administrative share access (T1021.002)**

  Name: `"APT29 Stage 24 — SMB Administrative Share Access (T1021.002)"`. Checks
  `$env:BAS_APT29_TARGET_HOST` first; SKIP with explicit reason if unset. If set:
  attempts `Test-Path "\\$target\C$"` (existence check only — never copies a file to
  or from the share). `cleanup: ""`.

- [ ] **Step 2: Append stage 25 — WinRM remote execution simulation (T1021.006)**

  Name: `"APT29 Stage 25 — WinRM Remote Execution Simulation (T1021.006)"`. Same
  SKIP-gate. If set: `Invoke-Command -ComputerName $target -ScriptBlock { "[BAS-SIM]" }`
  (benign no-op command only). `cleanup: ""`.

- [ ] **Step 3: Append stage 26 — Remote service execution simulation (T1569.002)**

  Name: `"APT29 Stage 26 — Remote Service Execution Simulation (T1569.002)"`. Same
  SKIP-gate. If set: uses `sc.exe \\$target create` to create then immediately delete
  a benign Manual-start service on the remote host (never starts it). `cleanup:`
  deletes the remote service by name as a second safety net. `ERROR` with explicit
  reason (not SKIP) if the host is reachable but the create call is denied —
  distinguish "no target configured" (SKIP) from "target configured but access
  denied" (ERROR).

- [ ] **Step 4: Verify — Review Focus item 2 check**

  Run each of the 3 new stages' PowerShell directly with `$env:BAS_APT29_TARGET_HOST`
  explicitly unset (e.g. `Remove-Item Env:\BAS_APT29_TARGET_HOST -ErrorAction
  SilentlyContinue` first), capturing stdout.
  Expected: each stage's output contains `SKIP` and the literal reason text, and
  contains neither `PASS:` nor `FAIL:`.

- [ ] **Step 5: Update the test and verify**

  Edit `internal/scenario/apt29_kill_chain_test.go`: extend the expected count to 26
  and append `"T1021.002","T1021.006","T1569.002"`.
  Run: `go test ./internal/scenario/... -run TestAPT29KillChain -v`. Expected: PASS,
  26 steps.

- [ ] **Step 6: Commit**

```bash
git add scenarios/apt29-kill-chain.yaml
git commit -m "feat(apt29): add lateral-movement cluster stages 24-26, SKIP-gated on BAS_APT29_TARGET_HOST (T1021.002, T1021.006, T1569.002)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

## Task 6: C2 / collection / exfiltration cluster — stages 27-30

**Files:**
- Modify: `scenarios/apt29-kill-chain.yaml` (append stages 27-30 after stage 26)

**Interfaces:**
- Consumes: stage 5's DNS-beacon stage (`scenarios/apt29-kill-chain.yaml:216-249`) as
  the "real network call, no real C2" template.
- Produces: 4 new stages, completing the 30-stage Windows file.

- [ ] **Step 1: Append stage 27 — HTTPS C2 beacon simulation (T1071.001)**

  Name: `"APT29 Stage 27 — HTTPS C2 Beacon Simulation (T1071.001)"`. Issues a real
  HTTPS GET via `Invoke-WebRequest` to a fixed, BAS-owned, non-routable-by-design
  endpoint pattern analogous to stage 5's `.invalid` DNS domain (e.g.
  `https://bas-sim-apt29-<runid>.invalid/beacon` — same RFC 6761 guarantee, so the TLS
  handshake fails closed and no real C2 channel exists). Records whether the request
  succeeded (expected: no — DNS resolution itself fails first). `cleanup: ""`.

- [ ] **Step 2: Append stage 28 — DNS periodic beacon detection (T1071.004)**

  Name: `"APT29 Stage 28 — DNS Periodic Beacon Detection (T1071.004)"`. Distinct from
  existing stage 5 (single beacon): issues the same `.invalid`-domain `nslookup`
  pattern 3 times at a fixed interval (`Start-Sleep -Seconds 2` between calls) to
  generate a periodicity signal a SIEM could alert on, rather than stage 5's one-shot
  probe. `cleanup: ""`.

- [ ] **Step 3: Append stage 29 — Sensitive file discovery and collection (T1005)**

  Name: `"APT29 Stage 29 — Sensitive File Discovery and Collection (T1005)"`. Creates
  one benign synthetic file under `$env:TEMP` containing only the literal string
  `[BAS-SIM] synthetic sensitive-file marker` (never touches any real user file),
  searches for it with `Get-ChildItem -Recurse -Filter '*BAS-SIM*'` scoped to
  `$env:TEMP` only, confirms it's found, then deletes it. `cleanup:` deletes the file
  as a second safety net.

- [ ] **Step 4: Append stage 30 — HTTPS exfiltration simulation (T1041)**

  Name: `"APT29 Stage 30 — HTTPS Exfiltration Simulation (T1041)"`. Issues a real
  HTTPS POST via `Invoke-WebRequest -Method Post -Body '[BAS-SIM] synthetic exfil
  payload'` to the same `.invalid`-domain pattern as stage 27 (fails closed, no real
  exfil channel). `cleanup: ""`.

- [ ] **Step 5: Update the test and verify**

  Edit `internal/scenario/apt29_kill_chain_test.go`: extend the expected count to 30
  and append `"T1071.001","T1071.004","T1005","T1041"` (note index 4, the existing
  stage 5, is also `T1071.004` — the DNS beacon; stage 28 is the new periodic variant
  — assert both positions).
  Run: `go test ./internal/scenario/... -run TestAPT29KillChain -v`. Expected: PASS,
  30 steps.

- [ ] **Step 6: Commit**

```bash
git add scenarios/apt29-kill-chain.yaml
git commit -m "feat(apt29): add C2/collection/exfiltration cluster stages 27-30, completing the 30-stage Windows file (T1071.001, T1071.004, T1005, T1041)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

## Task 7: Detection profiles for the 25 new Windows stages

**Files:**
- Create or extend: `scenarios/detection-profiles/windows_apt29_discovery.yaml` (covers
  stages 6-10)
- Create or extend: `scenarios/detection-profiles/windows_apt29_defense_evasion.yaml`
  (covers stages 11-14, 16, 18)
- Create: `scenarios/detection-profiles/windows_apt29_persistence.yaml` (covers stages
  15, 17; reuse the existing `windows_runkey_persistence`/`windows_schtask_persistence`
  pattern already referenced by stages 3-4)
- Reuse (do not duplicate): `scenarios/detection-profiles/windows_credential_access.yaml`
  for stages 19-23 (`detection_profiles: [windows_credential_access]` — it's already a
  behavioral, technique-agnostic profile per its own header comment)
- Reuse: `scenarios/detection-profiles/windows_dns_c2.yaml` for stage 28 (already
  `technique_ids: [T1071.004]`); create
  `scenarios/detection-profiles/windows_apt29_lateral_movement.yaml` for stages 24-26,
  `scenarios/detection-profiles/windows_apt29_c2_exfil.yaml` for stages 27, 29, 30.
- Each new profile file gets a matching `.yaml.sig` from Task 9's signing step — do not
  sign individually here.

**Interfaces:**
- Consumes: the `profile`/`version`/`technique_ids`/`expected_detection` shape from
  `scenarios/detection-profiles/windows_dns_c2.yaml` (read in full during Task-1
  research) as the exact field template.
- Produces: profile names referenced by `detection_profiles:` on every stage 6-30 in
  Tasks 1-6 — go back and add the `detection_profiles: [<name>]` line to each of those
  25 stages now that the profile names exist (this task closes that loop; Tasks 1-6
  intentionally left it out since the profile files didn't exist yet).

- [ ] **Step 1: Write the 6 new/extended profile YAML files**

  Each file: `profile:` name matching the filename, `version: 1`, `technique_ids:`
  listing every stage's technique ID it covers, one `expected_detection` entry per
  distinct control expectation (provider, type, confidence, finding with
  severity/title/remediation/reference) — follow `windows_dns_c2.yaml`'s shape
  exactly. One profile may cover several stages when the expected control response is
  the same behavioral class (e.g. all 5 discovery stages share one
  "recon-correlation" SIEM expectation), matching the DRY precedent in
  `windows_credential_access.yaml`'s own header comment.

- [ ] **Step 2: Add `detection_profiles:` references back into stages 6-30**

  Edit `scenarios/apt29-kill-chain.yaml`: add a `detection_profiles: [<name>]` line
  to each of stages 6-30 (not stages 1-5, which already have theirs), pointing at the
  profile file written in Step 1 that covers that stage's technique.

- [ ] **Step 3: Write the wiring test, following the proven pattern**

  Add `TestParseYAML_APT29Phase7DetectionProfilesWired` to
  `internal/scenario/engine_test.go` (same shape as the existing
  `TestParseYAML_NewRansomwareFamiliesDetectionProfilesWired` at line 949: a
  `{file, stepName, wantProfile}` table, parse once, assert
  `step.DetectionProfiles == [wantProfile]` per case), with one row for every one of
  stages 6-30's exact `name` string and the profile it should reference.

  Run: `go test ./internal/scenario/... -run TestParseYAML_APT29Phase7 -v`.
  Expected: PASS.

- [ ] **Step 4: Confirm every referenced profile file exists on disk**

  Run: `for p in $(grep -oP 'detection_profiles: \[\K[^]]+' ../scenarios/apt29-kill-chain.yaml); do test -f "../scenarios/detection-profiles/${p}.yaml" || echo "MISSING: $p"; done`
  (run from `orchestrator/`; adjust the grep pattern to the exact YAML list syntax
  used). Expected: no `MISSING` lines.

- [ ] **Step 4: Commit**

```bash
git add scenarios/apt29-kill-chain.yaml scenarios/detection-profiles/windows_apt29_*.yaml internal/scenario/engine_test.go
git commit -m "feat(apt29): wire detection_profiles into the 25 new Windows stages

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

## Task 8: Cloud identity branch — `apt29-cloud-identity.yaml`

**Files:**
- Create: `scenarios/apt29-cloud-identity.yaml`
- Create: `scenarios/detection-profiles/windows_apt29_cloud_identity.yaml`

**Interfaces:**
- Consumes: the `login.microsoftonline.com` OAuth2 client-credentials grant shape from
  `orchestrator/internal/platform/msauth/entra.go:44-60` (read as reference for the
  exact token-request form fields: `grant_type=client_credentials`, `client_id`,
  `client_secret`, `scope`) — reimplemented in PowerShell via `Invoke-RestMethod`, not
  called from Go.
- Produces: `scenarios/apt29-cloud-identity.yaml`, a standalone scenario file (not
  appended to `apt29-kill-chain.yaml`).

**Ruling (ratifies the plan's deviation from the design doc's sketch):** the design doc
suggested extending `secretstore`/`msauth` with a new Go connector and wiring it into
the `Step` model via a new executor type. On inspection, `secretstore` is a
DB-integrated store for the platform's own long-lived connector credentials, not a fit
for a scenario's disposable test-app secret, and adding a new `Step` executor type is
new orchestrator engine work beyond scenario content. PowerShell's `Invoke-RestMethod`
can perform the identical OAuth2 client-credentials grant and the subsequent Graph REST
call with zero new Go code, keeping every cloud stage inside the existing
`executor: powershell` shape used everywhere else in this repo. This still satisfies
the approved "Option B" (real Graph mutations, not just local condition checks) for 4
of the 5 stages. Cost if wrong: if a future need genuinely requires Go-side Graph calls
(e.g. to share a cached token across stages, or call an SDK that has no plain-REST
equivalent), this gets revisited then — each stage here re-authenticates independently,
which is simple and acceptable for a scenario that runs a handful of times, not a
production integration.

- [ ] **Step 1: Write the scenario header and the env-var contract**

  `id: apt29-cloud-identity`, `product_line: killchain`,
  `name: "APT29 Kill Chain — Cloud Identity Branch (Phase 7)"`. Description states: 5
  M365/Azure stages, requires `BAS_APT29_CLOUD_TENANT_ID`,
  `BAS_APT29_CLOUD_CLIENT_ID`, `BAS_APT29_CLOUD_CLIENT_SECRET` (a least-privilege test
  app registration's credentials — never a production app), plus
  `BAS_APT29_CLOUD_TEST_MAILBOX` (a synthetic test mailbox's UPN) for the mailbox
  stage. Explicitly states: execution-unverified until a real test tenant is
  configured; every stage ERRORs with an explicit "cloud tenant not configured" reason
  when the 3 required env vars are unset, and must never report PASS in that case.
  `supported_os: [windows]`, `executable: true`.

- [ ] **Step 2: Write stage 1 — Service principal credential addition (approved
  cloud-branch technique 1)**

  Name: `"APT29 Cloud Stage 1 — Service Principal Credential Addition"`. If the 3
  required env vars are unset: `Write-Output "ERROR: cloud tenant not configured
  (BAS_APT29_CLOUD_TENANT_ID/CLIENT_ID/CLIENT_SECRET unset) — stage not run.
  [BAS-SIM-APT29-CLOUD-1]"` and stop. Otherwise: acquires a token via the
  client-credentials grant, calls Graph `POST
  /applications/{id}/addPassword` on the test app's own service principal (never a
  different, pre-existing production app) to add a disposable client-secret
  credential, confirms it via `GET`, then calls `removePassword` to delete it,
  confirms removal. `cleanup:` calls `removePassword` again (idempotent) as a second
  safety net.

- [ ] **Step 3: Write stage 2 — OAuth application permission abuse**

  Name: `"APT29 Cloud Stage 2 — OAuth Application Permission Abuse"`. Same
  env-var-unset ERROR path. Otherwise: grants the test app a real but narrow Graph
  delegated/application permission scope via `POST
  /oauth2PermissionGrants` (a scope explicitly listed as test-safe, e.g.
  `User.Read` only — never `Mail.ReadWrite`/`Directory.ReadWrite.All` or any
  tenant-wide admin scope), confirms the grant exists, then deletes it via `DELETE
  /oauth2PermissionGrants/{id}`, confirms removal. `cleanup:` deletes the grant by ID
  as a second safety net.

- [ ] **Step 4: Write stage 3 — SAML token forgery detection**

  Name: `"APT29 Cloud Stage 3 — SAML Token Forgery Detection"`. Same env-var-unset
  ERROR path. Otherwise: reads the test app's federation/SAML signing-certificate
  configuration via `GET /applications/{id}/federatedIdentityCredentials` (or the
  equivalent SAML config endpoint) and checks it against an expected baseline
  (certificate thumbprint, validity window) — a real read-and-compare, never forges or
  installs a certificate. `cleanup: ""` (read-only).

- [ ] **Step 5: Write stage 4 — Mailbox collection**

  Name: `"APT29 Cloud Stage 4 — Mailbox Collection"`. Same env-var-unset ERROR path,
  plus ERROR if `BAS_APT29_CLOUD_TEST_MAILBOX` is also unset. Otherwise: calls Graph
  `GET /users/{testMailbox}/messages?$search=...` against the synthetic test mailbox
  only (never a real user's mailbox — the stage must refuse to run against any UPN
  other than the one in `BAS_APT29_CLOUD_TEST_MAILBOX`), confirming the search
  succeeds and recording the result count. `cleanup: ""` (read-only, no state
  changed — it only searched, never moved/deleted/forwarded anything).

- [ ] **Step 6: Write stage 5 — Cloud account discovery (condition check, not a real
  mutation)**

  Name: `"APT29 Cloud Stage 5 — Condition Check: Cloud Account Discovery (T1087.004)"`.
  Per the design doc's finding (no real atomic exists for this technique on this
  platform), this stage is a local condition check, matching
  `entra-hybrid-identity-attack.yaml`'s existing precedent for the same gap: it checks
  for the *presence* of cached cloud-account artifacts on the endpoint (e.g. a Microsoft
  365 token cache file under `$env:LOCALAPPDATA\Microsoft\IdentityCache`) rather than
  querying the tenant. State this plainly in the step's `blast_radius` field so it's
  never confused with the other 4 stages' real mutations.

- [ ] **Step 7: Write the detection-profile file**

  `scenarios/detection-profiles/windows_apt29_cloud_identity.yaml`: one profile
  covering `technique_ids: [T1098.001, T1550.001, T1556.007, T1114, T1087.004]` (or the
  precise IDs that match the 5 cloud stages above), `expected_detection` entries for
  Entra sign-in risk / Microsoft Defender for Cloud Apps-style OAuth consent alerting,
  following the same shape as Task 7's profiles.

- [ ] **Step 8: Verify — Review Focus item 3 check**

  Run stages 1, 2, 4 (the real-mutation, env-var-gated ones) with all cloud env vars
  explicitly unset. Expected: each stage's output contains `ERROR` and the literal
  "cloud tenant not configured" reason, and contains no `PASS:` line.

- [ ] **Step 9: Write the parse test and verify**

  Create `internal/scenario/apt29_cloud_identity_test.go`, same shape as
  `apt29_kill_chain_test.go` from Task 1: `ParseYAML` the new file, assert
  `len(sc.Steps) == 5`.
  Run: `go test ./internal/scenario/... -run TestAPT29CloudIdentity -v`. Expected:
  PASS.

- [ ] **Step 10: Commit**

```bash
git add scenarios/apt29-cloud-identity.yaml scenarios/detection-profiles/windows_apt29_cloud_identity.yaml internal/scenario/apt29_cloud_identity_test.go
git commit -m "feat(apt29): add cloud identity branch — 4 real Graph mutations + 1 condition check, execution-unverified pending a test tenant

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

## Task 9: Execution-class, step-contract ledger/baseline, signing

**Files:**
- Modify: `orchestrator/internal/scenario/execclass.go` (add entries for the new
  technique IDs that are genuinely non-destructive: all 5 discovery stages (T1069.002,
  T1018 x2, T1518.001, T1016), the 5 credential-access stages (T1003.001, T1555.004,
  T1555.003, T1558.003, T1555), T1218.011, T1027, the 3 lateral-movement stages
  (T1021.002, T1021.006, T1569.002), T1071.001, T1071.004, T1005, T1041 — every stage
  whose `cleanup` field is legitimately `""` because nothing persists. Leave the
  persistence/service/logging-impairment stages (T1547.001 x2, T1546.003, T1543.003,
  T1546.015, T1685.001) at the default `ClassDestructive`/`ClassPotentiallyDestructive`
  since they declare real `cleanup:` text instead.)
- Modify: `orchestrator/internal/scenario/testdata/step_contract_ledger.json`,
  `orchestrator/internal/scenario/testdata/step_contract_baseline.json` (regenerated,
  not hand-edited)
- Modify: `scenarios/apt29-kill-chain.yaml.sig`, create
  `scenarios/apt29-cloud-identity.yaml.sig`, create `.sig` for every new file in
  `scenarios/detection-profiles/` from Task 7 and Task 8

**Interfaces:**
- Consumes: every stage written in Tasks 1-8.
- Produces: nothing further downstream — this is the integration task that closes the
  loop for Tasks 1-8's content.

- [ ] **Step 1: Classify the new technique IDs**

  In `execclass.go`, add one entry per technique ID listed above, `Class:
  ClassNonDestructive`, following the existing map's shape exactly
  (`orchestrator/internal/scenario/execclass.go:51-220` as the template).

- [ ] **Step 2: Run the step-contract test to see the current (pre-regeneration) gap
  count**

  Run: `cd orchestrator && go test ./internal/scenario/... -run TestStepContract -v`
  Expected: `TestStepContract_Ratchet` FAILs if any new stage introduces a gap beyond
  the recorded baseline (expected at this point, since the baseline hasn't been
  regenerated yet) — read the failure output to confirm every reported gap is one this
  plan intended (SKIP-gated stages and persistence stages with real cleanup should show
  0 gaps; if a stage shows an unexpected gap, fix that stage's `cleanup`/`Irreversible`
  field now, don't just regenerate over it).

- [ ] **Step 3: Regenerate the ledger and baseline**

  Run: `cd orchestrator && STEP_CONTRACT_WRITE=1 go test ./internal/scenario/... -run TestStepContract -v`
  Expected: PASS, and `git diff --stat
  internal/scenario/testdata/step_contract_ledger.json
  internal/scenario/testdata/step_contract_baseline.json` shows only additions for
  `apt29-kill-chain.yaml` and `apt29-cloud-identity.yaml` entries — no unrelated
  scenario's numbers change.

- [ ] **Step 4: Review Focus item 5 check at the ledger level**

  Run: `grep -A3 '"scenario": "apt29-kill-chain.yaml"' orchestrator/internal/scenario/testdata/step_contract_ledger.json | grep -c '"technique": "T1547.001"'`
  Expected: `2` — stage 3 and stage 15 both present as distinct ledger entries.

- [ ] **Step 5: Run the full scenario package test suite**

  Run: `cd orchestrator && go test ./internal/scenario/... 2>&1 | tail -20`
  Expected: `ok`, 0 failures.

- [ ] **Step 6: Sign everything**

  Run (adjust paths to match the repo's actual signer invocation, e.g. from Task-1
  research of `orchestrator/scripts/signer.go`'s usage in the ADCS work):
  ```
  cd orchestrator
  go run scripts/signer.go sign private_key.pem ../scenarios/apt29-kill-chain.yaml
  go run scripts/signer.go sign private_key.pem ../scenarios/apt29-cloud-identity.yaml
  for f in ../scenarios/detection-profiles/windows_apt29_*.yaml; do go run scripts/signer.go sign private_key.pem "$f"; done
  go run scripts/signer.go verify-all ../scenarios
  ```
  Expected: `verify-all` reports `ok=<N> fail=0` where `N` includes every file just
  signed.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/scenario/execclass.go orchestrator/internal/scenario/testdata/step_contract_ledger.json orchestrator/internal/scenario/testdata/step_contract_baseline.json scenarios/*.sig scenarios/detection-profiles/*.sig
git commit -m "feat(apt29): classify new technique IDs, regenerate step-contract ledger/baseline, sign all new/changed YAML

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

## Task 10: Lab-validation runbook and QA-log entry

**Files:**
- Create: `docs/apt29-phase7-lab-validation-runbook.md`
- Create: `docs/apt29-phase7-mastery-qa-log.md`

**Interfaces:**
- Consumes: the exact stage names/technique IDs from Tasks 1-8, and the pattern already
  proven in `docs/adcs-lab-validation-runbook.md`/`docs/adcs-mastery-qa-log.md`
  (read those two files in full before writing, so the new docs follow the same
  structure: baseline run, per-stage expected telemetry, revert/cleanup checklist,
  result table left blank for the user to fill in after a real lab run).
- Produces: nothing further downstream — this closes the plan's lab-validation goal by
  giving the user the checklist, not by running it (per the design doc, the actual lab
  run against real Sysmon/Security events is the user's own next step, same as every
  prior lab-validation phase in this repo).

- [ ] **Step 1: Write `docs/apt29-phase7-lab-validation-runbook.md`**

  Structure per stage 6-30 (and the 5 cloud stages, marked "requires a test tenant —
  do this part only once one exists"): what to run, the exact `Get-WinEvent` filter
  that should confirm the claimed Sysmon/Security event ID actually fired (addressing
  "don't assume every API call generates the expected EDR event" directly — this is
  the whole point of the runbook), and the cleanup-verification command. Include the
  explicit warning for Task 9 Step 1's `ClassNonDestructive` stages that
  Review-Focus-item-1-sensitive credential-access stages (19-23) must show their
  command never called a memory-read/secret-retrieval API, cross-referencing Task 4
  Step 6's grep.

- [ ] **Step 2: Write `docs/apt29-phase7-mastery-qa-log.md`**

  A result table with one row per stage (35 rows: 30 Windows + 5 cloud), columns
  `Stage | Technique | Expected telemetry | Lab result (fill in) | Cleanup verified
  (fill in)`, left blank except for the Windows-stage rows already exercised by this
  plan's own `go test` runs (Steps already verified structurally, not yet against a
  real lab endpoint — state that distinction explicitly in the doc's header, matching
  `docs/adcs-mastery-qa-log.md`'s own "Still not shown to find anything in a real
  environment" convention).

- [ ] **Step 3: Commit**

```bash
git add docs/apt29-phase7-lab-validation-runbook.md docs/apt29-phase7-mastery-qa-log.md
git commit -m "docs(apt29): lab-validation runbook and QA-log scaffold for the Phase 7 expansion

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

## Completion

- [ ] **Full suite:** `cd orchestrator && go test ./... 2>&1 | tail -30` — expected
  `ok` across all packages (the pre-existing unrelated `internal/api` test timeout, if
  it recurs, is a known issue — note it, don't block on it).
- [ ] **Push:** `git push -u origin HEAD` from a feature branch (confirm branch name
  with the user before pushing, or follow `finishing-a-development-branch` at the end
  of the executing-plans run).
