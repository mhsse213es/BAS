# Audspect BAS — Hybrid Execution Framework

Reference for the hybrid scenario model: how posture and live execution differ,
the safety guarantees, and what each technique is expected to do. This is the
template all hybrid scenario families follow (PurpleSharp AD drill, LOLBin
execution, and future families).

---

## 1. Execution-mode taxonomy

| Mode | What runs | Telemetry generated | Where it may run | Gates |
|------|-----------|--------------------|------------------|-------|
| **Posture** (default) | Read-only configuration checks (`local_check`) | None — no attack behaviour | Any host, incl. production | role only |
| **Telemetry** (opt-in) | Real, **identity-safe** techniques (request-only / probe-only / handle-only) with benign, self-cleaning effects | Genuine endpoint telemetry (EID/Sysmon) | Production-safe under an approved window | `executable` + `confirmLive` |
| **Lab** (opt-in) | **Full-fidelity** emulation — persistence, real dumps, allowlisted spray | Maximum fidelity | **Isolated lab / AD range with snapshot only** | `executable` + `confirmLive` + `confirmLab` |

All three modes are enabled. A scenario opts into live capability with
`executable: true`; the mode is chosen per run (`mode: posture | telemetry | lab`,
default posture). Steps are filtered by `fidelity`: telemetry runs only
`telemetry-safe` steps; lab runs all. `execute` is accepted as a legacy alias for
`telemetry`.

The three tiers are operationally and commercially distinct: **Posture** =
continuous safe validation; **Telemetry** = production-safe detection validation
(primary SOC/EDR/SIEM layer); **Lab** = maximum-fidelity adversary emulation
(red/purple-team layer). They are never merged.

---

## 2. Safety / rollback framework

Every **live** step must satisfy these invariants (enforced by authoring review
and surfaced via per-step metadata):

- **Reversible / self-cleaning** — temp artifacts deleted, tasks removed, tickets
  purged. Declared via `reversible: true` and a `cleanup:` block.
- **No destructive payloads** — benign markers/empty scriptlets/`echo` only; never
  encryption, deletion of real data, or credential exfiltration.
- **No persistence unless explicitly testing persistence** — the only persistence
  technique (schtasks T1053.005) creates and immediately deletes its own task and
  is labelled as an explicit persistence test.
- **No outbound malicious C2** — no network egress to attacker infrastructure;
  encode/decode and process-spawn techniques run locally.
- **Audit logging for every action** — see §6.
- **Rollback guarantees** — each step's `cleanup` runs after execution (pass or
  fail); cleanups are idempotent (glob/pattern deletes, `-ErrorAction SilentlyContinue`).
- **Blast-radius / risk labels** — each step declares `risk` (low|medium|high) and
  a human `blast_radius` string so operators see the impact before running.

Per-step metadata fields (`scenario.Step`): `risk`, `blast_radius`, `reversible`,
`telemetry[]`, `detection[]`, `cleanup`.

---

## 3. Telemetry expectations — LOLBin execution (live mode)

| Technique | LOLBin | Risk | Expected telemetry |
|-----------|--------|------|--------------------|
| T1047 | WMI process creation | low | Security **EID 4688** (parent `WmiPrvSE.exe`); Sysmon **EID 1** |
| T1218.005 | mshta.exe | medium | Security **EID 4688** (mshta.exe); Sysmon **EID 1** |
| T1218.010 | regsvr32 + scrobj.dll (Squiblydoo) | medium | Sysmon **EID 7** (scrobj.dll image load); **EID 4688** regsvr32, parent powershell |
| T1140 | certutil.exe -encode | low | **EID 4688** certutil.exe; Sysmon **EID 1** with `-encode` |
| T1053.005 | schtasks.exe | medium | Security **EID 4698** (task created) + **EID 4699** (deleted) |

Every live step prints `EXEC`/`FAIL` (technique ran → a control gap exists) or
`PASS` (the technique was blocked by AppLocker/WDAC/EDR/Defender).

---

## 4. Posture vs. live-mode mappings — LOLBin

| Live technique | Posture control that defends against it |
|----------------|------------------------------------------|
| WMI process creation (T1047) | WinRM hardening; Sysmon coverage; ScriptBlock logging |
| mshta / regsvr32 / Squiblydoo (T1218.x) | **AppLocker** (deny rules); PowerShell **ConstrainedLanguage**; execution policy |
| certutil encode (T1140) | AppLocker / WDAC binary restriction; SIEM certutil arg detection |
| schtasks persistence (T1053.005) | AppLocker; least-privilege; 4698 alerting |
| (cross-cutting) detection | **ScriptBlock logging**, **Sysmon** presence |

Posture mode runs `lolbinPostureChecks()` on the agent: AppLocker, PowerShell
execution policy, PowerShell v2, WinRM, ScriptBlock logging, Sysmon.

---

## 5. Detection objectives (Sysmon / EDR / SIEM)

A mature SOC should, from a single live LOLBin run, observe:

- **Sysmon** — EID 1 (process create) for mshta/certutil/regsvr32 children; EID 7
  (image load) for `scrobj.dll`; command-line capture on all.
- **EDR** — suspicious parent→child chains: `WmiPrvSE.exe → powershell.exe`,
  `powershell.exe → regsvr32.exe → scrobj.dll`, `powershell.exe → certutil.exe`.
- **SIEM** — Security EID 4688 (with command line) for each LOLBin; EID 4698/4699
  for the scheduled-task lifecycle; correlation rules for `certutil -encode`,
  `regsvr32 /i:*.sct scrobj.dll`, and `mshta vbscript:`.

A missed signal = a detection gap to remediate; a `PASS` = the control prevented
the technique.

---

## 6. Operator guardrails & approval workflow

Live execution is gated at multiple layers:

1. **Role** — only Analyst/Admin can run scenarios (route-level RBAC).
2. **Scenario opt-in** — the scenario must declare `executable: true`. A live
   request against any other scenario is rejected (HTTP 400).
3. **Live acknowledgement** — any live run (telemetry or lab) requires
   `confirmLive: true`, else HTTP 400.
4. **Lab second-stage approval** — `mode: lab` additionally requires
   `confirmLab: true` (a separate, deliberate confirmation), else HTTP 400.
5. **Execution window** — if `live_policy.execution_window` is set, live runs
   outside the "HH:MM-HH:MM" local window are rejected (HTTP 400).
6. **Domain-controller interlock** — if `live_policy.block_on_domain_controller`
   is set and the target host is a DC, the agent aborts the whole run before any
   step executes.
7. **Account allowlist + attempt cap** — `live_policy.spray_account_allowlist`
   and `max_spray_attempts` are passed to the agent as env (`BAS_SPRAY_ALLOWLIST`,
   `BAS_MAX_SPRAY_ATTEMPTS`); the spray step refuses to target non-allowlisted
   accounts and caps attempts below the lockout threshold.
8. **Audit log** — every live dispatch emits:
   `[AUDIT] live-execution dispatched: mode=<...> user=<id> scenario=<id> agent=<id> run=<id> reason=<...>`
   and is captured in the `scenario_runs` record (`initiated_by`, timestamps).

**Default is always posture.** Telemetry and lab must be chosen deliberately each
run. Run lab mode only against an isolated lab / AD range with a snapshot — it
triggers EDR/Defender by design and requires admin/SYSTEM for some techniques.

---

## 8. Active Directory drill (PurpleSharp) — technique classification & policy

### Technique classification by risk
| Technique | Telemetry mode | Lab mode | Identity risk |
|-----------|----------------|----------|---------------|
| AD Enumeration (LDAP recon) T1087.002 | real read-only LDAP queries | same | very low |
| Kerberoasting T1558.003 | request **one** TGS; never export/crack/reuse; `klist purge` | same | low |
| LSASS access T1003.001 | **read-handle only** (no dump, no memory read) | comsvcs **MiniDump** created+deleted, never read | medium → high |
| Password Spraying T1110.003 | **non-existent probe** (cannot lock anyone) | **allowlisted** test accounts, capped < lockout threshold | low → high |

Persistence, lateral movement, and any credential reuse/ticket abuse are **lab-only**.

### Kerberos-safe execution
TGS requested via native `KerberosRequestorSecurityToken` to fire **4769** only;
the ticket is never serialised, cracked, or reused; the ticket cache is purged on
cleanup.

### Credential-handling policy
Never write hashes/tickets to disk; never export; never reuse. Telemetry mode
produces **no** LSASS dump file at all (handle only). The lab MiniDump is deleted
immediately and never read or exfiltrated.

### Domain-controller safety controls
`block_on_domain_controller` aborts live runs on a DC; `require_dc_reachable`
gates Kerberos operations; spray volume is capped via `max_spray_attempts`;
accounts are restricted to `spray_account_allowlist`.

### AD detection-telemetry matrix
| Technique | Windows Event | Sysmon | EDR signal |
|-----------|---------------|--------|------------|
| AD enumeration | 4662 (DS access) | — | bulk LDAP recon from one host |
| Kerberoasting | **4769** (RC4 = weak) | — | TGS for SPN, RC4 |
| Password spray | **4625**/4771; 4740 lockout **must NOT** fire | — | many 4625 one source/several accounts |
| LSASS read-handle | 4656/4663 (if SACL) | **EID 10** (GrantedAccess 0x1010/0x1410) | suspicious lsass read-handle |
| LSASS MiniDump (lab) | — | **EID 10** + dump-file create | comsvcs credential-theft behaviour |
