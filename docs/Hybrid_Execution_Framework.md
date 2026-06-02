# Audspect BAS — Hybrid Execution Framework

Reference for the hybrid scenario model: how posture and live execution differ,
the safety guarantees, and what each technique is expected to do. This is the
template all hybrid scenario families follow (PurpleSharp AD drill, LOLBin
execution, and future families).

---

## 1. Execution-mode taxonomy

| Tier | Mode | What runs | Telemetry generated | Where it may run |
|------|------|-----------|--------------------|------------------|
| **0** | **Posture** (default) | Read-only configuration checks (`local_check`) | None — no attack behaviour | Any host, including production |
| **1** | **Live (lab-safe)** | Real techniques with **benign, self-cleaning** payloads | Genuine endpoint telemetry (EID/Sysmon) | **Isolated lab / test VM with snapshot only** |
| **2** | **Full-fidelity** (future, not enabled) | Real techniques with realistic payloads (real C2 listener, test-file encryption) | Maximum fidelity, irreversible side effects | Dedicated, network-isolated cyber range only |

The platform currently ships Tier 0 and Tier 1. Tier 2 is reserved for explicitly
isolated range scenarios and is not enabled by default.

A scenario opts into live capability with `executable: true`. The run mode is
chosen per run (`mode: posture | execute`); posture is always the default.

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
3. **Explicit acknowledgement** — the live request must include
   `confirmLive: true`. Without it the server rejects the run (HTTP 400). The
   dashboard sets this only after the operator accepts the live-execution warning.
4. **Optional justification** — an operator may pass `reason`, which is recorded
   in the audit log.
5. **Audit log** — every live dispatch emits:
   `[AUDIT] live-execution dispatched: user=<id> scenario=<id> agent=<id> run=<id> reason=<...>`
   and is also captured in the `scenario_runs` record (`initiated_by`, timestamps).

**Default is always posture.** Live mode must be chosen deliberately each run.
Run live mode only against an isolated lab / test VM with a snapshot — it will
trigger EDR/Defender by design and requires admin/SYSTEM for some techniques.
