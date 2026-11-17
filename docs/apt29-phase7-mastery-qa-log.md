# APT29 Kill Chain Phase 7: QA log

**Naming note:** this work was built concurrently with a separate, independently
authored APT29 expansion (`apt29-kill-chain.yaml` reworked to 6 stages, plus
`apt29-execution-evasion.yaml`, `apt29-persistence.yaml`,
`apt29-credential-access.yaml`, `apt29-command-control.yaml`,
`apt29-collection-staging.yaml`, generated from a `scenarios-src/` pipeline). Both
landed on `main` around the same time. Rather than overwrite either, this scenario
ships under a distinct id, `apt29-kill-chain-phase7`, in
`scenarios/apt29-kill-chain-phase7.yaml`. The two overlap on roughly a dozen
technique IDs (T1053.005, T1059.001, T1071.001, T1071.004, T1482, T1547.001, T1027,
T1047, T1218.011, T1546.003, T1555.003, T1005) and each also covers techniques the
other doesn't — this scenario adds the full cloud-identity branch (5 techniques) and
several Windows techniques (discovery, lateral-movement, LSASS/DPAPI/Kerberos
credential-access detail) the other doesn't have. Reconciling the two into one
scenario is future work, by user decision, not done here.

Scenarios: `scenarios/apt29-kill-chain-phase7.yaml` (30 Windows stages, id
`apt29-kill-chain-phase7` — distinct from the separately-maintained
`apt29-kill-chain`), `scenarios/apt29-cloud-identity.yaml` (5 M365/Azure cloud
stages).
Spec: `docs/superpowers/specs/2026-11-17-apt29-kill-chain-phase7-expansion-design.md`.
Plan: `docs/superpowers/plans/2026-11-17-apt29-phase7-expansion.md`.
Runbook: `docs/apt29-phase7-lab-validation-runbook.md`.

## What is verified so far (structural, not live)

- `go test ./internal/scenario/...` green: both scenarios parse, step counts and
  `TechniqueID` ordering match the plan exactly (30 Windows, 5 cloud), every one of
  the 25 new Windows stages' `detection_profiles` reference resolves to a real
  profile file on disk, the step-contract ledger/baseline accounts for all 35 new
  steps with zero new gaps, and `TestBuiltinScenarios_AllHaveValidProductLine`
  confirms the new cloud file licenses correctly (141 builtin scenarios).
- `go run scripts/signer.go verify-all ../scenarios` → `ok=177 fail=0`.
- Credential-access tier (stages 19-23): confirmed by static grep that no command
  text calls a memory-read or secret-retrieval API (`ReadProcessMemory`, `VM_READ`,
  `MiniDumpWriteDump`, `CredRead`, `CryptUnprotectData` against a real file). This is
  a text-level check, not a runtime observation — see the runbook's "extra scrutiny"
  section for the live-endpoint version of this check.
- SKIP-gating (stages 8, 24-26): confirmed by running the guard logic directly with
  `BAS_APT29_TARGET_HOST` unset — all four print `SKIP` with an explicit reason,
  never `PASS:`/`FAIL:`.
- Cloud ERROR-gating (stages 1, 2, 4): confirmed by running the guard logic directly
  with no tenant env vars set — all three print `ERROR` with "cloud tenant not
  configured", never `PASS:`.
- T1547.001 appears twice in the ledger (stage 3's Run-key write, stage 15's
  Startup-folder write) as two distinct ledger entries — not merged.

## Still not shown to find anything in a real environment

Every claimed Sysmon/Security/Entra event ID in both scenarios — this scenario has
never been run on a real Windows endpoint or against a real Microsoft 365/Azure
tenant. The design doc's own requirement was explicit: "don't assume every API call
generates the expected EDR event." That check has not happened yet. Nor has:

- The multi-host-dependent stages (8, 24-26) run with a real second host configured
  (only the SKIP path, with no host, has been confirmed).
- The cloud branch run against a real tenant at all (only the ERROR-without-tenant
  path has been confirmed). Per the design doc, this scenario must never report PASS
  for an untested cloud stage — that rule is enforced in the YAML (`ERROR` before any
  tenant is configured), but has not yet been exercised with a real tenant present.
- Stage 19's LSASS access attempt's actual Sysmon EID 10 behavior on a real endpoint
  — the scenario's own text says this depends on the endpoint's process-access audit
  configuration and must not be assumed.

## Result table (fill in after a real lab run)

| Stage | Technique | Expected telemetry | Lab result | Cleanup verified |
|---|---|---|---|---|
| 1-5 (existing) | T1482, T1059.001, T1547.001, T1053.005, T1071.004 | (unchanged by Phase 7) | — | — |
| 6 | T1069.002 | Sysmon EID 1 (net.exe) | | |
| 7 | T1018 | Sysmon EID 1 (nltest.exe) | | |
| 8 | T1018 (remote) | SKIP without target / Sysmon EID 1+22 with target | | |
| 9 | T1518.001 | WMI query telemetry | | |
| 10 | T1016 | Sysmon EID 1 (ipconfig/arp) | | |
| 11 | T1047 | Sysmon EID 1 (WmiPrvSE.exe parent) | | |
| 12 | T1218.011 | Sysmon EID 1 (rundll32.exe) | | |
| 13 | T1027 | PowerShell EID 4104 | | |
| 14 | T1685.001 | Log config-change event | | |
| 15 | T1547.001 | Sysmon EID 11+23 | | |
| 16 | T1546.003 | Sysmon EID 19/20/21 | | |
| 17 | T1543.003 | Security EID 4697 | | |
| 18 | T1546.015 | Sysmon EID 13+14 | | |
| 19 | T1003.001 | Sysmon EID 10 (unconfirmed dependency on audit config) | | |
| 20 | T1555.004 | Sysmon EID 1 (cmdkey.exe) | | |
| 21 | T1555.003 | Low-fidelity file-metadata check | | |
| 22 | T1558.003 | Sysmon EID 1 (setspn.exe) | | |
| 23 | T1555 | DPAPI round-trip on synthetic data | | |
| 24 | T1021.002 | SKIP without target / Security EID 5140-5145 with target | | |
| 25 | T1021.006 | SKIP without target / Security EID 4624+WinRM 91 with target | | |
| 26 | T1569.002 | SKIP / ERROR / Security EID 4697 (3-way) | | |
| 27 | T1071.001 | Sysmon EID 22 | | |
| 28 | T1071.004 | Sysmon EID 22 x3 | | |
| 29 | T1005 | Sysmon EID 11 | | |
| 30 | T1041 | Sysmon EID 22 | | |
| Cloud 1 | T1098.001 | ERROR without tenant / Entra audit log with tenant | | |
| Cloud 2 | T1550.001 | ERROR without tenant / Entra audit log with tenant | | |
| Cloud 3 | T1556.007 | ERROR without tenant / read-only Graph call with tenant | | |
| Cloud 4 | T1114 | ERROR without tenant/mailbox / Graph search with both | | |
| Cloud 5 | T1087.004 | Local condition check only, no network call | | |
