# Akira ESXi and Virtual Infrastructure Assessment: design (approved 2026-11-18)

Sub-project 5. New scenario `akira-esxi-assessment`, 8 steps, executed from a Windows agent against operator-listed ESXi hosts (`BAS_ESXI_HOSTS`, comma or semicolon separated, host or host:port). No agent runs on ESXi; evidence is hypervisor-side (API facts), not endpoint telemetry.

## Steps
E1 management-plane exposure, unauthenticated (T1133). E2 administrative access with an operator read-only account from `BAS_ESXI_CRED_FILE` (JSON `{"user","password"}`, never printed) (T1078). E3 VM discovery, counts only (T1018). E4 datastore exposure (T1083). E5 power-off privilege exposure via AuthorizationManager.HasPrivilegeOnEntities (T1529). E6 snapshot-removal privilege and snapshot inventory; gated canary snapshot (T1485). E7 datastore write privileges; gated canary file with XOR transform (T1485). E8 chain correlation, AD "ESX Admins" group check, cleanup (T1078).

## Rules
- Never executes VM power-off, snapshot deletion of existing snapshots, or VM disk encryption. Gated canaries (`BAS_CONFIRM_ESXI_LAB_WRITE=true` exact plus `BAS_ESXI_LAB_VM` for E6, `BAS_ESXI_LAB_DATASTORE` for E7) touch only objects BAS creates and verifies removal.
- Techniques avoid T1490/T1486 (rwevidence models them as VSS/encryption on endpoints). T1018 and T1529 are newly mapped.
- Premise stated in output: the agent sits outside the management network, so a successful login is exposure.

## Honest limits
No ESXi host is available; protocol code is verified against a local stub that replays hand-written vSphere replies (parsing and verdict logic only). Real ESXi behaviour, version quirks, certificate and lockdown semantics, task polling and datastore HTTP access are unverified.
