# Akira ESXi and Virtual Infrastructure Assessment: QA log

Scenario `akira-esxi-assessment` v1.0.0, 8 steps, run from a Windows agent against lab ESXi hosts. Design: `docs/superpowers/specs/2026-11-18-akira-esxi-design.md` (approved; built directly from it, no separate plan document).

| Step | Tag | Behaviour | Verdict |
|---|---|---|---|
| E1 | T1133 | unauthenticated: ports 22, https, 902, 427, 5989; SSH banner; `/sdk` product, version, build | FAIL if any management port answers |
| E2 | T1078 | login with `BAS_ESXI_CRED_FILE` account; lockdown, SSH/Shell services, AD join | FAIL if login succeeds from this network; SKIP without hosts or credentials |
| E3 | T1018 | VM and powered-on counts | FAIL if enumerated |
| E4 | T1083 | datastore, accessible and type counts | FAIL if accessible datastores are visible |
| E5 | T1529 | `VirtualMachine.Interact.PowerOff` via HasPrivilegeOnEntities; no power-off | FAIL if granted on any VM |
| E6 | T1485 | RemoveSnapshot privilege, VMs without snapshots; gated canary snapshot on `BAS_ESXI_LAB_VM` | FAIL on privilege or canary |
| E7 | T1485 | `Datastore.FileManagement` and `LowLevelFileOperations`; gated XOR canary file on `BAS_ESXI_LAB_DATASTORE` | FAIL on privilege or canary |
| E8 | T1078 | ledger chain, AD "ESX Admins" group check, cleanup | FAIL if reachable + login + destructive privilege, or group exists |

Gate: `BAS_CONFIRM_ESXI_LAB_WRITE=true` (exact). T1490 and T1486 are deliberately not used (rwevidence models them as endpoint VSS and encryption). T1018 and T1529 newly mapped. Registered like the other ransomware scenarios; count pin 132 -> 133; step-contract baseline and ledger regenerated (new scenario has zero gaps).

## Evidence: a local stub, NOT an ESXi host

I wrote a Python stub (HTTPS, self-signed) that replays hand-written vSphere SOAP replies and a datastore `/folder` endpoint. Against it, the real scripts produced: readonly account: E1 FAIL, E2 FAIL (SSH running, lockdown disabled, AD domain read), E3 FAIL (4 VMs), E4 FAIL (2 datastores), E5/E6/E7 PASS, E8 PASS; admin account with the gate on: E5 FAIL (4 of 4), E6 canary snapshot created and removed, cleanup verified, E7 canary written, XOR round-trip true, content differs from plain, removed and verified, E8 FAIL (chain viable); wrong-case gate (`TRUE`) did not attempt canaries; bad password: E2 PASS, E3 and the rest SKIP; no credentials: E2-E7 SKIP; invalid host entries ignored; no hosts: SKIP; E8 without E1: SKIP; no work directories left after full runs. YAML commands are byte-identical to the scripts run; all parse; destructive-guard classification is non-destructive for every step; `verify-all` ok=163 fail=0; scenario (with step-contract ratchet), rwevidence, rwtaxonomy, rwdetect, rwrecover, compliance, adcoverage tests pass; `internal/api` corpus tests pass under `-short`.

Defects found by this review and fixed before commit: (1) the login helper printed a SKIP message and returned `$false`, but PowerShell merges printed text into the return value, so callers continued and E3 printed a false PASS after a failed login; the helper now sets a message and the caller prints it; (2) service state was read from elements named `service` whereas a real `ArrayOfHostService` value contains `HostService` elements, so SSH/Shell state would always have read empty on a real host.

## NOT verified (read before relying on this)

- Nothing was run against a real ESXi host or vCenter. The stub encodes my assumptions about vSphere SOAP: login cookie handling, `RetrieveServiceContent` field names, ContainerView plus PropertyCollector traversal, property value shapes (`config.lockdownMode`, the service array, AD `joinedDomain`, the `snapshot` property), `HasPrivilegeOnEntities` response shape, snapshot task polling (`info.state`, `info.result`), and datastore `/folder` PUT/GET/DELETE with Basic auth and `dcPath=ha-datacenter`. Any of these can differ on a real host (versions, lockdown mode, vCenter-managed hosts using different datacenter paths).
- The canary snapshot and datastore file were exercised only on the stub. Real snapshot creation on a lab VM, removal, and datastore folder deletion behaviour are untested; E6/E7 print a WARNING with manual cleanup steps if removal cannot be verified.
- E8 per-host chain is approximate: E6 and E7 record one ledger row for their first host.
- The ESX Admins group check never ran against a real domain (build host is a workgroup machine; the stub reports an AD-joined host but the LDAP half returned `agent_not_domain_joined`).
- E1 reads the version and build but does no vulnerability lookup. A build-host side effect worth knowing: on the build host port 902 answered (a VMware desktop service), so a closed-https-port run still reported E1 FAIL; the scenario cannot tell a desktop VMware service from ESXi by port alone.
- The credential file is read in clear from the agent host's disk; the scenario never prints it, but anyone who can read the file or the agent environment can. Use a dedicated read-only account.
- Real agent/orchestrator not used; `contentregistry` and the rest of `internal/api` tests need Docker; `ransomware.js` not browser-checked. No detection profiles are attached (none exist for ESXi).
- Branch `akira-esxi`, pushed, NOT merged to main.
