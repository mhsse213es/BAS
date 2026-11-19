# Ransomware Lateral Movement and Containment Assessment: QA log

Scenario `ransomware-lateral-containment-assessment` v1.0.0, 5 steps, Windows. Design: `docs/superpowers/specs/2026-11-17-ransomware-lateral-containment-design.md` (approved; built directly from it, no separate plan document).

| Step | Technique / profile | Verdict logic |
|---|---|---|
| L1 | T1021 / windows_smb_lateral_probe | Per target: SMB 445, ADMIN$, WinRM, WMI, SCM with the current identity; FAIL if any admin channel opens; SKIP with no valid targets |
| L2 | T1570 / windows_smb_lateral_probe | Gate `BAS_CONFIRM_LATERAL_WRITE=true` (exact): marker to ADMIN$\Temp, read back, delete, verify; FAIL if written |
| L3 | T1569.002 / windows_malicious_service | Gate `BAS_CONFIRM_REMOTE_EXEC=true` (exact): transient service writes a marker, seen over SMB, marker and service removed and verified; FAIL if it ran |
| L4 | T1021.002 / windows_smb_lateral_probe | From ledger: executed on >=2 targets FAIL (propagation), 1 FAIL (lateral only), reachable but gated SKIP, reachable but blocked PASS, none reachable PASS. Never encrypts; deliberately not T1486 |
| L5 | T1021.002 / windows_smb_lateral_probe | Wait `BAS_CONTAINMENT_WAIT_SEC` (60, max 600), re-probe, read local isolation signals; PASS if all previously reachable targets dropped; FAIL if partial or none; SKIP if nothing reachable; removes work dir, verified |

Registered like the earlier ransomware scenarios; T1021 and T1569.002 mapped to lateral movement; scenario-count pin 129 -> 130.

## Evidence (build host as its own target; NOT cross-host)

Target = this host's own name. Ran the real scripts: L1 found SMB, ADMIN$, WinRM, WMI and SCM all open (FAIL). Gates off: L2/L3 SKIP, L4 SKIP (reachability-only). Wrong-case gates (`TRUE`, `1`) stayed SKIP. Gates on: L2 wrote, read back and removed the marker; L3 created, started and deleted a transient service whose marker was seen and removed (FAIL both); L4 reported executed_on=1; L5 reported the target still reachable (FAIL). Unreachable name: L1 PASS, L4 PASS, L5 SKIP. Invalid entries are ignored and counted. Mixed run (L2 gate only) gave `execution_steps_skipped_by_gate=1`. After every run: no `bas_lat*` in %TEMP% or C:\Windows\Temp, service `BASLat*` gone (1060). YAML commands are byte-identical to the scripts run. `verify-all` ok=159 fail=0; scenario, rwevidence, rwtaxonomy, rwdetect, rwrecover, admatrix and `internal/api` corpus tests pass under `-short`.

Defects found by this review and fixed before commit: (1) the `IPC$` check never returned true (removed, not a reliable signal); (2) the isolation-rule pattern `contain` matched Docker/HNS "Container Networking" rules (14 false signals), now `isolat|quarantin` excluding HNS/Container/Hyper-V/Sandbox/Application Guard; (3) L4 counted skipped-gate rows from a previous attempt in the same run (now only steps that never executed); (4) my own patch dropped a backslash from the ADMIN$ path (admin_share read False), caught by the next run.

## NOT verified

- Never run against a real second host: loopback proves script logic, not cross-host auth behavior, firewall or segmentation. No PASS branch for L2/L3 (a blocking control) and no containment PASS for L5 (reachability dropping) was observed.
- Real agent/orchestrator not used; `contentregistry` and the rest of `internal/api` tests need Docker and were not run; `ransomware.js` not browser-checked.
- Run on the build host: L2 and L3 executed their gated paths against this host (a benign marker and a transient service, both removed and verified).
- L5 reachability drops cannot be attributed to containment; EDR-side status is not queried (the existing `rwcontain` observer reads it separately).
- Identity: results depend on the current agent identity; a non-admin identity will mostly fail to open channels and report PASS, which says nothing about a privileged attacker.
- The work directory and ledger persist between steps; an aborted run leaves `%TEMP%\bas_lat_<run>`. The ledger is endpoint-local.
- WinRM and WMI probes use `Test-WSMan` and `Get-WmiObject` with the current token; WMI has a 15 s per-target timeout.
