# Ransomware Lateral Movement and Containment Assessment: design (approved 2026-11-17)

Sub-project 3 of the Akira programme (user stages 26-29 plus old stage 42). Parent: `2026-11-17-akira-expansion-part1-design.md`.

## Intent
Establish whether a simulated compromise can reach and execute on other Windows endpoints, how many, and whether anything contains it, without propagating ransomware. Evidence is endpoint-visible only.

## Scope
Scenario `ransomware-lateral-containment-assessment`, 5 steps, Windows, read-only by default. Targets are operator-listed lab hosts in `BAS_LATERAL_TARGETS` (semicolon or comma separated; hostname characters only). Unset = SKIP. The current identity only; no credential guessing.
- L1 (T1021) auth reachability over SMB, WinRM, WMI and SCM; read-only.
- L2 (T1570) gated `BAS_CONFIRM_LATERAL_WRITE=true`: benign marker on ADMIN$, hash read-back, delete, verify.
- L3 (T1569.002) gated `BAS_CONFIRM_REMOTE_EXEC=true`: benign service writes a marker; confirmed over SMB; service and marker removed and verified.
- L4 (T1021.002) propagation assessment from the ledger: reachable and executed targets per channel, blast radius. Never encrypts. Not tagged T1486: rwevidence models T1486 as encryption and would misgrade it.
- L5 (T1021.002) containment response: wait `BAS_CONTAINMENT_WAIT_SEC` (default 60, cap 600), re-probe, read local isolation signals; PASS if previously reachable targets dropped; FAIL if all still reachable; SKIP if nothing was reachable. Cannot attribute the cause; EDR-side status stays with `rwcontain`.

## Non-goals
No encryption, no real tools, no persistence beyond a transient benign service, no orchestrator two-agent correlation (efficacy sub-project), no EDR API calls.

## Honest limits
Single-agent view; no second-host lab here, so testing uses this host as its own target (loopback is not cross-host). Ledger is endpoint-local.

## Approaches
A (chosen) one hand-written scenario; B two scenarios (rejected: containment needs propagation); C orchestrator correlation (deferred).
