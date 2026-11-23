# Clipboard Collection Probe: validation expansion plan

Status: PLAN ONLY for the expansion (decisions in section 6 still open). The Stage 3 verdict fix from decision 6.6 is done: see commit ea363cb4.
Current file: scenarios/collection-clipboard-exfil.yaml (3 steps, signed, on main).

## 1. Defects in the current scenario

1. **Stage 3 always reports FAIL.** Both branches of the `$reached` check write a `FAIL:` line. A blocked or unreachable upload and a delivered one score the same. This is the most serious defect: the scenario cannot return PASS on any host.
2. **Stage 3 treats a failed DNS lookup as the control.** The comment says "unreachable only because the domain is .invalid". That is not a DLP control, so the result proves nothing about prevention.
3. **Stage 3 sends a real POST.** The spec allows `.invalid` for policy and resolution testing, not for transmitting marker text. The redesign must separate a resolution-level probe from any transmission.
4. **Stage 2 FAIL is not tied to detection.** A successful write and read-back is reported as FAIL with no check of whether any monitoring saw it, so PASS (detected) and FAIL (undetected) are not distinguished.
5. **Stage 1 implies access control.** Its output says the clipboard is "empty, so Stage 2 can run", which describes a precondition, not protection.
6. **Stage 2 depends on an empty clipboard.** A user with content on the clipboard gets SKIP with no synthetic capture. The spec asks for synthetic content as the primary path.
7. **Shared clipboard policy is not read.** Clipboard history and cloud sync are controlled by policy, which the scenario never looks at.
8. **Stage 2 clears the clipboard.** It is restored to empty, but if the user copies something during the step, `Clear()` removes it. The step needs a read-before-clear guard or a documented limit.

## 2. Verdict vocabulary (proposed)

- **PREVENTED** → PASS. A control stopped the action: clipboard access denied by policy, a DLP block, or a blocked transfer with the block recorded.
- **DETECTED** → PASS. The action happened and a monitoring source recorded it. Reported separately in the evidence line, and not counted as prevention.
- **UNDETECTED** → FAIL. The action happened and no prevention or monitoring source recorded it.
- **NOT_CONFIGURED** → SKIP. The required control or integration was not present, so the result cannot be assessed. Per constraint 6, this is never PASS.
- **ERROR** → ERROR. The check could not complete.

A verdict reads PASS only when the evidence names the control that acted. "Nothing happened" is not PASS.

## 3. Proposed tests (about 30)

| Area | Tests | What each checks | Evidence |
|---|---|---|---|
| Clipboard access and permissions (5) | API available; clipboard access policy readable (`HKLM` / `HKCU` clipboard keys); access restricted by policy; access from a non-interactive process recorded in event log; unauthorised access detection source present | Policy and API state, no content | Registry value, event log presence |
| Clipboard monitoring and detection (5) | Clipboard write detection source configured; read detection source configured; synthetic write produces an event; synthetic read produces an event; event source latency noted | Monitoring state, synthetic action | Event IDs, query results |
| Synthetic capture (4) | Empty clipboard handled; synthetic non-sensitive text used; capture attempt detected; no read of user content (test passes if the user-content branch is taken without reading) | Synthetic marker only | Marker run-id, detection result |
| Clipboard history and cloud sync (5) | History policy read; cloud sync policy read; cross-device restriction read; policy enforced (history disabled actually stops recording, where testable); policy-drift check | Policy values, not user history | Registry values |
| Remote Desktop redirection (4) | Clipboard redirection policy read (`fDisableClip`); RDP clipboard restriction state; remote-session clipboard policy applied; policy enforcement check without opening a session | Policy only, no session created | Registry values |
| DLP and sensitive data (5) | Synthetic sensitive-looking string (test pattern, not real data) passed to DLP detection; clipboard DLP policy enforced; block mode vs audit mode read; policy-triggered action recorded; DLP source present | Synthetic pattern only | DLP event or NOT_CONFIGURED |
| Exfiltration prevention (4) | DNS resolution of a `.invalid` test host (resolver behaviour only); egress control present for the test host; network control event recorded; blocked vs failed transfer classified | No data sent | Resolver/egress evidence |

Total: 32.

## 4. Implementation constraints

1. Never read clipboard content except the test's own synthetic marker.
2. Synthetic test strings only. The DLP test uses a pattern that is obviously fake.
3. No clipboard data leaves the host. The `.invalid` probe is a DNS resolution check, not a POST.
4. The exfiltration verdict depends on a network or DLP event, not on DNS failure.
5. Prevention and detection are scored separately (section 2).
6. Missing DLP, monitoring or policy sources give NOT_CONFIGURED (SKIP), never PASS.
7. Every test emits one evidence line with an explicit verdict.
8. No browser or RDP session is opened, no policy is changed, and no process is terminated.

## 5. Changes to the three existing steps

- **Clipboard 1 (presence):** keep the check, but rename it to a precondition check and remove the claim that it tests protection.
- **Clipboard 2 (synthetic capture):** use the synthetic marker as the main path. It runs whether or not the clipboard holds content, and it only reads back its own marker. Before any clear, it compares the current content against the marker so it never clears user data.
- **Clipboard 3 (upload):** replace the POST with a resolution-level probe plus an egress or DLP event query. Fix the always-FAIL bug. Score PREVENTED, DETECTED, UNDETECTED or NOT_CONFIGURED from evidence.

## 6. Decisions for you

1. **Scope.** One scenario of about 30 tests (recommended), or split into collection (clipboard tests) and exfiltration (network tests) scenarios?
2. **Policy reads count as evidence.** A registry value shows configuration, not enforcement. Should configuration-only results score PASS, or be a separate verdict (recommended: reported as CONFIGURED and scored SKIP unless enforcement is shown)?
3. **Exfiltration probe.** Resolution-only (recommended: no transmission of any kind, verdict based on an egress or DLP event query), or keep a POST of the marker, which the spec does not allow?
4. **Detection sources.** Which integrations should the probe query for DLP and egress events? If none is configured, the tests return NOT_CONFIGURED. Confirm this is acceptable for a first release.
5. **Stage 2 clipboard clear.** Keep the clear after a compare-before-clear guard (recommended), or drop the clear and leave the marker in place?
6. **Fix order.** Approve the always-FAIL fix for Stage 3 as a separate commit before the expansion (recommended), so the current scenario stops reporting false failures now.

## 7. Status

Stage 3 verdict fix done (ea363cb4). Expansion not started: no tests written, the POST is still in place, and section 6 decisions 1-5 are open.
