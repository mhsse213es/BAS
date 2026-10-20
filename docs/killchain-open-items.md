# Full Kill Chain: Open Items

Status as of 2026-10-20. Companion to `docs/fullkillchain-foundation-audit.md`
(section 13 records what is built). Nothing here is marked done until its
evidence exists.

Staging server and test machine are **not available** to this work at the
moment. Items that need them are listed as blocked, not planned.

## Blocked on staging or a test machine

| # | Item | Blocks | Closed by |
|---|------|--------|-----------|
| 1 | Real dispatch and evidence on staging | Built: stages dispatch posture runs through the existing run path and collect the result. Not run against a real agent here. QA on staging is the user's. | Staging run of one campaign stage end to end. |
| 2 | Lab and live campaign runs | Campaign stages are posture-only. Telemetry and lab stages need the live-run gate replicated, which is not built. | A decision on the gate, then staging tests. |
| 3 | Lab validation of the vertical slice (identity, endpoint, lateral) | Any `lab-validated` claim. Nothing is lab-validated today. | A representative lab with ground-truth capture. |
| 4 | Live validation | Any `live-validated` claim. | Authorised run against the supported product in a test environment. |
| 5 | Ground-truth source per scenario | Prevention and execution verdicts. Built: a per-run ground-truth record that refuses the scenario run record as a source, requires a reference to the evidence, and accepts only a source class the scenario allows (identity: host event log or EDR; lateral: event log, network sensor or EDR; operator observation is refused for both). Automatic collection from a real host or sensor is not built; it needs staging. Stages without a record still stop at INCONCLUSIVE. Real sources (host or sensor) are still needed, on staging. | For each scenario, an independent record of what executed (host process record, file hash, network log). Design work, then staging to confirm. |
| 6 | Detection telemetry for each stage | Detection verdicts. Built: stage collection reads the run's attestations from the verification path, and a not-detected stays INCONCLUSIVE unless health and window are known. Connected telemetry on staging is still needed for any real detection. | Connected SIEM or EDR telemetry on staging, with health confirmed. |

## Not blocked, tracked here

| # | Item | Status |
|---|------|--------|
| 7 | API-created definitions must be signed | Built: create requires a signature over the exact bytes, and refuses unsigned or tampered definitions (403). The signing key is the project key, so the operator signs with it. |
| 10 | Interrupted campaigns at boot | Built: boot recovery collects finished runs and marks unfinished ones interrupted. It never starts a stage. Test on staging. |
| 8 | `DETECTED_NOT_CONTAINED` does not mark a campaign failed | Ruling made, see audit section 13.1. Reconsider if a reviewer disagrees. |
| 9 | Lateral scenario has no `id:` field in its YAML | Resolved in practice: the engine loads it by filename. Making the ID explicit is a small cleanup. |
| 11 | Coverage levels for lab and live need real proof records | Built as a model. No proof records exist yet, so the report shows zero at those levels. |

## Rules for closing items

- A verdict may change only when its evidence changes.
- A missing ground truth, telemetry or agent is reported as missing. It is never treated as a pass.
- Lab and live claims are made only with a stored run reference.

## Finding: existing host telemetry is detection evidence, not execution evidence

The agent already submits per-run detection alerts to
`POST /api/scenarios/runs/{id}/detections` (`agent/agent.go` around line 1207,
collected by `collectAlerts` in `agent/detect_windows.go`, reading the
alert-tier channels listed at `detect_windows.go:20`). They are an independent
host-side record, but they prove a detection happened. They do not prove a
step executed, so they must not be mapped to ground-truth `executed = yes`.

To build an execution source for identity and lateral stages, the agent needs
a process-creation and logon channel that it does not collect today (for
example Security 4688 and 4624/4648, or Sysmon event 1). Adding that is an
agent change. It can only be verified on a Windows host with those logs
enabled, so it is blocked on staging. Decision needed before it is built:
which channel to add first, and whether the agent should ship it.
