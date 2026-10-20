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
| 5 | Ground-truth source per scenario | Prevention and execution verdicts. Without it, stages stop at INCONCLUSIVE. | For each scenario, an independent record of what executed (host process record, file hash, network log). Design work, then staging to confirm. |
| 6 | Detection telemetry for each stage | Detection verdicts. | Connected SIEM or EDR telemetry on staging, with health confirmed. |

## Not blocked, tracked here

| # | Item | Status |
|---|------|--------|
| 7 | API-created definitions must be signed | Built: create requires a signature over the exact bytes, and refuses unsigned or tampered definitions (403). The signing key is the project key, so the operator signs with it. |
| 10 | Interrupted campaigns at boot | Built: boot recovery collects finished runs and marks unfinished ones interrupted. It never starts a stage. Test on staging. |
| 8 | `DETECTED_NOT_CONTAINED` does not mark a campaign failed | Ruling made, see audit section 13.1. Reconsider if a reviewer disagrees. |
| 9 | Lateral scenario has no `id:` field in its YAML | Resolved in practice: the engine loads it by filename. Making the ID explicit is a small cleanup. |
| 10 | Interrupted campaigns are reconciled only when the orchestrator is called again | Open. No background reconciler at boot. |
| 11 | Coverage levels for lab and live need real proof records | Built as a model. No proof records exist yet, so the report shows zero at those levels. |

## Rules for closing items

- A verdict may change only when its evidence changes.
- A missing ground truth, telemetry or agent is reported as missing. It is never treated as a pass.
- Lab and live claims are made only with a stored run reference.
