# Kill chain live and lab gate: design

Status: steps 1 to 4 built, flag off, nothing live enabled. Separation of duties
and approval scope are decided and built. Verification needs staging, which is not
available here. No live or lab claims are made.

## Decisions

| # | Decision | Outcome |
|---|----------|---------|
| 1 | Extract `checkLiveGates` as the first step | Built. No behaviour change in `RunScenario`. Bypass closed. |
| 2 | Keep the live-stage flag off until staging evidence exists | Built. `KILLCHAIN_LIVE_STAGES_ENABLED` defaults to off. |
| 3 | Separation of duties for lab approval | Decided: a single-person lab team may self-approve. The approver must be identified. The audit records creator and approver. |
| 4 | One approval covers all live stages at once | Decided and built. Bounded by the signed definition. Each stage re-checks at start. |
| 5 | Factory-lab rule | Already enforced in `dispatchRun` on the `is_factory_lab` flag. Tested. |
| 6 | Lab-only scenario fidelity | Open. The `fidelity: lab-only` field is not enforced by any code. Needs a policy decision. |

## Problem

A campaign stage was dispatched only in `posture` mode. That is safe, but no
campaign could exercise a live technique. Live or lab stages have to pass the same
gates a single run passes.

The gates were in `RunScenario`, not in one place. `dispatchRun` checked the OS
and the factory-lab flag, but not `confirmLive`, `confirmLab` or the execution
window. A live campaign stage dispatched through `dispatchRun` would have skipped
three gates. That was the defect to fix first.

Today this path is latent because campaign stages can only run in posture mode.

## Design

### 1. One gate function, used by both paths

`checkLiveGates(sc, mode, confirmLive, confirmLab, agentOS, now)` in
`orchestrator/internal/api/livegates.go` holds the request-level live gates:
executable, `confirmLive`, `confirmLab`, OS mismatch and the execution window.

- `RunScenario` calls it with the same status codes and messages as before.
- The campaign stage path calls it at start, with the agent's current OS and the
  current time.
- The function takes the time as an argument, so the window is testable without a clock.
- A test asserts that both callers reach it.

### 2. Modes are part of the signed definition

Each stage has a `mode` (posture by default, telemetry or lab). The mode is in the
signed definition, so the approval of which stages go live is fixed at signing.
Unknown modes are refused at validation.

### 3. Approval on advance

`POST /api/killchain/campaigns/{id}/advance` takes an optional body:

```json
{ "confirmLive": true, "confirmLab": true, "reason": "change ticket CHG-1234" }
```

- A campaign with live stages needs `confirmLive` and a non-empty `reason`.
- A campaign with lab stages also needs `confirmLab`.
- Unknown fields are refused, so a misspelt confirmation cannot be dropped silently.
- The approval is audited (`killchain.campaign.approve`) with the live and lab stages,
  the reason, the approver and the creator, before the advance runs.
- One approval covers every live stage in the signed definition (decision 4).

### 4. Gate check at each live stage start

Advance can run hours before a stage starts, and the window can close in between.
So each live stage start:

1. checks the flag and the approval for its mode,
2. reads the agent's OS, and refuses if it is unknown or no reader is wired,
3. calls `checkLiveGates` with the OS and the current time,
4. dispatches only if all gates pass.

A refused stage is recorded as an error with the gate's reason. It is not a pass.

### 5. Feature flag, off by default

`KILLCHAIN_LIVE_STAGES_ENABLED` must be exactly `true` to turn it on. It is read
from the environment only, logged at startup, and cannot be changed through the API.
With the flag off, every live stage is refused. With it on, a live stage still
needs the approval and every gate above.

Turning it on is a separate decision, and it waits for staging evidence.

### 6. Separation of duties: decided

Lab approval may come from the campaign's creator. A single-person lab team is
allowed. The approver must still be identified: if the approver cannot be
identified, lab approval is refused.

The audit event records both the approver and the creator, so self-approval is
visible after the fact.

### 7. Factory-lab ownership: exists and is enforced

`dispatchRun` refuses any mode other than `factory-validation` on the agent whose
`is_factory_lab` flag is set, and refuses `factory-validation` on any other agent.
The check reads the flag from the agent row on the server. A campaign stage bound
to the factory-lab agent is refused by the same gate. Tested against the database.

### 8. Lab-only scenario fidelity: open

Scenarios can carry `fidelity: lab-only` (for example the akira stage 8 in
`scenarios/`). No code enforces it. Blocking such scenarios outside an approved lab
needs a policy decision: which policy applies, and where the check sits. Not built.

### 9. Audit

- `killchain.campaign.approve` on advance approval.
- `killchain.stage.start` on each live stage that dispatches, with the approver,
  reason and run id.
- `killchain.stage.refused` on each live stage that is refused, with the gate that
  refused it.

## Build state

| Step | Status |
|------|--------|
| 1. Extract `checkLiveGates`, point `RunScenario` at it | Built |
| 2. Stage `mode` in the signed definition | Built |
| 3. Advance approval body and audit | Built |
| 4. Per-stage gate check and refusal at start | Built |
| 5. Feature flag, off by default | Built |
| 6. Separation of duties | Decided: self-approval allowed. Built. |
| 7. Factory-lab gate | Already in place. Test added. |
| 8. Lab-only fidelity | Open. Needs a policy decision. |

Tests cover each refusal and allowed case in `checkLiveGates`, the window with an
injected clock, flag and approval at stage start, OS mismatch and unknown OS at
start, the window closing after approval, the audit events, self-approval, and the
factory-lab refusal.

Verification on a real agent, with the flag on, is a staging item. See
`docs/killchain-open-items.md`.
