# Kill chain live and lab gate: design

Status: steps 1 and 5 built (refactor, flag off). Steps 2 to 4 and 6 are not built. Nothing live is enabled. Verification needs staging,
which is not available. Live and lab claims are not made.

## Problem

A campaign stage today is dispatched only in `posture` mode
(`EngineStageExecutor.Options.Mode`). That is safe, but it means no campaign can
exercise a live technique. Enabling live or lab stages has to pass the same
gates a single run passes. Those gates are not in one place.

Where they live now (`orchestrator/internal/api/handlers.go`):

| Gate | Where | Applied to |
|---|---|---|
| Scenario is executable | `RunScenario` (~line 2566) | live and lab |
| `confirmLive` acknowledgement | `RunScenario` (~2571) | live and lab |
| `confirmLab` second approval | `RunScenario` (~2575) | lab only |
| OS mismatch hard-block | `RunScenario` (~2586) and `dispatchRun` (~2095) | live only; posture only warns |
| Execution window (`LivePolicy.ExecutionWindow`) | `RunScenario` (~2600) | live only |
| Agent state (active only) | `dispatchRun` (~2045) | every mode |
| Factory-lab ownership | `dispatchRun` (~2060) | every mode |
| Concurrency guard | `dispatchRun` | every mode |

The `dispatchRun` comment (~line 1893) says the request-level guardrails are "the
caller's job". The campaign path is a caller. `dispatchRun` does refuse a live run
on OS mismatch itself, so that check holds for campaigns. It does not check
`confirmLive`, `confirmLab`, or the execution window. So a live stage dispatched
through `dispatchRun` today would skip three of the gates. **That is the defect
this design fixes first.** Nothing live may be dispatched from a campaign until
that is closed.

Today this is latent. The campaign advance handler hard-codes `Mode: "posture"`,
so no campaign can reach a live stage. The gap would open the moment a stage mode
is read from the definition, which is why the mode is only added with this gate.

## Design

### 1. One gate function, used by both paths

Extract the request-level guardrails from `RunScenario` into one function:

```go
func checkLiveGates(sc *scenario.Scenario, mode string, confirmLive, confirmLab bool,
    agentOS string, now time.Time) (osWarning string, err error)
```

- `RunScenario` calls it. Its behaviour does not change. The existing handler
  tests are the regression guard.
- The campaign stage starter calls it too, with the same inputs.
- It is pure and takes the time as an argument, so the execution window is
  testable without a clock.

No second copy of these rules may exist. A test asserts that both callers reach
the function, so a future edit cannot quietly drop one.

### 2. Modes are part of the signed definition

A campaign definition already has to be signed to be stored. Each stage gets a
`mode` field (`posture` by default). Because the definition is signed, the
approval of which stages are live is fixed when the campaign is signed. The
operator cannot switch a stage from posture to live at advance time.

### 3. Advance-time approval for the campaign

`POST /api/killchain/campaigns/{id}/advance` takes an optional body:

```json
{ "confirmLive": true, "confirmLab": false, "reason": "change ticket CHG-1234" }
```

- If any stage is `telemetry` or `lab`, `confirmLive` is required, and `reason`
  is required.
- If any stage is `lab`, `confirmLab` is required.
- The campaign's approval is recorded in the audit log: who confirmed, when, the
  reason, and which stages were approved. Approval covers only the stages in the
  signed definition.

### 4. Gate check at each live stage start, not only at advance

Advance can run hours after approval, and the execution window can close between
stages. So `Start` for each live stage calls `checkLiveGates` again with the
current time and the agent's current OS.

- A refused stage is recorded as `ERROR` with the gate's reason. It is not
  `NOT_TESTED` and not a pass. The reason names the gate, such as "outside the
  approved execution window".
- Dependent stages become `NOT_TESTED`, as they do for any error.

### 5. Feature flag, off by default

`KILLCHAIN_LIVE_STAGES_ENABLED` (default `false`). When off, `Start` refuses any
stage whose mode is not `posture`, with the reason "live campaign stages are
disabled on this server". The flag is read at startup and logged. It is not
changeable through the API.

Enabling the flag is a separate decision, and it should follow staging evidence.

### 6. Separation of duties for lab (recommended, needs your decision)

The person who signs a campaign should not be the only person who confirms its
lab stages. Recommendation: `confirmLab` must come from a different user from the
campaign's `created_by`. Refuse the advance otherwise, with the reason.

Single-run lab already needs `confirmLab`. Campaigns hold more stages, so the
second approver matters more. Trade-off: it adds friction for a single-person
lab team. Say if you would rather keep one approver.

### 7. Factory-lab ownership

A campaign bound to the factory-owned lab agent must not run customer-target
stages, and the reverse. `dispatchRun` already enforces this. The design keeps it,
and a test covers a campaign bound to the lab agent that includes a
customer-mode stage.

### 8. Audit

Every live stage start writes one audit event with: campaign ID, stage key,
scenario ID, agent ID, mode, the approver, the reason, the OS check result, and
the window result. Refusals are audited too, with the gate that refused.

## What is built and what is not

Not built. This document is the design only. Nothing in the current code is
changed by it.

Build order, once approved:
1. Extract `checkLiveGates`, with its tests, and point `RunScenario` at it.
   This is a refactor with no behaviour change.
2. Campaign stage `mode` field, validated at signing. Default `posture`.
3. Advance body and campaign-level approval, with the audit event.
4. Per-stage gate check in `Start`, with the refusal path.
5. The feature flag, default off, and the test that refuses live stages when it
   is off.
6. Separation-of-duties check, if approved.

Steps 1 to 5 can be built and tested here, with the flag off, because they use
unit and handler tests. Live verification of any stage needs staging.

## Tests planned

- `checkLiveGates`: each refusal, and each allowed case, including posture
  producing a warning and not an error on OS mismatch.
- Execution window: inside, outside and at the boundary, with an injected time.
- Campaign `Start`: refused when the flag is off; refused when the window has
  closed since advance; refused on OS mismatch for a live stage; allowed for a
  posture stage with the flag off.
- Separation of duties: same user refused; different user allowed.
- Factory-lab: lab-bound campaign with a customer-mode stage refused.
- The refactor guard: `RunScenario` and the campaign starter both reach
  `checkLiveGates`.

## Decisions needed

1. Approve the refactor (section 1) as the first step. It changes no behaviour
   and fixes the bypass.
2. Confirm the flag stays off until staging evidence exists (section 5).
3. Separation of duties for lab: yes or no (section 6).
4. Advance-time approval covers all live stages at once, or each stage is
   confirmed separately. Recommendation: all at once, bounded by the signed
   definition, because each stage already re-checks at start.
