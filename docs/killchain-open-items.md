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

## Host execution evidence: Security 4688 and 4624/4648 (built in part)

Built and tested:
- `orchestrator/internal/killchain/hostevents.go`: evaluates a step's host
  events. Process creation proves execution only with the step's marker,
  on the right host, inside the window. Duplicates count once. Records with the
  same id and different content are a conflict and are not trusted. Logons are
  reported as supporting evidence and never prove execution. Absence is a named
  gap and never a "no". Fixture tests cover present, missing, duplicated,
  delayed, contradictory, and other-host events.
- `agent/hostevents_windows.go`: collects only 4688, 4624 (logon types 3 and 10)
  and 4648 in the window, reading named EventData fields. It reads the audit
  state for both subcategories. Parser tests cover named fields, empty output,
  garbage output, and unreadable audit output (unknown, never disabled).
- Live check on this Windows 10 build (agent test with
  `AUDSPECT_LIVE_HOSTEVENTS=1`): the collector and audit probe run and read the
  current state. Named EventData fields were confirmed for 4688, 4624 and 4648.

Found on this host and handled as a gap, not a setting:
- `auditpol` reports Process Creation as "No Auditing", yet 4688 records exist
  in the Security log. The evaluator names this inconsistency and trusts neither
  signal alone.

Not built yet (each needs staging or a design step):
- The orchestrator endpoint that receives `RunHostEvents`, its storage, and the
  step that maps a matching finding into a ground-truth record. The mapping
  function exists (`GroundTruthFromFinding`), but nothing calls it yet.
- The agent does not submit host events after a run. The submission call is
  not wired, because the endpoint does not exist yet.
- Verification on staging: whether the marker reaches the 4688 command line
  (command-line capture needs its own policy), event volume and collection
  cost on real hosts, the 4648 semantics for lateral steps, and behaviour
  when audit policy is enabled by GPO.
- Live validation is not claimed.

### Update: receiving path built

Built and tested since the entry above:
- `POST /api/scenarios/runs/{runId}/host-events`: agent-authed. It refuses any
  event id outside 4688, 4624 and 4648, and a batch from an agent that did not
  run the scenario. Re-delivery replaces the run's events. Duplicates within a
  batch are kept, so the evaluator counts them.
- Storage: `killchain_host_events` and `killchain_run_audit`.
- Agent: after each run it collects and posts the events and audit state. On
  non-Windows builds it sends no events, and reports audit as unknown.

Still open, and the next blocker is a design decision:
- **Step marker.** A process-creation match needs a token that the step puts
  in its command line. No such field exists in the scenario schema. Adding one
  changes scenario YAML, so the scenario `.sig` must be re-signed. Until then
  the evaluator can find no evidence and every stage stays a named gap. No
  stage will be scored from host events.
- Ground-truth mapping is not yet called from stage collection, for the same reason.
- Staging: collection cost on real hosts, and whether the marker reaches the
  4688 command line under the enabled policy.

### Update: step markers and host evidence wiring

Built (Option A, approved):
- `Step.Marker`: validated on load. Format `[a-z0-9-]{8,40}`, must appear
  literally in the command, unique within a scenario and across scenarios.
  A scenario that fails is skipped with a log line.
- Marked steps: `credential-access` (`bas-cred-ident-01`, LSA secrets step) and
  `caldera-lateral-movement` (`bas-lat-svc-create-01`, remote service creation
  step). Each is re-signed; the verifier reports ok=2 fail=0.
- Stage collection reads host events when the scenario has markers, its source
  policy accepts event logs, and every marker is proven in the window. A manual
  ground-truth record takes precedence. Reference is kept on ground truth.
- Command-line capture is a separate audit state. The agent probes the value
  `ProcessCreationIncludeCmdLine_Enabled`. Unset means unknown, not disabled.
  The evaluator names a capture gap when a marker cannot be seen.

Not verified, and needs staging:
- Whether each marker reaches the 4688 command line under its executor. The
  `powershell` executor passes the text as a `-Command` argument, so it should.
  The `caldera` steps may be run by Caldera, not the agent, which changes the
  command line. Check which path runs them.
- The value name `ProcessCreationIncludeCmdLine_Enabled` is not confirmed, since
  it is unset on the build host.
- Gaps from host evidence are not yet shown as stage reasons. A stage with no
  host proof reports the missing ground truth, not the specific host gap.
- `TestRBACMatrix_NoDrift` fails on cloud routes that another session staged in
  `routes.go` (`/api/cloud-scenarios`, `/api/cloud-scenario-runs`). This work
  does not touch them.
