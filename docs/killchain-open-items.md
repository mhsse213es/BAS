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

### Update: host gaps now reach the verdict

Built: a stage whose host evidence cannot prove execution now reports the
specific gap as a reason, beside the missing-field name. For example, a
disabled process-creation audit is named, instead of only "missing evidence:
ground truth executed". Every unproven marker contributes its own gap.

### Parked for staging (no staging or test machine available now)

These cannot be closed here, so they are recorded and not planned:
1. Marker reaches the 4688 command line under each executor (`powershell`,
   `cmd`, `wmi`, `mshta`). The `powershell` path should work. The rest is untested.
2. Caldera versus agent: the lateral steps have `ability_id`s. Find out which
   path actually runs them, because that changes the command line.
3. Value name `ProcessCreationIncludeCmdLine_Enabled` is unconfirmed, because
   it is unset on the build host. Confirm the name the policy writes.
4. Collection cost and event volume on a real host.
5. Behaviour under audit policy set by group policy.
6. A live or lab claim for any stage. None is made.

### Live and lab gate for campaign stages: designed, not built

See `docs/killchain-live-gate-design.md`. Campaign stages are posture-only
today, so the gap in shared gate checks is latent. Decisions open:
1. Approve the shared `checkLiveGates` refactor (no behaviour change, closes the bypass).
2. Keep `KILLCHAIN_LIVE_STAGES_ENABLED` off until staging evidence exists.
3. Separation of duties for lab approval: yes or no.
4. One advance-time approval for all live stages, or one per stage.
Verification of any live stage needs staging.

### Update: shared live gate and flag (built, flag off)

Built:
- `checkLiveGates` (`orchestrator/internal/api/livegates.go`) is the single
  home for the request-level live gates. `RunScenario` calls it, with the same
  status codes and messages. Tests cover each refusal, the posture warning, and
  the window boundaries.
- `KILLCHAIN_LIVE_STAGES_ENABLED` is off by default. The server logs its state at
  startup. With the flag off, a live campaign stage is refused with the flag
  named. With it on, a live stage is still refused, because campaign approval is
  not built yet. The flag therefore has no effect on what runs until approval is built.

Not built: campaign stage modes in the signed definition, the advance-time
approval and its audit event, the per-stage gate call in `Start`, and the
separation-of-duties decision.

Note: `TestRBACMatrix_NoDrift` still fails on cloud routes staged by another
session. This work does not touch them.

### Update: stage modes and approval (built, flag off)

Built:
- Each stage has a `mode` (posture by default, telemetry, lab) in the signed
  definition. Unknown modes are refused at validation. The shipped campaign
  without modes still verifies, because its bytes did not change.
- The advance request takes an optional approval body: `confirmLive`,
  `confirmLab`, `reason`. A campaign with live stages needs `confirmLive` and a
  reason. A campaign with lab stages also needs `confirmLab`. Unknown fields are refused.
- Approval is audited (`killchain.campaign.approve`) with the live and lab stages,
  and the reason, before the advance runs.
- Each stage checks its own mode against the approval, the flag, and the
  scenario's live rules (`checkLiveGates`). Dispatch then passes the
  confirmations to the run path.

Not built, and recorded as gaps:
- Per-stage audit when a live stage starts. The approval is audited at advance,
  but a stage's own start is not audited separately.
- The OS check for a live stage relies on dispatchRun, which knows the agent's OS.
  `checkLiveGates` is called with no OS in the stage path.
- Separation of duties for lab approval is still undecided. Currently the
  campaign's creator can confirm lab stages.
- The flag stays off. Turning it on is a decision that waits for staging.

### Update: separation of duties and approval scope (decided, built)

Decided, on the recommendations:
- Lab stages need an approver who is not the campaign's creator. The creator
  comes from `killchain_campaigns.created_by` and is loaded with the campaign
  record. An approver who cannot be identified is refused, because the check
  cannot run. Telemetry stages are not affected.
- One advance-time approval covers all live stages, bounded by the signed
  definition. Each stage still re-checks its own gates at start.

Open, for you to reverse if wanted: whether a single-person lab team should be
allowed to self-approve. The current rule refuses it.

### Update: per-stage audit, start-time OS check, gate tests (built)

Built:
- Each live stage start and refusal is audited (`killchain.stage.start` /
  `killchain.stage.refused`) with the approver, reason, gate result and run id.
- Live stages read the agent's OS at start. Unknown OS, or no reader wired,
  refuses the stage.
- Tests: refusal and start audit, posture not audited, OS mismatch and unknown OS
  refused at start, window closed at start refused, injected clock, and a guard
  that both callers reach `checkLiveGates`.

Not built, and needs a decision first:
- The factory-lab rule in the design (a lab-bound campaign may not run
  customer-mode stages). `dispatchRun` only enforces that a factory-validation
  run needs the factory lab agent. The code has no "customer-mode" concept, so
  there is nothing to test until the rule is defined.

### Staging items from the live gate work

Built and unit-tested here. None is verified against a real agent, and none
makes a live or lab claim. Each needs staging before the flag can be turned on.
1. Turn `KILLCHAIN_LIVE_STAGES_ENABLED` on in staging only, after the items
   below pass. It stays off everywhere else.
2. One telemetry campaign stage, end to end, with a real approval: advance with
   `confirmLive` and a reason, the stage dispatches, and the run completes.
3. The approval and each live stage start appear in `audit_logs`. The audit
   write is fire-and-forget, so confirm rows arrive and none are lost.
4. A refusal is audited as `killchain.stage.refused` for each gate: flag off,
   no approval, OS mismatch, unknown OS, window closed.
5. The agent OS classification matches the real `os_version` of a Windows agent.
   The live gate refuses unknown OS, so a misclassified host blocks every live stage.
6. Separation of duties with two real users: the creator's lab approval is refused,
   and a second user's approval goes through.
7. The start-time OS check and the dispatch-time OS check give the same result on
   the same agent.
8. Window closing between approval and stage start, on a real clock, refuses the
   stage and the stage is recorded as an error, not a pass.
9. Factory-lab gate on a real factory-lab agent: a campaign stage is refused (the
   `is_factory_lab` gate in dispatchRun). Unit-tested here against the database; confirm on staging.

Decisions for you, not staging:
- Resolved: a single-person lab team may self-approve lab stages. The audit records creator and approver.

### Update: factory-lab gate and self-approval decision

- The factory-lab gate exists and is server-side. `dispatchRun` refuses any
  mode other than factory-validation on the agent whose `is_factory_lab` is set,
  and refuses factory-validation on any other agent. A campaign stage on the
  factory-lab agent is refused by the same gate. Tested against the database.
  An earlier note in this doc said the gate was missing. That was wrong.
- Decided: a single-person lab team may self-approve lab stages.
- Still not built, and needs a decision: the pasted policy says lab-only
  scenarios (`fidelity: lab-only`, e.g. the akira stage 8 in `scenarios/`)
  should be blocked outside an approved lab unless policy authorizes it. No code
  enforces `fidelity` today. Decide the policy and where the check sits before building it.

### SOC pipeline: posture core built, the rest open

Built (`orchestrator/internal/pipelinecheck`, 8 tests):
- Connectivity probe for SIEM and ticketing targets, through the existing connectivity
  functions. No second client.
- Verdict mapping: all targets reachable gives INCONCLUSIVE, never a pass, with every
  unverified stage listed. Any failed or untestable target gives ERROR, named. No targets gives ERROR.
- `siem.ErrProviderNotSupported`. Providers without a connectivity test are reported
  as not tested, not as failures.

Found while building: the SIEM connectivity test supports QRadar only. Every other
provider reports "not supported". The detection-verification connectors (Elastic,
Splunk, QRadar, Sentinel and others) have their own test and are a separate config
path. Two configuration paths exist and are not unified.

Not built, still open:
1. Wiring into a campaign stage type. The checker is not yet a stage the orchestrator advances.
2. Read-only ingestion. The connector interface cannot count raw events, so ingestion,
   normalisation and correlation stay NOT_TESTED until a per-connector event query exists.
3. Explicit per-test injection. Needs target SIEM, payload, expected change, scope and
   a recorded approval per run. Nothing runs from a campaign start.
4. Separate outcomes for ingestion, normalisation, correlation, alert, case and routing.
5. Human-dependent steps. Acknowledgement and escalation are NOT_TESTED unless an
   authorised integration or a recorded human confirmation exists.
6. Cleanup and tagging. Test events and cases need a tag so they can be found and removed
   without deleting legitimate audit records. The rule is not defined yet.
7. Permissions. The connector interface has no permission check. Reported as not verified.
