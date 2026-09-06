# Phases 1-8 + Orchestrator Skip-Attribution Rollout Plan (Agent Adaptive-Control-Plane)

**This is an operational rollout plan, not a TDD implementation plan** — there is no code left to
write; everything below is already implemented, tested, and pushed to `main`. This document is the
runbook for getting that code onto real endpoints and staging.

**Updated 2026-09-07** to cover Phases 6-8 and a real orchestrator-side fix, none of which existed
when this plan was first drafted for Phases 1-5 alone. The original Phase 1-5 build (`-Version 1.8.4`)
was started and then explicitly stopped before completion (no staging access) — since no `1.8.4`
package was ever actually produced, this plan now targets **`1.8.5`** for the full, expanded scope.
Everything below supersedes the original version of this document; nothing from the original Phase
1-5-only plan should be followed as written anymore.

It deliberately does not duplicate the platform's existing, general-purpose upgrade documentation —
`docs/guides/upgrade-guide.md` ("Upgrading Agents", "Step 5 — Update Agent Binaries") already covers
the mechanics. This plan says what's specific to *this* rollout: what's actually shipping, in what
order, how to verify it worked, and how to roll back.

## What's actually shipping

Confirmed via `git log`/`git diff --stat` against every phase commit on `main`.

| Phase | Commit(s) | What it does |
|---|---|---|
| 1 | `c3c8f4d` | WS reconnect: exponential backoff + full jitter (was a flat 5s retry) |
| 2 | `39242a3` | Scheduler telemetry: queue/lock/exec wait, timeout/panic counts, active/queued gauges |
| 3 | `3c8d2fc` | `sched.ConcurrencyLimiter` — admission ceiling mechanism (wired at `limit == workers`, a no-op until Phase 4) |
| 4 | `40e8e10` | `agent/pressure` — host CPU/memory sampling, EWMA+hysteresis, drives the Phase 3 ceiling down under load |
| 5 | `31548b1` | `sched.RiskGate` — defers modification/persistence-risk jobs under High/Critical pressure |
| 6 | `03c0706`, `053d8c5`, `a1d4e59` | `ConcurrencyLimiter` rewritten from `sync.Cond` broadcast-and-race to an explicit FIFO ticket queue — blocked `Acquire` callers are now admitted in strict arrival order, eliminating a real (if previously unmeasured) starvation risk. `RiskGate` deliberately left unchanged (doc-commented why: no scarce-resource contention to be unfair about). |
| — | `c5f79b7` | **Bug fix, not a phase**: Phase 7's retry made the `Job.Run` closure execute once per retry attempt instead of once per step, which silently inflated `startedJobs`/`completed`/`finishedJobs` (and the local progress bar) past the true step count on any run with retries. Fixed by gating those counters on genuinely-first-attempt / genuinely-terminal-attempt. |
| 7 | `587d70a`, `e985840`, `60ff5d9`, `e802a77` | Priority-aware retry-with-backoff for failed steps. Observation-risk steps get up to 4 attempts (1s/2s/4s backoff); Modification/Unknown get up to 2 (5s backoff). Each attempt independently re-passes admission and lock acquisition — nothing is held idle during backoff. New telemetry: `sched_retry_count`. |
| 8 | `02c825b`, `3be71d7`, `f5ef8ff` | Circuit breaker: after 3 consecutive terminal-outcome failures against the same ATT&CK technique or resource domain within a run, further steps against that key are skipped rather than attempted — reported to the orchestrator via the existing `skip:`-prefixed result convention. |

**One orchestrator-side commit that is now functionally required, not a nice-to-have:**

| Commit | What it does |
|---|---|
| `a3701bd` | Fixes skip-reason **attribution**: a Phase 8 circuit-breaker skip was already correctly classified as `SKIPPED` by the orchestrator with zero code changes (the existing `skip:`-prefix convention already handled that), but the *reason* fell through to an unclassified default and got bucketed as "Platform" (environment gap) in client reports — factually wrong for a skip that is the scheduler's own policy decision, not an environment problem. Adds a `Scheduler` bucket, a `classifySkipReason` case, an executive-conclusion sentence, and a live-run UI label fix. |

`7e1f747` (from the original Phase 1-5 plan — a dashboard sparkline grid for Phase 1-3 telemetry) is
still a separate, purely cosmetic, independently-optional orchestrator commit; it is unrelated to
`a3701bd` and unrelated to whether Phase 8's skip attribution works correctly.

## Wire compatibility — same claim, one important new exception

`ResourceProfile`'s JSON shape is still unchanged across all of Phases 1-8 (Phase 8's synthetic skip
result reuses existing `ExecResult` fields — `TaskID`/`ExitCode`/`Stdout`/`ExecutedAt` — no new wire
fields). A pre-Phase-1 orchestrator and a post-Phase-8 agent remain wire-compatible in the sense that
nothing breaks or fails to parse.

**But wire-compatible is not the same as functionally complete.** This is the one real behavioral
change from the original plan's framing:

- **Old agent + new orchestrator (`a3701bd`):** fine — the orchestrator's `classifySkipReason` simply
  never sees `"circuit breaker"` text from an agent that predates Phase 8, so the new case is inert.
- **New agent (Phase 8) + old orchestrator:** the agent emits a real `skip: circuit breaker open for
  ...` result, the orchestrator still classifies it as `SKIPPED` (that part needed no change), but
  `classifySkipReason` on the old orchestrator has no case for it and it falls into the default —
  reported to the client as "Platform," the exact misattribution `a3701bd` exists to fix. **Deploying
  the new agent without also deploying `a3701bd` does not fully deliver what Phase 8 was built for.**

This is why Track B below is no longer purely optional the way it was for Phases 1-5.

## Two tracks — Track B's status has changed

### Track A (required): rebuild and redeploy the agent binary

Unchanged in kind from the original plan — this is what puts Phases 1-8's behavior into effect on
endpoints. Bigger in scope now (8 phases + 1 bug fix instead of 5 phases).

### Track B (now recommended for full correctness, not merely "for dashboard charts"): upgrade the orchestrator

Splits into two independent reasons to do it, worth telling apart when deciding how urgently to run
Track B relative to Track A:

- **B1 — skip-attribution correctness (`a3701bd`).** Needed for Phase 8 circuit-breaker skips to be
  reported correctly to clients. Not a hard blocker on deploying Track A first (nothing breaks; skips
  just misattribute as Platform until this lands), but it should not be left indefinitely once Phase 8
  is live on canary endpoints, since every circuit-breaker skip between the two deployments produces a
  client-report inaccuracy in the interim.
- **B2 — dashboard visibility (`7e1f747`, pre-existing/unchanged from the original plan).** Still
  genuinely optional — the underlying telemetry lands in `agent_telemetry` and is queryable directly
  either way.

---

## Pre-flight checklist

- [ ] **Staging reachability** — re-check before starting: `ping -n 2 192.168.10.78` (Windows) or
  equivalent, and/or a raw TCP connect to `192.168.10.78:9443`. As of this plan's original writing
  (2026-09-06) both were unreachable from this machine; status has not been re-checked since. If still
  unreachable, this plan can be prepared and reviewed but not executed — flag that back rather than
  guessing at a workaround.
- [ ] **Docker Desktop running** on this Windows build host (`packaging/windows-build.ps1` requires
  it — see project memory: must be started manually, ~7.8GB RAM available).
- [ ] **Signing key present and unexpired** — the release GPG key (project memory: expires
  2029-06-04) and the RSA content-signing key (`private_key.pem`, confirmed this session to live at
  `orchestrator/private_key.pem`, used by `scripts/signer.go` for scenario/manifest signing) must both
  be present on this machine.
- [ ] **A `setup.conf` for the staging box** — either the original used for `--install` (needed for
  `--upgrade`, Track B) or reconstructed per `upgrade-guide.md`'s "setup.conf Reference". Not needed
  for Track A alone.
- [x] **Version number: `1.8.5`** — confirmed by the user 2026-09-07, superseding the original plan's
  `1.8.4` (which was never actually built). Last *actually-produced* package remains
  `dist/bas-install-1.8.3.zip` (built 2026-09-05, i.e. before any of this session's work).
- [ ] **`orchestrator/agents/BINARIES.sha256`/`.sig` working-tree state** — these two files showed as
  locally modified (uncommitted) throughout this session, independent of any of the phase work above.
  Check `git status -- orchestrator/agents/` before building; if they're still dirty, decide whether
  that's leftover from a prior partial build attempt (safe to let the new build overwrite) or something
  else worth investigating first — don't assume either way without looking.

---

## Track A: rebuild and redeploy the agent binary

### A1. Build

```powershell
cd C:\Users\Administrator\Downloads\Audspect_Cloud
.\packaging\windows-build.ps1 -Version 1.8.5 -SkipBuild:$false
```

(Confirmed by reading the script: `-Customer`/`-CustomerID` default to empty strings and license
generation is skipped entirely when either is blank — so omitting them for this internal staging
build is safe and produces no `.lic` file, exactly right since this isn't a customer delivery.)

This produces `dist\bas-install-1.8.5\` containing (among other things) the Windows agent binary,
Linux/macOS agent binaries, `agents\BINARIES.sha256` + `.sig`, and `install.sh`/`uninstall.sh`.

**If only the agent binaries are needed right now** (e.g. Track B is deliberately deferred), the
lighter `scripts\build-agent.ps1` produces just the Windows agent without a full versioned bundle —
but note it does **not** regenerate/sign `BINARIES.sha256`, so binaries built this way will show
"⚠ Unverified" in the dashboard indefinitely (harmless per `agent-management.md`'s own description —
"a visibility signal... not an enforcement gate" — but worth choosing deliberately, not by accident).
Recommended: use the full `windows-build.ps1` path even for an agent-only push, specifically so the
manifest stays accurate.

### A2. Canary first, not fleet-wide

This rollout's whole purpose is to put 8 phases of scheduler behavior changes into production for the
first time — a big-bang fleet-wide push would give real evidence *and* fleet-wide risk simultaneously.
Recommended:

1. Pick 2-3 non-critical, already-enrolled endpoints (mix of OS if possible, to also incidentally
   validate the Windows/macOS `agent/pressure` sampling code that could only be cross-compile-verified
   this session — see Phase 4's own noted gap: real hardware execution of `sample_windows.go`/
   `sample_darwin.go` is still owed).
2. Deploy the new binary to those endpoints only, via the existing idempotent install flow
   (`agent-management.md`: "Install is idempotent — running it a second time on an already-installed
   agent is safe").
3. Let them run real scenarios for a period — ideally including at least one multi-step or Full Sweep
   run, since several of the new behaviors (Phase 6's FIFO fairness, Phase 7's retries, Phase 8's
   circuit breaker) only have anything to do under real contention or real repeated failures — a single
   idle heartbeat or a trivially-passing one-step scenario won't exercise any of them.

### A3. Fleet-wide (after the canary looks healthy)

Use whatever mass-deployment method is already standard for this environment — Group Policy/SCCM
(Windows) or Ansible (Linux), both already documented in `agent-management.md`'s "Mass Deployment"
section. This plan doesn't repeat those mechanics.

---

## Track B: orchestrator upgrade

Follow `docs/guides/upgrade-guide.md` verbatim — Steps 1-4 (backup, extract, `install.sh --upgrade
--config setup.conf`, verify) — using the `dist/bas-install-1.8.5` bundle from A1. That guide's own
"Rollback Procedure" applies unchanged if anything goes wrong.

Two things specific to this rollout worth calling out in the maintenance-window notice:

- **Phase 1 (WS reconnect backoff+jitter) is exactly the code path this restart exercises
  fleet-wide.** Every connected agent will reconnect through the new backoff/jitter logic when the
  orchestrator restarts — this upgrade is itself a live test of Phase 1, and a fleet that reconnects
  smoothly (staggered, not a synchronized thundering herd) is a second, independent piece of evidence
  this rollout produces.
- **This restart is what actually activates `a3701bd`'s skip-attribution fix.** Until this Track B
  restart happens, any Phase 8 circuit-breaker skip on an already-upgraded (Track A) canary endpoint
  will still misattribute as "Platform" in generated reports — see the Wire Compatibility section
  above. If a canary run happens to trip the circuit breaker before Track B lands, don't be alarmed by
  a "Platform" skip in that specific report; it's expected until this step runs, not a new bug.

---

## Verification (do this regardless of which track(s) ran)

### Immediately after each canary endpoint is upgraded (Track A)

- [ ] Dashboard → Agents → confirm the endpoint shows **Active** within 60s of the agent restarting
  (per `upgrade-guide.md`'s own reconnection expectation).
- [ ] Confirm the endpoint's binary hash matches the new build — **✓ Verified** once the orchestrator
  has the matching manifest (Track B done) or **⚠ Unverified** harmlessly otherwise (Track B
  skipped/pending).
- [ ] Query telemetry directly for that agent ID and confirm the **new** metric names are actually
  arriving:
  ```sql
  SELECT DISTINCT metric FROM agent_telemetry
  WHERE agent_id = '<canary-agent-id>' AND created_at > now() - interval '10 minutes';
  ```
  Expect, once the agent has been running a few minutes: `ws_reconnect_attempts`,
  `ws_connection_duration_seconds`, `host_cpu_percent`, `host_mem_percent`, `pressure_level`,
  `agent_cpu_percent`, `agent_mem_percent`. The `sched_*` metrics (queue/lock/exec/admission wait,
  jobs total, timeout/panic counts, and now `sched_retry_count`) only appear **after the agent
  completes a scenario run** — emitted once per run by `runMetrics.report()`, not continuously — so
  don't expect them until a scenario has actually been dispatched to that endpoint.
- [ ] Dispatch one real, multi-step scenario to a canary endpoint and confirm `sched_jobs_total` and
  friends show up afterward with plausible (non-error) values. `sched_retry_count` will legitimately
  be **absent** (not zero — genuinely unreported) on a run with no retryable failures; that's the
  documented "only emitted when nonzero" convention from Phase 7, not a gap.
- [ ] If Track B ran: open the Agent Health tab for a canary endpoint and confirm the 6-tile grid
  renders (some tiles will correctly say "Not enough data yet" until more samples accumulate — that's
  the documented, tested behavior, not a bug).

### Opportunistic — only if a canary run actually exercises the new mechanisms

These aren't things to force, but if they happen naturally during canary testing, confirm they behave
as designed:

- [ ] **A step that genuinely fails and retries** (Phase 7): confirm a `"retrying"` `RunEvent` appears
  in that run's event stream, and that `sched_retry_count` is nonzero for that run.
- [ ] **A domain/technique with 3+ consecutive failures within one run** (Phase 8): confirm the
  subsequent steps against that same key show up in the generated report as **"Skipped (Scheduler)"**
  — not "Skipped (Platform)" — and that the executive conclusion contains the new "...automatically
  suppressed by the scheduler..." sentence. This is the actual end-to-end proof that both Track A
  (agent emits the right skip text) and Track B (`a3701bd`, orchestrator classifies it correctly) are
  both in place and working together.
- [ ] **Contention under a multi-step or Full Sweep run** (Phase 6): no direct dashboard signal for
  FIFO-fairness specifically — this is already proven by Phase 6's own test suite
  (`TestConcurrencyLimiter_FIFOOrderUnderContention`, deterministic). Nothing new to verify live here;
  listed for completeness only.

### What would indicate a real problem, not just "not enough data yet"

- An agent that never returns to Active after the restart (Phase 1 regression).
- `sched_panic_count` or `sched_timeout_count` climbing on canary endpoints where the pre-upgrade
  agent didn't show them (Phase 2/3/5 admission-path regression).
- A canary endpoint's `pressure_level` metric permanently stuck at `2` (Critical) with implausibly
  high `host_cpu_percent`/`host_mem_percent` alongside it — could indicate `pressure.Controller`'s
  EWMA math is behaving unexpectedly on that specific OS (this is exactly the kind of real-hardware
  finding the Windows/macOS sampling code still needs, per Phase 4's own noted verification gap).
- Any scenario on a canary endpoint taking dramatically longer than its pre-upgrade baseline —
  would suggest the admission ceiling, risk gate, retry backoff, or circuit breaker is
  over-throttling in practice, not just in tests.
- A step that fails once, cleanly, with no retryable characteristics still shows a `"retrying"` event
  or gets skipped by the circuit breaker on its very first attempt — would indicate a Phase 7/8 logic
  regression, not expected behavior.
- Any run's progress bar visibly exceeding 100% or the step counter overrunning the true step count —
  would mean the `c5f79b7` progress-counter fix regressed, not a new finding to chase further.

---

## On the original "Phase 6 spike" question — resolved differently than planned

The original version of this plan existed to gather evidence for a still-open Phase 6 decision (does
real telemetry show genuine lock/queue starvation). That decision has since been **resolved without
waiting for this rollout**: Phase 6 was built and shipped this session on engineering-merit grounds
(the `sync.Cond` broadcast-and-race mechanism is a known, general starvation-risk *class* of bug,
independent of whether this specific workload had hit it yet — see
`docs/superpowers/specs/2026-09-06-phase6-fifo-fair-concurrency-limiter-design.md`), not by waiting for
this rollout's telemetry.

This rollout's verification steps above are no longer *gating* a design decision — they're
*confirming* one that already shipped, plus generating the first real-world evidence for the (much
more recent) Phase 7/8 designs, which similarly weren't blocked on live telemetry. If real data ever
does show `sched_lock_wait_max_ms`/`sched_queue_wait_max_ms` behaving unexpectedly even after Phase 6,
that's new information worth raising on its own, not something this plan is structured to detect on a
schedule.

## Rollback

- **Track A (agent):** redeploy the prior binary (`dist/bas-install-1.8.3`'s agent binary, or
  whatever was running before) via the same idempotent install flow. There is no agent-side
  `--rollback` command — "rollback" here just means "reinstall the older binary," which is exactly
  as safe as the forward install per `agent-management.md`'s own idempotency guarantee.
- **Track B (orchestrator):** `sudo bash install.sh --rollback`, per `upgrade-guide.md`'s existing,
  unmodified rollback procedure. No schema migrations happened in this rollout (the new `Scheduler`
  `SkipBreakdown` field and `SkipReasonCircuitOpen` const are additive, not migrations), so the simple
  config/image rollback path applies — the "restore from database dump" branch in that guide's
  rollback section shouldn't be needed here.
- **Rolling back Track B alone while keeping Track A:** safe and explicitly anticipated by the Wire
  Compatibility section above — a new agent talking to an old (rolled-back) orchestrator just resumes
  misattributing circuit-breaker skips as "Platform" until Track B is re-applied. Nothing breaks.
