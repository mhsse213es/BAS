# Phases 1-5 Rollout Plan (Agent Adaptive-Control-Plane)

**This is an operational rollout plan, not a TDD implementation plan** — there is no code left to
write; Phases 1-5 are already implemented, tested, and pushed to `main`. This document is the
runbook for getting that code onto real endpoints and staging so it starts producing the real
telemetry evidence the Phase 6 spike (see chat, 2026-09-06) needs.

It deliberately does not duplicate the platform's existing, general-purpose upgrade documentation —
`docs/guides/upgrade-guide.md` ("Upgrading Agents", "Step 5 — Update Agent Binaries") already covers
the mechanics. This plan says what's specific to *this* rollout: what's actually shipping, in what
order, how to verify it worked, and how to use the result to close the loop on Phase 6.

## What's actually shipping

Confirmed via `git diff --stat` at the end of every phase this session — **Phases 1-5 are 100%
agent-side.** Zero lines changed under `orchestrator/` in any of the 5 phase commits themselves.

| Phase | Commit | What it does |
|---|---|---|
| 1 | `c3c8f4d` | WS reconnect: exponential backoff + full jitter (was a flat 5s retry) |
| 2 | `39242a3` | Scheduler telemetry: queue/lock/exec wait, timeout/panic counts, active/queued gauges |
| 3 | `3c8d2fc` | `sched.ConcurrencyLimiter` — admission ceiling mechanism (wired at `limit == workers`, a no-op until Phase 4) |
| 4 | `40e8e10` | `agent/pressure` — host CPU/memory sampling, EWMA+hysteresis, drives the Phase 3 ceiling down under load |
| 5 | `31548b1` | `sched.RiskGate` — defers modification/persistence-risk jobs under High/Critical pressure |

One earlier, separate commit (`7e1f747`, "surface Phase 1-3 agent telemetry in the dashboard") **is**
an `orchestrator/wwwroot` change — a metric filter dropdown and 6-tile sparkline grid in the Agent
Health tab. It's optional for Phases 1-5's actual behavior (the new telemetry flows and gets stored
via the orchestrator's already-generic `POST /api/agents/events` ingestion regardless — verified
earlier this session that ingestion has no metric-name allowlist), but without it an operator can't
*see* the new metrics in the dashboard, only query them via the DB or `GET /api/agents/{id}/telemetry`
directly.

**No wire-format changes anywhere.** `ResourceProfile`'s JSON shape is unchanged (Phase 5 explicitly
declined to add `CPUWeight`/`MemoryWeight` fields — see its spec). A pre-Phase-1 orchestrator and a
post-Phase-5 agent are fully compatible; nothing in this rollout requires the two to move in lockstep.

## Two independent tracks

Because of the above, this splits into a **required** track and an **optional** one — do the first
regardless; do the second only if dashboard visibility matters before the canary window ends.

### Track A (required): rebuild and redeploy the agent binary

This is the only track that actually puts Phases 1-5's behavior into effect anywhere.

### Track B (optional): upgrade the orchestrator for dashboard visibility

Only needed to see the new metrics as charts in the Agent Health tab. Skip it and the data still
lands in `agent_telemetry` — query it directly (`psql` or `GET /api/agents/{id}/telemetry`) instead.

---

## Pre-flight checklist

- [ ] **Staging reachability** — confirmed unreachable from this machine as of 2026-09-06 (both
  `ping` and a raw TCP connect to `192.168.10.78:9443` timed out). Re-check before starting:
  `ping -n 2 192.168.10.78` (Windows) or equivalent. If still unreachable, this plan can be prepared
  and reviewed but not executed — flag that back rather than guessing at a workaround.
- [ ] **Docker Desktop running** on this Windows build host (`packaging/windows-build.ps1` requires
  it — see project memory: must be started manually, ~7.8GB RAM available).
- [ ] **Signing key present and unexpired** — the release GPG key (project memory: expires
  2029-06-04) and the RSA content-signing key (`private_key.pem` at repo root, used by
  `scripts/signer.go` for scenario/manifest signing) must both be present on this machine.
- [ ] **A `setup.conf` for the staging box** — either the original used for `--install` (needed for
  `--upgrade`, Track B only) or reconstructed per `upgrade-guide.md`'s "setup.conf Reference". Not
  needed for Track A alone.
- [x] **Version number: `1.8.4`** — confirmed by the user 2026-09-06. Last built package was `1.8.3`
  (`dist/bas-install-1.8.3.zip`, built 2026-09-05, i.e. *before* any of this session's work).

---

## Track A: rebuild and redeploy the agent binary

### A1. Build

The full release pipeline (`packaging\windows-build.ps1`) cross-compiles the agent for Windows,
Linux (amd64 + arm64), regenerates `BINARIES.sha256`, and RSA-signs it — even if Track B (server
upgrade) isn't happening yet, running the *agent* portion of this script is the correct way to
produce trustworthy, manifest-covered binaries rather than a bare `go build`:

```powershell
cd C:\Users\Administrator\Downloads\Audspect_Cloud
.\packaging\windows-build.ps1 -Version 1.8.4 -SkipBuild:$false
```

(Confirmed by reading the script: `-Customer`/`-CustomerID` default to empty strings and license
generation is skipped entirely when either is blank — so omitting them for this internal staging
build is safe and produces no `.lic` file, exactly right since this isn't a customer delivery.)

This produces `dist\bas-install-1.8.4\` containing (among other things) the Windows agent binary,
Linux/macOS agent binaries, `agents\BINARIES.sha256` + `.sig`, and `install.sh`/`uninstall.sh`.

**If only the agent binaries are needed right now** (e.g. Track B is deliberately deferred), the
lighter `scripts\build-agent.ps1` produces just the Windows agent without a full versioned bundle —
but note it does **not** regenerate/sign `BINARIES.sha256`, so binaries built this way will show
"⚠ Unverified" in the dashboard indefinitely (harmless per `agent-management.md`'s own description —
"a visibility signal... not an enforcement gate" — but worth choosing deliberately, not by accident).
Recommended: use the full `windows-build.ps1` path even for an agent-only push, specifically so the
manifest stays accurate.

### A2. Canary first, not fleet-wide

This rollout's whole purpose is to generate real evidence for the Phase 6 decision — a big-bang
fleet-wide push would give that evidence *and* fleet-wide risk simultaneously, backwards from what a
canary is for. Recommended:

1. Pick 2-3 non-critical, already-enrolled endpoints (mix of OS if possible, to also incidentally
   validate the Windows/macOS `agent/pressure` sampling code that could only be cross-compile-verified
   this session — see Phase 4's own noted gap: real hardware execution of `sample_windows.go`/
   `sample_darwin.go` is still owed).
2. Deploy the new binary to those endpoints only, via the existing idempotent install flow
   (`agent-management.md`: "Install is idempotent — running it a second time on an already-installed
   agent is safe").
3. Let them run real scenarios for a period — see "How long to wait" below.

### A3. Fleet-wide (after the canary looks healthy)

Use whatever mass-deployment method is already standard for this environment — Group Policy/SCCM
(Windows) or Ansible (Linux), both already documented in `agent-management.md`'s "Mass Deployment"
section. This plan doesn't repeat those mechanics.

---

## Track B (optional): orchestrator upgrade for dashboard visibility

Follow `docs/guides/upgrade-guide.md` verbatim — Steps 1-4 (backup, extract, `install.sh --upgrade
--config setup.conf`, verify) — using the `dist/bas-install-1.8.4` bundle from A1. That guide's own
"Rollback Procedure" applies unchanged if anything goes wrong. Nothing about this rollout needs a
deviation from that documented procedure.

One thing specific to this rollout worth calling out in the maintenance-window notice: **Phase 1
(WS reconnect backoff+jitter) is exactly the code path this restart exercises fleet-wide.** Every
connected agent will reconnect through the new backoff/jitter logic when the orchestrator restarts —
this upgrade is itself a live test of Phase 1, and a fleet that reconnects smoothly (staggered, not
a synchronized thundering herd) is a second, independent piece of evidence this rollout produces.

---

## Verification (do this regardless of which track(s) ran)

### Immediately after each canary endpoint is upgraded

- [ ] Dashboard → Agents → confirm the endpoint shows **Active** within 60s of the agent restarting
  (per `upgrade-guide.md`'s own reconnection expectation).
- [ ] Confirm the endpoint's binary hash matches the new build — if Track A used the full
  `windows-build.ps1` path, it should show **✓ Verified** once the orchestrator has the matching
  manifest (Track B done) or **⚠ Unverified** harmlessly otherwise (Track B skipped/pending).
- [ ] Query telemetry directly for that agent ID and confirm the **new** metric names are actually
  arriving (not just the pre-existing `heartbeat_latency_ms`):
  ```sql
  SELECT DISTINCT metric FROM agent_telemetry
  WHERE agent_id = '<canary-agent-id>' AND created_at > now() - interval '10 minutes';
  ```
  Expect to see, once the agent has been running a few minutes: `ws_reconnect_attempts`,
  `ws_connection_duration_seconds`, `host_cpu_percent`, `host_mem_percent`, `pressure_level`,
  `agent_cpu_percent`, `agent_mem_percent`. The `sched_*` metrics (queue/lock/exec/admission wait,
  jobs total, timeout/panic counts) only appear **after the agent completes a scenario run** — they're
  emitted once per run by `runMetrics.report()`, not continuously like the pressure-loop metrics — so
  don't expect them until a scenario has actually been dispatched to that endpoint.
- [ ] Dispatch one real scenario to a canary endpoint and confirm `sched_jobs_total` and friends show
  up afterward, with plausible (non-error) values.
- [ ] If Track B ran: open the Agent Health tab for a canary endpoint and confirm the 6-tile grid
  renders (some tiles will correctly say "Not enough data yet" until more samples accumulate — that's
  the documented, tested behavior, not a bug).

### What would indicate a real problem, not just "not enough data yet"

- An agent that never returns to Active after the restart (Phase 1 regression).
- `sched_panic_count` or `sched_timeout_count` climbing on canary endpoints where the pre-upgrade
  agent didn't show them (Phase 2/3/5 admission-path regression).
- A canary endpoint's `pressure_level` metric permanently stuck at `2` (Critical) with implausibly
  high `host_cpu_percent`/`host_mem_percent` alongside it — could indicate `pressure.Controller`'s
  EWMA math is behaving unexpectedly on that specific OS (this is exactly the kind of real-hardware
  finding the Windows/macOS sampling code still needs, per Phase 4's own noted verification gap).
- Any scenario on a canary endpoint taking dramatically longer than its pre-upgrade baseline —
  would suggest the admission ceiling or risk gate is over-throttling in practice, not just in tests.

---

## How long to wait before re-running the Phase 6 spike

The original spike question was whether `sched_lock_wait_max_ms`/`sched_queue_wait_max_ms` show
genuine starvation. That needs:

1. Canary endpoints running **real, varied scenarios** (not just idle heartbeats) — ideally a mix
   including at least one Full Sweep or multi-technique run, since starvation (if it exists at all)
   is far more likely to show up when many jobs with conflicting `ResourceProfile`s compete for the
   global lock, not in a small single-technique run.
2. Enough elapsed time/run count that `sched_lock_wait_max_ms` reflects more than one lucky/unlucky
   sample — a handful of runs across a few days on the canary set is a reasonable minimum bar; there's
   no established statistical threshold for this project to point to, so use judgment once real data
   starts arriving rather than picking an arbitrary number now.
3. Re-run the exact query shape from this session's spike:
   ```sql
   SELECT agent_id, MAX(value) FROM agent_telemetry
   WHERE metric IN ('sched_lock_wait_max_ms', 'sched_queue_wait_max_ms')
   GROUP BY agent_id;
   ```
   against real values instead of concluding "unreachable" as this session's spike had to.

## Rollback

- **Track A (agent):** redeploy the prior binary (`dist/bas-install-1.8.3`'s agent binary, or
  whatever was running before) via the same idempotent install flow. There is no agent-side
  `--rollback` command — "rollback" here just means "reinstall the older binary," which is exactly
  as safe as the forward install per `agent-management.md`'s own idempotency guarantee.
- **Track B (orchestrator):** `sudo bash install.sh --rollback`, per `upgrade-guide.md`'s existing,
  unmodified rollback procedure. No schema migrations happened in this rollout, so the simple
  config/image rollback path applies — the "restore from database dump" branch in that guide's
  rollback section shouldn't be needed here.
