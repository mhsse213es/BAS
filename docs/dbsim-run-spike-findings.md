# DB Simulation Run Spike: Findings

Date: 2026-11-19
Build: `bas-orchestrator:1.9.9.4-dbsim-spike` (tag `dbsim_spike`), agent `bas-agent-linux-amd64` `df00c340…` (spike build)
Host: staging (audspecterver), lab agent `f0c7c6e89478b176`, PostgreSQL lab on `192.168.10.78:55432`, database `dbsim`

## Decision: PROCEED (with conditions)

The dispatch and execution path works on the lab. The run-experience wiring still has gaps, listed below, and those gaps are the work for the next phase.

## What was verified

| Check | Result |
|---|---|
| Spike image loads and self-integrity verifies | Pass |
| Lab agent trusted after manifest + agent swap | Pass (`binary hash verified OK`) |
| Dispatch of `dbsim-db01-auth-policy` (2 steps) | Pass: run `spike-4dec5a5e3b2205ec` |
| Dispatch of `dbsim-db05-suspicious-read` (1 step) | Pass: run `spike-b1725157fd21b02a` |
| Agent executes steps against the lab | Pass: `verdict=pass`, `exitCode=0`, 43 / 46 / 70 ms |
| Run events delivered to the platform DB | Pass: 8 and 5 events, `run_completed` present |

## Gaps found (not fixed in this spike)

1. **Host events and detections return 404.** The agent posts to `/api/scenarios/runs/<id>/host-events` and `/detections`. The spike path creates no `scenario_runs` row, so the orchestrator has no run to attach them to. Fix: create the run row in the real run-start path.
2. **`pass` is an execution verdict, not a policy grade.** The step verdict only shows the probe ran. The policy-diff grading (`dbsim.Diff` / `DiffGlobal` / `DiffMemberships`) was not evaluated because the spike never ingests into the grading path. Fix: wire the ingest hook (run-experience plan Task 6).
3. **Agent quarantine did not clear on its own.** The orchestrator reported the hash as verified, but the agent kept `state=quarantined` until the server row was set to `active`. Expected behavior; worth documenting for the operator.
4. **Spike target binding bug.** The spike handler built the target without `AgentID`, so the orchestrator refused every run with `not bound to an agent`. Fixed in the spike build only; the production run-start path must set the binding.
5. **Release manifest.** A build whose previous-release manifest is 1.8.6 marks the live 1.9.9.4 agents as outdated, which quarantines them. The spike needed the 1.9.9.4 `BINARIES.sha256` placed in `dist/`. Fix: the release script should select the previous release by real version order.
6. **Bundle integrity.** The bundle folder's `bas-agent-linux-amd64` (`71ae477c…`) did not match its own manifest (`df00c340…`), while the image's copy matched. The bundle folder was altered after build. Fix: verify bundle files against the manifest before packaging.

## Not yet verified

- Real grading outcome for DB-01 and DB-05 against `policy-lab.json`.
- Windows agent `b7894e069aee22c0`: still listed only as outdated (`#prev`) in the spike manifest. Unrelated to this spike.
- MySQL: not run.

## Rollback

Staging is restored to: agent `/usr/local/bin/bas-agent` from `/root/bas-agent-1.9.9.4.bak`, orchestrator `bas-orchestrator:1.9.9.4`. Rollback steps are in the session log; the spike image `bas-orchestrator:1.9.9.4-dbsim-spike` is kept on the host for re-runs.

## Next

Run-experience plan Tasks 2–10 (dispatcher, run-start routes that create the run row, ingest hook, result sink, identity recorder). Start with Task 2 and the run-row creation, because gaps 1 and 2 block everything after it.
