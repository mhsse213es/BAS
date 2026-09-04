# Phase 0A: Windows Execution Performance Measurement — Status

**Date:** 2026-09-04  
**Status:** ✅ FOUNDATION COMPLETE

## Instrumentation Deployed

### StepExecution Timestamps (types.go)
Added 4 performance tracking fields to the real execution data model:
- `PollSelectedAt` — when executor polled Store and selected this step
- `DispatchSentAt` — when dispatch call completed  
- `ResultReceivedAt` — when result was received and stored
- `ScoringCompletedAt` — when step marked completed

### Logging (executor.go)
Structured [perf] logs at each checkpoint:
```
[perf] execution_id=run-abc/task-1/1 poll_selected_at=2026-09-04T12:01:00.001Z
[perf] execution_id=run-abc/task-1/1 dispatch_sent_at=2026-09-04T12:01:00.004Z
[perf] execution_id=run-abc/task-1/1 result_received_at=2026-09-04T12:01:00.325Z
[perf] execution_id=run-abc/task-1/1 scoring_completed_at=2026-09-04T12:01:00.327Z
```

### Parser (scripts/parse-perf.go)
Utility to extract and analyze logs:
- Parses execution_id, timestamp_name, timestamp
- Groups by execution_id
- Calculates stage gaps:
  - selection → dispatch
  - dispatch → result
  - result → scoring
  - selection → scoring (total)
- Computes P50/P95/P99 percentiles

## Commits

1. `64888ee` — Add execution lifecycle timestamps to StepExecution
2. `5eeefeb` — Add structured logging at timestamp points
3. `8eae26e` — Add parse-perf log parser utility

## Ready for Measurement

### Local Baseline
```bash
cd orchestrator
go run ./cmd/server/main.go > orchestrator.log 2>&1 &

# Trigger scenario, wait for completion

go run scripts/parse-perf.go -log=orchestrator.log
```

### Staging Measurement
Same process on zain@audspectserver (192.168.10.78:9443)

## Next Steps

Run measurement when ready:
1. Start orchestrator (local or staging)
2. Trigger windows-discovery.yaml scenario
3. Capture logs
4. Parse with parse-perf
5. Analyze which stage dominates (dispatch→result will likely be the bottleneck)

## Key Questions This Will Answer

- **A. Large selection→dispatch gap?** → Scheduler/Store/locking issue
- **B. Large dispatch→result gap?** → Agent execution/PowerShell/network (most likely)
- **C. Large result→scoring gap?** → Evidence correlation/scoring overhead
- **D. Everything reasonable but total huge?** → Serialization/concurrency issue

The data will tell us exactly where to optimize in Phase 0B.
