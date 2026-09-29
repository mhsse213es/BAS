# Scheduler-Serialization Staging Measurement Guide

**Goal:** Determine whether the orchestrator scheduler serializes concurrent job execution or handles them in parallel.

**Status:** Investigating the remaining hypothesis from Phase 0A performance measurement.

## Background

### Confirmed Finding
- **PowerShell cold-spawn overhead:** ~205ms (verified locally 2026-09-08)
- **PowerShell warm-pooled:** ~33ms
- This is the dominant observable latency in current system performance

### Open Question
- **Scheduler serialization:** Is the scheduler intentionally serializing jobs, or queuing them in parallel?
- Why: If jobs are queued serially, total throughput is limited; if parallel, they should start executing concurrently

## Measurement Approach

### 1. Load Test Generation

**Run:** `staging-loadtest`

Submits N concurrent scenario runs to the orchestrator and measures submission latency.

```bash
go run ./cmd/staging-loadtest \
  -url http://192.168.10.78:9443 \
  -scenario <scenario_id> \
  -concurrency 10 \
  -reps 3 \
  -delay 100ms
```

**Parameters:**
- `-url`: Orchestrator endpoint
- `-scenario`: Scenario ID to run (choose a small, ~20-30s scenario)
- `-concurrency`: Number of parallel jobs per wave (10-15 recommended)
- `-reps`: Number of waves to run (3-5 for stable results)
- `-delay`: Optional delay between job submissions (test both 0 and 100ms)

**Output:**
- Per-job submission latency
- Wave completion time
- Success/failure counts

### 2. Results Analysis

**Run:** `analyze-staging-results`

Fetches run results from the orchestrator API and measures timing:

```bash
go run ./cmd/analyze-staging-results \
  -url http://192.168.10.78:9443 \
  <runId1> <runId2> <runId3> ...
```

**Metrics Calculated:**

| Metric | Meaning | Indicates |
|--------|---------|-----------|
| Queue Wait | CreatedAt → StartedAt | Scheduler latency before dispatch |
| Execution | StartedAt → EndedAt | Actual scenario execution time |
| Total | CreatedAt → EndedAt | Complete job duration |

**Serialization Signal:**

- **Uniform queue waits (min/max ratio ≈ 1.0):** Parallel processing
- **Increasing queue waits (ratio > 2.0):** Serial queue buildup → serialization detected
- **High variability:** Contention or resource constraints

## Test Execution Plan

### Phase 1: Baseline (Sequential)

Submit 1 job at a time, wait for completion, measure total throughput.

```bash
# Sequential: submit 1 job, wait, repeat 10 times
go run ./cmd/staging-loadtest -url ... -scenario ... -concurrency 1 -reps 10
```

**Expected:** Queue wait ≈ 0ms, execution ≈ scenario runtime

### Phase 2: Concurrent (Small Wave)

Submit 5 jobs simultaneously, measure queue buildup.

```bash
go run ./cmd/staging-loadtest -url ... -scenario ... -concurrency 5 -reps 3
```

**Expected:** 
- If parallel: All 5 have similar queue wait (~0ms)
- If serial: Queue waits increase: job1≈0ms, job2≈30s, job3≈60s, etc.

### Phase 3: Concurrent (Large Wave)

Submit 10 jobs simultaneously to stress-test queuing.

```bash
go run ./cmd/staging-loadtest -url ... -scenario ... -concurrency 10 -reps 2
```

**Expected:** Strong signal of serialization if present.

## Evidence Interpretation

### Scenario A: Parallel Execution
```
Queue Waits: [0ms, 10ms, 15ms, 20ms, 5ms, ...]  ← Uniform, low
Min/Max ratio: 1.2x
→ Conclusion: Scheduler handles jobs in parallel
```

### Scenario B: Serialization Detected
```
Queue Waits: [0ms, 30s, 60s, 90s, 120s, ...]  ← Increasing linearly
Min/Max ratio: 120x
→ Conclusion: Jobs are queued serially; each waits for prior to complete
```

### Scenario C: Resource Contention
```
Queue Waits: [0ms, 5s, 8s, 4s, 10s, ...]  ← High variability, modest increases
Min/Max ratio: 2.5x
→ Conclusion: Parallel queuing but resource contention causes variable delays
```

## Deliverables

After measurement:

1. **Evidence Report**
   - Load test output (submission latencies, wave completion)
   - Run IDs for tracing in orchestrator logs
   - Raw timing data

2. **Analysis Results**
   - Queue wait percentiles (p50, p95, p99)
   - Execution duration distribution
   - Serialization detection result

3. **Conclusion**
   - Confirmed: Scheduler is [parallel | serial | hybrid]
   - Rationale: Based on [evidence class A/B/C]
   - Closure: Tasks #671-672 closed with finding

## Notes

- **PowerShell overhead (205ms cold) is independent** — this finding stands regardless of scheduler concurrency
- **Use a small, deterministic scenario** — avoid network timeouts, variable execution times
- **Run multiple waves** — single-run noise can mask patterns (need 20-30 jobs minimum)
- **Capture run IDs** — needed to correlate timing data with orchestrator logs if debugging needed

## Rollback/Cleanup

After measurement:
- Delete temporary load test / analysis tools
- Keep orchestrator as-is (no test artifacts on staging)
- Preserve measurement data and this report for documentation
