# Phase 1: Exercise Detection Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `internal/exercise` to automated detection parity with the ART/Caldera `scenario_runs` path via two tracks converging on the existing `detect.Correlate`/`detect.Score` reference pipeline.

**Architecture:** Track 1 (BAS-backed `agent_task` steps) reuses `scenario_runs`' already-computed detection result via the exact same `StepWaiting`+`TriggerRegistry` polling mechanism `wait_for_agent`/`wait_for_detection` already use — no new mechanism invented. Track 2 (exercise-native, `phishing_reported` only) adds one new attribution signal and a small adapter, both flowing through the unmodified `Correlate`/`Score` functions.

**Tech Stack:** Go, PostgreSQL, existing `internal/exercise` executor/trigger machinery, existing `internal/detect` attribution package.

**Spec:** [docs/superpowers/specs/2026-09-05-phase1-exercise-detection-parity-design.md](../specs/2026-09-05-phase1-exercise-detection-parity-design.md) — read alongside this plan. This plan resolves the one architectural ambiguity the spec explicitly flagged (see Task 3's note) after verifying the real trigger-registry code, and corrects the spec's `bas_run_id`/detection wire shape references against the real `models.SimulationResult`/`DetectionAlert` structs.

## Global Constraints

- No changes to `wait_for_detection`/`bridgeVerifiedDetections` (human-verified evidence) — its own existing tests must pass unmodified (Task 5 confirms this explicitly).
- No changes to the five existing endpoint attribution signals in `internal/detect/attribution.go`, or to `Correlate`/`Score`'s core mechanics.
- No schema migration — `StepExecution.Result` is already `map[string]interface{}`.
- No external security-provider integration (mail/SMS gateways) — Track 2 in this phase only wires `phishing_reported`, the signal the platform already collects.
- Track 2 covers `send_email` (`StepTypeSendEmail`) steps only in this phase.

---

### Task 1: `internal/detect` — the `userReported` attribution signal

**Files:**
- Modify: `orchestrator/internal/detect/attribution.go` — add the `userReported` case to `attributionSignals`
- Test: `orchestrator/internal/detect/attribution_test.go` (append, or create if it doesn't exist — check first)

**Interfaces:**
- Consumes: nothing from later tasks
- Produces: `attributionSignals` recognizes `AlertRecord{Channel: "exercise-report"}` — Task 4 constructs exactly this shape.

- [ ] **Step 1: Check for an existing attribution test file**

Run: `ls orchestrator/internal/detect/*_test.go`

If `attribution_test.go` exists, read it fully first to match its exact test style (likely a table-driven test over `attributionSignals` or `IsAttributable`). If it doesn't exist, `internal/detect/detect_test.go` or similar is the fallback — check `ls` output and read whichever file already tests `attributionSignals` before writing Step 2, so the new test matches established conventions rather than inventing a new style.

- [ ] **Step 2: Write the failing test**

Add to whichever file Step 1 identified (adjust the exact table/assertion shape to match that file's real style once read — the logic below is what must be tested, not a literal drop-in):

```go
func TestAttributionSignals_UserReported(t *testing.T) {
	reported := AlertRecord{Channel: "exercise-report", Provider: "exercise-tracking"}
	signals := attributionSignals(reported, nil)
	found := false
	for _, s := range signals {
		if s == "userReported" {
			found = true
		}
	}
	if !found {
		t.Errorf("attributionSignals(%+v) = %v, want it to include %q", reported, signals, "userReported")
	}

	// Every existing endpoint-only signal must NOT fire for an exercise-report
	// channel -- this alert is not an EDR/kernel/macOS-security event.
	for _, unwanted := range []string{"defenderDetectId", "threatName", "edrProvider", "kernelDenial", "securitySubsystem"} {
		for _, s := range signals {
			if s == unwanted {
				t.Errorf("attributionSignals(%+v) unexpectedly included endpoint signal %q", reported, unwanted)
			}
		}
	}

	// An unrelated endpoint alert must NOT gain userReported.
	endpoint := AlertRecord{Channel: "Microsoft-Windows-Windows Defender/Operational", ThreatName: "Trojan:Win32/Test"}
	for _, s := range attributionSignals(endpoint, nil) {
		if s == "userReported" {
			t.Errorf("attributionSignals(%+v) unexpectedly included userReported", endpoint)
		}
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/detect/... -run TestAttributionSignals_UserReported -v`
Expected: FAIL — `userReported` never appears in `signals` (the case doesn't exist yet)

- [ ] **Step 4: Add the signal**

`orchestrator/internal/detect/attribution.go`, add to `attributionSignals` right after the existing `securitySubsystem` case, before `return out`:

```go
	// A simulated-phishing recipient reported it through the exercise's own
	// tracking/report mechanism (internal/exercise's phishing_reported
	// evidence, translated into this shape) -- a real, human-confirmed
	// control reaction, just not an endpoint one. Distinct from the five
	// signals above (all endpoint/EDR/kernel-audit concepts) but
	// participates in the exact same attribution/verdict/scoring model. See
	// docs/superpowers/specs/2026-09-05-phase1-exercise-detection-parity-design.md.
	if a.Channel == "exercise-report" {
		out = append(out, "userReported")
	}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/detect/... -run TestAttributionSignals_UserReported -v`
Expected: PASS

- [ ] **Step 6: Run the full package suite to confirm no breakage**

Run: `cd orchestrator && go test ./internal/detect/... -v`
Expected: `ok`, all existing tests (including the five endpoint signals' own tests) still pass unchanged

- [ ] **Step 7: Commit**

```bash
git add internal/detect/attribution.go internal/detect/attribution_test.go
git commit -m "feat(phase1): add userReported attribution signal for exercise-native detection"
```

(Adjust the test file path in this command if Step 1 found a different existing file.)

---

### Task 2: `internal/exercise` Store layer — read BAS run detection, read evidence timestamp

**Files:**
- Modify: `orchestrator/internal/exercise/store.go` — add `BASRunDetection` and `EarliestEvidenceTimestamp`
- Test: `orchestrator/internal/exercise/store_test.go` (append)

**Interfaces:**
- Consumes: `models.SimulationResult` (already imported in store.go), `exercise_evidence` table (existing)
- Produces:
  - `Store.BASRunDetection(ctx context.Context, runID, techniqueID string) (verdict, confidence, alertProvider string, mttdMs int64, ok bool, err error)` — Task 3 calls this.
  - `Store.EarliestEvidenceTimestamp(ctx context.Context, stepExecID, evType string) (*time.Time, error)` — Task 4 calls this.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/exercise/store_test.go`:

```go
func TestBASRunDetection_ReturnsDetectionVerdictForTechnique(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()
		runID := "bas-run-detection-test-1"
		agentID := "agent-detection-test"
		if _, err := pool.Exec(ctx,
			`INSERT INTO agents (agent_id, hostname, state) VALUES ($1,'h','active')`, agentID); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		resultsJSON := `[{"technique":{"id":"T1003.002"},"detectionVerdict":"detected","detectionAlert":{"channel":"Microsoft-Windows-Windows Defender/Operational","provider":"Windows Defender","confidence":"high","mttdMs":4200}}]`
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, status, results) VALUES ($1,'sc','` + agentID + `','completed',$2::jsonb)`,
			runID, resultsJSON); err != nil {
			t.Fatalf("seed scenario_run: %v", err)
		}

		verdict, confidence, provider, mttdMs, ok, err := store.BASRunDetection(ctx, runID, "T1003.002")
		if err != nil {
			t.Fatalf("BASRunDetection: %v", err)
		}
		if !ok {
			t.Fatal("ok = false, want true (matching technique with a detection verdict exists)")
		}
		if verdict != "detected" {
			t.Errorf("verdict = %q, want %q", verdict, "detected")
		}
		if confidence != "high" {
			t.Errorf("confidence = %q, want %q", confidence, "high")
		}
		if mttdMs != 4200 {
			t.Errorf("mttdMs = %d, want 4200", mttdMs)
		}
		if provider != "Windows Defender" {
			t.Errorf("provider = %q, want %q", provider, "Windows Defender")
		}

		// A technique not present in results: ok=false, no error.
		_, _, _, _, ok2, err2 := store.BASRunDetection(ctx, runID, "T9999")
		if err2 != nil {
			t.Fatalf("BASRunDetection (missing technique): %v", err2)
		}
		if ok2 {
			t.Error("ok = true for a technique not in results, want false")
		}
	})
}

func TestBASRunDetection_UnscoredTechniqueReturnsNotOK(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()
		runID := "bas-run-detection-test-2"
		agentID := "agent-detection-test-2"
		if _, err := pool.Exec(ctx,
			`INSERT INTO agents (agent_id, hostname, state) VALUES ($1,'h','active')`, agentID); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		// A completed run whose agent never found any alerts -- SubmitRunDetections
		// never ran (see agent/agent.go's collectAndSubmitDetections: it returns
		// early when len(alerts)==0), so DetectionVerdict is genuinely empty, not
		// an error. Must not be reported as ok=true with a fabricated verdict.
		resultsJSON := `[{"technique":{"id":"T1003.002"}}]`
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, status, results) VALUES ($1,'sc','` + agentID + `','completed',$2::jsonb)`,
			runID, resultsJSON); err != nil {
			t.Fatalf("seed scenario_run: %v", err)
		}

		_, _, _, _, ok, err := store.BASRunDetection(ctx, runID, "T1003.002")
		if err != nil {
			t.Fatalf("BASRunDetection: %v", err)
		}
		if ok {
			t.Error("ok = true for a technique with no DetectionVerdict, want false")
		}
	})
}

func TestEarliestEvidenceTimestamp_ReturnsFirstMatchingRecord(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		chain := NewEvidenceChain(store)
		ctx := context.Background()
		execID := seedExecution(t, store)
		se := &StepExecution{ExecutionID: execID, StepID: "s1", StepType: StepTypeSendEmail, Status: StepCompleted}
		if err := store.UpsertStepExecution(ctx, se); err != nil {
			t.Fatalf("UpsertStepExecution: %v", err)
		}

		if ts, err := store.EarliestEvidenceTimestamp(ctx, se.ID, "phishing_reported"); err != nil {
			t.Fatalf("EarliestEvidenceTimestamp (none yet): %v", err)
		} else if ts != nil {
			t.Errorf("ts = %v, want nil before any evidence exists", ts)
		}

		if _, err := chain.Append(ctx, execID, se.ID, "phishing_reported", "target", "tracker", map[string]any{}); err != nil {
			t.Fatalf("append phishing_reported: %v", err)
		}
		before := time.Now()

		ts, err := store.EarliestEvidenceTimestamp(ctx, se.ID, "phishing_reported")
		if err != nil {
			t.Fatalf("EarliestEvidenceTimestamp: %v", err)
		}
		if ts == nil {
			t.Fatal("ts = nil, want a real timestamp after evidence was appended")
		}
		if ts.After(before) {
			t.Errorf("ts = %v, want it at or before %v (recorded when the evidence was appended)", ts, before)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/exercise/... -run "TestBASRunDetection|TestEarliestEvidenceTimestamp" -v`
Expected: FAIL with `undefined: store.BASRunDetection` / `undefined: store.EarliestEvidenceTimestamp`

- [ ] **Step 3: Implement `BASRunDetection`**

`orchestrator/internal/exercise/store.go`, add near `BASRunStatus` (store.go:668):

```go
// BASRunDetection reads the DetectionVerdict already computed by
// SubmitRunDetections (internal/api/detection_handlers.go, the reference
// pipeline) for one technique within a scenario_run. ok=false (no error)
// means either the technique isn't in this run's results at all, or it is
// but was never detection-scored -- the agent found zero alerts in its
// post-run sweep and never called the detections endpoint at all (see
// agent/agent.go's collectAndSubmitDetections). Both are legitimate,
// common outcomes, never treated as an error.
func (s *Store) BASRunDetection(ctx context.Context, runID, techniqueID string) (verdict, confidence, alertProvider string, mttdMs int64, ok bool, err error) {
	var resultsRaw []byte
	if err := s.db.QueryRow(ctx,
		`SELECT results FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&resultsRaw); err != nil {
		return "", "", "", 0, false, err
	}
	var results []models.SimulationResult
	if err := json.Unmarshal(resultsRaw, &results); err != nil {
		return "", "", "", 0, false, err
	}
	for _, r := range results {
		if r.Technique.ID != techniqueID {
			continue
		}
		if r.DetectionVerdict == "" {
			return "", "", "", 0, false, nil
		}
		if r.DetectionAlert != nil {
			mttdMs = r.DetectionAlert.MTTDMs
			alertProvider = r.DetectionAlert.Provider
			confidence = r.DetectionAlert.Confidence
		}
		return r.DetectionVerdict, confidence, alertProvider, mttdMs, true, nil
	}
	return "", "", "", 0, false, nil
}
```

- [ ] **Step 4: Implement `EarliestEvidenceTimestamp`**

`orchestrator/internal/exercise/store.go`, add near `hasEvidenceType` (store.go:625):

```go
// EarliestEvidenceTimestamp returns when the first evidence record of evType
// was recorded for a step, or nil if none exists yet -- not an error, just
// not-yet-reported.
func (s *Store) EarliestEvidenceTimestamp(ctx context.Context, stepExecID, evType string) (*time.Time, error) {
	var ts time.Time
	err := s.db.QueryRow(ctx,
		`SELECT created_at FROM exercise_evidence
		 WHERE step_execution_id=$1 AND evidence_type=$2
		 ORDER BY created_at ASC LIMIT 1`, stepExecID, evType,
	).Scan(&ts)
	if err != nil {
		return nil, nil
	}
	return &ts, nil
}
```

Check `store.go`'s imports already include `"time"` — if not, add it (the file already imports `context`, `encoding/json`, `fmt`, `log`, `strings`, `github.com/jackc/pgx/v5/pgxpool`, `internal/exercise/tracker`, `internal/models`; `time` is used elsewhere in this package's other files but verify it's present in store.go specifically before assuming).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/exercise/... -run "TestBASRunDetection|TestEarliestEvidenceTimestamp" -v`
Expected: PASS

- [ ] **Step 6: Run the package suite to confirm no breakage**

Run: `cd orchestrator && go test ./internal/exercise/... -timeout 15m`
Expected: `ok`, zero FAIL lines

- [ ] **Step 7: Commit**

```bash
git add internal/exercise/store.go internal/exercise/store_test.go
git commit -m "feat(phase1): Store methods to read BAS run detection and evidence timestamps"
```

---

### Task 3: Track 1 — `agent_task` steps wait for and propagate BAS detection

**Files:**
- Modify: `orchestrator/internal/exercise/executor.go` — restructure `handleAgentTask`, add `triggerWaitForBASDetection`, register it
- Test: `orchestrator/internal/exercise/executor_test.go` (append)

**Interfaces:**
- Consumes: `Store.BASRunStatus` (existing, store.go:668), `Store.BASRunDetection` (Task 2)
- Produces: a completed `agent_task` `StepExecution.Result` gains `detection_verdict` (string), `detection_confidence` (string, omitted when empty), `detection_mttd_ms` (int64, omitted when 0), `detection_alert_provider` (string, omitted when empty) alongside the existing `bas_run_id`.

**Resolving the spec's flagged ambiguity, with real code:** `TriggerRegistry.Register(t StepType, fn TriggerFn)` (`triggers.go:22`) keys triggers by `StepType` — the same `StepTypeAgentTask` already used for the step *handler* registry (`e.registry.Register(StepTypeAgentTask, ...)`, executor.go:94) can independently have a *trigger* registered too; these are two separate maps (`e.registry` vs `e.triggers`), no collision. `advance()`'s "Dispatch ready pending steps" loop (executor.go:239) only processes `StepStatus == StepPending`, so once `handleAgentTask` transitions a step to `StepWaiting`, it is never re-dispatched. This means Track 1 does **not** need a new step type or a companion step an author must add — it fits the exact existing `StepWaiting`+`TriggerRegistry` architecture by registering a trigger against `agent_task`'s own existing type, exactly mirroring `handleWaitForAgent`/`triggerWaitForAgent`'s shape (executor.go:520-543, 591-604) instead of the `handleWaitForDetection`-style companion-step pattern.

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/exercise/executor_test.go`:

```go
// TestHandleAgentTask_WaitsForAndPropagatesDetection drives a real Executor
// through a real fake agent to a terminal scenario_run with a real
// SubmitRunDetections-equivalent write, then asserts the agent_task
// StepExecution picks up the resulting DetectionVerdict -- proving Track 1
// reuses the existing pipeline's already-computed result instead of
// duplicating correlation logic.
func TestHandleAgentTask_WaitsForAndPropagatesDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		runID := "bas-run-track1-test"
		agentID := "agent-track1-test"
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO agents (agent_id, hostname, state) VALUES ($1,'h','active')`, agentID); err != nil {
			t.Fatalf("seed agent: %v", err)
		}

		e, store := newTestExecutor(pool)
		e.SetDispatch(func(agentID, scenarioID, techniqueID string, policy scenario.ExecutionPolicy) (string, error) {
			return runID, nil
		})
		e.RegisterBuiltinTriggers()

		execID := seedExecution(t, store)
		ps := &PlanStep{ID: "dump-creds", Type: StepTypeAgentTask,
			Config: StepConfig{AgentTask: &AgentTaskConfig{AgentID: agentID, TechniqueID: "T1003.002"}}}
		ex := &Execution{ID: execID}

		if err := e.handleAgentTask(context.Background(), ex, ps, &StepExecution{ExecutionID: execID, StepID: ps.ID}); err != nil {
			t.Fatalf("handleAgentTask: %v", err)
		}
		// handleAgentTask dispatches asynchronously (existing goroutine) -- give it
		// a moment to reach StepWaiting with bas_run_id set.
		deadline := time.Now().Add(3 * time.Second)
		var se *StepExecution
		for time.Now().Before(deadline) {
			var err error
			se, err = store.GetStepExecByStepID(context.Background(), execID, ps.ID)
			if err == nil && se.Status == StepWaiting {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if se == nil || se.Status != StepWaiting {
			t.Fatalf("step never reached StepWaiting, got %+v", se)
		}
		if se.Result["bas_run_id"] != runID {
			t.Fatalf("bas_run_id = %v, want %q", se.Result["bas_run_id"], runID)
		}

		// Seed the underlying scenario_run as a terminal, detection-scored run --
		// exactly what SubmitRunDetections would have produced.
		resultsJSON := `[{"technique":{"id":"T1003.002"},"detectionVerdict":"detected","detectionAlert":{"channel":"Microsoft-Windows-Windows Defender/Operational","provider":"Windows Defender","confidence":"high","mttdMs":3100}}]`
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, status, results) VALUES ($1,'sc','`+agentID+`','completed',$2::jsonb)`,
			runID, resultsJSON); err != nil {
			t.Fatalf("seed scenario_run: %v", err)
		}

		triggered, payload, err := e.triggerWaitForBASDetection(context.Background(), ex, ps, se)
		if err != nil {
			t.Fatalf("triggerWaitForBASDetection: %v", err)
		}
		if !triggered {
			t.Fatal("triggered = false, want true (run is terminal and detection-scored)")
		}
		if payload["detection_verdict"] != "detected" {
			t.Errorf("payload[detection_verdict] = %v, want %q", payload["detection_verdict"], "detected")
		}
		if payload["detection_confidence"] != "high" {
			t.Errorf("payload[detection_confidence] = %v, want %q", payload["detection_confidence"], "high")
		}
		if payload["detection_mttd_ms"] != int64(3100) {
			t.Errorf("payload[detection_mttd_ms] = %v, want 3100", payload["detection_mttd_ms"])
		}
	})
}

// TestTriggerWaitForBASDetection_TerminalWithNoAlertsCompletesAfterGrace
// covers the common case where the agent found zero alerts and never called
// the detections endpoint at all -- the trigger must eventually fire with no
// fabricated verdict, not wait forever.
func TestTriggerWaitForBASDetection_TerminalWithNoAlertsCompletesAfterGrace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		runID := "bas-run-track1-nograce-test"
		agentID := "agent-track1-nograce-test"
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO agents (agent_id, hostname, state) VALUES ($1,'h','active')`, agentID); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		resultsJSON := `[{"technique":{"id":"T1003.002"}}]`
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, status, results) VALUES ($1,'sc','`+agentID+`','completed',$2::jsonb)`,
			runID, resultsJSON); err != nil {
			t.Fatalf("seed scenario_run: %v", err)
		}

		execID := seedExecution(t, store)
		ps := &PlanStep{ID: "dump-creds", Type: StepTypeAgentTask,
			Config: StepConfig{AgentTask: &AgentTaskConfig{AgentID: agentID, TechniqueID: "T1003.002"}}}
		ex := &Execution{ID: execID}
		// startedInPast simulates the trigger being checked well after the run
		// went terminal -- past the detection grace window -- without the test
		// needing to actually sleep 120s.
		startedInPast := time.Now().Add(-3 * time.Minute)
		se := &StepExecution{ExecutionID: execID, StepID: ps.ID, Status: StepWaiting, StartedAt: &startedInPast,
			Result: map[string]any{"bas_run_id": runID}}

		triggered, payload, err := e.triggerWaitForBASDetection(context.Background(), ex, ps, se)
		if err != nil {
			t.Fatalf("triggerWaitForBASDetection: %v", err)
		}
		if !triggered {
			t.Fatal("triggered = false, want true (grace window elapsed, must not wait forever)")
		}
		if _, has := payload["detection_verdict"]; has {
			t.Errorf("payload = %+v, want no detection_verdict key (never scored, not a fabricated verdict)", payload)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/exercise/... -run "TestHandleAgentTask_WaitsForAndPropagatesDetection|TestTriggerWaitForBASDetection_TerminalWithNoAlertsCompletesAfterGrace" -v`
Expected: FAIL — `undefined: e.triggerWaitForBASDetection`, and `handleAgentTask` still completes the step immediately rather than reaching `StepWaiting`

- [ ] **Step 3: Restructure `handleAgentTask`**

`orchestrator/internal/exercise/executor.go`, replace the function (executor.go:415-462) — the dispatch goroutine's tail changes from marking `StepCompleted` to marking `StepWaiting`, mirroring `handleWaitForAgent`'s shape:

```go
func (e *Executor) handleAgentTask(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
	cfg := ps.Config.AgentTask
	if cfg == nil || (cfg.ScenarioID == "" && cfg.TechniqueID == "") {
		return e.store.SetStepStatus(context.Background(), ex.ID, ps.ID, StepFailed, "missing agent_task config")
	}
	if e.dispatch == nil {
		return e.store.SetStepStatus(context.Background(), ex.ID, ps.ID, StepFailed, "agent dispatch not configured")
	}
	go func() {
		bctx := context.Background()
		bctx = observability.WithRunID(bctx, ex.ID)
		bctx = observability.WithTaskID(bctx, ps.ID)
		if cfg.AgentID != "" {
			bctx = observability.WithAgentID(bctx, cfg.AgentID)
		}
		start := time.Now()
		runID, err := e.dispatch(cfg.AgentID, cfg.ScenarioID, cfg.TechniqueID, ex.ExecutionPolicy)
		dispatchDuration := time.Since(start)
		if e.metrics != nil {
			e.metrics.AgentDispatchLatency.WithLabelValues(cfg.AgentID).Observe(dispatchDuration.Seconds())
		}
		if err != nil {
			_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepFailed, err.Error())
			return
		}
		dispatchSentTime := time.Now()
		se.DispatchSentAt = &dispatchSentTime
		log.Printf("[perf] execution_id=%s dispatch_sent_at=%s", se.ExecutionID, dispatchSentTime.Format(time.RFC3339Nano))
		// Phase 1: wait for detection (Track 1) instead of completing
		// immediately -- see triggerWaitForBASDetection, registered against
		// this same StepTypeAgentTask in RegisterBuiltinTriggers.
		se.Status = StepWaiting
		se.StartedAt = &dispatchSentTime
		se.Result = map[string]any{"bas_run_id": runID}
		if err := e.store.UpsertStepExecution(bctx, se); err != nil {
			log.Printf("[exercise] agent_task %s/%s: upsert waiting state: %v", ex.ID, ps.ID, err)
			return
		}
		_, _ = e.evidence.Append(bctx, ex.ID, se.ID, "agent_task_dispatched", "system", "bas_engine",
			map[string]any{"run_id": runID, "agent_id": cfg.AgentID})
		_ = e.store.RecordEvent(bctx, ex.ID, ps.ID, "step_waiting", "system", map[string]any{"waiting_for": "bas_run_detection", "bas_run_id": runID})
	}()
	return nil
}
```

(`ResultReceivedAt`/`ScoringCompletedAt` Phase 0A timestamps and the direct `SetStepResult`/`SetStepStatus(StepCompleted)` calls move to the new trigger in Step 4, since completion now happens there.)

- [ ] **Step 4: Add `triggerWaitForBASDetection`**

`orchestrator/internal/exercise/executor.go`, add right after `triggerWaitForAgent` (executor.go:604):

```go
// basDetectionGraceSecs bounds how long a dispatched agent_task step waits,
// after its underlying scenario_run goes terminal, for detection data that
// may simply never arrive -- the agent only calls the detections endpoint at
// all when its post-run alert sweep finds something (agent/agent.go's
// collectAndSubmitDetections, graceWait=90s then returns early on zero
// alerts). 120s covers that 90s plus sweep/network margin without asserting
// this number is final -- evidence-adjustable later the same way this
// codebase's timeout budgets already are (see project memory
// project_timeout_scored_as_pass.md).
const basDetectionGraceSecs = 120

func (e *Executor) triggerWaitForBASDetection(ctx context.Context, _ *Execution, ps *PlanStep, se *StepExecution) (bool, map[string]any, error) {
	runID, _ := se.Result["bas_run_id"].(string)
	if runID == "" {
		return false, nil, nil
	}
	status, err := e.store.BASRunStatus(ctx, runID)
	if err != nil {
		return false, nil, err
	}
	if status != "completed" && status != "failed" && status != "cancelled" && status != "partial" {
		return false, nil, nil // still running -- keep waiting
	}

	techniqueID := ""
	if ps.Config.AgentTask != nil {
		techniqueID = ps.Config.AgentTask.TechniqueID
	}
	payload := map[string]any{"bas_run_id": runID, "bas_run_status": status}
	if techniqueID == "" {
		// Whole-scenario dispatch (no single TechniqueID) -- Phase 1 scopes
		// Track 1 to the single-technique case; complete without a detection
		// verdict rather than guessing which of a multi-technique run's
		// results applies.
		return true, payload, nil
	}

	verdict, confidence, provider, mttdMs, ok, err := e.store.BASRunDetection(ctx, runID, techniqueID)
	if err != nil {
		return false, nil, err
	}
	if ok {
		payload["detection_verdict"] = verdict
		if confidence != "" {
			payload["detection_confidence"] = confidence
		}
		if mttdMs > 0 {
			payload["detection_mttd_ms"] = mttdMs
		}
		if provider != "" {
			payload["detection_alert_provider"] = provider
		}
		return true, payload, nil
	}

	// Not yet scored. If the run only just went terminal, the agent's 90s
	// grace + sweep may still be in flight -- keep waiting up to the bound.
	if se.StartedAt != nil && time.Since(*se.StartedAt) < basDetectionGraceSecs*time.Second {
		return false, nil, nil
	}
	// Grace window elapsed with nothing scored -- most likely the agent found
	// zero alerts and never called the detections endpoint at all. Complete
	// with no detection_verdict key rather than waiting forever or
	// fabricating a verdict.
	return true, payload, nil
}
```

- [ ] **Step 5: Register the trigger**

`orchestrator/internal/exercise/executor.go`, `RegisterBuiltinTriggers` (executor.go:109-113), add:

```go
	e.triggers.Register(StepTypeAgentTask, e.triggerWaitForBASDetection)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/exercise/... -run "TestHandleAgentTask_WaitsForAndPropagatesDetection|TestTriggerWaitForBASDetection_TerminalWithNoAlertsCompletesAfterGrace" -v`
Expected: PASS

- [ ] **Step 7: Run the package suite to confirm no breakage**

Run: `cd orchestrator && go test ./internal/exercise/... -timeout 15m`
Expected: `ok`, zero FAIL lines. Pay particular attention to any existing test that asserted `handleAgentTask` completes a step synchronously/immediately after dispatch — if one exists and now fails because the step reaches `StepWaiting` instead of `StepCompleted`, that test's assertion was pinning the exact behavior this task deliberately changes; update it to assert `StepWaiting` with `bas_run_id` set instead of asserting `StepCompleted`, and note the change in the commit message.

- [ ] **Step 8: Commit**

```bash
git add internal/exercise/executor.go internal/exercise/executor_test.go
git commit -m "feat(phase1): agent_task steps wait for and propagate BAS run detection (Track 1)"
```

---

### Task 4: Track 2 — `phishing_reported` scores `send_email` steps via the reference pipeline

**Files:**
- Modify: `orchestrator/internal/exercise/executor.go` — add a detection-scoring pass in `advance()`, plus the adapter function
- Test: `orchestrator/internal/exercise/executor_test.go` (append)

**Interfaces:**
- Consumes: `Store.EarliestEvidenceTimestamp` (Task 2), `hasEvidenceType` (existing, store.go:625), `detect.Correlate`/`detect.AlertRecord`/`detect.ExecutedStep`/`detect.TechniqueDetection` (existing, `internal/detect` — new import for this package), the `userReported` signal (Task 1). `detect.Score` is not called here — see Task 4 Step 4's doc comment for why.
- Produces: a completed `send_email` `StepExecution.Result` gains the same `detection_verdict`/`detection_confidence`/`detection_mttd_ms` keys Task 3 writes (no `detection_alert_provider` for this track — a report signal has no EDR provider).

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/exercise/executor_test.go`:

```go
// TestAdvance_ScoresPhishingReportedAsDetection drives a real Executor tick
// over a completed send_email step carrying phishing_reported evidence, and
// asserts it gains a detection_verdict via the same detect.Correlate
// attribution engine the ART/Caldera path uses -- proving Track 2 is not a
// second scoring interpretation.
func TestAdvance_ScoresPhishingReportedAsDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		chain := NewEvidenceChain(store)
		ctx := context.Background()
		execID := seedExecution(t, store)

		// StartedAt must be recent -- scoreExerciseNativeDetection uses it as
		// the technique's ExecutedAt, and Correlate's window-match compares it
		// against the report's timestamp (also "now", from chain.Append). A
		// zero-value StartedAt would sit outside even a 30-day window and the
		// alert would never match.
		sentAt := time.Now()
		se := &StepExecution{ExecutionID: execID, StepID: "phish1", StepType: StepTypeSendEmail, Status: StepCompleted, StartedAt: &sentAt}
		if err := store.UpsertStepExecution(ctx, se); err != nil {
			t.Fatalf("UpsertStepExecution: %v", err)
		}
		if _, err := chain.Append(ctx, execID, se.ID, "phishing_reported", "target", "tracker", map[string]any{}); err != nil {
			t.Fatalf("append phishing_reported: %v", err)
		}

		ex := &Execution{ID: execID}
		ps := &PlanStep{ID: "phish1", Type: StepTypeSendEmail,
			Config: StepConfig{Email: &EmailConfig{To: []string{"target@example.com"}}}}

		if err := e.scoreExerciseNativeDetection(ctx, ex, ps, se); err != nil {
			t.Fatalf("scoreExerciseNativeDetection: %v", err)
		}

		updated, err := store.GetStepExecByStepID(ctx, execID, "phish1")
		if err != nil {
			t.Fatalf("GetStepExecByStepID: %v", err)
		}
		if updated.Result["detection_verdict"] != "detected" {
			t.Errorf("detection_verdict = %v, want %q", updated.Result["detection_verdict"], "detected")
		}
	})
}

// TestAdvance_NoPhishingReportLeavesNoDetectionVerdict confirms a send_email
// step with no report evidence is not scored as anything -- absence of a
// report is not itself a verdict in Phase 1's scope.
func TestAdvance_NoPhishingReportLeavesNoDetectionVerdict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()
		execID := seedExecution(t, store)

		se := &StepExecution{ExecutionID: execID, StepID: "phish2", StepType: StepTypeSendEmail, Status: StepCompleted}
		if err := store.UpsertStepExecution(ctx, se); err != nil {
			t.Fatalf("UpsertStepExecution: %v", err)
		}
		ex := &Execution{ID: execID}
		ps := &PlanStep{ID: "phish2", Type: StepTypeSendEmail}

		if err := e.scoreExerciseNativeDetection(ctx, ex, ps, se); err != nil {
			t.Fatalf("scoreExerciseNativeDetection: %v", err)
		}

		updated, err := store.GetStepExecByStepID(ctx, execID, "phish2")
		if err != nil {
			t.Fatalf("GetStepExecByStepID: %v", err)
		}
		if _, has := updated.Result["detection_verdict"]; has {
			t.Errorf("Result = %+v, want no detection_verdict key (no report evidence)", updated.Result)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/exercise/... -run "TestAdvance_ScoresPhishingReportedAsDetection|TestAdvance_NoPhishingReportLeavesNoDetectionVerdict" -v`
Expected: FAIL with `undefined: e.scoreExerciseNativeDetection`

- [ ] **Step 3: Add the `internal/detect` import**

`orchestrator/internal/exercise/executor.go`, add to the import block:

```go
	"github.com/audspect/bas/internal/detect"
```

- [ ] **Step 4: Implement `scoreExerciseNativeDetection`**

`orchestrator/internal/exercise/executor.go`, add near `triggerWaitForBASDetection` (Task 3):

```go
// scoreExerciseNativeDetection is Track 2: normalizes phishing_reported
// evidence into a synthetic detect.AlertRecord and scores it through
// detect.Correlate -- the same attribution engine (via the new userReported
// signal, internal/detect/attribution.go) the ART/Caldera path uses, not a
// second interpretation. detect.Score is deliberately NOT called here: it
// aggregates DetectionRate/MTTDMs/etc. ACROSS a run's many techniques,
// which has nothing to add at single-step granularity -- every per-detection
// field this function needs (Verdict, Confidence, TimeToDetectMs) already
// lives on Correlate's own per-technique detect.TechniqueDetection result.
// Phase 1 scope: send_email steps only. A step with no phishing_reported
// evidence is left unscored (no detection_verdict key) -- absence of a
// report is not itself a verdict.
func (e *Executor) scoreExerciseNativeDetection(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
	reportedAt, err := e.store.EarliestEvidenceTimestamp(ctx, se.ID, "phishing_reported")
	if err != nil {
		return err
	}
	if reportedAt == nil {
		return nil
	}

	techniqueID := "T1566.001" // simulated phishing attachment/link -- the one technique this track scores in Phase 1
	sentAt := se.StartedAt
	if sentAt == nil {
		sentAt = se.CompletedAt
	}
	if sentAt == nil {
		sentAt = &ex.CreatedAt
	}
	// Verdict must be "fail" (not "completed") -- detect.go's isExecuted/
	// isPrevented only recognize "pass"|"blocked"|"fail" ("pass"/"blocked"
	// mean the control PREVENTED the technique; "fail" means it executed and
	// needs alert-correlation, which is exactly this case: the phishing email
	// was not blocked, it reached the recipient, who then reported it).
	steps := []detect.ExecutedStep{{TechniqueID: techniqueID, Verdict: "fail", ExecutedAt: *sentAt}}
	alerts := []detect.AlertRecord{{
		Channel: "exercise-report", Provider: "exercise-tracking", Timestamp: *reportedAt,
		Message: "recipient reported the simulated phishing email",
	}}
	// Window wide enough to never be the limiting factor -- a phishing report
	// can legitimately arrive hours or days after send, unlike an EDR alert's
	// tight post-execution window. detectIDs is nil (irrelevant here; only
	// meaningful for the Windows-Defender-specific signal).
	dets := detect.Correlate(steps, alerts, 30*24*time.Hour, nil)

	for _, d := range dets {
		if d.TechniqueID != techniqueID || d.Verdict == "" {
			continue
		}
		payload := map[string]any{"detection_verdict": d.Verdict}
		if d.Confidence != "" {
			payload["detection_confidence"] = d.Confidence
		}
		if d.TimeToDetectMs > 0 {
			payload["detection_mttd_ms"] = d.TimeToDetectMs
		}
		merged := mergeMaps(se.Result, payload)
		return e.store.SetStepResult(ctx, ex.ID, ps.ID, merged)
	}
	return nil
}
```

- [ ] **Step 5: Wire it into `advance()`**

`orchestrator/internal/exercise/executor.go`, in `advance()` (executor.go:131-234), add a lookup map plus a new loop after the existing "Fire triggers and advance timeout-expired wait steps" loop (after the closing `}` of the `for i := range plan.Steps` loop that ends around executor.go:217) and before the "Check completion" block. `advance()`'s existing `byID` (line 141) is keyed by step ID but maps to `*StepExecution`, not `*PlanStep`, so a second lookup map is needed here:

```go
	// Track 2: score exercise-native detection (phishing_reported) for
	// completed send_email steps not yet scored. Separate pass from the
	// trigger loop above -- this operates on already-StepCompleted steps
	// (an enrichment pass), not StepWaiting ones.
	planStepByID := make(map[string]*PlanStep, len(plan.Steps))
	for i := range plan.Steps {
		planStepByID[plan.Steps[i].ID] = &plan.Steps[i]
	}
	for i := range stepExecs {
		se := &stepExecs[i]
		if se.StepType != StepTypeSendEmail || se.Status != StepCompleted {
			continue
		}
		if _, scored := se.Result["detection_verdict"]; scored {
			continue
		}
		matchedStep, ok := planStepByID[se.StepID]
		if !ok {
			continue
		}
		if err := e.scoreExerciseNativeDetection(ctx, ex, matchedStep, se); err != nil {
			log.Printf("[exercise] score detection %s/%s: %v", ex.ID, se.StepID, err)
		}
	}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/exercise/... -run "TestAdvance_ScoresPhishingReportedAsDetection|TestAdvance_NoPhishingReportLeavesNoDetectionVerdict" -v`
Expected: PASS

- [ ] **Step 7: Run the package suite to confirm no breakage**

Run: `cd orchestrator && go build ./... && go test ./internal/exercise/... -timeout 15m`
Expected: build clean, `ok`, zero FAIL lines

- [ ] **Step 8: Commit**

```bash
git add internal/exercise/executor.go internal/exercise/executor_test.go
git commit -m "feat(phase1): phishing_reported scores send_email steps via detect.Correlate (Track 2)"
```

---

### Task 5: Regression — `wait_for_detection` unchanged, full suite green

**Files:**
- None modified — verification only.

**Interfaces:**
- Consumes: everything from Tasks 1-4.
- Produces: nothing further consumes this task.

- [ ] **Step 1: Run `wait_for_detection`'s own existing tests unmodified**

Run: `cd orchestrator && go test ./internal/exercise/... -run "TestTriggerWaitForDetection|TestBridgeVerifiedDetections|TestHandleWaitForDetection" -v`

Expected: PASS, and confirm via `git diff` that no test in this run required a code change from this plan — if any of these test names don't exist, run `grep -rn "func Test.*WaitForDetection\|func Test.*Verification" internal/exercise/*_test.go` first to find the real names, then run those.

- [ ] **Step 2: Full `internal/exercise` and `internal/detect` regression**

Run: `cd orchestrator && go build ./... && go vet ./internal/exercise/... ./internal/detect/... && go test ./internal/exercise/... ./internal/detect/... -timeout 20m -p 1`

Expected: build clean, vet clean, `ok` for both packages, zero FAIL lines. (`-p 1` avoids the known Docker-VM container-contention issue on this host if the default parallelism causes it — see this plan's own session history for precedent.)

- [ ] **Step 3: Confirm the 4 success criteria from the spec**

Point at the specific tests that demonstrate each:
1. Track 1 reuses the existing pipeline, no duplicated correlation logic → `TestHandleAgentTask_WaitsForAndPropagatesDetection` (Task 3)
2. `phishing_reported` produces a detection verdict via `detect.Correlate`'s attribution engine → `TestAdvance_ScoresPhishingReportedAsDetection` (Task 4)
3. `wait_for_detection` provably unchanged → Step 1 of this task
4. Zero new external integrations, zero schema migrations, zero changes to the five endpoint signals → confirmed by `git diff --stat` across all 4 tasks' commits (no `ALTER TABLE`, no new HTTP client/connector code, `attribution.go`'s diff is additive-only)

- [ ] **Step 4: No commit needed for this task** (verification-only) — if Step 1 or 2 surfaces a real regression, fix it as a follow-up commit referencing which task's change caused it, re-run this task's verification, and only then consider Phase 1 complete.

---

## Final verification

`cd orchestrator && go build ./... && go test ./internal/exercise/... ./internal/detect/... -timeout 20m -p 1`. All 4 success criteria demonstrated per Task 5. Then use `finishing-a-development-branch` (this plan, like Phase 0B and 0C before it, is executed directly on `main` — no separate branch to merge or PR).
