package exercise

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestHandleWait_EntersWaiting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()
		execID := seedExecution(t, store)
		ex := &Execution{ID: execID}
		ps := &PlanStep{ID: "w", Type: StepTypeWait, Config: StepConfig{WaitDuration: "5s"}}
		se := &StepExecution{ExecutionID: execID, StepID: "w", StepType: StepTypeWait}
		if err := e.handleWait(ctx, ex, ps, se); err != nil {
			t.Fatalf("handleWait: %v", err)
		}
		if se.Status != StepWaiting || se.ScheduledAt == nil {
			t.Fatalf("handleWait must set Waiting + ScheduledAt: %+v", se)
		}
		got, _ := store.GetStepExecByStepID(ctx, execID, "w")
		if got.Status != StepWaiting {
			t.Fatalf("persisted status = %q, want waiting", got.Status)
		}
	})
}

func TestHandleApproval_EntersWaitingWithEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()
		execID := seedExecution(t, store)
		ex := &Execution{ID: execID}
		ps := &PlanStep{ID: "ap", Type: StepTypeApproval, Config: StepConfig{ApprovalPrompt: "ok?"}}
		se := &StepExecution{ExecutionID: execID, StepID: "ap", StepType: StepTypeApproval}
		if err := e.handleApproval(ctx, ex, ps, se); err != nil {
			t.Fatalf("handleApproval: %v", err)
		}
		if se.Status != StepWaiting || se.StartedAt == nil {
			t.Fatalf("handleApproval must set Waiting + StartedAt: %+v", se)
		}
		evs, _ := store.ListEvidence(ctx, execID)
		if len(evs) != 1 || evs[0].EvidenceType != "approval_requested" {
			t.Fatalf("expected approval_requested evidence, got %+v", evs)
		}
	})
}

func TestHandleSendSMS_UnconfiguredFails(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()
		ex := seedRunningExecution(t, store, e, []PlanStep{{ID: "s", Type: StepTypeSendSMS, Config: StepConfig{SMS: &SMSConfig{To: []string{"+15550000"}, Body: "hi"}}}})
		ps := ex2step(store, ex, "s")
		se, _ := store.GetStepExecByStepID(ctx, ex.ID, "s")
		// With no gateway configured the handler fails the step synchronously.
		if err := e.handleSendSMS(nil)(ctx, ex, &ps, se); err != nil {
			t.Fatalf("handleSendSMS: %v", err)
		}
		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "s")
		if got.Status != StepFailed {
			t.Fatalf("SMS with nil gateway status = %q, want failed", got.Status)
		}
	})
}

func TestHandleWaitForAgent_CopiesRunID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()
		execID := seedExecution(t, store)

		// Referenced agent_task step holds bas_run_id in its result.
		atSe := &StepExecution{ExecutionID: execID, StepID: "at", StepType: StepTypeAgentTask, Status: StepCompleted}
		if err := store.UpsertStepExecution(ctx, atSe); err != nil {
			t.Fatalf("seed agent_task step: %v", err)
		}
		if err := store.SetStepResult(ctx, execID, "at", map[string]any{"bas_run_id": "r1"}); err != nil {
			t.Fatalf("SetStepResult: %v", err)
		}

		ps := &PlanStep{ID: "wa", Type: StepTypeWaitForAgent,
			Config: StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "at"}}}
		se := &StepExecution{ExecutionID: execID, StepID: "wa", StepType: StepTypeWaitForAgent}
		if err := e.handleWaitForAgent(ctx, &Execution{ID: execID}, ps, se); err != nil {
			t.Fatalf("handleWaitForAgent: %v", err)
		}
		if se.Status != StepWaiting {
			t.Fatalf("status = %q, want waiting", se.Status)
		}
		if se.Result["bas_run_id"] != "r1" {
			t.Fatalf("bas_run_id not copied from referenced step: %+v", se.Result)
		}
	})
}

func TestHandleWaitForDetectionAndWebhook_EnterWaiting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()
		execID := seedExecution(t, store)

		dse := &StepExecution{ExecutionID: execID, StepID: "wd", StepType: StepTypeWaitForDetection}
		if err := e.handleWaitForDetection(ctx, &Execution{ID: execID}, &PlanStep{ID: "wd", Type: StepTypeWaitForDetection}, dse); err != nil {
			t.Fatalf("handleWaitForDetection: %v", err)
		}
		if dse.Status != StepWaiting {
			t.Fatalf("wait_for_detection status = %q, want waiting", dse.Status)
		}

		wse := &StepExecution{ExecutionID: execID, StepID: "wh", StepType: StepTypeWaitForWebhook}
		if err := e.handleWaitForWebhook(ctx, &Execution{ID: execID}, &PlanStep{ID: "wh", Type: StepTypeWaitForWebhook}, wse); err != nil {
			t.Fatalf("handleWaitForWebhook: %v", err)
		}
		if wse.Status != StepWaiting {
			t.Fatalf("wait_for_webhook status = %q, want waiting", wse.Status)
		}
		if tok, _ := wse.Result["hook_token"].(string); tok == "" {
			t.Fatalf("wait_for_webhook must mint a hook_token: %+v", wse.Result)
		}
	})
}

func TestTriggerWaitForAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()

		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('a1')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		var runID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO scenario_runs (scenario_id, agent_id, status) VALUES ('s','a1','completed') RETURNING id`,
		).Scan(&runID); err != nil {
			t.Fatalf("seed scenario_run: %v", err)
		}

		se := &StepExecution{Result: map[string]any{"bas_run_id": runID}}
		ok, payload, err := e.triggerWaitForAgent(ctx, &Execution{}, &PlanStep{}, se)
		if err != nil || !ok || payload["bas_run_status"] != "completed" {
			t.Fatalf("trigger = (%v,%v,%v), want fired with status completed", ok, payload, err)
		}
		// No run id → not fired.
		ok2, _, _ := e.triggerWaitForAgent(ctx, &Execution{}, &PlanStep{}, &StepExecution{})
		if ok2 {
			t.Fatal("trigger with no bas_run_id must not fire")
		}
		_ = store
	})
}

func TestTriggerWaitForAgent_NonTerminalStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _ := newTestExecutor(pool)
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('a2')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		var runID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO scenario_runs (scenario_id, agent_id, status) VALUES ('s','a2','running') RETURNING id`,
		).Scan(&runID); err != nil {
			t.Fatalf("seed scenario_run: %v", err)
		}
		se := &StepExecution{Result: map[string]any{"bas_run_id": runID}}
		ok, _, err := e.triggerWaitForAgent(ctx, &Execution{}, &PlanStep{}, se)
		if err != nil {
			t.Fatalf("triggerWaitForAgent: %v", err)
		}
		if ok {
			t.Fatal("a still-running BAS run must not fire the wait_for_agent trigger")
		}
	})
}

func TestTriggerWaitForDetection_ExplicitConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		chain := NewEvidenceChain(store)
		ctx := context.Background()
		execID := seedExecution(t, store)
		if _, err := chain.Append(ctx, execID, "se1", "siem_alerted", "siem", "test", map[string]any{}); err != nil {
			t.Fatalf("append siem_alerted: %v", err)
		}
		// Explicit type list + MinCount 2 → one alert is not enough.
		ps := &PlanStep{Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
			DetectionTypes: []string{"siem_alerted"}, MinCount: 2}}}
		ok, _, err := e.triggerWaitForDetection(ctx, &Execution{ID: execID}, ps, &StepExecution{})
		if err != nil {
			t.Fatalf("triggerWaitForDetection: %v", err)
		}
		if ok {
			t.Fatal("MinCount 2 must not fire with a single matching alert")
		}
	})
}

func TestTriggerWaitForDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		chain := NewEvidenceChain(store)
		ctx := context.Background()
		execID := seedExecution(t, store)
		if _, err := chain.Append(ctx, execID, "se1", "edr_detected", "edr", "test", map[string]any{}); err != nil {
			t.Fatalf("append edr_detected: %v", err)
		}
		ok, payload, err := e.triggerWaitForDetection(ctx, &Execution{ID: execID}, &PlanStep{}, &StepExecution{})
		if err != nil || !ok || payload["detection_count"] != 1 {
			t.Fatalf("detection trigger = (%v,%v,%v), want fired with count 1", ok, payload, err)
		}
	})
}

func TestTriggerWaitForWebhook(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()
		if err := store.InsertWebhookCall(ctx, "tokX", "exW", "se1", []byte("{}")); err != nil {
			t.Fatalf("InsertWebhookCall: %v", err)
		}
		se := &StepExecution{Result: map[string]any{"hook_token": "tokX"}}
		ok, payload, err := e.triggerWaitForWebhook(ctx, &Execution{}, &PlanStep{}, se)
		if err != nil || !ok || payload["call_count"] == nil {
			t.Fatalf("webhook trigger = (%v,%v,%v), want fired with call_count", ok, payload, err)
		}
		// No token → not fired.
		ok2, _, _ := e.triggerWaitForWebhook(ctx, &Execution{}, &PlanStep{}, &StepExecution{})
		if ok2 {
			t.Fatal("webhook trigger with no token must not fire")
		}
	})
}

func TestTick_AdvancesRunningExecutions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.registry.Register(StepTypeNotify, completeHandler(store))
		ctx := context.Background()
		ex := seedRunningExecution(t, store, e, []PlanStep{{ID: "a", Type: StepTypeNotify}})
		if err := e.tick(ctx); err != nil {
			t.Fatalf("tick: %v", err)
		}
		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "a")
		if got.Status != StepCompleted {
			t.Fatalf("after tick, step a status = %q, want completed", got.Status)
		}
	})
}

func TestRegisterBuiltinTriggersAndSetDispatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _ := newTestExecutor(pool)
		e.RegisterBuiltinTriggers()
		if !e.triggers.Has(StepTypeWaitForAgent) || !e.triggers.Has(StepTypeWaitForDetection) || !e.triggers.Has(StepTypeWaitForWebhook) {
			t.Fatal("RegisterBuiltinTriggers must register all three event triggers")
		}
		e.SetDispatch(func(agentID, scenarioID, techniqueID string, policy scenario.ExecutionPolicy) (string, error) {
			return "run-1", nil
		})
	})
}

func TestListExecutions_DefaultLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()
		p := &Plan{Name: "P", Steps: []PlanStep{{ID: "a", Type: StepTypeNotify}}}
		if err := store.CreatePlan(ctx, p); err != nil {
			t.Fatalf("CreatePlan: %v", err)
		}
		for i := 0; i < 3; i++ {
			ex := &Execution{PlanID: p.ID, Name: "R", Status: ExecDraft}
			if err := store.CreateExecution(ctx, ex); err != nil {
				t.Fatalf("CreateExecution: %v", err)
			}
		}
		list, err := store.ListExecutions(ctx, 0) // 0 → default limit 50
		if err != nil || len(list) != 3 {
			t.Fatalf("ListExecutions = %d (err %v), want 3", len(list), err)
		}
	})
}
