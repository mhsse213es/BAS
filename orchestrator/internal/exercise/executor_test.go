package exercise

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/verification"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newTestExecutor wires an Executor with real store/evidence but no scheduler
// loop (we call advance directly) and an empty registry the caller populates.
func newTestExecutor(pool *pgxpool.Pool) (*Executor, *Store) {
	store := NewStore(pool)
	ev := NewEvidenceChain(store)
	reg := NewRegistry()
	e := NewExecutor(store, ev, reg, NewPollScheduler(time.Hour), nil)
	return e, store
}

// completeHandler marks the step Completed synchronously so advance() can make
// deterministic progress without goroutines.
func completeHandler(store *Store) StepHandlerFunc {
	return func(ctx context.Context, ex *Execution, ps *PlanStep, _ *StepExecution) error {
		return store.SetStepStatus(context.Background(), ex.ID, ps.ID, StepCompleted, "")
	}
}

func seedRunningExecution(t *testing.T, store *Store, e *Executor, steps []PlanStep) *Execution {
	t.Helper()
	ctx := context.Background()
	p := &Plan{Name: "P", Steps: steps}
	if err := store.CreatePlan(ctx, p); err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	ex := &Execution{PlanID: p.ID, Name: "R", Status: ExecDraft}
	if err := store.CreateExecution(ctx, ex); err != nil {
		t.Fatalf("CreateExecution: %v", err)
	}
	if err := e.LaunchExecution(ctx, ex.ID); err != nil {
		t.Fatalf("LaunchExecution: %v", err)
	}
	got, _ := store.GetExecution(ctx, ex.ID)
	return got
}

func TestLaunchExecution_SeedsStepsAndRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ex := seedRunningExecution(t, store, e, []PlanStep{{ID: "a", Type: StepTypeNotify}, {ID: "b", Type: StepTypeNotify, DependsOn: []string{"a"}}})
		if ex.Status != ExecRunning {
			t.Fatalf("status = %q, want running", ex.Status)
		}
		steps, _ := store.ListStepExecutions(context.Background(), ex.ID)
		if len(steps) != 2 {
			t.Fatalf("expected 2 seeded step execs, got %d", len(steps))
		}
		// A non-draft/scheduled execution is a no-op relaunch.
		if err := e.LaunchExecution(context.Background(), ex.ID); err != nil {
			t.Fatalf("relaunch should be a no-op, got %v", err)
		}
	})
}

func TestAdvance_DependencyOrderingAndCompletion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.registry.Register(StepTypeNotify, completeHandler(store))
		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "a", Type: StepTypeNotify},
			{ID: "b", Type: StepTypeNotify, DependsOn: []string{"a"}},
		})
		ctx := context.Background()

		// Tick 1: only "a" is ready; the completing handler marks it done.
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance 1: %v", err)
		}
		bStep, _ := store.GetStepExecByStepID(ctx, ex.ID, "b")
		if bStep != nil && bStep.Status == StepCompleted {
			t.Fatal("b must not complete before a is done")
		}
		// Tick 2: "a" done → "b" dispatched and completed.
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance 2: %v", err)
		}
		// Tick 3: all done → execution Completed.
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance 3: %v", err)
		}
		got, _ := store.GetExecution(ctx, ex.ID)
		if got.Status != ExecCompleted {
			t.Fatalf("execution status = %q, want completed", got.Status)
		}
	})
}

func TestAdvance_ConditionFalseSkips(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.registry.Register(StepTypeNotify, completeHandler(store))
		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "a", Type: StepTypeNotify},
			{ID: "b", Type: StepTypeNotify, DependsOn: []string{"a"}, Condition: "never"},
		})
		ctx := context.Background()
		_ = e.advance(ctx, ex) // a completes
		_ = e.advance(ctx, ex) // b evaluated: condition false → skipped
		bStep, _ := store.GetStepExecByStepID(ctx, ex.ID, "b")
		if bStep == nil || bStep.Status != StepSkipped {
			t.Fatalf("b status = %v, want skipped", bStep)
		}
	})
}

func TestEvalCondition_PredicateMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		chain := NewEvidenceChain(store)
		ctx := context.Background()
		execID := seedExecution(t, store)

		// Build a real step exec so hasEvidenceType has an id to match.
		se := &StepExecution{ExecutionID: execID, StepID: "s1", StepType: StepTypeSendEmail, Status: StepCompleted}
		if err := store.UpsertStepExecution(ctx, se); err != nil {
			t.Fatalf("UpsertStepExecution: %v", err)
		}
		if _, err := chain.Append(ctx, execID, se.ID, "link_clicked", "target", "tracker", map[string]any{}); err != nil {
			t.Fatalf("append link_clicked: %v", err)
		}
		byID := map[string]*StepExecution{"s1": se}

		// literals
		if !e.evalCondition(ctx, "", execID, byID, "") || !e.evalCondition(ctx, "always", execID, byID, "") || !e.evalCondition(ctx, "true", execID, byID, "") {
			t.Fatal("empty/always/true must be true")
		}
		if e.evalCondition(ctx, "false", execID, byID, "") || e.evalCondition(ctx, "never", execID, byID, "") {
			t.Fatal("false/never must be false")
		}
		// evidence-based
		if !e.evalCondition(ctx, "step:s1:clicked", execID, byID, "") {
			t.Fatal("clicked should be true (link_clicked evidence present)")
		}
		if e.evalCondition(ctx, "step:s1:not_clicked", execID, byID, "") {
			t.Fatal("not_clicked should be false")
		}
		if e.evalCondition(ctx, "step:s1:reported", execID, byID, "") {
			t.Fatal("reported should be false (no phishing_reported evidence)")
		}
		// status-based
		if !e.evalCondition(ctx, "step:s1:succeeded", execID, byID, "") {
			t.Fatal("succeeded should be true for a completed no-error step")
		}
		if e.evalCondition(ctx, "step:s1:failed", execID, byID, "") {
			t.Fatal("failed should be false for a completed step")
		}
		// timed_out via result
		se.Result = map[string]any{"timed_out": true}
		if !e.evalCondition(ctx, "step:s1:timeout", execID, byID, "") {
			t.Fatal("timeout should be true when result.timed_out is true")
		}
		if e.evalCondition(ctx, "step:s1:no_timeout", execID, byID, "") {
			t.Fatal("no_timeout should be false when timed_out is true")
		}
		// unknown predicate/format → defaults to true (fail-open per code)
		if !e.evalCondition(ctx, "step:s1:mystery", execID, byID, "") {
			t.Fatal("unknown predicate should default to true")
		}
		if !e.evalCondition(ctx, "garbage", execID, byID, "") {
			t.Fatal("unknown format should default to true")
		}
	})
}

// TestEvalCondition_AgentDomainJoinedPredicate covers the new agent: predicate
// namespace, sibling to the existing step: namespace. true/false/unknown-agent
// mirror the existing step: predicate tests' coverage shape.
func TestEvalCondition_AgentDomainJoinedPredicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _ := newTestExecutor(pool)
		ctx := context.Background()

		joinedAgent := "exercise-agent-domain-joined"
		notJoinedAgent := "exercise-agent-domain-not-joined"
		unknownAgent := "exercise-agent-domain-unknown"
		if _, err := pool.Exec(ctx,
			`INSERT INTO agents (agent_id, hostname, state, domain_joined) VALUES ($1,'h','active',true)`, joinedAgent); err != nil {
			t.Fatalf("seed joined agent: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO agents (agent_id, hostname, state, domain_joined) VALUES ($1,'h','active',false)`, notJoinedAgent); err != nil {
			t.Fatalf("seed not-joined agent: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO agents (agent_id, hostname, state) VALUES ($1,'h','active')`, unknownAgent); err != nil {
			t.Fatalf("seed unknown agent: %v", err)
		}

		byID := map[string]*StepExecution{}
		if !e.evalCondition(ctx, "agent:domain_joined:true", "exec-x", byID, joinedAgent) {
			t.Error("joined agent should satisfy agent:domain_joined:true")
		}
		if e.evalCondition(ctx, "agent:domain_joined:true", "exec-x", byID, notJoinedAgent) {
			t.Error("not-joined agent should fail agent:domain_joined:true")
		}
		if !e.evalCondition(ctx, "agent:domain_joined:false", "exec-x", byID, notJoinedAgent) {
			t.Error("not-joined agent should satisfy agent:domain_joined:false")
		}
		// Unknown (NULL) or no agent at all: fail open (true), same philosophy
		// as an unrecognised predicate defaulting to true.
		if !e.evalCondition(ctx, "agent:domain_joined:true", "exec-x", byID, unknownAgent) {
			t.Error("agent with unknown domain_joined should fail open (true)")
		}
		if !e.evalCondition(ctx, "agent:domain_joined:true", "exec-x", byID, "") {
			t.Error("no agent (empty agentID) should fail open (true)")
		}
	})
}

func TestAdvance_WaitTimeoutCompletes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()
		ex := seedRunningExecution(t, store, e, []PlanStep{{ID: "w", Type: StepTypeWait}})

		// Put the wait step into StepWaiting with a deadline in the past.
		past := time.Now().Add(-time.Minute)
		se := &StepExecution{ExecutionID: ex.ID, StepID: "w", StepType: StepTypeWait, Status: StepWaiting, ScheduledAt: &past}
		if err := store.UpsertStepExecution(ctx, se); err != nil {
			t.Fatalf("UpsertStepExecution waiting: %v", err)
		}
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}
		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "w")
		if got.Status != StepCompleted {
			t.Fatalf("timed-out wait step status = %q, want completed", got.Status)
		}
	})
}

func TestAdvance_TriggerFires(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()

		tr := NewTriggerRegistry()
		tr.Register(StepTypeWaitForWebhook, func(context.Context, *Execution, *PlanStep, *StepExecution) (bool, map[string]any, error) {
			return true, map[string]any{"fired": true}, nil
		})
		e.WithTriggers(tr)

		ex := seedRunningExecution(t, store, e, []PlanStep{{ID: "h", Type: StepTypeWaitForWebhook}})
		se := &StepExecution{ExecutionID: ex.ID, StepID: "h", StepType: StepTypeWaitForWebhook, Status: StepWaiting}
		if err := store.UpsertStepExecution(ctx, se); err != nil {
			t.Fatalf("UpsertStepExecution waiting: %v", err)
		}
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}
		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "h")
		if got.Status != StepCompleted || got.Result["fired"] != true {
			t.Fatalf("triggered step = %+v, want completed with fired=true", got)
		}
	})
}

func TestApproveStep_Completes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()
		ex := seedRunningExecution(t, store, e, []PlanStep{{ID: "ap", Type: StepTypeApproval}})
		if err := e.ApproveStep(ctx, ex.ID, "ap", "manager"); err != nil {
			t.Fatalf("ApproveStep: %v", err)
		}
		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "ap")
		if got.Status != StepCompleted || got.Result["approver"] != "manager" {
			t.Fatalf("approved step = %+v, want completed with approver=manager", got)
		}
	})
}

func TestAbortExecution_CancelsPendingAndWaiting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()
		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "p", Type: StepTypeNotify},
			{ID: "w", Type: StepTypeWait},
		})
		// Mark "w" waiting; leave "p" pending.
		wse := &StepExecution{ExecutionID: ex.ID, StepID: "w", StepType: StepTypeWait, Status: StepWaiting}
		_ = store.UpsertStepExecution(ctx, wse)

		if err := e.AbortExecution(ctx, ex.ID); err != nil {
			t.Fatalf("AbortExecution: %v", err)
		}
		got, _ := store.GetExecution(ctx, ex.ID)
		if got.Status != ExecAborted {
			t.Fatalf("execution status = %q, want aborted", got.Status)
		}
		steps, _ := store.ListStepExecutions(ctx, ex.ID)
		for _, s := range steps {
			if s.Status != StepCancelled {
				t.Fatalf("step %s status = %q, want cancelled", s.StepID, s.Status)
			}
		}
	})
}

func TestComputeScore_HumanAndOverall(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		chain := NewEvidenceChain(store)
		ctx := context.Background()
		execID := seedExecution(t, store)
		for _, ty := range []string{"email_sent", "email_sent", "link_clicked"} {
			if _, err := chain.Append(ctx, execID, "se1", ty, "system", "test", map[string]any{}); err != nil {
				t.Fatalf("append %s: %v", ty, err)
			}
		}
		score := e.computeScore(ctx, &Execution{ID: execID})
		if score.Human.Sent != 2 || score.Human.Clicked != 1 {
			t.Fatalf("human score = %+v, want Sent=2 Clicked=1", score.Human)
		}
		if score.Human.ClickRate != 0.5 {
			t.Fatalf("click rate = %v, want 0.5", score.Human.ClickRate)
		}
		// No edr/siem evidence → detBonus 0 → Overall = (1-0.5)*60 = 30.
		if score.Overall != 30 {
			t.Fatalf("overall = %v, want 30", score.Overall)
		}
		// Real injects were sent, so this IS a measurable result.
		if !score.Measurable {
			t.Error("Measurable = false, want true — 2 injects were actually sent")
		}
	})
}

// TestComputeScore_NoActivityIsNotMeasurable pins the fix for a real defect:
// an exercise whose steps perform no technical action (e.g. a plan of only
// approval gates — exactly what a user hit) sends nothing and detects
// nothing, leaving ClickRate at its 0.0 zero value because the
// `if h.Sent > 0` guard never runs. Overall then computes to
// (1-0)*60 + 0*40 = a confident-looking 60 for an exercise where literally
// nothing happened -- and indistinguishable from a genuinely excellent run
// (many sent, zero clicked, no EDR alert). Measurable must be false so the
// UI withholds the number instead of presenting it as a result.
func TestComputeScore_NoActivityIsNotMeasurable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()
		execID := seedExecution(t, store) // no evidence appended at all

		score := e.computeScore(ctx, &Execution{ID: execID})
		if score.Measurable {
			t.Error("Measurable = true, want false — nothing was sent and nothing detected")
		}
		// The misleading value is still computed (documented: zeroing it would
		// read as "scored terribly", an equally wrong claim) -- Measurable is
		// what gates its display, so assert the trap it guards against is real.
		if score.Overall != 60 {
			t.Errorf("overall = %v, want the documented misleading 60 this flag exists to suppress", score.Overall)
		}
		if score.Human.Sent != 0 || score.Human.Clicked != 0 {
			t.Errorf("human = %+v, want all zero", score.Human)
		}
	})
}

// TestExerciseScore_MarshalJSONDerivesMeasurable proves Measurable is always
// recomputed at marshal time rather than trusting stored state, so a score
// persisted before the field existed (unmarshals to false) is still reported
// correctly on read instead of hiding a legitimately-measured result.
func TestExerciseScore_MarshalJSONDerivesMeasurable(t *testing.T) {
	// Simulates a legacy row: real activity, but Measurable false on the struct.
	legacy := ExerciseScore{
		Human:      HumanScore{Sent: 10, Clicked: 2, ClickRate: 0.2},
		Overall:    48,
		Measurable: false,
	}
	b, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out["measurable"] != true {
		t.Errorf("measurable = %v, want true — 10 injects were sent, must be derived not trusted", out["measurable"])
	}

	// And the genuinely-empty case still marshals as not measurable.
	empty := ExerciseScore{Overall: 60, Measurable: true} // stored flag deliberately wrong
	b2, _ := json.Marshal(empty)
	var out2 map[string]any
	_ = json.Unmarshal(b2, &out2)
	if out2["measurable"] != false {
		t.Errorf("measurable = %v, want false — nothing sent, nothing detected", out2["measurable"])
	}
}

func TestBuiltinHandlers_SynchronousGuards(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.RegisterBuiltins(nil, nil, nil, nil) // nil injectors
		ctx := context.Background()

		// send_email with nil SMTP → Failed (synchronous guard).
		ex := seedRunningExecution(t, store, e, []PlanStep{{ID: "em", Type: StepTypeSendEmail, Config: StepConfig{Email: &EmailConfig{}}}})
		se, _ := store.GetStepExecByStepID(ctx, ex.ID, "em")
		emStep := ex2step(store, ex, "em")
		if err := e.registry.Dispatch(ctx, ex, &emStep, se); err != nil {
			t.Fatalf("dispatch send_email: %v", err)
		}
		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "em")
		if got.Status != StepFailed {
			t.Fatalf("send_email with nil SMTP status = %q, want failed", got.Status)
		}

		// agent_task with nil config → Failed.
		ex2 := seedRunningExecution(t, store, e, []PlanStep{{ID: "at", Type: StepTypeAgentTask}})
		se2, _ := store.GetStepExecByStepID(ctx, ex2.ID, "at")
		atStep := ex2step(store, ex2, "at")
		_ = e.registry.Dispatch(ctx, ex2, &atStep, se2)
		got2, _ := store.GetStepExecByStepID(ctx, ex2.ID, "at")
		if got2.Status != StepFailed {
			t.Fatalf("agent_task with nil config status = %q, want failed", got2.Status)
		}

		// notify → Completed (log-only stub).
		ex3 := seedRunningExecution(t, store, e, []PlanStep{{ID: "no", Type: StepTypeNotify, Config: StepConfig{NotifyMsg: "hi"}}})
		se3, _ := store.GetStepExecByStepID(ctx, ex3.ID, "no")
		noStep := ex2step(store, ex3, "no")
		_ = e.registry.Dispatch(ctx, ex3, &noStep, se3)
		got3, _ := store.GetStepExecByStepID(ctx, ex3.ID, "no")
		if got3.Status != StepCompleted {
			t.Fatalf("notify status = %q, want completed", got3.Status)
		}
	})
}

func TestAdvance_ApprovalTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()
		ex := seedRunningExecution(t, store, e, []PlanStep{{ID: "ap", Type: StepTypeApproval, TimeoutSecs: 1}})

		// UpsertStepExecution does not persist started_at from the struct (in the
		// real flow it is set by the Running transition), so back-date it via SQL.
		se := &StepExecution{ExecutionID: ex.ID, StepID: "ap", StepType: StepTypeApproval, Status: StepWaiting}
		if err := store.UpsertStepExecution(ctx, se); err != nil {
			t.Fatalf("UpsertStepExecution: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`UPDATE exercise_step_executions SET started_at = NOW() - interval '1 minute' WHERE execution_id=$1 AND step_id=$2`,
			ex.ID, "ap"); err != nil {
			t.Fatalf("back-date started_at: %v", err)
		}
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}
		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "ap")
		if got.Status != StepCompleted {
			t.Fatalf("timed-out approval status = %q, want completed", got.Status)
		}
	})
}

func TestAdvance_EventWaitTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()
		ex := seedRunningExecution(t, store, e, []PlanStep{{ID: "wa", Type: StepTypeWaitForAgent, TimeoutSecs: 1}})

		se := &StepExecution{ExecutionID: ex.ID, StepID: "wa", StepType: StepTypeWaitForAgent, Status: StepWaiting}
		if err := store.UpsertStepExecution(ctx, se); err != nil {
			t.Fatalf("UpsertStepExecution: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`UPDATE exercise_step_executions SET started_at = NOW() - interval '1 minute' WHERE execution_id=$1 AND step_id=$2`,
			ex.ID, "wa"); err != nil {
			t.Fatalf("back-date started_at: %v", err)
		}
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}
		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "wa")
		if got.Status != StepCompleted {
			t.Fatalf("timed-out event-wait status = %q, want completed", got.Status)
		}
	})
}

func TestAdvance_ResolvesVariables(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ev := NewEvidenceChain(store)
		reg := NewRegistry()
		e := NewExecutor(store, ev, reg, NewPollScheduler(time.Hour), nil)
		ctx := context.Background()

		// A handler that records the (already-resolved) NotifyMsg it receives.
		var seen string
		reg.Register(StepTypeNotify, StepHandlerFunc(func(_ context.Context, ex *Execution, ps *PlanStep, _ *StepExecution) error {
			seen = ps.Config.NotifyMsg
			return store.SetStepStatus(context.Background(), ex.ID, ps.ID, StepCompleted, "")
		}))

		p := &Plan{Name: "P",
			Variables: []VarDef{{Name: "Msg", Type: VarTypeString}},
			Steps:     []PlanStep{{ID: "n", Type: StepTypeNotify, Config: StepConfig{NotifyMsg: "hi ${Msg}"}}}}
		if err := store.CreatePlan(ctx, p); err != nil {
			t.Fatalf("CreatePlan: %v", err)
		}
		ex := &Execution{PlanID: p.ID, Name: "R", Status: ExecDraft, Variables: map[string]string{"Msg": "there"}}
		if err := store.CreateExecution(ctx, ex); err != nil {
			t.Fatalf("CreateExecution: %v", err)
		}
		if err := e.LaunchExecution(ctx, ex.ID); err != nil {
			t.Fatalf("LaunchExecution: %v", err)
		}
		got, _ := store.GetExecution(ctx, ex.ID)
		if err := e.advance(ctx, got); err != nil {
			t.Fatalf("advance: %v", err)
		}
		if seen != "hi there" {
			t.Fatalf("dispatchStep did not resolve ${Msg}: handler saw %q", seen)
		}
	})
}

func TestCreatePlan_VersionPreserved(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()
		p := &Plan{Name: "P", Version: 3, Steps: []PlanStep{{ID: "a", Type: StepTypeNotify}}}
		if err := store.CreatePlan(ctx, p); err != nil {
			t.Fatalf("CreatePlan: %v", err)
		}
		got, _ := store.GetPlan(ctx, p.ID)
		if got.Version != 3 {
			t.Fatalf("Version = %d, want 3 (max1 must preserve values >= 1)", got.Version)
		}
	})
}

// ex2step fetches the PlanStep for a given step id from the execution's plan.
func ex2step(store *Store, ex *Execution, stepID string) PlanStep {
	plan, _ := store.GetPlan(context.Background(), ex.PlanID)
	for _, ps := range plan.Steps {
		if ps.ID == stepID {
			return ps
		}
	}
	return PlanStep{ID: stepID}
}

func TestHandleAgentTask_PassesExecutionPolicyThroughDispatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.RegisterBuiltins(nil, nil, nil, nil)
		received := make(chan scenario.ExecutionPolicy, 1)
		e.SetDispatch(func(agentID, scenarioID, techniqueID string, policy scenario.ExecutionPolicy) (string, error) {
			received <- policy
			return "run-1", nil
		})

		ctx := context.Background()
		p := &Plan{Name: "P", Steps: []PlanStep{
			{ID: "at", Type: StepTypeAgentTask, Config: StepConfig{AgentTask: &AgentTaskConfig{AgentID: "agent-1", ScenarioID: "sc-1"}}},
		}}
		if err := store.CreatePlan(ctx, p); err != nil {
			t.Fatalf("CreatePlan: %v", err)
		}
		ex := &Execution{PlanID: p.ID, Name: "R", Status: ExecDraft, ExecutionPolicy: scenario.ExecutionPolicy{MaxPrivilege: "user"}}
		if err := store.CreateExecution(ctx, ex); err != nil {
			t.Fatalf("CreateExecution: %v", err)
		}
		if err := e.LaunchExecution(ctx, ex.ID); err != nil {
			t.Fatalf("LaunchExecution: %v", err)
		}
		got, err := store.GetExecution(ctx, ex.ID)
		if err != nil {
			t.Fatalf("GetExecution: %v", err)
		}
		if got.ExecutionPolicy.MaxPrivilege != "user" {
			t.Fatalf("ExecutionPolicy did not survive persist/reload: got %+v", got.ExecutionPolicy)
		}
		if err := e.advance(ctx, got); err != nil {
			t.Fatalf("advance: %v", err)
		}

		select {
		case policy := <-received:
			if policy.MaxPrivilege != "user" {
				t.Fatalf("dispatch received MaxPrivilege = %q, want user", policy.MaxPrivilege)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for dispatch to be called")
		}
	})
}

type fakeVerificationReader struct {
	records []verification.Record
	err     error
}

func (f fakeVerificationReader) CurrentApprovedForRun(context.Context, string) ([]verification.Record, error) {
	return f.records, f.err
}

func TestBridgeVerifiedDetections_HappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.WithVerification(fakeVerificationReader{records: []verification.Record{
			{ExpectationID: "exp-1", RunID: "run-1", Domain: "endpoint", Result: verification.ResultDetected},
		}})
		ctx := context.Background()

		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "sim", Type: StepTypeNotify},
			{ID: "wait_detect", Type: StepTypeWaitForDetection, DependsOn: []string{"sim"},
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{ExecutionStepID: "sim"}}},
		})
		// "sim" step completed and produced a bas_run_id.
		simSE := &StepExecution{ExecutionID: ex.ID, StepID: "sim", StepType: StepTypeNotify,
			Status: StepCompleted, Result: map[string]any{"bas_run_id": "run-1"}}
		if err := store.UpsertStepExecution(ctx, simSE); err != nil {
			t.Fatalf("UpsertStepExecution sim: %v", err)
		}
		waitSE := &StepExecution{ExecutionID: ex.ID, StepID: "wait_detect", StepType: StepTypeWaitForDetection, Status: StepWaiting}
		if err := store.UpsertStepExecution(ctx, waitSE); err != nil {
			t.Fatalf("UpsertStepExecution wait_detect: %v", err)
		}

		e.RegisterBuiltinTriggers()
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}

		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "wait_detect")
		if got.Status != StepCompleted {
			t.Fatalf("wait_detect status = %q, want completed", got.Status)
		}

		evs, err := store.ListEvidence(ctx, ex.ID)
		if err != nil {
			t.Fatalf("ListEvidence: %v", err)
		}
		found := false
		for _, ev := range evs {
			if ev.EvidenceType == "edr_detected" {
				found = true
				if ev.Payload["expectation_id"] != "exp-1" {
					t.Errorf("evidence payload expectation_id = %v, want exp-1", ev.Payload["expectation_id"])
				}
			}
		}
		if !found {
			t.Fatal("no edr_detected evidence was appended")
		}
	})
}

func TestBridgeVerifiedDetections_NotDetectedKeepsWaiting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.WithVerification(fakeVerificationReader{records: []verification.Record{
			{ExpectationID: "exp-1", RunID: "run-1", Domain: "endpoint", Result: verification.ResultNotDetected},
		}})
		ctx := context.Background()

		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "sim", Type: StepTypeNotify},
			{ID: "wait_detect", Type: StepTypeWaitForDetection, DependsOn: []string{"sim"},
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{ExecutionStepID: "sim"}}},
		})
		simSE := &StepExecution{ExecutionID: ex.ID, StepID: "sim", StepType: StepTypeNotify,
			Status: StepCompleted, Result: map[string]any{"bas_run_id": "run-1"}}
		_ = store.UpsertStepExecution(ctx, simSE)
		waitSE := &StepExecution{ExecutionID: ex.ID, StepID: "wait_detect", StepType: StepTypeWaitForDetection, Status: StepWaiting}
		_ = store.UpsertStepExecution(ctx, waitSE)

		e.RegisterBuiltinTriggers()
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}

		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "wait_detect")
		if got.Status != StepWaiting {
			t.Fatalf("wait_detect status = %q, want still waiting (NotDetected produces no evidence)", got.Status)
		}
	})
}

func TestBridgeVerifiedDetections_MissingPlanStepFailsVisibly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.WithVerification(fakeVerificationReader{})
		ctx := context.Background()

		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "wait_detect", Type: StepTypeWaitForDetection,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{ExecutionStepID: "typo-does-not-exist"}}},
		})
		waitSE := &StepExecution{ExecutionID: ex.ID, StepID: "wait_detect", StepType: StepTypeWaitForDetection, Status: StepWaiting}
		_ = store.UpsertStepExecution(ctx, waitSE)

		e.RegisterBuiltinTriggers()
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}

		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "wait_detect")
		if got.Status != StepFailed {
			t.Fatalf("wait_detect status = %q, want failed", got.Status)
		}
		if !strings.Contains(got.Error, "typo-does-not-exist") {
			t.Errorf("error = %q, want it to mention the bad execution_step_id", got.Error)
		}
	})
}

func TestBridgeVerifiedDetections_CompletedStepNoRunIDFailsVisibly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.WithVerification(fakeVerificationReader{})
		ctx := context.Background()

		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "approve", Type: StepTypeApproval},
			{ID: "wait_detect", Type: StepTypeWaitForDetection, DependsOn: []string{"approve"},
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{ExecutionStepID: "approve"}}},
		})
		// "approve" completed but is not an agent_task — no bas_run_id in its Result.
		approveSE := &StepExecution{ExecutionID: ex.ID, StepID: "approve", StepType: StepTypeApproval,
			Status: StepCompleted, Result: map[string]any{"approver": "manager"}}
		_ = store.UpsertStepExecution(ctx, approveSE)
		waitSE := &StepExecution{ExecutionID: ex.ID, StepID: "wait_detect", StepType: StepTypeWaitForDetection, Status: StepWaiting}
		_ = store.UpsertStepExecution(ctx, waitSE)

		e.RegisterBuiltinTriggers()
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}

		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "wait_detect")
		if got.Status != StepFailed {
			t.Fatalf("wait_detect status = %q, want failed", got.Status)
		}
	})
}

func TestBridgeVerifiedDetections_EmptyExecutionStepIDUnchangedBehavior(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.WithVerification(fakeVerificationReader{records: []verification.Record{
			{ExpectationID: "exp-1", RunID: "run-1", Domain: "endpoint", Result: verification.ResultDetected},
		}})
		ctx := context.Background()

		// ExecutionStepID deliberately unset (builtin-bec's regression shape).
		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "wait_detect", Type: StepTypeWaitForDetection,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{}}},
		})
		waitSE := &StepExecution{ExecutionID: ex.ID, StepID: "wait_detect", StepType: StepTypeWaitForDetection, Status: StepWaiting}
		_ = store.UpsertStepExecution(ctx, waitSE)

		e.RegisterBuiltinTriggers()
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}

		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "wait_detect")
		if got.Status != StepWaiting {
			t.Fatalf("wait_detect status = %q, want still waiting (no bridge, no external evidence posted)", got.Status)
		}
		evs, _ := store.ListEvidence(ctx, ex.ID)
		if len(evs) != 0 {
			t.Fatalf("evidence count = %d, want 0 — bridge must not run when ExecutionStepID is empty", len(evs))
		}
	})
}

func TestBridgeVerifiedDetections_NilVerificationReaderUnchangedBehavior(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool) // no WithVerification call
		ctx := context.Background()

		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "sim", Type: StepTypeNotify},
			{ID: "wait_detect", Type: StepTypeWaitForDetection, DependsOn: []string{"sim"},
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{ExecutionStepID: "sim"}}},
		})
		simSE := &StepExecution{ExecutionID: ex.ID, StepID: "sim", StepType: StepTypeNotify,
			Status: StepCompleted, Result: map[string]any{"bas_run_id": "run-1"}}
		_ = store.UpsertStepExecution(ctx, simSE)
		waitSE := &StepExecution{ExecutionID: ex.ID, StepID: "wait_detect", StepType: StepTypeWaitForDetection, Status: StepWaiting}
		_ = store.UpsertStepExecution(ctx, waitSE)

		e.RegisterBuiltinTriggers()
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}

		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "wait_detect")
		if got.Status != StepWaiting {
			t.Fatalf("wait_detect status = %q, want still waiting — nil verification reader must not panic or fire", got.Status)
		}
	})
}

func TestBridgeVerifiedDetections_NoDuplicateEvidenceAcrossTicks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		reader := &mutableVerificationReader{records: []verification.Record{
			{ExpectationID: "exp-1", RunID: "run-1", Domain: "endpoint", Result: verification.ResultDetected},
		}}
		e.WithVerification(reader)
		ctx := context.Background()

		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "sim", Type: StepTypeNotify},
			{ID: "wait_detect", Type: StepTypeWaitForDetection, DependsOn: []string{"sim"},
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{ExecutionStepID: "sim", MinCount: 2}}},
		})
		simSE := &StepExecution{ExecutionID: ex.ID, StepID: "sim", StepType: StepTypeNotify,
			Status: StepCompleted, Result: map[string]any{"bas_run_id": "run-1"}}
		_ = store.UpsertStepExecution(ctx, simSE)
		waitSE := &StepExecution{ExecutionID: ex.ID, StepID: "wait_detect", StepType: StepTypeWaitForDetection, Status: StepWaiting}
		_ = store.UpsertStepExecution(ctx, waitSE)

		e.RegisterBuiltinTriggers()
		if err := e.advance(ctx, ex); err != nil { // tick 1: exp-1 detected
			t.Fatalf("advance 1: %v", err)
		}
		// tick 2: exp-1 unchanged (must not duplicate), exp-2 newly detected.
		reader.records = append(reader.records, verification.Record{
			ExpectationID: "exp-2", RunID: "run-1", Domain: "endpoint", Result: verification.ResultDetected,
		})
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance 2: %v", err)
		}

		evs, err := store.ListEvidence(ctx, ex.ID)
		if err != nil {
			t.Fatalf("ListEvidence: %v", err)
		}
		bridged := 0
		seen := map[string]bool{}
		for _, ev := range evs {
			if ev.EvidenceType != "edr_detected" {
				continue
			}
			bridged++
			if id, _ := ev.Payload["expectation_id"].(string); id != "" {
				if seen[id] {
					t.Fatalf("duplicate evidence for expectation_id %q", id)
				}
				seen[id] = true
			}
		}
		if bridged != 2 {
			t.Fatalf("bridged evidence count = %d, want 2 (one per expectation, no duplicates)", bridged)
		}
	})
}

type mutableVerificationReader struct {
	records []verification.Record
}

func (m *mutableVerificationReader) CurrentApprovedForRun(context.Context, string) ([]verification.Record, error) {
	return m.records, nil
}

func TestBridgeVerifiedDetections_ReferencedStepNotYetCompletedKeepsWaiting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.WithVerification(fakeVerificationReader{})
		ctx := context.Background()

		// "sim" is a real plan step but has not been dispatched/completed yet
		// (still StepPending, as seedRunningExecution leaves an un-started
		// dependency) — this must be treated as "not ready", not an error.
		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "sim", Type: StepTypeNotify},
			{ID: "wait_detect", Type: StepTypeWaitForDetection, DependsOn: []string{"sim"},
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{ExecutionStepID: "sim"}}},
		})
		// wait_detect is forced into StepWaiting directly (bypassing the
		// normal DependsOn gate) purely to exercise the trigger in
		// isolation; "sim" is deliberately left at its seeded StepPending
		// status with no Result.
		waitSE := &StepExecution{ExecutionID: ex.ID, StepID: "wait_detect", StepType: StepTypeWaitForDetection, Status: StepWaiting}
		_ = store.UpsertStepExecution(ctx, waitSE)

		e.RegisterBuiltinTriggers()
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}

		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "wait_detect")
		if got.Status != StepWaiting {
			t.Fatalf("wait_detect status = %q, want still waiting (referenced step not completed yet is not an error)", got.Status)
		}
	})
}
