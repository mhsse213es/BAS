package exercise

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

// seedExecution creates a plan + execution and returns the execution ID, for
// tests that write child rows (step executions, events, evidence) constrained
// by the execution_id foreign key to exercise_executions(id).
func seedExecution(t *testing.T, store *Store) string {
	t.Helper()
	ctx := context.Background()
	p := &Plan{Name: "seed", Steps: []PlanStep{{ID: "a", Type: StepTypeNotify}}}
	if err := store.CreatePlan(ctx, p); err != nil {
		t.Fatalf("seedExecution CreatePlan: %v", err)
	}
	ex := &Execution{PlanID: p.ID, Name: "seed", Status: ExecRunning}
	if err := store.CreateExecution(ctx, ex); err != nil {
		t.Fatalf("seedExecution CreateExecution: %v", err)
	}
	return ex.ID
}

func TestPlan_CRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		p := &Plan{Name: "Phish Drill", Description: "q3",
			Steps:     []PlanStep{{ID: "a", Type: StepTypeNotify}},
			Variables: []VarDef{{Name: "X", Type: VarTypeString}}}
		if err := store.CreatePlan(ctx, p); err != nil {
			t.Fatalf("CreatePlan: %v", err)
		}
		if p.ID == "" || p.CreatedAt.IsZero() {
			t.Fatal("CreatePlan must set ID and CreatedAt")
		}

		got, err := store.GetPlan(ctx, p.ID)
		if err != nil {
			t.Fatalf("GetPlan: %v", err)
		}
		if got.Name != "Phish Drill" || len(got.Steps) != 1 || got.Steps[0].ID != "a" || len(got.Variables) != 1 {
			t.Fatalf("GetPlan round-trip mismatch: %+v", got)
		}

		p.Name = "Renamed"
		if err := store.UpdatePlan(ctx, p); err != nil {
			t.Fatalf("UpdatePlan: %v", err)
		}
		got, _ = store.GetPlan(ctx, p.ID)
		if got.Name != "Renamed" {
			t.Fatalf("UpdatePlan not applied: %q", got.Name)
		}

		list, err := store.ListPlans(ctx)
		if err != nil || len(list) != 1 {
			t.Fatalf("ListPlans = %v (err %v), want 1", list, err)
		}

		if err := store.DeletePlan(ctx, p.ID); err != nil {
			t.Fatalf("DeletePlan: %v", err)
		}
		if _, err := store.GetPlan(ctx, p.ID); err == nil {
			t.Fatal("GetPlan after delete should error")
		}
	})
}

func TestExecution_LifecycleAndStatusTimestamps(t *testing.T) {
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
		ex := &Execution{PlanID: p.ID, Name: "Run", Status: ExecDraft,
			InitiatedBy: "alice", Targets: []Target{{ID: "t1", Name: "Bob", Email: "b@x.io"}},
			Variables: map[string]string{"K": "V"}}
		if err := store.CreateExecution(ctx, ex); err != nil {
			t.Fatalf("CreateExecution: %v", err)
		}
		if ex.ID == "" {
			t.Fatal("CreateExecution must set ID")
		}

		got, err := store.GetExecution(ctx, ex.ID)
		if err != nil {
			t.Fatalf("GetExecution: %v", err)
		}
		if len(got.Targets) != 1 || got.Targets[0].Email != "b@x.io" || got.Variables["K"] != "V" {
			t.Fatalf("execution JSON round-trip mismatch: %+v", got)
		}
		if got.PlanVersion != 1 {
			t.Fatalf("PlanVersion default = %d, want 1", got.PlanVersion)
		}

		if err := store.UpdateExecutionStatus(ctx, ex.ID, ExecRunning); err != nil {
			t.Fatalf("UpdateExecutionStatus running: %v", err)
		}
		got, _ = store.GetExecution(ctx, ex.ID)
		if got.Status != ExecRunning || got.StartedAt == nil {
			t.Fatalf("running status must set started_at: %+v", got)
		}

		if err := store.UpdateExecutionStatus(ctx, ex.ID, ExecCompleted); err != nil {
			t.Fatalf("UpdateExecutionStatus completed: %v", err)
		}
		got, _ = store.GetExecution(ctx, ex.ID)
		if got.Status != ExecCompleted || got.CompletedAt == nil {
			t.Fatalf("completed status must set completed_at: %+v", got)
		}
	})
}

func TestListRunningExecutions_OnlyRunningAndPaused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()
		p := &Plan{Name: "P", Steps: []PlanStep{{ID: "a", Type: StepTypeNotify}}}
		_ = store.CreatePlan(ctx, p)

		mk := func(status ExecStatus) {
			ex := &Execution{PlanID: p.ID, Name: string(status), Status: status}
			if err := store.CreateExecution(ctx, ex); err != nil {
				t.Fatalf("CreateExecution: %v", err)
			}
		}
		mk(ExecRunning)
		mk(ExecPaused)
		mk(ExecDraft)
		mk(ExecCompleted)

		running, err := store.ListRunningExecutions(ctx)
		if err != nil {
			t.Fatalf("ListRunningExecutions: %v", err)
		}
		if len(running) != 2 {
			t.Fatalf("expected 2 running/paused, got %d", len(running))
		}
	})
}

// TestListExecutions_StepsProgressAggregate pins the steps_total/steps_done
// aggregate the executions list surfaces so an operator can see live
// progress ("3/8 steps") instead of a bare "running" badge that never
// changes. done counts every terminal StepStatus (completed/failed/
// cancelled/skipped); pending and running/waiting steps don't count as done.
func TestListExecutions_StepsProgressAggregate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()
		execID := seedExecution(t, store)

		statuses := []StepStatus{StepCompleted, StepFailed, StepCancelled, StepSkipped, StepRunning, StepPending}
		for i, st := range statuses {
			se := &StepExecution{ExecutionID: execID, StepID: string(rune('a' + i)), StepType: StepTypeNotify, Status: StepPending}
			if err := store.UpsertStepExecution(ctx, se); err != nil {
				t.Fatalf("seed step %d: %v", i, err)
			}
			if st != StepPending {
				if err := store.SetStepStatus(ctx, execID, se.StepID, st, ""); err != nil {
					t.Fatalf("set step %d status: %v", i, err)
				}
			}
		}

		list, err := store.ListExecutions(ctx, 50)
		if err != nil {
			t.Fatalf("ListExecutions: %v", err)
		}
		var got *Execution
		for i := range list {
			if list[i].ID == execID {
				got = &list[i]
			}
		}
		if got == nil {
			t.Fatalf("seeded execution %s not in list", execID)
		}
		if got.StepsTotal != 6 {
			t.Errorf("StepsTotal = %d, want 6", got.StepsTotal)
		}
		if got.StepsDone != 4 {
			t.Errorf("StepsDone = %d, want 4 (completed+failed+cancelled+skipped)", got.StepsDone)
		}
	})
}

func TestTemplate_UpsertAndSeed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		tpl := &Template{ID: "tpl-1", Name: "Phishing", Version: 1, Category: "phishing",
			Steps: []PlanStep{{ID: "a", Type: StepTypeSendEmail}}}
		if err := store.UpsertTemplate(ctx, tpl); err != nil {
			t.Fatalf("UpsertTemplate insert: %v", err)
		}
		tpl.Name = "Phishing v2"
		if err := store.UpsertTemplate(ctx, tpl); err != nil {
			t.Fatalf("UpsertTemplate update: %v", err)
		}
		got, err := store.GetTemplate(ctx, "tpl-1")
		if err != nil || got.Name != "Phishing v2" {
			t.Fatalf("GetTemplate = %+v (err %v)", got, err)
		}

		// Metadata round-trips through Postgres, not just Go-side construction.
		tpl.Metadata = TemplateMetadata{
			SuccessCriteria:    "test criterion",
			ExpectedTechniques: []string{"T1055"},
		}
		if err := store.UpsertTemplate(ctx, tpl); err != nil {
			t.Fatalf("UpsertTemplate with metadata: %v", err)
		}
		gotMeta, err := store.GetTemplate(ctx, "tpl-1")
		if err != nil {
			t.Fatalf("GetTemplate after metadata upsert: %v", err)
		}
		if gotMeta.Metadata.SuccessCriteria != "test criterion" || len(gotMeta.Metadata.ExpectedTechniques) != 1 || gotMeta.Metadata.ExpectedTechniques[0] != "T1055" {
			t.Fatalf("Metadata did not round-trip: %+v", gotMeta.Metadata)
		}

		// SeedBuiltinTemplates is idempotent.
		if err := store.SeedBuiltinTemplates(ctx); err != nil {
			t.Fatalf("SeedBuiltinTemplates 1: %v", err)
		}
		if err := store.SeedBuiltinTemplates(ctx); err != nil {
			t.Fatalf("SeedBuiltinTemplates 2 (idempotent): %v", err)
		}
		list, err := store.ListTemplates(ctx)
		if err != nil || len(list) == 0 {
			t.Fatalf("ListTemplates = %v (err %v)", list, err)
		}
	})
}

func TestStepExecution_UpsertStatusResult(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()
		execID := seedExecution(t, store)

		se := &StepExecution{ExecutionID: execID, StepID: "a", StepType: StepTypeNotify, Status: StepPending}
		if err := store.UpsertStepExecution(ctx, se); err != nil {
			t.Fatalf("UpsertStepExecution: %v", err)
		}
		if se.ID == "" {
			t.Fatal("UpsertStepExecution must set ID")
		}
		if err := store.SetStepStatus(ctx, execID, "a", StepRunning, ""); err != nil {
			t.Fatalf("SetStepStatus running: %v", err)
		}
		if err := store.SetStepResult(ctx, execID, "a", map[string]any{"ok": true}); err != nil {
			t.Fatalf("SetStepResult: %v", err)
		}
		if err := store.SetStepStatus(ctx, execID, "a", StepCompleted, ""); err != nil {
			t.Fatalf("SetStepStatus completed: %v", err)
		}

		list, err := store.ListStepExecutions(ctx, execID)
		if err != nil || len(list) != 1 {
			t.Fatalf("ListStepExecutions = %v (err %v)", list, err)
		}
		if list[0].Status != StepCompleted || list[0].Result["ok"] != true {
			t.Fatalf("step exec state mismatch: %+v", list[0])
		}
		if list[0].StartedAt == nil || list[0].CompletedAt == nil {
			t.Fatalf("running then completed must set both timestamps: %+v", list[0])
		}

		byStep, err := store.GetStepExecByStepID(ctx, execID, "a")
		if err != nil || byStep.ID != se.ID {
			t.Fatalf("GetStepExecByStepID = %+v (err %v)", byStep, err)
		}
	})
}

func TestEvents_RecordAndList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()
		execID := seedExecution(t, store)
		if err := store.RecordEvent(ctx, execID, "a", "started", "system", map[string]any{"n": 1}); err != nil {
			t.Fatalf("RecordEvent: %v", err)
		}
		events, err := store.ListEvents(ctx, execID)
		if err != nil || len(events) != 1 {
			t.Fatalf("ListEvents = %v (err %v)", events, err)
		}
		if events[0]["event_type"] != "started" || events[0]["actor"] != "system" {
			t.Fatalf("event shape mismatch: %+v", events[0])
		}
	})
}

func TestTrackToken_Lifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()
		if err := store.InsertTrackToken(ctx, "tok1", "ex-t", "se1", "target1", "click", map[string]any{"x": "y"}); err != nil {
			t.Fatalf("InsertTrackToken: %v", err)
		}
		got, err := store.GetTrackToken(ctx, "tok1")
		if err != nil || got.TokenType != "click" || got.Payload["x"] != "y" {
			t.Fatalf("GetTrackToken = %+v (err %v)", got, err)
		}
		if err := store.RecordTokenUse(ctx, "tok1"); err != nil {
			t.Fatalf("RecordTokenUse: %v", err)
		}
		got, _ = store.GetTrackToken(ctx, "tok1")
		if got.UsedCount != 1 || got.UsedAt == nil {
			t.Fatalf("RecordTokenUse must increment count and set used_at: %+v", got)
		}
	})
}

func TestEvidenceCounting_TypesAndDuration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		chain := NewEvidenceChain(store)
		ctx := context.Background()
		execID := seedExecution(t, store)

		appendEv := func(evType string) {
			if _, err := chain.Append(ctx, execID, "se1", evType, "system", "test", map[string]any{"t": evType}); err != nil {
				t.Fatalf("Append %s: %v", evType, err)
			}
		}
		appendEv("email_sent")
		appendEv("email_sent")
		appendEv("link_clicked")
		appendEv("edr_detected")

		counts, err := store.CountEvidenceByType(ctx, execID)
		if err != nil {
			t.Fatalf("CountEvidenceByType: %v", err)
		}
		if counts["email_sent"] != 2 || counts["link_clicked"] != 1 {
			t.Fatalf("CountEvidenceByType = %v", counts)
		}

		// CountEvidenceForExec with explicit types.
		n, err := store.CountEvidenceForExec(ctx, execID, []string{"edr_detected"})
		if err != nil || n != 1 {
			t.Fatalf("CountEvidenceForExec explicit = %d (err %v), want 1", n, err)
		}
		// Empty types defaults to edr_detected+siem_alerted.
		n, err = store.CountEvidenceForExec(ctx, execID, nil)
		if err != nil || n != 1 {
			t.Fatalf("CountEvidenceForExec default = %d (err %v), want 1", n, err)
		}

		// hasEvidenceType by step_execution_id.
		has, err := store.hasEvidenceType(ctx, "se1", "link_clicked")
		if err != nil || !has {
			t.Fatalf("hasEvidenceType link_clicked = %v (err %v)", has, err)
		}
		has, _ = store.hasEvidenceType(ctx, "se1", "never")
		if has {
			t.Fatal("hasEvidenceType for absent type should be false")
		}

		// SumDurationByType: from email_sent to edr_detected (>= 0 seconds, no error).
		if _, err := store.SumDurationByType(ctx, execID, "email_sent", "edr_detected"); err != nil {
			t.Fatalf("SumDurationByType: %v", err)
		}
	})
}

func TestWebhookCall_And_BASRunStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		if err := store.InsertWebhookCall(ctx, "hooktok", "ex-w", "se1", []byte(`{"a":1}`)); err != nil {
			t.Fatalf("InsertWebhookCall: %v", err)
		}
		n, err := store.WebhookCallCount(ctx, "hooktok")
		if err != nil || n != 1 {
			t.Fatalf("WebhookCallCount = %d (err %v), want 1", n, err)
		}

		// BASRunStatus not-found → ("", nil).
		status, err := store.BASRunStatus(ctx, "no-such-run")
		if err != nil || status != "" {
			t.Fatalf("BASRunStatus missing = (%q,%v), want (\"\",nil)", status, err)
		}
		// Seed agent + scenario_run (FK: scenario_runs.agent_id → agents.agent_id).
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-x')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		var runID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO scenario_runs (scenario_id, agent_id, status) VALUES ('s1','agent-x','completed') RETURNING id`,
		).Scan(&runID); err != nil {
			t.Fatalf("seed scenario_run: %v", err)
		}
		status, err = store.BASRunStatus(ctx, runID)
		if err != nil || status != "completed" {
			t.Fatalf("BASRunStatus found = (%q,%v), want (completed,nil)", status, err)
		}
	})
}

func TestStore_ClosedPool_ErrorsNotPanic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, sharedDB.Pool.Config().ConnString())
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	pool.Close()
	store := NewStore(pool)

	if _, err := store.ListPlans(ctx); err == nil {
		t.Error("ListPlans: want error on closed pool")
	}
	if _, err := store.GetExecution(ctx, "x"); err == nil {
		t.Error("GetExecution: want error on closed pool")
	}
	if _, err := store.ListRunningExecutions(ctx); err == nil {
		t.Error("ListRunningExecutions: want error on closed pool")
	}
	if _, err := store.ListStepExecutions(ctx, "x"); err == nil {
		t.Error("ListStepExecutions: want error on closed pool")
	}
	if _, err := store.CountEvidenceByType(ctx, "x"); err == nil {
		t.Error("CountEvidenceByType: want error on closed pool")
	}
}
