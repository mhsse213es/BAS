package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/dbsim"
)

func dbsimJob(id, target, agent string) dbsim.RunJob {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return dbsim.RunJob{
		ID: id, Kind: dbsim.JobKindRun, TargetID: target, AgentID: agent, Mode: dbsim.ModeLab,
		ScenarioIDs: []string{"dbsim-db01-auth-policy"}, Status: dbsim.JobPending, CreatedBy: "u1", LabConfirmation: target,
		CreatedAt: now, Deadline: dbsim.DeadlineFor(now, 1),
		Plan: []dbsim.PlannedStep{{ScenarioID: "dbsim-db01-auth-policy", Index: 0, Spec: dbsim.DBProbeSpec{
			ProbeID: "auth_check", TargetID: target, RunID: id, Marker: "bas-dbsim:abc", CredentialRef: "dbcred:lab"}}},
	}
}

// Needs the Docker-backed test database (TestMain of this package): written and
// compiled here, run on a Docker-capable host.
func TestDBSimJobStore(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		for i := 0; i < 2; i++ { // idempotent
			if err := db.EnsureDBSimJobSchema(ctx, pool); err != nil {
				t.Fatal(err)
			}
		}
		st := db.DBSimJobStore{Pool: pool}

		a := dbsimJob("run-a", "t1", "0123456789abcdef")
		if err := st.Create(ctx, a, dbsimAudit("job_create")); err != nil {
			t.Fatal(err)
		}
		got, err := st.Get(ctx, "run-a")
		if err != nil || got.Status != dbsim.JobPending || got.TargetID != "t1" || got.LabConfirmation != "t1" ||
			len(got.Plan) != 1 || got.Plan[0].Spec.Marker != "bas-dbsim:abc" || len(got.ScenarioIDs) != 1 || got.Kind != dbsim.JobKindRun {
			t.Fatalf("get %+v %v", got, err)
		}
		if _, err := st.Get(ctx, "nope"); !errors.Is(err, dbsim.ErrJobNotFound) {
			t.Fatalf("missing: %v", err)
		}

		// Partial unique indexes: same target, then same agent, are busy.
		if err := st.Create(ctx, dbsimJob("run-b", "t1", "fedcba9876543210"), dbsimAudit("job_create")); !errors.Is(err, dbsim.ErrJobBusy) {
			t.Fatalf("same target: %v", err)
		}
		if err := st.Create(ctx, dbsimJob("run-c", "t2", "0123456789abcdef"), dbsimAudit("job_create")); !errors.Is(err, dbsim.ErrJobBusy) {
			t.Fatalf("same agent: %v", err)
		}
		if ok, err := st.ActiveForTarget(ctx, "t1"); err != nil || !ok {
			t.Fatalf("active target %v %v", ok, err)
		}
		if ok, err := st.ActiveForAgent(ctx, "0123456789abcdef"); err != nil || !ok {
			t.Fatalf("active agent %v %v", ok, err)
		}
		if ok, _ := st.ActiveForTarget(ctx, "t9"); ok {
			t.Fatal("unrelated target must be idle")
		}

		// A duplicate id (primary key) is a plain error, never "busy".
		dup := dbsimJob("run-a", "t7", "3333333333333333")
		if err := st.Create(ctx, dup, dbsimAudit("job_create")); err == nil || errors.Is(err, dbsim.ErrJobBusy) {
			t.Fatalf("duplicate id must fail and not be ErrJobBusy: %v", err)
		}

		// A failed audit write rolls the whole create back.
		if err := st.Create(ctx, dbsimJob("run-d", "t3", "1111111111111111"), failingAudit()); err == nil {
			t.Fatal("create with a failing audit row must fail")
		}
		if _, err := st.Get(ctx, "run-d"); !errors.Is(err, dbsim.ErrJobNotFound) {
			t.Fatalf("rolled back: %v", err)
		}

		// Guarded transition: wrong `from` changes nothing and reports false.
		moved, err := st.Transition(ctx, "run-a", []dbsim.JobStatus{dbsim.JobRunning}, dbsim.JobCompleted, "", dbsimAudit("t"))
		if err != nil || moved {
			t.Fatalf("wrong from: %v %v", moved, err)
		}
		moved, err = st.Transition(ctx, "run-a", []dbsim.JobStatus{dbsim.JobPending}, dbsim.JobRunning, "", dbsimAudit("t"))
		if err != nil || !moved {
			t.Fatalf("pending->running: %v %v", moved, err)
		}
		if got, _ = st.Get(ctx, "run-a"); got.Status != dbsim.JobRunning || got.StartedAt.IsZero() {
			t.Fatalf("running %+v", got)
		}
		// A failed audit write rolls the transition back.
		if _, err := st.Transition(ctx, "run-a", []dbsim.JobStatus{dbsim.JobRunning}, dbsim.JobCompleted, "", failingAudit()); err == nil {
			t.Fatal("transition with a failing audit row must fail")
		}
		if got, _ = st.Get(ctx, "run-a"); got.Status != dbsim.JobRunning {
			t.Fatalf("not rolled back: %+v", got)
		}
		// A transition the state machine forbids (terminal -> running) is refused even if `from` lists it.
		moved, err = st.Transition(ctx, "run-a", []dbsim.JobStatus{dbsim.JobRunning}, dbsim.JobPending, "", dbsimAudit("t"))
		if err == nil && moved {
			t.Fatal("running->pending must never apply")
		}

		// Expired: only active jobs past their deadline.
		old := dbsimJob("run-old", "t5", "2222222222222222")
		old.CreatedAt = time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
		old.Deadline = old.CreatedAt.Add(time.Minute)
		if err := st.Create(ctx, old, dbsimAudit("job_create")); err != nil {
			t.Fatal(err)
		}
		exp, err := st.Expired(ctx, time.Now().UTC())
		if err != nil || len(exp) != 1 || exp[0].ID != "run-old" {
			t.Fatalf("expired %+v %v", exp, err)
		}

		// A terminal job frees its target and agent.
		if ok, err := st.Transition(ctx, "run-a", []dbsim.JobStatus{dbsim.JobRunning}, dbsim.JobCompleted, "", dbsimAudit("t")); err != nil || !ok {
			t.Fatalf("complete %v %v", ok, err)
		}
		if err := st.Create(ctx, dbsimJob("run-e", "t1", "0123456789abcdef"), dbsimAudit("job_create")); err != nil {
			t.Fatalf("target and agent must be free after completion: %v", err)
		}
	})
}
