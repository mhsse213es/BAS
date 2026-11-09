package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

// registerTarget stores a target whose fixture-selecting scenario IDs are already allowed.
func registerTarget(t *testing.T, pool *pgxpool.Pool, id, env, ref string, enabled bool) {
	t.Helper()
	err := db.CreateAPIBASTarget(context.Background(), pool, db.APIBASTarget{
		ID: id, Name: id, BaseURL: "http://127.0.0.1:8099", Environment: env,
		AllowedHosts: []string{"127.0.0.1:8099"}, AllowedScenarios: []string{"API-BAS-AUTHZ-001", "API-BAS-AUTHZ-002"},
		CredentialRefs: map[string]string{"apibas/lab/customer-a": ref}, Enabled: enabled, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatalf("register target %s: %v", id, err)
	}
}

func req(key, target, behaviour string, scenarios ...string) TargetRequest {
	if len(scenarios) == 0 {
		scenarios = []string{"API-BAS-AUTHZ-001"}
	}
	return TargetRequest{Key: key, RequestedBy: "alice", TargetID: target, Fixture: behaviour, ScenarioIDs: scenarios}
}

func TestSubmitForTargetEnforcesRegisteredScope(t *testing.T) {
	skipShort(t)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		svc, _, ref := setup(t, pool, Config{})
		ctx := context.Background()
		registerTarget(t, pool, "lab-one", "lab", ref, true)
		registerTarget(t, pool, "stg-one", "staging", ref, true)
		registerTarget(t, pool, "prod-one", "production", ref, true)
		registerTarget(t, pool, "off-one", "lab", ref, false)

		if _, created, err := svc.SubmitForTarget(ctx, req("scope-key-0001", "lab-one", "complete")); err != nil || !created {
			t.Fatalf("lab target: created=%v err=%v", created, err)
		}
		if _, _, err := svc.SubmitForTarget(ctx, req("scope-key-0002", "stg-one", "complete")); err != nil {
			t.Fatalf("staging target: %v", err)
		}
		if _, _, err := svc.SubmitForTarget(ctx, req("scope-key-0003", "prod-one", "complete")); !errors.Is(err, ErrEnvironmentNotPermitted) {
			t.Fatalf("production target: err = %v, want ErrEnvironmentNotPermitted", err)
		}
		if _, _, err := svc.SubmitForTarget(ctx, req("scope-key-0004", "off-one", "complete")); !errors.Is(err, ErrTargetDisabled) {
			t.Fatalf("disabled target: err = %v, want ErrTargetDisabled", err)
		}
		if _, _, err := svc.SubmitForTarget(ctx, req("scope-key-0005", "no-such", "complete")); !errors.Is(err, db.ErrAPIBASTargetNotFound) {
			t.Fatalf("unknown target: err = %v, want ErrAPIBASTargetNotFound", err)
		}
		if _, _, err := svc.SubmitForTarget(ctx, req("scope-key-0006", "stg-one", "complete", "API-BAS-DATA-102")); !errors.Is(err, ErrScopeViolation) {
			t.Fatalf("scenario outside scope: err = %v, want ErrScopeViolation", err)
		}
	})
}

// A target whose base URL host is not among its registered hosts is refused, even though the target itself is registered.
func TestSubmitForTargetRefusesHostOutsideScope(t *testing.T) {
	skipShort(t)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		svc, _, ref := setup(t, pool, Config{})
		err := db.CreateAPIBASTarget(context.Background(), pool, db.APIBASTarget{
			ID: "drift-one", Name: "drift", BaseURL: "http://10.9.9.9:8099", Environment: "lab",
			AllowedHosts: []string{"127.0.0.1:8099"}, AllowedScenarios: []string{"API-BAS-AUTHZ-001"},
			CredentialRefs: map[string]string{"apibas/lab/customer-a": ref}, Enabled: true, CreatedBy: "admin",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := svc.SubmitForTarget(context.Background(), req("host-key-00001", "drift-one", "complete")); !errors.Is(err, ErrScopeViolation) {
			t.Fatalf("err = %v, want ErrScopeViolation", err)
		}
	})
}

func TestOnlyOneActiveJobPerTarget(t *testing.T) {
	skipShort(t)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		svc, _, ref := setup(t, pool, Config{})
		ctx := context.Background()
		registerTarget(t, pool, "busy-one", "lab", ref, true)

		first, _, err := svc.SubmitForTarget(ctx, req("busy-key-00001", "busy-one", "complete"))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := svc.SubmitForTarget(ctx, req("busy-key-00002", "busy-one", "complete")); !errors.Is(err, db.ErrAPIBASTargetBusy) {
			t.Fatalf("second active job: err = %v, want ErrAPIBASTargetBusy", err)
		}
		// The same key is idempotent even while the target is busy.
		again, created, err := svc.SubmitForTarget(ctx, req("busy-key-00001", "busy-one", "complete"))
		if err != nil || created || again.ID != first.ID {
			t.Fatalf("repeat key: id=%s created=%v err=%v; want the same job", again.ID, created, err)
		}
		// Once the first job finishes, the target is free again.
		if _, err := svc.Dispatch(ctx, first.ID); err != nil {
			t.Fatal(err)
		}
		if _, _, err := svc.SubmitForTarget(ctx, req("busy-key-00003", "busy-one", "complete")); err != nil {
			t.Fatalf("after completion: %v", err)
		}
	})
}

func TestCancelStopsARunningJob(t *testing.T) {
	skipShort(t)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		svc, _, ref := setup(t, pool, Config{Timeout: time.Minute})
		registerTarget(t, pool, "cancel-tgt", "lab", ref, true)
		job, _, err := svc.SubmitForTarget(context.Background(), req("cancel-key-0002", "cancel-tgt", "hang"))
		if err != nil {
			t.Fatal(err)
		}
		if svc.Cancel(job.ID) {
			t.Fatal("Cancel reported a job that is not running")
		}
		done := make(chan error, 1)
		go func() { _, err := svc.Dispatch(context.Background(), job.ID); done <- err }()
		deadline := time.Now().Add(10 * time.Second)
		for !svc.Cancel(job.ID) {
			if time.Now().After(deadline) {
				t.Fatal("job never became cancellable")
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		got, reps := finalState(t, pool, job.ID)
		if got.Status != "cancelled" || len(reps) != 0 {
			t.Fatalf("status=%s reports=%d; want cancelled with no reports", got.Status, len(reps))
		}
	})
}

func TestBindingChangesWithAnyMaterialField(t *testing.T) {
	base := Binding("t1", "staging", "fx", []string{"B", "A"}, []string{"h:1"})
	if base != Binding("t1", "staging", "fx", []string{"A", "B"}, []string{"h:1"}) {
		t.Fatal("scenario order changed the binding")
	}
	for name, other := range map[string]string{
		"target":      Binding("t2", "staging", "fx", []string{"A", "B"}, []string{"h:1"}),
		"environment": Binding("t1", "production", "fx", []string{"A", "B"}, []string{"h:1"}),
		"fixture":     Binding("t1", "staging", "fy", []string{"A", "B"}, []string{"h:1"}),
		"scenarios":   Binding("t1", "staging", "fx", []string{"A", "B", "C"}, []string{"h:1"}),
		"hosts":       Binding("t1", "staging", "fx", []string{"A", "B"}, []string{"h:1", "h:2"}),
	} {
		if other == base {
			t.Errorf("changing %s did not change the binding", name)
		}
	}
}

func TestCheckApprovalRules(t *testing.T) {
	bind := Binding("t1", "production", "fx", []string{"A"}, []string{"h:1"})
	ok := db.APIBASApproval{BindingHash: bind, TargetID: "t1", RequestedBy: "alice", ApprovedBy: "bob"}
	if err := CheckApproval(ok, "alice", "t1", bind); err != nil {
		t.Fatalf("valid approval refused: %v", err)
	}
	cases := map[string]struct {
		a         db.APIBASApproval
		requester string
		target    string
		bind      string
	}{
		"not approved":        {db.APIBASApproval{BindingHash: bind, TargetID: "t1", RequestedBy: "alice"}, "alice", "t1", bind},
		"self approved":       {db.APIBASApproval{BindingHash: bind, TargetID: "t1", RequestedBy: "alice", ApprovedBy: "alice"}, "alice", "t1", bind},
		"other requester":     {ok, "mallory", "t1", bind},
		"other target":        {ok, "alice", "t2", bind},
		"configuration moved": {ok, "alice", "t1", Binding("t1", "production", "fx", []string{"A", "B"}, []string{"h:1"})},
	}
	for name, c := range cases {
		if err := CheckApproval(c.a, c.requester, c.target, c.bind); !errors.Is(err, ErrApprovalInvalid) {
			t.Errorf("%s: err = %v, want ErrApprovalInvalid", name, err)
		}
	}
}

// The store itself refuses self-approval and a second approval, whatever the caller checks.
func TestApprovalStoreRules(t *testing.T) {
	skipShort(t)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		setup(t, pool, Config{})
		ctx := context.Background()
		id, err := db.CreateAPIBASApproval(ctx, pool, db.APIBASApproval{BindingHash: "h", TargetID: "t1", RequestedBy: "alice"})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.ApproveAPIBASApproval(ctx, pool, id, "alice"); err == nil {
			t.Fatal("the requester approved their own request")
		}
		if err := db.ApproveAPIBASApproval(ctx, pool, id, "bob"); err != nil {
			t.Fatalf("a different user could not approve: %v", err)
		}
		if err := db.ApproveAPIBASApproval(ctx, pool, id, "carol"); err == nil {
			t.Fatal("an approved request was approved a second time")
		}
		got, err := db.GetAPIBASApproval(ctx, pool, id)
		if err != nil || got.ApprovedBy != "bob" {
			t.Fatalf("approval = %+v, err = %v; want approved by bob", got, err)
		}
	})
}
