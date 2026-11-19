package jobs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/audspect/bas/internal/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

// approvalFor creates an approval bound to the production target's current scope, and approves it when approver is not empty.
func approvalFor(t *testing.T, pool *pgxpool.Pool, target, requester, approver string, scenarios ...string) string {
	t.Helper()
	ctx := context.Background()
	tg, err := db.GetAPIBASTarget(ctx, pool, target)
	if err != nil {
		t.Fatal(err)
	}
	bind := Binding(tg.ID, tg.Environment, "complete", scenarios, tg.AllowedHosts, tg.AllowedPaths)
	id, err := db.CreateAPIBASApproval(ctx, pool, db.APIBASApproval{BindingHash: bind, TargetID: target, RequestedBy: requester})
	if err != nil {
		t.Fatal(err)
	}
	if approver != "" {
		if err := db.ApproveAPIBASApproval(ctx, pool, id, approver); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

// With production switched on, every approval rule is enforced before a job is created, and no failed attempt spends the approval.
func TestProductionSubmitEnforcesApproval(t *testing.T) {
	skipShort(t)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		svc, _, ref := setup(t, pool, Config{AllowProduction: true})
		ctx := context.Background()
		registerTarget(t, pool, "wprod", "production", ref, true)
		submit := func(key, approval string, scenarios ...string) error {
			r := req(key, "wprod", "complete", scenarios...)
			r.ApprovalID = approval
			_, _, err := svc.SubmitForTarget(ctx, r)
			return err
		}
		if err := submit("wire-key-0001", ""); !errors.Is(err, ErrApprovalRequired) {
			t.Errorf("no approval: %v, want ErrApprovalRequired", err)
		}
		if err := submit("wire-key-0002", "00000000-0000-0000-0000-000000000000"); !errors.Is(err, ErrApprovalInvalid) {
			t.Errorf("unknown approval: %v, want ErrApprovalInvalid", err)
		}
		bad := map[string]string{
			"pending":         approvalFor(t, pool, "wprod", "alice", "", "API-BAS-AUTHZ-001"),
			"other requester": approvalFor(t, pool, "wprod", "mallory", "bob", "API-BAS-AUTHZ-001"),
			"other scenarios": approvalFor(t, pool, "wprod", "alice", "bob", "API-BAS-AUTHZ-001", "API-BAS-AUTHZ-002"),
		}
		rev := approvalFor(t, pool, "wprod", "alice", "bob", "API-BAS-AUTHZ-001")
		if err := db.RevokeAPIBASApproval(ctx, pool, rev, "bob", "no"); err != nil {
			t.Fatal(err)
		}
		bad["revoked"] = rev
		exp := approvalFor(t, pool, "wprod", "alice", "bob", "API-BAS-AUTHZ-001")
		if _, err := pool.Exec(ctx, `UPDATE apibas_approvals SET expires_at = NOW() - interval '1 second' WHERE id = $1::uuid`, exp); err != nil {
			t.Fatal(err)
		}
		bad["expired"] = exp
		i := 3
		for name, id := range bad {
			i++
			if err := submit(fmt.Sprintf("wire-key-%04d", i), id); !errors.Is(err, ErrApprovalInvalid) {
				t.Errorf("%s: %v, want ErrApprovalInvalid", name, err)
			}
		}
		// A valid approval passes every check. The jobs table still only accepts lab and staging, so the insert is refused there
		// and, because consumption shares the transaction, the approval is left unused.
		good := approvalFor(t, pool, "wprod", "alice", "bob", "API-BAS-AUTHZ-001")
		err := submit("wire-key-0100", good)
		if err == nil || errors.Is(err, ErrApprovalInvalid) || errors.Is(err, ErrApprovalRequired) || errors.Is(err, ErrEnvironmentNotPermitted) {
			t.Errorf("valid approval: err = %v, want the jobs-table environment constraint to refuse the insert", err)
		}
		a, _ := db.GetAPIBASApproval(ctx, pool, good)
		if a.ConsumedAt != nil {
			t.Error("approval was spent although no job was created")
		}
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM apibas_jobs WHERE job_key LIKE 'wire-key-%'`).Scan(&n)
		if n != 0 {
			t.Errorf("%d production jobs exist, want none", n)
		}
	})
}

// Production stays refused by default, whatever approval is offered.
func TestProductionRefusedByDefaultEvenWithApproval(t *testing.T) {
	skipShort(t)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		svc, _, ref := setup(t, pool, Config{})
		registerTarget(t, pool, "dprod", "production", ref, true)
		id := approvalFor(t, pool, "dprod", "alice", "bob", "API-BAS-AUTHZ-001")
		r := req("default-key-0001", "dprod", "complete")
		r.ApprovalID = id
		if _, _, err := svc.SubmitForTarget(context.Background(), r); !errors.Is(err, ErrEnvironmentNotPermitted) {
			t.Fatalf("err = %v, want ErrEnvironmentNotPermitted", err)
		}
	})
}

// Job creation and approval consumption are one transaction: the approval is spent exactly when a job exists, never twice.
func TestJobCreationConsumesApprovalAtomically(t *testing.T) {
	skipShort(t)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		setup(t, pool, Config{})
		ctx := context.Background()
		mkJob := func(key, target string) db.APIBASJob {
			return db.APIBASJob{JobKey: key, TargetID: target, RequestedBy: "alice", TargetBaseURL: "http://127.0.0.1:8099",
				Environment: "staging", Fixture: "complete", ScenarioIDs: []string{"API-BAS-AUTHZ-001"}, CredentialRefs: map[string]string{}}
		}
		newApproval := func() string {
			id, err := db.CreateAPIBASApproval(ctx, pool, db.APIBASApproval{BindingHash: "h", TargetID: "t", RequestedBy: "alice"})
			if err != nil {
				t.Fatal(err)
			}
			if err := db.ApproveAPIBASApproval(ctx, pool, id, "bob"); err != nil {
				t.Fatal(err)
			}
			return id
		}
		id := newApproval()
		job, created, err := db.CreateAPIBASJobExclusiveWithApproval(ctx, pool, mkJob("atomic-key-0001", "at-1"), id)
		if err != nil || !created {
			t.Fatalf("first: created=%v err=%v", created, err)
		}
		a, _ := db.GetAPIBASApproval(ctx, pool, id)
		if a.ConsumedAt == nil || a.ConsumedByJob != job.ID {
			t.Fatalf("approval consumed_by_job = %q, want %q", a.ConsumedByJob, job.ID)
		}
		// A second job cannot reuse it, and nothing is created.
		if _, _, err := db.CreateAPIBASJobExclusiveWithApproval(ctx, pool, mkJob("atomic-key-0002", "at-2"), id); !errors.Is(err, db.ErrAPIBASApprovalUnusable) {
			t.Errorf("reuse: %v, want ErrAPIBASApprovalUnusable", err)
		}
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM apibas_jobs WHERE job_key = 'atomic-key-0002'`).Scan(&n)
		if n != 0 {
			t.Error("a job was created although its approval was refused")
		}
		// Repeating the first key returns the existing job and needs no approval.
		again, created, err := db.CreateAPIBASJobExclusiveWithApproval(ctx, pool, mkJob("atomic-key-0001", "at-1"), id)
		if err != nil || created || again.ID != job.ID {
			t.Errorf("repeat: id=%s created=%v err=%v, want the first job and created=false", again.ID, created, err)
		}
		// Many jobs racing for one approval: exactly one is created.
		race := newApproval()
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, c, err := db.CreateAPIBASJobExclusiveWithApproval(ctx, pool, mkJob(fmt.Sprintf("race-key-%04d", i), fmt.Sprintf("race-%d", i)), race)
				if err == nil && c {
					wins.Add(1)
				}
			}(i)
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Errorf("%d jobs were created from one approval, want 1", wins.Load())
		}
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM apibas_jobs WHERE job_key LIKE 'race-key-%'`).Scan(&n)
		if n != 1 {
			t.Errorf("%d race jobs exist, want 1", n)
		}
		// An expired approval creates nothing.
		old := newApproval()
		_, _ = pool.Exec(ctx, `UPDATE apibas_approvals SET expires_at = NOW() - interval '1 second' WHERE id = $1::uuid`, old)
		if _, _, err := db.CreateAPIBASJobExclusiveWithApproval(ctx, pool, mkJob("atomic-key-0009", "at-9"), old); !errors.Is(err, db.ErrAPIBASApprovalUnusable) {
			t.Errorf("expired: %v", err)
		}
	})
}
