package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/injectionapproval"
)

// failAuditAction makes the database reject any audit record with this action, for the duration of one
// test. It is the way a test reaches the "audit write fails" path.
func failAuditAction(t *testing.T, pool *pgxpool.Pool, action string) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `CREATE OR REPLACE FUNCTION bas_test_fail_audit() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'audit unavailable'; END; $$ LANGUAGE plpgsql`)
	if err != nil {
		t.Fatalf("create failure function: %v", err)
	}
	_, err = pool.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER bas_test_fail_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW WHEN (NEW.action = '%s') EXECUTE FUNCTION bas_test_fail_audit()`, action))
	if err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS bas_test_fail_audit ON audit_logs`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS bas_test_fail_audit()`)
	})
}

// auditActions returns the cleanup audit actions for one approval, in order, with the execution id
// each one carries.
func auditActions(t *testing.T, pool *pgxpool.Pool, approvalID string) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT action || ':' || COALESCE(detail->>'executionId','') FROM audit_logs WHERE resource=$1 ORDER BY id`, approvalID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// A successful execution writes a committed started record and a committed finished record, both with
// the same execution id.
func TestCleanupExecution_DurableStartAndFinish(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, _, connID := cleanupFixture(t, pool)
		_, out := requestCleanup(t, router, connID, "admin-1")
		id := out["approvalId"].(string)
		approveAs(t, router, id, "admin-2")
		code, res := executeCleanup(t, router, id, "admin-2")
		if code != http.StatusOK {
			t.Fatalf("execute: %d %v", code, res)
		}
		execID := res["executionId"].(string)
		// The request record is written in the background, so only the two durable records are checked.
		var durable []string
		for _, a := range auditActions(t, pool, id) {
			if strings.HasPrefix(a, "pipeline.cleanup.started:") || strings.HasPrefix(a, "pipeline.cleanup.finished:") {
				durable = append(durable, a)
			}
		}
		want := []string{"pipeline.cleanup.started:" + execID, "pipeline.cleanup.finished:" + execID}
		if strings.Join(durable, "|") != strings.Join(want, "|") {
			t.Fatalf("durable audit = %v, want %v", durable, want)
		}
	})
}

// Only the user who approved may execute. Another administrator with cleanup permission is refused,
// nothing is deleted, and the approval is not spent.
func TestCleanupExecution_OnlyApproverMayExecute(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, es, connID := cleanupFixture(t, pool)
		_, out := requestCleanup(t, router, connID, "admin-1")
		id := out["approvalId"].(string)
		approveAs(t, router, id, "admin-2")
		if code, res := executeCleanup(t, router, id, "admin-3"); code != http.StatusForbidden {
			t.Fatalf("another admin executed: %d %v, want 403", code, res)
		}
		if got := strings.Join(es.remaining(), ","); !strings.Contains(got, "mine-1") {
			t.Fatalf("refused executor deleted records: %s", got)
		}
		store := db.KillChainStore{Pool: pool}
		if got := historyOf(t, store, id); got != "requested,approved" {
			t.Fatalf("refused executor spent the approval: %s", got)
		}
		if code, _ := executeCleanup(t, router, id, "admin-2"); code != http.StatusOK {
			t.Fatalf("approver execute after refusal: %d", code)
		}
	})
}

// Lab deployment: the requester approves their own request, and as the approver may execute it.
func TestCleanupExecution_LabSelfApprovedRequesterMayExecute(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, es, connID := cleanupFixture(t, pool)
		lab := approvalRouter(pool, injectionapproval.Lab, t)
		_, out := requestCleanup(t, lab, connID, "admin-1")
		id := out["approvalId"].(string)
		if code := approveAs(t, lab, id, "admin-1"); code != http.StatusOK {
			t.Fatalf("lab self-approval: %d", code)
		}
		if code, res := executeCleanup(t, lab, id, "admin-1"); code != http.StatusOK {
			t.Fatalf("lab requester/approver execute: %d %v", code, res)
		}
		if strings.Contains(strings.Join(es.remaining(), ","), "mine-1") {
			t.Fatal("lab execution did not delete the approved record")
		}
	})
}

// If the started record cannot be committed, nothing is deleted and the approval is not spent.
func TestCleanupExecution_StartAuditFailureDeletesNothing(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, es, connID := cleanupFixture(t, pool)
		_, out := requestCleanup(t, router, connID, "admin-1")
		id := out["approvalId"].(string)
		approveAs(t, router, id, "admin-2")
		failAuditAction(t, pool, "pipeline.cleanup.started")
		code, res := executeCleanup(t, router, id, "admin-2")
		if code != http.StatusServiceUnavailable {
			t.Fatalf("start audit failure: %d %v, want 503", code, res)
		}
		if got := strings.Join(es.remaining(), ","); !strings.Contains(got, "mine-1") || !strings.Contains(got, "mine-2") {
			t.Fatalf("records deleted without a start record: %s", got)
		}
		store := db.KillChainStore{Pool: pool}
		if got := historyOf(t, store, id); got != "requested,approved" {
			t.Fatalf("approval spent without a start record: %s", got)
		}
	})
}

// If the finished record cannot be committed after a deletion ran, the response is unresolved. The start
// record stays, there is no finish record, the outcome stays unknown, and nothing is retried.
func TestCleanupExecution_FinishAuditFailureIsUnresolvedNotReplayed(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, es, connID := cleanupFixture(t, pool)
		_, out := requestCleanup(t, router, connID, "admin-1")
		id := out["approvalId"].(string)
		approveAs(t, router, id, "admin-2")
		failAuditAction(t, pool, "pipeline.cleanup.finished")
		code, res := executeCleanup(t, router, id, "admin-2")
		if code != http.StatusInternalServerError || !strings.Contains(fmt.Sprint(res["error"]), "unresolved") {
			t.Fatalf("finish audit failure: %d %v, want an unresolved 500", code, res)
		}
		if strings.Contains(strings.Join(es.remaining(), ","), "mine-1") {
			t.Fatal("the deletion did not run, so this test does not exercise the unresolved path")
		}
		actions := auditActions(t, pool, id)
		hasStart := false
		for _, a := range actions {
			if strings.HasPrefix(a, "pipeline.cleanup.started:") {
				hasStart = true
			}
			if strings.HasPrefix(a, "pipeline.cleanup.finished:") {
				t.Fatalf("finish record present despite the failure: %v", actions)
			}
		}
		if !hasStart {
			t.Fatalf("start record missing: %v", actions)
		}
		store := db.KillChainStore{Pool: pool}
		if got := historyOf(t, store, id); got != "requested,approved,consumed" {
			t.Fatalf("outcome recorded for an unresolved run: %s", got)
		}
		if code, _ := executeCleanup(t, router, id, "admin-2"); code != http.StatusConflict {
			t.Fatalf("retry after unresolved: %d, want 409 (no automatic or manual replay)", code)
		}
	})
}
