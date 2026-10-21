package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/injectionapproval"
)

// seedStartedExecution writes a started record with no closing record, as a crash would leave it.
func seedStartedExecution(t *testing.T, pool *pgxpool.Pool, execID, approvalID string) {
	t.Helper()
	detail := `{"executionId":"` + execID + `","approvalId":"` + approvalID + `","candidateSetHash":"abc","target":"logs-bas","runId":"` +
		cleanupRun + `","executor":"admin-2"}`
	_, err := pool.Exec(context.Background(),
		`INSERT INTO audit_logs (actor_id, action, resource, detail, ip, outcome) VALUES ('admin-2','pipeline.cleanup.started',$1,$2::jsonb,'','started')`,
		approvalID, detail)
	if err != nil {
		t.Fatalf("seed started record: %v", err)
	}
}

func unresolvedList(t *testing.T, router http.Handler, user string) []map[string]any {
	t.Helper()
	rec := doRoute(t, router, http.MethodGet, "/api/pipeline-approvals/unresolved-cleanups", "", auth.RoleAdmin, user)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Executions []map[string]any `json:"executions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Executions
}

// An execution with a started record and no closing record is listed as unresolved.
func TestReconcile_ListsUnresolvedExecution(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := approvalRouter(pool, injectionapproval.Customer, t)
		seedStartedExecution(t, pool, "exec-unres-1", "ap-1")
		got := unresolvedList(t, router, "admin-1")
		if len(got) != 1 || got[0]["executionId"] != "exec-unres-1" {
			t.Fatalf("unresolved = %v, want exec-unres-1", got)
		}
	})
}

// Reconciling records a durable resolution with the note and the reconciler, closes the execution in
// the list, and deletes nothing. The approval stays spent.
func TestReconcile_RecordsResolutionAndCloses(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := approvalRouter(pool, injectionapproval.Customer, t)
		seedStartedExecution(t, pool, "exec-unres-2", "ap-2")
		body := `{"resolution":"not_deleted","note":"checked the index at 10:40; records still present"}`
		rec := doRoute(t, router, http.MethodPost, "/api/pipeline-approvals/unresolved-cleanups/exec-unres-2/reconcile", body, auth.RoleAdmin, "admin-1")
		if rec.Code != http.StatusOK {
			t.Fatalf("reconcile: %d %s", rec.Code, rec.Body.String())
		}
		var n int
		_ = pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM audit_logs WHERE action='pipeline.cleanup.reconciled' AND detail->>'executionId'='exec-unres-2' AND detail->>'reconciler'='admin-1'`).Scan(&n)
		if n != 1 {
			t.Fatalf("reconciled records = %d, want 1", n)
		}
		if got := unresolvedList(t, router, "admin-1"); len(got) != 0 {
			t.Fatalf("closed execution still listed: %v", got)
		}
		// Reconciling again finds nothing unresolved.
		if rec := doRoute(t, router, http.MethodPost, "/api/pipeline-approvals/unresolved-cleanups/exec-unres-2/reconcile", body, auth.RoleAdmin, "admin-1"); rec.Code != http.StatusNotFound {
			t.Fatalf("second reconcile: %d, want 404", rec.Code)
		}
	})
}

// A resolution must be one of the two values, and a note is required.
func TestReconcile_RefusesBadResolutionOrMissingNote(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := approvalRouter(pool, injectionapproval.Customer, t)
		seedStartedExecution(t, pool, "exec-unres-3", "ap-3")
		for _, body := range []string{
			`{"resolution":"maybe","note":"x"}`,
			`{"resolution":"deleted","note":"   "}`,
			`{"resolution":"deleted"}`,
		} {
			if rec := doRoute(t, router, http.MethodPost, "/api/pipeline-approvals/unresolved-cleanups/exec-unres-3/reconcile", body, auth.RoleAdmin, "admin-1"); rec.Code != http.StatusBadRequest {
				t.Fatalf("body %s: %d, want 400", body, rec.Code)
			}
		}
		if got := unresolvedList(t, router, "admin-1"); len(got) != 1 {
			t.Fatalf("refused reconciles closed the execution: %v", got)
		}
	})
}

// An unknown execution id is 404, and it writes nothing.
func TestReconcile_UnknownExecutionNotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := approvalRouter(pool, injectionapproval.Customer, t)
		rec := doRoute(t, router, http.MethodPost, "/api/pipeline-approvals/unresolved-cleanups/exec-nope/reconcile",
			`{"resolution":"deleted","note":"x"}`, auth.RoleAdmin, "admin-1")
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "no unresolved") {
			t.Fatalf("unknown execution: %d %s", rec.Code, rec.Body.String())
		}
	})
}

// Listing and reconciling need the cleanup permission. An analyst is refused on both.
func TestReconcile_NeedsCleanupPermission(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := approvalRouter(pool, injectionapproval.Customer, t)
		seedStartedExecution(t, pool, "exec-unres-4", "ap-4")
		if rec := doRoute(t, router, http.MethodGet, "/api/pipeline-approvals/unresolved-cleanups", "", auth.RoleAnalyst, "alice"); rec.Code != http.StatusForbidden {
			t.Fatalf("analyst list: %d, want 403", rec.Code)
		}
		if rec := doRoute(t, router, http.MethodPost, "/api/pipeline-approvals/unresolved-cleanups/exec-unres-4/reconcile",
			`{"resolution":"deleted","note":"x"}`, auth.RoleAnalyst, "alice"); rec.Code != http.StatusForbidden {
			t.Fatalf("analyst reconcile: %d, want 403", rec.Code)
		}
	})
}
