package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
)

// cleanupAuditCount counts every cleanup audit row, so a test can show that a read wrote none.
func cleanupAuditCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_logs WHERE action LIKE 'pipeline.cleanup.%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func decodeBody(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("response is not JSON: %v: %s", err, raw)
	}
	return out
}

// executionIDOf returns the execution id recorded in the started audit row of an approval.
func executionIDOf(t *testing.T, pool *pgxpool.Pool, approvalID string) string {
	t.Helper()
	for _, a := range auditActions(t, pool, approvalID) {
		if strings.HasPrefix(a, "pipeline.cleanup.started:") {
			return strings.TrimPrefix(a, "pipeline.cleanup.started:")
		}
	}
	t.Fatalf("no started record for approval %s", approvalID)
	return ""
}

// unresolvedExecution produces a cleanup whose deletion ran but whose finish record could not be
// written. It returns the router, the fake Elasticsearch and the execution id.
func unresolvedExecution(t *testing.T, pool *pgxpool.Pool) (http.Handler, *fakeES, string) {
	t.Helper()
	router, es, connID := cleanupFixture(t, pool)
	_, out := requestCleanup(t, router, connID, "admin-1")
	id := out["approvalId"].(string)
	approveAs(t, router, id, "admin-2")
	failAuditAction(t, pool, "pipeline.cleanup.finished")
	if code, _ := executeCleanup(t, router, id, "admin-2"); code != http.StatusInternalServerError {
		t.Fatalf("setup: finish failure gave %d, want 500", code)
	}
	return router, es, executionIDOf(t, pool, id)
}

// checkExecution calls the read-only check endpoint and decodes its body.
func checkExecution(t *testing.T, router http.Handler, execID string) (int, map[string]any) {
	t.Helper()
	rec := doRoute(t, router, http.MethodGet, "/api/pipeline-approvals/unresolved-cleanups/"+execID+"/check", "", auth.RoleAdmin, "admin-2")
	return rec.Code, decodeBody(t, rec.Body.Bytes())
}

// Records were deleted before the finish record failed: the check finds nothing left and suggests
// deleted, and it writes no audit rows.
func TestCleanupCheck_DeletedSuggestsDeleted(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, _, execID := unresolvedExecution(t, pool)
		before := cleanupAuditCount(t, pool)
		code, res := checkExecution(t, router, execID)
		if code != http.StatusOK || res["status"] != "checked" || res["suggested"] != "deleted" {
			t.Fatalf("check: %d %v, want checked and suggested deleted", code, res)
		}
		if after := cleanupAuditCount(t, pool); after != before {
			t.Fatalf("check wrote audit rows: %d before, %d after", before, after)
		}
	})
}

// The records are still in the index: the check names them and does not suggest deleted.
func TestCleanupCheck_StillPresentIsNotDeleted(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, es, execID := unresolvedExecution(t, pool)
		es.put("mine-1", cleanupRun, true, oldEventTime())
		es.put("mine-2", cleanupRun, true, oldEventTime())
		code, res := checkExecution(t, router, execID)
		if code != http.StatusOK || res["suggested"] == "deleted" {
			t.Fatalf("check with records present: %d %v, must not suggest deleted", code, res)
		}
		if !strings.Contains(fmt.Sprint(res["remaining"]), "mine-1") {
			t.Fatalf("remaining does not name mine-1: %v", res["remaining"])
		}
	})
}

// An execution that is not unresolved (or does not exist) is not found.
func TestCleanupCheck_UnknownExecutionNotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, _, _ := cleanupFixture(t, pool)
		if code, _ := checkExecution(t, router, "exec-00000000000000000000000000000000"); code != http.StatusNotFound {
			t.Fatalf("unknown execution: %d, want 404", code)
		}
	})
}
