package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/injectionapproval"
)

// writeRecorder stands in for Elasticsearch's create endpoint. It records each write and answers with
// the given status, so a test can show how many writes happened.
type writeRecorder struct {
	mu     sync.Mutex
	status int
	writes []string
}

func (wr *writeRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	wr.mu.Lock()
	defer wr.mu.Unlock()
	b, _ := io.ReadAll(r.Body)
	if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/_doc/") {
		wr.writes = append(wr.writes, string(b))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(wr.status)
		if wr.status == http.StatusCreated {
			_, _ = w.Write([]byte(`{"result":"created","_id":"x"}`))
		} else {
			_, _ = w.Write([]byte(`{}`))
		}
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func (wr *writeRecorder) count() int {
	wr.mu.Lock()
	defer wr.mu.Unlock()
	return len(wr.writes)
}

const injectionBody = `{"kind":"injection","campaignId":"","stageKey":"","connectorId":"%s","index":"logs-bas",` +
	`"document":{"event":{"action":"probe"}},"testScope":"one record","expectedChange":"one record searchable"}`

// requestAndApproveInjection creates an injection approval, approves it as a second person, and returns
// its id.
func requestAndApproveInjection(t *testing.T, router http.Handler, connID string) string {
	t.Helper()
	rec := doRoute(t, router, http.MethodPost, "/api/pipeline-approvals", strings.Replace(injectionBody, "%s", connID, 1), auth.RoleAdmin, "admin-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("create injection: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		ApprovalID string `json:"approvalId"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if code := approveAs(t, router, out.ApprovalID, "admin-2"); code != http.StatusOK {
		t.Fatalf("approve injection: %d", code)
	}
	return out.ApprovalID
}

func executeInjection(t *testing.T, router http.Handler, id, user string) (int, map[string]any) {
	t.Helper()
	rec := doRoute(t, router, http.MethodPost, "/api/pipeline-approvals/"+id+"/execute-injection", "", auth.RoleAdmin, user)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func injectionFixture(t *testing.T, pool *pgxpool.Pool, status int) (http.Handler, *writeRecorder, string) {
	t.Helper()
	wr := &writeRecorder{status: status}
	srv := httptest.NewServer(wr)
	t.Cleanup(srv.Close)
	return approvalRouter(pool, injectionapproval.Customer, t), wr, insertCleanupConnector(t, pool, srv.URL)
}

// An approved injection is written exactly once. The write carries the marker and the run identifier,
// the stored payload has an event time, and the history shows consumed then executed.
func TestInjectionExecution_WritesOnceWithMarker(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, wr, connID := injectionFixture(t, pool, http.StatusCreated)
		id := requestAndApproveInjection(t, router, connID)
		code, res := executeInjection(t, router, id, "admin-2")
		if code != http.StatusOK || res["status"] != "EXECUTED" {
			t.Fatalf("execute: %d %v", code, res)
		}
		if wr.count() != 1 {
			t.Fatalf("%d writes, want exactly one", wr.count())
		}
		body := wr.writes[0]
		if !strings.Contains(body, `"tags":["audspect-bas-test"]`) || !strings.Contains(body, `"test_run":"bas-`) || !strings.Contains(body, `"@timestamp"`) {
			t.Fatalf("written document lacks the marker or event time: %s", body)
		}
		store := db.KillChainStore{Pool: pool}
		if got := historyOf(t, store, id); got != "requested,approved,consumed,executed" {
			t.Fatalf("history = %s", got)
		}
	})
}

// Only the approver may execute. Another administrator is refused, nothing is written and the approval
// is not spent.
func TestInjectionExecution_OnlyApproverMayExecute(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, wr, connID := injectionFixture(t, pool, http.StatusCreated)
		id := requestAndApproveInjection(t, router, connID)
		if code, _ := executeInjection(t, router, id, "admin-3"); code != http.StatusForbidden {
			t.Fatalf("another admin executed: %d, want 403", code)
		}
		if wr.count() != 0 {
			t.Fatalf("refused executor wrote %d records", wr.count())
		}
		store := db.KillChainStore{Pool: pool}
		if got := historyOf(t, store, id); got != "requested,approved" {
			t.Fatalf("refused executor spent the approval: %s", got)
		}
	})
}

// A consumed injection cannot be written again.
func TestInjectionExecution_ReplayRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, wr, connID := injectionFixture(t, pool, http.StatusCreated)
		id := requestAndApproveInjection(t, router, connID)
		executeInjection(t, router, id, "admin-2")
		if code, _ := executeInjection(t, router, id, "admin-2"); code != http.StatusConflict {
			t.Fatalf("replay: %d, want 409", code)
		}
		if wr.count() != 1 {
			t.Fatalf("replay wrote again: %d writes", wr.count())
		}
	})
}

// If the start record cannot be committed, nothing is written and the approval is not spent.
func TestInjectionExecution_StartAuditFailureWritesNothing(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, wr, connID := injectionFixture(t, pool, http.StatusCreated)
		id := requestAndApproveInjection(t, router, connID)
		failAuditAction(t, pool, "pipeline.injection.started")
		if code, _ := executeInjection(t, router, id, "admin-2"); code != http.StatusServiceUnavailable {
			t.Fatalf("start audit failure: %d, want 503", code)
		}
		if wr.count() != 0 {
			t.Fatalf("written without a start record: %d", wr.count())
		}
		store := db.KillChainStore{Pool: pool}
		if got := historyOf(t, store, id); got != "requested,approved" {
			t.Fatalf("approval spent without a start record: %s", got)
		}
	})
}

// A write Elasticsearch does not confirm is recorded as failed. The approval is spent, and a retry is
// refused. Nothing is retried automatically.
func TestInjectionExecution_UnconfirmedWriteIsFailedNotReplayed(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, wr, connID := injectionFixture(t, pool, http.StatusInternalServerError)
		id := requestAndApproveInjection(t, router, connID)
		code, res := executeInjection(t, router, id, "admin-2")
		if code != http.StatusOK || res["status"] != "ERROR" || res["outcome"] != "failed" {
			t.Fatalf("unconfirmed write: %d %v, want ERROR with outcome failed", code, res)
		}
		store := db.KillChainStore{Pool: pool}
		if got := historyOf(t, store, id); got != "requested,approved,consumed,failed" {
			t.Fatalf("history = %s", got)
		}
		if code, _ := executeInjection(t, router, id, "admin-2"); code != http.StatusConflict {
			t.Fatalf("retry after failed write: %d, want 409", code)
		}
		if wr.count() != 1 {
			t.Fatalf("retry wrote again: %d writes", wr.count())
		}
	})
}

// The start and finish records are committed with the same execution id.
func TestInjectionExecution_DurableStartAndFinish(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, _, connID := injectionFixture(t, pool, http.StatusCreated)
		id := requestAndApproveInjection(t, router, connID)
		code, res := executeInjection(t, router, id, "admin-2")
		if code != http.StatusOK {
			t.Fatalf("execute: %d %v", code, res)
		}
		execID := res["executionId"].(string)
		var durable []string
		for _, a := range auditActions(t, pool, id) {
			if strings.HasPrefix(a, "pipeline.injection.") {
				durable = append(durable, a)
			}
		}
		want := []string{"pipeline.injection.started:" + execID, "pipeline.injection.finished:" + execID}
		if strings.Join(durable, "|") != strings.Join(want, "|") {
			t.Fatalf("durable audit = %v, want %v", durable, want)
		}
	})
}
