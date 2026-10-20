package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/injectionapproval"
)

const cleanupRun = "bas-0123456789abcdef0123456789abcdef"

var runIDPattern = regexp.MustCompile(`bas-[0-9a-f]{32}`)

// fakeES is a small Elasticsearch stand-in. It answers the mapping, search and delete_by_query calls
// the cleanup path makes, and keeps documents in memory. It matches the marker by run identifier and
// tag, as the real query does.
type fakeES struct {
	mu       sync.Mutex
	docs     map[string]fakeDoc
	unmapped bool
}

type fakeDoc struct {
	run    string
	tagged bool
}

func (f *fakeES) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/_mapping"):
		if f.unmapped {
			_, _ = w.Write([]byte(`{"logs-bas":{"mappings":{}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"logs-bas":{"mappings":{"audspect.test_run":{},"tags":{}}}}`))
	case strings.HasSuffix(r.URL.Path, "/_search"):
		run := runIDPattern.FindString(string(body))
		var ids []string
		for id, d := range f.docs {
			if d.run == run && d.tagged {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		hits := make([]string, 0, len(ids))
		for _, id := range ids {
			hits = append(hits, `{"_id":"`+id+`","_source":{"audspect":{"test_run":"`+run+`"},"tags":["audspect-bas-test"]}}`)
		}
		_, _ = w.Write([]byte(`{"hits":{"total":{"value":` + strconv.Itoa(len(ids)) + `,"relation":"eq"},"hits":[` + strings.Join(hits, ",") + `]}}`))
	case strings.HasSuffix(r.URL.Path, "/_delete_by_query"):
		run := runIDPattern.FindString(string(body))
		var q struct {
			Query struct {
				Bool struct {
					Filter []map[string]json.RawMessage `json:"filter"`
				} `json:"bool"`
			} `json:"query"`
		}
		_ = json.Unmarshal(body, &q)
		var ids []string
		for _, clause := range q.Query.Bool.Filter {
			if raw, ok := clause["ids"]; ok {
				var v struct {
					Values []string `json:"values"`
				}
				_ = json.Unmarshal(raw, &v)
				ids = v.Values
			}
		}
		deleted := 0
		for _, id := range ids {
			if d, ok := f.docs[id]; ok && d.run == run && d.tagged {
				delete(f.docs, id)
				deleted++
			}
		}
		_, _ = w.Write([]byte(`{"deleted":` + strconv.Itoa(deleted) + `,"version_conflicts":0,"failures":[]}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeES) put(id, run string, tagged bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.docs[id] = fakeDoc{run: run, tagged: tagged}
}

func (f *fakeES) remaining() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ids []string
	for id := range f.docs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func insertCleanupConnector(t *testing.T, pool *pgxpool.Pool, baseURL string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(),
		`INSERT INTO detection_connectors
		 (name, provider, enabled, auto_verify, azure_tenant_id, client_id, client_secret, workspace_id, base_url, api_token, insecure_tls, verify_delay_seconds)
		 VALUES ('cleanup-test','elastic',true,false,'','','','',$1,'test-token',false,120) RETURNING id`, baseURL).Scan(&id)
	if err != nil {
		t.Fatalf("insert connector: %v", err)
	}
	return id
}

// cleanupFixture starts the fake Elasticsearch with two tagged records of this run, a record of
// another run, and a record of this run that lacks the tag. It returns the router and the connector.
func cleanupFixture(t *testing.T, pool *pgxpool.Pool) (http.Handler, *fakeES, string) {
	t.Helper()
	es := &fakeES{docs: map[string]fakeDoc{
		"mine-1":   {run: cleanupRun, tagged: true},
		"mine-2":   {run: cleanupRun, tagged: true},
		"other":    {run: "bas-ffffffffffffffffffffffffffffffff", tagged: true},
		"untagged": {run: cleanupRun, tagged: false},
	}}
	srv := httptest.NewServer(es)
	t.Cleanup(srv.Close)
	return approvalRouter(pool, injectionapproval.Customer, t), es, insertCleanupConnector(t, pool, srv.URL)
}

func requestCleanup(t *testing.T, router http.Handler, connID, user string) (int, map[string]any) {
	t.Helper()
	body := `{"kind":"cleanup","connectorId":"` + connID + `","index":"logs-bas","runId":"` + cleanupRun + `"}`
	rec := doRoute(t, router, http.MethodPost, "/api/pipeline-approvals", body, auth.RoleAdmin, user)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func executeCleanup(t *testing.T, router http.Handler, id, user string) (int, map[string]any) {
	t.Helper()
	rec := doRoute(t, router, http.MethodPost, "/api/pipeline-approvals/"+id+"/execute-cleanup", "", auth.RoleAdmin, user)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// The approved candidates are exactly the tagged records of this run. A second person approves,
// then the executor deletes exactly those. The record of another run and the untagged record survive.
func TestCleanupApproval_DeletesOnlyApprovedCandidates(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, es, connID := cleanupFixture(t, pool)
		code, out := requestCleanup(t, router, connID, "admin-1")
		if code != http.StatusOK {
			t.Fatalf("request: %d %v", code, out)
		}
		id := out["approvalId"].(string)
		if cands, _ := out["candidates"].([]any); len(cands) != 2 {
			t.Fatalf("candidates = %v, want the two tagged records of this run", out["candidates"])
		}
		if code := approveAs(t, router, id, "admin-2"); code != http.StatusOK {
			t.Fatalf("approve by second person: %d", code)
		}
		code, res := executeCleanup(t, router, id, "admin-3")
		if code != http.StatusOK || res["outcome"] != "executed" || res["deleted"].(float64) != 2 {
			t.Fatalf("execute: %d %v", code, res)
		}
		if got := strings.Join(es.remaining(), ","); got != "other,untagged" {
			t.Fatalf("remaining = %s, want other,untagged", got)
		}
		store := db.KillChainStore{Pool: pool}
		if got := historyOf(t, store, id); got != "requested,approved,consumed,executed" {
			t.Fatalf("history = %s", got)
		}
	})
}

// If the candidate set changes after approval, nothing is deleted and the approval is not spent.
// Restoring the set lets the same approval run.
func TestCleanupApproval_ChangedSetRefusedAndNotSpent(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, es, connID := cleanupFixture(t, pool)
		_, out := requestCleanup(t, router, connID, "admin-1")
		id := out["approvalId"].(string)
		approveAs(t, router, id, "admin-2")

		es.put("mine-3", cleanupRun, true)
		code, res := executeCleanup(t, router, id, "admin-3")
		if code != http.StatusConflict || !strings.Contains(res["error"].(string), "changed since approval") {
			t.Fatalf("changed set: %d %v, want 409 refusal", code, res)
		}
		if got := strings.Join(es.remaining(), ","); got != "mine-1,mine-2,mine-3,other,untagged" {
			t.Fatalf("a refused cleanup deleted records: %s", got)
		}
		store := db.KillChainStore{Pool: pool}
		if got := historyOf(t, store, id); got != "requested,approved" {
			t.Fatalf("refused cleanup spent the approval: history %s", got)
		}

		es.mu.Lock()
		delete(es.docs, "mine-3")
		es.mu.Unlock()
		if code, res := executeCleanup(t, router, id, "admin-3"); code != http.StatusOK || res["outcome"] != "executed" {
			t.Fatalf("restored set should run the same approval: %d %v", code, res)
		}
	})
}

// A consumed cleanup cannot be executed again.
func TestCleanupApproval_ReplayRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, _, connID := cleanupFixture(t, pool)
		_, out := requestCleanup(t, router, connID, "admin-1")
		id := out["approvalId"].(string)
		approveAs(t, router, id, "admin-2")
		if code, _ := executeCleanup(t, router, id, "admin-3"); code != http.StatusOK {
			t.Fatalf("first execute: %d", code)
		}
		if code, _ := executeCleanup(t, router, id, "admin-3"); code != http.StatusConflict {
			t.Fatalf("replay: %d, want 409", code)
		}
	})
}

// Customer deployment: the person who requested a cleanup cannot approve it.
func TestCleanupApproval_CustomerSelfApprovalRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, _, connID := cleanupFixture(t, pool)
		_, out := requestCleanup(t, router, connID, "admin-1")
		id := out["approvalId"].(string)
		if code := approveAs(t, router, id, "admin-1"); code != http.StatusForbidden {
			t.Fatalf("self-approval: %d, want 403", code)
		}
	})
}

// A cleanup is refused when the marker fields are not mapped. No approval is created.
func TestCleanupApproval_UnmappedIndexRefusedNoApproval(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		es := &fakeES{docs: map[string]fakeDoc{}, unmapped: true}
		srv := httptest.NewServer(es)
		defer srv.Close()
		router := approvalRouter(pool, injectionapproval.Customer, t)
		connID := insertCleanupConnector(t, pool, srv.URL)
		code, out := requestCleanup(t, router, connID, "admin-1")
		if code != http.StatusConflict || !strings.Contains(out["error"].(string), "not mapped") {
			t.Fatalf("unmapped: %d %v, want 409 refusal", code, out)
		}
		var n int
		_ = pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM pipeline_approvals WHERE kind='cleanup'`).Scan(&n)
		if n != 0 {
			t.Fatalf("%d cleanup approvals created for an unmapped index", n)
		}
	})
}

// A request may not carry a document, and a cleanup may not name a pattern index.
func TestCleanupApproval_RefusesDocumentAndPatternIndex(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, _, connID := cleanupFixture(t, pool)
		withDoc := `{"kind":"cleanup","connectorId":"` + connID + `","index":"logs-bas","runId":"` + cleanupRun + `","document":{"a":1}}`
		if rec := doRoute(t, router, http.MethodPost, "/api/pipeline-approvals", withDoc, auth.RoleAdmin, "admin-1"); rec.Code != http.StatusBadRequest {
			t.Fatalf("cleanup with document: %d", rec.Code)
		}
		pattern := `{"kind":"cleanup","connectorId":"` + connID + `","index":"logs-*","runId":"` + cleanupRun + `"}`
		if rec := doRoute(t, router, http.MethodPost, "/api/pipeline-approvals", pattern, auth.RoleAdmin, "admin-1"); rec.Code != http.StatusBadRequest {
			t.Fatalf("pattern index: %d", rec.Code)
		}
	})
}

// A cleanup approval cannot be executed by a role without the cleanup permission.
func TestCleanupApproval_ExecuteNeedsCleanupPermission(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router, _, connID := cleanupFixture(t, pool)
		_, out := requestCleanup(t, router, connID, "admin-1")
		id := out["approvalId"].(string)
		approveAs(t, router, id, "admin-2")
		if rec := doRoute(t, router, http.MethodPost, "/api/pipeline-approvals/"+id+"/execute-cleanup", "", auth.RoleAnalyst, "alice"); rec.Code != http.StatusForbidden {
			t.Fatalf("analyst execute: %d, want 403", rec.Code)
		}
	})
}

func approveAs(t *testing.T, router http.Handler, id, user string) int {
	t.Helper()
	return doRoute(t, router, http.MethodPost, "/api/pipeline-approvals/"+id+"/approve", "", auth.RoleAdmin, user).Code
}
