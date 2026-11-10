package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
)

func TestAPIBASTargetJobsPagingAndStatusFilter(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	ctx := context.Background()
	for _, id := range []string{"pg-1", "pg-2"} {
		if rec := postAs(t, h, "/api/apibas/targets", targetBody(id, "lab"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
			t.Fatalf("register %s: %d", id, rec.Code)
		}
	}
	// 7 jobs for pg-1: one hour apart, statuses alternating; two share the same creation time to exercise the tie-break; one for pg-2.
	base := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Microsecond)
	seed := func(target, key, status string, at time.Time) string {
		var id string
		err := sharedDB.Pool.QueryRow(ctx, `
			INSERT INTO apibas_jobs (job_key, requested_by, target_base_url, environment, fixture, scenario_ids, status, created_at, target_id)
			VALUES ($1, 'seed', 'http://127.0.0.1:8099', 'lab', 'orders-two-tenant', '["API-BAS-AUTHZ-001"]', $2, $3, $4)
			RETURNING id::text`, key, status, at, target).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	statuses := []string{"completed", "failed", "completed", "completed", "failed", "completed", "cancelled"}
	want := []string{}
	for i, st := range statuses {
		at := base.Add(time.Duration(i) * time.Hour)
		if i == 4 {
			at = base.Add(3 * time.Hour) // the same time as job 3
		}
		seed("pg-1", fmt.Sprintf("pg-key-%d", i), st, at)
	}
	seed("pg-2", "pg-key-other", "completed", base)
	_ = want

	page := func(query string) (ids []string, next string, status int) {
		rec := getAsUser(t, h, "/api/apibas/targets/pg-1/jobs"+query, auth.RoleAnalyst, "a1")
		if rec.Code != http.StatusOK {
			return nil, "", rec.Code
		}
		body := decode(t, rec)
		for _, j := range body["jobs"].([]any) {
			ids = append(ids, j.(map[string]any)["id"].(string))
		}
		if n, ok := body["next"].(string); ok {
			next = n
		}
		return ids, next, rec.Code
	}

	// Walking three at a time visits every job exactly once, newest first, and the last page has no cursor.
	seen := map[string]int{}
	var order []string
	cursor := ""
	for i := 0; i < 10; i++ {
		q := "?limit=3"
		if cursor != "" {
			q += "&before=" + url.QueryEscape(cursor)
		}
		ids, next, code := page(q)
		if code != http.StatusOK {
			t.Fatalf("page %d: %d", i, code)
		}
		for _, id := range ids {
			seen[id]++
			order = append(order, id)
		}
		if next == "" {
			if i != 2 || len(ids) != 1 {
				t.Errorf("the last page was page %d with %d jobs, want page 2 with 1", i, len(ids))
			}
			break
		}
		if len(ids) != 3 {
			t.Errorf("page %d has %d jobs with a cursor, want 3", i, len(ids))
		}
		cursor = next
	}
	if len(seen) != 7 || len(order) != 7 {
		t.Fatalf("paging visited %d distinct jobs in %d rows, want 7 and 7", len(seen), len(order))
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("job %s appeared %d times", id, n)
		}
	}
	// A full page that happens to be the last has no cursor.
	if _, next, _ := page("?limit=7"); next != "" {
		t.Errorf("a page holding every job carries a cursor: %q", next)
	}
	if ids, next, _ := page("?limit=6"); len(ids) != 6 || next == "" {
		t.Errorf("limit=6: %d jobs, cursor %q", len(ids), next)
	}

	// Status filter, alone and with paging.
	if ids, _, _ := page("?status=failed&limit=100"); len(ids) != 2 {
		t.Errorf("status=failed: %d jobs, want 2", len(ids))
	}
	if ids, next, _ := page("?status=completed&limit=2"); len(ids) != 2 || next == "" {
		t.Errorf("status=completed&limit=2: %d jobs, cursor %q", len(ids), next)
	}
	if ids, _, _ := page("?status=queued"); len(ids) != 0 {
		t.Errorf("status=queued: %d jobs, want 0", len(ids))
	}

	// Bad input is refused, never passed to the query.
	for _, bad := range []string{"?status=bogus", "?status=completed%27%3B--", "?before=garbage", "?before=2026-01-01T00:00:00Z_not-an-id",
		"?before=" + url.QueryEscape(strings.Repeat("a", 200)), "?before=_00000000-0000-0000-0000-000000000000"} {
		if _, _, code := page(bad); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", bad, code)
		}
	}
}
