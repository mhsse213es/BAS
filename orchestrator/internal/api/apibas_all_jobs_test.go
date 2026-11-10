package api

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
)

func TestAPIBASJobsAcrossTargets(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	ctx := context.Background()
	for id, env := range map[string]string{"xj-lab": "lab", "xj-stg": "staging", "xj-sch": "lab"} {
		if rec := postAs(t, h, "/api/apibas/targets", targetBody(id, env), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
			t.Fatalf("register %s: %d %s", id, rec.Code, rec.Body.String())
		}
	}
	submit := func(target, key string) string {
		rec := postAs(t, h, "/api/apibas/jobs", map[string]any{"key": key, "target_id": target, "fixture": "orders-two-tenant", "scenario_ids": []string{"API-BAS-AUTHZ-001"}}, auth.RoleAdmin, "admin1")
		if rec.Code != http.StatusAccepted {
			t.Fatalf("submit %s: %d %s", key, rec.Code, rec.Body.String())
		}
		return decode(t, rec)["id"].(string)
	}
	labJob := submit("xj-lab", "xj-key-1")
	stgJob := submit("xj-stg", "xj-key-2")
	schedJob := submit("xj-sch", "xj-key-3")
	if _, err := sharedDB.Pool.Exec(ctx, `UPDATE apibas_jobs SET requested_by = 'schedule:admin1' WHERE id = $1::uuid`, schedJob); err != nil {
		t.Fatal(err)
	}

	list := func(q string) (int, []map[string]any, map[string]any) {
		rec := getAsUser(t, h, "/api/apibas/jobs?"+q, auth.RoleAnalyst, "a1")
		if rec.Code != http.StatusOK {
			return rec.Code, nil, nil
		}
		body := decode(t, rec)
		var jobs []map[string]any
		for _, j := range body["jobs"].([]any) {
			jobs = append(jobs, j.(map[string]any))
		}
		return rec.Code, jobs, body
	}
	ids := func(jobs []map[string]any) map[string]map[string]any {
		m := map[string]map[string]any{}
		for _, j := range jobs {
			m[j["id"].(string)] = j
		}
		return m
	}

	// Every target's jobs appear, each carrying its target and whether a schedule queued it.
	code, jobs, _ := list("limit=100")
	got := ids(jobs)
	if code != http.StatusOK || got[labJob] == nil || got[stgJob] == nil || got[schedJob] == nil {
		t.Fatalf("unfiltered list missed a job: %d %v", code, got)
	}
	if got[labJob]["target_id"] != "xj-lab" || got[stgJob]["target_id"] != "xj-stg" || got[labJob]["scheduled"] != false || got[schedJob]["scheduled"] != true {
		t.Errorf("target or scheduled flag wrong: %v %v %v", got[labJob], got[stgJob], got[schedJob])
	}

	// Filters.
	_, jobs, _ = list("limit=100&target_id=xj-lab")
	got = ids(jobs)
	if len(got) != 1 || got[labJob] == nil {
		t.Errorf("target filter: %v", got)
	}
	_, jobs, _ = list("limit=100&environment=staging")
	got = ids(jobs)
	if got[stgJob] == nil || got[labJob] != nil || got[schedJob] != nil {
		t.Errorf("environment filter: %v", got)
	}
	_, jobs, _ = list("limit=100&source=scheduled&environment=lab")
	got = ids(jobs)
	if got[schedJob] == nil || got[labJob] != nil || got[stgJob] != nil {
		t.Errorf("source=scheduled: %v", got)
	}
	_, jobs, _ = list("limit=100&source=manual&environment=lab")
	got = ids(jobs)
	if got[labJob] == nil || got[schedJob] != nil {
		t.Errorf("source=manual: %v", got)
	}
	_, jobs, _ = list("limit=100&status=completed&target_id=xj-lab")
	if len(jobs) != 0 {
		t.Errorf("status filter: %d jobs, want 0 (all queued)", len(jobs))
	}
	// An unknown target gives an empty list, not an error.
	if code, jobs, _ := list("target_id=gone-target"); code != http.StatusOK || len(jobs) != 0 {
		t.Errorf("unknown target: %d %d", code, len(jobs))
	}

	// Paging across targets walks every job once, in order.
	seen := map[string]bool{}
	next := ""
	for page := 0; page < 200; page++ {
		q := "limit=2&environment=lab"
		if next != "" {
			q += "&before=" + url.QueryEscape(next)
		}
		_, jobs, body := list(q)
		for _, j := range jobs {
			if seen[j["id"].(string)] {
				t.Fatalf("job %v listed twice", j["id"])
			}
			seen[j["id"].(string)] = true
		}
		n, _ := body["next"].(string)
		if n == "" {
			break
		}
		next = n
	}
	if !seen[labJob] || !seen[schedJob] || seen[stgJob] {
		t.Errorf("paging saw %v", seen)
	}

	// Bad parameters and permission.
	for _, q := range []string{"limit=0", "limit=101", "status=bogus", "environment=prod", "source=robot", "before=junk", "target_id=" + strings.Repeat("a", 65)} {
		if code, _, _ := list(q); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", q, code)
		}
	}
	if rec := getAsUser(t, h, "/api/apibas/jobs", "", ""); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Errorf("unauthenticated: %d", rec.Code)
	}
	// The summary exposes no credential or report body.
	rec := getAsUser(t, h, "/api/apibas/jobs?limit=100", auth.RoleAnalyst, "a1")
	if strings.Contains(rec.Body.String(), "credential") || strings.Contains(rec.Body.String(), "run_tag") {
		t.Errorf("the list exposes more than a summary: %.300s", rec.Body.String())
	}
}
