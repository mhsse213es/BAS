package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/secretstore"
)

func boundTargetBody(id string, creds ...string) map[string]any {
	b := targetBody(id, "lab")
	refs := map[string]string{}
	for _, c := range creds {
		ref, _ := secretstore.MakeRef("apibas_targets", id, strings.ReplaceAll(c, "/", "_"))
		refs[c] = ref
	}
	b["credential_refs"] = refs
	return b
}

func TestAPIBASBindingRun(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	run := func(target string, body any) *httptest.ResponseRecorder {
		return postAs(t, h, "/api/apibas/targets/"+target+"/binding/jobs", body, auth.RoleAdmin, "admin1")
	}

	if rec := postAs(t, h, "/api/apibas/targets", boundTargetBody("brun-1", "shop/alice", "shop/bob"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	body := map[string]any{"key": "brun-key-1"}

	// Nothing stored yet.
	if rec := run("brun-1", body); rec.Code != http.StatusNotFound {
		t.Errorf("run with no test data: %d, want 404", rec.Code)
	}
	if rec := sendRaw(t, h, http.MethodPost, "/api/apibas/targets/brun-1/inventory", specBytes(t), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("import: %d", rec.Code)
	}
	if rec := putAs(t, h, "/api/apibas/targets/brun-1/binding", bindSpecWith("shop/alice", "shop/bob"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusOK {
		t.Fatalf("save binding: %d %s", rec.Code, rec.Body.String())
	}

	// A key is required and unknown fields are refused.
	if rec := run("brun-1", map[string]any{}); rec.Code != http.StatusBadRequest {
		t.Errorf("no key: %d", rec.Code)
	}
	if rec := run("brun-1", map[string]any{"key": "k", "scenario_ids": []string{"API-BAS-AUTHZ-001"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("caller-chosen scenarios: %d, want 400", rec.Code)
	}

	// Queued, with a fixture derived from the plan and scenarios derived from the test data.
	rec := run("brun-1", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("run: %d %s", rec.Code, rec.Body.String())
	}
	id := decode(t, rec)["id"].(string)
	view := getAsUser(t, h, "/api/apibas/jobs/"+id, auth.RoleAnalyst, "a1").Body.String()
	stored, err := db.GetAPIBASJob(context.Background(), sharedDB.Pool, id)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.Body.String(), `"created":true`) || !strings.HasPrefix(stored.Fixture, "bound:") || !strings.Contains(view, "API-BAS-AUTHZ-901") {
		t.Errorf("the job does not carry a bound fixture and bound scenarios: fixture %q view %s", stored.Fixture, view)
	}
	if _, err := db.GetAPIBASJobPlan(context.Background(), sharedDB.Pool, id); err != nil {
		t.Errorf("the plan was not stored with the job: %v", err)
	}
	// A repeated key returns the same job and queues nothing.
	rec = run("brun-1", body)
	if rec.Code != http.StatusOK || decode(t, rec)["id"] != id || decode(t, rec)["created"] != false {
		t.Errorf("replay: %d %s", rec.Code, rec.Body.String())
	}

	// A newer inventory makes the stored test data stale: running is refused until it is saved again.
	changed := strings.Replace(specBytes(t), "/v2/catalog", "/v2/catalogue", 1)
	if rec := sendRaw(t, h, http.MethodPost, "/api/apibas/targets/brun-1/inventory", changed, auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("second import: %d", rec.Code)
	}
	if rec := run("brun-1", map[string]any{"key": "brun-key-2"}); rec.Code != http.StatusConflict {
		t.Errorf("stale test data: %d, want 409", rec.Code)
	}

	// A credential that the target does not carry is refused, and the refusal is audited like any other.
	if rec := postAs(t, h, "/api/apibas/targets", boundTargetBody("brun-2", "shop/alice"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register 2: %d", rec.Code)
	}
	if rec := sendRaw(t, h, http.MethodPost, "/api/apibas/targets/brun-2/inventory", specBytes(t), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("import 2: %d", rec.Code)
	}
	if rec := putAs(t, h, "/api/apibas/targets/brun-2/binding", bindSpecWith("shop/alice", "shop/bob"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusOK {
		t.Fatalf("save binding 2: %d", rec.Code)
	}
	if rec := run("brun-2", map[string]any{"key": "brun-key-3"}); rec.Code != http.StatusForbidden {
		t.Errorf("unregistered credential: %d, want 403", rec.Code)
	}

	// Without the execution service the route answers 503, like the other job routes.
	h2 := jobsRouter(jobsHandler(t, false))
	if rec := postAs(t, h2, "/api/apibas/targets/brun-1/binding/jobs", body, auth.RoleAdmin, "admin1"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("no service: %d, want 503", rec.Code)
	}
}

func bindSpecWith(a, b string) map[string]any {
	m := bindSpec()
	m["identities"] = []map[string]string{{"name": "alice", "credential_ref": a}, {"name": "bob", "credential_ref": b}}
	return m
}
