package api

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
)

func gqlBindSpec() map[string]any {
	return map[string]any{
		"identities": []map[string]string{{"name": "alice", "credential_ref": "shop/alice"}, {"name": "bob", "credential_ref": "shop/bob"}},
		"objects": []map[string]any{
			{"operation": "QUERY /graphql#order", "params": map[string]string{"id": "ORD-A1"}, "owner": "alice", "selection": "id total", "protected_values": []string{"alice-gql-secret"}},
			{"operation": "QUERY /graphql#order", "params": map[string]string{"id": "ORD-B1"}, "owner": "bob", "selection": "id total", "protected_values": []string{"bob-gql-secret"}},
		},
	}
}

func TestAPIBASGraphQLQueriesBindAndRun(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	ctx := context.Background()
	if rec := postAs(t, h, "/api/apibas/targets", boundTargetBody("gql-1", "shop/alice", "shop/bob"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d", rec.Code)
	}
	schema, err := os.ReadFile("../apibas/openapi/testdata/shop.graphql")
	if err != nil {
		t.Fatal(err)
	}
	if rec := sendRaw(t, h, http.MethodPost, "/api/apibas/targets/gql-1/inventory", string(schema), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("import schema: %d %s", rec.Code, rec.Body.String())
	}
	// The inventory the console reads carries the argument and return types binding needs.
	inv := getAsUser(t, h, "/api/apibas/targets/gql-1/inventory", auth.RoleAnalyst, "a1").Body.String()
	if !strings.Contains(inv, `"returns":"Order"`) || !strings.Contains(inv, `"kind":"SCALAR"`) || !strings.Contains(inv, `"returns_composite":true`) {
		t.Errorf("the inventory does not carry GraphQL argument and return types: %.400s", inv)
	}

	// Refused when saving: a missing selection, an injection attempt in the selection, no protected value.
	for name, mutate := range map[string]func(map[string]any){
		"no selection": func(s map[string]any) { delete(s["objects"].([]map[string]any)[0], "selection") },
		"injection": func(s map[string]any) {
			s["objects"].([]map[string]any)[0]["selection"] = `id } } mutation { deleteAccount`
		},
		"no protected value": func(s map[string]any) { s["objects"].([]map[string]any)[0]["protected_values"] = []string{} },
		"unknown argument": func(s map[string]any) {
			s["objects"].([]map[string]any)[0]["params"] = map[string]string{"id": "A1", "x": "y1"}
		},
	} {
		spec := gqlBindSpec()
		mutate(spec)
		if rec := putAs(t, h, "/api/apibas/targets/gql-1/binding", spec, auth.RoleAdmin, "admin1"); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, rec.Code)
		}
	}

	rec := putAs(t, h, "/api/apibas/targets/gql-1/binding", gqlBindSpec(), auth.RoleAdmin, "admin1")
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "QUERY /graphql#order") || !strings.Contains(rec.Body.String(), "HTTP 200") {
		t.Errorf("the plan does not show the GraphQL scenarios and how they are graded: %s", rec.Body.String())
	}
	rec = postAs(t, h, "/api/apibas/targets/gql-1/binding/jobs", map[string]any{"key": "gql-key-1"}, auth.RoleAdmin, "admin1")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("run: %d %s", rec.Code, rec.Body.String())
	}
	job, err := db.GetAPIBASJob(ctx, sharedDB.Pool, decode(t, rec)["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(job.Fixture, "bound:") || len(job.ScenarioIDs) != 2 {
		t.Errorf("job: fixture %q scenarios %v, want a bound fixture and two scenarios", job.Fixture, job.ScenarioIDs)
	}
}
