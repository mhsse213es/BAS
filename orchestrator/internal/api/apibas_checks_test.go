package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
)

func checksSpec() map[string]any {
	return map[string]any{
		"identities": []map[string]string{{"name": "alice", "credential_ref": "shop/alice"}, {"name": "bob", "credential_ref": "shop/bob"}},
		"objects":    []map[string]any{},
		"functions": []map[string]any{{
			"operation": "GET /v2/orders", "privileged": "bob", "ordinary": "alice", "protected_values": []string{"bob-only-report-value"},
		}},
		"properties": []map[string]any{{
			"operation": "GET /v2/orders/{orderId}", "params": map[string]string{"orderId": "ORD-A1"}, "owner": "alice",
			"forbidden_values": []string{"internal-risk-flag-77"},
		}},
	}
}

func TestAPIBASFunctionAndPropertyChecksSaveAndRun(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	ctx := context.Background()
	if rec := postAs(t, h, "/api/apibas/targets", boundTargetBody("chk-1", "shop/alice", "shop/bob"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d", rec.Code)
	}
	if rec := sendRaw(t, h, http.MethodPost, "/api/apibas/targets/chk-1/inventory", specBytes(t), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("import: %d", rec.Code)
	}

	// A check that names an unknown identity, or has no value to look for, is refused when saving.
	bad := checksSpec()
	bad["functions"].([]map[string]any)[0]["ordinary"] = "carol"
	if rec := putAs(t, h, "/api/apibas/targets/chk-1/binding", bad, auth.RoleAdmin, "admin1"); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown identity: %d, want 400", rec.Code)
	}
	bad = checksSpec()
	bad["properties"].([]map[string]any)[0]["forbidden_values"] = []string{}
	if rec := putAs(t, h, "/api/apibas/targets/chk-1/binding", bad, auth.RoleAdmin, "admin1"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "forbidden value") {
		t.Errorf("no forbidden value: %d %s", rec.Code, rec.Body.String())
	}

	// Saved, previewed with their kinds, and run as a bound job with the checks' scenarios.
	rec := putAs(t, h, "/api/apibas/targets/chk-1/binding", checksSpec(), auth.RoleAdmin, "admin1")
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"kind":"function"`) || !strings.Contains(rec.Body.String(), `"kind":"property"`) {
		t.Errorf("the plan does not show the kinds of check: %s", rec.Body.String())
	}
	rec = postAs(t, h, "/api/apibas/targets/chk-1/binding/jobs", map[string]any{"key": "chk-key-1"}, auth.RoleAdmin, "admin1")
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
