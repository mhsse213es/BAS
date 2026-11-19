package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
)

func TestAPIBASBindingPlan(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	if rec := postAs(t, h, "/api/apibas/targets", targetBody("bind-t1", "lab"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	plan := "/api/apibas/targets/bind-t1/binding/plan"
	spec := map[string]any{
		"identities": []map[string]string{{"name": "alice", "credential_ref": "shop/alice"}, {"name": "bob", "credential_ref": "shop/bob"}},
		"objects": []map[string]any{
			{"operation": "GET /v2/orders/{orderId}", "params": map[string]string{"orderId": "ORD-A1"}, "owner": "alice", "protected_values": []string{"alice-private"}},
			{"operation": "GET /v2/orders/{orderId}", "params": map[string]string{"orderId": "ORD-B1"}, "owner": "bob"},
		},
	}

	// No inventory yet.
	if rec := postAs(t, h, plan, spec, auth.RoleAnalyst, "a1"); rec.Code != http.StatusNotFound {
		t.Errorf("plan before an inventory exists: %d, want 404", rec.Code)
	}
	if rec := sendRaw(t, h, http.MethodPost, "/api/apibas/targets/bind-t1/inventory", specBytes(t), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}

	rec := postAs(t, h, plan, spec, auth.RoleAnalyst, "a1")
	if rec.Code != http.StatusOK {
		t.Fatalf("plan: %d %s", rec.Code, rec.Body.String())
	}
	m := decode(t, rec)
	if m["scenarios"].(float64) != 2 || m["inventory_version"].(float64) != 1 {
		t.Errorf("plan: %v", m)
	}
	if len(m["limits"].([]any)) == 0 {
		t.Error("a plan must state its limits")
	}
	// The PATCH on the same path changes state, so it is reported as skipped with its reason.
	if !strings.Contains(rec.Body.String(), "changes state") {
		t.Errorf("no skipped write operation reported: %s", rec.Body.String())
	}
	// Only credential names are accepted and echoed nowhere: the response carries no credential reference at all.
	if strings.Contains(rec.Body.String(), "shop/alice") {
		t.Error("a credential reference came back in the plan")
	}

	for name, body := range map[string]any{
		"unknown field":     map[string]any{"identities": spec["identities"], "objects": spec["objects"], "token": "x"},
		"one identity":      map[string]any{"identities": []map[string]string{{"name": "alice", "credential_ref": "shop/alice"}}, "objects": spec["objects"]},
		"unknown operation": map[string]any{"identities": spec["identities"], "objects": []map[string]any{{"operation": "GET /nope/{id}", "params": map[string]string{"id": "1"}, "owner": "alice"}}},
		"path traversal": map[string]any{"identities": spec["identities"], "objects": []map[string]any{
			{"operation": "GET /v2/orders/{orderId}", "params": map[string]string{"orderId": "../x"}, "owner": "alice"}}},
	} {
		if rec := postAs(t, h, plan, body, auth.RoleAnalyst, "a1"); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, rec.Code)
		}
	}
	if rec := postAs(t, h, plan, spec, "", ""); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Errorf("unauthenticated: %d", rec.Code)
	}
}
