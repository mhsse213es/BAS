package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
)

func massAPISpec() map[string]any {
	spec := bindSpecWith("shop/alice", "shop/bob")
	spec["allow_writes"] = true
	spec["mass_assignments"] = []map[string]any{{
		"operation": "PATCH /v2/orders/{orderId}", "params": map[string]string{"orderId": "ORD-A1"}, "owner": "alice",
		"attack_body": `{"status":"shipped","role":"admin"}`, "forbidden_fields": []string{"role"},
		"restore_body": `{"status":"open","role":"user"}`,
	}}
	return spec
}

func TestAPIBASMassAssignmentPreviewAndScheduleWithoutWrites(t *testing.T) {
	hd := jobsHandler(t, true)
	h := jobsRouter(hd)
	ctx := context.Background()
	if rec := postAs(t, h, "/api/apibas/targets", boundTargetBody("mass-1", "shop/alice", "shop/bob"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d", rec.Code)
	}
	if rec := sendRaw(t, h, http.MethodPost, "/api/apibas/targets/mass-1/inventory", specBytes(t), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("import: %d", rec.Code)
	}
	plan := "/api/apibas/targets/mass-1/binding/plan"

	noAck := massAPISpec()
	noAck["allow_writes"] = false
	if rec := postAs(t, h, plan, noAck, auth.RoleAnalyst, "a1"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "allow_writes") {
		t.Errorf("mass assignment without allow_writes: %d %s", rec.Code, rec.Body.String())
	}
	bad := massAPISpec()
	bad["mass_assignments"].([]map[string]any)[0]["forbidden_fields"] = []string{"isAdmin"}
	if rec := postAs(t, h, plan, bad, auth.RoleAnalyst, "a1"); rec.Code != http.StatusBadRequest {
		t.Errorf("a forbidden field the attack does not set: %d", rec.Code)
	}
	rec := postAs(t, h, plan, massAPISpec(), auth.RoleAnalyst, "a1")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "mass_assignment") || !strings.Contains(rec.Body.String(), `"write":true`) {
		t.Fatalf("preview: %d %s", rec.Code, rec.Body.String())
	}
	if rec := putAs(t, h, "/api/apibas/targets/mass-1/binding", massAPISpec(), auth.RoleAdmin, "admin1"); rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	// A scheduled run without writes leaves the mass-assignment check out and still builds.
	without, err := hd.buildBoundPlan(ctx, "mass-1", false)
	if err != nil || without.Spec.AllowWrites || len(without.Spec.MassAssignments) != 0 {
		t.Fatalf("scheduled plan without writes: allow %v mass %d err %v", without.Spec.AllowWrites, len(without.Spec.MassAssignments), err)
	}
	with, err := hd.buildBoundPlan(ctx, "mass-1", true)
	if err != nil || len(with.Spec.MassAssignments) != 1 {
		t.Errorf("a manual run lost the mass-assignment check: %v", err)
	}
}
