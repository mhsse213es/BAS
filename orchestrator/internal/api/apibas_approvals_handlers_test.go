package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
)

func getAsUser(t *testing.T, h http.Handler, path string, role auth.Role, user string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: user, Role: role}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAPIBASApprovalFlow(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	for _, tc := range [][2]string{{"appr-prod", "production"}, {"appr-stg", "staging"}} {
		if rec := postAs(t, h, "/api/apibas/targets", targetBody(tc[0], tc[1]), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
			t.Fatalf("register %s: %d %s", tc[0], rec.Code, rec.Body.String())
		}
	}
	req := map[string]any{"target_id": "appr-prod", "fixture": "orders-two-tenant", "scenario_ids": []string{"API-BAS-AUTHZ-001"}}

	// Only production targets need an approval; unknown targets and out-of-scope scenarios are refused.
	stg := map[string]any{"target_id": "appr-stg", "fixture": "orders-two-tenant", "scenario_ids": []string{"API-BAS-AUTHZ-001"}}
	if rec := postAs(t, h, "/api/apibas/approvals", stg, auth.RoleAdmin, "admin1"); rec.Code != http.StatusBadRequest {
		t.Errorf("staging target: %d, want 400", rec.Code)
	}
	if rec := postAs(t, h, "/api/apibas/approvals", map[string]any{"target_id": "nope", "fixture": "f", "scenario_ids": []string{"x"}}, auth.RoleAdmin, "admin1"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown target: %d, want 404", rec.Code)
	}
	if rec := postAs(t, h, "/api/apibas/approvals", map[string]any{"target_id": "appr-prod", "fixture": "f", "scenario_ids": []string{"API-BAS-AUTHZ-002"}}, auth.RoleAdmin, "admin1"); rec.Code != http.StatusForbidden {
		t.Errorf("scenario outside the target: %d, want 403", rec.Code)
	}
	// An analyst may request but not approve.
	rec := postAs(t, h, "/api/apibas/approvals", req, auth.RoleAnalyst, "analyst1")
	if rec.Code != http.StatusCreated {
		t.Fatalf("request: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID, Status string
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	approve := "/api/apibas/approvals/" + created.ID + "/approve"
	if rec := postAs(t, h, approve, map[string]any{}, auth.RoleAnalyst, "analyst1"); rec.Code != http.StatusForbidden {
		t.Errorf("analyst approving: %d, want 403 from RBAC", rec.Code)
	}
	// The requester cannot approve their own request, even as an admin.
	own := postAs(t, h, "/api/apibas/approvals", req, auth.RoleAdmin, "admin1")
	var ownReq struct{ ID string }
	_ = json.Unmarshal(own.Body.Bytes(), &ownReq)
	if rec := postAs(t, h, "/api/apibas/approvals/"+ownReq.ID+"/approve", map[string]any{}, auth.RoleAdmin, "admin1"); rec.Code != http.StatusForbidden {
		t.Errorf("self approval: %d, want 403", rec.Code)
	}
	// A different admin approves once; a second approval is a conflict.
	if rec := postAs(t, h, approve, map[string]any{}, auth.RoleAdmin, "admin2"); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	if rec := postAs(t, h, approve, map[string]any{}, auth.RoleAdmin, "admin3"); rec.Code != http.StatusConflict {
		t.Errorf("second approval: %d, want 409", rec.Code)
	}
	if rec := postAs(t, h, "/api/apibas/approvals/00000000-0000-0000-0000-000000000000/approve", map[string]any{}, auth.RoleAdmin, "admin2"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown approval: %d, want 404", rec.Code)
	}
	got := getAsUser(t, h, "/api/apibas/approvals/"+created.ID, auth.RoleAnalyst, "analyst1")
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"status":"approved"`) || !strings.Contains(got.Body.String(), `"approved_by":"admin2"`) ||
		!strings.Contains(got.Body.String(), `"executable":false`) {
		t.Errorf("get: %d %s", got.Code, got.Body.String())
	}
	for action, resource := range map[string]string{"apibas.approval.request": "apibas-approval:" + created.ID, "apibas.approval.approve": "apibas-approval:" + created.ID} {
		if auditCount(t, action, resource) != 1 {
			t.Errorf("audit %s for %s missing", action, resource)
		}
	}
	if auditCount(t, "apibas.approval.refused", "apibas-approval:"+created.ID) != 1 {
		t.Error("refused second approval was not audited")
	}
}
