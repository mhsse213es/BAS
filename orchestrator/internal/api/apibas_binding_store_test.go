package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
)

func putAs(t *testing.T, h http.Handler, path string, body any, role auth.Role, user string) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	return sendRaw(t, h, http.MethodPut, path, string(raw), role, user)
}

func bindSpec() map[string]any {
	return map[string]any{
		"identities": []map[string]string{{"name": "alice", "credential_ref": "shop/alice"}, {"name": "bob", "credential_ref": "shop/bob"}},
		"objects": []map[string]any{
			{"operation": "GET /v2/orders/{orderId}", "params": map[string]string{"orderId": "ORD-A1"}, "owner": "alice", "protected_values": []string{"alice-private-note"}},
			{"operation": "GET /v2/orders/{orderId}", "params": map[string]string{"orderId": "ORD-B1"}, "owner": "bob"},
		},
	}
}

func TestAPIBASBindingStore(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	if rec := postAs(t, h, "/api/apibas/targets", targetBody("bst-1", "lab"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	path := "/api/apibas/targets/bst-1/binding"
	plan := path + "/plan"

	// Nothing stored yet: read 404, empty-body preview refused with a clear message, delete 404.
	if rec := sendRaw(t, h, http.MethodGet, path, "", auth.RoleAdmin, "admin1"); rec.Code != http.StatusNotFound {
		t.Errorf("get before save: %d", rec.Code)
	}
	if rec := sendRaw(t, h, http.MethodDelete, path, "", auth.RoleAdmin, "admin1"); rec.Code != http.StatusNotFound {
		t.Errorf("delete before save: %d", rec.Code)
	}
	// Saving needs an inventory.
	if rec := putAs(t, h, path, bindSpec(), auth.RoleAdmin, "admin1"); rec.Code != http.StatusNotFound {
		t.Errorf("save without an inventory: %d, want 404", rec.Code)
	}
	if rec := sendRaw(t, h, http.MethodPost, "/api/apibas/targets/bst-1/inventory", specBytes(t), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("import: %d", rec.Code)
	}
	if rec := sendRaw(t, h, http.MethodPost, plan, "", auth.RoleAnalyst, "a1"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "no test data stored") {
		t.Errorf("empty-body preview with nothing stored: %d %s", rec.Code, rec.Body.String())
	}

	// A spec that does not bind is refused and nothing is stored.
	bad := bindSpec()
	bad["objects"].([]map[string]any)[0]["owner"] = "mallory"
	if rec := putAs(t, h, path, bad, auth.RoleAdmin, "admin1"); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown owner saved: %d", rec.Code)
	}
	if rec := sendRaw(t, h, http.MethodGet, path, "", auth.RoleAdmin, "admin1"); rec.Code != http.StatusNotFound {
		t.Errorf("a refused spec was stored: %d", rec.Code)
	}
	// Unknown fields are refused.
	withExtra := bindSpec()
	withExtra["credential_value"] = "hunter2"
	if rec := putAs(t, h, path, withExtra, auth.RoleAdmin, "admin1"); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown field accepted: %d", rec.Code)
	}

	// Save, read back, preview from the stored spec.
	rec := putAs(t, h, path, bindSpec(), auth.RoleAdmin, "admin1")
	if rec.Code != http.StatusOK || decode(t, rec)["scenarios"].(float64) != 2 {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	rec = sendRaw(t, h, http.MethodGet, path, "", auth.RoleAdmin, "admin1")
	m := decode(t, rec)
	if rec.Code != http.StatusOK || m["stale"] != false || m["updated_by"] != "admin1" || m["validated_inventory"].(float64) != 1 {
		t.Fatalf("get: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "alice-private-note") || !strings.Contains(rec.Body.String(), "shop/alice") {
		t.Errorf("stored spec lost its content: %s", rec.Body.String())
	}
	rec = sendRaw(t, h, http.MethodPost, plan, "", auth.RoleAnalyst, "a1")
	if rec.Code != http.StatusOK || decode(t, rec)["scenarios"].(float64) != 2 {
		t.Errorf("preview from stored spec: %d %s", rec.Code, rec.Body.String())
	}

	// Replacing keeps one spec; a different inventory marks it stale.
	rec = putAs(t, h, path, bindSpec(), auth.RoleAdmin, "admin2")
	if rec.Code != http.StatusOK {
		t.Fatalf("replace: %d", rec.Code)
	}
	if got := decode(t, sendRaw(t, h, http.MethodGet, path, "", auth.RoleAdmin, "admin1"))["updated_by"]; got != "admin2" {
		t.Errorf("updated_by after replace: %v", got)
	}
	changed := strings.Replace(specBytes(t), "/v2/catalog", "/v2/catalogue", 1)
	if rec := sendRaw(t, h, http.MethodPost, "/api/apibas/targets/bst-1/inventory", changed, auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("second import: %d %s", rec.Code, rec.Body.String())
	}
	if m := decode(t, sendRaw(t, h, http.MethodGet, path, "", auth.RoleAdmin, "admin1")); m["stale"] != true || m["newest_inventory"].(float64) != 2 {
		t.Errorf("stale flag after a new inventory: %v", m)
	}

	// Permissions: an analyst can neither read nor write the spec; unauthenticated is refused.
	if rec := sendRaw(t, h, http.MethodGet, path, "", auth.RoleAnalyst, "a1"); rec.Code != http.StatusForbidden {
		t.Errorf("analyst read: %d, want 403", rec.Code)
	}
	if rec := putAs(t, h, path, bindSpec(), auth.RoleAnalyst, "a1"); rec.Code != http.StatusForbidden {
		t.Errorf("analyst write: %d, want 403", rec.Code)
	}

	// Delete, then it is gone and the target is untouched.
	if rec := sendRaw(t, h, http.MethodDelete, path, "", auth.RoleAdmin, "admin1"); rec.Code != http.StatusNoContent {
		t.Errorf("delete: %d", rec.Code)
	}
	if rec := sendRaw(t, h, http.MethodGet, path, "", auth.RoleAdmin, "admin1"); rec.Code != http.StatusNotFound {
		t.Errorf("get after delete: %d", rec.Code)
	}
}
