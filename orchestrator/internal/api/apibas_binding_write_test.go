package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
)

func writeBindSpec(allow bool) map[string]any {
	w := func() map[string]any {
		return map[string]any{"attack_body": `{"status":"hacked"}`, "restore_body": `{"status":"open"}`, "ignore_fields": []string{"updated_at"}}
	}
	return map[string]any{
		"allow_writes": allow,
		"identities":   []map[string]string{{"name": "alice", "credential_ref": "shop/alice"}, {"name": "bob", "credential_ref": "shop/bob"}},
		"objects": []map[string]any{
			{"operation": "PATCH /v2/orders/{orderId}", "params": map[string]string{"orderId": "ORD-A1"}, "owner": "alice", "write": w()},
			{"operation": "PATCH /v2/orders/{orderId}", "params": map[string]string{"orderId": "ORD-B1"}, "owner": "bob", "write": w()},
		},
	}
}

func TestAPIBASWriteBindingPreviewAndStore(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	if rec := postAs(t, h, "/api/apibas/targets", boundTargetBody("bwr-1", "shop/alice", "shop/bob"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	if rec := sendRaw(t, h, http.MethodPost, "/api/apibas/targets/bwr-1/inventory", specBytes(t), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("import: %d", rec.Code)
	}
	plan := "/api/apibas/targets/bwr-1/binding/plan"

	// Writes without the acknowledgement are refused.
	if rec := postAs(t, h, plan, writeBindSpec(false), auth.RoleAnalyst, "a1"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "allow_writes") {
		t.Errorf("writes without allow_writes: %d %s", rec.Code, rec.Body.String())
	}
	// With it, the preview marks the scenarios as writes and states the restore risk.
	rec := postAs(t, h, plan, writeBindSpec(true), auth.RoleAnalyst, "a1")
	if rec.Code != http.StatusOK {
		t.Fatalf("preview: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if decode(t, rec)["scenarios"].(float64) != 2 || !strings.Contains(body, `"write":true`) || !strings.Contains(body, "restore request") {
		t.Errorf("preview: %s", body)
	}
	// Storing and running it is the same path as any bound job.
	if rec := putAs(t, h, "/api/apibas/targets/bwr-1/binding", writeBindSpec(true), auth.RoleAdmin, "admin1"); rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	// This lab target has no registered paths, so a write job is refused before anything is queued.
	rec = postAs(t, h, "/api/apibas/targets/bwr-1/binding/jobs", map[string]any{"key": "bwr-key-1"}, auth.RoleAdmin, "admin1")
	if rec.Code != http.StatusForbidden {
		t.Errorf("write job on a target with no allowed paths: %d %s, want 403", rec.Code, rec.Body.String())
	}
}
