package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
)

func TestAPIBASTargetListShowsInventoryAndNeverCredentials(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	if rec := postAs(t, h, "/api/apibas/targets", targetBody("list-a", "lab"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register a: %d %s", rec.Code, rec.Body.String())
	}
	if rec := postAs(t, h, "/api/apibas/targets", targetBody("list-b", "staging"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register b: %d %s", rec.Code, rec.Body.String())
	}
	if rec := sendRaw(t, h, http.MethodPost, "/api/apibas/targets/list-a/inventory", specBytes(t), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("import: %d", rec.Code)
	}

	rec := getAsUser(t, h, "/api/apibas/targets", auth.RoleAnalyst, "a1")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// The credential references the targets were registered with must not appear in any form.
	if strings.Contains(body, "credential") || strings.Contains(body, "apibas_targets") {
		t.Errorf("the list exposes credential data: %s", body)
	}
	var withInv, without int
	for _, it := range decode(t, rec)["targets"].([]any) {
		tm := it.(map[string]any)
		switch tm["id"] {
		case "list-a":
			inv, _ := tm["inventory"].(map[string]any)
			if inv == nil || inv["version"].(float64) != 1 || inv["operations"].(float64) != 11 {
				t.Errorf("list-a inventory: %v", tm["inventory"])
			}
			withInv++
		case "list-b":
			if tm["inventory"] != nil {
				t.Errorf("list-b has no inventory but shows %v", tm["inventory"])
			}
			without++
		}
	}
	if withInv != 1 || without != 1 {
		t.Errorf("targets found: with inventory %d, without %d", withInv, without)
	}
	if rec := getAsUser(t, h, "/api/apibas/targets", "", ""); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Errorf("unauthenticated list: %d", rec.Code)
	}
}
