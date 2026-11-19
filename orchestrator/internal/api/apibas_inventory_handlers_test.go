package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
)

func specBytes(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../apibas/openapi/testdata/shop.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func sendRaw(t *testing.T, h http.Handler, method, path, body string, role auth.Role, user string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if role != "" {
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: user, Role: role}))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not JSON: %v: %s", err, rec.Body.String())
	}
	return m
}

func TestAPIBASInventoryImportAndRead(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	if rec := postAs(t, h, "/api/apibas/targets", targetBody("inv-t1", "lab"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	base := "/api/apibas/targets/inv-t1/inventory"
	spec := specBytes(t)

	// Authorization: an unauthenticated caller and a viewer cannot import; an analyst may read but not import.
	if rec := sendRaw(t, h, http.MethodPost, base, spec, "", ""); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Errorf("unauthenticated import: %d", rec.Code)
	}
	if rec := sendRaw(t, h, http.MethodPost, base, spec, auth.RoleViewer, "v1"); rec.Code != http.StatusForbidden {
		t.Errorf("viewer import: %d, want 403", rec.Code)
	}

	// Before any import there is no inventory.
	if rec := getAsUser(t, h, base, auth.RoleAdmin, "admin1"); rec.Code != http.StatusNotFound {
		t.Errorf("read before import: %d, want 404", rec.Code)
	}
	// Unknown target.
	if rec := sendRaw(t, h, http.MethodPost, "/api/apibas/targets/nope/inventory", spec, auth.RoleAdmin, "admin1"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown target: %d, want 404", rec.Code)
	}
	// A document in an unsupported version is a 400 with a reason, and stores nothing.
	rec := sendRaw(t, h, http.MethodPost, base, "swagger: '1.2'\npaths:\n  /a:\n    get: {}\n", auth.RoleAdmin, "admin1")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unsupported swagger version") {
		t.Errorf("swagger: %d %s", rec.Code, rec.Body.String())
	}
	if rec := getAsUser(t, h, base, auth.RoleAdmin, "admin1"); rec.Code != http.StatusNotFound {
		t.Errorf("a rejected import stored something: %d", rec.Code)
	}

	// First import: version 1, every operation added, classes counted, scope suggested, nothing applied.
	rec = sendRaw(t, h, http.MethodPost, base, spec, auth.RoleAdmin, "admin1")
	if rec.Code != http.StatusCreated {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	m := decode(t, rec)
	if m["version"].(float64) != 1 || m["operations"].(float64) != 11 {
		t.Errorf("import result: %v", m)
	}
	if m["classes"].(map[string]any)["object_level_authorization"].(float64) < 1 {
		t.Errorf("classes: %v", m["classes"])
	}
	if ch := m["changes"].(map[string]any); ch["added_total"].(float64) != 11 || ch["previous_version"].(float64) != 0 {
		t.Errorf("first-import changes: %v", ch)
	}
	if len(m["suggested_scope"].([]any)) == 0 {
		t.Error("no scope suggestion")
	}

	// Identical re-import changes nothing.
	rec = sendRaw(t, h, http.MethodPost, base, spec, auth.RoleAdmin, "admin1")
	if rec.Code != http.StatusOK || decode(t, rec)["unchanged"] != true {
		t.Errorf("identical re-import: %d %s", rec.Code, rec.Body.String())
	}

	// A changed document is version 2 and reports the difference: one route gone, one lost its authentication.
	changed := strings.Replace(spec, "  /v2/catalog:\n    get:\n      operationId: catalog\n      security: []\n", "  /v2/catalog2:\n    get:\n      operationId: catalog\n      security: []\n", 1)
	changed = strings.Replace(changed, "      operationId: listOrders\n", "      operationId: listOrders\n      security: []\n", 1)
	rec = sendRaw(t, h, http.MethodPost, base, changed, auth.RoleAdmin, "admin1")
	if rec.Code != http.StatusCreated {
		t.Fatalf("second import: %d %s", rec.Code, rec.Body.String())
	}
	ch := decode(t, rec)["changes"].(map[string]any)
	if ch["previous_version"].(float64) != 1 || ch["added_total"].(float64) != 1 || ch["removed_total"].(float64) != 1 || ch["auth_changed_total"].(float64) != 1 {
		t.Errorf("changes: %v", ch)
	}

	// Reads: newest, a named version, a class filter, an unknown class, a bad version.
	cur := decode(t, getAsUser(t, h, base, auth.RoleAnalyst, "a1"))
	if cur["version"].(float64) != 2 {
		t.Errorf("current version: %v", cur["version"])
	}
	v1 := decode(t, getAsUser(t, h, base+"?version=1", auth.RoleAnalyst, "a1"))
	if v1["version"].(float64) != 1 || len(v1["listed_operations"].([]any)) != 11 {
		t.Errorf("version 1: %v", v1["version"])
	}
	filtered := decode(t, getAsUser(t, h, base+"?class=file_upload", auth.RoleAnalyst, "a1"))
	if ops := filtered["listed_operations"].([]any); len(ops) != 1 {
		t.Errorf("file_upload filter returned %d operations, want 1", len(ops))
	}
	if rec := getAsUser(t, h, base+"?class=bogus", auth.RoleAnalyst, "a1"); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown class: %d", rec.Code)
	}
	if rec := getAsUser(t, h, base+"?version=0", auth.RoleAnalyst, "a1"); rec.Code != http.StatusBadRequest {
		t.Errorf("version 0: %d", rec.Code)
	}
	if rec := getAsUser(t, h, base+"?version=99", auth.RoleAnalyst, "a1"); rec.Code != http.StatusNotFound {
		t.Errorf("missing version: %d", rec.Code)
	}
	vers := decode(t, getAsUser(t, h, base+"/versions", auth.RoleAnalyst, "a1"))["versions"].([]any)
	if len(vers) != 2 {
		t.Errorf("%d versions listed, want 2", len(vers))
	}
	if strings.Contains(getAsUser(t, h, base+"/versions", auth.RoleAnalyst, "a1").Body.String(), "listed_operations") {
		t.Error("the version list must not carry operations")
	}
}

func TestAPIBASInventoryNeverReturnsExampleValues(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	if rec := postAs(t, h, "/api/apibas/targets", targetBody("inv-t2", "lab"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d", rec.Code)
	}
	base := "/api/apibas/targets/inv-t2/inventory"
	if rec := sendRaw(t, h, http.MethodPost, base, specBytes(t), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("import: %d", rec.Code)
	}
	body := getAsUser(t, h, base, auth.RoleAdmin, "admin1").Body.String()
	if strings.Contains(body, "hunter2-super-secret-example") {
		t.Error("an example value from the specification came back through the API")
	}
}

func TestAPIBASInventoryOversizeIsRejected(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	if rec := postAs(t, h, "/api/apibas/targets", targetBody("inv-t3", "lab"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d", rec.Code)
	}
	big := strings.Repeat("a", 8<<20+10)
	if rec := sendRaw(t, h, http.MethodPost, "/api/apibas/targets/inv-t3/inventory", big, auth.RoleAdmin, "admin1"); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize: %d, want 413", rec.Code)
	}
}

func TestAPIBASInventoryDrift(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	if rec := postAs(t, h, "/api/apibas/targets", targetBody("inv-t4", "lab"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d", rec.Code)
	}
	base := "/api/apibas/targets/inv-t4/inventory"
	drift := base + "/drift"
	obs := map[string]any{"observed": []map[string]string{{"method": "GET", "path": "/v2/orders"}, {"method": "GET", "path": "/v1/legacy/dump"}}}

	// No inventory yet.
	if rec := postAs(t, h, drift, obs, auth.RoleAnalyst, "a1"); rec.Code != http.StatusNotFound {
		t.Errorf("drift before import: %d, want 404", rec.Code)
	}
	if rec := sendRaw(t, h, http.MethodPost, base, specBytes(t), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("import: %d", rec.Code)
	}
	rec := postAs(t, h, drift, obs, auth.RoleAnalyst, "a1")
	if rec.Code != http.StatusOK {
		t.Fatalf("drift: %d %s", rec.Code, rec.Body.String())
	}
	m := decode(t, rec)
	if m["undocumented_total"].(float64) != 1 || m["unserved_total"].(float64) != 10 {
		t.Errorf("drift: %v", m)
	}
	// Invalid input.
	for name, body := range map[string]any{
		"empty":         map[string]any{"observed": []any{}},
		"lower method":  map[string]any{"observed": []map[string]string{{"method": "get", "path": "/a"}}},
		"relative path": map[string]any{"observed": []map[string]string{{"method": "GET", "path": "a"}}},
		"unknown field": map[string]any{"observed": []map[string]string{{"method": "GET", "path": "/a"}}, "extra": 1},
	} {
		if rec := postAs(t, h, drift, body, auth.RoleAnalyst, "a1"); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, rec.Code)
		}
	}
}

func TestAPIBASInventoryImportsSwaggerAndGraphQL(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	if rec := postAs(t, h, "/api/apibas/targets", targetBody("inv-t5", "lab"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d", rec.Code)
	}
	base := "/api/apibas/targets/inv-t5/inventory"
	for name, file := range map[string]string{"swagger": "shop_swagger2.yaml", "graphql": "shop.graphql"} {
		b, err := os.ReadFile("../apibas/openapi/testdata/" + file)
		if err != nil {
			t.Fatal(err)
		}
		rec := sendRaw(t, h, http.MethodPost, base, string(b), auth.RoleAdmin, "admin1")
		if rec.Code != http.StatusCreated {
			t.Fatalf("%s import: %d %s", name, rec.Code, rec.Body.String())
		}
		got := getAsUser(t, h, base, auth.RoleAdmin, "admin1").Body.String()
		if strings.Contains(got, "hunter2-super-secret-example") {
			t.Errorf("%s: a default value came back through the API", name)
		}
		if name == "graphql" && (!strings.Contains(got, `"field":"order"`) || !strings.Contains(got, `"method":"QUERY"`)) {
			t.Errorf("graphql operations were not returned with method and field: %.300s", got)
		}
	}
}
