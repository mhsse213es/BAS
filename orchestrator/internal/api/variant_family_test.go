package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func variantHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
}

func createFamilyReq(body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/payload-families", bytes.NewReader(b))
}

// TestGetPayloadFamilies_IncludesNewlyCreated pins the list + create
// contract. GetPayloadFamilies is never actually empty in practice — the
// schema auto-seeds ~19 default families (T1016/T1033/T1049/T1057/
// T1059.001/T1082) on creation — so this asserts the count increases by
// exactly 1 and the new entry appears, rather than an empty starting state.
func TestGetPayloadFamilies_IncludesNewlyCreated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)

		before := httptest.NewRecorder()
		h.GetPayloadFamilies(before, httptest.NewRequest(http.MethodGet, "/api/payload-families", nil))
		if before.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", before.Code)
		}
		var baseline []map[string]any
		json.Unmarshal(before.Body.Bytes(), &baseline)

		createRec := httptest.NewRecorder()
		h.CreatePayloadFamily(createRec, createFamilyReq(map[string]any{
			"techniqueId": "t1003.001", "name": "lsass-recon", "payload": "whoami /all",
		}))
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create: status = %d, want 201, body = %s", createRec.Code, createRec.Body.String())
		}

		after := httptest.NewRecorder()
		h.GetPayloadFamilies(after, httptest.NewRequest(http.MethodGet, "/api/payload-families", nil))
		var out []map[string]any
		json.Unmarshal(after.Body.Bytes(), &out)
		if len(out) != len(baseline)+1 {
			t.Fatalf("family count = %d, want baseline(%d)+1", len(out), len(baseline))
		}
		var found map[string]any
		for _, f := range out {
			if f["name"] == "lsass-recon" {
				found = f
			}
		}
		if found == nil {
			t.Fatal("newly created family not found in list")
		}
		if found["techniqueId"] != "T1003.001" {
			t.Errorf("techniqueId = %v, want T1003.001 (uppercased/trimmed)", found["techniqueId"])
		}
	})
}

func TestCreatePayloadFamily_ValidationErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		cases := []struct {
			name string
			body map[string]any
		}{
			{"missing techniqueId", map[string]any{"name": "x", "payload": "echo hi"}},
			{"missing name", map[string]any{"techniqueId": "T1003.001", "payload": "echo hi"}},
			{"missing payload", map[string]any{"techniqueId": "T1003.001", "name": "x"}},
		}
		for _, c := range cases {
			rec := httptest.NewRecorder()
			h.CreatePayloadFamily(rec, createFamilyReq(c.body))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400", c.name, rec.Code)
			}
		}
	})
}

func TestCreatePayloadFamily_MalformedJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		req := httptest.NewRequest(http.MethodPost, "/api/payload-families", strings.NewReader(`{"name":`))
		rec := httptest.NewRecorder()
		h.CreatePayloadFamily(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestCreatePayloadFamily_DuplicateNameConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		body := map[string]any{"techniqueId": "T1003.001", "name": "dup-name", "payload": "echo hi"}
		rec1 := httptest.NewRecorder()
		h.CreatePayloadFamily(rec1, createFamilyReq(body))
		if rec1.Code != http.StatusCreated {
			t.Fatalf("first create: status = %d, want 201", rec1.Code)
		}
		rec2 := httptest.NewRecorder()
		h.CreatePayloadFamily(rec2, createFamilyReq(body))
		if rec2.Code != http.StatusConflict {
			t.Fatalf("duplicate create: status = %d, want 409, body = %s", rec2.Code, rec2.Body.String())
		}
	})
}

// TestCreatePayloadFamily_Defaults pins the purpose/riskLevel/executor
// defaults applied when the caller omits them.
func TestCreatePayloadFamily_Defaults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		rec := httptest.NewRecorder()
		h.CreatePayloadFamily(rec, createFamilyReq(map[string]any{
			"techniqueId": "T1003.001", "name": "defaults-test", "payload": "echo hi",
		}))
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
		}

		listRec := httptest.NewRecorder()
		h.GetTechniqueFamilies(listRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "techniqueId", "T1003.001"))
		var out []map[string]any
		json.Unmarshal(listRec.Body.Bytes(), &out)
		if len(out) != 1 {
			t.Fatalf("expected 1 family (T1003.001 has no seeded families), got %d", len(out))
		}
		if out[0]["purpose"] != "recon" {
			t.Errorf("purpose = %v, want recon (default)", out[0]["purpose"])
		}
		if out[0]["riskLevel"] != "SAFE" {
			t.Errorf("riskLevel = %v, want SAFE (default)", out[0]["riskLevel"])
		}
		if out[0]["executor"] != "powershell" {
			t.Errorf("executor = %v, want powershell (default)", out[0]["executor"])
		}
	})
}

func TestGetTechniqueFamilies_FiltersToOneTechnique(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		h.CreatePayloadFamily(httptest.NewRecorder(), createFamilyReq(map[string]any{
			"techniqueId": "T1003.001", "name": "fam-a", "payload": "echo a",
		}))
		h.CreatePayloadFamily(httptest.NewRecorder(), createFamilyReq(map[string]any{
			"techniqueId": "T1021.001", "name": "fam-b", "payload": "echo b",
		}))

		rec := httptest.NewRecorder()
		h.GetTechniqueFamilies(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "techniqueId", "T1003.001"))
		var out []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 1 || out[0]["name"] != "fam-a" {
			t.Fatalf("families = %+v, want just fam-a", out)
		}
	})
}

func TestDeletePayloadFamily_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		rec := httptest.NewRecorder()
		h.DeletePayloadFamily(rec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestDeletePayloadFamily_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		createRec := httptest.NewRecorder()
		h.CreatePayloadFamily(createRec, createFamilyReq(map[string]any{
			"techniqueId": "T1003.001", "name": "to-delete", "payload": "echo hi",
		}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)

		delRec := httptest.NewRecorder()
		h.DeletePayloadFamily(delRec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", created.ID))
		if delRec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", delRec.Code)
		}

		listRec := httptest.NewRecorder()
		h.GetTechniqueFamilies(listRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "techniqueId", "T1003.001"))
		var out []map[string]any
		json.Unmarshal(listRec.Body.Bytes(), &out)
		if len(out) != 0 {
			t.Fatalf("expected 0 families after delete, got %d", len(out))
		}
	})
}
