package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestImportIOCs_WritesEntriesAndReturnsCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		body := `{"entries":[{"type":"filename","value":"import-test-1.exe"},{"type":"mutex","value":"Global\\import-test-2"}]}`
		req := httptest.NewRequest(http.MethodPost, "/api/iocs/import", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ImportIOCs(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got["written"] != float64(2) {
			t.Errorf("written = %v, want 2", got["written"])
		}
	})
}

func TestImportIOCs_InvalidBody_Returns400(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodPost, "/api/iocs/import", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	h.ImportIOCs(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
