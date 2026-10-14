package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestReferenceComponent_Returns200AndComponentID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, _ := registryEngine(t, pool)
		h := &Handler{db: pool, engine: e}
		body, _ := json.Marshal(map[string]any{
			"framework": "art", "techniqueId": "T1059", "title": "ART T1059", "actionKey": "",
			"testIndex": 5, "libraryVersion": "v1.2.3", "supportedOS": []string{"windows"},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/content-registry/components/reference", bytes.NewReader(body))
		w := httptest.NewRecorder()
		h.ReferenceComponent(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})
}
