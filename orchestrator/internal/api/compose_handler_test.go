package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/testutil"
	"github.com/audspect/bas/internal/threatidentity"
)

func TestComposeContent_Returns200AndVersionID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := contentregistry.New(pool, testutil.DevVerifier())
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1059", "c1", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1053", "c2", "", "", 2, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(ctx, threatidentity.Incoming{Name: "APT-compose-handler"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}

		e, _, _ := registryEngine(t, pool)
		h := &Handler{db: pool, engine: e}
		body, _ := json.Marshal(map[string]any{"componentIds": []string{c1, c2}, "threatId": resolved.ThreatID})
		req := httptest.NewRequest(http.MethodPost, "/api/content-registry/compose", bytes.NewReader(body))
		w := httptest.NewRecorder()
		h.ComposeContent(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})
}

func TestComposeContent_RefusalReturns422(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := contentregistry.New(pool, testutil.DevVerifier())
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1059", "c1", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1053", "c2", "", "", 2, "v1", []string{"linux"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(ctx, threatidentity.Incoming{Name: "APT-compose-handler-refuse"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}

		e, _, _ := registryEngine(t, pool)
		h := &Handler{db: pool, engine: e}
		body, _ := json.Marshal(map[string]any{"componentIds": []string{c1, c2}, "threatId": resolved.ThreatID})
		req := httptest.NewRequest(http.MethodPost, "/api/content-registry/compose", bytes.NewReader(body))
		w := httptest.NewRecorder()
		h.ComposeContent(w, req)

		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("expected 422 on a no-common-OS refusal, got %d: %s", w.Code, w.Body.String())
		}
	})
}
