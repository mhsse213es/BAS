package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/verification"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func detectverifyHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithVerificationStore(verification.NewStore(pool))
}

func detectverifyConfigReq(body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/detectverify/configs", bytes.NewReader(b))
}

// fakeDetectConnector is a no-network Connector used by handler tests so
// TestDetectionConnector can be exercised without a real Entra/Sentinel/Graph
// endpoint.
type fakeDetectConnector struct {
	testErr error
	result  detectverify.VerifyResult // defaults to the zero value (Verdict="" reads as NotDetected)
}

func (f *fakeDetectConnector) Verify(ctx context.Context, req detectverify.VerifyRequest) (detectverify.VerifyResult, error) {
	return f.result, nil
}
func (f *fakeDetectConnector) TestConnection(ctx context.Context) error { return f.testErr }

func TestListDetectionConnectors_EmptyAndPopulated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := detectverifyHandler(t, pool)
		rec := httptest.NewRecorder()
		h.ListDetectionConnectors(rec, httptest.NewRequest(http.MethodGet, "/api/detectverify/configs", nil))
		var empty []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &empty)
		if len(empty) != 0 {
			t.Fatalf("expected 0 connectors, got %d", len(empty))
		}

		createRec := httptest.NewRecorder()
		h.CreateDetectionConnector(createRec, detectverifyConfigReq(map[string]any{
			"name": "Prod Sentinel", "provider": "microsoft_sentinel", "workspaceId": "w1",
		}))
		if createRec.Code != http.StatusOK {
			t.Fatalf("create: status = %d, want 200, body = %s", createRec.Code, createRec.Body.String())
		}

		listRec := httptest.NewRecorder()
		h.ListDetectionConnectors(listRec, httptest.NewRequest(http.MethodGet, "/api/detectverify/configs", nil))
		var out []map[string]any
		json.Unmarshal(listRec.Body.Bytes(), &out)
		if len(out) != 1 || out[0]["name"] != "Prod Sentinel" || out[0]["provider"] != "microsoft_sentinel" {
			t.Fatalf("out = %+v, want 1 entry named Prod Sentinel/microsoft_sentinel", out)
		}
		if out[0]["verifyDelaySeconds"].(float64) != 120 {
			t.Fatalf("verifyDelaySeconds = %v, want default 120", out[0]["verifyDelaySeconds"])
		}
	})
}

func TestCreateDetectionConnector_ValidationErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := detectverifyHandler(t, pool)
		cases := []struct {
			name string
			body map[string]any
		}{
			{"missing name", map[string]any{"provider": "microsoft_sentinel"}},
			{"missing provider", map[string]any{"name": "x"}},
			{"invalid provider", map[string]any{"name": "x", "provider": "elastic"}},
		}
		for _, c := range cases {
			rec := httptest.NewRecorder()
			h.CreateDetectionConnector(rec, detectverifyConfigReq(c.body))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400", c.name, rec.Code)
			}
		}
	})
}

// TestUpdateDetectionConnector_PreservesMaskedSecret pins the "***" sentinel
// contract, same as SIEM configs: resubmitting the masked value must NOT
// overwrite the real stored secret.
func TestUpdateDetectionConnector_PreservesMaskedSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := detectverifyHandler(t, pool)
		createRec := httptest.NewRecorder()
		h.CreateDetectionConnector(createRec, detectverifyConfigReq(map[string]any{
			"name": "x", "provider": "microsoft_sentinel", "clientSecret": "real-secret",
		}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)

		b, _ := json.Marshal(map[string]any{"name": "x-renamed", "clientSecret": "***"})
		req := withURLParam(httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(b)), "id", created.ID)
		rec := httptest.NewRecorder()
		h.UpdateDetectionConnector(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}

		var name, secret string
		pool.QueryRow(context.Background(),
			`SELECT name, client_secret FROM detection_connectors WHERE id=$1`, created.ID,
		).Scan(&name, &secret)
		if name != "x-renamed" {
			t.Errorf("name = %q, want x-renamed", name)
		}
		if secret != "real-secret" {
			t.Errorf("client_secret = %q, want the original secret preserved", secret)
		}
	})
}

func TestDeleteDetectionConnector_NotFoundAndSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := detectverifyHandler(t, pool)
		notFoundRec := httptest.NewRecorder()
		h.DeleteDetectionConnector(notFoundRec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", "nope"))
		if notFoundRec.Code != http.StatusNotFound {
			t.Fatalf("not found: status = %d, want 404", notFoundRec.Code)
		}

		createRec := httptest.NewRecorder()
		h.CreateDetectionConnector(createRec, detectverifyConfigReq(map[string]any{"name": "x", "provider": "microsoft_defender"}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)

		delRec := httptest.NewRecorder()
		h.DeleteDetectionConnector(delRec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", created.ID))
		if delRec.Code != http.StatusOK {
			t.Fatalf("delete: status = %d, want 200", delRec.Code)
		}
		var n int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM detection_connectors WHERE id=$1`, created.ID).Scan(&n)
		if n != 0 {
			t.Fatalf("expected the connector to be gone, found %d rows", n)
		}
	})
}

func TestTestDetectionConnector_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := detectverifyHandler(t, pool)
		rec := httptest.NewRecorder()
		h.TestDetectionConnector(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestTestDetectionConnector_SuccessAndFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := detectverifyHandler(t, pool)
		h.detectVerifyConnector = func(cfg detectverify.Config) (detectverify.Connector, error) {
			if cfg.Name == "bad" {
				return &fakeDetectConnector{testErr: errors.New("auth failed")}, nil
			}
			return &fakeDetectConnector{}, nil
		}

		createRec := httptest.NewRecorder()
		h.CreateDetectionConnector(createRec, detectverifyConfigReq(map[string]any{"name": "good", "provider": "microsoft_sentinel"}))
		var good struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &good)

		rec := httptest.NewRecorder()
		h.TestDetectionConnector(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", good.ID))
		var out struct {
			OK bool `json:"ok"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if !out.OK {
			t.Fatalf("expected ok:true, body = %s", rec.Body.String())
		}

		createRec2 := httptest.NewRecorder()
		h.CreateDetectionConnector(createRec2, detectverifyConfigReq(map[string]any{"name": "bad", "provider": "microsoft_sentinel"}))
		var bad struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec2.Body.Bytes(), &bad)

		rec2 := httptest.NewRecorder()
		h.TestDetectionConnector(rec2, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", bad.ID))
		var out2 struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		json.Unmarshal(rec2.Body.Bytes(), &out2)
		if out2.OK || out2.Error == "" {
			t.Fatalf("expected ok:false with an error, got %+v", out2)
		}
	})
}
