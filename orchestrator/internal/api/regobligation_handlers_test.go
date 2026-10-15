package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/regobligation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func validObligationBody() map[string]any {
	return map[string]any{
		"jurisdiction":    "India",
		"regulator":       "RBI",
		"sector":          "Banking",
		"entityType":      "Regulated Financial Institution",
		"title":           "Network segmentation for critical payment/banking systems",
		"obligationType":  "mandatory",
		"sourceReference": "RBI Cyber Security Framework for Banks",
		"effectiveDate":   "2016-06-02T00:00:00Z",
		"version":         "RBI CSF 2016 (as amended)",
		"controlMappings": []map[string]any{
			{"canonicalId": "cm-1", "controlName": "Segmentation", "capabilityName": "zoneisolation.isolation-check"},
		},
	}
}

// createTestObligation mirrors createTestTopologyImport's own pattern
// exactly: seeds its own user, builds the request, and runs it through
// callAuthed so auth.ClaimsFrom resolves inside the handler.
func createTestObligation(t *testing.T, h *Handler, pool *pgxpool.Pool, body map[string]any) string {
	t.Helper()
	userID := seedUser(t, pool, fmt.Sprintf("regobligation-op-%d", time.Now().UnixNano()), "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	req := authedRequest(t, http.MethodPost, "/api/regulatory-obligations", bytes.NewReader(b), auth.RoleAnalyst, userID)
	rec := callAuthed(h.CreateRegulatoryObligation, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create obligation: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created regobligation.Obligation
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created obligation: %v", err)
	}
	return created.ID
}

func TestCreateRegulatoryObligation_Valid_Created(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		id := createTestObligation(t, h, pool, validObligationBody())
		if id == "" {
			t.Fatal("expected a non-empty obligation id")
		}

		getReq := authedRequest(t, http.MethodGet, "/api/regulatory-obligations/"+id, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", id)
		rec := callAuthed(h.GetRegulatoryObligation, getReq)
		if rec.Code != http.StatusOK {
			t.Fatalf("get obligation: expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var got regobligation.Obligation
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Jurisdiction != "India" || got.Regulator != "RBI" {
			t.Errorf("round-tripped obligation mismatch: %+v", got)
		}
		if len(got.ControlMappings) != 1 || got.ControlMappings[0].CapabilityName != "zoneisolation.isolation-check" {
			t.Errorf("control mappings mismatch: %+v", got.ControlMappings)
		}
	})
}

func TestCreateRegulatoryObligation_InvalidObligationType_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validObligationBody()
		body["obligationType"] = "not-a-real-type"
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "regobligation-badtype", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/regulatory-obligations", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateRegulatoryObligation, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for an invalid obligationType, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateRegulatoryObligation_MissingControlMappings_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validObligationBody()
		body["controlMappings"] = []map[string]any{}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "regobligation-nocm", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/regulatory-obligations", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateRegulatoryObligation, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for zero control mappings, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateRegulatoryObligation_MissingRequiredFields_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validObligationBody()
		delete(body, "sourceReference")
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "regobligation-missing", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/regulatory-obligations", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateRegulatoryObligation, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for a missing sourceReference, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestListRegulatoryObligations_ReturnsCreated(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		id := createTestObligation(t, h, pool, validObligationBody())

		req := authedRequest(t, http.MethodGet, "/api/regulatory-obligations", nil, auth.RoleViewer, "")
		rec := callAuthed(h.ListRegulatoryObligations, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("list: expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var list []regobligation.Obligation
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
			t.Fatalf("decode: %v", err)
		}
		found := false
		for _, ob := range list {
			if ob.ID == id {
				found = true
			}
		}
		if !found {
			t.Errorf("expected created obligation %s in list, got %+v", id, list)
		}
	})
}

func TestGetRegulatoryObligation_NotFound_Returns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := authedRequest(t, http.MethodGet, "/api/regulatory-obligations/nonexistent", nil, auth.RoleViewer, "")
		req = withURLParam(req, "id", "nonexistent")
		rec := callAuthed(h.GetRegulatoryObligation, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}
