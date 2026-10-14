package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/otsafety"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func validOTSafetyImportBody() map[string]any {
	return map[string]any{
		"sourceType": "manual",
		"sensitiveZones": []map[string]any{
			{"zoneName": "ot", "tier": "ot", "note": "engineering workstation zone"},
		},
		"requiredTransits": []map[string]any{
			{"canonicalId": "rt-1", "fromZone": "corporate", "toZone": "ot", "viaZone": "dmz"},
		},
		"limitations": []string{"zone names are not cross-validated against a real network-topology import"},
	}
}

func TestCreateOTSafetyImport_Valid_Created(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		b, _ := json.Marshal(validOTSafetyImportBody())
		userID := seedUser(t, pool, "otsafety-op", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateOTSafetyImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var created otsafety.OTSafetyImport
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if created.ID == "" {
			t.Fatal("want non-empty ID")
		}
	})
}

func TestCreateOTSafetyImport_InvalidTier_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validOTSafetyImportBody()
		body["sensitiveZones"] = []map[string]any{{"zoneName": "ot", "tier": "critical"}}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "otsafety-op-badtier", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateOTSafetyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- an unknown tier must be rejected", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateOTSafetyImport_ZonesWithoutLimitations_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validOTSafetyImportBody()
		delete(body, "limitations")
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "otsafety-op-nolim", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateOTSafetyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- any SensitiveZones/RequiredTransits present requires non-empty Limitations", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateOTSafetyImport_EmptyZoneName_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validOTSafetyImportBody()
		body["sensitiveZones"] = []map[string]any{{"zoneName": "", "tier": "ot"}}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "otsafety-op-emptyzone", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateOTSafetyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- an empty zone name must be rejected", rec.Code, rec.Body.String())
		}
	})
}

func TestListAndGetOTSafetyImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		b, _ := json.Marshal(validOTSafetyImportBody())
		userID := seedUser(t, pool, "otsafety-op-rt", "pw12345678", string(auth.RoleAnalyst), true)
		createReq := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		createRec := callAuthed(h.CreateOTSafetyImport, createReq)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create status = %d, body = %s", createRec.Code, createRec.Body.String())
		}
		var created otsafety.OTSafetyImport
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create: %v", err)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/ot-safety-imports", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListOTSafetyImports, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}

		getReq := authedRequest(t, http.MethodGet, "/api/ot-safety-imports/"+created.ID, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", created.ID)
		getRec := callAuthed(h.GetOTSafetyImport, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
	})
}

// TestCreateOTSafetyImport_TierClinical_Accepted pins Phase 7B's
// extension of otsafety's tier validation: TierClinical must be
// accepted exactly as TierOT already is.
func TestCreateOTSafetyImport_TierClinical_Accepted(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validOTSafetyImportBody()
		body["sensitiveZones"] = []map[string]any{{"zoneName": "clinical", "tier": "clinical"}}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "otsafety-op-clinical", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateOTSafetyImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s, want 201 -- TierClinical must be accepted", rec.Code, rec.Body.String())
		}
	})
}

// TestCreateOTSafetyImport_StillRejectsUnknownTier proves the
// TierClinical extension is additive, not a loosening of the
// existing check -- an unrelated unknown tier must still be rejected.
func TestCreateOTSafetyImport_StillRejectsUnknownTier(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validOTSafetyImportBody()
		body["sensitiveZones"] = []map[string]any{{"zoneName": "x", "tier": "unknown-tier"}}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "otsafety-op-unknowntier", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateOTSafetyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- an unknown tier must still be rejected", rec.Code, rec.Body.String())
		}
	})
}
