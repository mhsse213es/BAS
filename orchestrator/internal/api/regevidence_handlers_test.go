package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/regobligation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// createTestEvidenceSnapshot mirrors createTestObligation's pattern.
// It returns ("", code) when creation failed, so rejection tests can
// assert on the status code without decoding a body that isn't there.
func createTestEvidenceSnapshot(t *testing.T, h *Handler, pool *pgxpool.Pool, body map[string]any) (string, int) {
	t.Helper()
	userID := seedUser(t, pool, "regevidence-op", "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	req := authedRequest(t, http.MethodPost, "/api/regulatory-evidence-snapshots", bytes.NewReader(b), auth.RoleAnalyst, userID)
	rec := callAuthed(h.CreateEvidenceSnapshot, req)
	if rec.Code != http.StatusCreated {
		return "", rec.Code
	}
	var created regobligation.EvidenceSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created snapshot: %v", err)
	}
	return created.ID, rec.Code
}

func TestCreateEvidenceSnapshot_Valid_Created(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		obligationID := createTestObligation(t, h, pool, validObligationBody())

		id, code := createTestEvidenceSnapshot(t, h, pool, map[string]any{
			"obligationId":     obligationID,
			"controlMappingId": "cm-1",
			"capabilityName":   "zoneisolation.isolation-check",
			"status":           "captured",
			"capturedOutcome":  "no-violation-found",
			"importReferences": map[string]string{"topologyImportId": "topo-1", "isolationImportId": "iso-1"},
		})
		if code != http.StatusCreated {
			t.Fatalf("expected 201, got %d", code)
		}
		if id == "" {
			t.Fatal("expected a non-empty snapshot id")
		}
	})
}

func TestCreateEvidenceSnapshot_ControlMappingIDNotFound_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		obligationID := createTestObligation(t, h, pool, validObligationBody())

		_, code := createTestEvidenceSnapshot(t, h, pool, map[string]any{
			"obligationId":     obligationID,
			"controlMappingId": "cm-does-not-exist",
			"capabilityName":   "zoneisolation.isolation-check",
			"status":           "captured",
			"capturedOutcome":  "no-violation-found",
		})
		if code != http.StatusBadRequest {
			t.Fatalf("expected 400 for an unknown controlMappingId, got %d", code)
		}
	})
}

func TestCreateEvidenceSnapshot_ObligationNotFound_Returns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		_, code := createTestEvidenceSnapshot(t, h, pool, map[string]any{
			"obligationId":     "nonexistent-obligation",
			"controlMappingId": "cm-1",
			"capabilityName":   "zoneisolation.isolation-check",
			"status":           "captured",
			"capturedOutcome":  "no-violation-found",
		})
		if code != http.StatusNotFound {
			t.Fatalf("expected 404 for a nonexistent obligation, got %d", code)
		}
	})
}

func TestCreateEvidenceSnapshot_CapabilityNameMismatch_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		obligationID := createTestObligation(t, h, pool, validObligationBody())

		_, code := createTestEvidenceSnapshot(t, h, pool, map[string]any{
			"obligationId":     obligationID,
			"controlMappingId": "cm-1",
			"capabilityName":   "some-other-capability",
			"status":           "captured",
			"capturedOutcome":  "no-violation-found",
		})
		if code != http.StatusBadRequest {
			t.Fatalf("expected 400 for a mismatched capabilityName, got %d", code)
		}
	})
}

func TestCreateEvidenceSnapshot_CapturedStatusWithoutOutcome_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		obligationID := createTestObligation(t, h, pool, validObligationBody())

		_, code := createTestEvidenceSnapshot(t, h, pool, map[string]any{
			"obligationId":     obligationID,
			"controlMappingId": "cm-1",
			"capabilityName":   "zoneisolation.isolation-check",
			"status":           "captured",
		})
		if code != http.StatusBadRequest {
			t.Fatalf("expected 400 when status=captured has no capturedOutcome, got %d", code)
		}
	})
}

// TestCreateEvidenceSnapshot_IncompleteStatus_PersistsDistinctly --
// Review Focus #1: an incomplete snapshot must never be silently
// dropped or indistinguishable from a captured one when listed.
func TestCreateEvidenceSnapshot_IncompleteStatus_PersistsDistinctly(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		obligationID := createTestObligation(t, h, pool, validObligationBody())

		id, code := createTestEvidenceSnapshot(t, h, pool, map[string]any{
			"obligationId":     obligationID,
			"controlMappingId": "cm-1",
			"capabilityName":   "zoneisolation.isolation-check",
			"status":           "incomplete",
			"incompleteReason": "topology import was not yet available at assessment time",
		})
		if code != http.StatusCreated {
			t.Fatalf("expected 201, got %d", code)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/regulatory-evidence-snapshots?obligationId="+obligationID, nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListEvidenceSnapshots, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list: expected 200, got %d: %s", listRec.Code, listRec.Body.String())
		}
		var list []regobligation.EvidenceSnapshot
		if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var found *regobligation.EvidenceSnapshot
		for i := range list {
			if list[i].ID == id {
				found = &list[i]
			}
		}
		if found == nil {
			t.Fatalf("expected snapshot %s in list, got %+v", id, list)
		}
		if found.Status != regobligation.SnapshotIncomplete {
			t.Errorf("expected status %q, got %q", regobligation.SnapshotIncomplete, found.Status)
		}
		if found.IncompleteReason == "" {
			t.Error("expected a non-empty incompleteReason to be preserved")
		}
	})
}

// TestCreateEvidenceSnapshot_ServerAssignedFields_OverwriteCallerValues
// -- Review Focus #3: a caller-supplied obligationVersion/capturedAt
// must be ignored and overwritten by the server, not merely present.
func TestCreateEvidenceSnapshot_ServerAssignedFields_OverwriteCallerValues(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		obligationID := createTestObligation(t, h, pool, validObligationBody())

		data, _ := json.Marshal(map[string]any{
			"obligationId":      obligationID,
			"controlMappingId":  "cm-1",
			"capabilityName":    "zoneisolation.isolation-check",
			"status":            "captured",
			"capturedOutcome":   "no-violation-found",
			"obligationVersion": "a bogus caller-supplied version that should never be trusted",
			"capturedAt":        "1999-01-01T00:00:00Z",
		})
		userID := seedUser(t, pool, "regevidence-spoof-op", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/regulatory-evidence-snapshots", bytes.NewReader(data), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateEvidenceSnapshot, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
		}
		var created regobligation.EvidenceSnapshot
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if created.ObligationVersion == "a bogus caller-supplied version that should never be trusted" {
			t.Error("expected obligationVersion to be server-assigned from the real obligation, not the caller's value")
		}
		if created.ObligationVersion != "RBI CSF 2016 (as amended)" {
			t.Errorf("expected the real obligation's version, got %q", created.ObligationVersion)
		}
		if created.CapturedAt.Year() == 1999 {
			t.Error("expected capturedAt to be server-assigned to the current time, not the caller's 1999 value")
		}
	})
}

func TestListEvidenceSnapshots_MissingObligationID_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := authedRequest(t, http.MethodGet, "/api/regulatory-evidence-snapshots", nil, auth.RoleViewer, "")
		rec := callAuthed(h.ListEvidenceSnapshots, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 when obligationId is missing, got %d", rec.Code)
		}
	})
}

func TestGetEvidenceSnapshot_NotFound_Returns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := authedRequest(t, http.MethodGet, "/api/regulatory-evidence-snapshots/nonexistent", nil, auth.RoleViewer, "")
		req = withURLParam(req, "id", "nonexistent")
		rec := callAuthed(h.GetEvidenceSnapshot, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}
