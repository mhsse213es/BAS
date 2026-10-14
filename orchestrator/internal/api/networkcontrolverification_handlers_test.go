package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/networkefficacy"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func createTestControlExpectationImport(t *testing.T, h *Handler, pool *pgxpool.Pool, body map[string]any) string {
	t.Helper()
	req := networkControlExpectationImportReq(t, pool, body)
	rec := callAuthed(h.CreateNetworkControlExpectationImport, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create control expectation import: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return created.ID
}

// runDiscoveryAgainstOpenPort triggers a real network discovery run
// against a freshly-opened local TCP listener, returning the run's ID.
// Mirrors internal/api/networkpath_handlers_test.go's own precedent for
// getting a real NetworkObservation into a test without a live remote
// host.
func runDiscoveryAgainstOpenPort(t *testing.T, h *Handler, pool *pgxpool.Pool, host string, port int) string {
	t.Helper()
	discoveryReq := networkDiscoveryReq(t, pool, map[string]any{"targets": []map[string]any{{"host": host, "port": port}}})
	rec := callAuthed(h.TriggerNetworkDiscoveryRun, discoveryReq)
	if rec.Code != http.StatusCreated {
		t.Fatalf("trigger discovery: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		RunID string `json:"runId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	return resp.RunID
}

func TestVerifyNetworkControlExpectations_BlockExpectationWithMatchingEvidence_Met(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		openPort := ln.Addr().(*net.TCPAddr).Port

		runID := runDiscoveryAgainstOpenPort(t, h, pool, "127.0.0.1", openPort)
		expID := createTestControlExpectationImport(t, h, pool, map[string]any{
			"sourceType": "manual-declared",
			"expectations": []map[string]any{
				{"flowSourceCidr": "10.0.1.0/24", "flowDestCidr": "127.0.0.0/24", "flowPort": openPort, "flowProtocol": "tcp", "expectedAction": "block", "controlProduct": "opnsense"},
			},
		})

		body := map[string]any{
			"expectationImportId": expID,
			"discoveryRunId":      runID,
			"firewallEvidence": []map[string]any{
				{"sourceIp": "10.0.1.5", "destIp": "127.0.0.1", "port": openPort, "protocol": "tcp", "action": "block", "timestamp": "2026-10-14T10:00:00Z", "source": "synthetic"},
			},
		}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "ncv-op-met", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-control-verifications", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.VerifyNetworkControlExpectations, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var results []networkefficacy.EfficacyResult
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(results) != 1 || results[0].Verdict != networkefficacy.VerdictMet {
			t.Fatalf("got %+v, want one result with verdict met", results)
		}
	})
}

func TestVerifyNetworkControlExpectations_NoMatchingObservation_InconclusiveWithoutCallingVerify(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		openPort := ln.Addr().(*net.TCPAddr).Port

		// Discovery run observes 127.0.0.1, but the expectation declares
		// a completely different, unrelated destination flow -- no
		// observation will ever match it.
		runID := runDiscoveryAgainstOpenPort(t, h, pool, "127.0.0.1", openPort)
		expID := createTestControlExpectationImport(t, h, pool, map[string]any{
			"sourceType": "manual-declared",
			"expectations": []map[string]any{
				{"flowSourceCidr": "10.0.1.0/24", "flowDestCidr": "10.0.9.0/24", "flowPort": 443, "expectedAction": "block", "controlProduct": "opnsense"},
			},
		})

		body := map[string]any{"expectationImportId": expID, "discoveryRunId": runID}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "ncv-op-nomatch", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-control-verifications", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.VerifyNetworkControlExpectations, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var results []networkefficacy.EfficacyResult
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(results) != 1 || results[0].Verdict != networkefficacy.VerdictInconclusive {
			t.Fatalf("got %+v, want one inconclusive result", results)
		}
		if results[0].Reason == "" {
			t.Fatal("want a non-empty reason explaining no observation matched")
		}
	})
}

func TestVerifyNetworkControlExpectations_UnknownExpectationImportReturns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := map[string]any{"expectationImportId": "nonexistent-id", "discoveryRunId": "also-nonexistent"}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "ncv-op-404", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-control-verifications", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.VerifyNetworkControlExpectations, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestVerifyNetworkControlExpectations_MissingRequiredFieldsRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := map[string]any{"expectationImportId": "some-id"}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "ncv-op-missing", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-control-verifications", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.VerifyNetworkControlExpectations, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestVerifyNetworkControlExpectations_OversizedBodyRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "ncv-op-oversize", "pw12345678", string(auth.RoleAnalyst), true)
		oversized := make([]byte, maxNetworkControlVerificationRequestBytes+1)
		for i := range oversized {
			oversized[i] = 'x'
		}
		req := authedRequest(t, http.MethodPost, "/api/network-control-verifications", bytes.NewReader(oversized), auth.RoleAnalyst, userID)
		rec := callAuthed(h.VerifyNetworkControlExpectations, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}
