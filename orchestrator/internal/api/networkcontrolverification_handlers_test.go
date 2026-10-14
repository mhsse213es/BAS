package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkefficacy"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// TestWindowForObservation_AnchorsToObservationTimestampNotWallClock
// reproduces a reviewer-found High-severity defect: the verify
// endpoint's evidence time window was computed once from time.Now() at
// request-processing time, with no relationship to when the
// NetworkObservation was actually taken. A recorded-fixture evidence
// timestamp close to the observation's own ObservedAt -- but far from
// wall-clock "now" -- must still match.
func TestWindowForObservation_AnchorsToObservationTimestampNotWallClock(t *testing.T) {
	farFromNow := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	obs := networkgraph.NetworkObservation{
		Target:     networkgraph.Target{Host: "10.0.2.5", Port: 443},
		State:      cloudgraph.Observed,
		Provenance: cloudgraph.Provenance{ObservedAt: farFromNow},
	}
	window := windowForObservation(obs)

	evidenceTimestamp := farFromNow.Add(5 * time.Minute)
	if evidenceTimestamp.Before(window.Start) || evidenceTimestamp.After(window.End) {
		t.Fatalf("window %+v does not bracket a timestamp 5 minutes after the observation's own ObservedAt (%v) -- the window must anchor to the observation, not to wall-clock time.Now()", window, farFromNow)
	}
	if time.Now().After(window.Start) && time.Now().Before(window.End) {
		t.Fatalf("window %+v brackets the current wall-clock time even though the observation happened in 2020 -- it is still anchored to time.Now(), not to obs.Provenance.ObservedAt", window)
	}
}

func observationWithTimestamp(ts time.Time) networkgraph.NetworkObservation {
	return networkgraph.NetworkObservation{
		Target:     networkgraph.Target{Host: "10.0.2.5", Port: 443},
		State:      cloudgraph.Observed,
		Provenance: cloudgraph.Provenance{ObservedAt: ts},
	}
}

// TestSelectMatchingObservation_MultipleMatches_MostRecentWins is a
// coverage-gap fix (reviewer Medium finding): selectMatchingObservation's
// "most recent Provenance.ObservedAt wins" tie-break (spec §4.3) had no
// dedicated test, unlike the parallel evidence-selection tie-break in
// internal/networkefficacy (TestVerifyControlExpectation_MultipleMatchingRecords_MostRecentWins).
// No code change accompanies this test -- the existing logic already
// implements the rule correctly; this closes the coverage gap.
func TestSelectMatchingObservation_MultipleMatches_MostRecentWins(t *testing.T) {
	now := time.Now()
	exp := networkefficacy.ControlExpectation{FlowSourceCIDR: "10.0.1.0/24", FlowDestCIDR: "10.0.2.0/24", FlowPort: 443}
	observations := []networkgraph.NetworkObservation{
		observationWithTimestamp(now.Add(-time.Hour)), // older match
		observationWithTimestamp(now),                 // newer match -- must win
	}
	got, found := selectMatchingObservation(exp, observations)
	if !found {
		t.Fatal("want a match")
	}
	if !got.Provenance.ObservedAt.Equal(now) {
		t.Fatalf("ObservedAt = %v, want the most recent (%v)", got.Provenance.ObservedAt, now)
	}
}

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

		// Relative to time.Now(), not a hardcoded calendar date -- a
		// fixed absolute timestamp here would only pass on the day it
		// was written, since the window is anchored to the
		// observation's own timestamp (effectively "now" in this
		// synchronous test), not to wall-clock time at any later date.
		body := map[string]any{
			"expectationImportId": expID,
			"discoveryRunId":      runID,
			"firewallEvidence": []map[string]any{
				{"sourceIp": "10.0.1.5", "destIp": "127.0.0.1", "port": openPort, "protocol": "tcp", "action": "block", "timestamp": time.Now().Add(-5 * time.Minute).Format(time.RFC3339), "source": "synthetic"},
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
