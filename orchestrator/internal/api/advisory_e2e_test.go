package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/audspect/bas/internal/advisory"
	"github.com/audspect/bas/internal/auth"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Drives the real decision endpoint against Postgres and checks what it writes:
// the advisory_relevance rows (decider, decision, reason, supersession) and the
// advisory ledger events. Nothing here is mocked.
func TestAdvisoryDecisionEndToEndWritesToPostgres(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		st := advisory.NewStore(pool)
		if _, err := st.Intake(ctx, []advisory.Item{{
			Source: "cert_in", ExternalID: "E2E-CIAD-0001", Title: "e2e advisory", SourceRef: "e2e",
		}}); err != nil {
			t.Fatalf("intake: %v", err)
		}
		var advID string
		if err := pool.QueryRow(ctx, `SELECT id FROM advisory_intake WHERE external_id='E2E-CIAD-0001'`).Scan(&advID); err != nil {
			t.Fatalf("find advisory: %v", err)
		}

		h := (&Handler{}).WithAdvisoryStore(st)
		router := advisoryRouter(h)
		analyst := &auth.Claims{UserID: "e2e-analyst", Role: auth.RoleAnalyst}
		decidePath := "/api/advisories/" + advID + "/decision"
		reversePath := "/api/advisories/" + advID + "/reverse"

		// 1. Invalid exclusion is refused and writes nothing.
		if rec := postDecision(t, router, analyst, decidePath, `{"decision":"excluded","reasonCode":"not sure"}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("bad code: status %d, want 400", rec.Code)
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM advisory_relevance WHERE advisory_id=$1`, advID).Scan(&n); err != nil || n != 0 {
			t.Fatalf("rows after refused decision = %d, %v; want 0", n, err)
		}

		// 2. First relevant decision is written, attributed to the caller.
		if rec := postDecision(t, router, analyst, decidePath, `{"decision":"relevant","note":"in scope"}`); rec.Code != http.StatusCreated {
			t.Fatalf("first decision: status %d, body %s", rec.Code, rec.Body.String())
		}
		var decision, decidedBy, note string
		var reason *string
		var supersedes *int64
		if err := pool.QueryRow(ctx,
			`SELECT decision, decided_by, note, reason_code, supersedes FROM advisory_relevance WHERE advisory_id=$1`, advID,
		).Scan(&decision, &decidedBy, &note, &reason, &supersedes); err != nil {
			t.Fatalf("read decision row: %v", err)
		}
		if decision != "relevant" || decidedBy != "user:e2e-analyst" || note != "in scope" || reason != nil || supersedes != nil {
			t.Fatalf("decision row = (%s, %s, %q, reason=%v, supersedes=%v)", decision, decidedBy, note, reason, supersedes)
		}

		// 3. A second original decision is a conflict and adds no row.
		if rec := postDecision(t, router, analyst, decidePath, `{"decision":"excluded","reasonCode":"relevance"}`); rec.Code != http.StatusConflict {
			t.Fatalf("second original decision: status %d, want 409", rec.Code)
		}

		// 4. Reversal to an exclusion keeps the original and supersedes it.
		if rec := postDecision(t, router, analyst, reversePath, `{"decision":"excluded","reasonCode":"unsupported_platform"}`); rec.Code != http.StatusCreated {
			t.Fatalf("reverse: status %d, body %s", rec.Code, rec.Body.String())
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM advisory_relevance WHERE advisory_id=$1`, advID).Scan(&n); err != nil || n != 2 {
			t.Fatalf("rows after reversal = %d, %v; want 2 (history kept)", n, err)
		}
		var curDecision string
		var curReason *string
		var curSupersedes *int64
		if err := pool.QueryRow(ctx,
			`SELECT r.decision, r.reason_code, r.supersedes FROM advisory_relevance r
			  WHERE r.advisory_id=$1 AND r.supersedes IS NOT NULL`, advID,
		).Scan(&curDecision, &curReason, &curSupersedes); err != nil {
			t.Fatalf("read reversal row: %v", err)
		}
		if curDecision != "excluded" || curReason == nil || *curReason != "unsupported_platform" || curSupersedes == nil {
			t.Fatalf("reversal row = (%s, reason=%v, supersedes=%v)", curDecision, curReason, curSupersedes)
		}

		// 5. Ledger: one received event for the intake, one classified event per decision row.
		var received, classified int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM tcf_pipeline_events WHERE event_type='advisory_received' AND source_pk=$1`, advID,
		).Scan(&received); err != nil || received != 1 {
			t.Fatalf("advisory_received events = %d, %v; want 1", received, err)
		}
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM tcf_pipeline_events WHERE event_type='advisory_classified' AND source_table='advisory_relevance'
			   AND source_pk IN (SELECT id::text FROM advisory_relevance WHERE advisory_id=$1)`, advID,
		).Scan(&classified); err != nil || classified != 2 {
			t.Fatalf("advisory_classified events = %d, %v; want 2", classified, err)
		}
	})
}
