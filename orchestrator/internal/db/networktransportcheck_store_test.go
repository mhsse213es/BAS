package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networksecurity"
	"github.com/audspect/bas/internal/networktransport"
)

func TestInsertTransportSecurityCheckRun_RoundTripsThroughGetAndList(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		run := &db.TransportSecurityCheckRun{ID: "transrun-roundtrip-1", VantagePointID: "vp1", RequestedBy: "alice", CheckCount: 2, Status: "completed"}
		if err := db.InsertTransportSecurityCheckRun(context.Background(), pool, run); err != nil {
			t.Fatalf("insert run: %v", err)
		}

		results := []networksecurity.SecurityCheckResult{
			{Target: networkgraph.Target{Host: "10.0.1.5", Port: 80}, State: networksecurity.Secure, Provenance: cloudgraph.Provenance{}},
			{Target: networkgraph.Target{Host: "10.0.1.5", Port: 443}, State: networksecurity.Insecure, Reason: "expired", Provenance: cloudgraph.Provenance{}},
		}
		checkTypes := []networktransport.CheckType{networktransport.CheckCleartext, networktransport.CheckCert}
		if err := db.InsertTransportSecurityCheckResults(context.Background(), pool, run.ID, checkTypes, results); err != nil {
			t.Fatalf("insert results: %v", err)
		}

		gotRun, err := db.GetTransportSecurityCheckRun(context.Background(), pool, run.ID)
		if err != nil {
			t.Fatalf("get run: %v", err)
		}
		if gotRun.RequestedBy != "alice" || gotRun.CheckCount != 2 {
			t.Fatalf("got %+v, want RequestedBy=alice CheckCount=2", gotRun)
		}

		gotResults, err := db.ListTransportSecurityCheckResultsByRun(context.Background(), pool, run.ID)
		if err != nil {
			t.Fatalf("list results: %v", err)
		}
		if len(gotResults) != 2 {
			t.Fatalf("got %d results, want 2", len(gotResults))
		}
		var sawCleartext, sawCert bool
		for _, r := range gotResults {
			if r.Target.Port == 80 {
				sawCleartext = true
				if r.State != networksecurity.Secure {
					t.Fatalf("cleartext result round-trip mismatch: %+v", r)
				}
			}
			if r.Target.Port == 443 {
				sawCert = true
				if r.State != networksecurity.Insecure || r.Reason != "expired" {
					t.Fatalf("cert result round-trip mismatch: %+v", r)
				}
			}
		}
		if !sawCleartext || !sawCert {
			t.Fatalf("missing a result type in round-trip: cleartext=%v cert=%v", sawCleartext, sawCert)
		}

		list, err := db.ListTransportSecurityCheckRuns(context.Background(), pool, 100)
		if err != nil {
			t.Fatalf("list runs: %v", err)
		}
		found := false
		for _, r := range list {
			if r.ID == run.ID {
				found = true
			}
		}
		if !found {
			t.Fatal("inserted run should appear in the list")
		}
	})
}

func TestGetTransportSecurityCheckRun_NonexistentIDReturnsErrNoRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetTransportSecurityCheckRun(context.Background(), pool, "nonexistent-id")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("got %v, want an error satisfying errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}
