package ingest

import (
	"context"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

// withIngestSchema's name is kept for the existing call sites below, though
// it no longer calls EnsureIngestSchema itself (removed -- H1 forbids
// runtime DDL; the ingested_events table now comes from migration
// 000004_ingested_events, which every test database already has via
// migrate.Up).
func withIngestSchema(t *testing.T, fn func(pool *pgxpool.Pool)) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, fn)
}

func TestProcessEvent_WithIOC_CreatesLedgerRowAndIOC(t *testing.T) {
	withIngestSchema(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		ev := Event{
			Source: "splunk", ExternalEventID: "evt-1", EventType: "detection",
			Timestamp: time.Now(), Severity: "high", TechniqueID: "T1059.001",
			IOC: &IOCPayload{Type: "ip", Value: "203.0.113.9"},
		}
		result, err := ProcessEvent(ctx, pool, ev)
		if err != nil {
			t.Fatalf("ProcessEvent: %v", err)
		}
		if result.Status != "created" || result.IOCID == "" {
			t.Fatalf("result = %+v, want status=created with a non-empty ioc_id", result)
		}
	})
}

func TestProcessEvent_NoIOC_StillRecordsLedgerRow(t *testing.T) {
	withIngestSchema(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		ev := Event{Source: "sentinel", ExternalEventID: "evt-heartbeat", EventType: "evidence", Timestamp: time.Now()}
		result, err := ProcessEvent(ctx, pool, ev)
		if err != nil {
			t.Fatalf("ProcessEvent: %v", err)
		}
		if result.Status != "created" || result.IOCID != "" {
			t.Fatalf("result = %+v, want status=created with no ioc_id", result)
		}
	})
}

func TestProcessEvent_RepeatExternalEventID_ReturnsDuplicateNotASecondIOC(t *testing.T) {
	withIngestSchema(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		ev := Event{
			Source: "qradar", ExternalEventID: "evt-retry", EventType: "detection",
			Timestamp: time.Now(), IOC: &IOCPayload{Type: "domain", Value: "evil.example.test"},
		}
		first, err := ProcessEvent(ctx, pool, ev)
		if err != nil {
			t.Fatalf("first ProcessEvent: %v", err)
		}
		second, err := ProcessEvent(ctx, pool, ev)
		if err != nil {
			t.Fatalf("second ProcessEvent: %v", err)
		}
		if second.Status != "duplicate" {
			t.Fatalf("second result = %+v, want status=duplicate", second)
		}

		var sightingCount int
		if err := pool.QueryRow(ctx, `SELECT sighting_count FROM iocs WHERE id = $1`, first.IOCID).Scan(&sightingCount); err != nil {
			t.Fatalf("select: %v", err)
		}
		if sightingCount != 1 {
			t.Fatalf("sighting_count = %d, want 1 (the duplicate must not re-register the IOC)", sightingCount)
		}
	})
}

func TestProcessEvent_MissingExternalEventID_ReturnsErrorResultNotDBError(t *testing.T) {
	withIngestSchema(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		ev := Event{Source: "splunk", EventType: "detection", Timestamp: time.Now()}
		result, err := ProcessEvent(ctx, pool, ev)
		if err != nil {
			t.Fatalf("ProcessEvent: %v", err)
		}
		if result.Status != "error" || result.Error == "" {
			t.Fatalf("result = %+v, want status=error with a message", result)
		}
	})
}

func TestProcessEvent_UnknownIOCType_ReturnsErrorResult(t *testing.T) {
	withIngestSchema(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		ev := Event{
			Source: "splunk", ExternalEventID: "evt-bad-type", EventType: "detection", Timestamp: time.Now(),
			IOC: &IOCPayload{Type: "not_a_real_type", Value: "x"},
		}
		result, err := ProcessEvent(ctx, pool, ev)
		if err != nil {
			t.Fatalf("ProcessEvent: %v", err)
		}
		if result.Status != "error" || result.Error == "" {
			t.Fatalf("result = %+v, want status=error with a message", result)
		}
	})
}
