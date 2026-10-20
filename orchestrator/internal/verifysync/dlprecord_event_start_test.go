package verifysync

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/reporting"
)

// TestTestEventMapping_NilWhenNoStart checks the verdict-to-entry mapping: a
// zero start is never stored, and the source exists exactly when a start does.
func TestTestEventMapping_NilWhenNoStart(t *testing.T) {
	ev := &reporting.DLPEvidence{}
	if testEventStartOf(ev) != nil || testEventSourceOf(ev) != nil {
		t.Fatal("no start must map to nil start and nil source, never a zero timestamp")
	}
	ev.TestEventStart = time.Date(2026, 10, 20, 4, 39, 43, 0, time.UTC)
	if got := testEventStartOf(ev); got == nil || !got.Equal(ev.TestEventStart) {
		t.Fatalf("start = %v, want %v", got, ev.TestEventStart)
	}
	if src := testEventSourceOf(ev); src == nil || *src != "payload-marker" {
		t.Fatalf("source = %v, want payload-marker", src)
	}
}

// TestPersistDLPRecords_WritesTestEventColumns checks the test-event start is
// written to its own nullable columns only when a value exists. A row without a
// marker must stay NULL, not be given a default. The record JSON must not
// change, because the plan keeps new fields out of the record shape.
func TestPersistDLPRecords_WritesTestEventColumns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		const runID = "run-test-event-cols"
		at := time.Date(2026, 10, 20, 4, 39, 43, 500000000, time.UTC)
		src := "payload-marker"

		withStart := DLPRecordEntry{
			TaskID: "task-with", ExpectationID: "dlp-usb-block", TechniqueID: "T1052.001",
			TestEventStart: &at, TestEventSource: &src,
		}
		withStart.Record.ScenarioID = "sc-evs"
		noStart := DLPRecordEntry{
			TaskID: "task-without", ExpectationID: "dlp-usb-block", TechniqueID: "T1052.001",
		}
		noStart.Record.ScenarioID = "sc-evs"

		if err := persistDLPRecords(ctx, pool, runID, []DLPRecordEntry{withStart, noStart}); err != nil {
			t.Fatalf("persist: %v", err)
		}

		var gotAt *time.Time
		var gotSrc *string
		if err := pool.QueryRow(ctx,
			`SELECT test_event_timestamp, test_event_source FROM dlp_evidence_records
			 WHERE run_id = $1 AND task_id = 'task-with'`, runID).Scan(&gotAt, &gotSrc); err != nil {
			t.Fatalf("read with-start row: %v", err)
		}
		if gotAt == nil || !gotAt.Equal(at) {
			t.Fatalf("test_event_timestamp = %v, want %v", gotAt, at)
		}
		if gotSrc == nil || *gotSrc != "payload-marker" {
			t.Fatalf("test_event_source = %v, want payload-marker", gotSrc)
		}

		var nullAt *time.Time
		var nullSrc *string
		if err := pool.QueryRow(ctx,
			`SELECT test_event_timestamp, test_event_source FROM dlp_evidence_records
			 WHERE run_id = $1 AND task_id = 'task-without'`, runID).Scan(&nullAt, &nullSrc); err != nil {
			t.Fatalf("read without-start row: %v", err)
		}
		if nullAt != nil || nullSrc != nil {
			t.Fatalf("row without a marker must be NULL, got timestamp=%v source=%v", nullAt, nullSrc)
		}

		var raw string
		if err := pool.QueryRow(ctx,
			`SELECT record::text FROM dlp_evidence_records WHERE run_id = $1 AND task_id = 'task-with'`,
			runID).Scan(&raw); err != nil {
			t.Fatalf("read record json: %v", err)
		}
		if strings.Contains(raw, "payload-marker") || strings.Contains(raw, "TestEvent") || strings.Contains(raw, "testEvent") {
			t.Fatalf("test-event fields leaked into the record JSON: %s", raw)
		}
	})
}
