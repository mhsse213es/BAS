package tcv

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// execSpyQuerier records whether Exec was reached. Query/QueryRow are unused.
type execSpyQuerier struct{ execCalled bool }

func (q *execSpyQuerier) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	q.execCalled = true
	return pgconn.CommandTag{}, nil
}
func (q *execSpyQuerier) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return nil, nil
}
func (q *execSpyQuerier) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row { return nil }

// A zero EventTime (e.g. a connector that stamped an unparsed timestamp as the
// Go zero time, 0001-01-01) must never reach the ledger — it poisons the SLA
// (now() - 0001 ≈ 2000 years). RecordPipelineEvent rejects it and inserts
// nothing; the caller's log-and-continue then skips the event.
func TestRecordPipelineEvent_RejectsZeroEventTime(t *testing.T) {
	q := &execSpyQuerier{}
	err := RecordPipelineEvent(context.Background(), q, Event{
		Type:     EventThreatObserved,
		ThreatID: "t-zero",
		SourcePK: "obs-zero",
		// EventTime left as the zero value
	})
	if err == nil {
		t.Fatal("expected an error for a zero EventTime, got nil")
	}
	if q.execCalled {
		t.Fatal("a zero-EventTime event must not be inserted")
	}
}
