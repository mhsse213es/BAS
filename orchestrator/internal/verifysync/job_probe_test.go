package verifysync

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/verification"
)

// A reachability probe POST carries no sensitive content, so a receipt on the
// reachability channel must not count as data reaching the sink. Otherwise the
// existing DLP reporting would read a probe as a data leak.
func TestAnnotateSinkReceipts_ProbeChannelDoesNotCountAsReceived(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		job := NewJob(pool, verification.NewStore(pool), fakeResolver{})

		// T1048: only a probe receipt -> data never arrived, want false.
		mustExec(t, pool, `INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at)
			VALUES ('tok-probe-only', 'run-sink-probe', 'T1048', NOW() + interval '10 minutes')`)
		mustExec(t, pool, `INSERT INTO dlp_sink_receipts (token, channel)
			VALUES ('tok-probe-only', 'reachability')`)

		// T1041: probe plus data receipt -> data arrived, want true.
		mustExec(t, pool, `INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at)
			VALUES ('tok-probe-and-data', 'run-sink-probe', 'T1041', NOW() + interval '10 minutes')`)
		mustExec(t, pool, `INSERT INTO dlp_sink_receipts (token, channel)
			VALUES ('tok-probe-and-data', 'reachability')`)
		mustExec(t, pool, `INSERT INTO dlp_sink_receipts (token, channel)
			VALUES ('tok-probe-and-data', 'https-post')`)

		results := []models.SimulationResult{{ID: "T1048"}, {ID: "T1041"}}
		if err := job.annotateSinkReceipts(ctx, "run-sink-probe", results); err != nil {
			t.Fatalf("annotateSinkReceipts: %v", err)
		}
		if results[0].SinkTokenObserved == nil || *results[0].SinkTokenObserved {
			t.Errorf("probe-only T1048 SinkTokenObserved = %v, want false", results[0].SinkTokenObserved)
		}
		if results[1].SinkTokenObserved == nil || !*results[1].SinkTokenObserved {
			t.Errorf("probe+data T1041 SinkTokenObserved = %v, want true", results[1].SinkTokenObserved)
		}
	})
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}
