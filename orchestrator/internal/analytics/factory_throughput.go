package analytics

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// throughputSet holds the lifecycle-throughput and validation KPIs that
// FactoryHealth folds into its report.
type throughputSet struct {
	ThreatsMapped               Metric
	CandidatesValidated         Metric
	CandidatesValidatedPerDay   Metric
	CandidatesRejected          Metric
	CandidatesRejectedPerDay    Metric
	RejectedByReason            map[string]int
	ExecutionValidationPassRate Metric
	ExecutionValidationErrors   Metric
}

// factoryThroughput computes window throughput for the validate and reject stages,
// the count of threats mapped to at least one technique, and the execution-level
// validation pass rate.
//
// Validated and rejected count distinct versions that reached that state in the
// window, from the lifecycle events, so they are throughput and not the
// current-state funnel. Rejections are broken down by their exclusion reason code;
// rejections recorded before codes existed read as "unclassified".
//
// The execution pass rate is PASS over PASS+FAIL. ERROR is reported separately and
// kept out of the rate: an ERROR is an environment problem (a missing tool, an
// unreachable lab), not evidence the content is bad. In-flight (NO_DATA) rows are
// not outcomes and are excluded.
func factoryThroughput(ctx context.Context, pool *pgxpool.Pool, since time.Time, window time.Duration) (throughputSet, error) {
	var mapped int
	if err := pool.QueryRow(ctx, `
		SELECT count(DISTINCT t.id) FROM threats t
		JOIN threat_techniques tt ON tt.threat_id = t.id AND tt.status = 'active'
		WHERE t.created_at >= $1`, since).Scan(&mapped); err != nil {
		return throughputSet{}, err
	}

	var validated int
	if err := pool.QueryRow(ctx, `
		SELECT count(DISTINCT content_version_id) FROM content_version_events
		WHERE to_lifecycle = 'VALIDATED' AND at >= $1`, since).Scan(&validated); err != nil {
		return throughputSet{}, err
	}

	byReason := map[string]int{}
	rows, err := pool.Query(ctx, `
		SELECT COALESCE(reason_code, 'unclassified'), count(DISTINCT content_version_id)
		FROM content_version_events
		WHERE to_lifecycle = 'REJECTED' AND at >= $1
		GROUP BY 1`, since)
	if err != nil {
		return throughputSet{}, err
	}
	defer rows.Close()
	rejected := 0
	for rows.Next() {
		var code string
		var n int
		if err := rows.Scan(&code, &n); err != nil {
			return throughputSet{}, err
		}
		byReason[code] = n
		rejected += n
	}
	if err := rows.Err(); err != nil {
		return throughputSet{}, err
	}

	var pass, fail, execErr int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE outcome = 'PASS'),
		       count(*) FILTER (WHERE outcome = 'FAIL'),
		       count(*) FILTER (WHERE outcome = 'ERROR')
		FROM content_validations
		WHERE level = 'EXECUTION' AND created_at >= $1`, since).Scan(&pass, &fail, &execErr); err != nil {
		return throughputSet{}, err
	}

	days := window.Hours() / 24
	return throughputSet{
		ThreatsMapped:               measured(float64(mapped)),
		CandidatesValidated:         measured(float64(validated)),
		CandidatesValidatedPerDay:   perDay(validated, days),
		CandidatesRejected:          measured(float64(rejected)),
		CandidatesRejectedPerDay:    perDay(rejected, days),
		RejectedByReason:            byReason,
		ExecutionValidationPassRate: ratioOrNoData(pass, pass+fail, "no EXECUTION validations reached PASS or FAIL in the window"),
		ExecutionValidationErrors:   measured(float64(execErr)),
	}, nil
}
