package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkdns"
	"github.com/audspect/bas/internal/networkgraph"
)

func EnsureDNSSecurityCheckSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS dns_security_check_runs (
			id               text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			vantage_point_id text        NOT NULL,
			requested_by     text,
			check_count      int         NOT NULL,
			status           text        NOT NULL,
			started_at       timestamptz NOT NULL DEFAULT NOW(),
			completed_at     timestamptz
		)`)
	if err != nil {
		return fmt.Errorf("dns_security_check_runs: ensure schema: %w", err)
	}
	_, err = pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS dns_security_check_results (
			id                text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			run_id            text        NOT NULL REFERENCES dns_security_check_runs(id),
			check_type        text        NOT NULL,
			target_host       text,
			target_port       int,
			path_state        text,
			error_detail      text,
			dnssec_domain     text,
			dnssec_state      text,
			dnssec_reason     text,
			observed_at       timestamptz NOT NULL DEFAULT NOW()
		)`)
	if err != nil {
		return fmt.Errorf("dns_security_check_results: ensure schema: %w", err)
	}
	_, err = pool.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_dns_security_check_results_run ON dns_security_check_results (run_id)`)
	if err != nil {
		return fmt.Errorf("dns_security_check_results: ensure index: %w", err)
	}
	return nil
}

type DNSSecurityCheckRun struct {
	ID             string     `json:"id"`
	VantagePointID string     `json:"vantagePointId"`
	RequestedBy    string     `json:"requestedBy,omitempty"`
	CheckCount     int        `json:"checkCount"`
	Status         string     `json:"status"`
	StartedAt      time.Time  `json:"startedAt"`
	CompletedAt    *time.Time `json:"completedAt,omitempty"`
}

func InsertDNSSecurityCheckRun(ctx context.Context, pool *pgxpool.Pool, run *DNSSecurityCheckRun) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO dns_security_check_runs (id, vantage_point_id, requested_by, check_count, status)
		 VALUES ($1,$2,$3,$4,$5)`,
		run.ID, run.VantagePointID, nullableString(run.RequestedBy), run.CheckCount, run.Status)
	if err != nil {
		return fmt.Errorf("dns_security_check_runs: insert %s: %w", run.ID, err)
	}
	return nil
}

func UpdateDNSSecurityCheckRunStatus(ctx context.Context, pool *pgxpool.Pool, id string, status string) error {
	_, err := pool.Exec(ctx, `UPDATE dns_security_check_runs SET status = $1, completed_at = NOW() WHERE id = $2`, status, id)
	if err != nil {
		return fmt.Errorf("dns_security_check_runs: update status for %s: %w", id, err)
	}
	return nil
}

func scanDNSSecurityCheckRun(row pgx.Row) (*DNSSecurityCheckRun, error) {
	run := &DNSSecurityCheckRun{}
	var requestedBy *string
	if err := row.Scan(&run.ID, &run.VantagePointID, &requestedBy, &run.CheckCount, &run.Status, &run.StartedAt, &run.CompletedAt); err != nil {
		return nil, err
	}
	if requestedBy != nil {
		run.RequestedBy = *requestedBy
	}
	return run, nil
}

func GetDNSSecurityCheckRun(ctx context.Context, pool *pgxpool.Pool, id string) (*DNSSecurityCheckRun, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, vantage_point_id, requested_by, check_count, status, started_at, completed_at
		 FROM dns_security_check_runs WHERE id = $1`, id)
	run, err := scanDNSSecurityCheckRun(row)
	if err != nil {
		return nil, fmt.Errorf("dns_security_check_runs: get %s: %w", id, err)
	}
	return run, nil
}

func ListDNSSecurityCheckRuns(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*DNSSecurityCheckRun, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, vantage_point_id, requested_by, check_count, status, started_at, completed_at
		 FROM dns_security_check_runs ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("dns_security_check_runs: list: %w", err)
	}
	defer rows.Close()
	var out []*DNSSecurityCheckRun
	for rows.Next() {
		run, err := scanDNSSecurityCheckRun(rows)
		if err != nil {
			return nil, fmt.Errorf("dns_security_check_runs: list scan: %w", err)
		}
		out = append(out, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dns_security_check_runs: list rows: %w", err)
	}
	return out, nil
}

// InsertDNSSecurityCheckResults writes every result for one run in a
// single transaction -- mirrors InsertNetworkObservations' own
// all-or-nothing semantics.
func InsertDNSSecurityCheckResults(ctx context.Context, pool *pgxpool.Pool, runID string, results []networkdns.DNSCheckResult) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("dns_security_check_results: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, r := range results {
		var host *string
		var port *int
		var pathState, errDetail *string
		var dnssecDomain, dnssecState, dnssecReason *string
		var observedAt time.Time

		switch r.CheckType {
		case networkdns.CheckOpenResolver:
			if r.Observation != nil {
				host = nullableString(r.Observation.Target.Host)
				p := r.Observation.Target.Port
				port = &p
				ps := string(r.Observation.State)
				pathState = &ps
				errDetail = nullableString(r.Observation.ErrorDetail)
				observedAt = r.Observation.Provenance.ObservedAt
			}
		case networkdns.CheckDNSSEC:
			if r.DNSSEC != nil {
				dnssecDomain = nullableString(r.DNSSEC.Domain)
				ds := string(r.DNSSEC.State)
				dnssecState = &ds
				dnssecReason = nullableString(r.DNSSEC.Reason)
				observedAt = r.DNSSEC.Provenance.ObservedAt
			}
		}
		if observedAt.IsZero() {
			observedAt = time.Now()
		}

		_, err := tx.Exec(ctx,
			`INSERT INTO dns_security_check_results
			 (run_id, check_type, target_host, target_port, path_state, error_detail, dnssec_domain, dnssec_state, dnssec_reason, observed_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			runID, string(r.CheckType), host, port, pathState, errDetail, dnssecDomain, dnssecState, dnssecReason, observedAt)
		if err != nil {
			return fmt.Errorf("dns_security_check_results: insert for run %s: %w", runID, err)
		}
	}
	return tx.Commit(ctx)
}

func ListDNSSecurityCheckResultsByRun(ctx context.Context, pool *pgxpool.Pool, runID string) ([]networkdns.DNSCheckResult, error) {
	rows, err := pool.Query(ctx,
		`SELECT check_type, target_host, target_port, path_state, error_detail, dnssec_domain, dnssec_state, dnssec_reason, observed_at
		 FROM dns_security_check_results WHERE run_id = $1 ORDER BY observed_at ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("dns_security_check_results: list for run %s: %w", runID, err)
	}
	defer rows.Close()
	var out []networkdns.DNSCheckResult
	for rows.Next() {
		var checkType string
		var host, pathState, errDetail, dnssecDomain, dnssecState, dnssecReason *string
		var port *int
		var observedAt time.Time
		if err := rows.Scan(&checkType, &host, &port, &pathState, &errDetail, &dnssecDomain, &dnssecState, &dnssecReason, &observedAt); err != nil {
			return nil, fmt.Errorf("dns_security_check_results: scan for run %s: %w", runID, err)
		}
		r := networkdns.DNSCheckResult{CheckType: networkdns.CheckType(checkType)}
		switch r.CheckType {
		case networkdns.CheckOpenResolver:
			obs := networkgraph.NetworkObservation{Provenance: cloudgraph.Provenance{ObservedAt: observedAt}}
			if host != nil {
				obs.Target.Host = *host
			}
			if port != nil {
				obs.Target.Port = *port
			}
			if pathState != nil {
				obs.State = cloudgraph.PathState(*pathState)
			}
			if errDetail != nil {
				obs.ErrorDetail = *errDetail
			}
			r.Observation = &obs
		case networkdns.CheckDNSSEC:
			d := networkdns.DNSSECResult{Provenance: cloudgraph.Provenance{ObservedAt: observedAt}}
			if dnssecDomain != nil {
				d.Domain = *dnssecDomain
			}
			if dnssecState != nil {
				d.State = networkdns.DNSSECState(*dnssecState)
			}
			if dnssecReason != nil {
				d.Reason = *dnssecReason
			}
			r.DNSSEC = &d
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dns_security_check_results: rows for run %s: %w", runID, err)
	}
	return out, nil
}
