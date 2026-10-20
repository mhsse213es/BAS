package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/killchain"
)

// PutHostEvents replaces a run's host events and audit state, so a re-delivered
// batch heals rather than accumulates. Duplicate rows inside one batch are kept.
// The evaluator decides how to count them.
func (s KillChainStore) PutHostEvents(ctx context.Context, runID string, events []killchain.HostEvent, audit killchain.AuditState) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if _, err := tx.Exec(ctx, `DELETE FROM killchain_host_events WHERE run_id = $1`, runID); err != nil {
		return err
	}
	for _, e := range events {
		if _, err := tx.Exec(ctx, `INSERT INTO killchain_host_events
			(run_id, record_id, event_id, host, ts, subject, new_process, command_line, logon_type, target_user)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			runID, int64(e.RecordID), e.EventID, e.Host, e.Time, e.Subject, e.NewProcess,
			e.CommandLine, e.LogonType, e.TargetUser); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO killchain_run_audit (run_id, process_creation, logon)
		VALUES ($1, $2, $3)
		ON CONFLICT (run_id) DO UPDATE SET process_creation = EXCLUDED.process_creation,
			logon = EXCLUDED.logon, received_at = NOW()`,
		runID, string(audit.ProcessCreation), string(audit.Logon)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// HostEventsForRun returns a run's stored events and audit state. The bool is
// false when the run has no audit record, which means no host events were
// received, not that there were none to see.
func (s KillChainStore) HostEventsForRun(ctx context.Context, runID string) ([]killchain.HostEvent, killchain.AuditState, bool, error) {
	var audit killchain.AuditState
	var pc, lg string
	err := s.Pool.QueryRow(ctx, `SELECT process_creation, logon FROM killchain_run_audit WHERE run_id = $1`, runID).Scan(&pc, &lg)
	if err == pgx.ErrNoRows {
		return nil, killchain.AuditState{}, false, nil
	}
	if err != nil {
		return nil, killchain.AuditState{}, false, err
	}
	audit = killchain.AuditState{ProcessCreation: killchain.AuditSetting(pc), Logon: killchain.AuditSetting(lg)}

	rows, err := s.Pool.Query(ctx, `SELECT record_id, event_id, host, ts, subject, new_process, command_line, logon_type, target_user
		FROM killchain_host_events WHERE run_id = $1 ORDER BY record_id, event_id`, runID)
	if err != nil {
		return nil, audit, true, err
	}
	defer rows.Close()
	out := []killchain.HostEvent{}
	for rows.Next() {
		var e killchain.HostEvent
		var rid int64
		var ts time.Time
		if err := rows.Scan(&rid, &e.EventID, &e.Host, &ts, &e.Subject, &e.NewProcess, &e.CommandLine, &e.LogonType, &e.TargetUser); err != nil {
			return nil, audit, true, err
		}
		e.RecordID = uint64(rid)
		e.Time = ts
		out = append(out, e)
	}
	return out, audit, true, rows.Err()
}
