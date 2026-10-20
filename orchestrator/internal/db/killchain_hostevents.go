package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/killchain"
)

// HostEventWindow is the time range the agent collected over.
type HostEventWindow struct {
	From time.Time
	To   time.Time
}

// PutHostEvents replaces a run's host events, audit state and collection window, so
// a re-delivered batch heals rather than accumulates. Duplicate rows inside one batch
// are kept. The evaluator decides how to count them.
func (s KillChainStore) PutHostEvents(ctx context.Context, runID string, events []killchain.HostEvent, audit killchain.AuditState, win HostEventWindow) error {
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
	if _, err := tx.Exec(ctx, `INSERT INTO killchain_run_audit
		(run_id, process_creation, logon, command_line, window_from, window_to)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (run_id) DO UPDATE SET process_creation = EXCLUDED.process_creation,
			logon = EXCLUDED.logon, command_line = EXCLUDED.command_line,
			window_from = EXCLUDED.window_from, window_to = EXCLUDED.window_to, received_at = NOW()`,
		runID, string(audit.ProcessCreation), string(audit.Logon), string(audit.CommandLine),
		win.From, win.To); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// HostEventsForRun returns a run's stored events, audit state and window. The bool is
// false when no batch was received. That is not the same as a received batch with no
// events.
func (s KillChainStore) HostEventsForRun(ctx context.Context, runID string) ([]killchain.HostEvent, killchain.AuditState, HostEventWindow, bool, error) {
	var pc, lg, cl string
	var win HostEventWindow
	err := s.Pool.QueryRow(ctx, `SELECT process_creation, logon, command_line, window_from, window_to
		FROM killchain_run_audit WHERE run_id = $1`, runID).Scan(&pc, &lg, &cl, &win.From, &win.To)
	if err == pgx.ErrNoRows {
		return nil, killchain.AuditState{}, HostEventWindow{}, false, nil
	}
	if err != nil {
		return nil, killchain.AuditState{}, HostEventWindow{}, false, err
	}
	audit := killchain.AuditState{
		ProcessCreation: killchain.AuditSetting(pc),
		Logon:           killchain.AuditSetting(lg),
		CommandLine:     killchain.AuditSetting(cl),
	}

	rows, err := s.Pool.Query(ctx, `SELECT record_id, event_id, host, ts, subject, new_process, command_line, logon_type, target_user
		FROM killchain_host_events WHERE run_id = $1 ORDER BY record_id, event_id`, runID)
	if err != nil {
		return nil, audit, win, true, err
	}
	defer rows.Close()
	out := []killchain.HostEvent{}
	for rows.Next() {
		var e killchain.HostEvent
		var rid int64
		var ts time.Time
		if err := rows.Scan(&rid, &e.EventID, &e.Host, &ts, &e.Subject, &e.NewProcess, &e.CommandLine, &e.LogonType, &e.TargetUser); err != nil {
			return nil, audit, win, true, err
		}
		e.RecordID = uint64(rid)
		e.Time = ts
		out = append(out, e)
	}
	return out, audit, win, true, rows.Err()
}
