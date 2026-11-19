package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"audspect/agent/dbprobe"
)

// sqlConnEvents reads connection-authorised rows for one role inside a window.
// $3 is the LIKE pattern built from the role; $4 is the row cap + 1.
const sqlConnEvents = "SELECT log_time, user_name, message FROM dbsim_audit.pg_log " +
	"WHERE log_time >= $1::timestamptz AND log_time <= $2::timestamptz AND message LIKE $3 " +
	"ORDER BY log_time LIMIT $4"

// connectionPollBudget bounds the wait for the sentinel to reach the log.
const connectionPollBudget = 5 * time.Second

// CollectConnections reads connection events for q.Principal inside
// [q.Since, q.Until] from the audit source. It is a separate evidence class
// from the marker readback: a connection cannot carry a marker, so the match
// is by role and time window only, and the caller must report it as such.
//
// The sentinel statement (a marker-tagged SELECT) confirms the log has caught
// up to the window end before the connection rows are trusted; a missing
// sentinel or a window the log does not reach back to is AuditIncompleteError.
func (a *Adapter) CollectConnections(ctx context.Context, q dbprobe.AuditQuery) ([]dbprobe.AuditEvent, error) {
	if a.broken {
		return nil, a.require()
	}
	if len(a.auditSources) == 0 {
		if a.auditErr != "" {
			return nil, errors.New("dbprobe/postgres: " + a.auditErr)
		}
		return nil, dbprobe.ErrAuditUnsupported
	}
	if err := a.require(); err != nil {
		return nil, err
	}
	if q.Principal == "" {
		return nil, errors.New("dbprobe/postgres: connection audit needs a principal (role); a match without one would count every login")
	}
	if q.Since.IsZero() || q.Until.IsZero() || q.Until.Before(q.Since) {
		return nil, errors.New("dbprobe/postgres: connection audit needs a valid since/until window")
	}
	wrap := func(err error) error {
		if err == nil || strings.HasPrefix(err.Error(), "dbprobe/postgres:") {
			return err
		}
		return wrapErr("audit", err, a.secrets...)
	}
	since := q.Since.UTC().Format(time.RFC3339Nano)
	until := q.Until.UTC().Format(time.RFC3339Nano)
	limit := dbprobe.AuditMaxEvents + 1
	rolePattern := "connection authorized: user=" + dbprobe.EscapeLike(q.Principal) + " %"

	// 1. Sentinel: a marker-tagged statement run after the window closes.
	sm := dbprobe.NewSentinelMarker()
	if err := a.inTxn(ctx, a.mode, dbprobe.ClassReadOnly, auditLimits, sm, func(ctx context.Context, comment string) error {
		_, qerr := a.s.Query(ctx, comment+"SELECT 1", 1)
		return qerr
	}); err != nil {
		return nil, wrap(err)
	}
	sentinelPattern := "%" + dbprobe.EscapeLike(sm) + "%"
	winUntil := q.Until.Add(time.Minute).UTC().Format(time.RFC3339Nano)
	deadline := time.Now().Add(connectionPollBudget)
	for {
		var rows [][]any
		err := a.inTxn(ctx, a.mode, dbprobe.ClassReadOnly, auditLimits, metaMarker, func(ctx context.Context, comment string) error {
			var qerr error
			rows, qerr = a.s.Query(ctx, comment+sqlConnEvents, limit, since, winUntil, sentinelPattern, limit)
			return qerr
		})
		if err != nil {
			return nil, wrap(err)
		}
		if len(rows) > 0 {
			break
		}
		if !time.Now().Before(deadline) {
			return nil, &dbprobe.AuditIncompleteError{Reason: "sentinel did not reach the audit source within the sync budget"}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}

	// 2. Coverage and the connection rows themselves.
	var covered bool
	var rows [][]any
	if err := a.inTxn(ctx, a.mode, dbprobe.ClassReadOnly, auditLimits, metaMarker, func(ctx context.Context, comment string) error {
		c, err := a.s.Query(ctx, comment+sqlAuditCovered, 1, since)
		if err != nil {
			return err
		}
		if len(c) != 1 || len(c[0]) != 1 {
			return errors.New("audit coverage query returned no row")
		}
		covered, _ = c[0][0].(bool)
		rows, err = a.s.Query(ctx, comment+sqlConnEvents, limit, since, until, rolePattern, limit)
		return err
	}); err != nil {
		return nil, wrap(err)
	}
	if !covered {
		return nil, &dbprobe.AuditIncompleteError{Reason: "audit source retains no entry at or before the window start (rotated, evicted or enabled mid-run)"}
	}
	if len(rows) > dbprobe.AuditMaxEvents {
		return nil, &dbprobe.AuditIncompleteError{Reason: "source returned more connection rows than the cap"}
	}
	out := make([]dbprobe.AuditEvent, 0, len(rows))
	for _, r := range rows {
		if len(r) < 3 {
			continue
		}
		msg := str(r[2])
		out = append(out, dbprobe.AuditEvent{
			Time: asTime(r[0]), Principal: str(r[1]),
			Statement: dbprobe.TruncateUTF8(msg, dbprobe.AuditMaxStatementBytes),
			Source:    auditSourceName,
		})
	}
	return out, nil
}
