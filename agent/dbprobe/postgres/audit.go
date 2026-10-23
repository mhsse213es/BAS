package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"audspect/agent/dbprobe"
)

// PostgreSQL audit evidence comes from exactly one place: an operator-provisioned
// view the test account can read. The agent runs on a different host from the
// database, so it cannot read server log files; the lab (Task 11) exposes the
// csvlog through file_fdw as
//
//	dbsim_audit.pg_log(log_time timestamptz, user_name text, database_name text,
//	                   command_tag text, message text)
//
// If the view is absent or unreadable there is no audit source, the capability
// list is empty and callers report SKIPPED. Everything below is fixed SQL with
// bind parameters; the marker is never spliced into SQL text.
const (
	auditSourceName = "dbsim_audit.pg_log"

	// sqlAuditProbe proves every column the collector uses exists and is
	// readable (discovery only; reads one row's worth of metadata).
	sqlAuditProbe = "SELECT log_time, user_name, command_tag, message FROM dbsim_audit.pg_log LIMIT 1"
	// sqlAuditCovered asks whether the retained log reaches back to the
	// window start: true means at least one row at or before $1. False means
	// the log was rotated/truncated/enabled after Since, so absence of the
	// marker proves nothing. EXISTS stops at the first row (csvlog is
	// chronological), so it does not scan the whole file in the normal case.
	sqlAuditCovered = "SELECT EXISTS (SELECT 1 FROM dbsim_audit.pg_log WHERE log_time <= $1::timestamptz)"
	// sqlAuditEvents returns marker-bearing rows only. $3 is the LIKE pattern
	// with wildcards in the marker escaped (backslash is the default LIKE
	// escape in PostgreSQL); $4 is the row cap + 1.
	sqlAuditEvents = "SELECT log_time, user_name, message FROM dbsim_audit.pg_log " +
		"WHERE log_time >= $1::timestamptz AND log_time <= $2::timestamptz AND message LIKE $3 " +
		"ORDER BY log_time LIMIT $4"

	// read_audit_config statements: parameterless, catalog-only, cannot fail
	// on a missing view (to_regclass yields NULL instead of raising).
	sqlAuditSettings = "SELECT name::text, setting::text FROM pg_settings WHERE name IN " +
		"('log_destination', 'log_statement', 'logging_collector', 'pgaudit.log', 'shared_preload_libraries') ORDER BY name"
	sqlAuditViewState = "SELECT to_regclass('dbsim_audit.pg_log') IS NOT NULL, " +
		"CASE WHEN to_regclass('dbsim_audit.pg_log') IS NULL THEN false " +
		"ELSE has_table_privilege(to_regclass('dbsim_audit.pg_log'), 'SELECT') END"

	probeAuditConfig = "read_audit_config"
)

// auditConfigKeys are the settings read_audit_config always reports (as
// "absent" when pg_settings has no such row, e.g. pgaudit not loaded).
var auditConfigKeys = []string{"log_destination", "log_statement", "logging_collector", "pgaudit.log", "shared_preload_libraries"}

// auditLimits bounds discovery and collection (the executor's own deadline is
// tighter or equal; the smaller one wins).
var auditLimits = dbprobe.Limits{MaxRows: dbprobe.AuditMaxEvents + 1, TimeoutSec: 30, MaxConns: 1}

// discoverAudit finds out, once per connection, whether the audit view is
// usable, and caches the answer for Capabilities. A view that is missing or
// unreadable is not an error (the target simply has no audit source); a broken
// connection is.
func (a *Adapter) discoverAudit(ctx context.Context) error {
	a.auditSources, a.auditNotes = nil, nil
	if err := a.require(); err != nil {
		return err
	}
	err := a.inTxn(ctx, a.mode, dbprobe.ClassReadOnly, auditLimits, metaMarker, func(ctx context.Context, comment string) error {
		_, qerr := a.s.Query(ctx, comment+sqlAuditProbe, 1)
		return qerr
	})
	if err == nil {
		a.auditSources = []string{auditSourceName}
		a.auditNotes = []string{
			"Audit source dbsim_audit.pg_log is an operator-provisioned view (the lab exposes the csvlog through file_fdw; documented columns log_time, user_name, database_name, command_tag, message), read with the test account's own privileges; its layout and refresh behaviour are unverified against a live server.",
			"Marker evidence exists only if the server logs the statement text: log_statement='all' (or pgaudit with READ). With log_statement none/ddl/mod, reads are not logged and the collector reports absent; see read_audit_config.",
			"csvlog is written asynchronously by the logging collector, so events can lag the statement; matching uses a padded time window and the marker, not the clock alone.",
		}
		return nil
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		a.auditNotes = []string{fmt.Sprintf(
			"No audit source: dbsim_audit.pg_log is absent, unreadable or has an unexpected layout (sqlstate %s). Audit status is unsupported (SKIPPED), never a pass.", pe.Code)}
		return nil
	}
	if strings.HasPrefix(err.Error(), "dbprobe/postgres:") {
		return err
	}
	return wrapErr("audit discovery", err, a.secrets...)
}

// CollectAudit reads back marker-bearing events from dbsim_audit.pg_log.
//
// Return contract: ErrAuditUnsupported when no source was discovered;
// events plus an *AuditIncompleteError when the log window does not reach back
// to q.Since or the cap was hit; any other error is a failed collection (never
// "absent"); (nil, nil) means the source is healthy, covers the window and
// holds no marker event.
func (a *Adapter) CollectAudit(ctx context.Context, q dbprobe.AuditQuery) ([]dbprobe.AuditEvent, error) {
	if a.broken {
		return nil, a.require()
	}
	if len(a.auditSources) == 0 {
		return nil, dbprobe.ErrAuditUnsupported
	}
	if err := a.require(); err != nil {
		return nil, err
	}
	marker := sanitizeMarker(q.Marker, 120)
	if strings.Trim(marker, "_") == "" {
		return nil, errors.New("dbprobe/postgres: audit query needs a marker")
	}
	if q.Since.IsZero() || q.Until.IsZero() || q.Until.Before(q.Since) {
		return nil, errors.New("dbprobe/postgres: audit query needs a valid since/until window")
	}
	q.Marker = marker
	since, until := q.Since.UTC().Format(time.RFC3339Nano), q.Until.UTC().Format(time.RFC3339Nano)
	pattern := "%" + dbprobe.EscapeLike(marker) + "%"
	limit := dbprobe.AuditMaxEvents + 1

	var covered bool
	var rows [][]any
	err := a.inTxn(ctx, a.mode, dbprobe.ClassReadOnly, auditLimits, metaMarker, func(ctx context.Context, comment string) error {
		c, err := a.s.Query(ctx, comment+sqlAuditCovered, 1, since)
		if err != nil {
			return err
		}
		if len(c) != 1 || len(c[0]) != 1 {
			return errors.New("audit coverage query returned no row")
		}
		covered, _ = c[0][0].(bool)
		rows, err = a.s.Query(ctx, comment+sqlAuditEvents, limit, since, until, pattern, limit)
		return err
	})
	if err != nil {
		if strings.HasPrefix(err.Error(), "dbprobe/postgres:") {
			return nil, err
		}
		return nil, wrapErr("audit", err, a.secrets...)
	}
	raw := make([]dbprobe.AuditEvent, 0, len(rows))
	for _, r := range rows {
		if len(r) < 3 {
			continue
		}
		raw = append(raw, dbprobe.AuditEvent{Time: asTime(r[0]), Principal: str(r[1]), Statement: str(r[2]), Source: auditSourceName})
	}
	events, nerr := dbprobe.NormalizeAudit(q, raw, func(s string) string { return redact(s, a.secrets...) }, len(rows) > dbprobe.AuditMaxEvents)
	if !covered && nerr == nil {
		nerr = &dbprobe.AuditIncompleteError{Reason: "audit log retains no entry at or before the window start (rotated, truncated or enabled mid-run)"}
	}
	return events, nerr
}

func asTime(v any) time.Time {
	switch t := v.(type) {
	case time.Time:
		return t.UTC()
	case string:
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999-07", "2006-01-02 15:04:05.999999999"} {
			if ts, err := time.Parse(layout, t); err == nil {
				return ts.UTC()
			}
		}
	}
	return time.Time{}
}

// auditConfigNotes turns the read_audit_config observations into key=value
// lines plus the coverage summary. settings are (name, setting) rows; view is
// (present, selectable).
func auditConfigNotes(settings [][]any, view []any) []string {
	got := map[string]string{}
	for _, r := range settings {
		if len(r) >= 2 {
			got[str(r[0])] = dbprobe.TruncateUTF8(str(r[1]), 200)
		}
	}
	var notes []string
	for _, k := range auditConfigKeys {
		v, ok := got[k]
		if !ok {
			v = "absent"
		}
		notes = append(notes, k+"="+v)
	}
	present, selectable := false, false
	if len(view) >= 2 {
		present, _ = view[0].(bool)
		selectable, _ = view[1].(bool)
	}
	state := "absent"
	switch {
	case present && selectable:
		state = "readable"
	case present:
		state = "present_not_selectable"
	}
	notes = append(notes, auditSourceName+"="+state)
	notes = append(notes, "audit_config: "+pgAuditCoverage(got["log_statement"], got["pgaudit.log"], present && selectable))
	return notes
}

// pgAuditCoverage summarises whether reads would be logged AND the log is
// queryable: covered (both), partial (some logging or a readable view), none.
func pgAuditCoverage(logStatement, pgauditLog string, viewReadable bool) string {
	readLogged := logStatement == "all" || pgauditLogsReads(pgauditLog)
	anyLogging := (logStatement != "" && logStatement != "none") || (pgauditLog != "" && pgauditLog != "none")
	switch {
	case readLogged && viewReadable:
		return "covered"
	case anyLogging || viewReadable:
		return "partial"
	}
	return "none"
}

// pgauditLogsReads reports whether pgaudit.log enables the READ (or ALL) class
// and does not negate it.
func pgauditLogsReads(v string) bool {
	on := false
	for _, tok := range strings.Split(strings.ToLower(v), ",") {
		switch strings.TrimSpace(tok) {
		case "read", "all":
			on = true
		case "-read", "-all":
			return false
		}
	}
	return on
}
