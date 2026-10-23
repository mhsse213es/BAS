package mysql

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	drv "github.com/go-sql-driver/mysql"

	"audspect/agent/dbprobe"
)

// MySQL audit evidence comes only from SQL-queryable sources, read with the
// test account's own privileges (the agent is on a different host from the
// database and cannot read server log files). Two sources are recognised, in
// order of preference:
//
//  1. mysql.general_log, when general_log is ON and log_output includes TABLE.
//     It has a real wall-clock event_time.
//  2. performance_schema.events_statements_history_long, when performance_schema
//     is ON and the statement consumers are enabled. It has no wall-clock
//     column (TIMER_START is picoseconds on the server's timer), so event time
//     is derived as NOW() - Uptime + TIMER_START/1e12, an approximation.
//
// Anything else leaves Capabilities().AuditSources empty (unsupported).
// MariaDB is not supported by this adapter (Identity already fails closed).
// All SQL below is fixed; values are bind parameters; the marker is never
// spliced into SQL text.
const (
	srcGeneralLog  = "mysql.general_log"
	srcHistoryLong = "performance_schema.events_statements_history_long"

	probeAuditConfig = "read_audit_config"

	// discovery / read_audit_config (parameterless)
	sqlAuditVars      = "SELECT @@general_log, @@log_output, @@performance_schema"
	sqlAuditConsumers = "SELECT NAME, ENABLED FROM performance_schema.setup_consumers WHERE NAME IN " +
		"('events_statements_current', 'events_statements_history_long', 'global_instrumentation', 'thread_instrumentation') ORDER BY NAME"
	sqlAuditPlugins = "SELECT PLUGIN_NAME, PLUGIN_STATUS FROM information_schema.PLUGINS WHERE PLUGIN_TYPE = 'AUDIT' ORDER BY PLUGIN_NAME"
	// Readability probes: prove every column the collector uses is selectable.
	sqlGLProbe   = "SELECT event_time, user_host, argument FROM mysql.general_log LIMIT 1"
	sqlHistProbe = "SELECT TIMER_START, SQL_TEXT, THREAD_ID FROM performance_schema.events_statements_history_long LIMIT 1"

	// general_log. ? are whole-second epochs (since floored, until ceiled) and
	// the LIKE pattern; the default LIKE escape (backslash) is used so no
	// ESCAPE clause (whose quoting depends on NO_BACKSLASH_ESCAPES) is needed.
	// UNIX_TIMESTAMP(timestamp column) and FROM_UNIXTIME are both session
	// time_zone consistent, so no timezone conversion is involved.
	sqlGLCovered = "SELECT EXISTS (SELECT 1 FROM mysql.general_log WHERE event_time <= FROM_UNIXTIME(?))"
	sqlGLEvents  = "SELECT UNIX_TIMESTAMP(event_time), user_host, argument FROM mysql.general_log " +
		"WHERE event_time >= FROM_UNIXTIME(?) AND event_time <= FROM_UNIXTIME(?) AND argument LIKE ? " +
		"ORDER BY event_time LIMIT ?"

	// history_long. histEpoch is the wall-clock epoch (seconds, decimal) of an
	// event: now - uptime gives server start; TIMER_START is picoseconds from
	// the timer origin (approximately server start).
	histEpoch = "(UNIX_TIMESTAMP(NOW(6)) - (SELECT CAST(g.VARIABLE_VALUE AS DECIMAL(20,0)) " +
		"FROM performance_schema.global_status g WHERE g.VARIABLE_NAME = 'Uptime') + h.TIMER_START / 1000000000000)"
	sqlHistCovered = "SELECT EXISTS (SELECT 1 FROM performance_schema.events_statements_history_long h WHERE " + histEpoch + " <= ?)"
	sqlHistEvents  = "SELECT x.ev, x.usr, x.txt FROM (SELECT " + histEpoch + " AS ev, t.PROCESSLIST_USER AS usr, h.SQL_TEXT AS txt " +
		"FROM performance_schema.events_statements_history_long h " +
		"LEFT JOIN performance_schema.threads t ON t.THREAD_ID = h.THREAD_ID WHERE h.SQL_TEXT LIKE ?) x " +
		"WHERE x.ev >= ? AND x.ev <= ? ORDER BY x.ev LIMIT ?"
)

var auditLimits = dbprobe.Limits{MaxRows: dbprobe.AuditMaxEvents + 1, TimeoutSec: 30, MaxConns: 1}

var consumerNames = []string{"events_statements_current", "events_statements_history_long", "global_instrumentation", "thread_instrumentation"}

// auditState is what discovery (and read_audit_config) observed.
type auditState struct {
	glOn, psOn               bool
	logOutput                string
	consumers                map[string]string
	consumersReadable        bool
	glReadable, histReadable bool
}

func (s auditState) consumersOK() bool {
	if !s.consumersReadable {
		return false
	}
	for _, n := range consumerNames {
		if s.consumers[n] != "YES" {
			return false
		}
	}
	return true
}

func (s auditState) glUsable() bool {
	return s.glOn && strings.Contains(strings.ToUpper(s.logOutput), "TABLE") && s.glReadable
}

func (s auditState) histUsable() bool { return s.psOn && s.consumersOK() && s.histReadable }

func isMySQLErr(err error) bool {
	var me *drv.MySQLError
	return errors.As(err, &me)
}

// gatherAuditState runs the read-only detection queries. A server error
// (privilege, missing table) means that surface is unreadable; any other
// error is a real failure and is returned.
func (a *Adapter) gatherAuditState(ctx context.Context, comment string) (auditState, error) {
	var st auditState
	rows, err := a.s.Query(ctx, comment+sqlAuditVars, 1)
	if err != nil {
		return st, err
	}
	if len(rows) != 1 || len(rows[0]) < 3 {
		return st, errors.New("audit variable query returned no row")
	}
	st.glOn, st.logOutput, st.psOn = truthy(rows[0][0]), str(rows[0][1]), truthy(rows[0][2])
	if st.psOn {
		crow, err := a.s.Query(ctx, comment+sqlAuditConsumers, 16)
		switch {
		case err == nil:
			st.consumersReadable = true
			st.consumers = map[string]string{}
			for _, r := range crow {
				if len(r) >= 2 {
					st.consumers[str(r[0])] = strings.ToUpper(str(r[1]))
				}
			}
		case !isMySQLErr(err):
			return st, err
		}
	}
	if _, err := a.s.Query(ctx, comment+sqlGLProbe, 1); err == nil {
		st.glReadable = true
	} else if !isMySQLErr(err) {
		return st, err
	}
	if st.psOn {
		if _, err := a.s.Query(ctx, comment+sqlHistProbe, 1); err == nil {
			st.histReadable = true
		} else if !isMySQLErr(err) {
			return st, err
		}
	}
	return st, nil
}

// discoverAudit finds the usable audit sources once per connection and caches
// them for Capabilities. No usable source is not an error; a broken connection
// is.
func (a *Adapter) discoverAudit(ctx context.Context) error {
	a.auditSources, a.auditNotes = nil, nil
	if err := a.require(); err != nil {
		return err
	}
	var st auditState
	err := a.inTxn(ctx, a.mode, dbprobe.ClassReadOnly, auditLimits, metaMarker, func(ctx context.Context, comment string) error {
		var gerr error
		st, gerr = a.gatherAuditState(ctx, comment)
		return gerr
	})
	if err != nil {
		var re *redactedError
		if errors.As(err, &re) || strings.HasPrefix(err.Error(), "dbprobe/mysql:") {
			return err
		}
		return a.wrap("audit discovery", err)
	}
	if st.glUsable() {
		a.auditSources = append(a.auditSources, srcGeneralLog)
		a.auditNotes = append(a.auditNotes,
			"Audit source mysql.general_log (log_output includes TABLE, general_log ON): has a wall-clock event_time and logs every statement including reads; it is unbounded until the operator truncates it. Whether the statement text keeps the leading marker comment is unverified; for prepared executes the log shows the substituted text. Collection reads the first listed source only.")
	}
	if st.histUsable() {
		a.auditSources = append(a.auditSources, srcHistoryLong)
		a.auditNotes = append(a.auditNotes,
			"Audit source performance_schema.events_statements_history_long is a bounded ring buffer (performance_schema_events_statements_history_long_size): old events may already be evicted, which is reported as incomplete, never absent. It has no wall-clock column: event time is approximated as NOW() - Uptime + TIMER_START/1e12 (whole-second Uptime and the timer origin make it accurate to about a second or two, so the window is padded). The principal comes from performance_schema.threads and is unknown once the connection has ended. SQL_TEXT is cut at max_sql_text_length and comment preservation is unverified.")
	}
	if len(a.auditSources) == 0 {
		a.auditNotes = append(a.auditNotes,
			"No audit source: general_log is off or does not log to TABLE, and the performance_schema statement consumers are disabled or the tables are unreadable to this account. Audit status is unsupported (SKIPPED), never a pass.")
	}
	return nil
}

// CollectAudit reads back marker-bearing events from the first discovered
// source. Return contract: ErrAuditUnsupported when no source was discovered;
// events plus an *AuditIncompleteError when the retained window does not reach
// back to q.Since or the cap was hit; any other error is a failed collection
// (never "absent"); (nil, nil) means a healthy source covers the window and
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
		return nil, errors.New("dbprobe/mysql: audit query needs a marker")
	}
	if q.Since.IsZero() || q.Until.IsZero() || q.Until.Before(q.Since) {
		return nil, errors.New("dbprobe/mysql: audit query needs a valid since/until window")
	}
	q.Marker = marker
	src := a.auditSources[0]
	sinceSec := q.Since.UTC().Unix()
	untilSec := q.Until.UTC().Unix()
	if q.Until.UTC().Nanosecond() > 0 {
		untilSec++
	}
	pattern := "%" + dbprobe.EscapeLike(marker) + "%"
	limit := dbprobe.AuditMaxEvents + 1

	coveredSQL, eventsSQL := sqlGLCovered, sqlGLEvents
	eventArgs := []any{sinceSec, untilSec, pattern, limit}
	if src == srcHistoryLong {
		coveredSQL, eventsSQL = sqlHistCovered, sqlHistEvents
		eventArgs = []any{pattern, sinceSec, untilSec, limit}
	}
	var covered bool
	var rows [][]any
	err := a.inTxn(ctx, a.mode, dbprobe.ClassReadOnly, auditLimits, metaMarker, func(ctx context.Context, comment string) error {
		c, err := a.s.Query(ctx, comment+coveredSQL, 1, sinceSec)
		if err != nil {
			return err
		}
		if len(c) != 1 || len(c[0]) != 1 {
			return errors.New("audit coverage query returned no row")
		}
		covered = truthy(c[0][0])
		rows, err = a.s.Query(ctx, comment+eventsSQL, limit, eventArgs...)
		return err
	})
	if err != nil {
		var re *redactedError
		if errors.As(err, &re) || strings.HasPrefix(err.Error(), "dbprobe/mysql:") {
			return nil, err
		}
		return nil, a.wrap("audit", err)
	}
	raw := make([]dbprobe.AuditEvent, 0, len(rows))
	for _, r := range rows {
		if len(r) < 3 {
			continue
		}
		principal := str(r[1])
		if src == srcGeneralLog {
			principal = parseUserHost(principal)
		}
		raw = append(raw, dbprobe.AuditEvent{Time: parseEpoch(r[0]), Principal: principal, Statement: str(r[2]), Source: src})
	}
	scrub := a.scrub
	if scrub == nil {
		scrub = newScrubber(nil)
	}
	events, nerr := dbprobe.NormalizeAudit(q, raw, scrub, len(rows) > dbprobe.AuditMaxEvents)
	if !covered && nerr == nil {
		nerr = &dbprobe.AuditIncompleteError{Reason: "audit source retains no entry at or before the window start (rotated, evicted or enabled mid-run)"}
	}
	return events, nerr
}

// parseUserHost extracts the account from general_log.user_host, which has the
// form "user[user] @ host [ip]" ("[root] @ localhost []" for some internals).
func parseUserHost(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "["); i > 0 {
		return strings.TrimSpace(s[:i])
	} else if i == 0 {
		if j := strings.Index(s, "]"); j > 1 {
			return s[1:j]
		}
	}
	return s
}

// parseEpoch converts an epoch-seconds value ("1700000000.250000" as text from
// a DECIMAL, or an integer) to UTC time; zero on anything unparsable.
func parseEpoch(v any) time.Time {
	var s string
	switch t := v.(type) {
	case int64:
		return time.Unix(t, 0).UTC()
	case float64:
		return time.Unix(int64(t), int64((t-float64(int64(t)))*1e9)).UTC()
	case []byte:
		s = string(t)
	case string:
		s = t
	default:
		return time.Time{}
	}
	sec, frac, _ := strings.Cut(strings.TrimSpace(s), ".")
	secs, err := strconv.ParseInt(sec, 10, 64)
	if err != nil || secs < 0 {
		return time.Time{}
	}
	var nanos int64
	if frac != "" {
		if len(frac) > 9 {
			frac = frac[:9]
		}
		for len(frac) < 9 {
			frac += "0"
		}
		nanos, err = strconv.ParseInt(frac, 10, 64)
		if err != nil {
			return time.Time{}
		}
	}
	return time.Unix(secs, nanos).UTC()
}

// auditConfigNotes renders the read_audit_config observations as key=value
// lines plus the coverage summary. plugins are (PLUGIN_NAME, PLUGIN_STATUS).
func auditConfigNotes(st auditState, plugins [][]any) []string {
	onOff := func(b bool) string {
		if b {
			return "ON"
		}
		return "OFF"
	}
	readable := func(b bool) string {
		if b {
			return "readable"
		}
		return "unreadable"
	}
	notes := []string{
		"general_log=" + onOff(st.glOn),
		"log_output=" + dbprobe.TruncateUTF8(st.logOutput, 100),
		"performance_schema=" + onOff(st.psOn),
	}
	var pl []string
	activePlugin := false
	for _, p := range plugins {
		if len(p) >= 2 {
			pl = append(pl, str(p[0])+":"+str(p[1]))
			if strings.EqualFold(str(p[1]), "ACTIVE") {
				activePlugin = true
			}
		}
	}
	if len(pl) == 0 {
		pl = []string{"none"}
	}
	notes = append(notes, "audit_plugins="+dbprobe.TruncateUTF8(strings.Join(pl, ","), 200))
	for _, n := range consumerNames {
		v := "unreadable"
		if st.consumersReadable {
			if v = st.consumers[n]; v == "" {
				v = "absent"
			}
		}
		notes = append(notes, "ps_consumer."+n+"="+v)
	}
	notes = append(notes,
		srcGeneralLog+"="+readable(st.glReadable),
		srcHistoryLong+"="+readable(st.histReadable))
	notes = append(notes, "audit_config: "+mysqlAuditCoverage(st.glUsable() || st.histUsable(), st.glOn || activePlugin || (st.psOn && st.consumersOK())))
	return notes
}

// mysqlAuditCoverage: covered when a queryable source exists, partial when
// something logs but is not queryable by this account, none otherwise.
func mysqlAuditCoverage(queryable, anyLogging bool) string {
	switch {
	case queryable:
		return "covered"
	case anyLogging:
		return "partial"
	}
	return "none"
}
