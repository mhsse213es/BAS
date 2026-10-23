// Package mysql is the MySQL dbprobe adapter (read-only core). It registers
// itself under engine "mysql". Probes are observations only; nothing here
// scores.
//
// Differences from the PostgreSQL adapter, stated rather than hidden:
//   - No application_name: the per-probe marker travels only as a sanitized
//     leading /* ... */ query comment. The driver can set connection attributes
//     (Config.ConnectionAttributes, verified in go-sql-driver/mysql v1.10.1) but
//     only at connect time, so the only attribute set is the static
//     program_name:dbsim, never the per-probe marker.
//   - Statement time limit is SET SESSION max_execution_time (MySQL 5.7.8+,
//     SELECT only, milliseconds). MariaDB uses max_statement_time instead; that
//     is NOT implemented, so MariaDB fails closed (unknown variable).
//   - Identity is @@server_uuid. MariaDB has no server_uuid; Identity then
//     returns an error so the target-identity gate fails closed.
//   - DDL in Seed/Cleanup implicitly commits and cannot be rolled back, so a
//     failed Seed drops what it created instead.
package mysql

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	drv "github.com/go-sql-driver/mysql"

	"audspect/agent/dbprobe"
)

const engineName = "mysql"

func init() {
	dbprobe.Register(engineName, func() dbprobe.Adapter { return New() })
}

// session is the seam around the driver so probe logic is unit-testable.
// Query reads at most maxRows rows.
type session interface {
	Exec(ctx context.Context, sql string, args ...any) error
	Query(ctx context.Context, sql string, maxRows int, args ...any) ([][]any, error)
	Close(ctx context.Context) error
}

// sqlSession pins one database/sql connection so transaction statements and
// session variables all land on the same server connection.
type sqlSession struct {
	db *sql.DB
	c  *sql.Conn
}

func (s *sqlSession) Exec(ctx context.Context, q string, args ...any) error {
	_, err := s.c.ExecContext(ctx, q, args...)
	return err
}

func (s *sqlSession) Query(ctx context.Context, q string, maxRows int, args ...any) ([][]any, error) {
	rows, err := s.c.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out [][]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		out = append(out, vals)
		if len(out) >= maxRows {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *sqlSession) Close(ctx context.Context) error {
	cerr := s.c.Close()
	derr := s.db.Close()
	if cerr != nil {
		return cerr
	}
	return derr
}

// Adapter implements dbprobe.Adapter for MySQL. It deliberately holds no
// plaintext secret in a field: error scrubbing goes through a closure.
type Adapter struct {
	// ActiveFixture is the run's seeded fixture, bound by the executor after
	// Seed and cleared before Cleanup. Fixture-aware probes resolve their table
	// against it (spec R-Z); without one they fail closed.
	dbprobe.ActiveFixture

	s      session
	mode   dbprobe.ExecMode
	scrub  func(string) string
	notes  []string
	broken bool // connection closed after a timeout/cancel; reconnect required

	// Audit sources discovered once at Connect (audit.go); Capabilities and
	// CollectAudit read the cache and never query to answer.
	auditSources []string
	auditNotes   []string
	auditErr     string            // discovery hit a server timeout/shutdown: audit status is error
	auditSync    dbprobe.AuditSync // injectable clock/sleep for the catch-up wait (zero = real)

	// target is where Connect connected (never the password): auth_after_revoke
	// opens NEW connections to it as the throwaway account. dial is the injectable
	// seam for those connections (nil = real driver); acct tracks the throwaway
	// account this adapter created, so Cleanup drops exactly it.
	target dbprobe.ConnectionConfig
	dial   func(ctx context.Context, cfg dbprobe.ConnectionConfig) (session, error)
	acct   acctState
}

// String and GoString never print connection details or secrets.
func (a Adapter) String() string {
	return fmt.Sprintf("mysql.Adapter{connected=%t mode=%s broken=%t}", a.s != nil, a.mode, a.broken)
}

// GoString is the %#v form; same redaction as String.
func (a Adapter) GoString() string { return a.String() }

// New returns an unconnected adapter.
func New() *Adapter { return &Adapter{} }

// tlsFor maps a TLSMode to a TLS config. Empty / "verify-full" verifies the
// server certificate and name with TLS >= 1.2 and no plaintext fallback.
// "insecure-skip-verify" and "disable" are explicit opt-outs and return a note
// that must be reported. Anything else fails closed.
func tlsFor(mode, host string) (*tls.Config, string, error) {
	switch mode {
	case "", "verify-full":
		if host == "" {
			return nil, "", errors.New("dbprobe/mysql: host required to verify the server certificate")
		}
		return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}, "", nil
	case "insecure-skip-verify":
		return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, //nolint:gosec // explicit, reported opt-out
			"tls: certificate verification DISABLED by explicit opt-out", nil
	case "disable":
		return nil, "tls: DISABLED by explicit opt-out", nil
	}
	return nil, "", fmt.Errorf("dbprobe/mysql: unknown tlsMode %q", mode)
}

// secretsFor lists literals to scrub from error text. The password is always
// scrubbed; user and host only when long enough not to mangle ordinary text.
func secretsFor(cfg dbprobe.ConnectionConfig) []string {
	var out []string
	if cfg.Password != "" {
		out = append(out, cfg.Password)
	}
	for _, v := range []string{cfg.User, cfg.Host} {
		if len(v) >= 4 {
			out = append(out, v)
		}
	}
	return out
}

// buildConfig builds the driver Config field by field, never from a DSN
// string, so credentials (which may contain ':', '@', '/', ')') cannot be
// misparsed or end up in a formattable string.
//
// Isolation from the ambient environment: go-sql-driver/mysql v1.10.1 has no
// os.Getenv/LookupEnv and reads no my.cnf/.my.cnf (checked in the module
// source; its only file access is LOAD DATA LOCAL INFILE, which stays disabled
// because AllowAllFiles is false). So MYSQL_* variables and option files cannot
// influence a connection; every value below comes from ConnectionConfig.
func buildConfig(cfg dbprobe.ConnectionConfig) (*drv.Config, []string, error) {
	if cfg.Host == "" {
		return nil, nil, errors.New("dbprobe/mysql: host required")
	}
	port := cfg.Port
	if port == 0 {
		port = 3306
	}
	if port < 1 || port > 65535 {
		return nil, nil, fmt.Errorf("dbprobe/mysql: port %d out of range", cfg.Port)
	}
	tlsCfg, note, err := tlsFor(cfg.TLSMode, cfg.Host)
	if err != nil {
		return nil, nil, err
	}
	mc := drv.NewConfig()
	mc.User = cfg.User
	mc.Passwd = cfg.Password
	mc.Net = "tcp"
	mc.Addr = net.JoinHostPort(cfg.Host, strconv.Itoa(port))
	mc.DBName = cfg.Database
	mc.TLS = tlsCfg // nil only for the explicit "disable" opt-out
	mc.TLSConfig = ""
	mc.AllowFallbackToPlaintext = false
	mc.Timeout = 10 * time.Second
	mc.ParseTime = true
	mc.Logger = &drv.NopLogger{}
	mc.ConnectionAttributes = "program_name:dbsim"
	var notes []string
	if note != "" {
		notes = append(notes, note)
	}
	return mc, notes, nil
}

// Connect opens one connection. Any previous connection is closed first, but
// only after the new config validates. TLS verification is on unless the
// explicit opt-outs in tlsFor are chosen; those are reported in every
// ProbeResult's Notes. State (mode, notes, scrubber) only changes when the new
// connection succeeds.
func (a *Adapter) Connect(ctx context.Context, cfg dbprobe.ConnectionConfig) error {
	if cfg.Mode != dbprobe.ModeLab && cfg.Mode != dbprobe.ModeClient && cfg.Mode != "" {
		return fmt.Errorf("dbprobe/mysql: invalid mode %q", cfg.Mode)
	}
	mc, notes, err := buildConfig(cfg)
	if err != nil {
		return err
	}
	scrub := newScrubber(secretsFor(cfg))
	a.closeConn()
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := openSession(cctx, mc)
	if err != nil {
		return wrapErrWith("connect", err, scrub)
	}
	a.s = conn
	a.broken = false
	a.mode = cfg.Mode
	a.scrub = scrub
	a.notes = notes
	a.target = cfg
	a.target.Password = "" // new connections use the throwaway account's own credential
	// Find out what audit evidence this target can give us. No usable source
	// is not a failure; a broken connection is.
	if err := a.discoverAudit(ctx); err != nil {
		a.closeConn()
		return err
	}
	return nil
}

func openSession(ctx context.Context, mc *drv.Config) (session, error) {
	connector, err := drv.NewConnector(mc)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	c, err := db.Conn(ctx)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &sqlSession{db: db, c: c}, nil
}

func (a *Adapter) closeConn() {
	if a.s == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = a.s.Close(ctx)
	a.s = nil
}

// Close closes the connection.
func (a *Adapter) Close() error {
	a.closeConn()
	return nil
}

// markBroken closes a connection that hit a timeout or cancellation: its
// protocol state is unknown, so it must not be reused.
func (a *Adapter) markBroken() {
	a.closeConn()
	a.broken = true
}

func isCtxErr(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

func (a *Adapter) require() error {
	if a.broken {
		return errors.New("dbprobe/mysql: connection closed after a timeout or cancellation; reconnect")
	}
	if a.s == nil {
		return errors.New("dbprobe/mysql: not connected")
	}
	return nil
}

func (a *Adapter) wrap(op string, err error) error { return wrapErrWith(op, err, a.scrub) }

// Default limits for metadata reads (identity, roles, grants).
var metaLimits = dbprobe.Limits{MaxRows: 10000, TimeoutSec: 30, MaxConns: 1}

const metaMarker = dbprobe.MetaMarker

// inTxn is the one place client-mode statements run. It issues
// START TRANSACTION READ ONLY (always, for read-only work), sets the
// max_execution_time statement limit, runs fn, then ROLLBACK, all under the
// limits' deadline. fn gets the leading marker comment to prefix to its SQL;
// its error is returned unwrapped so callers can classify it (a ctx cause is
// attached when the context is done). A timeout or cancellation marks the
// adapter broken and skips ROLLBACK.
func (a *Adapter) inTxn(ctx context.Context, mode dbprobe.ExecMode, class dbprobe.ProbeClass,
	lim dbprobe.Limits, marker string, fn func(ctx context.Context, comment string) error) error {
	if err := a.require(); err != nil {
		return err
	}
	ctx, cancel := dbprobe.WithDeadline(ctx, lim)
	defer cancel()
	withCtx := func(err error) error {
		if err == nil {
			return nil
		}
		if isCtxErr(err) || ctx.Err() != nil {
			a.markBroken()
			if !isCtxErr(err) {
				err = fmt.Errorf("%w (%v)", ctx.Err(), err)
			}
		}
		return err
	}
	step := func(op string, err error) error {
		if err = withCtx(err); err == nil {
			return nil
		}
		return a.wrap(op, err)
	}
	if err := step("begin", a.s.Exec(ctx, beginStmt(mode, class))); err != nil {
		return err
	}
	defer func() {
		if a.broken || a.s == nil {
			return
		}
		rb, c := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer c()
		_ = a.s.Exec(rb, "ROLLBACK")
	}()
	if err := step("settings", a.s.Exec(ctx, timeLimitStmt(lim))); err != nil {
		return err
	}
	return withCtx(fn(ctx, markerComment(marker)+" "))
}

// metaQueryRaw returns driver errors from the query itself unwrapped (so
// callers can classify them) and already-redacted errors for everything else.
func (a *Adapter) metaQueryRaw(ctx context.Context, sqlText string, maxRows int) ([][]any, error) {
	var rows [][]any
	err := a.inTxn(ctx, a.mode, dbprobe.ClassReadOnly, metaLimits, metaMarker, func(ctx context.Context, comment string) error {
		var qerr error
		rows, qerr = a.s.Query(ctx, comment+sqlText, maxRows+1)
		return qerr
	})
	if err != nil {
		return nil, err
	}
	if len(rows) > maxRows {
		return nil, fmt.Errorf("dbprobe/mysql: result exceeds %d rows", maxRows)
	}
	return rows, nil
}

func (a *Adapter) metaQuery(ctx context.Context, op, sqlText string, maxRows int) ([][]any, error) {
	rows, err := a.metaQueryRaw(ctx, sqlText, maxRows)
	if err != nil {
		var re *redactedError
		if errors.As(err, &re) || strings.HasPrefix(err.Error(), "dbprobe/mysql:") {
			return nil, err
		}
		return nil, a.wrap(op, err)
	}
	return rows, nil
}

// Identity returns @@server_uuid. MariaDB has no server_uuid; that, and an
// empty or ambiguous answer, is an error so the identity gate fails closed.
func (a *Adapter) Identity(ctx context.Context) (string, error) {
	rows, err := a.metaQueryRaw(ctx, sqlIdentity, 2)
	if err != nil {
		var me *drv.MySQLError
		if errors.As(err, &me) && me.Number == 1193 {
			return "", errors.New("dbprobe/mysql: server has no @@server_uuid (MariaDB is not supported); identity cannot be verified")
		}
		var re *redactedError
		if errors.As(err, &re) || strings.HasPrefix(err.Error(), "dbprobe/mysql:") {
			return "", err
		}
		return "", a.wrap("identity", err)
	}
	if len(rows) != 1 || len(rows[0]) != 1 {
		return "", errors.New("dbprobe/mysql: identity query returned no single row")
	}
	id := strings.TrimSpace(str(rows[0][0]))
	if id == "" {
		return "", errors.New("dbprobe/mysql: server returned an empty server_uuid")
	}
	return id, nil
}

// EnumerateRoles lists non-system accounts.
func (a *Adapter) EnumerateRoles(ctx context.Context) ([]Role, error) {
	rows, err := a.metaQuery(ctx, "roles", sqlRoles, metaLimits.MaxRows)
	if err != nil {
		return nil, err
	}
	return toRoles(rows), nil
}

// ReadGrants lists table grants outside the system schemas.
func (a *Adapter) ReadGrants(ctx context.Context) ([]Grant, error) {
	rows, err := a.metaQuery(ctx, "grants", sqlAllGrants, metaLimits.MaxRows)
	if err != nil {
		return nil, err
	}
	return toGrants(rows), nil
}

// Aliases so signatures read like the interface.
type (
	Role  = dbprobe.Role
	Grant = dbprobe.Grant
)

func toRoles(rows [][]any) []Role {
	out := make([]Role, 0, len(rows))
	for _, r := range rows {
		if len(r) < 4 {
			continue
		}
		name := str(r[0])
		if h := str(r[1]); h != "%" && h != "" {
			name += "@" + h
		}
		out = append(out, Role{Name: name, Login: truthy(r[2]), Superuser: truthy(r[3])})
	}
	return out
}

func toGrants(rows [][]any) []Grant {
	out := make([]Grant, 0, len(rows))
	for _, r := range rows {
		if len(r) < 3 {
			continue
		}
		out = append(out, Grant{Role: parseGrantee(str(r[0])), Object: str(r[1]), Privilege: str(r[2])})
	}
	return out
}

func str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []byte:
		return string(t)
	default:
		return fmt.Sprint(t)
	}
}

func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case int64:
		return t != 0
	case []byte:
		s := string(t)
		return s == "1" || s == "Y" || s == "true"
	case string:
		return t == "1" || t == "Y" || t == "true"
	}
	return false
}

// Capabilities declares what this adapter supports. AuditSources reflects what
// Connect actually discovered (empty before Connect, and whenever neither
// general_log TABLE nor performance_schema history is usable), so callers treat
// missing audit as unsupported (SKIPPED), never as a pass. It answers from the
// cache; it issues no SQL.
func (a *Adapter) Capabilities() dbprobe.Capabilities {
	c := dbprobe.Capabilities{
		ProbeIDs: []string{"auth_after_revoke", "auth_check", "bounded_synthetic_read", "check_export_privileges", "check_readonly_identity", "read_audit_config", "read_classified_fixture",
			"read_grants", "read_restricted_table", "read_roles", "suspicious_read", "try_disable_audit", "try_write_fixture"},
		MarkerInAppName:   false, // no per-probe session attribute: attributes are connect-time only
		MarkerInQueryText: true,
		// The marker can only reach an audit record through the statement
		// text; true only when a source was discovered.
		MarkerInAuditRecord: len(a.auditSources) > 0,
		Notes: []string{
			"MySQL has no application_name; the per-probe marker is a leading /* */ query comment only.",
			"A static connection attribute program_name:dbsim is set (go-sql-driver ConnectionAttributes); it is connect-time, so it never carries the per-probe marker.",
			"MySQL's general_log and some audit plugins may strip or normalise comments; marker survival in those sinks is not verified here.",
			"Statement time limit is SET SESSION max_execution_time (MySQL 5.7.8+, SELECT only). MariaDB uses max_statement_time instead; that is not implemented and MariaDB fails closed.",
			"Identity is @@server_uuid; MariaDB lacks server_uuid and Identity returns an error there.",
		},
	}
	c.AuditError = a.auditErr
	c.Notes = append(c.Notes, a.auditNotes...)
	if len(a.auditSources) > 0 {
		c.AuditSources = append([]string(nil), a.auditSources...)
	}
	return c
}

// effectiveMode is lab only when both the connection and the spec say lab.
func (a *Adapter) effectiveMode(spec dbprobe.DBProbeSpec) dbprobe.ExecMode {
	if a.mode == dbprobe.ModeLab && spec.Mode == dbprobe.ModeLab {
		return dbprobe.ModeLab
	}
	return dbprobe.ModeClient
}

// beginStmt returns the transaction start for a probe. Read-only probes are
// always READ ONLY; anything that is not exactly lab mode is READ ONLY
// regardless of class.
func beginStmt(mode dbprobe.ExecMode, class dbprobe.ProbeClass) string {
	if mode != dbprobe.ModeLab || class == dbprobe.ClassReadOnly {
		return "START TRANSACTION READ ONLY"
	}
	return "START TRANSACTION"
}

// timeLimitStmt sets the per-statement server time limit in milliseconds. The
// value is an integer derived from validated, capped limits (never text).
func timeLimitStmt(l dbprobe.Limits) string {
	return "SET SESSION max_execution_time = " + strconv.Itoa(l.TimeoutSec*1000)
}

func sanitizeMarker(m string, max int) string { return dbprobe.SanitizeMarker(m, max) }

// markerComment is the leading SQL comment carrying the marker. The marker is
// reduced to [A-Za-z0-9._:-] so it cannot terminate the comment or turn it
// into an executable /*! ... */ comment (the "dbsim:" prefix always precedes it).
func markerComment(marker string) string { return dbprobe.MarkerComment(marker) }

// RunProbe runs one named probe and returns observations only.
func (a *Adapter) RunProbe(ctx context.Context, def dbprobe.ProbeDef, spec dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error) {
	var res dbprobe.ProbeResult
	if err := a.require(); err != nil {
		return res, err
	}
	real, ok := dbprobe.LookupProbe(spec.ProbeID)
	if !ok || def.ID != spec.ProbeID || real.Class != def.Class {
		return res, fmt.Errorf("dbprobe/mysql: unknown or mismatched probe %q", spec.ProbeID)
	}
	if spec.Engine != engineName {
		return res, fmt.Errorf("dbprobe/mysql: spec engine %q is not mysql", spec.Engine)
	}
	if err := dbprobe.ValidateSpec(spec); err != nil {
		return res, err
	}
	if err := checkParams(real, spec.Params); err != nil {
		return res, err
	}
	mode := a.effectiveMode(spec)
	if spec.ProbeID == dbprobe.ProbeAuthAfterRevoke {
		return a.runAuthAfterRevoke(ctx, real, spec, mode)
	}
	switch spec.ProbeID {
	case dbprobe.ProbeTryDisableAudit:
		return a.runTryDisableAudit(ctx, real, spec, mode)
	case dbprobe.ProbeTryWriteFixture:
		return a.runTryWriteFixture(ctx, real, spec, mode)
	case dbprobe.ProbeCheckExportPrivileges:
		return a.runCheckExportPrivileges(ctx, spec, mode)
	case dbprobe.ProbeCheckReadOnlyIdentity:
		return a.runCheckReadOnlyIdentity(ctx, spec, mode)
	}
	var (
		sqlText string
		args    []any
		err     error
		rowCap  int // fixture reads only
	)
	// A fixture-aware probe is resolved against the active fixture (never a
	// param-supplied schema). Its SQL is a SELECT, so the transaction is always
	// READ ONLY whatever the probe's class is; it asks for rowCap+1 rows so a
	// truncation is observable, and keeps at most rowCap.
	isFixtureRead := dbprobe.IsFixtureRead(real)
	txClass, queryMax := real.Class, spec.Limits.MaxRows+1
	if isFixtureRead {
		sqlText, args, rowCap, err = a.fixtureReadStmt(real, spec, mode)
		txClass, queryMax = dbprobe.ClassReadOnly, rowCap+1
	} else {
		sqlText, args, err = probeSQL(spec.ProbeID, spec.Params, spec.Limits.MaxRows)
	}
	if err != nil {
		return res, err
	}

	res.AgentTime = time.Now().UTC()
	res.Notes = append(res.Notes, a.notes...)
	var rows [][]any
	readStart := time.Now()
	err = a.inTxn(ctx, mode, txClass, spec.Limits, spec.Marker, func(ctx context.Context, comment string) error {
		clk, err := a.s.Query(ctx, comment+sqlClock, 1)
		if err != nil {
			return err
		}
		if len(clk) != 1 || len(clk[0]) != 1 {
			return errors.New("no clock row")
		}
		res.DBTime = toTime(clk[0][0])
		rows, err = a.s.Query(ctx, comment+sqlText, queryMax, args...)
		if err != nil || spec.ProbeID != probeAuditConfig {
			return err
		}
		st, err := a.gatherAuditState(ctx, comment)
		if err != nil {
			return err
		}
		res.Notes = append(res.Notes, auditConfigNotes(st, rows)...)
		return nil
	})
	if a.broken {
		res.ErrorClass = "timeout"
		if err != nil && errors.Is(err, context.Canceled) {
			res.ErrorClass = "canceled"
		}
		res.Notes = append(res.Notes, "connection closed after timeout or cancellation; reconnect required")
		return res, nil
	}
	if err != nil {
		var me *drv.MySQLError
		if errors.As(err, &me) {
			classify(&res, me)
			return res, nil
		}
		var re *redactedError
		if errors.As(err, &re) || strings.HasPrefix(err.Error(), "dbprobe/mysql:") {
			return res, err
		}
		return res, a.wrap("probe", err)
	}
	b := dbprobe.NewBudget(spec.Limits)
	if isFixtureRead {
		// Counts only: the rows are measured and dropped, never reported.
		sum := dbprobe.SummarizeBoundedRead(rows, rowCap, dbprobe.MaxReadBytes)
		if err := b.Charge(sum.Rows); err != nil {
			res.ErrorClass = "row_limit_exceeded"
			return res, nil
		}
		res.RowsRead = b.Used()
		if rowCap < spec.Limits.MaxRows {
			res.Notes = append(res.Notes, fmt.Sprintf("row_cap_applied=%d", rowCap))
		}
		res.Notes = append(res.Notes, sum.Notes(dbprobe.ReadShape(spec.ProbeID), time.Since(readStart))...)
		return res, nil
	}
	if err := b.Charge(len(rows)); err != nil {
		res.ErrorClass = "row_limit_exceeded"
		res.Notes = append(res.Notes, fmt.Sprintf("row limit %d exceeded", spec.Limits.MaxRows))
		return res, nil
	}
	res.RowsRead = b.Used()
	return res, nil
}

func toTime(v any) time.Time {
	switch t := v.(type) {
	case time.Time:
		return t.UTC()
	case []byte:
		if ts, err := time.ParseInLocation("2006-01-02 15:04:05.999999", string(t), time.UTC); err == nil {
			return ts
		}
	}
	return time.Time{}
}

// classify maps MySQL server error numbers to observation classes.
func classify(res *dbprobe.ProbeResult, me *drv.MySQLError) {
	switch me.Number {
	case 1044, 1142, 1143, 1227: // db / table / column / specific privilege denied
		res.Denied = true
		res.ErrorClass = "permission_denied"
	case 1045, 1698: // access denied for user
		res.Denied = true
		res.ErrorClass = "auth_failed"
	case 1146: // table does not exist
		res.ErrorClass = "undefined_table"
	case 1792: // ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION
		res.ErrorClass = "read_only_violation"
	case 3024: // ER_QUERY_TIMEOUT (max_execution_time)
		res.ErrorClass = "timeout"
	default:
		res.ErrorClass = "mysql_error_" + strconv.Itoa(int(me.Number))
	}
}

const labOpTimeout = 30 * time.Second

func fixtureNames(id string) (schema, user string, err error) {
	id = strings.ReplaceAll(strings.ToLower(id), "-", "_")
	if !fixtureID.MatchString(id) {
		return "", "", errors.New("dbprobe/mysql: invalid fixture id")
	}
	return "dbsim_" + id, "dbsim_" + id + "_ro", nil
}

var userNamePat = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)

// userLit quotes a fixture account name as 'name'@'%'. fixtureNames already
// restricts it to [a-z0-9_]; this re-checks before any splice.
func userLit(name string) (string, error) {
	if !userNamePat.MatchString(name) {
		return "", errors.New("dbprobe/mysql: invalid fixture user")
	}
	return "'" + name + "'@'%'", nil
}

func (a *Adapter) requireLab(op string) error {
	if err := a.require(); err != nil {
		return err
	}
	if a.mode != dbprobe.ModeLab {
		return fmt.Errorf("dbprobe/mysql: %s refused outside lab mode", op)
	}
	return nil
}

// fixtureSQL returns the statements that create, and drop, a fixture.
func fixtureSQL(schema, user string) (create, drop []string, err error) {
	qs, err := quoteIdent(schema)
	if err != nil {
		return nil, nil, err
	}
	tbl := qs + ".`restricted`"
	ul, err := userLit(user)
	if err != nil {
		return nil, nil, err
	}
	create = []string{
		"CREATE SCHEMA " + qs,
		"CREATE TABLE " + tbl + " (id INT PRIMARY KEY, label VARCHAR(64))",
		"INSERT INTO " + tbl + " VALUES (1, 'synthetic-1'), (2, 'synthetic-2'), (3, 'synthetic-3')",
		"CREATE USER " + ul + " ACCOUNT LOCK",
		"GRANT SELECT ON " + tbl + " TO " + ul,
	}
	drop = []string{
		"DROP SCHEMA IF EXISTS " + qs,
		"DROP USER IF EXISTS " + ul,
	}
	return create, drop, nil
}

// Seed creates a small synthetic fixture (schema, table, locked account and a
// SELECT grant). Lab mode only; no real data. MySQL DDL implicitly commits, so
// on failure the partial fixture is dropped rather than rolled back.
func (a *Adapter) Seed(ctx context.Context, f dbprobe.Fixture) error {
	if err := a.requireLab("seed"); err != nil {
		return err
	}
	schema, user, err := fixtureNames(f.ID)
	if err != nil {
		return err
	}
	baseCreate, drop, err := fixtureSQL(schema, user)
	if err != nil {
		return err
	}
	if err := dbprobe.ValidateFixtureTables(f.Tables); err != nil {
		return err
	}
	create := make([]myStmt, len(baseCreate))
	for i, s := range baseCreate {
		create[i] = myStmt{sql: s}
	}
	if len(f.Tables) > 0 {
		if create, err = tableFixtureSQL(schema, user, f.Tables); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, labOpTimeout)
	defer cancel()
	// created holds the undo statement of every object THIS call has
	// successfully created, in creation order. A failure rolls back exactly
	// those, newest first, and nothing else: an object this call did not create
	// (for example a database that already existed, which makes CREATE SCHEMA
	// fail) is never dropped.
	var created []string
	for _, s := range attachUndo(create, drop) {
		if err := a.s.Exec(ctx, s.sql, s.args...); err != nil {
			werr := a.wrap("seed", err)
			if isCtxErr(err) || ctx.Err() != nil {
				a.markBroken()
				return werr // state unknown: no sentinel
			}
			rb, c := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			clean := true
			for i := len(created) - 1; i >= 0; i-- {
				if a.s.Exec(rb, created[i]) != nil {
					clean = false
				}
			}
			c()
			if !clean {
				return werr
			}
			return fmt.Errorf("%w: %s", dbprobe.ErrFixtureNotCreated, werr.Error())
		}
		if s.undo != "" {
			created = append(created, s.undo)
		}
	}
	return nil
}

// myStmt is one fixture statement; values are always bound via args. undo, when
// set, is the exact statement that removes the object this statement creates.
type myStmt struct {
	sql  string
	args []any
	undo string
}

// attachUndo marks the statements that create a schema or an account with the
// matching drop from fixtureSQL's drop list ([0] schema, [1] account).
func attachUndo(stmts []myStmt, drop []string) []myStmt {
	out := make([]myStmt, len(stmts))
	copy(out, stmts)
	for i := range out {
		switch {
		case strings.HasPrefix(out[i].sql, "CREATE SCHEMA"):
			out[i].undo = drop[0]
		case strings.HasPrefix(out[i].sql, "CREATE USER"):
			out[i].undo = drop[1]
		}
	}
	return out
}

// tableFixtureSQL turns declarative fixture tables into DDL/DML. Identifiers
// are validated by dbprobe.ValidateFixtureTables and quoted with quoteIdent;
// cell values are bound parameters, never spliced. In MySQL a schema is a
// database, so "dbsim_<id>" is a dedicated database.
func tableFixtureSQL(schema, user string, tables []dbprobe.FixtureTable) ([]myStmt, error) {
	qs, err := quoteIdent(schema)
	if err != nil {
		return nil, err
	}
	ul, err := userLit(user)
	if err != nil {
		return nil, err
	}
	out := []myStmt{{sql: "CREATE SCHEMA " + qs + " CHARACTER SET utf8mb4"}}
	qualified := make([]string, len(tables))
	for ti, t := range tables {
		qt, err := quoteIdent(t.Name)
		if err != nil {
			return nil, err
		}
		qualified[ti] = qs + "." + qt
		cols := make([]string, len(t.Columns))
		names := make([]string, len(t.Columns))
		marks := make([]string, len(t.Columns))
		for i, c := range t.Columns {
			qc, err := quoteIdent(c.Name)
			if err != nil {
				return nil, err
			}
			typ := "LONGTEXT CHARACTER SET utf8mb4"
			if c.Type == dbprobe.FixtureColInt {
				typ = "BIGINT"
			}
			def := qc + " " + typ
			if c.PK {
				def += " PRIMARY KEY"
			}
			cols[i], names[i], marks[i] = def, qc, "?"
		}
		out = append(out, myStmt{sql: "CREATE TABLE " + qualified[ti] + " (" + strings.Join(cols, ", ") + ") DEFAULT CHARSET=utf8mb4"})
		ins := "INSERT INTO " + qualified[ti] + " (" + strings.Join(names, ", ") + ") VALUES (" + strings.Join(marks, ", ") + ")"
		for _, row := range t.Rows {
			args := make([]any, len(row))
			for i, c := range row {
				args[i] = dbprobe.FixtureCellArg(c)
			}
			out = append(out, myStmt{sql: ins, args: args})
		}
	}
	out = append(out, myStmt{sql: "CREATE USER " + ul + " ACCOUNT LOCK"})
	for _, q := range qualified {
		out = append(out, myStmt{sql: "GRANT SELECT ON " + q + " TO " + ul})
	}
	return out, nil
}

// Mode reports the connection mode (dbprobe.ModeReporter); fixtures.Seed
// refuses anything but lab.
func (a *Adapter) Mode() dbprobe.ExecMode { return a.mode }

const sqlFixtureTables = "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME"

// fixtureInspectMax bounds how many objects one inspection reads.
const fixtureInspectMax = 200

// InspectFixture lists the objects that exist for a fixture: its schema, the
// tables in it and its account. Names are bound parameters. Lab mode only.
func (a *Adapter) InspectFixture(ctx context.Context, f dbprobe.Fixture) ([]string, error) {
	if err := a.requireLab("inspect"); err != nil {
		return nil, err
	}
	schema, user, err := fixtureNames(f.ID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, labOpTimeout)
	defer cancel()
	var out []string
	rows, err := a.s.Query(ctx, sqlSchemaExists, 1, schema)
	if err != nil {
		return nil, a.wrap("inspect", err)
	}
	if len(rows) > 0 {
		out = append(out, "schema:"+schema)
	}
	rows, err = a.s.Query(ctx, sqlFixtureTables, fixtureInspectMax, schema)
	if err != nil {
		return nil, a.wrap("inspect", err)
	}
	for _, r := range rows {
		if len(r) > 0 {
			out = append(out, "table:"+schema+"."+cellString(r[0]))
		}
	}
	rows, err = a.s.Query(ctx, sqlUserExists, 1, user)
	if err != nil {
		return nil, a.wrap("inspect", err)
	}
	if len(rows) > 0 {
		out = append(out, "user:"+user)
	}
	if a.acct.mayExist && a.acct.name != "" {
		// The throwaway login account this adapter created for auth_after_revoke.
		rows, err = a.s.Query(ctx, sqlUserExists, 1, a.acct.name)
		if err != nil {
			return nil, a.wrap("inspect", err)
		}
		if len(rows) > 0 {
			out = append(out, "user:"+a.acct.name)
		}
	}
	return out, nil
}

func cellString(v any) string {
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return fmt.Sprint(v)
}

// Cleanup drops the fixture schema and account (lab mode only) and verifies
// nothing is left behind. All statements run under a bounded context.
func (a *Adapter) Cleanup(ctx context.Context, f dbprobe.Fixture) (dbprobe.CleanupResult, error) {
	var out dbprobe.CleanupResult
	if err := a.requireLab("cleanup"); err != nil {
		return out, err
	}
	schema, user, err := fixtureNames(f.ID)
	if err != nil {
		return out, err
	}
	_, drop, err := fixtureSQL(schema, user)
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, labOpTimeout)
	defer cancel()
	var errs []string
	for _, s := range drop {
		if err := a.s.Exec(ctx, s); err != nil {
			errs = append(errs, a.wrap("cleanup", err).Error())
		}
	}
	if rows, err := a.s.Query(ctx, sqlSchemaExists, 1, schema); err != nil || len(rows) > 0 {
		out.Residual = append(out.Residual, "schema:"+schema)
	} else {
		out.Removed = append(out.Removed, "schema:"+schema)
	}
	if rows, err := a.s.Query(ctx, sqlUserExists, 1, user); err != nil || len(rows) > 0 {
		out.Residual = append(out.Residual, "user:"+user)
	} else {
		out.Removed = append(out.Removed, "user:"+user)
	}
	if a.acct.mayExist && a.acct.name != "" {
		// Exactly the account this adapter created for this run, by name, and only
		// when its CREATE was not refused: never a pattern, never another account.
		lit, lerr := userLit(a.acct.name)
		if lerr != nil {
			errs = append(errs, lerr.Error())
		} else if err := a.s.Exec(ctx, "DROP USER IF EXISTS "+lit); err != nil {
			errs = append(errs, a.wrap("cleanup", err).Error())
		}
		if rows, err := a.s.Query(ctx, sqlUserExists, 1, a.acct.name); err != nil || len(rows) > 0 {
			out.Residual = append(out.Residual, "user:"+a.acct.name)
		} else {
			out.Removed = append(out.Removed, "user:"+a.acct.name)
		}
	}
	if ctx.Err() != nil {
		a.markBroken()
		errs = append(errs, "cleanup timed out; connection closed")
	}
	out.Error = strings.Join(errs, "; ")
	return out, nil
}

var (
	// user:pass@tcp(host:port)/db?params, wherever it appears.
	reDSN = regexp.MustCompile(`(?i)[^\s'"]*@(?:tcp[46]?|unix)\([^)]*\)(?:/[^\s'"]*)?`)
	// 'user'@'host' as in "Access denied for user 'u'@'h'".
	reAccount = regexp.MustCompile(`'[^']*'@'[^']*'`)
	rePassKV  = regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*\S+`)
	// dial tcp 10.0.0.5:3306: ...
	reDial = regexp.MustCompile(`(?i)\b(dial (?:tcp[46]?|unix)) \S+?:(?:\s|$)`)
)

// redact removes DSNs, account names, passwords and dial addresses from driver
// text, then any literal secret.
func redact(s string, secrets ...string) string {
	return newScrubber(secrets)(s)
}

// newScrubber returns a function that redacts driver text. The secret literals
// live only in the closure so no formattable field holds them.
func newScrubber(secrets []string) func(string) string {
	var pairs []string
	list := append([]string(nil), secrets...)
	sort.Slice(list, func(i, j int) bool { return len(list[i]) > len(list[j]) })
	for _, sec := range list {
		if sec != "" {
			pairs = append(pairs, sec, "[redacted]")
		}
	}
	var rep *strings.Replacer
	if len(pairs) > 0 {
		rep = strings.NewReplacer(pairs...)
	}
	return func(s string) string {
		s = reDSN.ReplaceAllString(s, "[redacted-dsn]")
		s = reAccount.ReplaceAllString(s, "[redacted-account]")
		s = rePassKV.ReplaceAllString(s, "$1=[redacted]")
		s = reDial.ReplaceAllString(s, "$1 [redacted-addr]: ")
		if rep != nil {
			s = rep.Replace(s)
		}
		return s
	}
}

// redactedError carries only scrubbed text. Its chain is cut at the driver
// error (which can hold secrets) but keeps the cancel/timeout class so
// errors.Is(err, context.Canceled / DeadlineExceeded) still works.
type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.cause }

// wrapErr turns a driver error into a redacted error with no chain to the
// original except the context class.
func wrapErr(op string, err error, secrets ...string) error {
	return wrapErrWith(op, err, newScrubber(secrets))
}

func wrapErrWith(op string, err error, scrub func(string) string) error {
	if scrub == nil {
		scrub = newScrubber(nil)
	}
	var cause error
	switch {
	case errors.Is(err, context.Canceled):
		cause = context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		cause = context.DeadlineExceeded
	}
	return &redactedError{msg: "dbprobe/mysql: " + op + ": " + scrub(err.Error()), cause: cause}
}
