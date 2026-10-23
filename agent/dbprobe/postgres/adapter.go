// Package postgres is the PostgreSQL dbprobe adapter (read-only core). It
// registers itself under engine "postgresql". Probes are observations only;
// nothing here scores.
package postgres

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"audspect/agent/dbprobe"
)

const engineName = "postgresql"

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

type pgxSession struct{ c *pgx.Conn }

func (p *pgxSession) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := p.c.Exec(ctx, sql, args...)
	return err
}

func (p *pgxSession) Query(ctx context.Context, sql string, maxRows int, args ...any) ([][]any, error) {
	rows, err := p.c.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]any
	for rows.Next() {
		v, err := rows.Values()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		if len(out) >= maxRows {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *pgxSession) Close(ctx context.Context) error { return p.c.Close(ctx) }

// Adapter implements dbprobe.Adapter for PostgreSQL.
type Adapter struct {
	s       session
	mode    dbprobe.ExecMode
	secrets []string // literals to scrub from any error text (password, long user/host)
	notes   []string
	broken  bool // connection closed after a timeout/cancel; reconnect required

	// Audit sources discovered once at Connect (audit.go); Capabilities and
	// CollectAudit read the cache and never query to answer.
	auditSources []string
	auditNotes   []string
	auditErr     string            // discovery hit a server timeout/shutdown: audit status is error
	auditSync    dbprobe.AuditSync // injectable clock/sleep for the catch-up wait (zero = real)
}

// String and GoString never print connection details or secrets.
func (a Adapter) String() string {
	return fmt.Sprintf("postgres.Adapter{connected=%t mode=%s broken=%t}", a.s != nil, a.mode, a.broken)
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
		return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}, "", nil
	case "insecure-skip-verify":
		return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, //nolint:gosec // explicit, reported opt-out
			"tls: certificate verification DISABLED by explicit opt-out", nil
	case "disable":
		return nil, "tls: DISABLED by explicit opt-out", nil
	}
	return nil, "", fmt.Errorf("dbprobe/postgres: unknown tlsMode %q", mode)
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

// buildConnConfig builds a pgx config from an explicit, isolated base: nothing
// ambient (PG* env vars, .pgpass, service files) may influence the result.
// ParseConfig still consults the environment, so every field it can touch is
// overwritten or reset here.
func buildConnConfig(cfg dbprobe.ConnectionConfig) (*pgx.ConnConfig, []string, error) {
	port := cfg.Port
	if port == 0 {
		port = 5432
	}
	if port < 1 || port > 65535 {
		return nil, nil, fmt.Errorf("dbprobe/postgres: port %d out of range", cfg.Port)
	}
	tlsCfg, note, err := tlsFor(cfg.TLSMode, cfg.Host)
	if err != nil {
		return nil, nil, err
	}
	cc, err := pgx.ParseConfig("connect_timeout=10")
	if err != nil {
		return nil, nil, wrapErr("config", err, secretsFor(cfg)...)
	}
	cc.Host = cfg.Host
	cc.Port = uint16(port)
	cc.Database = cfg.Database
	cc.User = cfg.User
	cc.Password = cfg.Password
	cc.TLSConfig = tlsCfg
	cc.Fallbacks = nil
	cc.ValidateConnect = nil
	cc.AfterConnect = nil
	cc.ConnectTimeout = 10 * time.Second
	cc.RuntimeParams = map[string]string{"application_name": "dbsim"}
	cc.DefaultQueryExecMode = pgx.QueryExecModeExec
	var notes []string
	if note != "" {
		notes = append(notes, note)
	}
	return cc, notes, nil
}

// Connect opens one connection. Any previous connection is closed first. TLS
// verification is on unless the explicit opt-outs in tlsFor are chosen; those
// are reported in every ProbeResult's Notes. State (mode, notes, secrets) only
// changes when the new connection succeeds.
func (a *Adapter) Connect(ctx context.Context, cfg dbprobe.ConnectionConfig) error {
	cc, notes, err := buildConnConfig(cfg)
	if err != nil {
		return err
	}
	a.closeConn()
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return wrapErr("connect", err, secretsFor(cfg)...)
	}
	a.s = &pgxSession{c: conn}
	a.broken = false
	a.mode = cfg.Mode
	a.secrets = secretsFor(cfg)
	a.notes = notes
	// Find out what audit evidence this target can give us. A missing view is
	// not a failure; a broken connection is.
	if err := a.discoverAudit(ctx); err != nil {
		a.closeConn()
		return err
	}
	return nil
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
		return errors.New("dbprobe/postgres: connection closed after a timeout or cancellation; reconnect")
	}
	if a.s == nil {
		return errors.New("dbprobe/postgres: not connected")
	}
	return nil
}

// Default limits for metadata reads (identity, roles, grants).
var metaLimits = dbprobe.Limits{MaxRows: 10000, TimeoutSec: 30, MaxConns: 1}

const metaMarker = dbprobe.MetaMarker

// inTxn runs fn inside BEGIN READ ONLY (always, for read-only work) with the
// statement timeout and marker-derived application_name applied, then
// ROLLBACK. fn gets the leading marker comment to prefix to its SQL and its
// error is returned unwrapped so callers can classify it. A timeout or
// cancellation marks the adapter broken and skips ROLLBACK.
func (a *Adapter) inTxn(ctx context.Context, mode dbprobe.ExecMode, class dbprobe.ProbeClass,
	lim dbprobe.Limits, marker string, fn func(ctx context.Context, comment string) error) error {
	if err := a.require(); err != nil {
		return err
	}
	ctx, cancel := dbprobe.WithDeadline(ctx, lim)
	defer cancel()
	step := func(op string, err error) error {
		if err == nil {
			return nil
		}
		if isCtxErr(err) || ctx.Err() != nil {
			a.markBroken()
		}
		return wrapErr(op, err, a.secrets...)
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
	if err := step("settings", a.applyTxnSettings(ctx, dbprobe.DBProbeSpec{Marker: marker, Limits: lim})); err != nil {
		return err
	}
	err := fn(ctx, markerComment(marker)+" ")
	if err != nil && (isCtxErr(err) || ctx.Err() != nil) {
		a.markBroken()
	}
	return err
}

func (a *Adapter) metaQuery(ctx context.Context, op, sql string, maxRows int) ([][]any, error) {
	var rows [][]any
	err := a.inTxn(ctx, a.mode, dbprobe.ClassReadOnly, metaLimits, metaMarker, func(ctx context.Context, comment string) error {
		var qerr error
		rows, qerr = a.s.Query(ctx, comment+sql, maxRows)
		return qerr
	})
	if err != nil {
		if strings.HasPrefix(err.Error(), "dbprobe/postgres:") {
			return nil, err
		}
		return nil, wrapErr(op, err, a.secrets...)
	}
	return rows, nil
}

// Identity returns pg_control_system().system_identifier as a string.
func (a *Adapter) Identity(ctx context.Context) (string, error) {
	rows, err := a.metaQuery(ctx, "identity", sqlIdentity, 2)
	if err != nil {
		return "", err
	}
	if len(rows) != 1 || len(rows[0]) != 1 {
		return "", errors.New("dbprobe/postgres: identity query returned no row")
	}
	return str(rows[0][0]), nil
}

// EnumerateRoles lists non-system roles.
func (a *Adapter) EnumerateRoles(ctx context.Context) ([]Role, error) {
	rows, err := a.metaQuery(ctx, "roles", sqlRoles, 10000)
	if err != nil {
		return nil, err
	}
	return toRoles(rows), nil
}

// ReadGrants lists table grants outside the system schemas.
func (a *Adapter) ReadGrants(ctx context.Context) ([]Grant, error) {
	rows, err := a.metaQuery(ctx, "grants", sqlAllGrants, 10000)
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
		if len(r) < 3 {
			continue
		}
		out = append(out, Role{Name: str(r[0]), Login: r[1] == true, Superuser: r[2] == true})
	}
	return out
}

func toGrants(rows [][]any) []Grant {
	out := make([]Grant, 0, len(rows))
	for _, r := range rows {
		if len(r) < 3 {
			continue
		}
		out = append(out, Grant{Role: str(r[0]), Object: str(r[1]), Privilege: str(r[2])})
	}
	return out
}

func str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

// Capabilities declares what this adapter supports. AuditSources reflects what
// Connect actually discovered (empty before Connect, and whenever the audit
// view is absent/unreadable), so callers treat missing audit as unsupported
// (SKIPPED), never as a pass. It answers from the cache; it issues no SQL.
func (a *Adapter) Capabilities() dbprobe.Capabilities {
	c := dbprobe.Capabilities{
		ProbeIDs:          []string{"auth_check", "read_audit_config", "read_grants", "read_restricted_table", "read_roles"},
		MarkerInAppName:   true,
		MarkerInQueryText: true,
		// The marker can only reach an audit record through the statement
		// text, and only if the server logs it; true only with a source.
		MarkerInAuditRecord: len(a.auditSources) > 0,
	}
	if len(a.auditSources) > 0 {
		c.AuditSources = append([]string(nil), a.auditSources...)
	}
	c.AuditError = a.auditErr
	c.Notes = append(c.Notes, a.auditNotes...)
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
// always READ ONLY; client mode is READ ONLY regardless of class.
func beginStmt(mode dbprobe.ExecMode, class dbprobe.ProbeClass) string {
	if mode != dbprobe.ModeLab || class == dbprobe.ClassReadOnly {
		return "BEGIN READ ONLY"
	}
	return "BEGIN"
}

func sanitizeMarker(m string, max int) string { return dbprobe.SanitizeMarker(m, max) }

// appNameFor derives a safe application_name (<= 63 bytes) from the marker.
func appNameFor(marker string) string {
	n := sanitizeMarker(marker, 63)
	if n == "" {
		return "dbsim"
	}
	return n
}

// markerComment is the leading SQL comment carrying the marker. The marker is
// sanitized so it cannot terminate the comment.
func markerComment(marker string) string { return dbprobe.MarkerComment(marker) }

// applyTxnSettings sets the per-transaction statement timeout and the
// marker-derived application_name. Must run inside the probe transaction.
func (a *Adapter) applyTxnSettings(ctx context.Context, spec dbprobe.DBProbeSpec) error {
	ms := strconv.Itoa(spec.Limits.TimeoutSec * 1000)
	if err := a.s.Exec(ctx, "SELECT set_config('statement_timeout', $1, true)", ms); err != nil {
		return err
	}
	return a.s.Exec(ctx, "SELECT set_config('application_name', $1, true)", appNameFor(spec.Marker))
}

// RunProbe runs one named probe and returns observations only.
func (a *Adapter) RunProbe(ctx context.Context, def dbprobe.ProbeDef, spec dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error) {
	var res dbprobe.ProbeResult
	if err := a.require(); err != nil {
		return res, err
	}
	real, ok := dbprobe.LookupProbe(spec.ProbeID)
	if !ok || def.ID != spec.ProbeID || real.Class != def.Class {
		return res, fmt.Errorf("dbprobe/postgres: unknown or mismatched probe %q", spec.ProbeID)
	}
	if spec.Engine != engineName {
		return res, fmt.Errorf("dbprobe/postgres: spec engine %q is not postgresql", spec.Engine)
	}
	if err := dbprobe.ValidateSpec(spec); err != nil {
		return res, err
	}
	if err := checkParams(real, spec.Params); err != nil {
		return res, err
	}
	sql, args, err := probeSQL(spec.ProbeID, spec.Params, spec.Limits.MaxRows)
	if err != nil {
		return res, err
	}
	mode := a.effectiveMode(spec)

	res.AgentTime = time.Now().UTC()
	res.Notes = append(res.Notes, a.notes...)
	var rows [][]any
	err = a.inTxn(ctx, mode, real.Class, spec.Limits, spec.Marker, func(ctx context.Context, comment string) error {
		clk, err := a.s.Query(ctx, comment+sqlClock, 1)
		if err != nil {
			return err
		}
		if len(clk) != 1 || len(clk[0]) != 1 {
			return errors.New("no clock row")
		}
		if t, ok := clk[0][0].(time.Time); ok {
			res.DBTime = t.UTC()
		}
		rows, err = a.s.Query(ctx, comment+sql, spec.Limits.MaxRows+1, args...)
		if err != nil || spec.ProbeID != probeAuditConfig {
			return err
		}
		view, err := a.s.Query(ctx, comment+sqlAuditViewState, 1)
		if err != nil {
			return err
		}
		var vs []any
		if len(view) == 1 {
			vs = view[0]
		}
		res.Notes = append(res.Notes, auditConfigNotes(rows, vs)...)
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
		var pe *pgconn.PgError
		if errors.As(err, &pe) {
			classify(&res, pe)
			return res, nil
		}
		if strings.HasPrefix(err.Error(), "dbprobe/postgres:") {
			return res, err
		}
		return res, wrapErr("probe", err, a.secrets...)
	}
	b := dbprobe.NewBudget(spec.Limits)
	if err := b.Charge(len(rows)); err != nil {
		res.ErrorClass = "row_limit_exceeded"
		res.Notes = append(res.Notes, fmt.Sprintf("row limit %d exceeded", spec.Limits.MaxRows))
		return res, nil
	}
	res.RowsRead = b.Used()
	return res, nil
}

func classify(res *dbprobe.ProbeResult, pe *pgconn.PgError) {
	switch {
	case pe.Code == "42501":
		res.Denied = true
		res.ErrorClass = "permission_denied"
	case strings.HasPrefix(pe.Code, "28"):
		res.Denied = true
		res.ErrorClass = "auth_failed"
	case pe.Code == "42P01":
		res.ErrorClass = "undefined_table"
	case pe.Code == "25006":
		res.ErrorClass = "read_only_violation"
	case pe.Code == "57014":
		res.ErrorClass = "timeout"
	default:
		res.ErrorClass = "sqlstate_" + pe.Code
	}
}

func errOr(err error, msg string) error {
	if err != nil {
		return err
	}
	return errors.New(msg)
}

const labOpTimeout = 30 * time.Second

// Seed creates a small synthetic fixture (schema, table, NOLOGIN role and a
// SELECT grant). Lab mode only; no real data.
func (a *Adapter) Seed(ctx context.Context, f dbprobe.Fixture) error {
	if err := a.require(); err != nil {
		return err
	}
	if a.mode != dbprobe.ModeLab {
		return errors.New("dbprobe/postgres: seed refused outside lab mode")
	}
	schema, role, err := fixtureNames(f.ID)
	if err != nil {
		return err
	}
	if err := dbprobe.ValidateFixtureTables(f.Tables); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, labOpTimeout)
	defer cancel()
	tbl := pgx.Identifier{schema, "restricted"}.Sanitize()
	stmts := []pgStmt{
		{sql: "CREATE SCHEMA " + pgx.Identifier{schema}.Sanitize()},
		{sql: "CREATE TABLE " + tbl + " (id int PRIMARY KEY, label text)"},
		{sql: "INSERT INTO " + tbl + " VALUES (1, 'synthetic-1'), (2, 'synthetic-2'), (3, 'synthetic-3')"},
		{sql: "CREATE ROLE " + pgx.Identifier{role}.Sanitize() + " NOLOGIN"},
		{sql: "GRANT USAGE ON SCHEMA " + pgx.Identifier{schema}.Sanitize() + " TO " + pgx.Identifier{role}.Sanitize()},
		{sql: "GRANT SELECT ON " + tbl + " TO " + pgx.Identifier{role}.Sanitize()},
	}
	if len(f.Tables) > 0 {
		stmts = tableFixtureStmts(schema, role, f.Tables)
	}
	// fail rolls the transaction back (PG DDL is transactional, so nothing this
	// call created survives and nothing else is ever dropped). When rollback
	// is confirmed, the error wraps dbprobe.ErrFixtureNotCreated so the caller
	// skips Cleanup (its DROP ... CASCADE must never reach an object this call
	// did not create). When the outcome is unknown (cancelled context, failed
	// rollback, commit failure) the sentinel is withheld.
	fail := func(err error, claim bool) error {
		werr := wrapErr("seed", err, a.secrets...)
		if isCtxErr(err) || ctx.Err() != nil {
			a.markBroken()
			return werr
		}
		rb, c := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		rerr := a.s.Exec(rb, "ROLLBACK") // also clears an aborted transaction state
		c()
		if rerr != nil || !claim {
			return werr
		}
		return fmt.Errorf("%w: %s", dbprobe.ErrFixtureNotCreated, werr.Error())
	}
	if err := a.s.Exec(ctx, "BEGIN"); err != nil {
		return fail(err, false)
	}
	for _, s := range stmts {
		if err := a.s.Exec(ctx, s.sql, s.args...); err != nil {
			return fail(err, true)
		}
	}
	if err := a.s.Exec(ctx, "COMMIT"); err != nil {
		return fail(err, false)
	}
	return nil
}

// pgStmt is one fixture statement; values are always bound via args.
type pgStmt struct {
	sql  string
	args []any
}

// tableFixtureStmts turns declarative fixture tables into DDL/DML. Identifiers
// are validated by dbprobe.ValidateFixtureTables and quoted with
// pgx.Identifier; cell values are bound parameters, never spliced.
func tableFixtureStmts(schema, role string, tables []dbprobe.FixtureTable) []pgStmt {
	qs := pgx.Identifier{schema}.Sanitize()
	qr := pgx.Identifier{role}.Sanitize()
	out := []pgStmt{{sql: "CREATE SCHEMA " + qs}}
	for _, t := range tables {
		tbl := pgx.Identifier{schema, t.Name}.Sanitize()
		cols := make([]string, len(t.Columns))
		names := make([]string, len(t.Columns))
		marks := make([]string, len(t.Columns))
		for i, c := range t.Columns {
			typ := "text"
			if c.Type == dbprobe.FixtureColInt {
				typ = "bigint"
			}
			def := pgx.Identifier{c.Name}.Sanitize() + " " + typ
			if c.PK {
				def += " PRIMARY KEY"
			}
			cols[i] = def
			names[i] = pgx.Identifier{c.Name}.Sanitize()
			marks[i] = "$" + strconv.Itoa(i+1)
		}
		out = append(out, pgStmt{sql: "CREATE TABLE " + tbl + " (" + strings.Join(cols, ", ") + ")"})
		ins := "INSERT INTO " + tbl + " (" + strings.Join(names, ", ") + ") VALUES (" + strings.Join(marks, ", ") + ")"
		for _, row := range t.Rows {
			args := make([]any, len(row))
			for i, c := range row {
				args[i] = dbprobe.FixtureCellArg(c)
			}
			out = append(out, pgStmt{sql: ins, args: args})
		}
	}
	out = append(out,
		pgStmt{sql: "CREATE ROLE " + qr + " NOLOGIN"},
		pgStmt{sql: "GRANT USAGE ON SCHEMA " + qs + " TO " + qr},
	)
	for _, t := range tables {
		out = append(out, pgStmt{sql: "GRANT SELECT ON " + pgx.Identifier{schema, t.Name}.Sanitize() + " TO " + qr})
	}
	return out
}

// Mode reports the connection mode (dbprobe.ModeReporter); fixtures.Seed
// refuses anything but lab.
func (a *Adapter) Mode() dbprobe.ExecMode { return a.mode }

// InspectFixture lists the objects that exist for a fixture: its schema, the
// tables in it and its role. Names are bound parameters. Lab mode only.
func (a *Adapter) InspectFixture(ctx context.Context, f dbprobe.Fixture) ([]string, error) {
	if err := a.require(); err != nil {
		return nil, err
	}
	if a.mode != dbprobe.ModeLab {
		return nil, errors.New("dbprobe/postgres: fixture inspection refused outside lab mode")
	}
	schema, role, err := fixtureNames(f.ID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, labOpTimeout)
	defer cancel()
	var out []string
	rows, err := a.s.Query(ctx, "SELECT 1 FROM pg_namespace WHERE nspname = $1", 1, schema)
	if err != nil {
		return nil, wrapErr("inspect", err, a.secrets...)
	}
	if len(rows) > 0 {
		out = append(out, "schema:"+schema)
	}
	rows, err = a.s.Query(ctx, "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "+
		"WHERE n.nspname = $1 AND c.relkind IN ('r','p','v','m','f','S') ORDER BY c.relname", fixtureInspectMax, schema)
	if err != nil {
		return nil, wrapErr("inspect", err, a.secrets...)
	}
	for _, r := range rows {
		if len(r) > 0 {
			out = append(out, "table:"+schema+"."+fmt.Sprint(r[0]))
		}
	}
	rows, err = a.s.Query(ctx, "SELECT 1 FROM pg_roles WHERE rolname = $1", 1, role)
	if err != nil {
		return nil, wrapErr("inspect", err, a.secrets...)
	}
	if len(rows) > 0 {
		out = append(out, "role:"+role)
	}
	return out, nil
}

// fixtureInspectMax bounds how many objects one inspection reads.
const fixtureInspectMax = 200

func fixtureNames(id string) (schema, role string, err error) {
	id = strings.ReplaceAll(strings.ToLower(id), "-", "_")
	if !fixtureID.MatchString(id) {
		return "", "", errors.New("dbprobe/postgres: invalid fixture id")
	}
	return "dbsim_" + id, "dbsim_" + id + "_ro", nil
}

// Cleanup drops the fixture schema and role (lab mode only) and verifies
// nothing is left behind. All statements run under a bounded context.
func (a *Adapter) Cleanup(ctx context.Context, f dbprobe.Fixture) (dbprobe.CleanupResult, error) {
	var out dbprobe.CleanupResult
	if err := a.require(); err != nil {
		return out, err
	}
	if a.mode != dbprobe.ModeLab {
		return out, errors.New("dbprobe/postgres: cleanup refused outside lab mode")
	}
	schema, role, err := fixtureNames(f.ID)
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, labOpTimeout)
	defer cancel()
	var errs []string
	for _, s := range []string{
		"DROP SCHEMA IF EXISTS " + pgx.Identifier{schema}.Sanitize() + " CASCADE",
		"DROP ROLE IF EXISTS " + pgx.Identifier{role}.Sanitize(),
	} {
		if err := a.s.Exec(ctx, s); err != nil {
			errs = append(errs, wrapErr("cleanup", err, a.secrets...).Error())
		}
	}
	if rows, err := a.s.Query(ctx, "SELECT 1 FROM pg_namespace WHERE nspname = $1", 1, schema); err != nil || len(rows) > 0 {
		out.Residual = append(out.Residual, "schema:"+schema)
	} else {
		out.Removed = append(out.Removed, "schema:"+schema)
	}
	if rows, err := a.s.Query(ctx, "SELECT 1 FROM pg_roles WHERE rolname = $1", 1, role); err != nil || len(rows) > 0 {
		out.Residual = append(out.Residual, "role:"+role)
	} else {
		out.Removed = append(out.Removed, "role:"+role)
	}
	if ctx.Err() != nil {
		a.markBroken()
		errs = append(errs, "cleanup timed out; connection closed")
	}
	out.Error = strings.Join(errs, "; ")
	return out, nil
}

var (
	reDSN    = regexp.MustCompile(`(?i)postgres(?:ql)?://\S+`)
	rePassKV = regexp.MustCompile(`(?i)password\s*=\s*\S+`)
	reConnKV = regexp.MustCompile("(?i)\\b(host|user|dbname|database)=[^\\s`']+")
)

// redact removes passwords, DSNs and connection key/values from driver text.
func redact(s string, secrets ...string) string {
	s = reDSN.ReplaceAllString(s, "[redacted-dsn]")
	s = rePassKV.ReplaceAllString(s, "password=[redacted]")
	s = reConnKV.ReplaceAllString(s, "$1=[redacted]")
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
	}
	return s
}

// wrapErr turns a driver error into a redacted error with no chain to the
// original (which could hold the secret).
func wrapErr(op string, err error, secrets ...string) error {
	return fmt.Errorf("dbprobe/postgres: %s: %s", op, redact(err.Error(), secrets...))
}
