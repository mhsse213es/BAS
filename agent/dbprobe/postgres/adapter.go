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
	secrets []string
	notes   []string
}

// New returns an unconnected adapter.
func New() *Adapter { return &Adapter{} }

// Connect opens one connection. TLS verification is on unless TLSMode is the
// explicit opt-out "insecure-skip-verify" or "disable"; either is reported in
// every ProbeResult's Notes.
func (a *Adapter) Connect(ctx context.Context, cfg dbprobe.ConnectionConfig) error {
	a.mode = cfg.Mode
	a.secrets = []string{cfg.Password}
	a.notes = nil
	cc, err := pgx.ParseConfig("connect_timeout=10")
	if err != nil {
		return wrapErr("config", err, cfg.Password)
	}
	cc.Host = cfg.Host
	if cfg.Port > 0 {
		cc.Port = uint16(cfg.Port)
	}
	cc.Database = cfg.Database
	cc.User = cfg.User
	cc.Password = cfg.Password
	cc.Fallbacks = nil
	cc.DefaultQueryExecMode = pgx.QueryExecModeExec
	cc.RuntimeParams["application_name"] = "dbsim"
	switch cfg.TLSMode {
	case "", "verify-full":
		cc.TLSConfig = &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	case "insecure-skip-verify":
		cc.TLSConfig = &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} //nolint:gosec // explicit, reported opt-out
		a.notes = append(a.notes, "tls: certificate verification DISABLED by explicit opt-out")
	case "disable":
		cc.TLSConfig = nil
		a.notes = append(a.notes, "tls: DISABLED by explicit opt-out")
	default:
		return fmt.Errorf("dbprobe/postgres: unknown tlsMode %q", cfg.TLSMode)
	}
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return wrapErr("connect", err, cfg.Password)
	}
	a.s = &pgxSession{c: conn}
	return nil
}

// Close closes the connection.
func (a *Adapter) Close() error {
	if a.s == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := a.s.Close(ctx)
	a.s = nil
	return err
}

func (a *Adapter) require() error {
	if a.s == nil {
		return errors.New("dbprobe/postgres: not connected")
	}
	return nil
}

// Identity returns pg_control_system().system_identifier as a string.
func (a *Adapter) Identity(ctx context.Context) (string, error) {
	if err := a.require(); err != nil {
		return "", err
	}
	rows, err := a.s.Query(ctx, sqlIdentity, 2)
	if err != nil {
		return "", wrapErr("identity", err, a.secrets...)
	}
	if len(rows) != 1 || len(rows[0]) != 1 {
		return "", errors.New("dbprobe/postgres: identity query returned no row")
	}
	return str(rows[0][0]), nil
}

// EnumerateRoles lists non-system roles.
func (a *Adapter) EnumerateRoles(ctx context.Context) ([]Role, error) {
	if err := a.require(); err != nil {
		return nil, err
	}
	rows, err := a.s.Query(ctx, sqlRoles, 10000)
	if err != nil {
		return nil, wrapErr("roles", err, a.secrets...)
	}
	return toRoles(rows), nil
}

// ReadGrants lists table grants outside the system schemas.
func (a *Adapter) ReadGrants(ctx context.Context) ([]Grant, error) {
	if err := a.require(); err != nil {
		return nil, err
	}
	rows, err := a.s.Query(ctx, sqlAllGrants, 10000)
	if err != nil {
		return nil, wrapErr("grants", err, a.secrets...)
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

// Capabilities declares what this adapter supports. Audit is not supported
// yet (Task 9), so callers must treat audit as unsupported (SKIPPED).
func (a *Adapter) Capabilities() dbprobe.Capabilities {
	return dbprobe.Capabilities{
		ProbeIDs:            []string{"auth_check", "read_grants", "read_restricted_table", "read_roles"},
		AuditSources:        nil,
		MarkerInAppName:     true,
		MarkerInQueryText:   true,
		MarkerInAuditRecord: false,
	}
}

// CollectAudit is a stub until Task 9: no events, no error. Capabilities
// reports no audit source so callers treat audit as unsupported.
func (a *Adapter) CollectAudit(ctx context.Context, q dbprobe.AuditQuery) ([]dbprobe.AuditEvent, error) {
	return nil, nil
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

var unsafeMarker = regexp.MustCompile(`[^A-Za-z0-9._:-]`)

func sanitizeMarker(m string, max int) string {
	m = unsafeMarker.ReplaceAllString(m, "_")
	if len(m) > max {
		m = m[:max]
	}
	return m
}

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
func markerComment(marker string) string {
	m := sanitizeMarker(marker, 120)
	if m == "" {
		m = "none"
	}
	return "/* dbsim:" + m + " */"
}

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
	ctx, cancel := dbprobe.WithDeadline(ctx, spec.Limits)
	defer cancel()

	res.AgentTime = time.Now().UTC()
	res.Notes = append(res.Notes, a.notes...)
	if err := a.s.Exec(ctx, beginStmt(mode, real.Class)); err != nil {
		return res, wrapErr("begin", err, a.secrets...)
	}
	defer func() {
		rb, c := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer c()
		_ = a.s.Exec(rb, "ROLLBACK")
	}()
	if err := a.applyTxnSettings(ctx, spec); err != nil {
		return res, wrapErr("settings", err, a.secrets...)
	}
	comment := markerComment(spec.Marker) + " "
	clk, err := a.s.Query(ctx, comment+sqlClock, 1)
	if err != nil || len(clk) != 1 || len(clk[0]) != 1 {
		return res, wrapErr("clock", errOr(err, "no clock row"), a.secrets...)
	}
	if t, ok := clk[0][0].(time.Time); ok {
		res.DBTime = t.UTC()
	}

	rows, err := a.s.Query(ctx, comment+sql, spec.Limits.MaxRows+1, args...)
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) {
			classify(&res, pe)
			return res, nil
		}
		if errors.Is(err, context.DeadlineExceeded) {
			res.ErrorClass = "timeout"
			return res, nil
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
	tbl := pgx.Identifier{schema, "restricted"}.Sanitize()
	stmts := []string{
		"CREATE SCHEMA " + pgx.Identifier{schema}.Sanitize(),
		"CREATE TABLE " + tbl + " (id int PRIMARY KEY, label text)",
		"INSERT INTO " + tbl + " VALUES (1, 'synthetic-1'), (2, 'synthetic-2'), (3, 'synthetic-3')",
		"CREATE ROLE " + pgx.Identifier{role}.Sanitize() + " NOLOGIN",
		"GRANT USAGE ON SCHEMA " + pgx.Identifier{schema}.Sanitize() + " TO " + pgx.Identifier{role}.Sanitize(),
		"GRANT SELECT ON " + tbl + " TO " + pgx.Identifier{role}.Sanitize(),
	}
	if err := a.s.Exec(ctx, "BEGIN"); err != nil {
		return wrapErr("seed", err, a.secrets...)
	}
	for _, s := range stmts {
		if err := a.s.Exec(ctx, s); err != nil {
			_ = a.s.Exec(context.WithoutCancel(ctx), "ROLLBACK")
			return wrapErr("seed", err, a.secrets...)
		}
	}
	if err := a.s.Exec(ctx, "COMMIT"); err != nil {
		return wrapErr("seed", err, a.secrets...)
	}
	return nil
}

func fixtureNames(id string) (schema, role string, err error) {
	id = strings.ReplaceAll(strings.ToLower(id), "-", "_")
	if !fixtureID.MatchString(id) {
		return "", "", errors.New("dbprobe/postgres: invalid fixture id")
	}
	return "dbsim_" + id, "dbsim_" + id + "_ro", nil
}

// Cleanup drops the fixture schema and role (lab mode only) and verifies
// nothing is left behind.
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
	out.Error = strings.Join(errs, "; ")
	return out, nil
}

var (
	reURLCreds = regexp.MustCompile(`://[^/\s:@]+:[^@\s]*@`)
	rePassKV   = regexp.MustCompile(`(?i)password\s*=\s*\S+`)
)

// redact removes passwords and DSN credentials from driver text.
func redact(s string, secrets ...string) string {
	s = reURLCreds.ReplaceAllString(s, "://[redacted]@")
	s = rePassKV.ReplaceAllString(s, "password=[redacted]")
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
