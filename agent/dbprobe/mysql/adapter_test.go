package mysql

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	drv "github.com/go-sql-driver/mysql"

	"audspect/agent/dbprobe"
)

type fakeCall struct {
	sql         string
	args        []any
	hasDeadline bool
}

type fakeSession struct {
	calls   []fakeCall
	queryFn func(sql string, args []any) ([][]any, error)
	execFn  func(sql string) error
	closed  bool
}

func (f *fakeSession) Exec(ctx context.Context, sql string, args ...any) error {
	_, dl := ctx.Deadline()
	f.calls = append(f.calls, fakeCall{sql, args, dl})
	if f.execFn != nil {
		return f.execFn(sql)
	}
	return nil
}

func (f *fakeSession) Query(ctx context.Context, sql string, maxRows int, args ...any) ([][]any, error) {
	_, dl := ctx.Deadline()
	f.calls = append(f.calls, fakeCall{sql, args, dl})
	if f.queryFn != nil {
		return f.queryFn(sql, args)
	}
	if strings.Contains(sql, "UTC_TIMESTAMP") {
		return [][]any{{time.Unix(1700000000, 0).UTC()}}, nil
	}
	return nil, nil
}

func (f *fakeSession) Close(ctx context.Context) error { f.closed = true; return nil }

func spec(id string, mode dbprobe.ExecMode, params map[string]string) dbprobe.DBProbeSpec {
	return dbprobe.DBProbeSpec{Engine: "mysql", ProbeID: id, TargetID: "t", Host: "db.example", Port: 1, ExpectedIdentity: "id-1", Mode: mode,
		Marker: "dbsim-abc123", Params: params,
		Limits: dbprobe.Limits{MaxRows: 5, TimeoutSec: 7, MaxConns: 1}}
}

func def(id string) dbprobe.ProbeDef { d, _ := dbprobe.LookupProbe(id); return d }

func nowUTC() time.Time { return time.Now().UTC() }

// closedPort returns a loopback address nothing listens on.
func closedPort(t *testing.T) (host string, port int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().(*net.TCPAddr)
	l.Close()
	return "127.0.0.1", addr.Port
}

func TestMySQLConnectErrorRedactsPassword(t *testing.T) {
	const pw = "S3cr3t-FAKE-pw-9f8e7d"
	host, port := closedPort(t)
	a := New()
	err := a.Connect(context.Background(), dbprobe.ConnectionConfig{
		Engine: "mysql", Host: host, Port: port, Database: "d", User: "svc_dbsim_probe",
		Password: pw, TLSMode: "disable", Mode: dbprobe.ModeClient})
	if err == nil {
		t.Fatal("expected connect failure")
	}
	t.Logf("scrubbed real driver error: %v", err)
	for _, bad := range []string{pw, "svc_dbsim_probe", "@tcp(", host + ":" + fmt.Sprint(port)} {
		if strings.Contains(err.Error(), bad) {
			t.Fatalf("real driver error leaks %q: %v", bad, err)
		}
	}
	// The driver really did produce a dial error naming the address: prove the
	// scrubbing did work on real text, not on an empty message.
	if !strings.Contains(err.Error(), "dial") && !strings.Contains(err.Error(), "refused") && !strings.Contains(err.Error(), "connect") {
		t.Fatalf("unexpected error shape: %v", err)
	}
}

func TestMySQLCapabilitiesTruth(t *testing.T) {
	c := New().Capabilities()
	if len(c.AuditSources) != 0 {
		t.Fatalf("an unconnected adapter has discovered no audit source, got %v", c.AuditSources)
	}
	if c.MarkerInAuditRecord || !c.MarkerInQueryText || c.MarkerInAppName {
		t.Fatalf("marker facts wrong: %+v", c)
	}
	if len(c.ProbeIDs) != 12 {
		t.Fatalf("probe ids: %v", c.ProbeIDs)
	}
	joined := strings.Join(c.Notes, "|")
	for _, want := range []string{"max_statement_time", "server_uuid", "general_log", "program_name"} {
		if !strings.Contains(joined, want) {
			t.Errorf("capability notes missing %q: %s", want, joined)
		}
	}
	ev, err := New().CollectAudit(context.Background(), dbprobe.AuditQuery{})
	if !errors.Is(err, dbprobe.ErrAuditUnsupported) || len(ev) != 0 {
		t.Fatalf("unconnected audit must be unsupported: %v %v", ev, err)
	}
}

func TestRegistry(t *testing.T) {
	a, ok := dbprobe.New("mysql")
	if !ok || a == nil {
		t.Fatal("mysql not registered")
	}
}

func TestRedactStripsDSNAndAccounts(t *testing.T) {
	cases := []struct{ in, bad string }{
		{"failed bob:hunter2@tcp(db.internal:3306)/prod?tls=true", "hunter2"},
		{"failed bob:hunter2@tcp(db.internal:3306)/prod?tls=true", "db.internal"},
		{"Error 1045 (28000): Access denied for user 'bob'@'10.1.2.3' (using password: YES)", "10.1.2.3"},
		{"Error 1045 (28000): Access denied for user 'bob'@'10.1.2.3' (using password: YES)", "'bob'"},
		{"dial tcp 10.9.9.9:3306: connectex: refused", "10.9.9.9"},
		{"raw hunter2 appears", "hunter2"},
	}
	for _, c := range cases {
		if got := redact(c.in, "hunter2"); strings.Contains(got, c.bad) {
			t.Errorf("redact(%q)=%q still has %q", c.in, got, c.bad)
		}
	}
	if got := redact("plain message"); got != "plain message" {
		t.Errorf("unexpected change: %q", got)
	}
}

func TestRealMySQLErrorValueIsScrubbed(t *testing.T) {
	var state [5]byte
	copy(state[:], "28000")
	real := &drv.MySQLError{Number: 1045, SQLState: state,
		Message: "Access denied for user 'svc_dbsim_probe'@'db-internal-01.corp.example' (using password: YES) hunter2"}
	got := wrapErr("connect", real, "hunter2").Error()
	for _, bad := range []string{"svc_dbsim_probe", "db-internal-01", "hunter2"} {
		if strings.Contains(got, bad) {
			t.Errorf("wrapped real MySQLError leaks %q: %s", bad, got)
		}
	}
	if errors.As(wrapErr("connect", real), new(*drv.MySQLError)) {
		t.Error("wrapped error must not expose the raw driver error chain")
	}
}

func TestWrapErrKeepsContextClass(t *testing.T) {
	for _, base := range []error{context.Canceled, context.DeadlineExceeded} {
		e := wrapErr("probe", fmt.Errorf("read tcp 1.2.3.4:5: %w", base), "hunter2")
		if !errors.Is(e, base) {
			t.Errorf("errors.Is(%v) lost through wrapErr: %v", base, e)
		}
	}
	if errors.Is(wrapErr("x", errors.New("boom")), context.Canceled) {
		t.Error("unrelated error classified as cancel")
	}
}

func TestIdentifierValidationAndQuoting(t *testing.T) {
	good := []string{"users", "Users", "app.users", "dbsim_ab12.restricted"}
	bad := []string{"", "Users; drop table x", "a.b.c", "x-y", "1abc", "a b", "a`b", "a\x00b", "a\nb", "a\"b", strings.Repeat("a", 65), ".x", "x.", "a.`b`"}
	for _, g := range good {
		if _, err := quoteTable(g); err != nil {
			t.Errorf("%q should be valid: %v", g, err)
		}
	}
	for _, b := range bad {
		if _, err := quoteTable(b); err == nil {
			t.Errorf("%q should be rejected", b)
		}
	}
	if q, _ := quoteTable("app.users"); q != "`app`.`users`" {
		t.Errorf("quote=%s", q)
	}
	if q, _ := quoteTable("users"); q != "`users`" {
		t.Errorf("quote=%s", q)
	}
	for _, b := range []string{"a`b", "a\x01b", "", "a b"} {
		if _, err := quoteIdent(b); err == nil {
			t.Errorf("quoteIdent accepted %q", b)
		}
	}
	if err := validRole("ok_role1"); err != nil {
		t.Error(err)
	}
	for _, b := range []string{"a'b", "a@b", "", strings.Repeat("a", 33), "a b"} {
		if err := validRole(b); err == nil {
			t.Errorf("bad role %q accepted", b)
		}
	}
}

func TestMarkerCommentSafe(t *testing.T) {
	c := markerComment("abc*/ DROP TABLE x; /*")
	if strings.Count(c, "*/") != 1 || !strings.HasPrefix(c, "/* ") || !strings.HasSuffix(c, "*/") {
		t.Errorf("comment breakable: %q", c)
	}
	if strings.Contains(c, "/*!") || strings.Contains(c, "--") && !strings.HasPrefix(c, "/* dbsim:") {
		t.Errorf("executable comment form: %q", c)
	}
	if markerComment("dbsim-abc123") != "/* dbsim:dbsim-abc123 */" {
		t.Errorf("got %q", markerComment("dbsim-abc123"))
	}
	// A marker beginning with '!' must not turn the comment into /*! ... */
	if c := markerComment("!x"); strings.HasPrefix(c, "/*!") || strings.Contains(c, "dbsim:!") {
		t.Errorf("executable comment: %q", c)
	}
}

func TestParamEnforcement(t *testing.T) {
	if err := checkParams(def("read_grants"), nil); err == nil {
		t.Error("missing required role accepted")
	}
	if err := checkParams(def("read_restricted_table"), map[string]string{"table": ""}); err == nil {
		t.Error("empty table accepted")
	}
	if err := checkParams(def("read_roles"), map[string]string{"x": "y"}); err == nil {
		t.Error("undeclared param accepted")
	}
	if err := checkParams(def("read_grants"), map[string]string{"role": "r1"}); err != nil {
		t.Error(err)
	}
	d := dbprobe.ProbeDef{ID: "x", ParamSchema: map[string]dbprobe.ParamKind{"n": dbprobe.ParamInt, "b": dbprobe.ParamBool}}
	if err := checkParams(d, map[string]string{"n": "abc", "b": "true"}); err == nil {
		t.Error("non-int accepted for int")
	}
	if err := checkParams(d, map[string]string{"n": "5", "b": "maybe"}); err == nil {
		t.Error("non-bool accepted for bool")
	}
	if err := checkParams(d, map[string]string{"n": "5", "b": "false"}); err != nil {
		t.Error(err)
	}
}

func TestBeginStatement(t *testing.T) {
	const ro = "START TRANSACTION READ ONLY"
	if beginStmt(dbprobe.ModeClient, dbprobe.ClassReadOnly) != ro {
		t.Error("client must be READ ONLY")
	}
	if beginStmt(dbprobe.ModeClient, dbprobe.ClassMutation) != ro {
		t.Error("client mode must be READ ONLY even for a non-read-only class")
	}
	if beginStmt(dbprobe.ModeLab, dbprobe.ClassReadOnly) != ro {
		t.Error("read_only probes are always READ ONLY")
	}
	if beginStmt("", dbprobe.ClassMutation) != ro {
		t.Error("empty mode must be READ ONLY")
	}
}

func TestProbeSQLFixedAndParameterized(t *testing.T) {
	sql, args, err := probeSQL("read_grants", map[string]string{"role": "r1"}, 5)
	if err != nil || len(args) != 1 || args[0] != "r1" || !strings.Contains(sql, "?") || strings.Contains(sql, "r1") {
		t.Fatalf("read_grants: %q %v %v", sql, args, err)
	}
	sql, args, err = probeSQL("read_restricted_table", map[string]string{"table": "app.users"}, 5)
	if err != nil || !strings.Contains(sql, "`app`.`users`") || !strings.Contains(sql, "LIMIT ?") || len(args) != 1 || args[0] != 6 {
		t.Fatalf("restricted: %q %v %v", sql, args, err)
	}
	if _, _, err = probeSQL("read_restricted_table", map[string]string{"table": "x; drop"}, 5); err == nil {
		t.Fatal("injection accepted")
	}
	if _, _, err = probeSQL("nope", nil, 5); err == nil {
		t.Fatal("unknown probe accepted")
	}
}

func TestRunProbeSequenceClientMode(t *testing.T) {
	f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		if strings.Contains(sql, "UTC_TIMESTAMP") {
			return [][]any{{time.Unix(1700000000, 0).UTC()}}, nil
		}
		return [][]any{{"r1", int64(1), int64(0)}, {"r2", int64(0), int64(0)}}, nil
	}}
	a := &Adapter{s: f, mode: dbprobe.ModeClient}
	res, err := a.RunProbe(context.Background(), def("read_roles"), spec("read_roles", dbprobe.ModeClient, nil))
	if err != nil {
		t.Fatal(err)
	}
	if res.Denied || res.RowsRead != 2 || res.DBTime.IsZero() || res.AgentTime.IsZero() {
		t.Fatalf("result %+v", res)
	}
	if f.calls[0].sql != "START TRANSACTION READ ONLY" {
		t.Fatalf("first stmt %q", f.calls[0].sql)
	}
	if f.calls[1].sql != "SET SESSION max_execution_time = 7000" {
		t.Fatalf("second stmt %q", f.calls[1].sql)
	}
	if last := f.calls[len(f.calls)-1].sql; last != "ROLLBACK" {
		t.Fatalf("last stmt %q", last)
	}
	var sawComment bool
	for _, c := range f.calls[2 : len(f.calls)-1] {
		if !strings.HasPrefix(c.sql, "/* dbsim:dbsim-abc123 */ SELECT") {
			t.Errorf("statement without marker comment: %q", c.sql)
		} else {
			sawComment = true
		}
	}
	if !sawComment {
		t.Fatal("no marker-commented query")
	}
	for i, c := range f.calls {
		if !c.hasDeadline {
			t.Errorf("call %d (%q) ran without a deadline", i, c.sql)
		}
	}
}

func TestRunProbeDeniedIsObservation(t *testing.T) {
	for _, tc := range []struct {
		num   uint16
		class string
		deny  bool
	}{
		{1142, "permission_denied", true},
		{1044, "permission_denied", true},
		{1045, "auth_failed", true},
		{1146, "undefined_table", false},
		{1792, "read_only_violation", false},
		{3024, "timeout", false},
		{1999, "mysql_error_1999", false},
	} {
		f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
			if strings.Contains(sql, "UTC_TIMESTAMP") {
				return [][]any{{time.Now()}}, nil
			}
			return nil, &drv.MySQLError{Number: tc.num, Message: "x"}
		}}
		a := &Adapter{s: f, mode: dbprobe.ModeClient}
		res, err := a.RunProbe(context.Background(), def("read_restricted_table"),
			spec("read_restricted_table", dbprobe.ModeClient, map[string]string{"table": "app.users"}))
		if err != nil {
			t.Fatal(err)
		}
		if res.Denied != tc.deny || res.ErrorClass != tc.class || res.RowsRead != 0 {
			t.Fatalf("code %d: result %+v", tc.num, res)
		}
		if f.calls[len(f.calls)-1].sql != "ROLLBACK" {
			t.Errorf("code %d: no rollback after a SQL error", tc.num)
		}
	}
}

func TestRunProbeRowBudget(t *testing.T) {
	f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		if strings.Contains(sql, "UTC_TIMESTAMP") {
			return [][]any{{time.Now()}}, nil
		}
		rows := make([][]any, 6) // MaxRows is 5: MaxRows+1 means overflow
		for i := range rows {
			rows[i] = []any{i}
		}
		return rows, nil
	}}
	a := &Adapter{s: f, mode: dbprobe.ModeClient}
	res, err := a.RunProbe(context.Background(), def("auth_check"), spec("auth_check", dbprobe.ModeClient, nil))
	if err != nil {
		t.Fatal(err)
	}
	if res.ErrorClass != "row_limit_exceeded" {
		t.Fatalf("result %+v", res)
	}
}

func TestRunProbeRejectsBadInputBeforeSQL(t *testing.T) {
	f := &fakeSession{}
	a := &Adapter{s: f, mode: dbprobe.ModeClient}
	_, err := a.RunProbe(context.Background(), def("read_grants"), spec("read_grants", dbprobe.ModeClient, nil))
	if err == nil || len(f.calls) != 0 {
		t.Fatalf("err=%v calls=%d", err, len(f.calls))
	}
	_, err = a.RunProbe(context.Background(), dbprobe.ProbeDef{ID: "evil"}, spec("evil", dbprobe.ModeClient, nil))
	if err == nil || len(f.calls) != 0 {
		t.Fatal("unknown probe ran")
	}
	bad := spec("auth_check", dbprobe.ModeClient, nil)
	bad.Engine = "postgresql"
	if _, err = a.RunProbe(context.Background(), def("auth_check"), bad); err == nil || len(f.calls) != 0 {
		t.Fatal("wrong engine ran")
	}
	over := spec("auth_check", dbprobe.ModeClient, nil)
	over.Limits.MaxRows = dbprobe.MaxRowsCap + 1
	if _, err = a.RunProbe(context.Background(), def("auth_check"), over); err == nil || len(f.calls) != 0 {
		t.Fatal("over-cap limits ran")
	}
}

func TestSeedAndCleanupRefusedOutsideLab(t *testing.T) {
	for _, m := range []dbprobe.ExecMode{dbprobe.ModeClient, ""} {
		f := &fakeSession{}
		a := &Adapter{s: f, mode: m}
		if err := a.Seed(context.Background(), dbprobe.Fixture{ID: "ab12", Kind: "my_basic"}); err == nil {
			t.Fatalf("seed allowed in mode %q", m)
		}
		if _, err := a.Cleanup(context.Background(), dbprobe.Fixture{ID: "ab12"}); err == nil {
			t.Fatalf("cleanup allowed in mode %q", m)
		}
		if len(f.calls) != 0 {
			t.Fatal("SQL issued")
		}
	}
	lab := &Adapter{s: &fakeSession{}, mode: dbprobe.ModeLab}
	for _, id := range []string{"x; drop", "", "a`b", strings.Repeat("a", 21)} {
		if err := lab.Seed(context.Background(), dbprobe.Fixture{ID: id}); err == nil {
			t.Fatalf("bad fixture id %q accepted", id)
		}
	}
}

func TestFixtureNames(t *testing.T) {
	s, u, err := fixtureNames("AB-12")
	if err != nil || s != "dbsim_ab_12" || u != "dbsim_ab_12_ro" {
		t.Fatalf("%q %q %v", s, u, err)
	}
	if len(u) > 32 {
		t.Fatal("MySQL user name over 32 chars")
	}
	if _, _, err := fixtureNames(strings.Repeat("a", 20)); err != nil {
		t.Fatal(err)
	}
}

func TestParseGrantee(t *testing.T) {
	for in, want := range map[string]string{
		"'app'@'%'":         "app",
		"'app'@'10.0.0.1'":  "app@10.0.0.1",
		"weird":             "weird",
		"'dbsim_x_ro'@'%'":  "dbsim_x_ro",
		"'a'@'localhost'":   "a@localhost",
		"'a'@'%.corp.test'": "a@%.corp.test",
	} {
		if got := parseGrantee(in); got != want {
			t.Errorf("parseGrantee(%q)=%q want %q", in, got, want)
		}
	}
}
