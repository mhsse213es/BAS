package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

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
	if strings.Contains(sql, "clock_timestamp") {
		return [][]any{{time.Unix(1700000000, 0).UTC()}}, nil
	}
	return nil, nil
}

func (f *fakeSession) Close(ctx context.Context) error { f.closed = true; return nil }

func spec(id string, mode dbprobe.ExecMode, params map[string]string) dbprobe.DBProbeSpec {
	return dbprobe.DBProbeSpec{Engine: "postgresql", ProbeID: id, TargetID: "t", Mode: mode,
		Marker: "dbsim-abc123", Params: params,
		Limits: dbprobe.Limits{MaxRows: 5, TimeoutSec: 7, MaxConns: 1}}
}

func def(id string) dbprobe.ProbeDef { d, _ := dbprobe.LookupProbe(id); return d }

func TestPGConnectErrorRedactsPassword(t *testing.T) {
	const pw = "S3cr3t-FAKE-pw-9f8e7d"
	a := New()
	err := a.Connect(context.Background(), dbprobe.ConnectionConfig{
		Engine: "postgresql", Host: "127.0.0.1", Port: 1, Database: "d", User: "u",
		Password: pw, TLSMode: "disable", Mode: dbprobe.ModeClient})
	if err == nil {
		t.Fatal("expected connect failure")
	}
	if strings.Contains(err.Error(), pw) {
		t.Fatalf("password leaked in error: %v", err)
	}
	if strings.Contains(err.Error(), "postgres://") {
		t.Fatalf("DSN leaked: %v", err)
	}
}

func TestPGCapabilitiesDeclareAuditSource(t *testing.T) {
	c := New().Capabilities()
	if len(c.AuditSources) != 0 {
		t.Fatalf("audit sources must be empty until Task 9, got %v", c.AuditSources)
	}
	if c.MarkerInAuditRecord || !c.MarkerInQueryText || !c.MarkerInAppName {
		t.Fatalf("marker facts wrong: %+v", c)
	}
	if len(c.ProbeIDs) != 4 {
		t.Fatalf("probe ids: %v", c.ProbeIDs)
	}
	ev, err := New().CollectAudit(context.Background(), dbprobe.AuditQuery{})
	if err != nil || len(ev) != 0 {
		t.Fatalf("stub audit must return nothing: %v %v", ev, err)
	}
}

func TestRegistry(t *testing.T) {
	a, ok := dbprobe.New("postgresql")
	if !ok || a == nil {
		t.Fatal("postgresql not registered")
	}
	if _, ok := dbprobe.New("nope"); ok {
		t.Fatal("unexpected adapter")
	}
}

func TestRedact(t *testing.T) {
	cases := []struct{ in, bad string }{
		{"failed postgres://bob:hunter2@host:5432/db?x=1", "hunter2"},
		{"dial error password=hunter2 host=x", "hunter2"},
		{"raw hunter2 appears", "hunter2"},
	}
	for _, c := range cases {
		got := redact(c.in, "hunter2")
		if strings.Contains(got, c.bad) {
			t.Errorf("redact(%q)=%q still has secret", c.in, got)
		}
	}
	if got := redact("plain message"); got != "plain message" {
		t.Errorf("unexpected change: %q", got)
	}
}

func TestIdentifierValidation(t *testing.T) {
	good := []string{"users", "public.users", "dbsim_ab12.restricted"}
	bad := []string{"", "Users; drop table x", "a.b.c", "x-y", "1abc", "a b", "a\"b", strings.Repeat("a", 64), ".x", "x."}
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
	q, _ := quoteTable("public.users")
	if q != `"public"."users"` {
		t.Errorf("quote=%s", q)
	}
	if err := validRole("ok_role1"); err != nil {
		t.Error(err)
	}
	if err := validRole("a'b"); err == nil {
		t.Error("bad role accepted")
	}
}

func TestAppNameDerivation(t *testing.T) {
	if got := appNameFor("dbsim-abc123"); got != "dbsim-abc123" {
		t.Errorf("got %q", got)
	}
	long := strings.Repeat("x", 200)
	got := appNameFor(long)
	if len(got) > 63 {
		t.Errorf("len %d > 63", len(got))
	}
	got = appNameFor("a b\x00c'd;--")
	if strings.ContainsAny(got, " \x00';") {
		t.Errorf("not sanitized: %q", got)
	}
	if appNameFor("") == "" {
		t.Error("empty marker must still yield a stable name")
	}
}

func TestMarkerCommentSafe(t *testing.T) {
	c := markerComment("abc*/ DROP TABLE x; /*")
	if strings.Count(c, "*/") != 1 || !strings.HasPrefix(c, "/* ") || !strings.HasSuffix(c, "*/") {
		t.Errorf("comment breakable: %q", c)
	}
	if markerComment("dbsim-abc123") != "/* dbsim:dbsim-abc123 */" {
		t.Errorf("got %q", markerComment("dbsim-abc123"))
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
	if beginStmt(dbprobe.ModeClient, dbprobe.ClassReadOnly) != "BEGIN READ ONLY" {
		t.Error("client must be READ ONLY")
	}
	if beginStmt(dbprobe.ModeClient, dbprobe.ClassMutation) != "BEGIN READ ONLY" {
		t.Error("client mode must be READ ONLY even for a non-read-only class")
	}
	if beginStmt(dbprobe.ModeLab, dbprobe.ClassReadOnly) != "BEGIN READ ONLY" {
		t.Error("read_only probes are always READ ONLY")
	}
}

func TestProbeSQLFixedAndParameterized(t *testing.T) {
	sql, args, err := probeSQL("read_grants", map[string]string{"role": "r1"}, 5)
	if err != nil || len(args) != 1 || args[0] != "r1" || !strings.Contains(sql, "$1") || strings.Contains(sql, "r1") {
		t.Fatalf("read_grants: %q %v %v", sql, args, err)
	}
	sql, args, err = probeSQL("read_restricted_table", map[string]string{"table": "public.users"}, 5)
	if err != nil || !strings.Contains(sql, `"public"."users"`) || !strings.Contains(sql, "LIMIT $1") || len(args) != 1 || args[0] != 6 {
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
		if strings.Contains(sql, "clock_timestamp") {
			return [][]any{{time.Unix(1700000000, 0).UTC()}}, nil
		}
		return [][]any{{"r1", true, false}, {"r2", false, false}}, nil
	}}
	a := &Adapter{s: f, mode: dbprobe.ModeClient}
	res, err := a.RunProbe(context.Background(), def("read_roles"), spec("read_roles", dbprobe.ModeClient, nil))
	if err != nil {
		t.Fatal(err)
	}
	if res.Denied || res.RowsRead != 2 || res.DBTime.IsZero() || res.AgentTime.IsZero() {
		t.Fatalf("result %+v", res)
	}
	if f.calls[0].sql != "BEGIN READ ONLY" {
		t.Fatalf("first stmt %q", f.calls[0].sql)
	}
	last := f.calls[len(f.calls)-1].sql
	if last != "ROLLBACK" {
		t.Fatalf("last stmt %q", last)
	}
	var sawTimeout, sawApp, sawComment bool
	for _, c := range f.calls {
		if strings.Contains(c.sql, "statement_timeout") && len(c.args) == 1 && c.args[0] == "7000" {
			sawTimeout = true
		}
		if strings.Contains(c.sql, "'application_name'") && len(c.args) == 1 && c.args[0] == "dbsim-abc123" {
			sawApp = true
		}
		if strings.HasPrefix(c.sql, "/* dbsim:dbsim-abc123 */ SELECT") {
			sawComment = true
		}
	}
	if !sawTimeout || !sawApp || !sawComment {
		t.Fatalf("timeout=%v app=%v comment=%v calls=%+v", sawTimeout, sawApp, sawComment, f.calls)
	}
}

func TestRunProbeDeniedIsObservation(t *testing.T) {
	f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		if strings.Contains(sql, "clock_timestamp") {
			return [][]any{{time.Now()}}, nil
		}
		return nil, &pgconn.PgError{Code: "42501", Message: "permission denied for table users"}
	}}
	a := &Adapter{s: f, mode: dbprobe.ModeClient}
	res, err := a.RunProbe(context.Background(), def("read_restricted_table"),
		spec("read_restricted_table", dbprobe.ModeClient, map[string]string{"table": "public.users"}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Denied || res.ErrorClass != "permission_denied" || res.RowsRead != 0 {
		t.Fatalf("result %+v", res)
	}
}

func TestRunProbeRowBudget(t *testing.T) {
	f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		if strings.Contains(sql, "clock_timestamp") {
			return [][]any{{time.Now()}}, nil
		}
		rows := make([][]any, 9)
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
}

func TestSeedRefusedInClientMode(t *testing.T) {
	f := &fakeSession{}
	a := &Adapter{s: f, mode: dbprobe.ModeClient}
	if err := a.Seed(context.Background(), dbprobe.Fixture{ID: "ab12", Kind: "pg_basic"}); err == nil {
		t.Fatal("seed allowed in client mode")
	}
	if _, err := a.Cleanup(context.Background(), dbprobe.Fixture{ID: "ab12"}); err == nil {
		t.Fatal("cleanup allowed in client mode")
	}
	if len(f.calls) != 0 {
		t.Fatal("SQL issued")
	}
	if err := (&Adapter{s: f, mode: dbprobe.ModeLab}).Seed(context.Background(), dbprobe.Fixture{ID: "x; drop"}); err == nil {
		t.Fatal("bad fixture id accepted")
	}
}

func TestWrapErrRedacted(t *testing.T) {
	err := errors.New("boom password=zzz postgres://u:zzz@h/db")
	if strings.Contains(wrapErr("connect", err, "zzz").Error(), "zzz") {
		t.Fatal("leak")
	}
}
