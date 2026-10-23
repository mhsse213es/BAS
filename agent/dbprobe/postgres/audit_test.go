package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"audspect/agent/dbprobe"
)

const auditMarker = "BAS-DBSIM-run_1"

var (
	auditSince = time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	auditUntil = auditSince.Add(20 * time.Second)
)

func auditQ() dbprobe.AuditQuery {
	return dbprobe.AuditQuery{Marker: auditMarker, Principal: "svc_dbsim_probe", Since: auditSince, Until: auditUntil}
}

// auditFake scripts the audit view: probeOK says the view is readable at
// discovery, covered is the "a row exists at or before Since" answer, rows are
// the marker query's rows (log_time, user_name, message).
type auditFake struct {
	*fakeSession
	probeErr error
	covered  bool
	rows     [][]any
	evErr    error
}

func newAuditFake() *auditFake {
	af := &auditFake{covered: true}
	af.fakeSession = &fakeSession{}
	af.fakeSession.queryFn = func(sql string, args []any) ([][]any, error) {
		switch {
		case strings.Contains(sql, sqlAuditProbe):
			if af.probeErr != nil {
				return nil, af.probeErr
			}
			return [][]any{{auditSince, "u", "SELECT", "m"}}, nil
		case strings.Contains(sql, sqlAuditCovered):
			return [][]any{{af.covered}}, nil
		case strings.Contains(sql, sqlAuditEvents):
			if af.evErr != nil {
				return nil, af.evErr
			}
			return af.rows, nil
		}
		return nil, nil
	}
	return af
}

func auditRow(sec int, user, stmt string) []any {
	return []any{auditSince.Add(time.Duration(sec) * time.Second), user, "statement: " + stmt}
}

func discovered(t *testing.T, af *auditFake) *Adapter {
	t.Helper()
	a := &Adapter{s: af.fakeSession, mode: dbprobe.ModeClient, secrets: []string{"hunter2-secret"}}
	if err := a.discoverAudit(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestPGAuditEventContainsMarkerAndPrincipal(t *testing.T) {
	af := newAuditFake()
	af.rows = [][]any{
		auditRow(2, "svc_dbsim_probe", "/* dbsim:"+auditMarker+" */ SELECT rolname::text FROM pg_roles"),
		auditRow(3, "someone_else", "/* dbsim:"+auditMarker+" */ SELECT 1"), // other known principal: dropped
		auditRow(4, "svc_dbsim_probe", "/* dbsim:OTHER-RUN */ SELECT 1"),    // other marker: dropped
	}
	a := discovered(t, af)
	af.calls = nil
	ev, err := a.CollectAudit(context.Background(), auditQ())
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 {
		t.Fatalf("want exactly the marker+principal event, got %+v", ev)
	}
	e := ev[0]
	if !strings.Contains(e.Statement, auditMarker) || e.Principal != "svc_dbsim_probe" || e.Source != "dbsim_audit.pg_log" || !e.Time.Equal(auditSince.Add(2*time.Second)) {
		t.Fatalf("event %+v", e)
	}
	if dbprobe.AuditStatusOf(ev, err) != "found" {
		t.Fatal("status must be found")
	}
	assertAuditTxn(t, af.fakeSession)
	// the marker is a bound parameter with LIKE wildcards escaped, never spliced
	var evCall *fakeCall
	for i := range af.calls {
		if strings.Contains(af.calls[i].sql, sqlAuditEvents) {
			evCall = &af.calls[i]
		}
		if strings.Contains(af.calls[i].sql, "BAS-DBSIM") {
			t.Fatalf("marker spliced into SQL text: %q", af.calls[i].sql)
		}
	}
	if evCall == nil {
		t.Fatal("events query not issued")
	}
	if len(evCall.args) != 4 || evCall.args[2] != `%BAS-DBSIM-run\_1%` || evCall.args[3] != dbprobe.AuditMaxEvents+1 {
		t.Fatalf("args %#v", evCall.args)
	}
	if evCall.args[0] != auditSince.Format(time.RFC3339Nano) || evCall.args[1] != auditUntil.Format(time.RFC3339Nano) {
		t.Fatalf("window args %#v", evCall.args)
	}
}

// Every statement of a collection runs inside BEGIN READ ONLY ... ROLLBACK and
// carries the collector's own comment, so it can never be mistaken for probe
// evidence.
func assertAuditTxn(t *testing.T, f *fakeSession) {
	t.Helper()
	if len(f.calls) < 4 || f.calls[0].sql != "BEGIN READ ONLY" {
		t.Fatalf("not wrapped in BEGIN READ ONLY: %+v", f.calls)
	}
	if f.calls[len(f.calls)-1].sql != "ROLLBACK" {
		t.Fatalf("last %q", f.calls[len(f.calls)-1].sql)
	}
	for i, c := range f.calls {
		if !c.hasDeadline {
			t.Errorf("call %d without deadline", i)
		}
		if strings.Contains(c.sql, "dbsim_audit.pg_log") && !strings.HasPrefix(c.sql, dbprobe.MetaStatementTag+" ") {
			t.Errorf("audit query without the collector tag: %q", c.sql)
		}
	}
}

func TestPGAuditSQLIsFixedAndReadOnly(t *testing.T) {
	for _, s := range []string{sqlAuditProbe, sqlAuditCovered, sqlAuditEvents, sqlAuditSettings, sqlAuditViewState} {
		u := strings.ToUpper(s)
		if !strings.HasPrefix(u, "SELECT") {
			t.Errorf("not a SELECT: %q", s)
		}
		for _, bad := range []string{"INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "COPY", "GRANT", "SET "} {
			if strings.Contains(u, bad) {
				t.Errorf("%q contains %s", s, bad)
			}
		}
	}
	if strings.Count(sqlAuditEvents, "$") != 4 || strings.Contains(sqlAuditEvents, "'") {
		t.Errorf("events query must bind exactly 4 params and embed no literal: %q", sqlAuditEvents)
	}
	if strings.Contains(sqlAuditSettings, "$") || strings.Contains(sqlAuditViewState, "$") {
		t.Error("read_audit_config SQL must be parameterless")
	}
}

func TestAuditUnavailableReportsSkippedCapability(t *testing.T) {
	// before Connect: no sources, collection is unsupported, no SQL issued
	a := New()
	if len(a.Capabilities().AuditSources) != 0 {
		t.Fatal("unconnected adapter must declare no audit source")
	}
	if _, err := a.CollectAudit(context.Background(), auditQ()); !errors.Is(err, dbprobe.ErrAuditUnsupported) {
		t.Fatalf("want ErrAuditUnsupported, got %v", err)
	}
	// connected, view missing / unreadable: still no source
	for name, perr := range map[string]error{
		"missing":    &pgconn.PgError{Code: "42P01", Message: `relation "dbsim_audit.pg_log" does not exist`},
		"unreadable": &pgconn.PgError{Code: "42501", Message: "permission denied for view pg_log"},
	} {
		t.Run(name, func(t *testing.T) {
			af := newAuditFake()
			af.probeErr = perr
			b := discovered(t, af)
			if got := b.Capabilities().AuditSources; len(got) != 0 {
				t.Fatalf("sources %v", got)
			}
			af.calls = nil
			ev, err := b.CollectAudit(context.Background(), auditQ())
			if !errors.Is(err, dbprobe.ErrAuditUnsupported) || len(ev) != 0 {
				t.Fatalf("%v %v", ev, err)
			}
			if len(af.calls) != 0 {
				t.Fatalf("unsupported collection must not touch the database: %+v", af.calls)
			}
			if dbprobe.AuditStatusOf(ev, err) != "unsupported" {
				t.Fatal("status must be unsupported")
			}
			if !strings.Contains(strings.Join(b.Capabilities().Notes, "|"), "dbsim_audit.pg_log") {
				t.Fatal("notes must say why there is no source")
			}
		})
	}
}

func TestPGCapabilitiesReflectDiscoveredSourceAndCacheIt(t *testing.T) {
	af := newAuditFake()
	a := discovered(t, af)
	n := len(af.calls)
	for i := 0; i < 3; i++ {
		c := a.Capabilities()
		if len(c.AuditSources) != 1 || c.AuditSources[0] != "dbsim_audit.pg_log" || !c.MarkerInAuditRecord {
			t.Fatalf("caps %+v", c)
		}
	}
	if len(af.calls) != n {
		t.Fatal("Capabilities must not query the database (discovery is cached)")
	}
	notes := strings.Join(a.Capabilities().Notes, "|")
	for _, want := range []string{"file_fdw", "log_statement", "operator"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes missing %q: %s", want, notes)
		}
	}
	if len(a.Capabilities().ProbeIDs) != 5 {
		t.Fatalf("probe ids %v", a.Capabilities().ProbeIDs)
	}
}

func TestPGDiscoveryRunsInReadOnlyTxn(t *testing.T) {
	af := newAuditFake()
	_ = discovered(t, af)
	assertAuditTxn(t, af.fakeSession)
}

func TestAuditSliceIncompleteWhenLogRotatedMidRun(t *testing.T) {
	af := newAuditFake()
	af.covered = false // nothing at or before Since: the retained log starts later
	af.rows = [][]any{auditRow(2, "svc_dbsim_probe", "/* dbsim:"+auditMarker+" */ SELECT 1")}
	a := discovered(t, af)
	ev, err := a.CollectAudit(context.Background(), auditQ())
	if !errors.Is(err, dbprobe.ErrAuditIncomplete) {
		t.Fatalf("want ErrAuditIncomplete, got %v", err)
	}
	if len(ev) != 1 {
		t.Fatalf("events seen must still be returned: %+v", ev)
	}
	if dbprobe.AuditStatusOf(ev, err) != "incomplete" {
		t.Fatal("status must be incomplete")
	}
	// and with no event at all it must be incomplete, never absent
	af.rows = nil
	ev, err = a.CollectAudit(context.Background(), auditQ())
	if got := dbprobe.AuditStatusOf(ev, err); got != "incomplete" {
		t.Fatalf("rotated log with no event must be incomplete, got %s", got)
	}
}

func TestPGAuditStatusFoundAbsentCapAndError(t *testing.T) {
	af := newAuditFake()
	a := discovered(t, af)

	// absent: source healthy, window covered, no marker event
	ev, err := a.CollectAudit(context.Background(), auditQ())
	if dbprobe.AuditStatusOf(ev, err) != "absent" {
		t.Fatalf("absent: %v %v", ev, err)
	}

	// cap: the source returns cap+1 rows -> 50 events and incomplete
	af.rows = nil
	for i := 0; i < dbprobe.AuditMaxEvents+1; i++ {
		af.rows = append(af.rows, auditRow(i%15, "svc_dbsim_probe", fmt.Sprintf("/* dbsim:%s */ SELECT %d", auditMarker, i)))
	}
	ev, err = a.CollectAudit(context.Background(), auditQ())
	if len(ev) != dbprobe.AuditMaxEvents || !errors.Is(err, dbprobe.ErrAuditIncomplete) {
		t.Fatalf("cap: %d %v", len(ev), err)
	}

	// error: a failed collection is never absent, and the text is redacted
	af.rows = nil
	af.evErr = errors.New("boom while reading with password=hunter2-secret")
	ev, err = a.CollectAudit(context.Background(), auditQ())
	if err == nil || dbprobe.AuditStatusOf(ev, err) != "error" {
		t.Fatalf("error path: %v %v", ev, err)
	}
	if strings.Contains(err.Error(), "hunter2-secret") {
		t.Fatalf("error leaks secret: %v", err)
	}
	if errors.Is(err, dbprobe.ErrAuditUnsupported) || errors.Is(err, dbprobe.ErrAuditIncomplete) {
		t.Fatal("a failure must not look unsupported/incomplete")
	}
}

func TestPGAuditTruncatesOnRuneBoundaryAndRedacts(t *testing.T) {
	af := newAuditFake()
	stmt := "/* dbsim:" + auditMarker + " */ -- password=hunter2-secret " + strings.Repeat("é", 400)
	af.rows = [][]any{auditRow(1, "svc_dbsim_probe", stmt)}
	a := discovered(t, af)
	ev, err := a.CollectAudit(context.Background(), auditQ())
	if err != nil || len(ev) != 1 {
		t.Fatalf("%v %v", ev, err)
	}
	s := ev[0].Statement
	if len(s) > dbprobe.AuditMaxStatementBytes || strings.Contains(s, "hunter2-secret") {
		t.Fatalf("len=%d %q", len(s), s)
	}
	for _, r := range s {
		if r == '�' {
			t.Fatal("statement cut inside a rune")
		}
	}
}

func TestPGAuditRefusesBadQueries(t *testing.T) {
	af := newAuditFake()
	a := discovered(t, af)
	af.calls = nil
	bad := []dbprobe.AuditQuery{
		{Marker: "", Since: auditSince, Until: auditUntil},
		{Marker: "!!!", Since: auditSince, Until: auditUntil}, // sanitises to underscores only
		{Marker: auditMarker},
		{Marker: auditMarker, Since: auditUntil, Until: auditSince},
	}
	for i, q := range bad {
		ev, err := a.CollectAudit(context.Background(), q)
		if err == nil || dbprobe.AuditStatusOf(ev, err) != "error" {
			t.Errorf("query %d must be refused as an error: %v %v", i, ev, err)
		}
	}
	if len(af.calls) != 0 {
		t.Fatalf("a refused query must not reach the database: %+v", af.calls)
	}
}

func TestPGAuditOnBrokenConnectionIsAnErrorNotUnsupported(t *testing.T) {
	af := newAuditFake()
	a := discovered(t, af)
	a.markBroken()
	_, err := a.CollectAudit(context.Background(), auditQ())
	if err == nil || errors.Is(err, dbprobe.ErrAuditUnsupported) {
		t.Fatalf("broken connection must be an error: %v", err)
	}
}

func auditConfigFake(settings [][]any, view []any) *fakeSession {
	return &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		switch {
		case strings.Contains(sql, "clock_timestamp"):
			return [][]any{{time.Unix(1700000000, 0).UTC()}}, nil
		case strings.Contains(sql, sqlAuditSettings):
			return settings, nil
		case strings.Contains(sql, sqlAuditViewState):
			return [][]any{view}, nil
		}
		return nil, nil
	}}
}

func TestReadAuditConfigReportsSettingsAndCoverage(t *testing.T) {
	cases := []struct {
		name     string
		settings [][]any
		view     []any
		want     string
	}{
		{"covered", [][]any{{"log_statement", "all"}, {"pgaudit.log", "read,write"}, {"shared_preload_libraries", "pgaudit"}}, []any{true, true}, "audit_config: covered"},
		{"partial: logging but no queryable view", [][]any{{"log_statement", "all"}}, []any{false, false}, "audit_config: partial"},
		{"partial: ddl-only logging misses reads", [][]any{{"log_statement", "ddl"}}, []any{true, true}, "audit_config: partial"},
		{"none", [][]any{{"log_statement", "none"}}, []any{false, false}, "audit_config: none"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := auditConfigFake(c.settings, c.view)
			a := &Adapter{s: f, mode: dbprobe.ModeClient}
			res, err := a.RunProbe(context.Background(), def("read_audit_config"), spec("read_audit_config", dbprobe.ModeClient, nil))
			if err != nil {
				t.Fatal(err)
			}
			notes := strings.Join(res.Notes, "\n")
			if !strings.Contains(notes, c.want) {
				t.Fatalf("notes %q lack %q", notes, c.want)
			}
			for _, row := range c.settings {
				if !strings.Contains(notes, fmt.Sprintf("%v=%v", row[0], row[1])) {
					t.Errorf("notes lack key=value for %v: %s", row, notes)
				}
			}
			if !strings.Contains(notes, "dbsim_audit.pg_log=") {
				t.Errorf("notes lack view state: %s", notes)
			}
			if f.calls[0].sql != "BEGIN READ ONLY" || f.calls[len(f.calls)-1].sql != "ROLLBACK" {
				t.Fatalf("not read-only wrapped: %+v", f.calls)
			}
			for _, call := range f.calls {
				if (strings.Contains(call.sql, "pg_settings") || strings.Contains(call.sql, "to_regclass")) && len(call.args) != 0 {
					t.Errorf("config SQL must be parameterless: %+v", call)
				}
			}
		})
	}
}

func TestAuditCoverageUnits(t *testing.T) {
	if got := pgAuditCoverage("all", "", true); got != "covered" {
		t.Error(got)
	}
	if got := pgAuditCoverage("none", "all", true); got != "covered" {
		t.Error("pgaudit all + readable view is covered:", got)
	}
	if got := pgAuditCoverage("none", "-read,write", true); got != "partial" {
		t.Error("negated read must not count:", got)
	}
	if got := pgAuditCoverage("", "", false); got != "none" {
		t.Error(got)
	}
}
