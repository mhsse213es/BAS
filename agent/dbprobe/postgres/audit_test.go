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

	// sync sentinel scripting: the sentinel statement becomes visible after
	// `lag` polls (never when `never`); the clock and sleep are fake.
	lag, polls int
	never      bool
	now        time.Time
	sleeps     []time.Duration
	cancel     func()
}

func (af *auditFake) syncEnv() dbprobe.AuditSync {
	return dbprobe.AuditSync{
		Now: func() time.Time { return af.now },
		Sleep: func(ctx context.Context, d time.Duration) error {
			af.sleeps = append(af.sleeps, d)
			af.now = af.now.Add(d)
			if af.cancel != nil {
				af.cancel()
			}
			return ctx.Err()
		},
	}
}

func newAuditFake() *auditFake {
	af := &auditFake{covered: true, now: time.Unix(1700000000, 0)}
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
			if pat, _ := args[2].(string); strings.Contains(pat, "dbsim-sync:") {
				af.polls++
				if af.never || af.polls <= af.lag {
					return nil, nil
				}
				m := strings.Trim(pat, "%")
				return [][]any{{auditSince, "svc_dbsim_probe", "statement: " + dbprobe.MarkerComment(m) + " SELECT 1"}}, nil
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
	a := &Adapter{s: af.fakeSession, mode: dbprobe.ModeClient, secrets: []string{"hunter2-secret"}, auditSync: af.syncEnv()}
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
	if len(a.Capabilities().ProbeIDs) != 7 {
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

func TestPGStatementTextStripsOnlyKnownLogPrefixes(t *testing.T) {
	c := dbprobe.MarkerComment("M")
	for in, want := range map[string]string{
		"statement: " + c + " SELECT 1":           c + " SELECT 1",
		"execute <unnamed>: " + c + " SELECT 1":   c + " SELECT 1",
		"execute S_1: " + c + " SELECT 1":         c + " SELECT 1",
		c + " SELECT 1":                           c + " SELECT 1",
		"AUDIT: SESSION,1,1,READ,SELECT,,," + c:   "AUDIT: SESSION,1,1,READ,SELECT,,," + c, // pgaudit: not identifiable
		"duration: 1.2 ms  statement: " + c + "x": "duration: 1.2 ms  statement: " + c + "x",
	} {
		if got := pgStatementText(in); got != want {
			t.Errorf("pgStatementText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPGAuditSelfLookupAndStrippedRowsAreNotFound(t *testing.T) {
	af := newAuditFake()
	af.rows = [][]any{
		// the collector's own lookup, comment-led with the meta tag, marker in the text
		auditRow(1, "svc_dbsim_probe", dbprobe.MetaStatementTag+" SELECT log_time FROM dbsim_audit.pg_log WHERE message LIKE '%"+auditMarker+"%'"),
		// a log path that stripped the leading comment from the probe statement
		auditRow(2, "svc_dbsim_probe", "SELECT rolname FROM pg_roles -- "+auditMarker),
		// the marker only inside a WHERE clause of another run's statement
		auditRow(3, "svc_dbsim_probe", dbprobe.MarkerComment("OTHER")+" SELECT 1 WHERE x = '"+dbprobe.MarkerComment(auditMarker)+"'"),
	}
	a := discovered(t, af)
	ev, err := a.CollectAudit(context.Background(), auditQ())
	if got := dbprobe.AuditStatusOf(ev, err); got != "absent" || len(ev) != 0 {
		t.Fatalf("self/stripped rows must never be found: %s %+v", got, ev)
	}
}

func TestPGSentinelRunsReadOnlyBeforeTheLookup(t *testing.T) {
	af := newAuditFake()
	af.rows = [][]any{auditRow(2, "svc_dbsim_probe", dbprobe.MarkerComment(auditMarker)+" SELECT 1")}
	a := discovered(t, af)
	af.calls = nil
	if _, err := a.CollectAudit(context.Background(), auditQ()); err != nil {
		t.Fatal(err)
	}
	if af.calls[0].sql != "BEGIN READ ONLY" {
		t.Fatalf("first %q", af.calls[0].sql)
	}
	sentinelIdx, firstPoll, lookupIdx := -1, -1, -1
	for i, c := range af.calls {
		switch {
		case strings.Contains(c.sql, "/* dbsim:dbsim-sync:") && strings.HasSuffix(c.sql, " SELECT 1"):
			sentinelIdx = i
		case strings.Contains(c.sql, sqlAuditEvents):
			if firstPoll < 0 {
				firstPoll = i
			}
			lookupIdx = i
		}
	}
	if sentinelIdx < 0 || firstPoll < 0 || !(sentinelIdx < firstPoll && firstPoll < lookupIdx) {
		t.Fatalf("order sentinel=%d poll=%d lookup=%d: %+v", sentinelIdx, firstPoll, lookupIdx, af.calls)
	}
	// the sentinel sits inside its own BEGIN READ ONLY ... ROLLBACK
	if af.calls[sentinelIdx-3].sql != "BEGIN READ ONLY" || af.calls[sentinelIdx+1].sql != "ROLLBACK" {
		t.Fatalf("sentinel not read-only wrapped: %+v", af.calls[:sentinelIdx+2])
	}
	if !strings.Contains(af.calls[sentinelIdx-1].args[0].(string), "dbsim-sync:") {
		t.Fatalf("application_name should carry the sentinel marker: %+v", af.calls[sentinelIdx-1])
	}
	for _, c := range af.calls {
		if strings.Contains(c.sql, "dbsim-sync:") && strings.Contains(c.sql, "pg_log") {
			t.Errorf("sentinel marker spliced into audit SQL: %q", c.sql)
		}
	}
	if len(af.sleeps) != 0 {
		t.Fatalf("sentinel visible at once must not sleep: %v", af.sleeps)
	}
}

func TestPGLagThenCatchUpPollsWithBackoffNoRealSleep(t *testing.T) {
	af := newAuditFake()
	af.lag = 3
	af.rows = [][]any{auditRow(2, "svc_dbsim_probe", dbprobe.MarkerComment(auditMarker)+" SELECT 1")}
	a := discovered(t, af)
	ev, err := a.CollectAudit(context.Background(), auditQ())
	if err != nil || len(ev) != 1 {
		t.Fatalf("%v %+v", err, ev)
	}
	if len(af.sleeps) != 3 || af.sleeps[0] != 250*time.Millisecond || af.sleeps[2] != time.Second {
		t.Fatalf("sleeps %v", af.sleeps)
	}
}

func TestPGNeverCatchesUpIsIncompleteAndBounded(t *testing.T) {
	af := newAuditFake()
	af.never = true
	a := discovered(t, af)
	ev, err := a.CollectAudit(context.Background(), auditQ())
	if dbprobe.AuditStatusOf(ev, err) != "incomplete" || !strings.Contains(err.Error(), "did not catch up") {
		t.Fatalf("%v %v", ev, err)
	}
	if af.polls > 10 {
		t.Fatalf("unbounded polling: %d", af.polls)
	}
}

func TestPGCancelDuringPollStopsAndIsError(t *testing.T) {
	af := newAuditFake()
	af.never = true
	ctx, cancel := context.WithCancel(context.Background())
	af.cancel = cancel
	a := discovered(t, af)
	ev, err := a.CollectAudit(ctx, auditQ())
	if dbprobe.AuditStatusOf(ev, err) != "error" || !errors.Is(err, context.Canceled) || af.polls != 1 {
		t.Fatalf("%v %v polls=%d", ev, err, af.polls)
	}
}

func TestPGDiscoveryHasItsOwnFiveSecondBudget(t *testing.T) {
	af := newAuditFake()
	_ = discovered(t, af)
	if af.calls[1].args[0] != "5000" {
		t.Fatalf("discovery statement_timeout arg %v, want 5000", af.calls[1].args)
	}
}

func TestPGDiscoveryErrorClasses(t *testing.T) {
	// server-side timeout/shutdown => audit status error, recorded with the sqlstate
	for _, code := range []string{"57014", "57P01", "57P02", "57P03"} {
		t.Run("fatal "+code, func(t *testing.T) {
			af := newAuditFake()
			af.probeErr = &pgconn.PgError{Code: code, Message: "canceling statement due to statement timeout"}
			b := discovered(t, af)
			c := b.Capabilities()
			if len(c.AuditSources) != 0 || c.AuditError == "" || !strings.Contains(c.AuditError, code) {
				t.Fatalf("caps %+v", c)
			}
			if !strings.Contains(strings.Join(c.Notes, "|"), code) {
				t.Fatalf("notes must carry the sqlstate: %v", c.Notes)
			}
			ev, err := b.CollectAudit(context.Background(), auditQ())
			if dbprobe.AuditStatusOf(ev, err) != "error" || errors.Is(err, dbprobe.ErrAuditUnsupported) {
				t.Fatalf("must be error, not unsupported: %v", err)
			}
		})
	}
	// ordinary server errors degrade to "no source", sqlstate carried in Notes
	af := newAuditFake()
	af.probeErr = &pgconn.PgError{Code: "42501", Message: "denied"}
	b := discovered(t, af)
	if c := b.Capabilities(); c.AuditError != "" || !strings.Contains(strings.Join(c.Notes, "|"), "42501") {
		t.Fatalf("caps %+v", c)
	}
	// transport failure aborts discovery (connection state unknown)
	af = newAuditFake()
	af.probeErr = errors.New("connection reset by peer")
	a := &Adapter{s: af.fakeSession, mode: dbprobe.ModeClient}
	if err := a.discoverAudit(context.Background()); err == nil {
		t.Fatal("transport failure must abort")
	}
	// context failure aborts discovery too
	af = newAuditFake()
	af.probeErr = context.DeadlineExceeded
	a = &Adapter{s: af.fakeSession, mode: dbprobe.ModeClient}
	if err := a.discoverAudit(context.Background()); err == nil {
		t.Fatal("context failure must abort")
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
