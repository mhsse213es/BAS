package mysql

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	drv "github.com/go-sql-driver/mysql"

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

func epoch(sec int) []byte {
	return []byte(fmt.Sprintf("%d.%06d", auditSince.Unix()+int64(sec), 250000))
}

// auditFake scripts a MySQL server's audit surface.
type auditFake struct {
	*fakeSession
	glOn, psOn        int64
	logOutput         string
	consumersYes      bool
	glErr, histErr    error // errors reading the two tables at discovery
	consumersErr      error
	covered           bool
	rows              [][]any
	evErr             error
	plugins           [][]any
	glReadableForConf bool

	// sync sentinel scripting (see the PostgreSQL fake)
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

// sentinelRows answers an events query whose pattern names a sync sentinel.
func (af *auditFake) sentinelRows(sql string, args []any) ([][]any, bool) {
	var pat string
	for _, a := range args {
		if s, ok := a.(string); ok && strings.Contains(s, "dbsim-sync:") {
			pat = s
		}
	}
	if pat == "" {
		return nil, false
	}
	af.polls++
	if af.never || af.polls <= af.lag {
		return nil, true
	}
	stmt := dbprobe.MarkerComment(strings.Trim(pat, "%")) + " SELECT 1"
	if strings.Contains(sql, sqlHistEvents) {
		return [][]any{{epoch(1), []byte("svc_dbsim_probe"), []byte(stmt)}}, true
	}
	return [][]any{glRow(1, "svc_dbsim_probe[svc_dbsim_probe] @ h [1.1.1.1]", stmt)}, true
}

func newAuditFake() *auditFake {
	af := &auditFake{glOn: 1, psOn: 1, logOutput: "FILE,TABLE", consumersYes: true, covered: true, now: time.Unix(1700000000, 0)}
	af.fakeSession = &fakeSession{}
	af.fakeSession.queryFn = func(sql string, args []any) ([][]any, error) {
		switch {
		case strings.Contains(sql, sqlAuditVars):
			return [][]any{{af.glOn, []byte(af.logOutput), af.psOn}}, nil
		case strings.Contains(sql, sqlAuditConsumers):
			if af.consumersErr != nil {
				return nil, af.consumersErr
			}
			en := "YES"
			if !af.consumersYes {
				en = "NO"
			}
			return [][]any{{"events_statements_current", en}, {"events_statements_history_long", en}, {"global_instrumentation", en}, {"thread_instrumentation", en}}, nil
		case strings.Contains(sql, sqlGLProbe):
			if af.glErr != nil {
				return nil, af.glErr
			}
			return [][]any{{auditSince, "u[u] @ h [1.2.3.4]", []byte("x")}}, nil
		case strings.Contains(sql, sqlHistProbe):
			if af.histErr != nil {
				return nil, af.histErr
			}
			return [][]any{{int64(1), []byte("x"), int64(1)}}, nil
		case strings.Contains(sql, sqlGLCovered), strings.Contains(sql, sqlHistCovered):
			if af.covered {
				return [][]any{{int64(1)}}, nil
			}
			return [][]any{{int64(0)}}, nil
		case strings.Contains(sql, sqlGLEvents), strings.Contains(sql, sqlHistEvents):
			if af.evErr != nil {
				return nil, af.evErr
			}
			if rows, ok := af.sentinelRows(sql, args); ok {
				return rows, nil
			}
			return af.rows, nil
		case strings.Contains(sql, sqlAuditPlugins):
			return af.plugins, nil
		}
		return nil, nil
	}
	return af
}

func glRow(sec int, userHost, stmt string) []any {
	return []any{epoch(sec), []byte(userHost), []byte(stmt)}
}

func discovered(t *testing.T, af *auditFake) *Adapter {
	t.Helper()
	a := &Adapter{s: af.fakeSession, mode: dbprobe.ModeClient, scrub: newScrubber([]string{"hunter2-secret"}), auditSync: af.syncEnv()}
	if err := a.discoverAudit(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}

func assertAuditTxn(t *testing.T, f *fakeSession) {
	t.Helper()
	if len(f.calls) < 3 || f.calls[0].sql != "START TRANSACTION READ ONLY" {
		t.Fatalf("not wrapped in START TRANSACTION READ ONLY: %+v", f.calls)
	}
	if f.calls[len(f.calls)-1].sql != "ROLLBACK" {
		t.Fatalf("last %q", f.calls[len(f.calls)-1].sql)
	}
	for i, c := range f.calls {
		if !c.hasDeadline {
			t.Errorf("call %d without deadline", i)
		}
		if (strings.Contains(c.sql, "general_log") || strings.Contains(c.sql, "events_statements_history_long")) &&
			!strings.HasPrefix(c.sql, dbprobe.MetaStatementTag+" ") {
			t.Errorf("audit query without the collector tag: %q", c.sql)
		}
	}
}

func TestMySQLAuditEventContainsMarkerAndPrincipal(t *testing.T) {
	af := newAuditFake()
	af.rows = [][]any{
		glRow(2, "svc_dbsim_probe[svc_dbsim_probe] @ app01 [10.0.0.9]", "/* dbsim:"+auditMarker+" */ SELECT `User` FROM mysql.user"),
		glRow(3, "other_user[other_user] @ app02 [10.0.0.8]", "/* dbsim:"+auditMarker+" */ SELECT 1"), // other known principal: dropped
		glRow(4, "svc_dbsim_probe[svc_dbsim_probe] @ app01 [10.0.0.9]", "/* dbsim:OTHER */ SELECT 1"), // other marker: dropped
	}
	a := discovered(t, af)
	if got := a.Capabilities().AuditSources; len(got) != 2 || got[0] != "mysql.general_log" {
		t.Fatalf("sources %v", got)
	}
	af.calls = nil
	ev, err := a.CollectAudit(context.Background(), auditQ())
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 {
		t.Fatalf("want exactly the marker+principal event, got %+v", ev)
	}
	e := ev[0]
	if !strings.Contains(e.Statement, auditMarker) || e.Principal != "svc_dbsim_probe" || e.Source != "mysql.general_log" ||
		!e.Time.Equal(time.Unix(auditSince.Unix()+2, 250000000).UTC()) {
		t.Fatalf("event %+v (%v)", e, e.Time)
	}
	assertAuditTxn(t, af.fakeSession)
	var evCall *fakeCall
	for i := range af.calls {
		if strings.Contains(af.calls[i].sql, sqlGLEvents) {
			evCall = &af.calls[i]
		}
		if strings.Contains(af.calls[i].sql, "BAS-DBSIM") {
			t.Fatalf("marker spliced into SQL text: %q", af.calls[i].sql)
		}
	}
	if evCall == nil {
		t.Fatal("events query not issued")
	}
	// whole-second window floor/ceil, wildcard-escaped pattern, cap+1
	if len(evCall.args) != 4 || evCall.args[0] != auditSince.Unix() || evCall.args[1] != auditUntil.Unix() ||
		evCall.args[2] != `%BAS-DBSIM-run\_1%` || evCall.args[3] != dbprobe.AuditMaxEvents+1 {
		t.Fatalf("args %#v", evCall.args)
	}
}

func TestMySQLHistoryLongSourceWhenGeneralLogOff(t *testing.T) {
	af := newAuditFake()
	af.glOn = 0
	af.rows = [][]any{
		{epoch(1), []byte("svc_dbsim_probe"), []byte("/* dbsim:" + auditMarker + " */ SELECT 1")},
		{epoch(2), nil, []byte("/* dbsim:" + auditMarker + " */ SELECT 2")}, // thread gone: principal unknown, kept by marker
	}
	a := discovered(t, af)
	if got := a.Capabilities().AuditSources; len(got) != 1 || got[0] != "performance_schema.events_statements_history_long" {
		t.Fatalf("sources %v", got)
	}
	ev, err := a.CollectAudit(context.Background(), auditQ())
	if err != nil || len(ev) != 2 {
		t.Fatalf("%v %+v", err, ev)
	}
	if ev[0].Principal != "svc_dbsim_probe" || ev[1].Principal != "" || ev[0].Source != "performance_schema.events_statements_history_long" {
		t.Fatalf("%+v", ev)
	}
	notes := strings.Join(a.Capabilities().Notes, "|")
	for _, want := range []string{"ring buffer", "TIMER_START", "approximat"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes must state the history_long limits (%q missing): %s", want, notes)
		}
	}
}

func TestMySQLAuditSQLIsFixedAndReadOnly(t *testing.T) {
	all := []string{sqlAuditVars, sqlAuditConsumers, sqlAuditPlugins, sqlGLProbe, sqlHistProbe,
		sqlGLCovered, sqlGLEvents, sqlHistCovered, sqlHistEvents}
	for _, s := range all {
		u := strings.ToUpper(s)
		if !strings.HasPrefix(u, "SELECT") {
			t.Errorf("not a SELECT: %q", s)
		}
		for _, bad := range []string{"INSERT", "UPDATE ", "DELETE", "DROP", "ALTER", "CREATE", "GRANT", "TRUNCATE", "SET "} {
			if strings.Contains(u, bad) {
				t.Errorf("%q contains %s", s, bad)
			}
		}
	}
	if strings.Count(sqlGLEvents, "?") != 4 || strings.Count(sqlHistEvents, "?") != 4 {
		t.Error("events queries must bind exactly 4 params")
	}
	for _, s := range []string{sqlAuditVars, sqlAuditConsumers, sqlAuditPlugins} {
		if strings.Contains(s, "?") {
			t.Errorf("read_audit_config SQL must be parameterless: %q", s)
		}
	}
}

func TestAuditUnavailableReportsSkippedCapability(t *testing.T) {
	a := New()
	if len(a.Capabilities().AuditSources) != 0 {
		t.Fatal("unconnected adapter must declare no audit source")
	}
	if _, err := a.CollectAudit(context.Background(), auditQ()); !errors.Is(err, dbprobe.ErrAuditUnsupported) {
		t.Fatalf("want ErrAuditUnsupported, got %v", err)
	}
	denied := &drv.MySQLError{Number: 1142, Message: "SELECT command denied"}
	cases := map[string]func(*auditFake){
		"both off":             func(f *auditFake) { f.glOn, f.psOn = 0, 0 },
		"general_log to FILE":  func(f *auditFake) { f.logOutput = "FILE"; f.psOn = 0 },
		"consumers disabled":   func(f *auditFake) { f.glOn = 0; f.consumersYes = false },
		"consumers unreadable": func(f *auditFake) { f.glOn = 0; f.consumersErr = denied },
		"tables unreadable":    func(f *auditFake) { f.glErr = denied; f.histErr = denied },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			af := newAuditFake()
			mut(af)
			b := discovered(t, af)
			if got := b.Capabilities().AuditSources; len(got) != 0 {
				t.Fatalf("sources %v", got)
			}
			af.calls = nil
			ev, err := b.CollectAudit(context.Background(), auditQ())
			if !errors.Is(err, dbprobe.ErrAuditUnsupported) || len(ev) != 0 || len(af.calls) != 0 {
				t.Fatalf("%v %v calls=%d", ev, err, len(af.calls))
			}
			if dbprobe.AuditStatusOf(ev, err) != "unsupported" {
				t.Fatal("status must be unsupported")
			}
			if !strings.Contains(strings.Join(b.Capabilities().Notes, "|"), "No audit source") {
				t.Fatalf("notes must say why: %v", b.Capabilities().Notes)
			}
		})
	}
}

func TestMySQLCapabilitiesReflectDiscoveryAndCacheIt(t *testing.T) {
	af := newAuditFake()
	a := discovered(t, af)
	n := len(af.calls)
	for i := 0; i < 3; i++ {
		c := a.Capabilities()
		if len(c.AuditSources) != 2 || !c.MarkerInAuditRecord || len(c.ProbeIDs) != 13 {
			t.Fatalf("caps %+v", c)
		}
	}
	if len(af.calls) != n {
		t.Fatal("Capabilities must not query the database")
	}
	joined := strings.Join(a.Capabilities().Notes, "|")
	for _, want := range []string{"general_log", "program_name", "max_statement_time", "server_uuid"} {
		if !strings.Contains(joined, want) {
			t.Errorf("notes lack %q: %s", want, joined)
		}
	}
	assertAuditTxn(t, af.fakeSession)
}

func TestAuditSliceIncompleteWhenLogRotatedMidRun(t *testing.T) {
	for _, glOn := range []int64{1, 0} { // general_log and history_long paths
		af := newAuditFake()
		af.glOn = glOn
		af.covered = false
		uh := "svc_dbsim_probe[svc_dbsim_probe] @ h [1.1.1.1]" // general_log: user_host
		if glOn == 0 {
			uh = "svc_dbsim_probe" // history_long: thread user
		}
		af.rows = [][]any{glRow(2, uh, "/* dbsim:"+auditMarker+" */ SELECT 1")}
		a := discovered(t, af)
		ev, err := a.CollectAudit(context.Background(), auditQ())
		if !errors.Is(err, dbprobe.ErrAuditIncomplete) || len(ev) != 1 {
			t.Fatalf("glOn=%d: %v %+v", glOn, err, ev)
		}
		af.rows = nil
		ev, err = a.CollectAudit(context.Background(), auditQ())
		if got := dbprobe.AuditStatusOf(ev, err); got != "incomplete" {
			t.Fatalf("glOn=%d: rotated log with no event must be incomplete, got %s", glOn, got)
		}
	}
}

func TestMySQLAuditStatusFoundAbsentCapAndError(t *testing.T) {
	af := newAuditFake()
	a := discovered(t, af)
	ev, err := a.CollectAudit(context.Background(), auditQ())
	if dbprobe.AuditStatusOf(ev, err) != "absent" {
		t.Fatalf("absent: %v %v", ev, err)
	}
	af.rows = nil
	for i := 0; i < dbprobe.AuditMaxEvents+1; i++ {
		af.rows = append(af.rows, glRow(i%15, "svc_dbsim_probe[svc_dbsim_probe] @ h [1.1.1.1]", fmt.Sprintf("/* dbsim:%s */ SELECT %d", auditMarker, i)))
	}
	ev, err = a.CollectAudit(context.Background(), auditQ())
	if len(ev) != dbprobe.AuditMaxEvents || !errors.Is(err, dbprobe.ErrAuditIncomplete) {
		t.Fatalf("cap: %d %v", len(ev), err)
	}
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

func TestMySQLAuditTruncatesOnRuneBoundaryAndRedacts(t *testing.T) {
	af := newAuditFake()
	stmt := "/* dbsim:" + auditMarker + " */ -- password=hunter2-secret " + strings.Repeat("\u00e9", 400)
	af.rows = [][]any{glRow(1, "svc_dbsim_probe[svc_dbsim_probe] @ h [1.1.1.1]", stmt)}
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
		if r == '\uFFFD' {
			t.Fatal("statement cut inside a rune")
		}
	}
}

func TestMySQLAuditRefusesBadQueriesAndBrokenConnection(t *testing.T) {
	af := newAuditFake()
	a := discovered(t, af)
	af.calls = nil
	for i, q := range []dbprobe.AuditQuery{
		{Marker: "", Since: auditSince, Until: auditUntil},
		{Marker: "%%", Since: auditSince, Until: auditUntil},
		{Marker: auditMarker},
		{Marker: auditMarker, Since: auditUntil, Until: auditSince},
	} {
		ev, err := a.CollectAudit(context.Background(), q)
		if err == nil || dbprobe.AuditStatusOf(ev, err) != "error" {
			t.Errorf("query %d must be refused as an error: %v %v", i, ev, err)
		}
	}
	if len(af.calls) != 0 {
		t.Fatalf("a refused query must not reach the database: %+v", af.calls)
	}
	a.markBroken()
	if _, err := a.CollectAudit(context.Background(), auditQ()); err == nil || errors.Is(err, dbprobe.ErrAuditUnsupported) {
		t.Fatalf("broken connection must be an error: %v", err)
	}
}

func TestParseUserHostAndEpoch(t *testing.T) {
	for in, want := range map[string]string{
		"svc[svc] @ host [10.0.0.1]": "svc",
		"root[root] @ localhost []":  "root",
		"[root] @ localhost []":      "root",
		"plain":                      "plain",
		"":                           "",
	} {
		if got := parseUserHost(in); got != want {
			t.Errorf("parseUserHost(%q)=%q want %q", in, got, want)
		}
	}
	ts := parseEpoch([]byte("1700000000.250000"))
	if !ts.Equal(time.Unix(1700000000, 250000000).UTC()) {
		t.Errorf("epoch %v", ts)
	}
	if !parseEpoch(int64(1700000000)).Equal(time.Unix(1700000000, 0).UTC()) {
		t.Error("int epoch")
	}
	if !parseEpoch("garbage").IsZero() || !parseEpoch(nil).IsZero() {
		t.Error("bad epoch must be zero")
	}
}

func TestMySQLSelfLookupAndStrippedRowsAreNotFound(t *testing.T) {
	for _, glOn := range []int64{1, 0} {
		af := newAuditFake()
		af.glOn = glOn
		uh := "svc_dbsim_probe[svc_dbsim_probe] @ h [1.1.1.1]"
		if glOn == 0 {
			uh = "svc_dbsim_probe"
		}
		lookupSub := "SELECT UNIX_TIMESTAMP(event_time), user_host, argument FROM mysql.general_log WHERE argument LIKE '%" + auditMarker + "%'"
		af.rows = [][]any{
			// the collector's own prepared Execute with the marker substituted: meta-tagged
			glRow(1, uh, dbprobe.MetaStatementTag+" "+lookupSub),
			// the same lookup as seen through a path that stripped the leading comment
			glRow(2, uh, lookupSub),
			// the probe statement with its leading comment stripped by the log path
			glRow(3, uh, "SELECT User FROM mysql.user -- "+auditMarker),
			// marker only inside another run's WHERE clause
			glRow(4, uh, dbprobe.MarkerComment("OTHER")+" SELECT 1 WHERE x = '"+dbprobe.MarkerComment(auditMarker)+"'"),
		}
		a := discovered(t, af)
		ev, err := a.CollectAudit(context.Background(), auditQ())
		if got := dbprobe.AuditStatusOf(ev, err); got != "absent" || len(ev) != 0 {
			t.Fatalf("glOn=%d: self/stripped rows must never be found: %s %+v", glOn, got, ev)
		}
	}
}

func TestMySQLSentinelRunsReadOnlyBeforeTheLookup(t *testing.T) {
	af := newAuditFake()
	af.rows = [][]any{glRow(2, "svc_dbsim_probe[svc_dbsim_probe] @ h [1.1.1.1]", dbprobe.MarkerComment(auditMarker)+" SELECT 1")}
	a := discovered(t, af)
	af.calls = nil
	ev, err := a.CollectAudit(context.Background(), auditQ())
	if err != nil || len(ev) != 1 {
		t.Fatalf("%v %v", err, ev)
	}
	sentinelIdx, firstPoll, lookupIdx := -1, -1, -1
	for i, c := range af.calls {
		switch {
		case strings.Contains(c.sql, "/* dbsim:dbsim-sync:") && strings.HasSuffix(c.sql, " SELECT 1"):
			sentinelIdx = i
		case strings.Contains(c.sql, sqlGLEvents):
			if firstPoll < 0 {
				firstPoll = i
			}
			lookupIdx = i
		}
	}
	if sentinelIdx < 0 || firstPoll < 0 || !(sentinelIdx < firstPoll && firstPoll < lookupIdx) {
		t.Fatalf("order sentinel=%d poll=%d lookup=%d", sentinelIdx, firstPoll, lookupIdx)
	}
	if af.calls[0].sql != "START TRANSACTION READ ONLY" || af.calls[sentinelIdx-1].sql != "SET SESSION max_execution_time = 30000" ||
		af.calls[sentinelIdx-2].sql != "START TRANSACTION READ ONLY" || af.calls[sentinelIdx+1].sql != "ROLLBACK" {
		t.Fatalf("sentinel not read-only wrapped: %+v", af.calls[:sentinelIdx+2])
	}
	if len(af.sleeps) != 0 {
		t.Fatalf("sentinel visible at once must not sleep: %v", af.sleeps)
	}
}

func TestMySQLLagCatchUpNeverAndCancel(t *testing.T) {
	af := newAuditFake()
	af.lag = 3
	af.rows = [][]any{glRow(2, "svc_dbsim_probe[svc_dbsim_probe] @ h [1.1.1.1]", dbprobe.MarkerComment(auditMarker)+" SELECT 1")}
	a := discovered(t, af)
	ev, err := a.CollectAudit(context.Background(), auditQ())
	if err != nil || len(ev) != 1 || len(af.sleeps) != 3 {
		t.Fatalf("lag: %v %v sleeps=%v", err, ev, af.sleeps)
	}
	af = newAuditFake()
	af.never = true
	a = discovered(t, af)
	ev, err = a.CollectAudit(context.Background(), auditQ())
	if dbprobe.AuditStatusOf(ev, err) != "incomplete" || !strings.Contains(err.Error(), "did not catch up") || af.polls > 10 {
		t.Fatalf("never: %v %v polls=%d", ev, err, af.polls)
	}
	af = newAuditFake()
	af.never = true
	ctx, cancel := context.WithCancel(context.Background())
	af.cancel = cancel
	a = discovered(t, af)
	ev, err = a.CollectAudit(ctx, auditQ())
	if dbprobe.AuditStatusOf(ev, err) != "error" || !errors.Is(err, context.Canceled) || af.polls != 1 {
		t.Fatalf("cancel: %v %v polls=%d", ev, err, af.polls)
	}
}

func TestMySQLDiscoveryHasItsOwnFiveSecondBudget(t *testing.T) {
	af := newAuditFake()
	_ = discovered(t, af)
	if af.calls[1].sql != "SET SESSION max_execution_time = 5000" {
		t.Fatalf("discovery time limit %q, want 5000 ms", af.calls[1].sql)
	}
}

func TestMySQLDiscoveryErrorClasses(t *testing.T) {
	for _, no := range []uint16{3024, 1317, 1053, 2013} {
		t.Run(fmt.Sprint("fatal ", no), func(t *testing.T) {
			af := newAuditFake()
			af.consumersErr = &drv.MySQLError{Number: no, Message: "Query execution was interrupted"}
			b := discovered(t, af)
			c := b.Capabilities()
			if len(c.AuditSources) != 0 || c.AuditError == "" || !strings.Contains(c.AuditError, fmt.Sprint(no)) {
				t.Fatalf("caps %+v", c)
			}
			if !strings.Contains(strings.Join(c.Notes, "|"), fmt.Sprint(no)) {
				t.Fatalf("notes must carry the errno: %v", c.Notes)
			}
			ev, err := b.CollectAudit(context.Background(), auditQ())
			if dbprobe.AuditStatusOf(ev, err) != "error" || errors.Is(err, dbprobe.ErrAuditUnsupported) {
				t.Fatalf("must be error, not unsupported: %v", err)
			}
		})
	}
	// ordinary server errors degrade to no source; the errno is carried in Notes
	af := newAuditFake()
	af.glOn = 0
	af.consumersErr = &drv.MySQLError{Number: 1142, Message: "denied"}
	b := discovered(t, af)
	if c := b.Capabilities(); c.AuditError != "" || len(c.AuditSources) != 0 || !strings.Contains(strings.Join(c.Notes, "|"), "1142") {
		t.Fatalf("caps %+v", b.Capabilities())
	}
	// transport and context failures abort discovery
	af = newAuditFake()
	af.consumersErr = errors.New("driver: bad connection")
	a := &Adapter{s: af.fakeSession, mode: dbprobe.ModeClient}
	if err := a.discoverAudit(context.Background()); err == nil {
		t.Fatal("transport failure must abort")
	}
	af = newAuditFake()
	af.consumersErr = context.DeadlineExceeded
	a = &Adapter{s: af.fakeSession, mode: dbprobe.ModeClient}
	if err := a.discoverAudit(context.Background()); err == nil {
		t.Fatal("context failure must abort")
	}
}

func configFake(vars []any, consumers, plugins [][]any, glErr, histErr error) *fakeSession {
	return &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		switch {
		case strings.Contains(sql, "UTC_TIMESTAMP"):
			return [][]any{{time.Unix(1700000000, 0).UTC()}}, nil
		case strings.Contains(sql, sqlAuditVars):
			return [][]any{vars}, nil
		case strings.Contains(sql, sqlAuditConsumers):
			return consumers, nil
		case strings.Contains(sql, sqlAuditPlugins):
			return plugins, nil
		case strings.Contains(sql, sqlGLProbe):
			return [][]any{{auditSince, "u", "x"}}, glErr
		case strings.Contains(sql, sqlHistProbe):
			return [][]any{{int64(1), "x", int64(1)}}, histErr
		}
		return nil, nil
	}}
}

func TestReadAuditConfigReportsSettingsAndCoverage(t *testing.T) {
	yes := [][]any{{"events_statements_current", "YES"}, {"events_statements_history_long", "YES"}, {"global_instrumentation", "YES"}, {"thread_instrumentation", "YES"}}
	no := [][]any{{"events_statements_current", "NO"}, {"events_statements_history_long", "NO"}, {"global_instrumentation", "YES"}, {"thread_instrumentation", "YES"}}
	denied := &drv.MySQLError{Number: 1142, Message: "denied"}
	cases := []struct {
		name      string
		vars      []any
		consumers [][]any
		plugins   [][]any
		glErr     error
		histErr   error
		want      string
		wantNotes []string
	}{
		{"covered via general_log", []any{int64(1), []byte("TABLE"), int64(0)}, no, nil, nil, denied, "audit_config: covered",
			[]string{"general_log=ON", "log_output=TABLE", "performance_schema=OFF", "audit_plugins=none", "mysql.general_log=readable"}},
		{"covered via performance_schema", []any{int64(0), []byte("FILE"), int64(1)}, yes, nil, denied, nil, "audit_config: covered",
			[]string{"general_log=OFF", "performance_schema=ON", "ps_consumer.events_statements_history_long=YES", "performance_schema.events_statements_history_long=readable"}},
		{"partial: audit plugin only", []any{int64(0), []byte("FILE"), int64(0)}, no, [][]any{{"audit_log", "ACTIVE"}}, denied, denied, "audit_config: partial",
			[]string{"audit_plugins=audit_log:ACTIVE", "mysql.general_log=unreadable"}},
		{"partial: general_log to FILE", []any{int64(1), []byte("FILE"), int64(0)}, no, nil, nil, denied, "audit_config: partial", []string{"log_output=FILE"}},
		{"none", []any{int64(0), []byte("FILE"), int64(0)}, no, nil, denied, denied, "audit_config: none", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := configFake(c.vars, c.consumers, c.plugins, c.glErr, c.histErr)
			a := &Adapter{s: f, mode: dbprobe.ModeClient}
			res, err := a.RunProbe(context.Background(), def("read_audit_config"), spec("read_audit_config", dbprobe.ModeClient, nil))
			if err != nil {
				t.Fatal(err)
			}
			notes := strings.Join(res.Notes, "\n")
			for _, w := range append([]string{c.want}, c.wantNotes...) {
				if !strings.Contains(notes, w) {
					t.Errorf("notes lack %q:\n%s", w, notes)
				}
			}
			if f.calls[0].sql != "START TRANSACTION READ ONLY" || f.calls[len(f.calls)-1].sql != "ROLLBACK" {
				t.Fatalf("not read-only wrapped: %+v", f.calls)
			}
			for _, call := range f.calls {
				if (strings.Contains(call.sql, "PLUGINS") || strings.Contains(call.sql, "@@general_log")) && len(call.args) != 0 {
					t.Errorf("config SQL must be parameterless: %+v", call)
				}
			}
		})
	}
}
