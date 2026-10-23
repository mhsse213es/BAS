package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"audspect/agent/dbprobe"
	"audspect/agent/protocol"
)

var auditT0 = time.Date(2026, 10, 22, 9, 30, 0, 0, time.UTC)

func auditFake(t *testing.T) *fakeDBAdapter {
	t.Helper()
	fa := setupHappy(t)
	fa.auditSources = []string{"dbsim_audit.pg_log"}
	fa.probeFn = func(context.Context, dbprobe.ProbeDef, dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error) {
		return dbprobe.ProbeResult{RowsRead: 3, DBTime: auditT0}, nil
	}
	return fa
}

func TestDBProbeAuditCollectedAfterProbeWithPaddedWindow(t *testing.T) {
	fa := auditFake(t)
	fa.auditFn = func(_ context.Context, q dbprobe.AuditQuery) ([]dbprobe.AuditEvent, error) {
		return []dbprobe.AuditEvent{{Time: auditT0.Add(time.Second), Principal: "ro_user", Statement: "/* dbsim:BAS-DBSIM-1 */ SELECT 1", Source: "dbsim_audit.pg_log"}}, nil
	}
	out, err := executeDBProbe(context.Background(), testDBProbeStep(nil))
	if err != nil {
		t.Fatal(err)
	}
	// order: audit strictly after the probe, before Close
	want := []string{"Connect", "Identity", "RunProbe", "CollectAudit", "Close"}
	if got := strings.Join(fa.calls, ","); got != strings.Join(want, ",") {
		t.Fatalf("call order %s want %s", got, strings.Join(want, ","))
	}
	if len(fa.auditQueries) != 1 {
		t.Fatalf("queries %+v", fa.auditQueries)
	}
	q := fa.auditQueries[0]
	if q.Marker != "BAS-DBSIM-1" || q.Principal != "ro_user" {
		t.Fatalf("marker/principal %+v", q)
	}
	// window anchored on the DB-reported clock: [DBTime-5s, DBTime+elapsed+5s]
	if !q.Since.Equal(auditT0.Add(-dbprobe.AuditWindowSkew)) {
		t.Fatalf("since %v want %v", q.Since, auditT0.Add(-dbprobe.AuditWindowSkew))
	}
	if q.Until.Before(auditT0.Add(dbprobe.AuditWindowSkew)) || q.Until.After(auditT0.Add(dbprobe.AuditWindowSkew+5*time.Second)) {
		t.Fatalf("until %v out of range", q.Until)
	}
	if !fa.auditHadDeadline {
		t.Fatal("audit collection must run under its own deadline")
	}
	r := out.Result
	if r.AuditStatus != protocol.DBAuditFound || len(r.AuditEvents) != 1 || r.RowsRead != 3 {
		t.Fatalf("result %+v", r)
	}
	e := r.AuditEvents[0]
	if e.Principal != "ro_user" || e.Source != "dbsim_audit.pg_log" || !strings.Contains(e.Statement, "BAS-DBSIM-1") || !e.Time.Equal(auditT0.Add(time.Second)) {
		t.Fatalf("event %+v", e)
	}
}

func TestDBProbeAuditWindowFallsBackToAgentClock(t *testing.T) {
	fa := auditFake(t)
	fa.probeFn = func(context.Context, dbprobe.ProbeDef, dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error) {
		return dbprobe.ProbeResult{RowsRead: 1}, nil // no DBTime
	}
	before := time.Now()
	if _, err := executeDBProbe(context.Background(), testDBProbeStep(nil)); err != nil {
		t.Fatal(err)
	}
	q := fa.auditQueries[0]
	if q.Since.After(before.Add(-dbprobe.AuditWindowSkew+time.Second)) || q.Since.Before(before.Add(-dbprobe.AuditWindowSkew-5*time.Second)) {
		t.Fatalf("since %v not ~now-5s (now %v)", q.Since, before)
	}
}

func TestDBProbeAuditUnsupportedWhenAdapterHasNoSources(t *testing.T) {
	fa := setupHappy(t) // no audit sources
	out, err := executeDBProbe(context.Background(), testDBProbeStep(nil))
	if err != nil {
		t.Fatal(err)
	}
	if fa.count("CollectAudit") != 0 {
		t.Fatal("CollectAudit must not be called when the adapter reports no audit source")
	}
	if out.Result.AuditStatus != protocol.DBAuditUnsupported || len(out.Result.AuditEvents) != 0 {
		t.Fatalf("result %+v", out.Result)
	}
}

// A discovery failure that is a server timeout/shutdown is an audit ERROR with
// a Notes line, not "unsupported"; the probe observation is unaffected.
func TestDBProbeAuditDiscoveryErrorIsErrorNotUnsupported(t *testing.T) {
	fa := setupHappy(t)
	fa.auditError = "audit discovery failed: server timeout or shutdown (sqlstate 57014) for " + testCredPassword
	out, err := executeDBProbe(context.Background(), testDBProbeStep(nil))
	if err != nil {
		t.Fatal(err)
	}
	if fa.count("CollectAudit") != 0 {
		t.Fatal("no collection without a source")
	}
	r := out.Result
	joined := strings.Join(r.Notes, "|")
	if r.AuditStatus != protocol.DBAuditError || !strings.Contains(joined, "57014") || strings.Contains(joined, testCredPassword) || r.RowsRead != 3 {
		t.Fatalf("result %+v", r)
	}
}

func TestDBProbeAuditAbsentAndAdapterUnsupported(t *testing.T) {
	fa := auditFake(t)
	out, _ := executeDBProbe(context.Background(), testDBProbeStep(nil))
	if out.Result.AuditStatus != protocol.DBAuditAbsent {
		t.Fatalf("no events, nil error must be absent: %+v", out.Result)
	}
	fa.auditFn = func(context.Context, dbprobe.AuditQuery) ([]dbprobe.AuditEvent, error) {
		return nil, dbprobe.ErrAuditUnsupported
	}
	out, _ = executeDBProbe(context.Background(), testDBProbeStep(nil))
	if out.Result.AuditStatus != protocol.DBAuditUnsupported {
		t.Fatalf("adapter-reported unsupported: %+v", out.Result)
	}
}

func TestDBProbeAuditFailureNeverTurnsIntoPassOrCrash(t *testing.T) {
	fa := auditFake(t)
	fa.auditFn = func(context.Context, dbprobe.AuditQuery) ([]dbprobe.AuditEvent, error) {
		return nil, errors.New("log view broke for ro_user with " + testCredPassword)
	}
	out, err := executeDBProbe(context.Background(), testDBProbeStep(nil))
	if err != nil {
		t.Fatalf("an audit failure must not fail the probe run: %v", err)
	}
	r := out.Result
	if r.AuditStatus != protocol.DBAuditError || len(r.AuditEvents) != 0 {
		t.Fatalf("status %q events %d", r.AuditStatus, len(r.AuditEvents))
	}
	if r.RowsRead != 3 {
		t.Fatal("probe observation must still be reported")
	}
	joined := strings.Join(r.Notes, "|")
	if strings.Contains(joined, testCredPassword) || !strings.Contains(joined, "audit") {
		t.Fatalf("notes %q", joined)
	}
	// a panicking collector is contained as an error too
	fa.auditFn = func(context.Context, dbprobe.AuditQuery) ([]dbprobe.AuditEvent, error) { panic("kaboom") }
	out, err = executeDBProbe(context.Background(), testDBProbeStep(nil))
	if err != nil || out.Result.AuditStatus != protocol.DBAuditError {
		t.Fatalf("panic must be contained: %v %+v", err, out.Result)
	}
}

func TestDBProbeAuditIncompleteKeepsEventsAndReason(t *testing.T) {
	fa := auditFake(t)
	fa.auditFn = func(context.Context, dbprobe.AuditQuery) ([]dbprobe.AuditEvent, error) {
		return []dbprobe.AuditEvent{{Time: auditT0, Statement: "x"}}, &dbprobe.AuditIncompleteError{Reason: "log rotated"}
	}
	out, _ := executeDBProbe(context.Background(), testDBProbeStep(nil))
	r := out.Result
	if r.AuditStatus != protocol.DBAuditIncomplete || len(r.AuditEvents) != 1 || !strings.Contains(strings.Join(r.Notes, "|"), "log rotated") {
		t.Fatalf("result %+v", r)
	}
}

func TestDBProbeAuditDefensivelyCapsAndTruncates(t *testing.T) {
	fa := auditFake(t)
	fa.auditFn = func(context.Context, dbprobe.AuditQuery) ([]dbprobe.AuditEvent, error) {
		var evs []dbprobe.AuditEvent
		for i := 0; i < 60; i++ {
			evs = append(evs, dbprobe.AuditEvent{Time: auditT0, Statement: strings.Repeat("é", 600)})
		}
		return evs, nil // a misbehaving adapter: no incomplete signal
	}
	out, _ := executeDBProbe(context.Background(), testDBProbeStep(nil))
	r := out.Result
	if len(r.AuditEvents) != dbprobe.AuditMaxEvents || r.AuditStatus != protocol.DBAuditIncomplete {
		t.Fatalf("cap: %d %s", len(r.AuditEvents), r.AuditStatus)
	}
	for _, e := range r.AuditEvents {
		if len(e.Statement) > dbprobe.AuditMaxStatementBytes {
			t.Fatalf("statement %d bytes", len(e.Statement))
		}
	}
}

func TestDBProbeAuditNotAttemptedWhenProbeFailsToRun(t *testing.T) {
	fa := auditFake(t)
	fa.probeFn = func(context.Context, dbprobe.ProbeDef, dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error) {
		return dbprobe.ProbeResult{}, errors.New("driver exploded")
	}
	_, err := executeDBProbe(context.Background(), testDBProbeStep(nil))
	if err == nil {
		t.Fatal("expected probe error")
	}
	if fa.count("CollectAudit") != 0 {
		t.Fatal("no audit collection after a failed probe run")
	}
}

func TestDBProbeAuditStillCollectedForDeniedProbe(t *testing.T) {
	fa := auditFake(t)
	fa.probeFn = func(context.Context, dbprobe.ProbeDef, dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error) {
		return dbprobe.ProbeResult{Denied: true, ErrorClass: "permission_denied", DBTime: auditT0}, nil
	}
	fa.auditFn = func(context.Context, dbprobe.AuditQuery) ([]dbprobe.AuditEvent, error) {
		return []dbprobe.AuditEvent{{Time: auditT0, Statement: "/* dbsim:BAS-DBSIM-1 */ SELECT 1 FROM restricted"}}, nil
	}
	out, _ := executeDBProbe(context.Background(), testDBProbeStep(nil))
	if !out.Result.Denied || out.Result.AuditStatus != protocol.DBAuditFound {
		t.Fatalf("a denied attempt is exactly what the audit should show: %+v", out.Result)
	}
}

func TestDBProbeAuditNotAttemptedOnGateRefusal(t *testing.T) {
	fa := auditFake(t)
	fa.identity = "some-other-server"
	out, _ := executeDBProbe(context.Background(), testDBProbeStep(nil))
	if out.GateRefusal == "" || fa.count("CollectAudit") != 0 || fa.count("RunProbe") != 0 {
		t.Fatalf("refusal %q, calls %v", out.GateRefusal, fa.calls)
	}
}

func TestExecDBProbeStepCarriesAuditFields(t *testing.T) {
	fa := auditFake(t)
	fa.auditFn = func(context.Context, dbprobe.AuditQuery) ([]dbprobe.AuditEvent, error) {
		return []dbprobe.AuditEvent{{Time: auditT0, Principal: "ro_user", Statement: "s", Source: "src"}}, nil
	}
	r := execDBProbeStep(context.Background(), testDBProbeStep(nil))
	if r.DBProbe == nil || r.DBProbe.AuditStatus != "found" || len(r.DBProbe.AuditEvents) != 1 || r.ExitCode != 0 {
		t.Fatalf("%+v", r)
	}
}
