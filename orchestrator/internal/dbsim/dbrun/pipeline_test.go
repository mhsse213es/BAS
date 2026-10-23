package dbrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/dlpreport"
)

var pT0 = time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)

const pMarker = "bas-dbsim:0123456789abcdef01234567"

func baseSpec(probe string) dbsim.DBProbeSpec {
	return dbsim.DBProbeSpec{Engine: "postgresql", ProbeID: probe, TargetID: "lab-db", Host: "db.lab", Port: 55432,
		RunID: "bas-dbsim-run:1111", Marker: pMarker, Mode: dbsim.ModeLab, Limits: dbsim.Limits{MaxRows: 10, TimeoutSec: 30, MaxConns: 1}}
}

func okExec(rows int, notes ...string) AgentExec {
	return AgentExec{DBProbe: &dbsim.DBProbeResult{RowsRead: rows, DBTime: pT0, AgentTime: pT0, Notes: notes, CleanupStatus: dbsim.CleanupOK}}
}

func input(scenarioID, probe string, ex AgentExec) StepInput {
	spec := baseSpec(probe)
	return StepInput{
		Scenario: labMeta(scenarioID, spec), Spec: spec, Exec: ex, Principal: "dbsim_lab",
		DBHost: "dbsim-pg", DBIP: "172.28.50.10", AgentIP: "172.28.50.20",
		Window: 2 * time.Minute, SkewAllowance: 2 * time.Second,
		Now: func() time.Time { return pT0.Add(time.Minute) },
	}
}

func realStmt(marker string) string {
	return "execute S_1: /* dbsim:" + marker + " */ SELECT * FROM \"dbsim_x\".\"accounts\" LIMIT $1"
}

func mustEval(t *testing.T, c detectverify.Connector, in StepInput) Evaluation {
	t.Helper()
	ev, err := Evaluate(context.Background(), c, in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if err := ev.Record.Validate(); err != nil {
		t.Fatalf("Record.Validate: %v", err)
	}
	if !ev.Result.Valid() {
		t.Fatalf("invalid result %q", ev.Result)
	}
	return ev
}

func TestPipeline_FakeAgentFakeConnector_ExactMarkerIsPresentAlerted(t *testing.T) {
	c := &fakeConn{reply: alertsReply(elasticLikeAlert("al1", pT0.Add(14*time.Second), realStmt(pMarker)))}
	ev := mustEval(t, c, input("dbsim-db05-suspicious-read", "suspicious_read", okExec(10, "shape=wide_select", "rows_read=10")))
	if ev.Record.Telemetry != dlpreport.TelemetryPresent || ev.Record.Response != dlpreport.ResponseAlerted {
		t.Fatalf("telemetry %s response %s", ev.Record.Telemetry, ev.Record.Response)
	}
	if ev.Outcome.Corr.Latency <= 0 || ev.Outcome.Corr.Latency != 14*time.Second {
		t.Fatalf("latency %s", ev.Outcome.Corr.Latency)
	}
	if ev.Result != dbsim.ResultPass || ev.Record.Confidence != string(dbsim.MatchExactMarker) {
		t.Fatalf("result %s confidence %s (%s)", ev.Result, ev.Record.Confidence, ev.Report.Reason)
	}
	if !strings.Contains(ev.Record.Limitations, "no case, escalation or remediation") {
		t.Fatalf("Alerted must be bounded in the limitations: %q", ev.Record.Limitations)
	}
	if strings.Contains(ev.Record.Limitations, "Response was not assessed") {
		t.Fatalf("contradictory response limitation: %q", ev.Record.Limitations)
	}
	if c.calls != 2 {
		t.Fatalf("DB host and agent host must both be queried, got %d lookups", c.calls)
	}
}

func TestPipeline_FakeAgentFakeConnector_NoAlertIsAbsentAndFails(t *testing.T) {
	ev := mustEval(t, &fakeConn{reply: alertsReply()}, input("dbsim-db05-suspicious-read", "suspicious_read", okExec(10)))
	if ev.Record.Telemetry != dlpreport.TelemetryAbsent || ev.Result != dbsim.ResultFail {
		t.Fatalf("telemetry %s result %s", ev.Record.Telemetry, ev.Result)
	}
	if ev.Record.Response == dlpreport.ResponseAlerted {
		t.Fatal("Alerted without an alert")
	}
}

func TestPipeline_FakeAgentFakeConnector_UnmarkedAlertIsAmbiguousNeverPass(t *testing.T) {
	// The connector's Verdict says Detected; it must be ignored.
	c := &fakeConn{reply: alertsReply(elasticLikeAlert("al1", pT0.Add(5*time.Second), "SELECT 1 on some other session"))}
	ev := mustEval(t, c, input("dbsim-db05-suspicious-read", "suspicious_read", okExec(10)))
	if ev.Record.Telemetry == dlpreport.TelemetryPresent || ev.Result == dbsim.ResultPass {
		t.Fatalf("ambiguous alert credited: %s / %s", ev.Record.Telemetry, ev.Result)
	}
	if ev.Outcome.Corr.Match != dbsim.MatchAmbiguous || ev.Result != dbsim.ResultError {
		t.Fatalf("match %s result %s", ev.Outcome.Corr.Match, ev.Result)
	}
}

func TestPipeline_FakeAgentFakeConnector_OtherRunsMarkerIsNotCredited(t *testing.T) {
	other := "bas-dbsim:fedcba9876543210fedcba98"
	c := &fakeConn{reply: alertsReply(elasticLikeAlert("al1", pT0.Add(5*time.Second), realStmt(other)))}
	ev := mustEval(t, c, input("dbsim-db05-suspicious-read", "suspicious_read", okExec(10)))
	if ev.Outcome.Corr.Match == dbsim.MatchExactMarker || ev.Result == dbsim.ResultPass {
		t.Fatalf("cross-run credit: %s / %s", ev.Outcome.Corr.Match, ev.Result)
	}
}

func TestPipeline_FakeAgentFakeConnector_ConnectorDownIsUnverifiable(t *testing.T) {
	c := &fakeConn{reply: func(detectverify.VerifyRequest) (detectverify.VerifyResult, error) {
		return detectverify.VerifyResult{}, errors.New("elastic: connection refused to https://es.lab:9200 using password=hunter2")
	}}
	ev := mustEval(t, c, input("dbsim-db05-suspicious-read", "suspicious_read", okExec(10)))
	if ev.Record.Telemetry != dlpreport.TelemetryUnverifiable || ev.Result != dbsim.ResultError {
		t.Fatalf("telemetry %s result %s", ev.Record.Telemetry, ev.Result)
	}
	if ev.CorrelationErr == "" {
		t.Fatal("correlation error not surfaced")
	}
	b, _ := json.Marshal(ev)
	if strings.Contains(string(b), "hunter2") {
		t.Fatal("secret from a connector error survived")
	}
}

func TestPipeline_FakeAgentFakeConnector_NilConnectorIsUnverifiable(t *testing.T) {
	ev := mustEval(t, nil, input("dbsim-db05-suspicious-read", "suspicious_read", okExec(10)))
	if ev.Record.Telemetry != dlpreport.TelemetryUnverifiable || ev.Result != dbsim.ResultError || ev.Outcome.Corr.Evaluated {
		t.Fatalf("telemetry %s result %s evaluated %v", ev.Record.Telemetry, ev.Result, ev.Outcome.Corr.Evaluated)
	}
}

func TestPipeline_FakeAgentFakeConnector_DelayedAlertFails(t *testing.T) {
	late := pT0.Add(2*time.Minute + 2*time.Second + 30*time.Second)
	c := &fakeConn{reply: alertsReply(elasticLikeAlert("al1", late, realStmt(pMarker)))}
	ev := mustEval(t, c, input("dbsim-db05-suspicious-read", "suspicious_read", okExec(10)))
	if ev.Record.Telemetry != dlpreport.TelemetryDelayed || ev.Result != dbsim.ResultFail {
		t.Fatalf("telemetry %s result %s", ev.Record.Telemetry, ev.Result)
	}
	if ev.Record.Response == dlpreport.ResponseAlerted {
		t.Fatal("a late alert must not be reported as an on-time response")
	}
}

func TestPipeline_FakeAgentFakeConnector_NoDetectionExpectedSkipsTheSIEM(t *testing.T) {
	in := input("dbsim-db04-audit-coverage", "read_audit_config", okExec(5, "audit_config: covered"))
	c2 := &fakeConn{reply: alertsReply()}
	ev2 := mustEval(t, c2, in)
	if c2.calls != 0 || ev2.Outcome.Corr.Evaluated {
		t.Fatalf("SIEM queried for a scenario that expects no detection (%d calls)", c2.calls)
	}
	if ev2.Result != dbsim.ResultPass {
		t.Fatalf("covered config: %s (%s)", ev2.Result, ev2.Report.Reason)
	}
}

func auditExec(status string, events ...dbsim.DBProbeAuditEvent) AgentExec {
	return AgentExec{DBProbe: &dbsim.DBProbeResult{RowsRead: 4, DBTime: pT0, AgentTime: pT0, AuditStatus: status, AuditEvents: events}}
}

func db04Tagged(ex AgentExec, alerts ...detectverify.MatchedAlert) Evaluation {
	return mustEvalNoT(&fakeConn{reply: alertsReply(alerts...)}, input("dbsim-db04-audit-coverage", "read_roles", ex))
}

func mustEvalNoT(c detectverify.Connector, in StepInput) Evaluation {
	ev, err := Evaluate(context.Background(), c, in)
	if err != nil {
		panic(err)
	}
	return ev
}

func TestPipeline_FakeAgentFakeConnector_AuditStatuses(t *testing.T) {
	good := dbsim.DBProbeAuditEvent{Time: pT0, Principal: "dbsim_lab", Statement: "/* dbsim:" + pMarker + " */ SELECT rolname FROM pg_roles"}
	alert := elasticLikeAlert("al1", pT0.Add(8*time.Second), realStmt(pMarker))
	cases := []struct {
		name   string
		ex     AgentExec
		alerts []detectverify.MatchedAlert
		result dbsim.RunResult
		tel    dlpreport.TelemetryOutcome
	}{
		{"found+alert", auditExec(dbsim.AuditFound, good), []detectverify.MatchedAlert{alert}, dbsim.ResultPass, dlpreport.TelemetryPresent},
		{"unsupported", auditExec(dbsim.AuditUnsupported), []detectverify.MatchedAlert{alert}, dbsim.ResultSkipped, dlpreport.TelemetryPresent},
		{"absent", auditExec(dbsim.AuditAbsent), []detectverify.MatchedAlert{alert}, dbsim.ResultFail, dlpreport.TelemetryIncomplete},
		{"incomplete", auditExec(dbsim.AuditIncomplete), []detectverify.MatchedAlert{alert}, dbsim.ResultError, dlpreport.TelemetryIncomplete},
		{"error", auditExec(dbsim.AuditError), []detectverify.MatchedAlert{alert}, dbsim.ResultError, dlpreport.TelemetryIncomplete},
		{"legacy-empty", auditExec(""), []detectverify.MatchedAlert{alert}, dbsim.ResultError, dlpreport.TelemetryIncomplete},
	}
	for _, c := range cases {
		ev := db04Tagged(c.ex, c.alerts...)
		if err := ev.Record.Validate(); err != nil {
			t.Errorf("%s: Validate: %v", c.name, err)
		}
		if ev.Result != c.result {
			t.Errorf("%s: result %s want %s (%s)", c.name, ev.Result, c.result, ev.Report.Reason)
		}
		if c.name == "unsupported" {
			// unsupported is a coverage gap of the audit slice; the alert itself is real
			if ev.Record.Telemetry == dlpreport.TelemetryPresent && ev.Result == dbsim.ResultPass {
				t.Errorf("unsupported audit graded as pass")
			}
			continue
		}
		if ev.Record.Telemetry != c.tel {
			t.Errorf("%s: telemetry %s want %s", c.name, ev.Record.Telemetry, c.tel)
		}
	}
}

func TestPipeline_FakeAgentFakeConnector_AuditConfigNoneFails(t *testing.T) {
	ev := mustEval(t, &fakeConn{reply: alertsReply()}, input("dbsim-db04-audit-coverage", "read_audit_config", okExec(5, "log_statement=none", "audit_config: none")))
	if ev.Result != dbsim.ResultFail || ev.Record.Telemetry != dlpreport.TelemetryAbsent {
		t.Fatalf("result %s telemetry %s", ev.Result, ev.Record.Telemetry)
	}
}

func TestPipeline_FakeAgentFakeConnector_DB02ZeroGrantsIsNeverPass(t *testing.T) {
	alert := elasticLikeAlert("al1", pT0.Add(8*time.Second), realStmt(pMarker))
	ev := mustEval(t, &fakeConn{reply: alertsReply(alert)}, input("dbsim-db02-excessive-grants", "read_grants", okExec(0)))
	if ev.Result == dbsim.ResultPass || ev.Result != dbsim.ResultError {
		t.Fatalf("result %s", ev.Result)
	}
	if !strings.Contains(ev.Record.Limitations, "no grants observed: account may lack catalog visibility") {
		t.Fatalf("limitations %q", ev.Record.Limitations)
	}
	in := input("dbsim-db02-excessive-grants", "read_grants", okExec(0))
	n := 7
	in.GrantsChecked = &n
	// R-AJ: a count without a performed diff is still ERROR (grants listable, not compared).
	ev = mustEval(t, &fakeConn{reply: alertsReply(alert)}, in)
	if ev.Result != dbsim.ResultError || !strings.Contains(ev.Record.Limitations, "policy diff not performed; grants were observable (7) but not compared to a stated policy") {
		t.Fatalf("count without diff: %s (%s) %q", ev.Result, ev.Report.Reason, ev.Record.Limitations)
	}
	in.Diff = &dbsim.DiffReport{PolicySource: "lab", GrantsChecked: 7, Deviations: []dbsim.Deviation{}}
	if ev := mustEval(t, &fakeConn{reply: alertsReply(alert)}, in); ev.Result != dbsim.ResultPass {
		t.Fatalf("a supplied clean diff should pass, got %s (%s)", ev.Result, ev.Report.Reason)
	}
	in.Diff = nil
	zero := 0
	in.GrantsChecked = &zero
	in.Exec = okExec(9)
	if ev := mustEval(t, &fakeConn{reply: alertsReply(alert)}, in); ev.Result != dbsim.ResultError {
		t.Fatalf("DiffReport.GrantsChecked=0 must be ERROR even if rows were reported, got %s", ev.Result)
	}
}

func TestPipeline_FakeAgentFakeConnector_SafetyIncidentBeatsExactAlert(t *testing.T) {
	ex := okExec(10)
	ex.DBProbe.SafetyIncident = true
	ex.DBProbe.CleanupStatus = dbsim.CleanupResidual
	c := &fakeConn{reply: alertsReply(elasticLikeAlert("al1", pT0.Add(5*time.Second), realStmt(pMarker)))}
	ev := mustEval(t, c, input("dbsim-db09-bounded-bulk-read", "bounded_synthetic_read", ex))
	if ev.Result != dbsim.ResultError {
		t.Fatalf("result %s", ev.Result)
	}
	if !strings.Contains(ev.Record.Limitations, "safety incident") {
		t.Fatalf("limitations %q", ev.Record.Limitations)
	}
}

func TestPipeline_FakeAgentFakeConnector_RedactionAndMinimisation(t *testing.T) {
	stmt := "/* dbsim:" + pMarker + " */ SELECT * FROM t WHERE x='a' -- password=hunter2 Bearer abc.def.ghi " + strings.Repeat("Z", 4000)
	al := elasticLikeAlert("al1", pT0.Add(5*time.Second), stmt)
	var many []detectverify.MatchedAlert
	for i := 0; i < 30; i++ {
		many = append(many, elasticLikeAlert(fmt.Sprintf("al%d", i), pT0.Add(time.Duration(i+1)*time.Second), stmt))
	}
	many[0] = al
	ex := okExec(10, "token=sekrit9 in a note")
	ev := mustEval(t, &fakeConn{reply: alertsReply(many...)}, input("dbsim-db05-suspicious-read", "suspicious_read", ex))
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, bad := range []string{"hunter2", "sekrit9", "abc.def.ghi", `"raw"`, strings.Repeat("Z", 600)} {
		if strings.Contains(s, bad) {
			t.Errorf("%.20q survived into the evaluation", bad)
		}
	}
	refs := ev.Outcome.Corr.AlertRefs
	if len(refs) == 0 || len(refs) > dbsim.MaxAlertRefs {
		t.Fatalf("alert refs %d", len(refs))
	}
	for _, r := range refs {
		if len(r.Excerpt) > dbsim.MaxAlertExcerptBytes || r.ID == "" {
			t.Fatalf("ref %+v", r)
		}
	}
	if !strings.Contains(refs[0].Excerpt, pMarker) {
		t.Fatalf("excerpt lost the marker: %q", refs[0].Excerpt)
	}
}

func TestPipeline_FakeAgentFakeConnector_AgentOutputIsBounded(t *testing.T) {
	notes := make([]string, 1000)
	for i := range notes {
		notes[i] = "k=" + strings.Repeat("v", 5000)
	}
	var evs []dbsim.DBProbeAuditEvent
	for i := 0; i < 500; i++ {
		evs = append(evs, dbsim.DBProbeAuditEvent{Time: pT0, Statement: strings.Repeat("S", 100000) + pMarker})
	}
	ex := AgentExec{DBProbe: &dbsim.DBProbeResult{RowsRead: 1, DBTime: pT0, Notes: notes, AuditStatus: dbsim.AuditFound, AuditEvents: evs}}
	ev := mustEval(t, &fakeConn{reply: alertsReply()}, input("dbsim-db04-audit-coverage", "read_roles", ex))
	if len(ev.Outcome.Probe.Notes) > 64 || len(ev.Outcome.Probe.AuditEvents) > 50 {
		t.Fatalf("unbounded: %d notes %d events", len(ev.Outcome.Probe.Notes), len(ev.Outcome.Probe.AuditEvents))
	}
	for _, n := range ev.Outcome.Probe.Notes {
		if len(n) > 1024 {
			t.Fatalf("note %d bytes", len(n))
		}
	}
	// the marker is beyond the first 512 bytes of every statement, so it is not
	// evidence: found without a visible marker event must not pass
	if ev.Result == dbsim.ResultPass {
		t.Fatal("unbounded audit statements credited")
	}
}

func TestPipeline_FakeAgentFakeConnector_AgentExecClassification(t *testing.T) {
	mk := func(class string, mut func(*AgentExec)) AgentExec {
		ex := AgentExec{DBProbe: &dbsim.DBProbeResult{ErrorClass: class, Notes: []string{"reason text"}, AgentTime: pT0}}
		if mut != nil {
			mut(&ex)
		}
		return ex
	}
	cases := []struct {
		name string
		ex   AgentExec
		want dbsim.RunResult
	}{
		{"gate refused", mk("gate_refused", nil), dbsim.ResultSkipped},
		{"credential unresolved", mk("credential_unresolved", nil), dbsim.ResultSkipped},
		{"adapter unsupported", mk("adapter_unsupported", nil), dbsim.ResultSkipped},
		{"identity mismatch", mk("identity_error", nil), dbsim.ResultSkipped},
		{"connect error", mk("connect_error", nil), dbsim.ResultError},
		{"fixture error", mk("fixture_error", nil), dbsim.ResultError},
		{"timeout", mk("timeout", nil), dbsim.ResultError},
		{"cancelled", mk("cancelled", nil), dbsim.ResultError},
		{"probe error", mk("probe_error", nil), dbsim.ResultError},
		{"cleanup incident", mk("cleanup_incident", func(e *AgentExec) { e.DBProbe.SafetyIncident = true }), dbsim.ResultError},
		{"no dbprobe result", AgentExec{ExitCode: -1, Stderr: "boom"}, dbsim.ResultError},
		{"vetoed by agent", AgentExec{Vetoed: true, VetoedBlockSource: "dbsim_gate", ExitCode: -1, Stderr: "dbprobe refused: x"}, dbsim.ResultSkipped},
	}
	for _, c := range cases {
		c2 := &fakeConn{reply: alertsReply()}
		ev := mustEval(t, c2, input("dbsim-db05-suspicious-read", "suspicious_read", c.ex))
		if ev.Result != c.want {
			t.Errorf("%s: result %s want %s (%s)", c.name, ev.Result, c.want, ev.Report.Reason)
		}
		if c2.calls != 0 {
			t.Errorf("%s: SIEM queried although the probe did not complete", c.name)
		}
	}
}

func TestPipeline_FakeAgentFakeConnector_DeniedProbeIsPrevention(t *testing.T) {
	ex := AgentExec{DBProbe: &dbsim.DBProbeResult{Denied: true, ErrorClass: "permission_denied", DBTime: pT0, AgentTime: pT0}}
	alert := elasticLikeAlert("al1", pT0.Add(3*time.Second), realStmt(pMarker))
	ev := mustEval(t, &fakeConn{reply: alertsReply(alert)}, input("dbsim-db03-unauthorized-access", "read_restricted_table", ex))
	if ev.Record.Enforcement != dlpreport.EnforcementBlocked || ev.Result != dbsim.ResultPass {
		t.Fatalf("enforcement %s result %s (%s)", ev.Record.Enforcement, ev.Result, ev.Report.Reason)
	}
	// the same read succeeding is a prevention failure even though it was alerted
	ev2 := mustEval(t, &fakeConn{reply: alertsReply(alert)}, input("dbsim-db03-unauthorized-access", "read_restricted_table", okExec(3)))
	if ev2.Result != dbsim.ResultFail || ev2.Report.Dimensions.Detection != dbsim.DimPass {
		t.Fatalf("result %s detection %s", ev2.Result, ev2.Report.Dimensions.Detection)
	}
}

func TestPipeline_FakeAgentFakeConnector_ObservationsComeFromOneParser(t *testing.T) {
	ex := okExec(7, "shape=bulk_select_capped", "rows_read=5", "bytes_read=2048", "truncated=true", "row_cap_applied=5", "duration_ms=31")
	ev := mustEval(t, &fakeConn{reply: alertsReply()}, input("dbsim-db09-bounded-bulk-read", "bounded_synthetic_read", ex))
	o := ev.Observations
	if o.Shape != "bulk_select_capped" || o.RowsRead != 7 || o.NoteRowsRead != 5 || o.BytesRead != 2048 || !o.Truncated || o.RowCapApplied != 5 || o.DurationMs != 31 {
		t.Fatalf("observations %+v", o)
	}
	if !o.RowsDisagree {
		t.Fatal("the typed RowsRead=7 and the note rows_read=5 disagree; that must be flagged")
	}
	if !strings.Contains(ev.Record.Limitations, "disagree") {
		t.Fatalf("limitations %q", ev.Record.Limitations)
	}
}

func TestPipeline_FakeAgentFakeConnector_InvalidInputIsAnError(t *testing.T) {
	in := input("dbsim-db05-suspicious-read", "suspicious_read", okExec(1))
	in.Spec.Marker = ""
	if _, err := Evaluate(context.Background(), &fakeConn{reply: alertsReply()}, in); err == nil {
		t.Fatal("empty marker accepted")
	}
	in = input("dbsim-db05-suspicious-read", "suspicious_read", okExec(1))
	in.Window = 0
	if _, err := Evaluate(context.Background(), &fakeConn{reply: alertsReply()}, in); err == nil {
		t.Fatal("zero window accepted")
	}
}
