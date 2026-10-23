package dbrun

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dlpreport"
)

const (
	t15Tamper = "audit_tamper_steps=create=ok,baseline=ok,attempt=denied"
	t15Write  = "write_attempt_steps=insert=denied,update=denied,delete=denied,fingerprint=unchanged"
	t15Export = "export_checks=file_write=no,program_exec=no,file_read=no,bulk_select=no,dump_privs=12"
)

func t15Exec(denied bool, class string, notes ...string) AgentExec {
	return AgentExec{DBProbe: &dbsim.DBProbeResult{Denied: denied, ErrorClass: class, DBTime: pT0, AgentTime: pT0, Notes: notes,
		CleanupStatus: dbsim.CleanupOK}}
}

func tamperStmt(marker string) string {
	return "LOG:  statement: /* dbsim:" + marker + " */ SET log_statement = 'none'"
}

func TestTask15PipelineDB08PassNeedsDenialBaselineCleanupAndMarkerAlert(t *testing.T) {
	c := &fakeConn{reply: alertsReply(elasticLikeAlert("a1", pT0.Add(5*time.Second), tamperStmt(pMarker)))}
	ev := mustEval(t, c, input("dbsim-db08-audit-tamper-resistance", "try_disable_audit", t15Exec(true, "permission_denied", t15Tamper)))
	if ev.Result != dbsim.ResultPass || ev.Record.Enforcement != dlpreport.EnforcementBlocked ||
		ev.Record.Telemetry != dlpreport.TelemetryPresent || ev.Record.Response != dlpreport.ResponseAlerted {
		t.Fatalf("result %s enforcement %s telemetry %s response %s (%s)", ev.Result, ev.Record.Enforcement, ev.Record.Telemetry, ev.Record.Response, ev.Report.Reason)
	}
	if c.calls == 0 {
		t.Fatal("DB-08 grades detection like DB-03: the SIEM must be asked")
	}
	if !strings.Contains(ev.Record.Limitations, "session-scoped") {
		t.Fatalf("limitations: %q", ev.Record.Limitations)
	}
	// Not a pass without the marker alert, or with an unverified cleanup.
	ev = mustEval(t, nil, input("dbsim-db08-audit-tamper-resistance", "try_disable_audit", t15Exec(true, "permission_denied", t15Tamper)))
	if ev.Result != dbsim.ResultError {
		t.Fatalf("no connector must be ERROR, got %s", ev.Result)
	}
	bad := t15Exec(true, "permission_denied", t15Tamper)
	bad.DBProbe.CleanupStatus = dbsim.CleanupNotApplicable
	c2 := &fakeConn{reply: alertsReply(elasticLikeAlert("a1", pT0.Add(5*time.Second), tamperStmt(pMarker)))}
	ev = mustEval(t, c2, input("dbsim-db08-audit-tamper-resistance", "try_disable_audit", bad))
	if ev.Result != dbsim.ResultError || c2.calls != 0 {
		t.Fatalf("an unverified cleanup is ERROR and is not correlated: %s calls=%d", ev.Result, c2.calls)
	}
}

func TestTask15PipelineDB08EveryNonDenialIsNotAPass(t *testing.T) {
	for name, c := range map[string]struct {
		ex   AgentExec
		want dbsim.RunResult
	}{
		"allowed":          {t15Exec(false, "", "audit_tamper_steps=create=ok,baseline=ok,attempt=allowed"), dbsim.ResultFail},
		"attempt error":    {t15Exec(false, "attempt_error", "audit_tamper_steps=create=ok,baseline=ok,attempt=error"), dbsim.ResultError},
		"baseline failed":  {t15Exec(false, "baseline_failed", "audit_tamper_steps=create=ok,baseline=failed,attempt=skipped"), dbsim.ResultError},
		"denial, no steps": {t15Exec(true, "permission_denied"), dbsim.ResultError},
		"leftover account": {AgentExec{DBProbe: &dbsim.DBProbeResult{Denied: true, ErrorClass: "permission_denied", DBTime: pT0, AgentTime: pT0,
			Notes: []string{t15Tamper}, CleanupStatus: dbsim.CleanupResidual, SafetyIncident: true}}, dbsim.ResultError},
	} {
		ev := mustEval(t, &fakeConn{reply: alertsReply()}, input("dbsim-db08-audit-tamper-resistance", "try_disable_audit", c.ex))
		if ev.Result != c.want {
			t.Errorf("%s: %s (%s), want %s", name, ev.Result, ev.Report.Reason, c.want)
		}
	}
}

func TestTask15PipelineDB10(t *testing.T) {
	stmt := "execute: /* dbsim:" + pMarker + " */ INSERT INTO \"dbsim_x\".\"accounts\" (id) VALUES (9001)"
	c := &fakeConn{reply: alertsReply(elasticLikeAlert("w1", pT0.Add(4*time.Second), stmt))}
	ev := mustEval(t, c, input("dbsim-db10-write-delete-prevention", "try_write_fixture", t15Exec(true, "permission_denied", t15Write)))
	if ev.Result != dbsim.ResultPass || ev.Record.Enforcement != dlpreport.EnforcementBlocked {
		t.Fatalf("result %s enforcement %s (%s)", ev.Result, ev.Record.Enforcement, ev.Report.Reason)
	}
	// A permitted write is a FAIL that reports the dirty fixture.
	ev = mustEval(t, &fakeConn{reply: alertsReply()}, input("dbsim-db10-write-delete-prevention", "try_write_fixture",
		t15Exec(false, "", "write_attempt_steps=insert=allowed,update=denied,delete=denied,fingerprint=changed", "fixture_changed=true")))
	if ev.Result != dbsim.ResultFail || ev.Record.Enforcement != dlpreport.EnforcementAllowed || !strings.Contains(ev.Record.Limitations, "fixture was changed") {
		t.Fatalf("result %s enforcement %s limitations %q", ev.Result, ev.Record.Enforcement, ev.Record.Limitations)
	}
	// All denied but the table moved: ERROR, never PASS.
	ev = mustEval(t, &fakeConn{reply: alertsReply()}, input("dbsim-db10-write-delete-prevention", "try_write_fixture",
		t15Exec(false, "fixture_state_inconsistent", "write_attempt_steps=insert=denied,update=denied,delete=denied,fingerprint=changed")))
	if ev.Result != dbsim.ResultError {
		t.Fatalf("inconsistent fixture state must be ERROR, got %s", ev.Result)
	}
}

func TestTask15PipelineDB11(t *testing.T) {
	// No privilege held and all observed: PASS, with no SIEM lookup and no
	// telemetry claim, even when the caller's scenario (wrongly) expects detection.
	in := input("dbsim-db11-backup-export-permissions", "check_export_privileges", t15Exec(true, "", t15Export))
	in.Scenario.ExpectDetection, in.Scenario.ExpectResponse = true, true
	c := &fakeConn{reply: alertsReply(elasticLikeAlert("a", pT0.Add(time.Second), realStmt(pMarker)))}
	ev := mustEval(t, c, in)
	if ev.Result != dbsim.ResultPass || ev.Record.Enforcement != dlpreport.EnforcementBlocked {
		t.Fatalf("result %s enforcement %s (%s)", ev.Result, ev.Record.Enforcement, ev.Report.Reason)
	}
	if c.calls != 0 || ev.Record.Telemetry == dlpreport.TelemetryPresent || ev.Record.Response != dlpreport.ResponseNotTested {
		t.Fatalf("calls %d telemetry %s response %s", c.calls, ev.Record.Telemetry, ev.Record.Response)
	}
	// The expectation is intrinsic: a caller meta saying "allow" cannot turn a
	// held privilege into a pass.
	in = input("dbsim-db11-backup-export-permissions", "check_export_privileges",
		t15Exec(false, "", "export_checks=file_write=yes,program_exec=no,file_read=no,bulk_select=no,dump_privs=3"))
	in.Scenario.ExpectedPrevention = "allow"
	if ev := mustEval(t, nil, in); ev.Result != dbsim.ResultFail || ev.Record.Enforcement != dlpreport.EnforcementAllowed {
		t.Fatalf("held privilege: %s %s", ev.Result, ev.Record.Enforcement)
	}
	for name, ex := range map[string]AgentExec{
		"unobservable": t15Exec(false, "export_check_incomplete", "export_checks=file_write=no,program_exec=no,file_read=unknown,bulk_select=no,dump_privs=3"),
		"no note":      t15Exec(true, ""),
	} {
		ev := mustEval(t, nil, input("dbsim-db11-backup-export-permissions", "check_export_privileges", ex))
		if ev.Result != dbsim.ResultError {
			t.Errorf("%s: %s, want ERROR", name, ev.Result)
		}
	}
	if !strings.Contains(ev.Record.Limitations, "controlled operation") && !strings.Contains(mustEval(t, nil, input("dbsim-db11-backup-export-permissions", "check_export_privileges", t15Exec(true, "", t15Export))).Record.Limitations, "controlled operation") {
		t.Fatal("the not-built controlled-operation mode must be stated")
	}
}

func TestTask15PipelineNeverLeaksAPassword(t *testing.T) {
	ex := t15Exec(true, "permission_denied", t15Tamper, "tamper_detail: baseline: dial failed password=hunter2hunter2 host=x")
	ev := mustEval(t, &fakeConn{reply: alertsReply()}, input("dbsim-db08-audit-tamper-resistance", "try_disable_audit", ex))
	b, _ := json.Marshal(ev.Report)
	if strings.Contains(string(b), "hunter2hunter2") {
		t.Fatalf("password in report: %s", b)
	}
}
