package dbrun

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dlpreport"
)

const stepsDenied = "revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=denied"

func revokeExec(denied bool, class, steps string) AgentExec {
	notes := []string{}
	if steps != "" {
		notes = append(notes, steps)
	}
	return AgentExec{DBProbe: &dbsim.DBProbeResult{Denied: denied, ErrorClass: class, DBTime: pT0, AgentTime: pT0, Notes: notes,
		CleanupStatus: dbsim.CleanupOK}}
}

func TestRevocationPipelinePassNeedsBaselineDenialAndCleanup(t *testing.T) {
	c := &fakeConn{reply: alertsReply()}
	ev := mustEval(t, c, input("dbsim-db06-account-revocation", "auth_after_revoke", revokeExec(true, "auth_failed", stepsDenied)))
	if ev.Result != dbsim.ResultPass || ev.Record.Enforcement != dlpreport.EnforcementBlocked {
		t.Fatalf("result %s enforcement %s (%s)", ev.Result, ev.Record.Enforcement, ev.Report.Reason)
	}
	// Telemetry honesty: never queried, never claimed.
	if c.calls != 0 {
		t.Fatalf("a SIEM lookup was made for a failed-login probe: %d", c.calls)
	}
	if ev.Record.Telemetry != dlpreport.TelemetryUnverifiable || ev.Record.Response != dlpreport.ResponseNotTested {
		t.Fatalf("telemetry %s response %s", ev.Record.Telemetry, ev.Record.Response)
	}
	if !strings.Contains(ev.Record.Limitations, "failed login has no SQL statement") {
		t.Fatalf("limitation sentence missing: %q", ev.Record.Limitations)
	}
}

// Even a scenario meta that (wrongly) expects detection and response cannot make
// DB-06 claim them, and never reaches the SIEM.
func TestRevocationPipelineIgnoresDetectionExpectation(t *testing.T) {
	in := input("dbsim-db06-account-revocation", "auth_after_revoke", revokeExec(true, "auth_failed", stepsDenied))
	in.Scenario.ExpectDetection, in.Scenario.ExpectResponse = true, true
	c := &fakeConn{reply: alertsReply(elasticLikeAlert("a", pT0.Add(time.Second), realStmt(pMarker)))}
	ev := mustEval(t, c, in)
	if c.calls != 0 || ev.Record.Telemetry == dlpreport.TelemetryPresent || ev.Record.Response == dlpreport.ResponseAlerted {
		t.Fatalf("calls %d telemetry %s response %s", c.calls, ev.Record.Telemetry, ev.Record.Response)
	}
}

func TestRevocationPipelineEveryNonDenialIsNotAPass(t *testing.T) {
	for name, c := range map[string]struct {
		ex   AgentExec
		want dbsim.RunResult
	}{
		"baseline failed":  {revokeExec(false, "baseline_failed", "revoke_steps=create=ok,baseline=failed,revoke=skipped,reconnect=skipped"), dbsim.ResultError},
		"revoke failed":    {revokeExec(false, "revoke_failed", "revoke_steps=create=ok,baseline=ok,revoke=failed,reconnect=skipped"), dbsim.ResultError},
		"reconnect error":  {revokeExec(false, "reconnect_error", "revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=error"), dbsim.ResultError},
		"still connects":   {revokeExec(false, "", "revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=connected"), dbsim.ResultFail},
		"denial, no steps": {revokeExec(true, "auth_failed", ""), dbsim.ResultError},
		"leftover account": {AgentExec{DBProbe: &dbsim.DBProbeResult{Denied: true, ErrorClass: "auth_failed", DBTime: pT0, AgentTime: pT0,
			Notes: []string{stepsDenied}, CleanupStatus: dbsim.CleanupResidual, SafetyIncident: true}}, dbsim.ResultError},
	} {
		ev := mustEval(t, &fakeConn{reply: alertsReply()}, input("dbsim-db06-account-revocation", "auth_after_revoke", c.ex))
		if ev.Result != c.want {
			t.Errorf("%s: %s (%s), want %s", name, ev.Result, ev.Report.Reason, c.want)
		}
	}
}

func TestRevocationPipelineNeverLeaksAPassword(t *testing.T) {
	ex := revokeExec(true, "auth_failed", stepsDenied)
	ex.DBProbe.Notes = append(ex.DBProbe.Notes, "revoke_detail: baseline: connection failed password=hunter2xyz")
	ev := mustEval(t, &fakeConn{reply: alertsReply()}, input("dbsim-db06-account-revocation", "auth_after_revoke", ex))
	b, _ := json.Marshal(ev)
	if strings.Contains(string(b), "hunter2xyz") {
		t.Fatal("a secret in an agent note survived into the evaluation")
	}
}
