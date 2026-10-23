package dbrun

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/dlpreport"
)

const classRule = "BAS dbsim classified-fixture read"

var errTest = errors.New("elastic: connection refused")

func ruleAlert(id, rule string, at time.Time, statement string) detectverify.MatchedAlert {
	a := elasticLikeAlert(id, at, statement)
	a.RuleName = rule
	return a
}

func genericAlert(at time.Time) detectverify.MatchedAlert {
	return ruleAlert("gen1", dbsim.GenericMarkerRuleName, at, realStmt(pMarker))
}

func classAlert(at time.Time) detectverify.MatchedAlert {
	return ruleAlert("cls1", classRule, at, realStmt(pMarker))
}

func db07Input(ruleName string) StepInput {
	in := input("dbsim-db07-sensitive-classification", "read_classified_fixture", okExec(6, "shape=wide_select", "rows_read=6"))
	in.ClassificationRuleName = ruleName
	return in
}

func TestClassificationOutcomeCorrectWhenRuleFires(t *testing.T) {
	c := &fakeConn{reply: alertsReply(genericAlert(pT0.Add(10*time.Second)), classAlert(pT0.Add(12*time.Second)))}
	ev := mustEval(t, c, db07Input(classRule))
	if ev.Record.Classification != dlpreport.ClassificationCorrect {
		t.Fatalf("classification %s (%s)", ev.Record.Classification, ev.Record.Limitations)
	}
	if ev.Result != dbsim.ResultPass || ev.Report.Dimensions.Classification != dbsim.DimPass {
		t.Fatalf("result %s %+v (%s)", ev.Result, ev.Report.Dimensions, ev.Report.Reason)
	}
	if ev.Record.Telemetry != dlpreport.TelemetryPresent {
		t.Fatalf("telemetry %s", ev.Record.Telemetry)
	}
}

func TestClassificationOutcomeIncorrectWhenRuleSilent(t *testing.T) {
	// The read was allowed and the SIEM provably saw the statement (the generic
	// marker rule fired) but the classification rule did not.
	c := &fakeConn{reply: alertsReply(genericAlert(pT0.Add(10 * time.Second)))}
	ev := mustEval(t, c, db07Input(classRule))
	if ev.Record.Classification != dlpreport.ClassificationIncorrect {
		t.Fatalf("classification %s", ev.Record.Classification)
	}
	if ev.Result != dbsim.ResultFail || ev.Report.Dimensions.Classification != dbsim.DimFail {
		t.Fatalf("a silent classification rule is a control failure: %s %+v", ev.Result, ev.Report.Dimensions)
	}
	if !strings.Contains(ev.Record.Limitations, "classification rule") {
		t.Fatalf("limitation should say why: %q", ev.Record.Limitations)
	}
}

func TestClassificationOutcomeNotEvaluatedWhenNoRuleConfigured(t *testing.T) {
	c := &fakeConn{reply: alertsReply(genericAlert(pT0.Add(10*time.Second)), classAlert(pT0.Add(12*time.Second)))}
	ev := mustEval(t, c, db07Input(""))
	if ev.Record.Classification != dlpreport.ClassificationNotEvaluated {
		t.Fatalf("classification %s", ev.Record.Classification)
	}
	if ev.Result == dbsim.ResultPass {
		t.Fatal("DB-07 must never pass without a classification verdict (it would be a rename of DB-05)")
	}
	if !strings.Contains(ev.Record.Limitations, "no classification rule is configured") {
		t.Fatalf("limitation missing: %q", ev.Record.Limitations)
	}
	if strings.Contains(ev.Record.Limitations, "does not classify data") {
		t.Fatalf("misleading limitation for a classification scenario: %q", ev.Record.Limitations)
	}
}

func TestClassificationOutcomeUnknownWhenTelemetryUnverifiable(t *testing.T) {
	for name, in := range map[string]struct {
		conn *fakeConn
	}{
		"no alerts at all":   {&fakeConn{reply: alertsReply()}},
		"unattributed alert": {&fakeConn{reply: alertsReply(ruleAlert("u1", classRule, pT0.Add(5*time.Second), "SELECT 1 elsewhere"))}},
		"connector failure": {&fakeConn{reply: func(detectverify.VerifyRequest) (detectverify.VerifyResult, error) {
			return detectverify.VerifyResult{}, errTest
		}}},
		"other runs' marker": {&fakeConn{reply: alertsReply(ruleAlert("o1", classRule, pT0.Add(5*time.Second), realStmt("bas-dbsim:fedcba9876543210fedcba98")))}},
	} {
		ev := mustEval(t, in.conn, db07Input(classRule))
		if ev.Record.Classification != dlpreport.ClassificationUnknown {
			t.Errorf("%s: classification %s, want unknown (missing evidence is never Incorrect)", name, ev.Record.Classification)
		}
		if ev.Result == dbsim.ResultPass {
			t.Errorf("%s: passed", name)
		}
	}
	// No connector at all.
	ev := mustEval(t, nil, db07Input(classRule))
	if ev.Record.Classification != dlpreport.ClassificationUnknown || ev.Result == dbsim.ResultPass {
		t.Fatalf("nil connector: %s %s", ev.Record.Classification, ev.Result)
	}
}

func TestClassificationOutcomeGenericMarkerAlertDoesNotCountAsClassification(t *testing.T) {
	// Only the generic rule fired. Even if the configured "classification" rule
	// IS the generic rule, nothing counts: DB-07 would be a rename of DB-05.
	c := &fakeConn{reply: alertsReply(genericAlert(pT0.Add(10 * time.Second)))}
	ev := mustEval(t, c, db07Input(dbsim.GenericMarkerRuleName))
	if ev.Record.Classification == dlpreport.ClassificationCorrect || ev.Result == dbsim.ResultPass {
		t.Fatalf("a generic marker alert was credited as classification: %s %s", ev.Record.Classification, ev.Result)
	}
	if ev.Record.Classification != dlpreport.ClassificationNotEvaluated {
		t.Fatalf("misconfiguration must be NotEvaluated, got %s", ev.Record.Classification)
	}
	// With a real rule name configured and only the generic alert: Incorrect, not Correct.
	ev = mustEval(t, &fakeConn{reply: alertsReply(genericAlert(pT0.Add(10 * time.Second)))}, db07Input(classRule))
	if ev.Record.Classification != dlpreport.ClassificationIncorrect {
		t.Fatalf("got %s", ev.Record.Classification)
	}
}

func TestClassificationNotAttemptedForOtherProbesOrDeniedReads(t *testing.T) {
	// Another probe never gets a classification verdict, whatever the input says.
	in := input("dbsim-db05-suspicious-read", "suspicious_read", okExec(10))
	in.ClassificationRuleName = classRule
	ev := mustEval(t, &fakeConn{reply: alertsReply(classAlert(pT0.Add(5 * time.Second)))}, in)
	if ev.Record.Classification != dlpreport.ClassificationNotEvaluated {
		t.Fatalf("suspicious_read classified: %s", ev.Record.Classification)
	}
	// A denied read: nothing was read, so nothing was classified.
	den := db07Input(classRule)
	den.Exec = AgentExec{DBProbe: &dbsim.DBProbeResult{Denied: true, ErrorClass: "permission_denied", DBTime: pT0, AgentTime: pT0}}
	ev = mustEval(t, &fakeConn{reply: alertsReply(genericAlert(pT0.Add(5 * time.Second)))}, den)
	if ev.Record.Classification != dlpreport.ClassificationNotEvaluated || ev.Result == dbsim.ResultPass {
		t.Fatalf("denied read: %s %s", ev.Record.Classification, ev.Result)
	}
}

// F2: a classification alert that is only strong-contextual is set aside behind
// the exact generic alert by the correlator; its silence must not read as Incorrect.
func TestClassificationOutcomeUnknownWhenStrongAlertsWereSetAside(t *testing.T) {
	strong := ruleAlert("s1", classRule, pT0.Add(11*time.Second), "dbsim_lab bas-dbsim-run:1111 read customers_pii")
	c := &fakeConn{reply: alertsReply(genericAlert(pT0.Add(10*time.Second)), strong)}
	ev := mustEval(t, c, db07Input(classRule))
	if ev.Correlation == nil || ev.Correlation.StrongDropped != 1 {
		t.Fatalf("correlator did not report the set-aside strong alert: %+v", ev.Correlation)
	}
	if ev.Record.Classification != dlpreport.ClassificationUnknown {
		t.Fatalf("classification %s, want unknown", ev.Record.Classification)
	}
}

// M1: a fixture-gated probe whose cleanup is not positively verified is
// incident-equivalent in Evaluate: no correlation, no classification verdict.
func TestEvaluateUnverifiedCleanupCarriesNoClassificationVerdict(t *testing.T) {
	for _, st := range []string{"", dbsim.CleanupNotApplicable} {
		ex := okExec(6, "shape=wide_select", "rows_read=6")
		ex.DBProbe.CleanupStatus = st
		in := db07Input(classRule)
		in.Exec = ex
		c := &fakeConn{reply: alertsReply(genericAlert(pT0.Add(10*time.Second)), classAlert(pT0.Add(12*time.Second)))}
		ev := mustEval(t, c, in)
		if ev.Correlation != nil {
			t.Errorf("cleanup %q: SIEM correlation ran for an unverified-cleanup run", st)
		}
		if cl := ev.Record.Classification; cl == dlpreport.ClassificationCorrect || cl == dlpreport.ClassificationIncorrect {
			t.Errorf("cleanup %q: classification verdict %s next to an ERROR grade", st, cl)
		}
		if ev.Result != dbsim.ResultError {
			t.Errorf("cleanup %q: result %s", st, ev.Result)
		}
	}
}

func TestEvaluateOkCleanupAndNonFixtureProbesUnchanged(t *testing.T) {
	c := &fakeConn{reply: alertsReply(genericAlert(pT0.Add(10*time.Second)), classAlert(pT0.Add(12*time.Second)))}
	if ev := mustEval(t, c, db07Input(classRule)); ev.Result != dbsim.ResultPass {
		t.Fatalf("DB-07 ok cleanup: %s", ev.Result)
	}
	ex := okExec(3)
	ex.DBProbe.CleanupStatus = ""
	ev := mustEval(t, &fakeConn{reply: alertsReply()}, input("dbsim-db01-role-enumeration", "read_roles", ex))
	if ev.Result == dbsim.ResultError {
		t.Fatalf("non-fixture probe with empty cleanup must not be ERROR: %s (%s)", ev.Result, ev.Report.Reason)
	}
}

// M2: exactly one "Classification not evaluated" sentence through Evaluate.
func TestEvaluateClassificationNotEvaluatedSentenceAppearsOnce(t *testing.T) {
	denied := db07Input(classRule)
	denied.Exec.DBProbe.Denied = true
	for name, in := range map[string]StepInput{
		"empty rule":   db07Input(""),
		"generic rule": db07Input(dbsim.GenericMarkerRuleName),
		"denied read":  denied,
	} {
		ev := mustEval(t, &fakeConn{reply: alertsReply(genericAlert(pT0.Add(10 * time.Second)))}, in)
		if n := strings.Count(strings.ToLower(ev.Record.Limitations), "classification not evaluated"); n != 1 {
			t.Errorf("%s: %d sentences in %q", name, n, ev.Record.Limitations)
		}
	}
}

// Live run 1: a B5 veto has empty stderr; the refusal text must still say which
// signed class the agent refused, never "agent veto (catalog): ".
func TestAgentVetoReasonNamesTheSignedExecutionClass(t *testing.T) {
	ex := AgentExec{ExitCode: -1, Vetoed: true, VetoedBlockSource: "catalog", VetoedActionKey: "dbprobe_mutation", VetoedExecutionClass: "destructive"}
	ev := mustEval(t, nil, input("dbsim-db06-account-revocation", "auth_after_revoke", ex))
	for _, want := range []string{"agent veto (catalog)", `"destructive"`, `"dbprobe_mutation"`} {
		if !strings.Contains(ev.Report.Reason, want) {
			t.Errorf("reason %q lacks %s", ev.Report.Reason, want)
		}
	}
	if ev.Result != dbsim.ResultSkipped {
		t.Errorf("result %s", ev.Result)
	}
}
