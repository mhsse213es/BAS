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
