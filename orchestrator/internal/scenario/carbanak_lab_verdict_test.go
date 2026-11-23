package scenario

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

// Carbanak Task 6 combined-verdict check. These are the BAS-FRAUD-CONTROL lines the Windows lab endpoint
// printed on 2026-11-23 against the live ledger (copied verbatim). Each goes through the same parser and scoring
// path the orchestrator uses, with endpoint results PASS and FAIL, to check the runbook's table.
var labFraudLines = map[string]struct {
	line, wantFraud string
}{
	"8a": {`BAS-FRAUD-CONTROL {"ledger_decision":"approved","step":"8a","expected_control":"evidence","rule_fired":"","audit_hash":"1c87bfc284616b6119dea214cab645d2cfbdc37798eefd6c0937ff7f691677f5","ledger_called":true}`, "SKIPPED"},
	"8b": {`BAS-FRAUD-CONTROL {"ledger_decision":"rejected","step":"8b","expected_control":"prevent","rule_fired":"beneficiary_second_approver_missing","audit_hash":"59554135734580a1bbf2bb2872372e444796c46b51b2f1b6f7621d405a4e1cb3","ledger_called":true}`, "PASS"},
	"8c": {`BAS-FRAUD-CONTROL {"ledger_decision":"flagged","step":"8c","expected_control":"detect","rule_fired":"amount_over_limit","audit_hash":"e0e4c6676cf6ddfd829b5f68c6066b7ff1435f47a611e42f0662341a31b3e177","ledger_called":true}`, "PASS"},
	"8d": {`BAS-FRAUD-CONTROL {"ledger_decision":"rejected","step":"8d","expected_control":"prevent","rule_fired":"maker_checker_self_approval","audit_hash":"df917c4be0e44eca7765b96c010aa22499df4924cc604a0d1947ff7aa430c03c","ledger_called":true}`, "PASS"},
	"8e": {`BAS-FRAUD-CONTROL {"ledger_decision":"rejected","step":"8e","expected_control":"prevent","rule_fired":"approver_role_missing","audit_hash":"3135c09cbe58a48317abd75bc713382bc793ea53b641d122e8db310fd3d96040","ledger_called":true}`, "PASS"},
	"8f": {`BAS-FRAUD-CONTROL {"step":"8f","audit_intact":true,"expected_control":"verify","ledger_called":true}`, "PASS"},
	"8g": {`BAS-FRAUD-CONTROL {"step":"8g","alert_present":true,"expected_control":"detect","ledger_decision":"rejected","ledger_called":true}`, "PASS"},
	"24": {`BAS-FRAUD-CONTROL {"ledger_decision":"flagged","step":"24","expected_control":"detect","rule_fired":"amount_over_limit","audit_hash":"9dcf9ae198f294356eed98f56546b86da73a5e10fb95090d7813ad8d9cf015b5","ledger_called":true}`, "PASS"},
	"27": {`BAS-FRAUD-CONTROL {"ledger_decision":"flagged","step":"27","expected_control":"detect","rule_fired":"outside_operating_window","audit_hash":"1709ffa293a1b31ebbaa790e1ad4811ff62c441dcaab84726075f2876fbc3a54","ledger_called":true}`, "PASS"},
}

func TestCarbanakLabCombinedVerdicts(t *testing.T) {
	for step, c := range labFraudLines {
		rec, ok := ParseFraudControl(c.line)
		if !ok {
			t.Fatalf("step %s: lab marker did not parse", step)
		}
		if rec.Verdict != c.wantFraud {
			t.Errorf("step %s: fraud verdict %s, want %s", step, rec.Verdict, c.wantFraud)
		}
		// Endpoint PASS: the combined result must follow the runbook table.
		pass := models.SimulationResult{Result: models.ResultPass, FraudControl: rec}
		models.ApplyFraudControl(&pass)
		wantPass := map[string]models.CheckResult{"PASS": models.ResultPass, "SKIPPED": models.ResultSkipped}[c.wantFraud]
		if pass.Result != wantPass {
			t.Errorf("step %s, endpoint PASS: combined %s, want %s", step, pass.Result, wantPass)
		}
		// Endpoint FAIL: the combined result must be FAIL, whatever the fraud verdict.
		fail := models.SimulationResult{Result: models.ResultFail, FraudControl: rec}
		models.ApplyFraudControl(&fail)
		if fail.Result != models.ResultFail {
			t.Errorf("step %s, endpoint FAIL: combined %s, want FAIL", step, fail.Result)
		}
	}
}
