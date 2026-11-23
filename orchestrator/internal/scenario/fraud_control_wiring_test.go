package scenario

import "testing"

func TestInterpretAttachesFraudControlFromMarker(t *testing.T) {
	step := Step{Name: "Carbanak Stage 8b -- test", TechniqueID: "T1098"}
	res := ExecResult{
		ExitCode: 0,
		Stdout:   "BAS-FRAUD-CONTROL {\"step\":\"8b\",\"expected_control\":\"prevent\",\"ledger_called\":true,\"ledger_decision\":\"rejected\",\"rule_fired\":\"beneficiary_second_approver_missing\"}\n",
	}
	got := Interpret(step, res)
	if got.FraudControl == nil {
		t.Fatal("FraudControl not attached to the step result")
	}
	if got.FraudControl.Verdict != "PASS" {
		t.Fatalf("fraud verdict = %q, want PASS", got.FraudControl.Verdict)
	}
}

func TestInterpretLeavesFraudControlNilWithoutMarker(t *testing.T) {
	step := Step{Name: "Carbanak Stage 1 -- test", TechniqueID: "T1566.001"}
	got := Interpret(step, ExecResult{Stdout: "ordinary output"})
	if got.FraudControl != nil {
		t.Fatalf("non-fraud step got a FraudControl record: %+v", got.FraudControl)
	}
}
