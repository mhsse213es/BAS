package scenario

import (
	"strings"
	"testing"
)

// Carbanak BFSI plan Task 4, criteria 8 and 9.
// 8: a fraud step whose ledger is unreachable must record ledger_called=false, which scores SKIPPED,
//    never PASS, and the overall verdict must not be PASS.
// 9: Stage 8 steps 8b-8g must read the run state that 8a writes, so they share one run.

var carbanakBFSIFraudFiles = []string{
	"carbanak-bfsi-beneficiary-creation.yaml",
	"carbanak-bfsi-amount-manipulation.yaml",
	"carbanak-bfsi-unauthorized-approval.yaml",
	"carbanak-bfsi-session-misuse.yaml",
	"carbanak-bfsi-off-hours-transfer.yaml",
	"carbanak-bfsi-limit-modification.yaml",
}

func TestFraudStepsRecordLedgerOutageAsNotCalled(t *testing.T) {
	chain := loadCarbanakChain(t)
	for _, prefix := range []string{"Carbanak Stage 8a ", "Carbanak Stage 8b ", "Carbanak Stage 8c ", "Carbanak Stage 8d ", "Carbanak Stage 8e ", "Carbanak Stage 8f ", "Carbanak Stage 8g "} {
		st := carbanakStep(t, chain, prefix)
		if !strings.Contains(st.Command, "ledger_called=$false") {
			t.Errorf("%s: no ledger_called=$false record for an unreachable ledger", prefix)
		}
	}
	for _, f := range carbanakBFSIFraudFiles {
		sc := loadBFSIScenario(t, f)
		if !strings.Contains(sc.Steps[0].Command, "ledger_called=$false") {
			t.Errorf("%s: no ledger_called=$false record for an unreachable ledger", f)
		}
	}
}

// Ruling (Task 4): 8f checks the integrity of the whole audit chain (/audit/verify), which is
// a property of the entire log, not of one run, so it does not read the run state. Steps that
// act on a run (8b-8e) and the alert check for it (8g) must share the state.
func TestStage8StepsReadTheSharedRunState(t *testing.T) {
	chain := loadCarbanakChain(t)
	for _, prefix := range []string{"Carbanak Stage 8b ", "Carbanak Stage 8c ", "Carbanak Stage 8d ", "Carbanak Stage 8e ", "Carbanak Stage 8g "} {
		st := carbanakStep(t, chain, prefix)
		if !strings.Contains(st.Command, "bas_carbanak_run.json") {
			t.Errorf("%s: does not read the run state 8a writes, so it cannot share the run", prefix)
		}
	}
}

// Criterion 8 end to end: a ledger outage marker, parsed as the step output would be, must
// score SKIPPED for the fraud control, and the combined verdict must not be PASS even when
// the endpoint passed.
func TestLedgerOutageMarkerNeverScoresPass(t *testing.T) {
	out := `BAS-FRAUD-CONTROL {"step":"23","expected_control":"prevent","ledger_called":false}`
	rec, ok := ParseFraudControl(out)
	if !ok {
		t.Fatal("outage marker did not parse")
	}
	if rec.Verdict != "SKIPPED" {
		t.Fatalf("fraud verdict = %q, want SKIPPED for an unreachable ledger", rec.Verdict)
	}
	if got := CombinedVerdict("PASS", rec.Verdict); got == "PASS" {
		t.Fatal("combined verdict was PASS with the fraud control untested")
	}
}
