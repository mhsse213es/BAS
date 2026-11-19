package scenario

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

func fraudStep() Step {
	return Step{Name: "Carbanak Item 24 -- test", TechniqueID: "T1565.002", Framework: "custom"}
}

const fraudFailMarker = "BAS-FRAUD-CONTROL {\"step\":\"24\",\"expected_control\":\"detect\",\"ledger_called\":true,\"ledger_decision\":\"approved\",\"alert_present\":false}"

// The stored Result must be the combined verdict, so every reader (scorer,
// dashboards, PDF, CSV, run lists) sees the fraud outcome, while the endpoint
// verdict is kept alongside it.
func TestInterpretStoresCombinedResultWhenFraudFails(t *testing.T) {
	step := fraudStep()
	endpointOnly := Interpret(step, ExecResult{ExitCode: 0, Stdout: "ok"})
	if endpointOnly.Result != models.ResultPass {
		t.Fatalf("precondition: endpoint-only result = %q, want pass", endpointOnly.Result)
	}

	got := Interpret(step, ExecResult{ExitCode: 0, Stdout: fraudFailMarker})
	if got.Result != models.ResultFail {
		t.Fatalf("stored Result = %q, want fail (fraud control FAIL)", got.Result)
	}
	if got.EndpointResult != models.ResultPass {
		t.Fatalf("EndpointResult = %q, want pass (endpoint verdict kept)", got.EndpointResult)
	}
}

func TestInterpretStoresSkippedWhenLedgerNotCalled(t *testing.T) {
	step := fraudStep()
	got := Interpret(step, ExecResult{ExitCode: 0, Stdout: "BAS-FRAUD-CONTROL {\"step\":\"24\",\"expected_control\":\"detect\",\"ledger_called\":false}"})
	if got.Result != models.ResultSkipped {
		t.Fatalf("stored Result = %q, want skipped (ledger not called)", got.Result)
	}
}

func TestApplyFraudControlIsIdempotent(t *testing.T) {
	step := fraudStep()
	once := Interpret(step, ExecResult{ExitCode: 0, Stdout: fraudFailMarker})
	twice := once
	models.ApplyFraudControl(&twice)
	if twice.Result != once.Result || twice.EndpointResult != once.EndpointResult || twice.Details != once.Details {
		t.Fatalf("re-applying changed the result: once=%+v twice=%+v", once, twice)
	}
}
