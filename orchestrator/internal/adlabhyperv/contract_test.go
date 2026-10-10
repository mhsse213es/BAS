package adlabhyperv

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/adgate"
	"github.com/audspect/bas/internal/adlabrt"
	"github.com/audspect/bas/internal/adprimitive"
)

func runWith(f *fakeCommander, auth adgate.Authorization) adlabrt.Result {
	rt := &adlabrt.Runtime{Sub: &HyperV{Cmd: f}, Now: func() time.Time { return time.Unix(0, 0) }}
	return rt.Validate(context.Background(), adlabrt.Request{
		RunID: "run1",
		Lab:   adlabrt.LabSpec{Name: "dc-only"},
		Case: adlabrt.ValidationCase{
			Name:      "dcsync-positive",
			Primitive: adprimitive.Primitive{ID: "dcsync", RiskClass: adprimitive.RiskNonDestructive},
		},
		Authorization: auth,
	})
}

func authorized() adgate.Authorization { return adgate.Authorization{Authorized: true} }

func TestContract_Validated(t *testing.T) {
	res := runWith(newFakeCommander(), authorized())
	if res.Status != adlabrt.StatusValidated {
		t.Fatalf("status = %q, want validated", res.Status)
	}
	if res.TeardownErr != nil {
		t.Errorf("teardown must succeed on the happy path: %v", res.TeardownErr)
	}
}

func TestContract_ProvisionFailed(t *testing.T) {
	f := newFakeCommander()
	f.provision = func(Command) (Output, error) { return Output{OK: false, Detail: "no base checkpoint"}, nil }
	if got := runWith(f, authorized()).Status; got != adlabrt.StatusProvisionFailed {
		t.Fatalf("status = %q, want provision_failed", got)
	}
}

func TestContract_IsolationUnverifiedMintsNoProvenance(t *testing.T) {
	f := newFakeCommander()
	f.probe = func(cmd Command) (Output, error) {
		if cmd.Args["check"] == string(CheckNoExternalRoute) {
			return Output{Passed: false, Determinate: true, Detail: "route to host net"}, nil
		}
		return Output{Passed: true, Determinate: true}, nil
	}
	res := runWith(f, authorized())
	if res.Status != adlabrt.StatusIsolationUnverified {
		t.Fatalf("status = %q, want isolation_unverified", res.Status)
	}
	if res.Decision.Allowed {
		t.Error("gate must not be reached (no provenance) when isolation is unverified")
	}
	if res.TeardownErr != nil {
		t.Errorf("teardown must still run: %v", res.TeardownErr)
	}
}

func TestContract_GateDeniedWhenUnauthorized(t *testing.T) {
	if got := runWith(newFakeCommander(), adgate.Authorization{Authorized: false}).Status; got != adlabrt.StatusGateDenied {
		t.Fatalf("status = %q, want gate_denied", got)
	}
}

func TestContract_ExecutionErrored(t *testing.T) {
	f := newFakeCommander()
	f.execute = func(Command) (Output, error) { return Output{}, errors.New("boom") }
	if got := runWith(f, authorized()).Status; got != adlabrt.StatusExecutionErrored {
		t.Fatalf("status = %q, want execution_errored", got)
	}
}

func TestContract_EvidenceInconclusive(t *testing.T) {
	f := newFakeCommander()
	f.execute = func(Command) (Output, error) { return Output{Complete: false}, nil }
	if got := runWith(f, authorized()).Status; got != adlabrt.StatusEvidenceInconclusive {
		t.Fatalf("status = %q, want evidence_inconclusive", got)
	}
}

func TestContract_NegativeControlNotValidated(t *testing.T) {
	f := newFakeCommander()
	// Negative control: the primitive runs but the postcondition is NOT observed.
	f.execute = func(Command) (Output, error) { return Output{PostconditionObserved: false, Complete: true}, nil }
	if got := runWith(f, authorized()).Status; got != adlabrt.StatusNotValidated {
		t.Fatalf("status = %q, want not_validated", got)
	}
}
