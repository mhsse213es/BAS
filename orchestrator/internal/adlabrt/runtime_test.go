package adlabrt

import (
	"context"
	"errors"
	"testing"

	"github.com/audspect/bas/internal/adgate"
	"github.com/audspect/bas/internal/adprimitive"
)

// fakeSub is an in-process Substrate whose every stage is scriptable.
type fakeSub struct {
	provErr     error
	iso         IsolationResult
	isoErr      error
	obs         Observation
	execErr     error
	execPanic   bool
	teardowns   int
	teardownErr error
}

func (f *fakeSub) Provision(ctx context.Context, s LabSpec) (Target, error) {
	if f.provErr != nil {
		return Target{}, f.provErr
	}
	return Target{ID: "t-" + s.Name}, nil
}
func (f *fakeSub) VerifyIsolation(ctx context.Context, t Target) (IsolationResult, error) {
	return f.iso, f.isoErr
}
func (f *fakeSub) Execute(ctx context.Context, t Target, vc ValidationCase) (Observation, error) {
	if f.execPanic {
		panic("boom during execute")
	}
	return f.obs, f.execErr
}
func (f *fakeSub) Teardown(ctx context.Context, t Target) error {
	f.teardowns++
	return f.teardownErr
}

func dcsyncPrimitive() adprimitive.Primitive {
	return adprimitive.Primitive{ID: "dcsync", TechniqueID: "T1003.006", RiskClass: adprimitive.RiskPotentiallyDestructive}
}

func baseReq() Request {
	return Request{
		RunID: "run-1",
		Lab:   LabSpec{Name: "dcsync-dc"},
		Case: ValidationCase{
			Name:                "dcsync-replication",
			Primitive:           dcsyncPrimitive(),
			ExpectPostcondition: adprimitive.Capability{Kind: adprimitive.CapDomainCredentialMaterial},
		},
		Authorization: adgate.Authorization{Authorized: true},
	}
}

func verified() IsolationResult { return IsolationResult{Verified: true, Method: "fake"} }

func TestValidate_HappyPathValidated(t *testing.T) {
	f := &fakeSub{iso: verified(), obs: Observation{PostconditionObserved: true, Complete: true}}
	res := (&Runtime{Sub: f}).Validate(context.Background(), baseReq())
	if res.Status != StatusValidated {
		t.Fatalf("want validated, got %q (%+v)", res.Status, res)
	}
	if !res.Evidence.PostconditionObserved || !res.Evidence.Complete || res.Evidence.TargetID == "" {
		t.Fatalf("evidence incomplete: %+v", res.Evidence)
	}
	if f.teardowns != 1 {
		t.Fatalf("teardown must run exactly once, ran %d", f.teardowns)
	}
}

func TestValidate_ProvisionFailed(t *testing.T) {
	f := &fakeSub{provErr: errors.New("no capacity")}
	res := (&Runtime{Sub: f}).Validate(context.Background(), baseReq())
	if res.Status != StatusProvisionFailed {
		t.Fatalf("want provision_failed, got %q", res.Status)
	}
}

func TestValidate_IsolationUnverifiedBlocksAndMintsNoProvenance(t *testing.T) {
	f := &fakeSub{iso: IsolationResult{Verified: false, Detail: "probe reached prod"}, obs: Observation{PostconditionObserved: true, Complete: true}}
	res := (&Runtime{Sub: f}).Validate(context.Background(), baseReq())
	if res.Status != StatusIsolationUnverified {
		t.Fatalf("want isolation_unverified, got %q", res.Status)
	}
	if res.Evidence.PostconditionObserved {
		t.Fatalf("must NOT execute when isolation unverified: %+v", res.Evidence)
	}
	if f.teardowns != 1 {
		t.Fatalf("teardown must still run, ran %d", f.teardowns)
	}
}

func TestValidate_IsolationProbeErrorBlocks(t *testing.T) {
	f := &fakeSub{isoErr: errors.New("probe failed"), iso: IsolationResult{Verified: true}}
	res := (&Runtime{Sub: f}).Validate(context.Background(), baseReq())
	if res.Status != StatusIsolationUnverified {
		t.Fatalf("probe error must be treated as unverified, got %q", res.Status)
	}
}

func TestValidate_GateDeniedWhenNotAuthorized(t *testing.T) {
	f := &fakeSub{iso: verified(), obs: Observation{PostconditionObserved: true, Complete: true}}
	req := baseReq()
	req.Authorization = adgate.Authorization{Authorized: false}
	res := (&Runtime{Sub: f}).Validate(context.Background(), req)
	if res.Status != StatusGateDenied || res.Decision.Reason != adgate.ReasonDeniedMissingAuth {
		t.Fatalf("verified lab but unauthorized must be gate_denied/missing_auth, got %q/%+v", res.Status, res.Decision)
	}
	if res.Evidence.PostconditionObserved {
		t.Fatalf("must not execute when gate denies")
	}
}

func TestValidate_ExecutionErrored(t *testing.T) {
	f := &fakeSub{iso: verified(), execErr: errors.New("agent lost")}
	res := (&Runtime{Sub: f}).Validate(context.Background(), baseReq())
	if res.Status != StatusExecutionErrored {
		t.Fatalf("want execution_errored, got %q", res.Status)
	}
	if f.teardowns != 1 {
		t.Fatalf("teardown must run on execution error, ran %d", f.teardowns)
	}
}

func TestValidate_EvidenceInconclusive(t *testing.T) {
	f := &fakeSub{iso: verified(), obs: Observation{PostconditionObserved: true, Complete: false}}
	res := (&Runtime{Sub: f}).Validate(context.Background(), baseReq())
	if res.Status != StatusEvidenceInconclusive {
		t.Fatalf("incomplete evidence must fail closed, got %q", res.Status)
	}
}

func TestValidate_NegativeControlNotValidated(t *testing.T) {
	f := &fakeSub{iso: verified(), obs: Observation{PostconditionObserved: false, Complete: true}}
	res := (&Runtime{Sub: f}).Validate(context.Background(), baseReq())
	if res.Status != StatusNotValidated {
		t.Fatalf("complete evidence with postcondition NOT observed must be not_validated, got %q", res.Status)
	}
}

func TestValidate_TeardownRunsOnPanic(t *testing.T) {
	f := &fakeSub{iso: verified(), execPanic: true}
	res := (&Runtime{Sub: f}).Validate(context.Background(), baseReq())
	if f.teardowns != 1 {
		t.Fatalf("teardown must run exactly once after panic, ran %d", f.teardowns)
	}
	if res.Status != StatusExecutionErrored {
		t.Fatalf("panic must be recovered into execution_errored, got %q", res.Status)
	}
}

func TestValidate_TeardownErrorSurfaced(t *testing.T) {
	f := &fakeSub{iso: verified(), obs: Observation{PostconditionObserved: true, Complete: true}, teardownErr: errors.New("leak")}
	res := (&Runtime{Sub: f}).Validate(context.Background(), baseReq())
	if res.TeardownErr == nil {
		t.Fatal("teardown error must be surfaced in Result, not swallowed")
	}
}
