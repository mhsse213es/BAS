package phishbridge

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/actions"
	"github.com/audspect/bas/internal/phishval"
)

// endpointFakeVendorClient mirrors internal/actions' own in-package
// fakeVendorClient test double exactly -- actions.Execute's status-
// transition logic doesn't need a real HTTP round trip to prove; the
// vendor HTTP call itself is already proven by internal/vendors/
// crowdstrike and internal/vendors/defender's own tests, and by
// internal/actions' own test suite using this same double.
type endpointFakeVendorClient struct {
	resolveErr, actionErr error
}

func (f *endpointFakeVendorClient) ResolveDevice(ctx context.Context, hostname string) (string, error) {
	if f.resolveErr != nil {
		return "", f.resolveErr
	}
	return "device-1", nil
}
func (f *endpointFakeVendorClient) Isolate(ctx context.Context, deviceID string) (string, error) {
	if f.actionErr != nil {
		return "", f.actionErr
	}
	return "vendor-req-1", nil
}
func (f *endpointFakeVendorClient) Release(ctx context.Context, deviceID string) (string, error) {
	return "vendor-req-1", nil
}
func (f *endpointFakeVendorClient) KillProcess(ctx context.Context, deviceID string, pid int) (string, error) {
	return "vendor-req-1", nil
}
func (f *endpointFakeVendorClient) QuarantineFile(ctx context.Context, deviceID, param string) (string, error) {
	return "vendor-req-1", nil
}

func TestPHIR003_EndToEnd_KnownGood_IsolateDispatchCompleted(t *testing.T) {
	action := actions.Execute(context.Background(), &endpointFakeVendorClient{}, actions.Request{
		Type: actions.TypeIsolate, Target: actions.Target{Type: "hostname", Identifier: "WIN-01"}, Reason: "confirmed phishing payload executed",
	})
	if action.Status != actions.StatusCompleted {
		t.Fatalf("precondition: actions.Execute() status = %q, want %q", action.Status, actions.StatusCompleted)
	}

	obs := FromEPPResponseAction(action)
	outcome := phishval.Evaluate("run-ph-ir-003", "known-good", catalogExpectation(t, "PH-IR-003"), obs)
	if outcome.Response.Verdict != phishval.VerdictPass {
		t.Errorf("Response.Verdict = %q (%s), want %q", outcome.Response.Verdict, outcome.Response.Reason, phishval.VerdictPass)
	}
}

func TestPHIR003_EndToEnd_KnownBad_VendorRejectsIsolate(t *testing.T) {
	action := actions.Execute(context.Background(), &endpointFakeVendorClient{actionErr: errTestEndpoint}, actions.Request{
		Type: actions.TypeIsolate, Target: actions.Target{Type: "hostname", Identifier: "WIN-01"}, Reason: "confirmed phishing payload executed",
	})
	if action.Status != actions.StatusFailed {
		t.Fatalf("precondition: actions.Execute() status = %q, want %q", action.Status, actions.StatusFailed)
	}

	obs := FromEPPResponseAction(action)
	outcome := phishval.Evaluate("run-ph-ir-003", "known-bad", catalogExpectation(t, "PH-IR-003"), obs)
	if outcome.Response.Verdict != phishval.VerdictFail {
		t.Errorf("Response.Verdict = %q, want %q", outcome.Response.Verdict, phishval.VerdictFail)
	}
}

var errTestEndpoint = &testVendorError{"vendor API rejected isolate request"}

type testVendorError struct{ msg string }

func (e *testVendorError) Error() string { return e.msg }
