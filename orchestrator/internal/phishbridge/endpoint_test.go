package phishbridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/actions"
	"github.com/audspect/bas/internal/phishval"
	"github.com/audspect/bas/internal/vendors/defender"
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

// --- FromIndependentlyVerifiedEndpointIsolation: real dispatch +
// independent re-read round trip against a local httptest Defender
// server, proving the postcondition verification genuinely re-reads
// rather than trusting the dispatch response. ---

func defenderTokenMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	}))
}

func TestFromIndependentlyVerifiedEndpointIsolation_RealDispatchAndReread_Succeeded(t *testing.T) {
	actionTokenSrv := defenderTokenMock(t)
	defer actionTokenSrv.Close()

	var isolateCalls, getActionCalls int
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/machines":
			json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{"id": "machine-1", "computerDnsName": "WIN-01"}}})
		case r.Method == http.MethodPost:
			isolateCalls++
			json.NewEncoder(w).Encode(map[string]any{"id": "action-1"})
		case r.Method == http.MethodGet && r.URL.Path == "/machineactions/action-1":
			getActionCalls++
			json.NewEncoder(w).Encode(map[string]any{"id": "action-1", "type": "Isolate", "status": "Succeeded", "machineId": "machine-1"})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer actionSrv.Close()

	client := defender.New(defender.Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = actionTokenSrv.URL
	*client.ActionTokenURL() = actionTokenSrv.URL
	client.ActionBaseURL = actionSrv.URL

	action := actions.Execute(context.Background(), client, actions.Request{
		Type: actions.TypeIsolate, Target: actions.Target{Type: "hostname", Identifier: "WIN-01"}, Reason: "confirmed phishing payload executed",
	})
	if action.Status != actions.StatusCompleted {
		t.Fatalf("precondition: dispatch status = %q, want %q", action.Status, actions.StatusCompleted)
	}
	if isolateCalls != 1 {
		t.Fatalf("isolateCalls = %d, want 1", isolateCalls)
	}

	reread, err := client.PollMachineActionUntilTerminal(context.Background(), action.VendorRequestID, 3, time.Millisecond)
	if err != nil {
		t.Fatalf("PollMachineActionUntilTerminal: %v", err)
	}
	if getActionCalls == 0 {
		t.Fatal("GetMachineAction was never called -- the dispatch response alone must never satisfy this verification")
	}

	obs := FromIndependentlyVerifiedEndpointIsolation(reread)
	outcome := phishval.Evaluate("run-ph-ir-003", "known-good-independently-verified", catalogExpectation(t, "PH-IR-003"), obs)
	if outcome.Response.Verdict != phishval.VerdictPass {
		t.Errorf("Response.Verdict = %q (%s), want %q", outcome.Response.Verdict, outcome.Response.Reason, phishval.VerdictPass)
	}
	if outcome.Response.Evidence != phishval.EvidenceVerifiedTelemetry {
		t.Errorf("Response.Evidence = %q, want %q (an independent re-read earns a stronger evidence tier than dispatch acceptance)", outcome.Response.Evidence, phishval.EvidenceVerifiedTelemetry)
	}
}

func TestFromIndependentlyVerifiedEndpointIsolation_Failed(t *testing.T) {
	obs := FromIndependentlyVerifiedEndpointIsolation(defender.MachineAction{ID: "action-1", Type: "Isolate", Status: "Failed"})
	outcome := phishval.Evaluate("run-ph-ir-003", "known-bad-independently-verified", catalogExpectation(t, "PH-IR-003"), obs)
	if outcome.Response.Verdict != phishval.VerdictFail {
		t.Errorf("Response.Verdict = %q, want %q", outcome.Response.Verdict, phishval.VerdictFail)
	}
}

func TestFromIndependentlyVerifiedEndpointIsolation_StillPending_NeverFabricatesTerminalOutcome(t *testing.T) {
	obs := FromIndependentlyVerifiedEndpointIsolation(defender.MachineAction{ID: "action-1", Type: "Isolate", Status: "Pending"})
	outcome := phishval.Evaluate("run-ph-ir-003", "pending", catalogExpectation(t, "PH-IR-003"), obs)
	if outcome.Response.Verdict != phishval.VerdictNotTested {
		t.Errorf("Response.Verdict = %q, want %q (a non-terminal status must never be read as pass or fail)", outcome.Response.Verdict, phishval.VerdictNotTested)
	}
}
