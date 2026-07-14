package detectverify

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/verification"
)

type fakeScenarios struct {
	sc *scenario.Scenario
}

func (f *fakeScenarios) Get(id string) (*scenario.Scenario, bool) {
	if f.sc == nil || f.sc.ID != id {
		return nil, false
	}
	return f.sc, true
}

func (f *fakeScenarios) ResolveStepExpectations(step scenario.Step) ([]scenario.ExpectedDetection, []scenario.ProfileRef) {
	return step.ExpectedDetections, nil
}

type fakeConnector struct {
	result VerifyResult
	err    error
	calls  int
}

func (f *fakeConnector) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	f.calls++
	return f.result, f.err
}
func (f *fakeConnector) TestConnection(ctx context.Context) error { return nil }

type fakeStore struct {
	attested  []verification.AttestInput
	evidence  []verification.EvidenceInput
	attestErr error
}

func (f *fakeStore) Attest(ctx context.Context, in verification.AttestInput) (verification.Record, error) {
	if f.attestErr != nil {
		return verification.Record{}, f.attestErr
	}
	f.attested = append(f.attested, in)
	return verification.Record{ID: "rec-" + in.ExpectationID}, nil
}

func (f *fakeStore) AddEvidence(ctx context.Context, in verification.EvidenceInput) (verification.Evidence, error) {
	f.evidence = append(f.evidence, in)
	return verification.Evidence{ID: "ev-1"}, nil
}

func testScenario(exp scenario.ExpectedDetection) *scenario.Scenario {
	return &scenario.Scenario{
		ID: "sc-1",
		Steps: []scenario.Step{
			{Name: "step1", TechniqueID: "T1059.001", ExpectedDetections: []scenario.ExpectedDetection{exp}},
		},
	}
}

func baseParams(exp scenario.ExpectedDetection, conn Connector, store *fakeStore, result models.CheckResult) VerifyRunParams {
	return VerifyRunParams{
		RunID: "run-1", ScenarioID: "sc-1", HostName: "HOST1", HostIP: "10.0.0.5",
		Results: []models.SimulationResult{
			{Technique: models.AttackTechnique{ID: "T1059.001"}, Result: result, ExecutedAt: time.Now(), DurationMs: 1000},
		},
		Scenarios:  &fakeScenarios{sc: testScenario(exp)},
		Store:      store,
		Connectors: map[string]Connector{"microsoft_sentinel": conn},
	}
}

func apiExpectation() scenario.ExpectedDetection {
	return scenario.ExpectedDetection{ID: "exp-1", Provider: "microsoft_sentinel", Verification: scenario.VerificationAPI, Confidence: scenario.ConfidenceRequired}
}

func TestVerifyRun_DetectedVerdict_AttestsApprovedAndAttachesEvidence(t *testing.T) {
	conn := &fakeConnector{result: VerifyResult{
		Verdict: VerdictDetected, Confidence: ConfidenceHigh,
		MatchedAlerts: []MatchedAlert{{AlertID: "a1"}},
	}}
	store := &fakeStore{}
	summary := VerifyRun(context.Background(), baseParams(apiExpectation(), conn, store, models.ResultFail))

	if summary.Checked != 1 || summary.Attested != 1 || summary.Errors != 0 {
		t.Fatalf("summary = %+v, want Checked=1 Attested=1 Errors=0", summary)
	}
	if len(store.attested) != 1 {
		t.Fatalf("attested = %d, want 1", len(store.attested))
	}
	got := store.attested[0]
	if got.Result != verification.ResultDetected || got.WorkflowState != verification.StateApproved {
		t.Fatalf("attestation = %+v, want Result=Detected WorkflowState=Approved", got)
	}
	if got.Source != verification.SourceAPI {
		t.Fatalf("Source = %q, want %q", got.Source, verification.SourceAPI)
	}
	if got.AlertID != "a1" {
		t.Fatalf("AlertID = %q, want a1", got.AlertID)
	}
	if len(store.evidence) != 1 {
		t.Fatalf("evidence = %d, want 1 (matched alert JSON attached)", len(store.evidence))
	}
}

func TestVerifyRun_NotDetectedVerdict_AttestsNeedsReview(t *testing.T) {
	conn := &fakeConnector{result: VerifyResult{Verdict: VerdictNotDetected}}
	store := &fakeStore{}
	summary := VerifyRun(context.Background(), baseParams(apiExpectation(), conn, store, models.ResultFail))

	if summary.Attested != 1 {
		t.Fatalf("Attested = %d, want 1", summary.Attested)
	}
	got := store.attested[0]
	if got.Result != verification.ResultNotDetected || got.WorkflowState != verification.StateNeedsReview {
		t.Fatalf("attestation = %+v, want Result=NotDetected WorkflowState=NeedsReview", got)
	}
	if len(store.evidence) != 0 {
		t.Fatalf("evidence = %d, want 0 for a NotDetected verdict", len(store.evidence))
	}
}

func TestVerifyRun_SkipsNonAPIVerification(t *testing.T) {
	exp := apiExpectation()
	exp.Verification = scenario.VerificationManual
	conn := &fakeConnector{result: VerifyResult{Verdict: VerdictDetected}}
	store := &fakeStore{}
	summary := VerifyRun(context.Background(), baseParams(exp, conn, store, models.ResultFail))

	if summary.Checked != 0 || conn.calls != 0 {
		t.Fatalf("summary = %+v, conn.calls = %d, want a manual-verification expectation to be skipped entirely", summary, conn.calls)
	}
}

func TestVerifyRun_SkipsWhenStepDidNotFail(t *testing.T) {
	conn := &fakeConnector{result: VerifyResult{Verdict: VerdictDetected}}
	store := &fakeStore{}
	summary := VerifyRun(context.Background(), baseParams(apiExpectation(), conn, store, models.ResultBlocked))

	if summary.Checked != 0 || conn.calls != 0 {
		t.Fatalf("summary = %+v, want a Blocked step to be skipped (nothing to alert on)", summary)
	}
}

func TestVerifyRun_SkipsWhenNoConnectorForProvider(t *testing.T) {
	exp := apiExpectation()
	exp.Provider = "splunk" // no connector registered under this key
	conn := &fakeConnector{result: VerifyResult{Verdict: VerdictDetected}}
	store := &fakeStore{}
	summary := VerifyRun(context.Background(), baseParams(exp, conn, store, models.ResultFail))

	if summary.Checked != 0 || conn.calls != 0 {
		t.Fatalf("summary = %+v, want an expectation with no configured connector to be skipped", summary)
	}
}

func TestVerifyRun_ConnectorError_NoAttestationWritten(t *testing.T) {
	conn := &fakeConnector{err: context.DeadlineExceeded}
	store := &fakeStore{}
	summary := VerifyRun(context.Background(), baseParams(apiExpectation(), conn, store, models.ResultFail))

	if summary.Errors != 1 || summary.Attested != 0 {
		t.Fatalf("summary = %+v, want Errors=1 Attested=0", summary)
	}
	if len(store.attested) != 0 {
		t.Fatalf("attested = %d, want 0 — a connector error must never fabricate a verdict", len(store.attested))
	}
}
