package k8sscenario

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const (
	synthProbeIdentity = "system:serviceaccount:bas-sandbox:bas-sbx-token-probe"
	synthProbeSubject  = "ServiceAccount/bas-sandbox/bas-sbx-token-probe"
)

// synthFake models the synthetic-secret fixtures and RBAC: the secret, the binding, and whether the probe can read the
// secret with its token. Embedding the plain fake keeps the object and token behaviour unchanged.
type synthFake struct {
	*fakeClient
	secretLabels map[string]string
	value        string
	binding      BindingState
	bindingOK    bool
	sets         []string // every value written, to check none leaks
	ignoreGrant  bool     // the grant is recorded but has no effect on reads
	failRevoke   bool     // removing the subjects silently does nothing
	readErr      error    // the read fails in a way that is not an allow or a deny
}

func newSynthFake() *synthFake {
	fc := newFakeClient()
	fc.tokenIdentity = synthProbeIdentity
	return &synthFake{
		fakeClient:   fc,
		secretLabels: map[string]string{SynthLabel: "true"},
		value:        "original",
		binding:      BindingState{RoleName: "bas-synthetic-secret-reader"},
		bindingOK:    true,
	}
}

func (f *synthFake) Get(ctx context.Context, r ObjectRef) (Object, bool, error) {
	if r.Kind == "Secret" {
		return Object{Ref: r, Labels: f.secretLabels, Data: map[string]string{"value": f.value}}, true, nil
	}
	return f.fakeClient.Get(ctx, r)
}

func (f *synthFake) SyntheticSecretLabels(_ context.Context, _, _ string) (map[string]string, bool, error) {
	return f.secretLabels, true, nil
}

func (f *synthFake) GetBinding(_ context.Context, _, _ string) (BindingState, bool, error) {
	return f.binding, f.bindingOK, nil
}

func (f *synthFake) SetBindingSubjects(_ context.Context, _, _ string, subjects []string) error {
	f.writes = append(f.writes, "subjects "+strings.Join(subjects, ","))
	if f.failRevoke && len(subjects) == 0 {
		return nil
	}
	f.binding.Subjects = append([]string(nil), subjects...)
	return nil
}

func (f *synthFake) SetSecretValue(_ context.Context, _, _, value string) error {
	f.writes = append(f.writes, "secret value")
	f.sets = append(f.sets, value)
	f.value = value
	return nil
}

func (f *synthFake) ReadSecretAs(_ context.Context, token []byte, _, _ string) (string, bool, error) {
	if f.readErr != nil {
		return "", false, f.readErr
	}
	if f.fakeClient.issued == nil || string(token) != string(f.fakeClient.issued) {
		return "", false, nil // a token the fake did not mint is refused
	}
	if f.ignoreGrant {
		return "", false, nil
	}
	for _, s := range f.binding.Subjects {
		if s == synthProbeSubject {
			return f.value, true, nil
		}
	}
	return "", false, nil
}

func synthRequest(t *testing.T, store *memApprovals, live bool) RunRequest {
	t.Helper()
	req := RunRequest{RunID: "syn-1", Requester: "operator-1",
		Cluster:   ClusterRef{Name: testCluster, Server: testServer},
		Namespace: "bas-sandbox", ActionID: "synthetic-secret-read", Params: map[string]string{}, Live: live}
	if live {
		req.ApprovalID = approvedPod(t, store, req)
	}
	return req
}

// TestSynthetic_GrantReadRevokeReportsSucceeded checks the full sequence: the probe reads the rotated value while
// granted, the grant is removed and verified, and the run ends not revoked because the token cannot be revoked.
func TestSynthetic_GrantReadRevokeReportsSucceeded(t *testing.T) {
	fc := newSynthFake()
	store := newMemApprovals()
	audit := &captureAudit{}
	res := NewEngine(synthConfig(fc, audit, &recordAlert{}, store)).Run(context.Background(), synthRequest(t, store, true))

	if res.State != StateDiscardedNotRevoked || !res.Verified {
		t.Fatalf("state = %s verified=%v (%q), want %s verified", res.State, res.Verified, res.Error, StateDiscardedNotRevoked)
	}
	if res.Observation != ObservationSucceeded {
		t.Fatalf("observation = %q, want %q", res.Observation, ObservationSucceeded)
	}
	if len(fc.binding.Subjects) != 0 {
		t.Fatalf("grant still in place after the run: %v", fc.binding.Subjects)
	}
	if !strings.Contains(res.Error, "grant removed and verified") || !strings.Contains(res.Error, "cannot be revoked") {
		t.Fatalf("summary = %q, want grant removal and the unrevocable token", res.Error)
	}
}

// synthConfig is testConfig with the synthetic fake as the cluster client, so the overridden methods are used.
func synthConfig(f *synthFake, au Audit, al *recordAlert, store *memApprovals) Config {
	cfg := testConfig(nil, au, al, store)
	cfg.Client = f
	return cfg
}

// TestSynthetic_DeniedReadIsReportedAsDenied checks a read the grant did not allow is recorded as denied, which is a
// conclusive finding, and the grant is still removed.
func TestSynthetic_DeniedReadIsReportedAsDenied(t *testing.T) {
	fc := newSynthFake()
	fc.ignoreGrant = true
	store := newMemApprovals()
	res := NewEngine(synthConfig(fc, &captureAudit{}, &recordAlert{}, store)).Run(context.Background(), synthRequest(t, store, true))
	if res.Observation != ObservationDenied || !res.Verified {
		t.Fatalf("observation = %q verified=%v, want %q and verified", res.Observation, res.Verified, ObservationDenied)
	}
	if len(fc.binding.Subjects) != 0 {
		t.Fatalf("grant still in place: %v", fc.binding.Subjects)
	}
}

// TestSynthetic_InconclusiveReadIsNotCalledDenied checks a read that fails for another reason is inconclusive, never denied.
func TestSynthetic_InconclusiveReadIsNotCalledDenied(t *testing.T) {
	fc := newSynthFake()
	fc.readErr = errors.New("connection reset")
	store := newMemApprovals()
	res := NewEngine(synthConfig(fc, &captureAudit{}, &recordAlert{}, store)).Run(context.Background(), synthRequest(t, store, true))
	if res.Observation != ObservationInconclusive || res.Verified {
		t.Fatalf("observation = %q verified=%v, want inconclusive and not verified", res.Observation, res.Verified)
	}
}

// TestSynthetic_NoValueReachesTheResultOrAudit checks the rotated secret value appears nowhere in the result or audit.
func TestSynthetic_NoValueReachesTheResultOrAudit(t *testing.T) {
	fc := newSynthFake()
	store := newMemApprovals()
	audit := &captureAudit{}
	res := NewEngine(synthConfig(fc, audit, &recordAlert{}, store)).Run(context.Background(), synthRequest(t, store, true))
	if len(fc.sets) == 0 {
		t.Fatal("the value was never rotated")
	}
	value := fc.sets[0]
	if strings.Contains(res.Error, value) || strings.Contains(res.Observation, value) || strings.Contains(strings.Join(res.Plan, " "), value) {
		t.Fatal("the secret value reached the result")
	}
	for _, ev := range audit.events {
		for k, v := range ev.Fields {
			if strings.Contains(v, value) || strings.Contains(k, value) {
				t.Fatalf("the secret value reached the audit record in field %q", k)
			}
		}
	}
}

// TestSynthetic_RefusesWhenBindingNotInExpectedState checks a binding that already has subjects stops the run before any write.
func TestSynthetic_RefusesWhenBindingNotInExpectedState(t *testing.T) {
	fc := newSynthFake()
	fc.binding.Subjects = []string{"ServiceAccount/bas-sandbox/someone-else"}
	store := newMemApprovals()
	res := NewEngine(synthConfig(fc, &captureAudit{}, &recordAlert{}, store)).Run(context.Background(), synthRequest(t, store, true))
	if res.State != StateFailed || len(fc.sets) != 0 || fc.issued != nil {
		t.Fatalf("state = %s, sets=%d, minted=%v; want FAILED before any write", res.State, len(fc.sets), fc.issued != nil)
	}
}

// TestSynthetic_RefusesAnythingThatIsNotTheFixture checks the secret must carry the synthetic label.
func TestSynthetic_RefusesAnythingThatIsNotTheFixture(t *testing.T) {
	fc := newSynthFake()
	fc.secretLabels = map[string]string{}
	store := newMemApprovals()
	res := NewEngine(synthConfig(fc, &captureAudit{}, &recordAlert{}, store)).Run(context.Background(), synthRequest(t, store, true))
	if res.State != StateFailed || len(fc.sets) != 0 {
		t.Fatalf("state = %s, sets=%d; want FAILED before any write", res.State, len(fc.sets))
	}
}

// TestSynthetic_FailedRevokeIsCleanupFailed checks a grant that stays in place is never reported as cleaned up.
func TestSynthetic_FailedRevokeIsCleanupFailed(t *testing.T) {
	fc := newSynthFake()
	fc.failRevoke = true
	store := newMemApprovals()
	alert := &recordAlert{}
	res := NewEngine(synthConfig(fc, &captureAudit{}, alert, store)).Run(context.Background(), synthRequest(t, store, true))
	if res.State != StateCleanupFailed {
		t.Fatalf("state = %s (%q), want %s", res.State, res.Error, StateCleanupFailed)
	}
	if len(alert.msgs) == 0 {
		t.Fatal("CLEANUP_FAILED raised no alert")
	}
}

// TestSynthetic_DryRunWritesNothing checks planning never rotates, grants or mints.
func TestSynthetic_DryRunWritesNothing(t *testing.T) {
	fc := newSynthFake()
	res := NewEngine(synthConfig(fc, &captureAudit{}, &recordAlert{}, newMemApprovals())).Run(context.Background(), synthRequest(t, newMemApprovals(), false))
	if res.State != StateDryRunPlanned {
		t.Fatalf("state = %s, want %s", res.State, StateDryRunPlanned)
	}
	if len(fc.writes) != 0 || fc.issued != nil {
		t.Fatalf("dry run wrote %v or minted a token", fc.writes)
	}
}

// TestSynthetic_RefusesAnyParameter checks a run cannot choose its target.
func TestSynthetic_RefusesAnyParameter(t *testing.T) {
	fc := newSynthFake()
	store := newMemApprovals()
	req := synthRequest(t, store, false)
	req.Params = map[string]string{"secret": "some-other-secret"}
	res := NewEngine(synthConfig(fc, &captureAudit{}, &recordAlert{}, store)).Run(context.Background(), req)
	if res.State != StateRefused {
		t.Fatalf("state = %s, want %s", res.State, StateRefused)
	}
}
