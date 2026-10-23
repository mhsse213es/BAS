package k8sscenario

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

const probeSecret = "SECRET-PROBE-TOKEN-VALUE"

func probeRequest(live bool) RunRequest {
	return RunRequest{
		RunID: "tok-1", Requester: "operator-1",
		Cluster:   ClusterRef{Name: testCluster, Server: testServer},
		Namespace: "bas-sandbox", ActionID: "sa-token-probe", Params: map[string]string{}, Live: live,
	}
}

// TestTokenProbe_EndsDiscardedNotRevokedAndLeaksNothing checks the state is never CLEANED, the token bytes are
// cleared, and the token text appears nowhere in the result or the audit record.
func TestTokenProbe_EndsDiscardedNotRevokedAndLeaksNothing(t *testing.T) {
	fc := newFakeClient()
	fc.tokenIdentity = "system:serviceaccount:bas-sandbox:bas-sbx-token-probe"
	store := newMemApprovals()
	req := probeRequest(true)
	req.ApprovalID = approvedPod(t, store, req)
	audit := &captureAudit{}
	res := NewEngine(testConfig(fc, audit, &recordAlert{}, store)).Run(context.Background(), req)

	if res.State != StateDiscardedNotRevoked {
		t.Fatalf("state = %s (%q), want %s", res.State, res.Error, StateDiscardedNotRevoked)
	}
	if !res.Verified {
		t.Fatal("the probe identity should have verified")
	}
	if !strings.Contains(res.Error, "cannot be revoked") {
		t.Fatalf("detail must say the token cannot be revoked, got %q", res.Error)
	}
	if fc.issued == nil || bytes.Contains(fc.issued, []byte("SECRET")) {
		t.Fatalf("the minted token must be cleared after rollback, got %q", fc.issued)
	}
	for _, b := range fc.issued {
		if b != 0 {
			t.Fatal("token bytes were not zeroed")
		}
	}
	if strings.Contains(res.Error, probeSecret) || strings.Contains(strings.Join(res.Plan, " "), probeSecret) {
		t.Fatal("token text reached the result")
	}
	if len(audit.events) == 0 {
		t.Fatal("no audit events were captured")
	}
	for _, ev := range audit.events {
		for k, v := range ev.Fields {
			if strings.Contains(v, "SECRET") || strings.Contains(k, "SECRET") {
				t.Fatalf("token text reached the audit record in field %q", k)
			}
		}
	}
}

// TestTokenProbe_RefusesAnyParameter checks a run cannot pick its own target.
func TestTokenProbe_RefusesAnyParameter(t *testing.T) {
	fc := newFakeClient()
	store := newMemApprovals()
	req := probeRequest(true)
	req.Params = map[string]string{"serviceAccount": "default"}
	req.ApprovalID = approvedPod(t, store, req)
	res := NewEngine(testConfig(fc, &recordAudit{}, &recordAlert{}, store)).Run(context.Background(), req)
	if res.State != StateRefused {
		t.Fatalf("state = %s, want %s", res.State, StateRefused)
	}
	if fc.issued != nil {
		t.Fatal("a refused run minted a token")
	}
}

// TestTokenProbe_DryRunMintsNothing checks planning never requests a token.
func TestTokenProbe_DryRunMintsNothing(t *testing.T) {
	fc := newFakeClient()
	res := NewEngine(testConfig(fc, &recordAudit{}, &recordAlert{}, newMemApprovals())).Run(context.Background(), probeRequest(false))
	if res.State != StateDryRunPlanned {
		t.Fatalf("state = %s, want %s", res.State, StateDryRunPlanned)
	}
	if fc.issued != nil {
		t.Fatal("a dry run minted a token")
	}
}

// TestTokenProbe_UnexpectedIdentityIsReportedNotCleaned checks a token that authenticates as someone else is
// reported as a failed verification, still discarded, and never called clean.
func TestTokenProbe_UnexpectedIdentityIsReportedNotCleaned(t *testing.T) {
	fc := newFakeClient()
	fc.tokenIdentity = "system:serviceaccount:default:someone-else"
	store := newMemApprovals()
	req := probeRequest(true)
	req.ApprovalID = approvedPod(t, store, req)
	res := NewEngine(testConfig(fc, &recordAudit{}, &recordAlert{}, store)).Run(context.Background(), req)
	if res.State != StateDiscardedNotRevoked || res.Verified {
		t.Fatalf("state = %s verified=%v, want %s unverified", res.State, res.Verified, StateDiscardedNotRevoked)
	}
	if !strings.Contains(res.Error, "verification failed") {
		t.Fatalf("detail must report the failed verification, got %q", res.Error)
	}
}

// TestTokenProbe_MintFailureIsFailed checks a refused token request ends as FAILED with no credential held.
func TestTokenProbe_MintFailureIsFailed(t *testing.T) {
	fc := newFakeClient()
	fc.issueErr = errors.New("HTTP 403 Forbidden")
	store := newMemApprovals()
	req := probeRequest(true)
	req.ApprovalID = approvedPod(t, store, req)
	res := NewEngine(testConfig(fc, &recordAudit{}, &recordAlert{}, store)).Run(context.Background(), req)
	if res.State != StateFailed {
		t.Fatalf("state = %s (%q), want %s", res.State, res.Error, StateFailed)
	}
	if fc.issued != nil {
		t.Fatal("a failed mint left a token behind")
	}
}

// captureAudit keeps full audit events so tests can check every field.
type captureAudit struct {
	events []Event
}

func (a *captureAudit) Write(_ context.Context, e Event) error {
	a.events = append(a.events, e)
	return nil
}
