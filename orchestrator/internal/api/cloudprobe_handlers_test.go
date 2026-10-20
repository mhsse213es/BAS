package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cloudgraph"
)

const probeBody = `{"provider":"aws","accountId":"111111111111","operation":"s3:ListBucket","target":"arn:aws:s3:::corp-bucket","mode":"%s"}`

// probeRecorder records every audit entry and prober call, and can make one
// audit action fail.
type probeRecorder struct {
	actions  []string
	outcomes []string
	failOn   string
	calls    int
	out      cloudgraph.ProbeOutcome
}

func (p *probeRecorder) audit(_ context.Context, _, action, _ string, _ map[string]any, outcome string) error {
	p.actions = append(p.actions, action)
	p.outcomes = append(p.outcomes, outcome)
	if action == p.failOn {
		return errors.New("audit store down")
	}
	return nil
}

func (p *probeRecorder) Probe(context.Context, cloudgraph.ProbeRequest) (cloudgraph.ProbeOutcome, error) {
	p.calls++
	return p.out, nil
}

func probeHandler(rec *probeRecorder) *Handler {
	h := &Handler{probeAudit: rec.audit}
	h.cloudProber = func(context.Context, string, string) (cloudgraph.Prober, error) { return rec, nil }
	return h
}

func postProbe(t *testing.T, h *Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := authedRequest(t, http.MethodPost, "/api/cloud-probes", strings.NewReader(body), auth.RoleAnalyst, "user-1")
	return callAuthed(h.TriggerCloudProbe, req)
}

// A request that carries a read-only label is refused by the decoder. Nothing is
// audited and nothing runs.
func TestCloudProbe_UnknownFieldRefusedBeforeAnyAction(t *testing.T) {
	t.Setenv(cloudProbeAllowListEnv, "aws:111111111111")
	rec := &probeRecorder{}
	body := strings.Replace(probeBody, `"mode":"%s"`, `"mode":"live-readonly","readOnly":true`, 1)
	res := postProbe(t, probeHandler(rec), body)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.Code)
	}
	if len(rec.actions) != 0 || rec.calls != 0 {
		t.Fatal("a request with an unknown field reached audit or a provider")
	}
}

// Without an authenticated actor, the audit entry cannot say who asked, so the
// request is refused.
func TestCloudProbe_NoActorRefused(t *testing.T) {
	t.Setenv(cloudProbeAllowListEnv, "aws:111111111111")
	rec := &probeRecorder{}
	req := httptest.NewRequest(http.MethodPost, "/api/cloud-probes", strings.NewReader(probeBody))
	res := httptest.NewRecorder()
	probeHandler(rec).TriggerCloudProbe(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.Code)
	}
	if len(rec.actions) != 0 || rec.calls != 0 {
		t.Fatal("a request with no actor reached audit or a provider")
	}
}

// An account that is not allow-listed is rejected. The request is still audited,
// and the outcome is recorded as rejected. No provider is contacted.
func TestCloudProbe_UnlistedAccountRejectedAndAudited(t *testing.T) {
	t.Setenv(cloudProbeAllowListEnv, "aws:111111111111")
	rec := &probeRecorder{}
	body := strings.Replace(probeBody, "111111111111", "999999999999", 1)
	body = strings.Replace(body, `"mode":"%s"`, `"mode":"live-readonly"`, 1)
	res := postProbe(t, probeHandler(rec), body)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.Code)
	}
	if rec.calls != 0 {
		t.Fatal("prober was called for an unlisted account")
	}
	if strings.Join(rec.outcomes, ",") != "pending,rejected" {
		t.Errorf("audit outcomes = %v, want pending then rejected", rec.outcomes)
	}
}

// An unset allow-list permits nothing.
func TestCloudProbe_UnsetAllowListPermitsNothing(t *testing.T) {
	t.Setenv(cloudProbeAllowListEnv, "")
	rec := &probeRecorder{}
	res := postProbe(t, probeHandler(rec), strings.Replace(probeBody, `"mode":"%s"`, `"mode":"live-readonly"`, 1))
	if res.Code != http.StatusBadRequest || rec.calls != 0 {
		t.Fatalf("status = %d, calls = %d; an unset allow-list must refuse", res.Code, rec.calls)
	}
}

// If the requested entry cannot be written, the probe does not run.
func TestCloudProbe_RequestedAuditFailureStopsProbe(t *testing.T) {
	t.Setenv(cloudProbeAllowListEnv, "aws:111111111111")
	rec := &probeRecorder{failOn: "cloud.probe.requested"}
	res := postProbe(t, probeHandler(rec), strings.Replace(probeBody, `"mode":"%s"`, `"mode":"live-readonly"`, 1))
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", res.Code)
	}
	if rec.calls != 0 {
		t.Fatal("the probe ran although its audit entry was not written")
	}
}

// Dry-run returns the plan and contacts no provider, even with a prober present.
func TestCloudProbe_DryRunContactsNoProvider(t *testing.T) {
	t.Setenv(cloudProbeAllowListEnv, "aws:111111111111")
	rec := &probeRecorder{out: cloudgraph.ProbeOutcome{Outcome: "allowed", Evidence: cloudgraph.EvidenceObserved}}
	res := postProbe(t, probeHandler(rec), strings.Replace(probeBody, "%s", "dry-run", 1))
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
	if rec.calls != 0 {
		t.Fatal("dry-run called the provider")
	}
	if !strings.Contains(res.Body.String(), `"outcome":"planned"`) {
		t.Errorf("body = %s, want a planned outcome", res.Body.String())
	}
}

// A live probe runs once, and both the request and the outcome are audited.
func TestCloudProbe_LiveProbeRunsAndIsAudited(t *testing.T) {
	t.Setenv(cloudProbeAllowListEnv, "aws:111111111111")
	rec := &probeRecorder{out: cloudgraph.ProbeOutcome{Outcome: "allowed", Evidence: cloudgraph.EvidenceObserved}}
	res := postProbe(t, probeHandler(rec), strings.Replace(probeBody, "%s", "live-readonly", 1))
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
	if rec.calls != 1 {
		t.Fatalf("prober calls = %d, want 1", rec.calls)
	}
	if strings.Join(rec.outcomes, ",") != "pending,allowed" {
		t.Errorf("audit outcomes = %v, want pending then allowed", rec.outcomes)
	}
}

// If the outcome entry cannot be written after the probe ran, the result is
// withheld, because it could not be recorded.
func TestCloudProbe_OutcomeAuditFailureWithholdsResult(t *testing.T) {
	t.Setenv(cloudProbeAllowListEnv, "aws:111111111111")
	rec := &probeRecorder{failOn: "cloud.probe.outcome", out: cloudgraph.ProbeOutcome{Outcome: "allowed", Evidence: cloudgraph.EvidenceObserved}}
	res := postProbe(t, probeHandler(rec), strings.Replace(probeBody, "%s", "live-readonly", 1))
	if res.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", res.Code)
	}
	if strings.Contains(res.Body.String(), `"outcome":"allowed"`) {
		t.Error("the result was returned although its outcome was not recorded")
	}
}
