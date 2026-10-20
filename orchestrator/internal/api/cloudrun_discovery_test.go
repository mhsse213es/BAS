package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/db"
)

func TestValidateCloudPlanRunRequest_DiscoverAndEdgesMutuallyExclusive(t *testing.T) {
	base := db.CloudPlanRunRequest{
		ScenarioID: "s",
		Target:     "t",
		Account:    cloudgraph.AccountScope{Provider: "aws", AccountID: "111"},
	}
	withEdges := base
	withEdges.Discover = true
	withEdges.Edges = []*cloudgraph.CloudPermission{{}}
	if err := validateCloudPlanRunRequest(withEdges); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err = %v, want mutually exclusive", err)
	}
	discoverOnly := base
	discoverOnly.Discover = true
	if err := validateCloudPlanRunRequest(discoverOnly); err != nil {
		t.Fatalf("discover without edges should validate, got %v", err)
	}
}

func TestCloudDiscovererFor_AzureNamesMissingVariableNotValue(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "tenant")
	t.Setenv("AZURE_CLIENT_ID", "client")
	t.Setenv("AZURE_CLIENT_SECRET", "")
	t.Setenv("AZURE_SUBSCRIPTION_ID", "sub-1")

	_, err := cloudDiscovererFor(context.Background(), cloudgraph.AccountScope{Provider: "azure", AccountID: "sub-1"})
	if !errors.Is(err, errCloudDiscoveryNotConfigured) {
		t.Fatalf("err = %v, want not-configured", err)
	}
	if !strings.Contains(err.Error(), "AZURE_CLIENT_SECRET") {
		t.Errorf("error should name the missing variable: %v", err)
	}
	if discoveryStatusCode(err) != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 for missing server config", discoveryStatusCode(err))
	}
}

func TestCloudDiscovererFor_AzureRejectsSubscriptionMismatch(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "tenant")
	t.Setenv("AZURE_CLIENT_ID", "client")
	t.Setenv("AZURE_CLIENT_SECRET", "secret")
	t.Setenv("AZURE_SUBSCRIPTION_ID", "sub-configured")

	_, err := cloudDiscovererFor(context.Background(), cloudgraph.AccountScope{Provider: "azure", AccountID: "sub-requested"})
	if err == nil || !strings.Contains(err.Error(), "sub-configured") {
		t.Fatalf("err = %v, want subscription mismatch naming the configured subscription", err)
	}
	if discoveryStatusCode(err) != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an account the server cannot serve", discoveryStatusCode(err))
	}
}

func TestCloudDiscovererFor_UnknownProviderRejected(t *testing.T) {
	if _, err := cloudDiscovererFor(context.Background(), cloudgraph.AccountScope{Provider: "oci", AccountID: "x"}); err == nil {
		t.Fatal("unknown provider must be rejected")
	}
}

// fakeInner is a Discoverer that always fails with the given message.
type fakeInner struct{ err error }

func (f fakeInner) Discover(context.Context) (*cloudgraph.DiscoveredGraph, cloudgraph.DiscoveryReport, error) {
	return nil, nil, f.err
}

func (f fakeInner) Preflight(context.Context) []cloudgraph.PreflightCheck {
	return []cloudgraph.PreflightCheck{{Name: "inner-check", Status: "PASS", Detail: "ok"}}
}

// bareInner discovers but cannot be preflighted.
type bareInner struct{}

func (bareInner) Discover(context.Context) (*cloudgraph.DiscoveredGraph, cloudgraph.DiscoveryReport, error) {
	return nil, nil, nil
}

func findPreflight(checks []cloudgraph.PreflightCheck, name string) *cloudgraph.PreflightCheck {
	for i := range checks {
		if checks[i].Name == name {
			return &checks[i]
		}
	}
	return nil
}

// A mismatched account is a failed check, and the inner checks still run, so one
// run shows every gap.
func TestAccountChecked_PreflightMismatchFailsAndInnerStillRuns(t *testing.T) {
	d := accountChecked("111", nil, fakeInner{}, func(context.Context) (string, error) { return "999", nil })
	checks := d.(cloudgraph.Preflighter).Preflight(context.Background())

	acct := findPreflight(checks, "account-match")
	if acct == nil || acct.Status != "FAIL" || !strings.Contains(acct.Detail, "resolve to account 999") {
		t.Fatalf("account-match = %+v, want FAIL naming account 999", acct)
	}
	if findPreflight(checks, "inner-check") == nil {
		t.Error("inner checks did not run after an account mismatch")
	}
}

func TestAccountChecked_PreflightMatchPasses(t *testing.T) {
	d := accountChecked("111", nil, fakeInner{}, func(context.Context) (string, error) { return "111", nil })
	checks := d.(cloudgraph.Preflighter).Preflight(context.Background())
	if acct := findPreflight(checks, "account-match"); acct == nil || acct.Status != "PASS" {
		t.Errorf("account-match = %+v, want PASS", acct)
	}
}

// Inner check details are scrubbed of the client secret, as discovery errors are.
func TestAccountChecked_PreflightDetailIsRedacted(t *testing.T) {
	const secret = "client-secret-xyz"
	inner := fakeSecretInner{detail: "token request failed for secret client-secret-xyz"}
	d := accountChecked("sub", []string{secret}, inner, func(context.Context) (string, error) { return "sub", nil })
	checks := d.(cloudgraph.Preflighter).Preflight(context.Background())
	for _, c := range checks {
		if strings.Contains(c.Detail, secret) {
			t.Errorf("check %s leaks the secret: %q", c.Name, c.Detail)
		}
	}
}

type fakeSecretInner struct{ detail string }

func (f fakeSecretInner) Discover(context.Context) (*cloudgraph.DiscoveredGraph, cloudgraph.DiscoveryReport, error) {
	return nil, nil, nil
}

func (f fakeSecretInner) Preflight(context.Context) []cloudgraph.PreflightCheck {
	return []cloudgraph.PreflightCheck{{Name: "token-graph", Status: "FAIL", Detail: f.detail}}
}

// A source with no preflight is reported as a failure, not passed over.
func TestAccountChecked_PreflightUnpreflightableInnerFails(t *testing.T) {
	d := accountChecked("111", nil, bareInner{}, func(context.Context) (string, error) { return "111", nil })
	checks := d.(cloudgraph.Preflighter).Preflight(context.Background())
	if ds := findPreflight(checks, "discovery-source"); ds == nil || ds.Status != "FAIL" {
		t.Errorf("discovery-source = %+v, want FAIL", ds)
	}
}

// The handler rejects a request that names no account before any credential is read.
func TestTriggerCloudPreflight_RequiresAccount(t *testing.T) {
	for _, body := range []string{`{}`, `{"account":{"provider":"aws"}}`, `{"account":{"accountId":"111"}}`} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/cloud-preflight", strings.NewReader(body))
		(&Handler{}).TriggerCloudPreflight(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400", body, rec.Code)
		}
	}
}

func TestAccountChecked_MismatchFailsBeforeInventory(t *testing.T) {
	d := accountChecked("111", nil, fakeInner{err: errors.New("should not run")}, func(context.Context) (string, error) {
		return "999", nil
	})
	_, _, err := d.Discover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "resolve to account 999") {
		t.Fatalf("err = %v, want account mismatch", err)
	}
	if strings.Contains(err.Error(), "should not run") {
		t.Error("inner discovery must not run on an account mismatch")
	}
}

func TestAccountChecked_InnerErrorIsRedacted(t *testing.T) {
	const secret = "client-secret-xyz"
	d := accountChecked("sub", []string{secret}, fakeInner{err: errors.New("token request failed for secret client-secret-xyz")}, func(context.Context) (string, error) {
		return "sub", nil
	})
	_, _, err := d.Discover(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("secret leaked into error: %v", err)
	}
	if !strings.Contains(err.Error(), "[REDACTED]") {
		t.Errorf("expected redaction marker, got %v", err)
	}
}
