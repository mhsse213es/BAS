package api

import (
	"context"
	"errors"
	"net/http"
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
